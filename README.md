# ZZ EDR

> 单文件、无依赖的 Windows 终端安全检测与应急响应工具。一个 `.cpp` 编译成一个 `.exe`，覆盖病毒查杀、行为审计、持久化清理、勒索防护、内核驱动五层防御。

[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0078D4)](https://www.microsoft.com/windows)
[![Compiler](https://img.shields.io/badge/compiler-MSVC%20/cl.exe%20(x64)-blue)](https://visualstudio.microsoft.com/)
[![Standard](https://img.shields.io/badge/std-C%2B%2B17-00599C)](https://isocpp.org/)
[![Version](https://img.shields.io/badge/version-14.17.0.0-brightgreen)](#版本)

---

## ⚠️ 安全警告（务必先读）

1. **本工具会修改系统安全配置**（创建还原点、调整组策略/SRP、禁用服务、删除计划任务、清理注册表项、终止进程）。**请在虚拟机或测试机上先行验证**，确认无误后再部署到生产环境。
2. **必须以管理员身份运行**。非管理员时多数检测会失败并明确记录日志，不会静默绕过。
3. **默认只告警、不自动处置**。自动删除/禁用/终止需开启「激进模式（`advAggressive`）」；处置前会弹出**三选确认框**（是=处理 / 否=忽略 / 取消=加白名单），确认框最多等待 3 分钟超时放行。
4. **处置强度分三级，逐级递增**（`advAggressive` < `escapeMode`）：

   | 级别 | 触发条件 | 覆写 | 还原策略 |
   |---|---|---|---|
   | 普通 | 确认有害 | 无 | 隔离，可一键还原 |
   | 激进 | 行为越界 | 1 遍随机 | 扫描干净则自动还原 + 重点观察 10 分钟 |
   | **紧急逃生** | **命中任意规则（含提示级）** | **3 遍（0x00→0xFF→随机）** | **不自动还原** |

   紧急逃生模式开启时需二次确认，可能造成**系统无法启动、正常软件永久损坏**，仅在确认系统已被控制需立即止损时使用。

4. **告警等待会阻塞后台扫描线程**。无人值守场景（开机扫描、服务化）建议将 `alertAskOn` 设为 `false` 退回自动模式。
5. **族谱库初始为空**，靠本机确认过的恶意样本做种子积累；首次遇到全新家族时仅能依靠通用启发式特征。
6. **能力族谱对正常远控/打包工具存在误报可能**（如远程协助、安装包），请先观察日志再决定是否启用自动处置。
7. **不包含任何恶意代码**，所有特征均为检测规则；蜜罐诱饵文件（`~$财务汇总.xlsx` 等）是故意放置的监测点，可放心删除或关闭（`canaryOn=false`）。
8. **内核驱动（`zz_edrdrv`）是独立组件**，需 WDK 单独编译、测试签名加载，见 [驱动组件](#驱动组件-zz_edrdrv) 一节。

---

## 功能一览

> 以下模块均已在源码中核实实现（`ZZ_EDR.cpp`，约 9800 行）。

### 检测与查杀
- **分级扫描**：按 `无签名 > 有签名 > 系统组件 > 驱动` 排优先级队列，签名仅用于排序、**不作为放行依据**
- **规则/哈希/恶意特征**：精确哈希比对 + 进程名黑名单 + 明文字符串特征
- **派生类 / 变种检测**：能力族谱（MITRE ATT&CK API 序列匹配，规则表见 `g_malFam`）+ spamsum 风格模糊哈希（滚动窗口 32 字节 + FNV-1a 块哈希，实现于 `MalFamilyScan`）+ PE 解析（导入表 / 节区熵 / RWX 节）+ 本地族谱库（`g_family`，存于 `%TEMP%\zz_EDR.family`，上限 2000 条，同类仅留一个种子；与样本比对 ≥60% 判为派生变种，详见 3603 行处比对逻辑）。族谱扫描仅取文件前 2MB，调用入口 `MalFamilyScan(path, why)`，命中 sev≥5 自动 `SetThreatLevel(THREAT_DANGER)`
- **HEUR 启发式引擎**：加壳/高熵/反调试/反VM/RTLO伪装/双扩展名/系统名伪装 加权评分，输出 `HEUR:Trojan.Win32.Generic` 等命名
- **PDM 主动防御**：8 个 ATT&CK 战术阶段关联，10 条攻击链规则（钓鱼宏链/注入回连/无文件/勒索链等），单阶段高频兜底
- **强制终止规则（ForceKill）**：用户指定的高危目标，命中即 **强杀 + 自动恢复**、不经确认弹窗。规则表 `g_forceKillRules`（当前含 `Philips Speech Driver Client`）；匹配范围为 **进程名 / 映像路径 / 命令行**，并做 **归一化匹配**（路径分隔符 `\`、驼峰 `SpeechDriverClient` → `speech driver client`），因此 `C:\Program Files (x86)\Philips\Speech Driver Client\...` 这类真实安装路径也能命中。恢复流程：建系统还原点（仅一次）→ 删注册表自启动项（Run/RunOnce/Winlogon）→ 停止并禁用命中服务 → 禁用命中计划任务 → 隔离映像文件（**可撤销**，隔离区可恢复；受保护路径跳过）→ 打红警。开关 `forceKillOn`（默认 true）
- **银狐 / 紫狐 / 全品类族谱**：规则表 `g_malFam`，覆盖远控、银行木马、信息窃取、勒索、挖矿、僵尸网络、蠕虫、Rootkit、无文件、下载器、键盘记录、间谍、宏病毒、引导区、凭据窃取；进程层 `FoxProcScan` 含**白加黑侧载 DLL 名单**（`g_sideloadDll`，35 个：`version.dll` / `dbghelp.dll` / `winhttp.dll` / … / `wwlib.dll` / `vgx.dll`）与**系统名伪装检测**（`g_sysNames`，14 个：`svchost.exe` / `dllhost.exe` / `lsass.exe` 等——出现在非 System32 目录即高危）
- **沙箱动态分析 / 静态分析 / 启发式**
- **隔离**：可疑文件移入 `zz_EDR_quarantine/`，支持列表管理
- **顽固病毒免疫处置**：结束占用 → `DeleteFileW` → 移出 → 重启删除 → 创建同名占位文件（覆写 1MB 随机数据）→ 设只读+系统+隐藏 → 开启超强拦截

### 隐藏文件与 NTFS 备用数据流（ADS）检测（v13.33 新增）

恶意软件用「看不见」做持久化，两条路径必须分别处理：

- **隐藏文件 / 隐藏目录**（`HiddenFileScan`）
  - 扫描 `%TEMP%` / `AppData` / `Downloads` / `Desktop` / `ProgramData` / `Public` 等目录
  - 关注带 `FILE_ATTRIBUTE_HIDDEN` 或 `SYSTEM` 属性的**可执行文件与脚本**
    （`.exe / .dll / .scr / .bat / .ps1 / .vbs / .js / .hta` 等 17 类）
  - 评分：隐藏 `+3`｜隐藏+系统组合 `+2`｜高危目录 `+1`｜无有效签名 `+2`｜
    情报哈希命中一票否决拉满 `5`
  - 白名单跳过 `desktop.ini` / `thumbs.db` / `NTUSER.DAT` 等系统自动生成文件
  - 隐藏目录自动递归一层

- **NTFS 备用数据流**（`AdsScan`，此前为**完全空白**）
  - 形如 `note.txt:payload.exe`，资源管理器看不到、`dir` 也看不到、
    文件大小不计入主数据流，但可用 `start "" "note.txt:payload.exe"` 直接执行
  - 用 `FindFirstStreamW` 枚举（动态加载 `kernel32`，非 NTFS / 老系统优雅跳过）
  - 判定：流名为可执行扩展名 → 高危；**流内容以 `MZ` 开头（PE 文件）→ 高危**；
    含 `WScript.Shell` / `powershell` 等脚本特征 → 高危；
    体积 `>100KB` 高危、`>10KB` 可疑；随机哈希流名可疑
  - `Zone.Identifier` 按体积区分（正常 `<4KB`），避免误报
  - 处置顺序硬约束：**先 `SetEndOfFile` 截断，再尝试 `DeleteFileW` 删流** ——
    保证删除失败时 payload 也已失效

### 告警与自愈
- **告警确认机制**：所有自动处置经 UI 线程三选确认框（`AlertConfirm`），支持白名单（`zz_EDR.userallow`）
- **启动限制自修复**：主程序起不来时自动修复 IFEO 镜像劫持、SRP 默认级别、DisallowRun 策略、AppLocker EXE 规则，并 `gpupdate /force`
- **配置备份 / 防篡改**：HMAC 签名校验，支持备份与恢复

### 行为审计（恢复页按钮）
- 资源异常监控（CPU / 内存 / 磁盘 IO / TCP 连接数 / **GPU 通过 `nvidia-smi`**）
- 未知 / 可疑账户清理（动态加载 `netapi32.dll`，四重兜底防锁死）
- 服务与驱动后门扫描（`EnumServicesStatusEx` + `QueryServiceConfig`）
- 浏览器劫持检测（主页策略 + 可疑扩展）
- ARP 欺骗 / DNS 劫持检测（`GetIpNetTable`）
- 计划任务持久化、进程注入、快捷方式劫持、勒索诱饵蜜罐
- COM 劫持 / SilentProcessExit / IFEO 镜像劫持
- 防火墙规则篡改、端口代理/隧道、安全事件日志审计（wevtutil）
- hosts 文件审计、WMI 事件订阅持久化、剪贴板监控

### 内核驱动（`zz_edrdrv`，独立组件）
进程创建回调（可拦截）、镜像/DLL 加载、线程创建、注册表回调、**对象回调自保护（ObRegisterCallbacks）**、**微过滤文件驱动（FltRegisterFilter）**、强制删除、进程终止、事件环形缓冲 + IOCTL 通道。

### 漏洞情报订阅（v13.23 新增）

按"1 个必盯 + 1 个底座 + 1 个自定义订阅"搭建，不做全量堆砌：

| 层 | 源 | 用途 |
|---|---|---|
| **必盯** | CISA KEV（已知在野利用目录） | 数量极少但条条要命，是"现在就得修"的最高信号 |
| **底座** | NVD RSS + NVD API 2.0 | 全量 CVE 底座，提供 CVSS 用于判断严重性 |
| **自定义** | `vulnCustomUrl`（可留空） | 国内 CNNVD/CNVD、奇安信/360/腾讯/Seebug 等导出的 CVE 编号列表 |

**KEV 的核心作用不是"多一条情报"，而是处置升级**：命中某个 CVE 时若它同时
在 KEV 中，说明攻击者已在实战使用，程序会把风险拉满（10）、告警升到最高级，
并**强制隔离**（不再受激进模式开关限制）。

> 关于国内源：CNNVD / CNVD 官方**未提供稳定的可机读公开 feed**（页面需登录
> 或验证码、无 RSS），因此本程序不硬编码死链——那只会造成"每次更新都失败"
> 的假象。改为提供 `vulnCustomUrl` 配置项，支持最简格式（纯文本每行一个
> CVE 编号），用户从周报或聚合平台导出后填入即可。

配置项：

```json
"vulnIntelOn": true,      // 总开关
"vulnCvssThresh": 9,      // NVD 高危判定阈值（CVSS ≥ 该值入高危库）
"vulnCustomUrl": ""       // 自定义订阅源，留空则只拉 KEV + NVD
```

启动时先读本地缓存（保证离线可用），再后台拉取更新；拉取失败会明确记日志
并继续使用旧缓存，**不会静默失败**。

### 其它
- **VirusTotal 在线核查**：配置 `vtApiKey` 后启用，未配置则跳过并记录日志
- **日夜主题切换**（自绘控件，配置持久化）
- **主界面危险指示**：顶部常驻 ⚠️ 横幅，安全/可疑/危险三态，跨线程安全刷新
- **系统还原点**：操作前自动创建，配套一键自救链（还原点 → Defender → MRT → SFC → DISM）

---

### 统一威胁处置链（v13.24 新增）

命中"确认有害"后执行固定五步，**顺序不可颠倒**：

| 步骤 | 动作 | 为什么必须这个顺序 |
|---|---|---|
| 1 | 挂起进程 | 冻结内存，转储期间状态稳定 |
| 2 | **内存转储** | **必须在杀进程之前** — 进程一死，解密后的 payload、C2 地址、注入代码全部消失 |
| 3 | 终止进程 | 止血，阻止继续破坏 |
| 4 | 隔离（可逆） | `CopyFile` + `.meta` 记录原路径，误报可一键还原；**不直接删除** |
| 5 | 静态分析 + 系统通知 | 出报告并发托盘气泡：`发现可疑文件，疑似<类别>，已自动隔离至备分区` |

受保护路径（系统目录 / 自身）一律拒绝处置；`sev < 2` 仅记录不处置。
配置项：`dumpOn`（转储）、`notifyOn`（通知）。

### 历史 IoC 保留策略（v13.24）

**旧 IoC 不剔除，新旧一律生效。** 直觉上"过期情报该淘汰"，实战恰恰相反：攻击者会
故意复用早已曝光的基础设施，因为多数防护产品按新鲜度淘汰旧情报，老 C2 反而成了盲区。
正常软件不会去连被公开点名的 C2，因此"命中历史 IoC"本身就是强信号。

可靠度分两级（避免误报）：
- **域名命中** — 可靠度最高。域名由攻击者持有，不会像 IP 那样被运营商回收再分配。
- **IP 命中** — 可靠度高，但 VPS 的 IP 存在回收可能，日志会标注便于人工复核。

配置项：`legacyIocOn`（默认 `true`）。

## 响应式界面布局（v14.10 新增）

按钮坐标**不再写死**。原先每个按钮都是 `CreateButton(p, 文本, IDC, x, y, w, h)`，
x/y 按容器固定宽度 880 排布；一旦窗口变窄（小屏、系统缩放 125%~150%、远程桌面低
分辨率），写在 x=420 之后的按钮会被容器裁掉，既看不见也点不到。

现在改为 **行 + 期望宽度**：

- 同一行的按钮等宽排布，列数由可用宽度算出
- 放不下 2 列，或列间距被压到小于 8px → **整行自动切换为竖向**，每个按钮铺满可用宽度
- 混排行（如「按钮 + 标签 + 输入框 + 按钮」）保留相对坐标；宽度不够时整行同样转竖向
- 窗口 `WM_SIZE` 时重算：只 `MoveWindow` 不重建控件，因此不闪屏、不丢状态
- 内容变高后由页面滚动条容纳（页面本就有滚动）

为什么不按比例缩放：190px 的按钮在窄屏上缩成 90px 会把中文标题截断；
减列转竖向保住了按钮的可读宽度，代价只是多占纵向空间。

布局器相关函数：`LayBegin / LayRowBegin / LayBtn / LayBtnAt / LayApplyAll`。

## 架构

```
┌──────────────────────────────────────────────┐
│                 ZZ_EDR.exe                   │
│  ┌──────────┐  ┌────────────┐  ┌──────────┐ │
│  │  主界面  │  │  扫描引擎  │  │ 恢复页   │ │
│  │ 危险横幅 │  │ 分级+规则 │  │ 手动触发 │ │
│  │ 日夜主题 │  │ 族谱+启发 │  │ 各审计项 │ │
│  └──────────┘  └────────────┘  └──────────┘ │
│  ┌──────────────────────────────────────────┐│
│  │  后台守护线程（LaunchBg，全部异步）       ││
│  │ 扫描 / 用户 / 资源 / 蜜罐 / 告警确认    ││
│  └──────────────────────────────────────────┘│
│  ┌──────────────────────────────────────────┐│
│  │  告警确认（PostMessage → UI 三选框）      ││
│  │  配置 HMAC / 还原点 / 自修复             ││
│  └──────────────────────────────────────────┘│
└──────────────────────┬───────────────────────┘
                       │ IOCTL  \\.\zz_edrdrv
                       ▼
┌──────────────────────────────────────────────┐
│              zz_edrdrv.sys (WDM)             │
│  PsSetCreateProcessNotifyRoutineEx            │
│  PsSetLoadImageNotifyRoutine                  │
│  CmRegisterCallbackEx                         │
│  ObRegisterCallbacks                          │
│  FltRegisterFilter                            │
└──────────────────────────────────────────────┘
```

**设计要点**：所有耗时操作走后台线程；跨线程刷新 UI 一律 `PostMessage`（不跨线程碰控件）；`netapi32 / winhttp / amsi / srclient / mf / ntdll` 等均**动态加载**（`LoadLibrary`），缺失时优雅降级而非崩溃。

---

## 编译

### 环境要求
- Windows 10 / 11（x64）
- **MSVC**（Visual Studio 2019+ 或 Build Tools），需含 Windows SDK
- 无需第三方库，全部 API 来自系统 DLL

### 一键编译
双击 `一键编译.bat`，脚本会：
1. 自动定位 MSVC（`vswhere`），找不到则提示配置环境变量
2. 编译 `ZZ_EDR.cpp` → `ZZ_EDR_v14.39.0.0.exe`
3. 剥离调试信息、计算 SHA-256 写入 `sha256.txt`
4. 确认 `zz_EDR.cfg.json` 存在

```bat
:: 或手动编译
cl /std:c++17 /O2 /MT /W3 /GS /guard:cf /CETCOMPAT ^
   /D_WIN32_WINNT=0x0A00 ^
   /DVER_MAJOR=14 /DVER_MINOR=4 /DVER_PATCH=0 /DVER_BUILD=0 ^
   ZZ_EDR.cpp ^
   user32.lib comctl32.lib gdi32.lib advapi32.lib ^
   psapi.lib iphlpapi.lib crypt32.lib shell32.lib shlwapi.lib winmm.lib ^
   /Fe:ZZ_EDR_v14.39.0.0.exe
```

> **说明**：`iphlpapi / psapi / crypt32 / comctl32 / advapi32 / winhttp` 同时在源码中以 `#pragma comment(lib,...)` 声明，链接时自动带入。

### Linux 离线校验（仅用于语法检查，非真机验证）
仓库根目录可保留 `probe_project.py` 等核查脚本，配合桩头在 Linux 下做语法/类型检查；**真实 Win32 行为必须在 Windows + MSVC 下验证**。

---

## 配置（`zz_EDR.cfg.json`）

47 个字段，与 `Config::Load / Save` 完全对应。关键项：

| 字段 | 默认 | 说明 |
|---|---|---|
| `version` | `14.17.0.0` | 配置文件版本，自动迁移 |
| `advAggressive` | false | 激进模式（自动处置） |
| `escapeMode` | false | **紧急逃生模式**（最高级：命中任意规则即终极查杀+多遍覆写，不自动还原） |
| `advHeuristic` | true | 启用启发式 |
| `variantOn` | true | 派生类/变种检测 |
| `alertAskOn` | true | 处置前弹确认框 |
| `selfRepairOn` | true | 启动限制自修复 |
| `selfDefenseOn` | — | 自我保护 |
| `canaryOn` | — | 勒索诱饵蜜罐 |
| `lnkScanOn` / `comHijackOn` / `taskScanOn` / `wmiScanOn` / `clipGuardOn` / `hostGuardOn` / `dlGuardOn` / `resGuardOn` / `immunizeOn` / `netAuditOn` / `lsassGuardOn` / `fimOn` | — | 各审计模块开关 |
| `camOn` / `micOn` | false | 虚拟化摄像头/麦克风（需配套驱动组件） |
| `vtApiKey` | 空 | VirusTotal API Key，空则跳过在线核查 |
| `scanIntervalMs` | 5000 | 扫描间隔 |
| `resCpuThresh` / `resGpuThresh` / `resMemMB` / `resIoMB` / `resConnThresh` | — | 资源异常阈值 |
| `backupPath` | — | 备份目录 |
| `themeDark` | — | 日夜主题 |
| `password` | — | 配置加密口令 |

> ⚠️ **不要把含真实 `vtApiKey` / `password` 的 `zz_EDR.cfg.json` 提交到公开仓库**——已在 `.gitignore` 中排除。建议提交一份 `zz_EDR.cfg.example.json` 作为模板。

---

## 使用流程

1. **以管理员身份**运行 `ZZ_EDR_v14.39.0.0.exe`
2. 首次运行会自动创建系统还原点、部署蜜罐诱饵（若开启）
3. 概览页查看实时危险等级（🟢 安全 / 🟡 可疑 / 🔴 危险）
4. 按需执行：全盘扫描、开机扫描、沙箱分析、各专项审计（恢复页）
5. 发现威胁 → 三选确认框决定处置方式
6. 可疑项被隔离到 `zz_EDR_quarantine/`，可从恢复页还原

### 推荐验证步骤（首次部署）
```powershell
# 1. 建测试账户验证账户清理检出
net user backdoor$ /add

# 2. 跑一次资源异常扫描看输出是否合理

# 3. 造一个被占用文件测试免疫处置

# 4. 确认无误后再开激进模式
```

---

## 驱动组件（`zz_edrdrv`）

> 位于独立目录/仓库，本仓库 `ZZ_EDR.cpp` 仅实现**用户态扫描引擎**。

- 源码：`zz_edrdrv.c`（WDM 原生 NT 驱动）、共享头 `zz_edrdrv.h`
- 编译：Windows + WDK，**选 WDM Empty 工程**（不要选 KMDF）
- 加载：
  ```bat
  bcdedit /set testsigning on          :: 启用测试签名（重启）
  sc create zz_edrdrv type= kernel start= demand binPath= C:\...\zz_edrdrv.sys
  sc start zz_edrdrv
  ```
- IOCTL 通道：`\\.\zz_edrdrv`，命令 PING / SET_RULES / GET_EVENT / FORCE_DELETE / KILL_PID / SELF_PROTECT
- ⚠️ 出厂策略保守：仅 `BlockOfficeChild` 与自保护默认开启，`BlockPersistence` / `FileGuard` 默认关闭——先在虚拟机跑通再逐项打开
- ⚠️ 修改内核有进不去系统的风险，**保留安全模式 / PE 回退手段**

---

## 安全补丁核查（v14.35/14.37 新增）

按 build.UBR 精确判定关键安全补丁是否已安装，不依赖任何外部命令或 COM 组件。

判定依据：Windows 累积更新是累积的，UBR（Update Build Revision）严格单调递增，
因此「当前 UBR >= 该补丁目标 UBR」等价于已安装该补丁。

内置 2026-09 真实补丁基线：

| KB | 目标版本 | 修复的在野漏洞 |
|---|---|---|
| KB5124008 | 26100.9445 / 26200.9445 | CVE-2026-81963（Windows Update Stack 提权）、CVE-2026-85880（ALPC 堆溢出，可从 AppContainer 逃逸） |
| KB5122880 | 22631.7582 | 同上两个在野零日（23H2） |
| KB5124012 | 28000.2954 | CVE-2026-85921（26H1） |
| KB5129195 | 26100.9457 / 26200.9457 | CVE-2026-62721（User-Mode Power Service 提权，带外更新） |
| KB5124007 | 26100.9441 | 服务堆栈更新（SSU） |

同时检查：版本是否临近或已过支持终点（EOL）、上次成功安装更新的时间、
自动更新是否被组策略禁用。

命令行：`ZZ_EDR.exe patch`
界面：扫描页「安全补丁核查(关键KB)」
离线套件：`ZZ_EDR.exe offline` 已包含本项

说明：只报告不自动安装。补丁安装会触发重启，且历史上出现过更新本身导致故障的案例，
自动安装失误的代价大于晚几天打补丁。拿不到确切 UBR 的分支（如 Win10 22H2 ESU、
各 Server 版本）不编造数值，仅做时间戳检查。

## v14.17 新增功能

### 1. 命令行参数模式（此前参数被丢弃）

原 `wWinMain` 的第三个形参 `LPWSTR`（命令行）被写成无名参数直接丢弃，兼容入口 `main()`
又硬传 `nullptr`，**导致外部传任何参数都无效**。现统一从 `GetCommandLineW()` 取真实参数。

| 命令 | 作用 |
|---|---|
| `scan` | 全盘扫描后退出（加 `--ui` 保留界面） |
| `quick` | 快速扫描（进程/启动项/网络）后退出 |
| `emergency shield` | 最强防护：剑盾 + 坚盾 + 全部检测项开启并落盘 |
| `shield` / `sword` | 开启坚盾 / 剑盾守护模式 |
| `canary` | 部署勒索诱饵文件 |
| `usb` | 对所有可移动盘做免疫接种 |
| `integrity` | 校验自身哈希（被篡改则告警） |
| `rehash` | 以当前程序哈希重建自校验基线（升级后执行） |
| `help` | 显示用法 |

支持 `-x` `/x` `--x` 三种前缀，且**大小写不敏感**。

### 1.1 剑盾免责声明与静默处置（v14.18）

剑盾会结束所有非系统进程、改写系统策略、阻断全部外连，属于**高风险破坏性功能**。
因此设计上做了两件事：

1. **开启前必须过一次免责声明弹窗**，内容包括：
   - 剑盾将执行的全部策略；
   - 静默说明（开启后不再询问、不再弹窗，结论只进日志）；
   - **企业/IT 管控判定**：调用 `GpoIsDomainJoined` 判断是否域成员。
     若已加域，明确提示"属于企业受管机器，**第一时间联系公司 IT 支持**"，
     并说明自行清除域策略的后果由本人承担；
   - **免责声明**：列出可能造成的损失（未保存数据丢失、网络中断、合规冲突、
     需修复或重装），并声明**出现任何问题概不负责**。
2. **选择「仍要开启」后立即静默启用并禁用限制策略**：
   - 先 `GpoPolicyPolClear()` 移走策略源文件 `Registry.pol`，再改写 `Policies`
     结果键 —— 顺序颠倒的话任何一次 `gpupdate` 都会把改动刷回去；
   - 接着强制写入 Defender/更新/关机/证书/还原点/侧加载策略，并锁死摄像头、
     麦克风、定位；
   - 设置 `g_swordSilent`，使 `AlertConfirm` 一律返回"立即处理"，全程不弹窗。

命令行 `sword` 与 `emergency shield` 同样会先弹免责声明，确认后才生效；
未确认则直接放弃启用并建议联系 IT 支持。同一进程内只弹一次，避免
`emergency shield` 同时命中两个分支时重复弹窗。

配置项：`swordSilent`（默认 `true`）、`swordDisclaimer`（是否已确认过，仅审计留痕）。
重启后若配置中剑盾仍为开启状态，会自动恢复静默标志，否则静默名存实亡。

### 2. 完整性基线校验（哈希 / DNS / 响应头）

- **自身 exe 的 SHA256**：与基线不一致即告警。注意若一律判"不可用"会把用户自己重新编译的
  升级路径也堵死，所以做成**弹窗让用户判断**："我刚升级（重建基线）" 或 "判定被篡改（不可用）"。
  命令行 `--rehash` 用于非交互重建。
- **DNS 解析基线**：解析若干知名域名并记录；离线或解析失败时**跳过而非误报**。
- **HTTP 响应头基线**：对响应头做摘要比对，变化即提示疑似中间人篡改。

### 3. "你的组织限制 / IT 管控" 检测

Windows 的"你的组织限制你使用本软件""部分功能已被 IT 禁用"这类提示，来源是策略键值
（`Policies` 各子键、WDAC 的 `CI\Policy`、AppLocker/SRP），没有单一 API 能问出来。
现枚举这些策略源，命中即提示并**询问是否处理**——**不静默清除企业策略**（域管机器上属合规要求）。

### 4. Windows 版本 / 篡改检测

版本来自可写注册表，本身也是攻击面。做两件事：
(a) 交叉核对 `ProductName` 与 `EditionID` 是否自相矛盾；(b) 与本机上次基线比对。
**自动改写版本键值会导致激活失效、升级故障，故只告警不改写。**

### 5. 霸屏拦截

判定"可见 + 覆盖整屏 + `WS_EX_TOPMOST` + 非系统目录 + 非本程序"。全屏游戏/播放器同样满足
前两条，故**首次一律询问**；用户确认后取消其置顶并加入名单，之后自动阻止不再询问。

### 6. PowerShell / 命令行启动拦截

- 命中**下载类**特征（`certutil -urlcache`、`bitsadmin /transfer`、PowerShell
  `DownloadString`/`Invoke-WebRequest`/`iwr`、curl/wget 带 http、`msiexec http`、
  `regsvr32 scrobj` 等）→ **直接判定恶意**，不询问。
- 命中**命令行宿主**（powershell/pwsh/cmd/wscript/cscript/mshta）→ **弹窗询问**后处置。
  只对新出现的进程生效，且跳过系统目录，避免刷屏误伤。

### 7. C2 连接即恶意

取带 PID 的 TCP 表，远端 IP 命中情报库即处置（不询问）。为避开 `tcpmib.h` 在不同 SDK 上的
包含差异，这里**自带结构体布局并动态取函数地址**，零头文件零 lib 依赖。

---

## 版本

当前 **v14.39.0.0**。版本号在源码与脚本中保持一致：


> **v14.39.0.0（路径策略统一 + 深度扫描改递归 + 三项持久化面审计）**

> **① 路径策略：程序侧相对、系统侧绝对。**
> 程序自己的数据（配置 / 撤销栈 / 报告）一律以 **exe 自身所在目录**为基准拼
> ——即"相对路径"：整体拷到 U 盘、换盘符、改文件夹名都能继续用。此前有 9 处
> 直接写 `g_cfg.Save(L"zz_EDR.cfg.json")`，那是**依赖"当前工作目录"**的裸相对路径；
> 本程序会被开机自启、计划任务、右键菜单等多种方式拉起，每次工作目录都可能不同，
> 结果就是"在这里存、在那里读"，设置看着像丢了。现统一走 `CfgDefaultPath()` /
> `AppRelPath()`。系统侧（Windows / System32 / Program Files / ProgramData /
> Public / Temp）一律用 API 现取**绝对路径**，不再写死 `C:\...`：系统盘未必是 C:，
> 目录也可能被重定向到别的盘，写死会指向不存在的目录，表现为"扫了但一个文件都没扫到"。

> **② 深度扫描此前几乎没扫到东西——它根本不递归。**
> 原 `DeepFullScan()` 用 `FindFirstFileW(dir + "\\*")` 只取**顶层文件**，四个目录
> 各扫一层就结束，而载荷几乎都藏在子目录里；且只比对哈希情报，没用上
> `FileScanOneFile` 里已有的整套规则（勒索后缀 / 哈希命名 / 签名伪造 / 双扩展名 /
> 进程名仿冒），同一套检测被写成两份；覆盖面也漏掉了 Program Files、ProgramData、
> 下载、桌面、启动文件夹、计划任务——恰恰是投放最集中的位置。现改为**递归遍历**
> （默认 3 层、自定义 5 层）+ 复用 `FileScanOneFile` + 目录面大幅扩展 + 文件预算控制，
> 并跳过 WinSxS / Installer / SoftwareDistribution 这类巨大且与安全无关的目录。

> **③ 新增三项持久化面审计**（此前完全没覆盖的缺口）：
> - **启动文件夹**：注册表 Run 早就在扫，但把快捷方式往 `shell:startup` 一丢同样能
>   开机自启，且**不写任何注册表**，注册表扫描完全看不到。四个 startup 目录全扫。
> - **计划任务定义**：存在 `System32\Tasks` 下，是**无扩展名的 XML 文件**，按扩展名
>   过滤的扫描器天然扫不到。提取 `<Command>`，指向可写目录或 LOLBins 即报。
> - **WMI 事件订阅**：恶意逻辑存进 CIM 数据库（`System32\wbem\Repository`），不落可
>   执行文件、不写注册表，文件与注册表两个维度**都扫不到**。查 `root\Subscription`
>   的 `__EventFilter` / `__FilterToConsumerBinding` / `CommandLineEventConsumer`。
   只有"过滤器+绑定"同时存在才算会被真正触发的订阅。

> 入口：扫描页**「持久化面审计(启动/计划任务/WMI)」**按钮、命令行 `persist`、
> 其中本地两项（启动文件夹 + 计划任务）已纳入 `offline` 离线套件。
> **v14.28.0.0 修复（变更台账：恢复页面加"恢复所有更改"）**
> 此前"撤销/回滚"只覆盖剑盾写过的 DWORD，且**台账是纯内存 vector，重启即清空**——
> 等于改完就再也恢复不了。而真正让人头疼的几处改动全都**没留痕**：
> `GpoPolicyPolClear()` 移走的 `Registry.pol`、系统修复用 `RegDeleteTreeW` 删掉的
> Defender 策略键树、`ChangeServiceConfigW` 改的 WinDefend 启动类型、被重命名成
> `.old` 的 `SoftwareDistribution`/`catroot2`、U盘免疫建的 `autorun.inf` 目录。
> 想还原只能手动去注册表里翻，正是本次要解决的问题。
> 现已：①台账**落盘持久化**（`zz_EDR_undo.dat`，启动时 `UndoLedgerLoad()`）；
> ②新增三类可自动还原的记录——`SK_UNDO_REGEXPORT`（删键树前先 `reg export` 出
> `.reg`，撤销时 `reg import` 导回）、`SK_UNDO_SVCCFG`（改服务前先
> `QueryServiceConfigW` 读出原启动类型，撤销时还原）、`SK_UNDO_DIRCREATE`（撤销时
> 清属性后删目录）；③回滚页新增**「恢复所有更改(全量)」**与**「查看更改清单」**两个按钮；
> ④台账万一被删，仍按 `.zzedr.bak` 这个本程序专属后缀兜底把组策略源移回原位。

> **v14.25.0.0 修复（面板输入只写不挂钩）**
> 全项目 7 个输入框中，有 4 个**创建后从不读取其值**——用户在框里输入的内容一点
> "应用"就丢，形同虚设：`IDC_CB_SCAN_TYPE`（扫描类型）、`IDC_CB_CAM_FILE`、
> `IDC_CB_MIC_FILE`、`IDC_CB_EMG_PWD`（紧急密码）。同时这些框的初值**硬编码**
> （固定 `L"5000"` / `L"0"` / 空串），不取 `g_cfg`，导致重启后显示旧值，
> 一点"应用"又把已保存的配置刷回去。
> 现已：①初值改为读 `g_cfg`；②`ApplyConfig()` 新增 `ApplyReadEdit` / `ApplyReadEditInt`
> 统一读取 5 个框，**取到空串时不覆盖**（摄像头/麦克风面板默认隐藏，隐藏时
> `GetWindowTextW` 返回空，若照样写回会把用户用"浏览"选好的路径清掉）；
> ③`scanType` 此前是死配置（Load/Save 齐全但业务从不使用），现按语义在
> `DeepFullScan()` 生效：0=快速（跳过 System32）/ 1=全盘 / 2=自定义（每目录上限放宽至 1200）。


- `ZZ_EDR.cpp`：`VER_MAJOR=14 / VER_MINOR=28 / VER_PATCH=0 / VER_BUILD=0`、`APP_VERSION`、`APP_TITLE`
- `zz_EDR.cfg.json`：`version`
- `Build.bat` / `一键编译.bat`：`/DVER_MAJOR=14 /DVER_MINOR=33 /DVER_PATCH=0 /DVER_BUILD=0` 与产物名 `ZZ_EDR_v14.39.0.0.exe`

> 发版请用 Git tag（`v14.39.0.0`）并上传 Release 附编译产物；**不要将 `.zip` 发行包提交进仓库**（已在 `.gitignore` 排除）。

---

### 漏洞利用防护与基线加固

- **进程缓解策略审计** — 检查 ASLR / DEP / CFG / 禁止动态代码四项缓解措施是否开启。
  攻击入口程序(浏览器、Office、PDF、脚本宿主)缺防护会单独标为高危。
  查询失败记为"未知"而非"未开启", 避免误报。
- **凭据防护基线** — 审计 LSASS 保护(PPL)、WDigest 明文缓存、CachedLogonsCount、
  匿名枚举限制等六项, 从环境上让 Mimikatz 类工具失效, 而非只查杀进程名。
- **网络共享与自动播放审计** — 枚举 SMB 共享(识别整盘共享等高危配置)与
  自动播放策略。`NoDriveTypeAutoRun` 是**位掩码**而非布尔值, 按 bit2
  (DRIVE_REMOVABLE=0x04) 判定, 避免得出相反结论。

## 已知边界

- **GPU 监控仅支持 NVIDIA**（走 `nvidia-smi`，非 NVML/CUDA Driver API），AMD/Intel 未覆盖
- **CPU 为单核口径**：8 核机器上 800% 才是满负荷，阈值 `resCpuThresh` 需按机器调整
- **网络仅统计 TCP 连接数，无字节流量**（精确带宽需 ETW/NDIS 驱动级）
- **DNS 白名单硬编码**（114/223/8.8/1.1/119.29/180.76/内网段），企业自建 DNS 需自行扩展
- **仅覆盖 Chrome / Edge / IE**，Firefox 的 `prefs.js` 未扫
- **计划任务读 XML 实现**（非 COM），任务缓存注册表残留不在范围
- **行为时间线二级窗口未纳入日夜主题**
- **触发点尚未全部接入 `SetThreatLevel`**（目前接隔离与哈希命中；规则命中/CVE/挖矿/资源异常的自动升危待补）
- **各项审计默认手动按钮触发**，未全部接入全链扫描自动调度（蜜罐、用户、资源守护为自动）
- **能力族谱规则基于 MITRE ATT&CK 公开特征**，未在真实大规模样本集上验证——先扫正常程序确认无误报

详见各提交记录与安全公告。

---

## 目录结构

```
zz_EDR_clean/
├── ZZ_EDR.cpp            # 主程序（单文件，~9800 行）
├── zz_EDR.cfg.json       # 配置（47 字段，已 gitignore）
├── 一键编译.bat          # 一键编译脚本
├── .gitignore
└── README.md
```

---

## 许可证

仅供安全研究与个人学习使用。使用本工具造成的任何系统损坏、数据丢失或业务中断，**作者与仓库维护者不承担任何责任**。请勿用于未授权扫描或攻击。

---

## 免责声明

本工具**不收集、不上传任何用户数据**。VirusTotal 核查仅在用户主动配置 `vtApiKey` 后启用，上传内容由用户自行承担合规责任。族谱库与规则为本地静态特征，更新需手动同步。

## 银狐(SilverFox / Winos4.0 / ValleyRAT) 专项 — v13.19

情报来源（公开权威）：国家计算机病毒应急处理中心通报、微步在线「银狐」情报共享站
(https://s.threatbook.com/cybercrime/silverfox)、Cato CTRL、CheckPoint、奇安信天穹、
亚信安全、360、CloudSEK、Rapid7。

| 检测维度 | 覆盖内容 |
|---|---|
| 社工诱饵文件名 | 违纪/违规/裁员/补偿/通报/内职/稽查/补贴/公示…；`xxx名单pdf.exe` 伪装判高危 |
| 侧载载荷 DLL | xpsplog/libcef/libcurl/UxEnhance64/d3dcompiler_74/icsvcext/PDFCORE8/libexpat/sqlite3… |
| 白程序宿主 | CEFProcess/ConvertToPDF/PDFDirect/Thunder/GDFInstall/irsetup/wsctrlsvc/ion |
| BYOVD 驱动 | amsdk.sys、wsftprm.sys、BootRepair.sys、EnPortv.sys（用于终止杀软/EDR） |
| C2 | 23 个域名 + 31 个 IP + 端口 18852/8852/670/8670/521xx/9527-9528/6074-6076/8888 |
| 投放路径 | ProgramData\CfServerSoftwareDistribution、Windows\Installer、msys64、ProgramLog、aff-web |
| 对抗手法 | Defender 整盘排除项、Python 化载荷(.pyc/.pyd 落在非 Python 目录) |

配置 `foxIntelUrl` 可填入自建 IoC 订阅地址（如从微步导出的列表），留空则仅用内置表。

> 说明：内置 IoC 为公开报告中出现过的历史指标，**基础设施轮换极快**（微步共享站每日更新、
> 累计 6000+ 条）。生产环境请配合情报订阅使用，历史 IoC 仅作 hunting 线索。

## 剑盾数据看板 (v14.19)

剑盾守护模式开启后**自动弹出**；也可在「进程」页点「数据看板」手动打开。

### 采集的数据（23 列）

| 类别 | 字段 |
|---|---|
| 标识 | 新增标记、PID、父 PID、进程名、映像路径、命令行 |
| 性能 | CPU%、工作集、私有提交、线程数、句柄数 |
| 网络 | TCP/UDP 连接数 |
| 能耗 | 能耗指数（CPU+IO 加权估算） |
| IO | 读字节、写字节 |
| 安全 | 会话 ID、完整性级别、位数、优先级、运行用户、签名状态 |
| 其他 | 启动时间、窗口标题 |

顶部概览条：全局 CPU、内存、磁盘、网络速率、进程/线程/句柄总数、开机时长、电源状态、Windows 版本。

### 操作

- **点击列头**排序，再点一次切换升序/降序
- **右键进程**：结束进程 / 强制结束（无视保护）/ 结束进程树 / 内存转储 / 隔离文件 / 打开文件位置 / 验证签名 / 复制命令行 / 属性详情
- 新增进程自动置顶并标记 NEW（可关闭）
- 刷新间隔 1/2/5 秒可调，可暂停
- 导出 CSV（带 UTF-8 BOM，Excel 直接打开不乱码）
- 「系统信息」窗口：CPU/内存/磁盘/电源/显示/网络适配器/域状态等系统级数据

### 已知边界

1. **CPU 占用率需要两次采样**：`GetProcessTimes` 返回的是累计 CPU 时间，首轮无基线时显示 0。
2. **能耗指数是估算值**：Windows 没有公开稳定的每进程功耗接口，该列仅用于排序比较，不代表真实瓦数。
3. **进程级只给连接数，不给收发字节**：`GetPerTcpConnectionEStats` 需先 `Set` 启用才能读，对陌生进程启用属于副作用；全局收发速率在顶部概览条给出。
4. **强制结束核心进程会蓝屏**：对 csrss/smss/wininit/winlogon/lsass 会先弹确认说明后果，其余进程不再阻拦。
5. 看板为采样视图，两次刷新之间启动又退出的短命进程可能采集不到。

## v14.22 —— Win10 / Win11 双路径 API 层

过去各模块一律"能用就用、不能用就降级", 等于按最低公分母写代码: Win10 上跑不了的新 API
全部放弃, Win11 上能用的强 API 也从来没启用过。本层先查清"这台机器是哪一代", 再让每个
模块按版本挑最强的那个 API。

三级判定, 逐级收紧:
1. build 达标 (官方最低要求) —— 反例: MFCreateVirtualCamera 在 Win10 的 mf.dll 里也能解析到名字, 但调用必失败
2. 导出存在 (GetProcAddress 拿得到地址) —— 只看 build 会在精简版系统上调用到不存在的函数
3. 实测调用 —— 部分项真跑一次, 证明不只是"存在"而是"能返回合理值"

| 功能 | 新路径 | 次选 | 兜底 |
|---|---|---|---|
| 进程架构 | IsWow64Process2 (Win10 1709) | IsWow64Process | 指针宽度 |
| DPI | GetDpiForWindow (1607) | GetDpiForSystem | GetDeviceCaps (96) |
| ETW 启用 | EnableTraceEx2 (1703) | EnableTrace | 无 |
| 线程名 | GetThreadDescription (1607) | — | 空 |
| 能耗 | ProcessEnergyValues (76, 1703) | — | 估算 |
| 节能节流 | SetProcessInformation (22, 1703) | — | 不节流 |
| 进程枚举 | NtQuerySystemInformation (148) | (57) | (5) |
| 缓解策略 | GetProcessMitigationPolicy | — | 不判 |

命令行 `ZZ_EDR.exe osapi` 输出实测表 (含导出是否解析到 + 真调结果); UI「系统信息」展示同一张表。
看板能耗列带 `*` 表示系统给的真实能耗, 不带则是估算值 —— 两者量纲不同, 不混为一谈。

## v14.39.0.0 修复（接线核查 + 两个致命缺陷）

本轮对全项目做了一次"定义了但没挂钩"的接线核查（652 个函数定义、
209 个控件 ID、94 个配置字段），查出并修复四类问题：

1. **致命：关闭窗口后进程退不掉**。`case WM_DEVICECHANGE` 标签被误插进了
   `case WM_DESTROY` 的函数体内部，而 case 标签只是跳转点、不阻断执行流，
   于是 WM_DESTROY 会 fall-through 进 U 盘分支并在 `return TRUE` 处返回，
   `ThemeFreeRes()` / `PostQuitMessage()` 永远执行不到。已补回闭合。
2. **致命：11 个页面只能看到第 1 个**。主窗口 `MainWndProc` 完全没有
   `WM_NOTIFY` 分支，Tab 建好了但点击标签没有任何处理，`ShowPage` 全项目
   只在初始化时被调用过一次。已新增 `TCN_SELCHANGE` → `ShowPage(idx)`。
3. **`foxIntelUrl` 是死字段**：cfg.json 里有值，cpp 既没声明也没 Load/Save
   更没使用。已补为第二个自定义情报源（与 vulnCustomUrl 并存，主源挂掉时
   备用镜像仍能拉到，落盘文件名分开写，不互相覆盖）。
4. **清理死代码**：`DeleteFileWWrapper`（零调用，且只是 DeleteFileW 的等价
   包装，属重复轮子）、`IDC_CB_PROC_KILL_4568` / `_9912`（早期硬编码测试
   pid 残留）。

核查结果：函数零调用 0 个、控件创建无挂钩 0 个、配置字段缺 Load/Save 0 个、
编译零新增错误、UI 重叠越界 0 处。

## v14.31 —— 离线能力增强（新增 4 项，全程不联网）

### 为什么必须做离线能力

在线情报（CISA KEV / NVD / 风险 IP / 威胁情报）全部依赖网络。而机器真正失陷时，
病毒往往会主动断网、劫持 DNS、或把安全站点写进 hosts 黑名单 ——
**"最需要检测的时机，恰好是情报源全部失效的时机"**。

以下 4 项只读取本机数据（进程列表 / 注册表 / 证书存储 / 进程名），
断网、被劫持、刚装机未更新，都能照常工作。

### ① 系统进程路径仿冒检测（`ProcMimicAudit`）

真正的 `csrss` / `lsass` / `svchost` 只可能位于 `System32`（或 `SysWOW64`）。
病毒最经典的伪装就是把恶意程序改名成 `svchost.exe` 丢在 `Temp` 或 `AppData` 下运行 ——
**只看"进程名对不对"必然被骗，必须连路径一起校验**。

- 20 个系统进程名强制校验路径，合法位置仅 `System32` / `SysWOW64`
- `explorer.exe` 强制校验位于 Windows 根目录
- **西里尔同形字检测**：用 `а/е/о/р/с/х`（U+0430 等）替换拉丁字母，
  肉眼几乎无法分辨，是高级木马常用的伪装手法

### ② UAC 绕过注册表劫持审计（`UacBypassAudit`）

UAC 绕过**不写任何自启动项**，所以常规"启动项扫描"完全看不见它：
它只是往 `HKCU\Software\Classes` 下写几个键，让 `fodhelper` / `eventvwr` 等
微软自 elevate 的程序启动时去执行攻击者命令。

覆盖 7 个经典劫持点（`ms-settings`、`mscfile`、`Folder\IsolatedCommand`、
`exefile\runas` 等）。这是此前唯一没有覆盖的持久化面。

### ③ 冒充微软的伪造根证书检测（`RootCertAudit`）

v14.15 修过"病毒伪造微软签名"这条绕过链：攻击者自签一张 Subject 写着
`Microsoft` 的根证书并导入本机信任库，之后由它签出的恶意程序在"签名有效"
判据下会被放行。这里**从源头查** —— 遍历本机 ROOT 证书库，凡声称 Microsoft
但指纹不在微软真实根白名单内的，一律判伪造。

指纹是证书内容的哈希，攻击者造不出哈希相同的证书。

### ④ 已知攻击工具名 / IOC 特征库（`HackToolAudit`）

内置 32 个公开知名的攻击与渗透工具名。

> **诚实说明**：这是**名称特征，重命名即可绕过**，因此只登记为 WARN 线索，
> 不作为定罪的唯一依据。真正可靠的是哈希，但哈希必须来自真实样本提取；
> 本程序**刻意不内置未经核实的哈希值**，以免制造永不命中或误伤正常文件的假数据。

### 使用方式

- UI：进程扫描页新增 5 个按钮（进程仿冒 / UAC 绕过 / 伪造根证书 / 攻击工具名 / 离线套件全执行）
- 命令行：`ZZ_EDR.exe offline`

## v14.39.0.0 新增（打开方式劫持检测：独立入口 + 纳入离线套件）

打开方式/文件关联劫持此前只有剑盾巡检会跑（`SwordFileAssocGate`），**没有独立按钮也没有命令行参数**，
不开剑盾则一次都不会执行。本版补齐入口。

**新增 `FileAssocAudit()`（只读审计）**

为什么不直接复用 `SwordFileAssocGate`：后者是门禁，命中即清除 `UserChoice` / 改写 `HKCR` 默认值，属写操作；
用户手动点「检测」不该悄悄改掉自己的文件关联。因此做纯只读版本，完全复用 `SwordAssocCommand` /
`SwordAssocImage` / `SwordAssocSuspect` / `kSwordAssocStd`，只报告不修改。

**分两级输出**

| 级别 | 判据 | 含义 |
|---|---|---|
| 高危 | 指向可写目录 或 指向 LOLBins（powershell/wscript/rundll32 等）且非微软签名 | 典型劫持 |
| 提示 | 实际 ProgId 与系统标准 ProgId 不一致 | 不定罪，交用户判断 |

第二级的必要性：攻击者若把恶意程序放进 Program Files 并签上名，第一级会放行。
「提示」级同时说明——正常软件（WPS、记事本替代品、播放器）改关联也会命中，需自行判断。

**三个入口**

1. 进程扫描页按钮「打开方式劫持检测(离线)」
2. 命令行 `ZZ_EDR.exe assoc`（或 `fileassoc`）
3. 纳入离线检测套件 `ZZ_EDR.exe offline`（不依赖网络）

**顺带修复的检出缺口**

`C:\Windows\Temp`、`Tasks`、`debug`、`tracing`、`System32\Tasks` 这些子目录**普通用户即可写入**，
是恶意程序的经典投放点；原判据因父目录是 Windows 而整体豁免，导致劫持到这些目录时漏检。
现改为先排除这些热目录再走保护路径豁免。
