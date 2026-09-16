# ZZ-EDR
A practical program that can protect your computer.
# ZZ EDR
本项为实验性研究，如果造成任何不良影响或不良后果，由运行者负责，与仓库运营者及代码作者无关，如果发现了问题，欢迎通过邮件来向我们反馈
> 单文件、无依赖的 Windows 终端安全检测与应急响应工具。一个 `.cpp` 编译成一个 `.exe`，覆盖病毒查杀、行为审计、持久化清理、勒索防护、内核驱动等多层防御。

## ⚠️ 安全警告（务必先读）

1. **本工具会修改系统安全配置**（创建还原点、调整组策略/SRP、禁用服务、删除计划任务、清理注册表项、终止进程）。**请在虚拟机或测试机上先行验证**，确认无误后再部署到生产环境。
2. **必须以管理员身份运行**。非管理员时多数检测会失败并明确记录日志，不会静默绕过。
3. **默认只告警、不自动处置**。自动删除/禁用/终止需开启「激进模式（`advAggressive`）」；处置前会弹出**三选确认框**（是=处理 / 否=忽略 / 取消=加白名单），确认框最多等待 3 分钟超时放行。
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
- **派生类 / 变种检测**：能力族谱（MITRE ATT&CK API 序列）+ spamsum 风格模糊哈希 + PE 解析（导入表/节区熵/RWX 节）+ 本地族谱库
- **银狐 / 紫狐 / 全品类族谱**：60+ 条规则，覆盖远控、银行木马、信息窃取、勒索、挖矿、僵尸网络、蠕虫、Rootkit、无文件、下载器、键盘记录、间谍、宏病毒、引导区、凭据窃取；含**白加黑侧载 DLL 名单**（35 个）与**系统名伪装检测**
- **沙箱动态分析 / 静态分析 / 启发式**
- **隔离**：可疑文件移入 `zz_EDR_quarantine/`，支持列表管理
- **顽固病毒免疫处置**：结束占用 → `DeleteFileW` → 移出 → 重启删除 → 创建同名占位文件（覆写 1MB 随机数据）→ 设只读+系统+隐藏 → 开启超强拦截

### 告警与自愈
- **告警确认机制**：所有自动处置经 UI 线程三选确认框，支持白名单
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

### 其它
- **VirusTotal 在线核查**：配置 `vtApiKey` 后启用，未配置则跳过并记录日志
- **日夜主题切换**（自绘控件，配置持久化）
- **主界面危险指示**：顶部常驻 ⚠️ 横幅，安全/可疑/危险三态，跨线程安全刷新
- **系统还原点**：操作前自动创建，配套一键自救链（还原点 → Defender → MRT → SFC → DISM）

---

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
2. 编译 `ZZ_EDR.cpp` → `ZZ_EDR_v13.14.0.exe`
3. 剥离调试信息、计算 SHA-256 写入 `sha256.txt`
4. 确认 `zz_EDR.cfg.json` 存在

```bat
:: 或手动编译
cl /std:c++17 /O2 /MT /W3 /GS /guard:cf /CETCOMPAT ^
   /D_WIN32_WINNT=0x0A00 ^
   /DVER_MAJOR=13 /DVER_MINOR=14 /DVER_PATCH=0 ^
   ZZ_EDR.cpp ^
   user32.lib comctl32.lib gdi32.lib advapi32.lib ^
   psapi.lib iphlpapi.lib crypt32.lib shell32.lib shlwapi.lib winmm.lib ^
   /Fe:ZZ_EDR_v13.14.0.exe
```

> **说明**：`iphlpapi / psapi / crypt32 / comctl32 / advapi32 / winhttp` 同时在源码中以 `#pragma comment(lib,...)` 声明，链接时自动带入。

### Linux 离线校验（仅用于语法检查，非真机验证）
仓库根目录可保留 `probe_project.py` 等核查脚本，配合桩头在 Linux 下做语法/类型检查；**真实 Win32 行为必须在 Windows + MSVC 下验证**。

---

## 配置（`zz_EDR.cfg.json`）

47 个字段，与 `Config::Load / Save` 完全对应。关键项：

| 字段 | 默认 | 说明 |
|---|---|---|
| `version` | `13.14.0` | 配置文件版本，自动迁移 |
| `advAggressive` | false | 激进模式（自动处置） |
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

1. **以管理员身份**运行 `ZZ_EDR_v13.14.0.exe`
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

## 版本

当前 **v13.14.0**。版本号在源码三处保持一致：
- `ZZ_EDR.cpp`：`VER_MAJOR=13 / VER_MINOR=14 / VER_PATCH=0`、`APP_VERSION`、`APP_TITLE`
- `zz_EDR.cfg.json`：`version`
- `一键编译.bat`：`/DVER_MAJOR=13 /DVER_MINOR=14` 与产物名 `ZZ_EDR_v13.14.0.exe`

> 发版请用 Git tag（`v13.14.0`）并上传 Release 附编译产物；**不要将 `.zip` 发行包提交进仓库**（已在 `.gitignore` 排除）。

---

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

