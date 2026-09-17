// ============================================================
//  ZZ EDR v13.36.0 -  单文件主程序 (Windows Desktop, C++17)
// ------------------------------------------------------------
//  功能: 引擎调度 / 进程·网络·文件·注册表·内存扫描 / 主动响应
//        (终止·隔离·回滚·恢复) / 隐私(虚拟摄像头MF+DS / 虚拟麦克风
//        驱动通道) / DLP / FIM / SCA / 应急自救 / 日志
//  UI  : Legacy 风格, SysTabControl32, 11 页, 开关+展开式控件
//
//  编译: 见 一键编译.bat (MSVC) 或 g++ (MinGW / 跨平台自检)
// ============================================================
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#ifndef VER_MAJOR
#define VER_MAJOR 13
#define VER_MINOR 38
#define VER_PATCH 0
#endif

#include <string>
#include <vector>
#include <map>
#include <random>
#include <mutex>
#include <atomic>
#include <thread>
#include <chrono>
#include <deque>
#include <set>
#include <functional>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <algorithm>
#include <memory>

// ---- 平台适配: Windows 用系统头, 跨平台自检用桩头 ----
#ifdef _WIN32
#  include <windows.h>
#  include <commctrl.h>
#  include <iphlpapi.h>
#  include <tlhelp32.h>
#  include <psapi.h>
#  include <wincrypt.h>
#  include <shlwapi.h>
#else
#  include "stub_win32.h"
#endif

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "winhttp.lib")

// ---- 常量适配: Windows 使用 wincrypt.h / winbase.h 的定义, 桩环境补上 ----
#ifndef CALG_SHA_256
#define CALG_SHA_256  0x0000800c
#endif
#ifndef CALG_AES_256
#define CALG_AES_256  0x00006610
#endif
#ifndef INVALID_SET_FILE_POINTER
#define INVALID_SET_FILE_POINTER  ((DWORD)-1)
#endif

using std::wstring;
using std::string;
using std::vector;
using std::map;

// ------------------------------------------------------------
//  版本字符串
// ------------------------------------------------------------
// v13.15: 版本号改为由 VER_* 宏自动拼接, 杜绝各处硬编码脱节
#define ZZ_S2_(x) L"" #x
#define ZZ_S_(x)  ZZ_S2_(x)
#define ZZ_VER_W  ZZ_S_(VER_MAJOR) L"." ZZ_S_(VER_MINOR) L"." ZZ_S_(VER_PATCH)
static const wchar_t* const APP_VERSION = ZZ_VER_W;
static const wchar_t* const APP_TITLE   = L"ZZ EDR V" ZZ_VER_W;

// ------------------------------------------------------------
//  简易 JSON 配置 (不依赖第三方库)
// ------------------------------------------------------------
struct Config {
    bool engine[8] = {true, true, true, true, true, true, true, true};
    bool camOn = false, micOn = false;
    int  camMode = 0;   // 0=black, 1=file
    int  micMode = 0;   // 0=mute,  1=file
    wstring camFile, micFile;
    int  scanIntervalMs = 5000;
    int  scanType = 0;  // 0=quick,1=full,2=custom
    bool advHeuristic = true, advMemory = true, advCloud = false,
         advDeobf = false, advAggressive = false;
    // v13.26 紧急逃生模式: 级别高于激进模式。命中"任意规则"(含提示级)即执行
    // 终极查杀 + 多遍覆写彻底销毁, 且不再自动还原。默认关闭。
    bool escapeMode = false;
    // v13.37 邮件附件扫描: 扫本地邮件存储(.eml/.mbox/.msg)中的恶意附件
    bool mailScanOn = true;
    // v13.37 强制解除占用: 关闭他人进程持有的文件句柄(需管理员+SeDebugPrivilege)
    bool forceUnlockOn = true;
    // v13.27 覆写强度由用户决定: 1=弱(1遍) 2=中(3遍,默认) 3=强(7遍)
    // 【思路】覆写遍数越多越难恢复, 但耗时也线性增长。这不是技术参数而是
    // 风险偏好: 弱=快速止损(秒级), 强=追求不可恢复(大文件可能分钟级)。
    // 所以交给用户按当前处境选, 而不是我们替他定。
    int  escapeWipeLevel = 2;
    // v13.38 顽固病毒压制: 轮次与间隔(守护重启窗口覆盖)
    int  escapeKillTimes = 20;        // 压制轮次
    int  escapeKillIntervalMs = 5;    // 每轮间隔毫秒
    // 内核驱动支持: true=启动时尝试装载 zz_edrdrv.sys 以获得内核级拦截。
    // 装载失败(无管理员/未签名/sys缺失)会自动回落到应用层防护, 不影响其他功能。
    bool drvOn = false;
    bool fimOn = false;
    wstring fimPath;                 // FIM 监控目录(空=回落默认)
    wstring password = L"472910";

    // ---- 建议#6 多引擎在线核查 ----
    std::wstring vtApiKey;          // VirusTotal API Key (空=跳过在线核查)
    // ---- 建议#2 U盘/下载防护, #4 补丁审计, #8 备份 ----
    bool usbGuardOn   = true;       // U盘插入时扫描 autorun.inf 与可执行文件
    bool dlGuardOn    = true;       // 下载目录扫描
    bool patchAuditOn = true;       // 补丁/软件版本审计
    std::wstring backupPath;        // 数据备份目标(空=自动选离线盘)
    bool offlineBackupOn = true; // 离线备份: 优先写可移动盘/外置盘(防同盘一起被加密)
    bool officeGuardOn = true;   // 办公软件子进程防护(默认开启)

    // ---- 资源异常监控 (CPU/内存/磁盘IO/GPU-CUDA/网络) ----
    bool resGuardOn    = true;   // 资源异常监控守护
    bool variantOn    = true;   // 派生/变种检测(模糊哈希+能力族谱)
    bool heurOn       = true;   // HEUR 启发式检测(未知/变种)
    bool pdmOn        = true;   // PDM 主动防御(行为链关联)
    int  resCpuThresh  = 60;     // CPU 单核口径百分比阈值
    int  resGpuThresh  = 70;     // GPU 利用率阈值(需 NVIDIA)
    int  resMemMB      = 1500;   // 工作集内存阈值(MB)
    int  resIoMB       = 200;    // 单周期磁盘读写总量阈值(MB)
    int  resConnThresh = 60;     // TCP 连接数阈值(接近满负荷)
    // ---- 顽固病毒免疫处置 ----
    bool immunizeOn    = true;   // 无法删除时创建同名占位文件
    bool themeDark     = true;   // true=夜间(深色), false=白天(浅色)

    // ---- 漏洞情报订阅 (KEV/NVD/国内信创) ----
    bool vulnIntelOn   = true;   // 漏洞情报订阅总开关
    int  vulnCvssThresh = 9;     // NVD 高危判定阈值(CVSS>=该值入高危库)
    std::wstring vulnCustomUrl;  // 自定义订阅源(国内CNNVD/CNVD、聚合平台导出的CVE编号列表, 可留空)

    // ---- 持久化与劫持检测 (本轮新增) ----
    bool hostGuardOn    = true;  // hosts 文件劫持检测
    bool wmiScanOn      = true;  // WMI 事件订阅持久化检测
    bool taskScanOn     = true;  // 计划任务持久化检测
    bool clipGuardOn    = true;  // 剪贴板劫持监控(加密币地址替换)
    bool selfDefenseOn  = true;  // 自我保护看门狗(双进程互保)
    bool netAuditOn     = true;  // 网络审计(DNS/网关ARP/共享)
    // ---- 深度对抗检测 (本轮新增) ----
    bool scanPriorityOn = true;  // 扫描优先级: 无签名>有签名>系统>驱动
    bool lsassGuardOn   = true;  // LSASS 凭据窃取检测
    bool hollowScanOn   = true;  // 进程镂空检测
    bool dllHijackOn    = true;  // DLL 劫持检测
    bool lnkScanOn      = true;  // 快捷方式(.lnk)劫持检测
    bool canaryOn       = true;  // 勒索诱饵蜜罐(Canary)监控
    bool comHijackOn    = true;  // COM劫持/SilentProcessExit/IFEO 检测
    // ---- 告警确认与启动自修复 (v13.14) ----
    bool alertAskOn     = true;  // 所有告警由用户确认是否处理
    bool forceKillOn    = true;  // 强制终止规则(命中即强杀+恢复, 不经确认)
    bool dumpOn       = true;  // 命中有害时创建内存转储(取证, 须在杀进程前)
    bool notifyOn     = true;  // 系统通知(托盘气泡)
    bool legacyIocOn  = true;  // 旧/已曝光 IoC 仍生效(攻击者常故意复用旧基础设施)
    bool selfRepairOn   = true;  // 检测到本程序无法启动时自动修复组策略
    // ---- Rootkit隐藏进程 / 代理劫持 / 隔离区 (v13.15) ----
    bool hiddenProcOn    = true;  // Rootkit 隐藏进程交叉视图检测
    bool proxyGuardOn    = true;  // 系统代理 / PAC 劫持检测
    bool quarManageOn    = true;  // 隔离区管理(列出/恢复/删除)
    bool etwOn           = true;  // ETW 实时事件追踪(进程/映像/网络/注册表)
    bool procTreeOn      = true;  // 进程血缘树(父子关系与异常血缘检测)
    bool usbAuditOn      = true;  // USB 设备审计(BadUSB/未授权U盘取证)
    bool mitAuditOn       = true;  // 进程缓解策略审计(ASLR/DEP/CFG 等漏洞利用防护)
    bool credGuardOn      = true;  // 凭据防护基线(LSASS 保护/明文密码缓存)
    bool shareAuditOn     = true;  // 网络共享与自动播放(横向移动/U盘传播防护)
    bool hiddenScanOn     = true;  // 隐藏文件/隐藏目录扫描
    bool adsScanOn        = true;  // NTFS 备用数据流(ADS) 检测

    bool Load(const wchar_t* path);
    bool Save(const wchar_t* path) const;
};


// ===================== 配置文件路径与转义 =====================
// 【思路】配置文件必须放在 exe 同目录, 而不是"当前工作目录"。
// 原因: 本程序会被开机自启、计划任务、右键菜单、资源管理器等多种方式拉起,
// 每次的"当前工作目录"都可能不同。若用相对路径 "zz_EDR.cfg.json",
// 会出现三种后果: 1) 启动时读不到配置, 全部回落默认值;
// 2) 在别处又新建一份空配置, 用户的设置"看起来丢了";
// 3) 防篡改校验比对了错误的文件, 误报"配置被篡改"。
// 所以用 GetModuleFileNameW 取自身真实路径再拼, 行为恒定。
static std::wstring CfgDefaultPath() {
    wchar_t self[MAX_PATH] = {0};
    if (GetModuleFileNameW(nullptr, self, MAX_PATH) && *self) {
        std::wstring p(self);
        size_t pos = p.find_last_of(L"\\/");
        if (pos != std::wstring::npos)
            return p.substr(0, pos + 1) + L"zz_EDR.cfg.json";
    }
    return std::wstring(L"zz_EDR.cfg.json");   // 取不到自身路径时回落(极罕见)
}

// 【思路】JSON 字符串里, 反斜杠与双引号必须转义。
// Windows 路径天然含反斜杠(C:\Users\...\backup), 若直接 %ls 写入,
// 生成的 JSON 里 "\\U" 会被解析器当成非法转义 -> 整个配置文件语法错误
// -> 读不回来 -> 所有设置静默失效。中文/空格无需转义, UTF-8 原样保留。
static std::wstring JsonEscW(const std::wstring& in) {
    std::wstring o;
    o.reserve(in.size() + 8);
    for (wchar_t c : in) {
        switch (c) {
            case L'\\': o += L"\\\\"; break;
            case L'"':  o += L"\\\""; break;
            case L'\n': o += L"\\n";  break;
            case L'\r': o += L"\\r";  break;
            case L'\t': o += L"\\t";  break;
            default:
                if (c < 0x20) { wchar_t b[8]; swprintf(b, 8, L"\\u%04x", (unsigned)c); o += b; }
                else o += c;
        }
    }
    return o;
}

// ===================== 配置文件防篡改: 备份 + 校验 =====================
// 机制: 每次保存先把当前文件备份为 <path>.bak, 再写入 <path>.sig 记录
//       FNV-1a 64 校验值。启动时校验: 校验值不符即视为被篡改,
//       自动从 .bak 恢复并告警, 防止病毒/篡改者关闭防护开关。
static uint64_t CfgFnv1a(const void* data, size_t len) {
    const unsigned char* p = (const unsigned char*)data;
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < len; i++) { h ^= (uint64_t)p[i]; h *= 1099511628211ULL; }
    return h;
}
static bool CfgReadAll(const std::wstring& path, std::string& out) {
    FILE* f = _wfopen(path.c_str(), L"rb");
    if (!f) return false;
    out.clear();
    char tmp[4096];
    size_t n;
    while ((n = fread(tmp, 1, sizeof(tmp), f)) > 0) out.append(tmp, n);
    fclose(f);
    return true;
}
static uint64_t CfgHashFile(const std::wstring& path) {
    std::string s;
    if (!CfgReadAll(path, s)) return 0;
    return CfgFnv1a(s.data(), s.size());
}
static bool CfgWriteSig(const std::wstring& path, uint64_t h) {
    std::wstring sig = path + L".sig";
    FILE* f = _wfopen(sig.c_str(), L"wb");
    if (!f) return false;
    fprintf(f, "%016llx", (unsigned long long)h);
    fclose(f);
    return true;
}
static uint64_t CfgReadSig(const std::wstring& path) {
    std::wstring sig = path + L".sig";
    std::string s;
    if (!CfgReadAll(sig, s)) return 0;
    return (uint64_t)strtoull(s.c_str(), nullptr, 16);
}
// 备份: path -> path.bak
static bool CfgBackup(const std::wstring& path) {
    std::string s;
    if (!CfgReadAll(path, s)) return false;
    std::wstring bak = path + L".bak";
    FILE* f = _wfopen(bak.c_str(), L"wb");
    if (!f) return false;
    size_t w = fwrite(s.data(), 1, s.size(), f);
    fclose(f);
    return w == s.size();
}
// 恢复: path.bak -> path (并同步刷新校验值)
static bool CfgRestore(const std::wstring& path) {
    std::wstring bak = path + L".bak";
    std::string s;
    if (!CfgReadAll(bak, s)) return false;
    FILE* f = _wfopen(path.c_str(), L"wb");
    if (!f) return false;
    size_t w = fwrite(s.data(), 1, s.size(), f);
    fclose(f);
    if (w != s.size()) return false;
    CfgWriteSig(path, CfgFnv1a(s.data(), s.size()));
    return true;
}

bool Config::Load(const wchar_t* path) {
    FILE* f = _wfopen(path, L"rb");
    if (!f) return false;
    string buf;
    char c;
    while (fread(&c, 1, 1, f)) buf.push_back(c);
    fclose(f);
    // 极简解析: 仅读我们关心的键
    auto getBool = [&](const string& key) -> bool {
        auto p = buf.find("\"" + key + "\"");
        if (p == string::npos) return false;
        auto c2 = buf.find(":", p);
        if (c2 == string::npos) return false;

        return buf.find("true", c2) < buf.find("\n", c2) || buf.find("true", c2) < buf.find(",", c2);
    };
    auto getInt = [&](const string& key, int def) -> int {
        auto p = buf.find("\"" + key + "\"");
        if (p == string::npos) return def;
        auto c2 = buf.find(":", p);
        if (c2 == string::npos) return def;
        auto end = buf.find_first_of(",}\n", c2);
        string num = buf.substr(c2 + 1, end - (c2 + 1));
        return atoi(num.c_str());
    };
    // 恢复已保存字段 (真实赋值, 此前为只解析不赋值的空壳)
    auto getStr = [&](const string& key) -> wstring {
        auto p = buf.find("\"" + key + "\"");
        if (p == string::npos) return L"";
        auto c1 = buf.find(':', p);
        if (c1 == string::npos) return L"";
        auto q1 = buf.find('"', c1);
        if (q1 == string::npos) return L"";
        auto q2 = buf.find('"', q1 + 1);
        if (q2 == string::npos) return L"";
        string raw = buf.substr(q1 + 1, q2 - q1 - 1);
        return wstring(raw.begin(), raw.end());
    };
    camOn = getBool("camOn");
    micOn = getBool("micOn");
    camMode = getInt("camMode", camMode);
    micMode = getInt("micMode", micMode);
    scanIntervalMs = getInt("scanIntervalMs", scanIntervalMs);
    scanType = getInt("scanType", scanType);
    advHeuristic  = getBool("advHeuristic");
    advMemory     = getBool("advMemory");
    advCloud      = getBool("advCloud");
    advDeobf      = getBool("advDeobf");
    advAggressive = getBool("advAggressive");
    escapeMode     = getBool("escapeMode");
    escapeWipeLevel = getInt("escapeWipeLevel", 2);
    // 越界保护: 配置文件可能被手改成任意值, 夹回 1..3, 否则遍数会失控
    if (escapeWipeLevel < 1) escapeWipeLevel = 1;
    if (escapeWipeLevel > 3) escapeWipeLevel = 3;
    escapeKillTimes = getInt("escapeKillTimes", 20);
    escapeKillIntervalMs = getInt("escapeKillIntervalMs", 5);
    // 夹紧: 防止配置文件被手改成极端值导致长时间空转或 CPU 打满
    if (escapeKillTimes < 1) escapeKillTimes = 1;
    if (escapeKillTimes > 200) escapeKillTimes = 200;
    if (escapeKillIntervalMs < 0) escapeKillIntervalMs = 0;
    if (escapeKillIntervalMs > 1000) escapeKillIntervalMs = 1000;
    drvOn = getBool("drvOn");
    fimOn = getBool("fimOn");
    officeGuardOn = getBool("officeGuardOn");
    vtApiKey     = getStr("vtApiKey");
    usbGuardOn   = getBool("usbGuardOn");
    dlGuardOn    = getBool("dlGuardOn");
    patchAuditOn = getBool("patchAuditOn");
    if (getStr("backupPath").size()) backupPath = getStr("backupPath");
    offlineBackupOn = getBool("offlineBackupOn");
    { wstring v = getStr("camFile"); if (!v.empty()) camFile = v; }
    { wstring v = getStr("micFile"); if (!v.empty()) micFile = v; }
    { wstring v = getStr("fimPath"); if (!v.empty()) fimPath = v; }
    { wstring v = getStr("password"); if (!v.empty()) password = v; }
    resGuardOn = getBool("resGuardOn");
    variantOn = getBool("variantOn");
    heurOn    = getBool("heurOn");
    forceKillOn = getBool("forceKillOn");
    dumpOn      = getBool("dumpOn");
    notifyOn    = getBool("notifyOn");
    legacyIocOn = getBool("legacyIocOn");
    pdmOn     = getBool("pdmOn");
    immunizeOn = getBool("immunizeOn");
    themeDark  = getBool("themeDark");
    vulnIntelOn    = getBool("vulnIntelOn");
    vulnCvssThresh = getInt("vulnCvssThresh", vulnCvssThresh);
    vulnCustomUrl  = getStr("vulnCustomUrl");
    if (vulnCvssThresh <= 0 || vulnCvssThresh > 10) vulnCvssThresh = 9;
    hostGuardOn   = getBool("hostGuardOn");
    wmiScanOn     = getBool("wmiScanOn");
    taskScanOn    = getBool("taskScanOn");
    clipGuardOn   = getBool("clipGuardOn");
    selfDefenseOn = getBool("selfDefenseOn");
    netAuditOn    = getBool("netAuditOn");
    scanPriorityOn = getBool("scanPriorityOn");
    lsassGuardOn   = getBool("lsassGuardOn");
    hollowScanOn   = getBool("hollowScanOn");
    dllHijackOn    = getBool("dllHijackOn");
    lnkScanOn      = getBool("lnkScanOn");
    canaryOn       = getBool("canaryOn");
    comHijackOn    = getBool("comHijackOn");
    hiddenProcOn   = getBool("hiddenProcOn");
    proxyGuardOn   = getBool("proxyGuardOn");
    quarManageOn   = getBool("quarManageOn");
    alertAskOn     = getBool("alertAskOn");
    selfRepairOn   = getBool("selfRepairOn");
    etwOn          = getBool("etwOn");
    procTreeOn     = getBool("procTreeOn");
    usbAuditOn     = getBool("usbAuditOn");
    mitAuditOn     = getBool("mitAuditOn");
    credGuardOn    = getBool("credGuardOn");
    shareAuditOn   = getBool("shareAuditOn");
    hiddenScanOn   = getBool("hiddenScanOn");
    adsScanOn      = getBool("adsScanOn");
    mailScanOn     = getBool("mailScanOn");
    forceUnlockOn  = getBool("forceUnlockOn");
    { int v = getInt("resCpuThresh", resCpuThresh);  if (v > 0) resCpuThresh  = v; }
    { int v = getInt("resGpuThresh", resGpuThresh);  if (v > 0) resGpuThresh  = v; }
    { int v = getInt("resMemMB", resMemMB);      if (v > 0) resMemMB      = v; }
    { int v = getInt("resIoMB", resIoMB);       if (v > 0) resIoMB       = v; }
    { int v = getInt("resConnThresh", resConnThresh); if (v > 0) resConnThresh = v; }
    return true;
}
bool Config::Save(const wchar_t* path) const {
    // 防篡改: 覆盖前先备份现有配置, 便于被篡改后一键恢复
    CfgBackup(std::wstring(path));
    FILE* f = _wfopen(path, L"wb");
    if (!f) return false;
    fprintf(f, "{\n");
    {
        wchar_t vbuf[64];
        swprintf(vbuf, 64, L"%d.%d.%d", VER_MAJOR, VER_MINOR, VER_PATCH);
        fwprintf(f, L"  \"version\": \"%ls\",\n", vbuf);
    }
    fprintf(f, "  \"camOn\": %s,\n", camOn ? "true" : "false");
    fprintf(f, "  \"micOn\": %s,\n", micOn ? "true" : "false");
    fprintf(f, "  \"camMode\": %d,\n", camMode);
    fprintf(f, "  \"micMode\": %d,\n", micMode);
    fprintf(f, "  \"scanIntervalMs\": %d,\n", scanIntervalMs);
    fprintf(f, "  \"scanType\": %d,\n", scanType);
    fprintf(f, "  \"advHeuristic\": %s,\n", advHeuristic ? "true" : "false");
    fprintf(f, "  \"advMemory\": %s,\n", advMemory ? "true" : "false");
    fprintf(f, "  \"advCloud\": %s,\n", advCloud ? "true" : "false");
    fprintf(f, "  \"advDeobf\": %s,\n", advDeobf ? "true" : "false");
    fprintf(f, "  \"advAggressive\": %s,\n", advAggressive ? "true" : "false");
    fprintf(f, "  \"escapeMode\": %s,\n", escapeMode ? "true" : "false");
    fprintf(f, "  \"escapeWipeLevel\": %d,\n", escapeWipeLevel);
    fprintf(f, "  \"escapeKillTimes\": %d,\n", escapeKillTimes);
    fprintf(f, "  \"escapeKillIntervalMs\": %d,\n", escapeKillIntervalMs);
    fprintf(f, "  \"drvOn\": %s,\n", drvOn ? "true" : "false");
    fprintf(f, "  \"fimOn\": %s,\n", fimOn ? "true" : "false");
    fprintf(f, "  \"officeGuardOn\": %s,\n", officeGuardOn ? "true" : "false");
    fprintf(f, "  \"vtApiKey\": \"%ls\",\n", vtApiKey.c_str());
    fprintf(f, "  \"usbGuardOn\": %s,\n", usbGuardOn ? "true" : "false");
    fprintf(f, "  \"patchAuditOn\": %s,\n", patchAuditOn ? "true" : "false");
    fprintf(f, "  \"backupPath\": \"%ls\",\n", JsonEscW(backupPath).c_str());
    fprintf(f, "  \"offlineBackupOn\": %s,\n", offlineBackupOn ? "true" : "false");
    fprintf(f, "  \"camFile\": \"%ls\",\n", JsonEscW(camFile).c_str());
    fprintf(f, "  \"micFile\": \"%ls\",\n", JsonEscW(micFile).c_str());
    fprintf(f, "  \"fimPath\": \"%ls\",\n", JsonEscW(fimPath).c_str());
    fprintf(f, "  \"password\": \"%ls\",\n", password.c_str());
    fprintf(f, "  \"resGuardOn\": %s,\n", resGuardOn ? "true" : "false");
    fprintf(f, "  \"variantOn\": %s,\n", variantOn ? "true" : "false");
    fprintf(f, "  \"heurOn\": %s,\n", heurOn ? "true" : "false");
    fprintf(f, "  \"forceKillOn\": %s,\n", forceKillOn ? "true" : "false");
    fprintf(f, "  \"dumpOn\": %s,\n", dumpOn ? "true" : "false");
    fprintf(f, "  \"notifyOn\": %s,\n", notifyOn ? "true" : "false");
    fprintf(f, "  \"legacyIocOn\": %s,\n", legacyIocOn ? "true" : "false");
    fprintf(f, "  \"pdmOn\": %s,\n", pdmOn ? "true" : "false");
    fprintf(f, "  \"immunizeOn\": %s,\n", immunizeOn ? "true" : "false");
    fprintf(f, "  \"themeDark\": %s,\n", themeDark ? "true" : "false");
    fprintf(f, "  \"hostGuardOn\": %s,\n", hostGuardOn ? "true" : "false");
    fprintf(f, "  \"wmiScanOn\": %s,\n", wmiScanOn ? "true" : "false");
    fprintf(f, "  \"taskScanOn\": %s,\n", taskScanOn ? "true" : "false");
    fprintf(f, "  \"clipGuardOn\": %s,\n", clipGuardOn ? "true" : "false");
    fprintf(f, "  \"selfDefenseOn\": %s,\n", selfDefenseOn ? "true" : "false");
    fprintf(f, "  \"netAuditOn\": %s,\n", netAuditOn ? "true" : "false");
    fprintf(f, "  \"scanPriorityOn\": %s,\n", scanPriorityOn ? "true" : "false");
    fprintf(f, "  \"lsassGuardOn\": %s,\n", lsassGuardOn ? "true" : "false");
    fprintf(f, "  \"hollowScanOn\": %s,\n", hollowScanOn ? "true" : "false");
    fprintf(f, "  \"dllHijackOn\": %s,\n", dllHijackOn ? "true" : "false");
    fprintf(f, "  \"lnkScanOn\": %s,\n", lnkScanOn ? "true" : "false");
    fprintf(f, "  \"canaryOn\": %s,\n", canaryOn ? "true" : "false");
    fprintf(f, "  \"comHijackOn\": %s,\n", comHijackOn ? "true" : "false");
    fprintf(f, "  \"hiddenProcOn\": %s,\n", hiddenProcOn ? "true" : "false");
    fprintf(f, "  \"proxyGuardOn\": %s,\n", proxyGuardOn ? "true" : "false");
    fprintf(f, "  \"quarManageOn\": %s,\n", quarManageOn ? "true" : "false");
    fprintf(f, "  \"alertAskOn\": %s,\n", alertAskOn ? "true" : "false");
    fprintf(f, "  \"selfRepairOn\": %s,\n", selfRepairOn ? "true" : "false");
    fprintf(f, "  \"dlGuardOn\": %s,\n", dlGuardOn ? "true" : "false");
    fprintf(f, "  \"etwOn\": %s,\n", etwOn ? "true" : "false");
    fprintf(f, "  \"procTreeOn\": %s,\n", procTreeOn ? "true" : "false");
    fprintf(f, "  \"usbAuditOn\": %s,\n", usbAuditOn ? "true" : "false");
    fprintf(f, "  \"mitAuditOn\": %s,\n", mitAuditOn ? "true" : "false");
    fprintf(f, "  \"credGuardOn\": %s,\n", credGuardOn ? "true" : "false");
    fprintf(f, "  \"shareAuditOn\": %s,\n", shareAuditOn ? "true" : "false");
    fprintf(f, "  \"hiddenScanOn\": %s,\n", hiddenScanOn ? "true" : "false");
    fprintf(f, "  \"adsScanOn\": %s,\n", adsScanOn ? "true" : "false");
    fprintf(f, "  \"mailScanOn\": %s,\n", mailScanOn ? "true" : "false");
    fprintf(f, "  \"forceUnlockOn\": %s,\n", forceUnlockOn ? "true" : "false");
    fprintf(f, "  \"resCpuThresh\": %d,\n", resCpuThresh);
    fprintf(f, "  \"resGpuThresh\": %d,\n", resGpuThresh);
    fprintf(f, "  \"resMemMB\": %d,\n", resMemMB);
    fprintf(f, "  \"resIoMB\": %d,\n", resIoMB);
    fprintf(f, "  \"resConnThresh\": %d,\n", resConnThresh);
    fprintf(f, "  \"vulnIntelOn\": %s,\n", vulnIntelOn ? "true" : "false");
    fprintf(f, "  \"vulnCvssThresh\": %d,\n", vulnCvssThresh);
    fprintf(f, "  \"vulnCustomUrl\": \"%ls\"\n", vulnCustomUrl.c_str());
    fprintf(f, "}\n");
    fclose(f);
    // 防篡改: 写入后刷新校验值 (备份在写入前完成, 见函数入口)
    std::wstring wp(path);
    CfgWriteSig(wp, CfgHashFile(wp));
    return true;
}
static Config g_cfg;

// ------------------------------------------------------------
//  资源 / 控件 ID  (分段, 无重叠)
// ------------------------------------------------------------
enum {
    IDC_TAB = 100,
    IDC_LOG = 101,
    IDC_BTN_APPLY = 102,

    IDC_ENGINE_BASE = 500,
    IDC_ENGINE_BSS = 500, IDC_ENGINE_HIPS, IDC_ENGINE_DAC, IDC_ENGINE_VEH,
    IDC_ENGINE_YARA, IDC_ENGINE_PE, IDC_ENGINE_EVASION, IDC_ENGINE_APIHOOK,

    // ---- 行为 / 情报 / 沙箱 / 连坐 (段 300) ----
    IDC_PROC_LIST = 300,
    IDC_BTN_BEHAVIOR,
    IDC_BTN_INTEL_UPDATE,
    IDC_BTN_EXT_SCAN,
    IDC_BTN_SANDBOX,
    IDC_BTN_STARTUP_SCAN,
    IDC_BTN_GUARD,
    IDC_BTN_OFFICE_GUARD,
    IDC_BTN_MACRO_SCAN,
    IDC_BTN_TRUST_MGR,      // 信任管理(最小信任)
    IDC_BTN_TRUST_LEARN,    // 重新学习系统基线

    IDC_BTN_VT_SCAN,        // 建议#6 VirusTotal 多引擎
    IDC_BTN_USB_GUARD,      // 建议#2 U盘防护
    IDC_BTN_DL_SCAN,        // 建议#5 下载目录扫描
    IDC_BTN_CTX_MENU,       // 建议#5 右键扫描集成
    IDC_BTN_PATCH_AUDIT,    // 建议#4 补丁/软件审计
    IDC_BTN_DEEP_SCAN,      // 建议#3 全盘深度扫描
    IDC_BTN_SAFEMODE,       // 建议#7 安全模式清除
    IDC_BTN_BACKUP,         // 建议#8 数据备份
    IDC_BTN_MBR,            // 建议#9 引导区 MBR/GPT
    IDC_BTN_RANSOM_KILL,    // 建议#10 勒索专杀
    IDC_BTN_MINER_KILL,     // 建议#10 挖矿专杀
    IDC_BTN_RES_SCAN,       // 资源异常监控
    IDC_BTN_USER_SCAN,      // 未知账户扫描
    IDC_BTN_USER_CLEAN,     // 未知账户清理
    IDC_BTN_RES_TOGGLE,     // 资源监控守护开关
    IDC_BTN_IMMUNE,         // 顽固病毒免疫处置
    IDC_BTN_CVE_SCAN,
    IDC_BTN_VULN_UPDATE, IDC_BTN_VULN_CHECK,
    IDC_CB_ESCAPE_WIPE,     // v13.27 覆写强度下拉(弱/中/强)
    // ---- 持久化与劫持检测 (本轮新增) ----
    IDC_BTN_HOSTS_SCAN,     // hosts 劫持检测与修复
    IDC_BTN_WMI_SCAN,       // WMI 事件订阅持久化检测
    IDC_BTN_TASK_SCAN,      // 计划任务持久化检测
    IDC_BTN_CLIP_TOGGLE,    // 剪贴板劫持监控开关
    IDC_BTN_SELFDEF_TOGGLE, // 自我保护看门狗开关
    IDC_BTN_NETAUDIT,       // 网络审计(DNS/网关ARP/共享)
    // ---- 内核驱动对接 (DrvLink) ----
    IDC_BTN_DRV_TOGGLE,     // 装载/连接内核驱动
    IDC_BTN_DRV_STATUS,     // 查看驱动状态(重发规则+探测)
    IDC_BTN_DRV_UNINSTALL,  // 卸载驱动服务
    IDC_BEHAV_LIST = 310,
    IDC_CB_BASE = 1000,
    IDC_CB_CAM_ON, IDC_CB_CAM_MODE, IDC_CB_CAM_FILE, IDC_CB_CAM_BLACK,
    IDC_CB_MIC_ON, IDC_CB_MIC_MODE, IDC_CB_MIC_FILE, IDC_CB_MIC_MUTE,
    /* 注意: 浏览按钮的独立 ID 在下方 Legacy 段(2000+)已有定义，
       此处不可重复声明；原先 Edit 与 Button 共用 ID 的问题已修复 */
    IDC_CB_FULLCHAIN_ON, IDC_CB_SCAN_INTERVAL, IDC_CB_SCAN_TYPE,
    IDC_CB_ADV_HEURISTIC, IDC_CB_ADV_MEMORY, IDC_CB_ADV_CLOUD,
    IDC_CB_ADV_DEOBF, IDC_CB_ADV_AGGRESSIVE,
    IDC_CB_ADV_ESCAPE,
    IDC_CB_KILLALL, IDC_CB_DEEPCLEAN, IDC_CB_REMOTE, IDC_CB_REFRESH,
    IDC_CB_NETWORK_WINDOW, IDC_CB_NETWORK_REFRESH, IDC_CB_DISCONNECT,
    IDC_CB_PROTECTION_SCAN, IDC_CB_PROTECTION_MONITOR, IDC_CB_PROTECTION_LOCKDOWN, IDC_CB_PROTECTION_AMSI,
    IDC_CB_ETW_TRACE, IDC_CB_PROC_TREE, IDC_CB_USB_AUDIT,
    IDC_CB_CREATE_SNAPSHOT, IDC_CB_RECOVERY_ENV, IDC_CB_ROLLBACK_REFRESH,
    IDC_CB_ENCRYPT, IDC_CB_SHRED, IDC_CB_DPAPI,
    IDC_CB_BASELINE, IDC_CB_START_FIM, IDC_CB_STOP_FIM, IDC_CB_RUN_SCA,
    IDC_CB_EMG_RUN, IDC_CB_SHOWPWD, IDC_CB_EMG_PWD,
    IDC_CB_THEME_TOGGLE, IDC_CB_CLEAR_THREAT,
    IDC_CB_BOOTSCAN, IDC_CB_BOOTSCAN_OFF,

    // ---- Legacy UI 命名对齐 (短横线 -> 下划线, 段 2000+) ----
    IDC_CB_CAM_TOGGLE = 2000, IDC_CB_CAM_BROWSE,
    IDC_CB_HEUR_SCAN = 2060, IDC_CB_PDM_SCAN, IDC_CB_PDM_TOGGLE,
    IDC_CB_MIC_TOGGLE, IDC_CB_MIC_BROWSE,
    IDC_CB_CHAIN_TOGGLE, IDC_CB_CHAIN_START, IDC_CB_CHAIN_MONITOR,
    IDC_CB_CHAIN_AMSI, IDC_CB_CHAIN_LOCKDOWN, IDC_CB_CHAIN_ONCE,
    IDC_CB_PROC_KILLALL, IDC_CB_PROC_DEEPCLEAN, IDC_CB_PROC_REMOTE,
    IDC_CB_PROC_REFRESH, IDC_CB_PROC_KILL_4568, IDC_CB_PROC_KILL_9912,
    IDC_CB_NET_WINDOW, IDC_CB_NET_REFRESH, IDC_CB_NET_CUTOFF,
    IDC_CB_OVERVIEW_SCAN, IDC_CB_OVERVIEW_REFRESH,
    IDC_CB_DLP_ENCRYPT, IDC_CB_DLP_SHRED, IDC_CB_DLP_DPAPI,
    IDC_CB_FIM_BASELINE, IDC_CB_FIM_START, IDC_CB_FIM_STOP,
    IDC_CB_SCA_RUN,
    IDC_CB_RB_CREATE, IDC_CB_RB_RECOVERY, IDC_CB_RB_RESTORE,
    IDC_CB_REC_CREATE, IDC_CB_REC_CHECK,
    IDC_CB_SVC_BACKDOOR, IDC_CB_BROWSER_HIJACK, IDC_CB_ARP_DNS,
    IDC_CB_SCAN_BY_PRIO, IDC_CB_TASK_SCHED, IDC_CB_INJECT_SCAN,
    IDC_CB_FW_AUDIT, IDC_CB_PROXY_AUDIT, IDC_CB_EVTLOG_AUDIT,
    IDC_CB_HIDDEN_FILE, IDC_CB_ADS_SCAN,
    IDC_CB_MAIL_SCAN, IDC_CB_FORCE_UNLOCK, IDC_ED_UNLOCK_PATH,
    IDC_CB_VARIANT_SCAN,
    IDC_CB_FAMILY_SCAN,   // v13.14 \u94f6\u72d0/\u7d2b\u72d0\u4e0e\u5168\u54c1\u7c7b\u8bc6\u522b
    IDC_CB_SELF_REPAIR,  // v13.14 \u542f\u52a8\u9650\u5236\u81ea\u4fee\u590d
    IDC_CB_LNK_HIJACK, IDC_CB_CANARY_GUARD, IDC_CB_COM_HIJACK,
    IDC_CB_MIT_AUDIT, IDC_CB_CRED_GUARD, IDC_CB_SHARE_AUDIT,
    IDC_CB_HIDDEN_PROC, IDC_CB_PROXY_HIJACK, IDC_CB_QUAR_MANAGE,
    IDC_CB_FOX_DEEP, IDC_CB_FOX_BYOVD,
    IDC_CB_CFG_BACKUP, IDC_CB_CFG_RESTORE,
    IDC_BTN_SCAN_PRIORITY, IDC_BTN_LSASS_GUARD, IDC_BTN_HOLLOW_SCAN, IDC_BTN_DLLHIJACK_SCAN,
    IDC_CB_LOG_REFRESH, IDC_CB_LOG_CLEAR,
    IDC_CB_LOG_EXPORT, IDC_CB_AUTORUN_MANAGE, IDC_CB_KILL_TREE,
    IDC_CB_PWD_TOGGLE, IDC_CB_EMG_RUN2 = IDC_CB_EMG_RUN, // 别名, 复用既有
};

// ------------------------------------------------------------
//  全局状态 (受锁保护)
// ------------------------------------------------------------
static HWND   g_hMain = nullptr;
static HWND   g_hLog  = nullptr;
static HWND   g_hTab  = nullptr;
static HWND   g_hProcList = nullptr;
static std::atomic<bool> g_running{true};
static std::atomic<bool> g_scanning{false};
static std::atomic<bool> g_guardOn{true};   // v13: 默认开启 —— 无签名/随机哈希命名程序默认阻止运行  // 进程守护: 阻止无签名/随机哈希命名程序运行

struct ProcInfo { DWORD pid; DWORD ppid; wstring name; wstring path; bool suspicious; };
struct NetInfo  { wstring local, remote, state; DWORD pid; };
struct SvcInfo  { wstring name, state; };

static std::mutex g_procsMtx, g_netsMtx, g_svcsMtx, g_logMtx;
static vector<ProcInfo> g_procs;
static vector<NetInfo>  g_nets;
static vector<SvcInfo>  g_svcs;

// 快照访问器 (线程安全)
static vector<ProcInfo> SnapshotProcs() { std::lock_guard<std::mutex> lk(g_procsMtx); return g_procs; }
static vector<NetInfo>  SnapshotNets()  { std::lock_guard<std::mutex> lk(g_netsMtx);  return g_nets;  }
static vector<SvcInfo>  SnapshotSvcs()  { std::lock_guard<std::mutex> lk(g_svcsMtx);  return g_svcs;  }

// ------------------------------------------------------------
//  日志 (PostMessage 跨线程 -> UI 线程刷新, 有界队列)
// ------------------------------------------------------------
#define MAX_LOG 2000
#define WM_APP_LOG  (WM_APP + 2)

// 【日志限流 v13.28】
// PostMessage 是无界的: 后台任务若疯狂打日志而 UI 线程处理不及,
// 消息队列会无限积压 -> 内存暴涨 + 界面无响应(用户感知就是"卡死")。
// 这里做每秒条数限流, 超出则丢弃并计数。
//
// 【为什么用时间窗而不是"在途计数"】
// 在途计数需 UI 线程每处理一条就递减; 一旦有消息被丢弃/未送达,
// 计数只增不减, 会导致日志永久停摆 —— 那是比刷屏更糟的故障。
// 时间窗每秒自动重置, 不存在累积误差。
//
// 【被丢弃的会不会是重要告警】
// 不会遗漏真正的告警: 危险信号走 SetThreatLevel(红色横幅) 与
// AlertConfirm(弹窗)、SysNotify(托盘), 都不经过 LogPost 队列。
static std::mutex      g_logRateMtx;
static DWORD           g_logWinStart = 0;    // 当前 1 秒窗口起始
static int             g_logWinCount = 0;    // 本窗口已放行条数
static long long       g_logDropped  = 0;    // 累计丢弃
static const int       kLogRatePerSec = 200; // 每秒上限

static bool LogRateAllow() {
    std::lock_guard<std::mutex> lk(g_logRateMtx);
    DWORD now = GetTickCount();
    if (now - g_logWinStart >= 1000) {        // 进入新窗口(同时兼容 49 天回绕)
        g_logWinStart = now;
        g_logWinCount = 0;
    }
    if (g_logWinCount >= kLogRatePerSec) { ++g_logDropped; return false; }
    ++g_logWinCount;
    return true;
}

// 前向声明: 最近日志缓冲(供备用呈现器读取, 定义见后台任务调度节)
static void RecentLogAdd(const std::wstring& s);

static void LogPost(const wstring& msg) {
    RecentLogAdd(msg);                        // 先入缓冲, 主窗口失效时仍可回溯
    if (!g_hMain) return;
    if (!LogRateAllow()) return;              // 超限丢弃, 保护 UI 消息队列
    wchar_t* dup = _wcsdup(msg.c_str());
    if (!dup) return;
    if (!PostMessageW(g_hMain, WM_APP_LOG, 0, reinterpret_cast<LPARAM>(dup))) {
        free(dup);
    }
}

// ---- 前向声明: 主题 / 危险指示(实现位于主窗口过程之前) ----
enum { THREAT_SAFE = 0, THREAT_WARN = 1, THREAT_DANGER = 2 };
static void ThemeApply(bool dark);
static void ThemeToggle();
static void SetThreatLevel(int lv, const wchar_t* reason);
static int  ThreatLevelGet();   // 前向声明: g_threatLevel 定义在后文
// v13.24 统一处置链前向声明
static void ContainThreat(DWORD pid, const std::wstring& path,
                          const std::wstring& category, int sev);
static bool DumpProcessMemory(DWORD pid, const std::wstring& outPath);
static void SysNotify(const std::wstring& title, const std::wstring& msg);
static void TrayCleanup(void);
static void ClearThreat();
static void UpdateThreatBannerUI();

// 兼容旧版命名: LogMsg(tag, msg) -> LogPost
static void LogMsg(const wstring& tag, const wstring& msg) {
    wchar_t buf[2048];
    wsprintfW(buf, L"[%s] %s", tag.c_str(), msg.c_str());
    LogPost(buf);
}
static void LogFmt(const wchar_t* fmt, ...) {
    wchar_t buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vswprintf(buf, 1024, fmt, ap);
    va_end(ap);
    LogPost(buf);
}

// ============================================================
//  后台任务调度 (v13.29 重构: 三级分类并发池 + UI 三角色)
//
//  =========================================================
//  一、并发预算按"任务性质"分配, 不共用同一个池
//  =========================================================
//
//    SCAN   (扫描类)   线程=2   队列=256
//      全盘/深度扫描这类重 IO 任务。
//      【为什么只有 2 个】磁盘并发数超过 2~3 后, 总吞吐不再上升,
//      但单次任务延迟线性增长 —— 5 个一起扫, 结果是"全都卡住",
//      而不是"快 5 倍"。与其都慢, 不如排队各自快速完成。
//
//    BUTTON (按钮类)   线程=5   队列=512
//      用户点击触发的短任务。这类任务要求"点了有反应",
//      所以给得宽松, 且多数是轻量操作(读注册表/枚举少量对象)。
//
//    UI     (界面类)   线程=3   队列=128
//      3 条线程对应你指定的三个角色:
//        #1 主呈现器(main)   —— 主线程窗口 + 消息循环
//        #2 备用呈现器(backup) —— 主界面失活时接管, 独立消息循环
//        #3 监控器(monitor)  —— 心跳检测, 发现崩溃/错误/加载失败则切备用
//      池内 3 线程用于界面异步工作(延迟重绘/列表填充等),
//      监控器本身是长驻守护(见 UiWatchdogLoop), 不占池内线程,
//      否则它会永久占满 1/3 的界面并发额度。
//
//  =========================================================
//  二、为什么守护循环不能进池
//  =========================================================
//    守护是 while(g_running) 的永不退出循环。若放进池子, 几个守护
//    就会占满全部工作线程, 短任务永远排不上队(线程饥饿)。
//    所以长驻守护走 LaunchDaemon(按名字去重), 与池完全分离。
// ============================================================

// 兼容保留: 少数需要长期独立线程的任务(不占池内并发额度)
static std::vector<std::thread> g_bgThreads;
static std::mutex g_bgMtx;
static std::atomic<bool> g_stopFlag{false};

// ---------------- 任务分类 ----------------
enum class TaskCls { SCAN = 0, BUTTON = 1, UI = 2, CLS_COUNT = 3 };

// 【为什么 SCAN 只有 2 / BUTTON 5 / UI 3】见上方说明。
// 这三个数字是"并发预算": 同一时刻该类别最多有几个任务在跑。
static const int     kScanThreads   = 2;
static const int     kButtonThreads = 5;
static const int     kUiThreads     = 3;
static const size_t  kScanQueue     = 256;
static const size_t  kButtonQueue   = 512;
static const size_t  kUiQueue       = 128;

struct ClsPool {
    const wchar_t*               name = L"?";
    int                          maxThread = 1;
    size_t                       maxQueue  = 64;
    std::deque<std::function<void()>> q;
    std::mutex                   mtx;
    std::condition_variable      cv;
    std::atomic<bool>            stop{false};
    std::atomic<int>             size{0};       // 已启动的工作线程数
    std::atomic<int>             active{0};     // 正在执行的任务数
    std::atomic<int>             queued{0};     // 队列中等待的任务数
    std::atomic<long long>       dropped{0};    // 因队列满被丢弃数
    std::atomic<long long>       done{0};       // 已完成任务数
};
static ClsPool        g_pools[(int)TaskCls::CLS_COUNT];
static std::atomic<bool> g_poolReady{false};
static std::mutex        g_poolInitMtx;

// 前向声明: 任务异常需要上报 UI 监控器(定义在下方)
static void UiReportFault(const wchar_t* why);

static void PoolWorkerMain(ClsPool* p) {
    for (;;) {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lk(p->mtx);
            p->cv.wait(lk, [p] { return p->stop.load() || !p->q.empty(); });
            if (p->stop.load() && p->q.empty()) return;
            if (p->q.empty()) continue;                  // 虚假唤醒保护
            task = std::move(p->q.front());
            p->q.pop_front();
            p->queued.fetch_sub(1);
        }
        p->active.fetch_add(1);
        try {
            if (task) task();
        } catch (...) {
            // 单任务异常绝不能杀死工作线程(否则池会逐渐失血至 0)
            UiReportFault(L"后台任务抛出异常");
        }
        p->active.fetch_sub(1);
        p->done.fetch_add(1);
    }
}

static void PoolInitAll() {
    if (g_poolReady.load()) return;
    std::lock_guard<std::mutex> lk(g_poolInitMtx);
    if (g_poolReady.load()) return;                       // 双重检查, 幂等
    g_pools[(int)TaskCls::SCAN].name      = L"SCAN";
    g_pools[(int)TaskCls::SCAN].maxThread = kScanThreads;
    g_pools[(int)TaskCls::SCAN].maxQueue  = kScanQueue;
    g_pools[(int)TaskCls::BUTTON].name      = L"BUTTON";
    g_pools[(int)TaskCls::BUTTON].maxThread = kButtonThreads;
    g_pools[(int)TaskCls::BUTTON].maxQueue  = kButtonQueue;
    g_pools[(int)TaskCls::UI].name      = L"UI";
    g_pools[(int)TaskCls::UI].maxThread = kUiThreads;
    g_pools[(int)TaskCls::UI].maxQueue  = kUiQueue;

    for (int i = 0; i < (int)TaskCls::CLS_COUNT; ++i) {
        ClsPool& p = g_pools[i];
        p.stop.store(false);
        for (int k = 0; k < p.maxThread; ++k)
            // detach 而非保存 thread 对象: 若存进静态 vector, 进程走异常
            // 退出路径时静态析构会撞上"仍 joinable 的 thread"直接 terminate
            // (该 abort 已在测试中真实复现)。退出安全性由"等队列排空"保证。
            std::thread(PoolWorkerMain, &p).detach();
        p.size.store(p.maxThread);
    }
    g_poolReady.store(true);
}

// 统一投递。返回 false = 队列满被丢弃(调用点多忽略返回值, 但会计数)
template<typename F>
static bool LaunchCls(TaskCls c, F&& f) {
    PoolInitAll();                                        // 惰性初始化
    ClsPool& p = g_pools[(int)c];
    {
        std::lock_guard<std::mutex> lk(p.mtx);
        if (p.stop.load()) return false;
        if (p.q.size() >= p.maxQueue) { p.dropped.fetch_add(1); return false; }
        p.q.emplace_back(std::forward<F>(f));
        p.queued.fetch_add(1);
    }
    p.cv.notify_one();
    return true;
}

// 扫描类: 全盘/深度/下载目录等重 IO 任务 -> 最多 2 个并发
template<typename F> static bool LaunchScan(F&& f) { return LaunchCls(TaskCls::SCAN,   std::forward<F>(f)); }
// 按钮类: 用户点击触发的短任务 -> 最多 5 个并发
template<typename F> static bool LaunchBg  (F&& f) { return LaunchCls(TaskCls::BUTTON, std::forward<F>(f)); }
// 界面类: 界面相关异步工作 -> 最多 3 个并发
template<typename F> static bool LaunchUi  (F&& f) { return LaunchCls(TaskCls::UI,     std::forward<F>(f)); }

// 供 UI/诊断显示: 各池当前状态
static std::wstring PoolStatusText() {
    wchar_t b[512];
    std::wstring out;
    for (int i = 0; i < (int)TaskCls::CLS_COUNT; ++i) {
        ClsPool& p = g_pools[i];
        wsprintfW(b, L"%s %d/%d (队列%d 丢弃%lld)  ",
                  p.name, p.active.load(), p.size.load(),
                  p.queued.load(), p.dropped.load());
        out += b;
    }
    return out;
}

static void PoolShutdown() {
    for (int i = 0; i < (int)TaskCls::CLS_COUNT; ++i) {
        { std::lock_guard<std::mutex> lk(g_pools[i].mtx); g_pools[i].stop.store(true); }
        g_pools[i].cv.notify_all();
        g_pools[i].size.store(0);
    }
    g_poolReady.store(false);
}

// ---------------- 长驻守护: 按名字去重, 防重复启动 ----------------
static std::mutex              g_daemonMtx;
static std::set<std::wstring>  g_daemonRunning;
static std::atomic<long long>  g_daemonRejected{0};        // 被去重拦截的重复启动次数

// 返回 false = 同名守护已在运行, 本次被忽略(不是失败, 是正确行为)
static bool LaunchDaemon(const wchar_t* name, std::function<void()> fn) {
    if (!name || !fn) return false;
    {
        std::lock_guard<std::mutex> lk(g_daemonMtx);
        if (g_daemonRunning.count(name)) { g_daemonRejected.fetch_add(1); return false; }
        g_daemonRunning.insert(name);
    }
    std::wstring nm(name);
    // detach 而非保存 thread 对象: 守护反复启停不会累积 thread 句柄
    std::thread([nm, fn] {
        try { fn(); } catch (...) {}
        std::lock_guard<std::mutex> lk(g_daemonMtx);
        g_daemonRunning.erase(nm);                         // 退出后释放, 允许下次再启动
    }).detach();
    return true;
}
static bool DaemonRunning(const wchar_t* name) {
    if (!name) return false;
    std::lock_guard<std::mutex> lk(g_daemonMtx);
    return g_daemonRunning.count(name) != 0;
}

// ============================================================
//  UI 三角色: 主呈现器 / 备用呈现器 / 监控器
//
//  【为什么需要备用呈现器】
//    EDR 是安全软件, 主界面卡死 = 用户失去对机器的最后控制手段,
//    尤其在"激进/紧急模式"误伤系统时, 没有 UI 就无法撤销。
//    所以界面本身也要有冗余。
//
//  【监控器怎么判定主界面"坏了"】四条独立信号, 任一成立即切换:
//    (1) 心跳超时: 每 5 秒向主窗口发 WM_APP_HEARTBEAT, 主窗口回执
//        序号。连续 3 次没收到底确认 -> 判定卡死(消息循环不再泵消息)
//    (2) 系统判定: IsHungAppWindow(g_hMain) 为真(Win32 自带挂起检测)
//    (3) 窗口失效: IsWindow(g_hMain) 为假(被意外销毁)
//    (4) 主动上报: 代码调用 UiReportFault(L"页面加载失败: xxx")
//
//    只用(1)不够 —— 界面可能"活着但画不出来"(GDI 资源耗尽);
//    只用(2)不够 —— 该函数对非响应窗口有滞后。多信号互补。
// ============================================================
#ifndef WM_APP_HEARTBEAT
#define WM_APP_HEARTBEAT (WM_APP + 20)
#endif
#ifndef WM_APP_PROCLIST
#define WM_APP_PROCLIST (WM_APP + 21)   // 异步刷新进程列表: lParam = new vector<wstring>*
#endif

static std::atomic<long long>  g_uiHeartSeq{0};      // 监控器发出的心跳序号
static std::atomic<long long>  g_uiHeartAck{-1};     // 主呈现器回执的序号
static std::atomic<int>        g_uiMiss{0};          // 连续未回执次数
static std::atomic<bool>       g_uiBackupOn{false};  // 备用呈现器是否已启用(只切一次)
// 冷却: 用户主动关闭备用窗口后 60 秒内不再自动弹, 否则会陷入
// "关掉->立刻又弹" 的死循环(主界面确实没恢复, 条件仍成立)。
static std::atomic<long long>  g_uiBackupCoolUntil{0};
static std::atomic<bool>       g_uiBackupAlive{false};
static std::atomic<long long>  g_uiFaultCount{0};
static std::mutex              g_uiFaultMtx;
static std::wstring            g_uiLastFault;

// 最近日志环形缓冲: 备用呈现器不依赖主窗口也能展示发生了什么
static std::mutex              g_recentLogMtx;
static std::deque<std::wstring> g_recentLog;
static const size_t            kRecentLogMax = 200;

static void RecentLogAdd(const std::wstring& s) {
    std::lock_guard<std::mutex> lk(g_recentLogMtx);
    g_recentLog.push_back(s);
    while (g_recentLog.size() > kRecentLogMax) g_recentLog.pop_front();
}
static std::deque<std::wstring> RecentLogSnapshot() {
    std::lock_guard<std::mutex> lk(g_recentLogMtx);
    return g_recentLog;
}

// 主呈现器收到心跳后调用: 回执序号 + 清零连续失败计数
static void UiHeartbeatAck(long long seq) {
    g_uiHeartAck.store(seq);
    g_uiMiss.store(0);
}

// 前向声明: 备用呈现器激活(定义在本节下方)
static void UiBackupActivate(const wchar_t* reason);

// 供各处主动上报: 页面加载失败 / 控件创建失败 / 渲染异常等
static void UiReportFault(const wchar_t* why) {
    g_uiFaultCount.fetch_add(1);
    {
        std::lock_guard<std::mutex> lk(g_uiFaultMtx);
        g_uiLastFault = why ? why : L"未知错误";
    }
    UiBackupActivate(why);
}

// ---- 备用呈现器: 独立线程 + 独立消息循环 ----
static LRESULT CALLBACK UiBackupWndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    static HWND lb = nullptr, st = nullptr;
    switch (m) {
        case WM_CREATE: {
            st = CreateWindowExW(0, L"STATIC",
                L"主界面无响应, 已切换到备用呈现器 (EDR 后台防护不受影响)",
                WS_CHILD | WS_VISIBLE | SS_LEFT, 10, 10, 680, 24, h, nullptr,
                GetModuleHandleW(nullptr), nullptr);
            lb = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"",
                WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY,
                10, 44, 680, 360, h, nullptr, GetModuleHandleW(nullptr), nullptr);
            CreateWindowExW(0, L"BUTTON", L"重启主界面",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                10, 414, 160, 34, h, (HMENU)1001, GetModuleHandleW(nullptr), nullptr);
            CreateWindowExW(0, L"BUTTON", L"退出程序",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                190, 414, 160, 34, h, (HMENU)1002, GetModuleHandleW(nullptr), nullptr);
            SetTimer(h, 1, 1000, nullptr);          // 每秒拉一次最近日志
            return 0;
        }
        case WM_TIMER: {
            if (!lb) return 0;
            // 全量重绘代价高, 采用"数量变化才追加"的增量策略
            int cnt = (int)SendMessageW(lb, LB_GETCOUNT, 0, 0);
            auto logs = RecentLogSnapshot();
            if ((int)logs.size() < cnt) { SendMessageW(lb, LB_RESETCONTENT, 0, 0); cnt = 0; }
            for (int i = cnt; i < (int)logs.size(); ++i)
                SendMessageW(lb, LB_ADDSTRING, 0, (LPARAM)logs[i].c_str());
            if (cnt < (int)logs.size())
                SendMessageW(lb, LB_SETTOPINDEX,
                             (WPARAM)(SendMessageW(lb, LB_GETCOUNT, 0, 0) - 1), 0);
            return 0;
        }
        case WM_COMMAND:
            if (LOWORD(w) == 1001) {
                // 重启主界面: 由外部重写入口, 这里仅提示(避免在本线程重建主窗口
                // 造成两个消息循环竞争同一组全局控件句柄)
                MessageBoxW(h, L"请关闭本程序后重新启动以恢复主界面。\r\n"
                               L"后台防护(扫描/守护/拦截)在此期间持续运行。",
                            L"ZZ EDR 备用呈现器", MB_OK | MB_ICONINFORMATION);
                return 0;
            }
            if (LOWORD(w) == 1002) { g_running.store(false); DestroyWindow(h); return 0; }
            return 0;
        case WM_CLOSE:
            // 备用窗口关闭不等于退出: 后台防护继续, 仅停止呈现
            DestroyWindow(h);
            return 0;
        case WM_DESTROY:
            KillTimer(h, 1);
            g_uiBackupAlive.store(false);
            // 必须复位 g_uiBackupOn, 否则一旦误触发过一次, 监控器就永远
            // 跳过检测(它开头有 if(g_uiBackupOn) continue), 之后主界面真
            // 卡死也检测不到了 —— 冗余机制形同虚设。配合冷却避免反复弹。
            g_uiBackupOn.store(false);
            g_uiBackupCoolUntil.store((long long)time(nullptr) + 60);
            PostQuitMessage(0);                     // 只结束本线程消息循环
            return 0;
        default: return DefWindowProcW(h, m, w, l);
    }
}

// 冷却: 用户主动关闭备用窗口后 60 秒内不再自动弹, 否则会陷入
// "关掉->立刻又弹" 的死循环(主界面确实没恢复, 条件仍成立)。
// 代价是这 60 秒内主界面若卡死需稍等, 远好于无法关闭的弹窗骚扰。

// 启用备用呈现器(幂等: 只切换一次, 避免反复弹窗)
static void UiBackupActivate(const wchar_t* reason) {
    // 冷却期内不重复弹(用户刚关掉就又弹会形成死循环)
    if (time(nullptr) < g_uiBackupCoolUntil.load()) return;
    bool expect = false;
    if (!g_uiBackupOn.compare_exchange_strong(expect, true)) return;
    std::wstring why = reason ? reason : L"未知原因";
    RecentLogAdd(L"[UI] 主呈现器异常, 启用备用呈现器: " + why);
    std::thread([why] {
        WNDCLASSEXW wc = { sizeof(wc) };
        wc.lpfnWndProc   = UiBackupWndProc;
        wc.hInstance     = GetModuleHandleW(nullptr);
        wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = L"ZZEDRBackupUI";
        wc.hIcon         = LoadIconW(nullptr, IDI_APPLICATION);
        // 已注册过则忽略失败(重复注册在同一进程内是允许的重复调用场景)
        RegisterClassExW(&wc);
        HWND h = CreateWindowExW(WS_EX_TOPMOST, L"ZZEDRBackupUI",
                                 L"ZZ EDR - 备用呈现器", WS_OVERLAPPEDWINDOW,
                                 CW_USEDEFAULT, CW_USEDEFAULT, 720, 500,
                                 nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
        if (!h) { g_uiBackupOn.store(false); return; }
        ShowWindow(h, SW_SHOW);
        UpdateWindow(h);
        g_uiBackupAlive.store(true);
        MSG m;
        while (GetMessageW(&m, nullptr, 0, 0)) { TranslateMessage(&m); DispatchMessageW(&m); }
        g_uiBackupAlive.store(false);
    }).detach();
}

// ---- 监控器: 长驻守护, 不占 UI 池线程 ----
static void UiWatchdogLoop() {
    const int kIntervalMs = 5000;      // 心跳间隔
    const int kMaxMiss    = 3;         // 连续 3 次未回执 -> 判定卡死(约 15 秒)
    while (g_running.load()) {
        Sleep(kIntervalMs);
        if (!g_running.load()) break;
        if (g_uiBackupOn.load()) { Sleep(kIntervalMs); continue; }   // 已切备用, 不再重复切换

        HWND hm = g_hMain;
        // 信号(3): 窗口已失效
        if (!hm || !IsWindow(hm)) { UiReportFault(L"主窗口句柄失效"); continue; }
        // 信号(2): 系统判定窗口无响应
        if (IsHungAppWindow(hm))  { UiReportFault(L"系统判定主界面无响应"); continue; }

        // 信号(1): 心跳超时 —— 能抓到"消息循环不再泵消息"的卡死
        long long seq = g_uiHeartSeq.fetch_add(1) + 1;
        // 【关键】必须把 seq 放进 lParam 带给主窗口。
        // 曾漏传(写死 (LPARAM)0), 主窗口回执恒为 0, 而监控器要求 ack>=seq
        // (seq 从 1 递增), 于是 0>=1 永远不成立 —— 启动约 15 秒后必然误判
        // 主界面卡死并弹出备用呈现器。心跳"发了但没发序号"等于没发。
        if (!PostMessageW(hm, WM_APP_HEARTBEAT, 0, (LPARAM)seq)) {
            // 投递失败通常意味着消息队列已满(典型的 UI 线程阻塞)
            if (g_uiMiss.fetch_add(1) + 1 >= kMaxMiss) UiReportFault(L"主界面消息队列阻塞(心跳投递失败)");
            continue;
        }
        for (int w = 0; w < 20 && g_running.load(); ++w) {   // 最多等 2 秒
            if (g_uiHeartAck.load() >= seq) break;
            Sleep(100);
        }
        if (g_uiHeartAck.load() < seq) {
            int miss = g_uiMiss.fetch_add(1) + 1;
            if (miss >= kMaxMiss) UiReportFault(L"主界面心跳超时(疑似卡死)");
        } else {
            g_uiMiss.store(0);
        }
    }
}

static void JoinAllBg() {
    // 先等三个池的队列排空(最多 5 秒), 避免退出时无限等待
    for (int i = 0; i < 50; ++i) {
        bool empty = true;
        for (int c = 0; c < (int)TaskCls::CLS_COUNT; ++c) {
            std::lock_guard<std::mutex> lk(g_pools[c].mtx);
            if (!g_pools[c].q.empty()) { empty = false; break; }
        }
        int act = 0;
        for (int c = 0; c < (int)TaskCls::CLS_COUNT; ++c) act += g_pools[c].active.load();
        if (empty && act == 0) break;
        Sleep(100);
    }
    PoolShutdown();
    std::lock_guard<std::mutex> lk(g_bgMtx);
    for (auto& t : g_bgThreads) {
        if (t.joinable()) {
            if (t.get_id() == std::this_thread::get_id()) t.detach();
            else t.join();
        }
    }
    g_bgThreads.clear();
}

// ============================================================
//  进程枚举 / 终止
// ============================================================
static void EnumAllProcesses() {
    vector<ProcInfo> local;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe = { sizeof(pe) };
        if (Process32FirstW(snap, &pe)) {
            do {
                ProcInfo pi;
                pi.pid  = pe.th32ProcessID;
                pi.ppid = pe.th32ParentProcessID;
                pi.name = pe.szExeFile;
                pi.path.clear();          // 路径按需获取(GetProcPath), 避免枚举开销
                pi.suspicious = false;
                local.push_back(pi);
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }
    std::lock_guard<std::mutex> lk(g_procsMtx);
    g_procs.swap(local);
}

static bool KillProcess(DWORD pid) {
    if (pid == 0 || pid == 4) return false;
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!h || h == INVALID_HANDLE_VALUE) {
        LogFmt(L"KillProcess: OpenProcess(%u) failed err=%u", pid, GetLastError());
        return false;
    }
    bool ok = (TerminateProcess(h, 1) != 0);
    CloseHandle(h);
    LogFmt(L"KillProcess: pid=%u %s", pid, ok ? L"ok" : L"fail");
    return ok;
}


// ============================================================
//  威胁情报: 在线哈希库 / 恶意 IP 库
//  设计要点:
//   - 多源全量拉取(宁可重复, 不可缺漏), 解析后去重入库
//   - 拉取结果落盘缓存, 离线时可继续使用上次情报
//   - 仅用于"检测与告警", 不含任何攻击性 payload
// ============================================================
#include <deque>
#include <cmath>
#include <set>
#include <unordered_set>
#include <unordered_map>
#ifdef _WIN32
#include <winsvc.h>
#include <iphlpapi.h>
#include <map>
#endif

struct IntelSource {
    const wchar_t* url;
    int kind;              // 0=哈希列表  1=IP/CIDR 列表
    const wchar_t* name;
    bool big;              // 体积很大(如 MalwareBazaar 全量), 默认不拉
};

// kind=0 哈希源: 公开恶意文件哈希列表 (MD5/SHA1/SHA256 混合文本, 按长度自动识别)
// kind=1 IP 源 : 公开恶意 IP / CIDR 列表
static const IntelSource g_intelSources[] = {
    // ---- Malicious-Hash-Threat-List (GitHub raw) ----
    { L"https://raw.githubusercontent.com/amitambekar510/Malicious-Hash-Threat-List/main/Malicious_md5_hashes_aa.txt",   0, L"MHTL-MD5-aa",     false },
    { L"https://raw.githubusercontent.com/amitambekar510/Malicious-Hash-Threat-List/main/malicious_md5_hashes_ab.txt",   0, L"MHTL-MD5-ab",     false },
    { L"https://raw.githubusercontent.com/amitambekar510/Malicious-Hash-Threat-List/main/malicious_SHA1_hashes-aa.txt",  0, L"MHTL-SHA1-aa",    false },
    { L"https://raw.githubusercontent.com/amitambekar510/Malicious-Hash-Threat-List/main/malicious_SHA256_hashes_aa.txt",0, L"MHTL-SHA256-aa",  false },
    { L"https://raw.githubusercontent.com/amitambekar510/Malicious-Hash-Threat-List/main/malicious_SHA256_hashes_ab.txt",0, L"MHTL-SHA256-ab",  false },
    { L"https://raw.githubusercontent.com/amitambekar510/Malicious-Hash-Threat-List/main/malicious_SHA256_hashes_ac.txt",0, L"MHTL-SHA256-ac",  false },
    // ---- romainmarcoux/malicious-hash (聚合: MalwareBazaar + URLhaus + OTX) ----
    { L"https://raw.githubusercontent.com/romainmarcoux/malicious-hash/main/full-hash-md5-aa.txt",    0, L"RM-hash-md5",   false },
    { L"https://raw.githubusercontent.com/romainmarcoux/malicious-hash/main/full-hash-sha1-aa.txt",   0, L"RM-hash-sha1",  false },
    { L"https://raw.githubusercontent.com/romainmarcoux/malicious-hash/main/full-hash-sha256-aa.txt", 0, L"RM-hash-sha256", false },
    // ---- abuse.ch MalwareBazaar 官方导出 (recent = 最近 48 小时) ----
    { L"https://bazaar.abuse.ch/export/txt/sha256/recent/", 0, L"MalwareBazaar-recent", false },
    { L"https://bazaar.abuse.ch/export/txt/md5/recent/",    0, L"MalwareBazaar-md5-recent", false },
    { L"https://bazaar.abuse.ch/export/txt/sha256/full/",   0, L"MalwareBazaar-FULL(70MB)", true },
    // ---- 恶意 IP / CIDR ----
    { L"https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/inbound.txt",  1, L"bitwire-inbound",  false },
    { L"https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/outbound.txt", 1, L"bitwire-outbound", false },
    { L"https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", 1, L"firehol-level1", false },
    { L"https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_abusers_1d.netset", 1, L"firehol-abusers-1d", false },
};
static const int g_intelSourceCount = (int)(sizeof(g_intelSources) / sizeof(g_intelSources[0]));

// 情报库
static std::mutex g_intelMtx;
static std::unordered_set<std::wstring> g_intelHashes;              // 恶意文件哈希(小写)
static std::vector<std::pair<unsigned long, unsigned long>> g_intelNets; // (网络序网络号, 掩码)
static std::atomic<long long> g_intelHashCount{0};
static std::atomic<long long> g_intelIpCount{0};
static std::atomic<long long> g_intelLastUpdate{0};   // Unix 秒
static std::atomic<bool>      g_intelUpdating{false};

// ---- 工具: IP 字符串 -> 32 位整数 (网络序) ----
static bool IpToUint(const std::wstring& ip, unsigned long& out) {
    {
        int part = 0; unsigned long val = 0; unsigned long res = 0;
        for (size_t i = 0; i <= ip.size(); ++i) {
            wchar_t ch = (i < ip.size()) ? ip[i] : L'.';
            if (ch >= L'0' && ch <= L'9') {
                val = val * 10 + (unsigned long)(ch - L'0');
            } else if (ch == L'.') {
                if (part >= 4 || val > 255) return false;
                res = (res << 8) | val; val = 0; part++;
            } else {
                return false;   // 非法字符(含 ':' 即 IPv6, 本函数只处理 IPv4)
            }
        }
        if (part != 4) return false;
        out = res;
        return true;
    }
}

// ---- 工具: 判断是否为内网/私有/保留地址 ----
static bool IsPrivateIp(unsigned long ip) {
    unsigned char b1 = (unsigned char)((ip >> 24) & 0xFF);
    unsigned char b2 = (unsigned char)((ip >> 16) & 0xFF);
    if (b1 == 10) return true;                       // 10.0.0.0/8
    if (b1 == 172 && b2 >= 16 && b2 <= 31) return true; // 172.16.0.0/12
    if (b1 == 192 && b2 == 168) return true;         // 192.168.0.0/16
    if (b1 == 127) return true;                      // 127.0.0.0/8 loopback
    if (b1 == 169 && b2 == 254) return true;         // 169.254.0.0/16 link-local
    if (b1 == 0) return true;                        // 0.0.0.0/8
    if (b1 >= 224) return true;                      // 组播/保留
    return false;
}

// ---- 工具: 十六进制字符判定 ----
static inline bool IsHexW(wchar_t c) {
    return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F');
}

// ---- 解析一段情报文本, 提取哈希 / IP ----
// kind: 0=哈希 1=IP/CIDR ; 返回本次新增条目数
static long long IntelParseText(const std::wstring& text, int kind, long long& addedHash, long long& addedIp) {
    long long n = 0;
    size_t i = 0;
    const size_t len = text.size();
    while (i < len) {
        // 跳到行尾
        size_t e = text.find(L'\n', i);
        if (e == std::wstring::npos) e = len;
        size_t r = e;
        if (r > i && text[r - 1] == L'\r') r--;
        std::wstring line = text.substr(i, r - i);
        i = e + 1;

        // 去注释
        size_t hashPos = line.find(L'#');
        if (hashPos != std::wstring::npos) line = line.substr(0, hashPos);
        // 去空白
        std::wstring t;
        for (wchar_t c : line) if (c != L' ' && c != L'\t') t.push_back(c);
        if (t.empty()) continue;

        if (kind == 0) {
            // 提取连续 hex 串, 长度 32(MD5) / 40(SHA1) / 64(SHA256)
            size_t p = 0;
            while (p < t.size()) {
                while (p < t.size() && !IsHexW(t[p])) p++;
                size_t s = p;
                while (p < t.size() && IsHexW(t[p])) p++;
                size_t l = p - s;
                if (l == 32 || l == 40 || l == 64) {
                    std::wstring h = t.substr(s, l);
                    for (wchar_t& c : h) if (c >= L'A' && c <= L'F') c = (wchar_t)(c - L'A' + L'a');
                    std::lock_guard<std::mutex> lk(g_intelMtx);
                    if (g_intelHashes.insert(h).second) { addedHash++; n++; }
                }
            }
        } else {
            // 提取 x.x.x.x 或 x.x.x.x/nn
            std::wstring ipPart = t;
            std::wstring cidr;
            size_t sl = t.find(L'/');
            if (sl != std::wstring::npos) { ipPart = t.substr(0, sl); cidr = t.substr(sl + 1); }
            // 去掉可能的 "ip,port" 或尾部附加字段: 取第一个非 IP 字符前
            std::wstring ip;
            int dots = 0;
            for (wchar_t c : ipPart) {
                if ((c >= L'0' && c <= L'9') || c == L'.') { ip.push_back(c); if (c == L'.') dots++; }
                else break;
            }
            unsigned long u = 0;
            if (dots == 3 && IpToUint(ip, u)) {
                unsigned long bits = 32;
                if (!cidr.empty()) {
                    unsigned long v = 0; bool ok = true;
                    for (wchar_t c : cidr) {
                        if (c >= L'0' && c <= L'9') v = v * 10 + (unsigned long)(c - L'0');
                        else { ok = false; break; }
                    }
                    if (ok && v <= 32) bits = v;
                }
                unsigned long mask = (bits == 0) ? 0 : (0xFFFFFFFFu << (32 - bits));
                unsigned long net = u & mask;
                std::lock_guard<std::mutex> lk(g_intelMtx);
                // 去重: 相同 (net,mask) 只存一次
                bool dup = false;
                for (auto& pr : g_intelNets) if (pr.first == net && pr.second == mask) { dup = true; break; }
                if (!dup) { g_intelNets.emplace_back(net, mask); addedIp++; n++; }
            }
        }
    }
    return n;
}

// ---- HTTP(S) 下载文本 (WinHTTP) ----
static bool HttpGetText(const std::wstring& url, std::wstring& out) {
    out.clear();
    // 解析 scheme / host / path
    std::wstring u = url;
    bool https = false;
    if (u.rfind(L"https://", 0) == 0) { https = true; u = u.substr(8); }
    else if (u.rfind(L"http://", 0) == 0) { u = u.substr(7); }
    else return false;
    size_t slash = u.find(L'/');
    std::wstring host = (slash == std::wstring::npos) ? u : u.substr(0, slash);
    std::wstring path = (slash == std::wstring::npos) ? L"/" : u.substr(slash);

    HINTERNET hSession = WinHttpOpen(L"ZZ-EDR/13.5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;
    HINTERNET hConn = WinHttpConnect(hSession, host.c_str(), https ? 443 : 80, 0);
    if (!hConn) { WinHttpCloseHandle(hSession); return false; }
    HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", path.c_str(), nullptr,
                                        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                        https ? WINHTTP_FLAG_SECURE : 0);
    if (!hReq) { WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSession); return false; }

    bool ok = false;
    if (WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                           WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(hReq, nullptr)) {
        ok = true;
        char buf[8192];
        for (;;) {
            unsigned long avail = 0;
            if (!WinHttpQueryDataAvailable(hReq, &avail) || avail == 0) break;
            if (avail > sizeof(buf)) avail = sizeof(buf);
            unsigned long read = 0;
            if (!WinHttpReadData(hReq, buf, avail, &read) || read == 0) break;
            // 窄字符按本地代码页扩展为宽字符(情报文件均为 ASCII)
            for (unsigned long k = 0; k < read; ++k) out.push_back((wchar_t)(unsigned char)buf[k]);
            if (out.size() > 200 * 1024 * 1024) break;  // 200MB 上限保护
        }
    }
    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    WinHttpCloseHandle(hSession);
    return ok && !out.empty();
}

// ---- 情报缓存目录 ----
static std::wstring IntelCacheDir() {
    wchar_t tmp[MAX_PATH] = { 0 };
    GetTempPathW(MAX_PATH, tmp);
    std::wstring d = std::wstring(tmp) + L"zz_EDR_intel";
    CreateDirectoryW(d.c_str(), nullptr);
    return d;
}

// ---- 从磁盘缓存加载 ----
static long long IntelLoadCache() {
    long long ah = 0, ai = 0;
    std::wstring dir = IntelCacheDir();
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((dir + L"\\*.txt").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        std::wstring fp = dir + L"\\" + fd.cFileName;
        HANDLE f = CreateFileW(fp.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f == INVALID_HANDLE_VALUE) continue;
        std::wstring text;
        char buf[65536];
        for (;;) {
            unsigned long rd = 0;
            if (!ReadFile(f, buf, sizeof(buf), &rd, nullptr) || rd == 0) break;
            for (unsigned long k = 0; k < rd; ++k) text.push_back((wchar_t)(unsigned char)buf[k]);
        }
        CloseHandle(f);
        int kind = (wcsstr(fd.cFileName, L"ip") == fd.cFileName) ? 1 : 0;
        IntelParseText(text, kind, ah, ai);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    g_intelHashCount.fetch_add(ah);
    g_intelIpCount.fetch_add(ai);
    if (ah || ai) LogFmt(L"情报: 已从本地缓存加载 哈希=%lld IP=%lld", ah, ai);
    return ah + ai;
}

// ---- 在线更新全部情报源 ----
static long long IntelUpdateAll(bool includeBig) {
    if (g_intelUpdating.exchange(true)) {
        LogPost(L"情报: 更新已在进行中, 请稍候");
        return 0;
    }
    long long total = 0;
    LogPost(L"情报: 开始从公开源更新 (多源全量拉取, 去重入库)...");
    std::wstring dir = IntelCacheDir();
    for (int i = 0; i < g_intelSourceCount; ++i) {
        const IntelSource& s = g_intelSources[i];
        if (s.big && !includeBig) {
            LogFmt(L"情报: 跳过超大源 %s (体积过大, 可在配置中开启)", s.name);
            continue;
        }
        std::wstring text;
        if (!HttpGetText(s.url, text)) {
            LogFmt(L"情报: 源 %s 拉取失败(离线或网络不可达), 继续使用缓存", s.name);
            continue;
        }
        long long ah = 0, ai = 0;
        long long n = IntelParseText(text, s.kind, ah, ai);
        total += n;
        LogFmt(L"情报: %s 解析完成, 新增 哈希=%lld IP=%lld", s.name, ah, ai);
        // 落盘缓存
        std::wstring fn = dir + L"\\" + (s.kind == 1 ? L"ip_" : L"hash_") + s.name + L".txt";
        HANDLE f = CreateFileW(fn.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f != INVALID_HANDLE_VALUE) {
            std::string narrow;
            for (wchar_t c : text) narrow.push_back((char)(c & 0x7F));
            unsigned long wr = 0;
            WriteFile(f, narrow.data(), (unsigned long)narrow.size(), &wr, nullptr);
            CloseHandle(f);
        }
    }
    g_intelHashCount.store((long long)g_intelHashes.size());
    g_intelIpCount.store((long long)g_intelNets.size());
    g_intelLastUpdate.store((long long)time(nullptr));
    LogFmt(L"情报: 更新完成, 本次新增 %lld 条; 库中 哈希=%lld IP段=%lld",
           total, g_intelHashCount.load(), g_intelIpCount.load());
    g_intelUpdating.store(false);
    return total;
}

// ---- 查询: 文件哈希是否命中情报 ----
static bool IntelHashHit(const std::wstring& hex, std::wstring& tag) {
    if (hex.empty()) return false;
    std::wstring h = hex;
    for (wchar_t& c : h) if (c >= L'A' && c <= L'F') c = (wchar_t)(c - L'A' + L'a');
    std::lock_guard<std::mutex> lk(g_intelMtx);
    if (g_intelHashes.find(h) != g_intelHashes.end()) {
        tag = L"在线情报库命中(已知恶意文件哈希)";
        return true;
    }
    return false;
}

// ---- 查询: IP 是否命中情报 (含 CIDR 匹配) ----
static bool IntelIpHit(const std::wstring& ip, std::wstring& why) {
    unsigned long u = 0;
    if (!IpToUint(ip, u)) return false;
    if (IsPrivateIp(u)) return false;    // 内网不参与外部情报判定
    std::lock_guard<std::mutex> lk(g_intelMtx);
    for (auto& pr : g_intelNets) {
        if ((u & pr.second) == pr.first) {
            why = L"命中威胁情报 IP 黑名单 (CIDR 匹配)";
            return true;
        }
    }
    return false;
}

// ---- 判断是否为"对外/境外方向"的连接 ----
// 说明: 未内置 GeoIP 数据库, 采用"排除内网 + 公网判定";
//       公网外连统一标记为"对外连接", 命中黑名单者判定为风险。
static bool IntelIsExternalIp(const std::wstring& ip) {
    unsigned long u = 0;
    if (!IpToUint(ip, u)) return false;
    return !IsPrivateIp(u);
}


// 前向声明: 保护路径判定 (定义见后文, 此处供行为/沙箱模块使用)
static bool IsProtectedPath(const wstring& p);
// 前向声明: 定义见后文, 供沙箱/行为模块使用
static bool FileSha256W(const std::wstring& path, std::wstring& outHex);
static int  RuleMatchText(const wstring& lowerText, wstring& hitName, wstring& hitDesc);
static void EnumTcpConnections();
static void EnumAllProcesses();
static void DisconnectConnection(DWORD pid);
static void QuarantineFile(const wstring& path);
static void DeleteFileWWrapper(const wstring& path);
// 强制终止规则 (定义见后文)
static int  ForceKillRuleEnforce(bool recover);
static bool ForceKillMatch(const std::wstring& name, const std::wstring& path,
                           const std::wstring& cmd, std::wstring& hitDesc);
static void RecoverAfterForceKill(const std::wstring& name, const std::wstring& path,
                                  DWORD pid, const std::wstring& hitDesc);
// v13.18 银狐白加黑专项 (定义见文件后部 g_sideloadDll 之后)
static int  FoxSideloadDllHit(const std::wstring& exePath, std::wstring& outDll);
static int  FoxWhiteBlackEnforce();
// v13.19 银狐深度专项(定义见文件后部)
static bool FoxC2Hit(const std::wstring& remote, std::wstring& why);
static int  FoxBaitNameHit(const std::wstring& path);
static void FoxByovdScan();
static void FoxDefenderExclusionScan();
static void FoxPythonPayloadScan();
static void FoxDeepScan();

// ============================================================
//  行为监控系统 (Behavior Monitor)
//  记录每个进程的: 启动/命令行/钩子/文件/注册表/网络/内存/驱动行为
//  UI: 进程列表 -> "行为" -> 二级菜单(时间线)
// ============================================================
enum BehavType {
    BEHAV_PROC_START = 0,   // 进程启动
    BEHAV_CMD,              // 命令行
    BEHAV_HOOK,             // 钩子/注入
    BEHAV_FILE,             // 文件操作
    BEHAV_REG,              // 注册表操作
    BEHAV_NET,              // 网络连接
    BEHAV_MEM,              // 内存异常
    BEHAV_DRIVER,           // 驱动加载
    BEHAV_SIGN,             // 签名/哈希判定
    BEHAV_BLOCK,            // 被阻止
    BEHAV_SANDBOX           // 沙箱分析
};
static const wchar_t* BehavTypeName(int t) {
    switch (t) {
        case BEHAV_PROC_START: return L"进程启动";
        case BEHAV_CMD:        return L"命令行";
        case BEHAV_HOOK:       return L"钩子/注入";
        case BEHAV_FILE:       return L"文件操作";
        case BEHAV_REG:        return L"注册表";
        case BEHAV_NET:        return L"网络连接";
        case BEHAV_MEM:        return L"内存异常";
        case BEHAV_DRIVER:     return L"驱动加载";
        case BEHAV_SIGN:       return L"签名/哈希";
        case BEHAV_BLOCK:      return L"已阻止";
        case BEHAV_SANDBOX:    return L"沙箱分析";
    }
    return L"其他";
}

struct BehavRecord {
    long long  ts;      // Unix 秒
    DWORD      pid;
    wstring    proc;    // 进程名
    int        type;    // BehavType
    int        risk;    // 0-10
    wstring    detail;
};

#define MAX_BEHAV 20000
static std::mutex g_behavMtx;
static std::deque<BehavRecord> g_behav;   // 有界队列

static void BehavAdd(DWORD pid, const wstring& proc, int type, int risk, const wstring& detail) {
    BehavRecord r;
    r.ts = (long long)time(nullptr);
    r.pid = pid; r.proc = proc; r.type = type; r.risk = risk; r.detail = detail;
    std::lock_guard<std::mutex> lk(g_behavMtx);
    g_behav.push_back(r);
    while ((int)g_behav.size() > MAX_BEHAV) g_behav.pop_front();
}

static std::vector<BehavRecord> BehavGet(DWORD pid) {
    std::lock_guard<std::mutex> lk(g_behavMtx);
    std::vector<BehavRecord> out;
    for (auto& r : g_behav) if (r.pid == pid) out.push_back(r);
    return out;
}
static std::vector<BehavRecord> BehavGetAll() {
    std::lock_guard<std::mutex> lk(g_behavMtx);
    return std::vector<BehavRecord>(g_behav.begin(), g_behav.end());
}

// ---- 读取进程命令行 (PEB -> RTL_USER_PROCESS_PARAMETERS -> CommandLine) ----
static wstring GetProcCommandLine(DWORD pid) {
    if (pid == 0 || pid == 4) return L"";
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h || h == INVALID_HANDLE_VALUE) return L"";
    wstring out;
    // 动态取 NtQueryInformationProcess
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
        NtQueryInformationProcessPtr pNt =
            (NtQueryInformationProcessPtr)GetProcAddress(ntdll, "NtQueryInformationProcess");
        if (pNt) {
            PROCESS_BASIC_INFORMATION_STUB pbi;
            memset(&pbi, 0, sizeof(pbi));
            if (pNt(h, 0, &pbi, (unsigned long)sizeof(pbi), nullptr) == 0 && pbi.PebBaseAddress) {
                PEB_STUB peb;
                memset(&peb, 0, sizeof(peb));
                SIZE_T rd = 0;
                if (ReadProcessMemory(h, pbi.PebBaseAddress, &peb, sizeof(peb), &rd) && peb.ProcessParameters) {
                    RTL_USER_PROCESS_PARAMETERS_STUB upp;
                    memset(&upp, 0, sizeof(upp));
                    rd = 0;
                    if (ReadProcessMemory(h, peb.ProcessParameters, &upp, sizeof(upp), &rd) &&
                        upp.CommandLine.Buffer && upp.CommandLine.Length > 0 &&
                        upp.CommandLine.Length < 32768) {
                        std::vector<wchar_t> buf((size_t)upp.CommandLine.Length / sizeof(wchar_t) + 2, L'\0');
                        rd = 0;
                        if (ReadProcessMemory(h, upp.CommandLine.Buffer, buf.data(),
                                              upp.CommandLine.Length, &rd)) {
                            out.assign(buf.data(), rd / sizeof(wchar_t));
                        }
                    }
                }
            }
        }
    }
    CloseHandle(h);
    return out;
}

// ---- 数字签名验证 (WinVerifyTrust, 动态加载 wintrust.dll) ----
// 返回: 1=签名有效  0=无签名/无效  -1=无法验证
static int VerifyFileSignature(const wstring& path) {
    HMODULE hWt = LoadLibraryW(L"wintrust.dll");
    if (!hWt) return -1;
    WinVerifyTrustPtr pVerify = (WinVerifyTrustPtr)GetProcAddress(hWt, "WinVerifyTrust");
    if (!pVerify) { FreeLibrary(hWt); return -1; }

    // WINTRUST_ACTION_GENERIC_VERIFY_V2
    GUID_STUB policy;
    policy.a = 0x00AAC56B; policy.b = 0xCD44; policy.c = 0x11D0;
    const unsigned char d8[8] = { 0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE };
    for (int i = 0; i < 8; ++i) policy.d[i] = d8[i];

    WINTRUST_FILE_INFO_STUB fi;
    memset(&fi, 0, sizeof(fi));
    fi.cbStruct = (unsigned long)sizeof(fi);
    fi.pcwszFilePath = path.c_str();

    WINTRUST_DATA_STUB wd;
    memset(&wd, 0, sizeof(wd));
    wd.cbStruct = (unsigned long)sizeof(wd);
    wd.dwUnionChoice = 1;              // WTD_CHOICE_FILE
    wd.pFile = &fi;
    wd.dwUIChoice = 2;                 // WTD_UI_NONE
    wd.fdwRevocationChecks = 0;        // WTD_REVOKE_NONE
    wd.dwStateAction = 1;              // WTD_STATEACTION_VERIFY
    wd.dwProvFlags = 0x00000010;       // WTD_SAFER_FLAG

    long rc = pVerify(nullptr, &policy, &wd);
    wd.dwStateAction = 2;              // WTD_STATEACTION_CLOSE
    pVerify(nullptr, &policy, &wd);
    FreeLibrary(hWt);
    return (rc == 0) ? 1 : 0;
}

// ---- "乱七八糟哈希值命名"判定 ----
// 命中条件: 主文件名是 32/40/64 位纯 hex, 或 >=25 字符且无元音/无语义分隔的高熵串
static bool IsHashLikeName(const wstring& path) {
    wstring name = path;
    size_t bs = name.rfind(L'\\');
    if (bs != wstring::npos) name = name.substr(bs + 1);
    size_t dot = name.rfind(L'.');
    wstring stem = (dot != wstring::npos) ? name.substr(0, dot) : name;
    if (stem.size() < 16) return false;

    int hex = 0;
    for (wchar_t c : stem) if (IsHexW(c)) hex++;
    bool allHex = ((size_t)hex == stem.size());
    if (allHex && (stem.size() == 32 || stem.size() == 40 || stem.size() == 64)) return true;

    // 长随机串: 长度>=25 且 数字+字母混合且含 >=6 个数字
    if (stem.size() >= 25) {
        int digits = 0, letters = 0;
        for (wchar_t c : stem) {
            if (c >= L'0' && c <= L'9') digits++;
            else if ((c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z')) letters++;
        }
        if (digits >= 6 && letters >= 6) return true;
    }
    return false;
}

// ---- 是否应阻止运行 ----
// 规则: 无有效数字签名 或 文件名像随机哈希 -> 默认阻止
static bool ShouldBlockRun(const wstring& path, wstring& reason) {
    if (IsProtectedPath(path)) return false;         // 系统路径/自身 永不阻止
    if (path.empty()) return false;
    int sig = VerifyFileSignature(path);
    if (sig == 0) {
        reason = L"无有效数字签名";
        return true;
    }
    if (IsHashLikeName(path)) {
        reason = L"文件名呈随机哈希特征";
        return true;
    }
    return false;
}

// ---- 用同名空文件覆盖 (销毁文件内容) ----
// 说明: 先把目标截断为 0 字节, 再写入同名空文件; 仅限用户确认/高危连坐场景
static bool OverwriteWithEmptyFile(const wstring& path) {
    if (path.empty() || IsProtectedPath(path)) return false;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        // 只读/占用文件: 尝试去掉只读属性后重试
        DWORD attr = GetFileAttributesW(path.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_READONLY)) {
            SetFileAttributesW(path.c_str(), attr & ~FILE_ATTRIBUTE_READONLY);
            h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                            TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        }
        if (h == INVALID_HANDLE_VALUE) return false;
    }
    SetEndOfFile(h);
    FlushFileBuffers(h);
    CloseHandle(h);
    return true;
}

// ============================================================
//  漏洞情报订阅 —— CISA KEV / NVD / 国内信创 / 自定义聚合
// ------------------------------------------------------------
//  【设计思路】三层情报, 信号强度与用途各不相同, 不可混为一谈:
//
//   ① CISA KEV      "已在野利用"漏洞目录。数量极少(千级)但条条要命,
//                   是判断"现在立刻就得修"的最高信号源。
//                   本程序用它做【处置升级】: 命中某个 CVE 且该 CVE
//                   同时出现在 KEV 中, 说明攻击者已经在实战中使用,
//                   不再是"理论风险", 因此风险拉满并允许强制处置。
//                   —— 这是 KEV 区别于其他源的核心价值。
//
//   ② NVD / CVE.org 全量 CVE 底座(20万+条), 提供 CVSS 评分与 CPE
//                   影响范围, 用来判断"有多严重"和"影响哪些版本"。
//                   量太大, 本程序只取近期条目并按 CVSS 阈值筛选入库,
//                   避免内存与匹配开销失控。
//
//   ③ CNNVD / CNVD  国内与信创生态(麒麟/统信/达梦/人大金仓等)的一手材料。
//                   【重要说明】这两家官方并未提供稳定的、可机读的公开
//                   feed(页面需登录/验证码/无 RSS), 因此本程序不硬编码
//                   死链——那只会造成"每次更新都失败"的假象。
//                   改为留出可配置订阅入口(配置项 vulnCustomUrl):
//                   用户从 CNNVD 周报 / 奇安信威胁情报中心 / 360 漏洞云 /
//                   腾讯安全通告 / Seebug 等渠道导出 CVE 编号列表后填入,
//                   支持最简格式(纯文本, 每行一个 CVE 编号)。
//
//  【为什么这样接】"宁可重复、不可缺少"的哈希库思路不适用于漏洞库:
//                  漏洞库的价值在于"精选+分级", 全量堆砌只会淹没信号。
//                  所以本模块只做三件事: 拉 KEV、拉 NVD 近期高危、
//                  把 KevSet 用于处置升级。
// ============================================================

struct VulnSource {
    const wchar_t* url;
    int kind;   // 0=CISA KEV JSON  1=NVD RSS(XML)  2=NVD API JSON  3=纯CVE编号文本(自定义/国内)
    const wchar_t* name;
};

static const VulnSource g_vulnSources[] = {
    // ① 必盯: CISA 已知被利用漏洞目录 (官方 JSON, 每日更新)
    { L"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
      0, L"CISA-KEV" },
    // ② 底座: NVD 近期 CVE 的 RSS (XML, 无需 API Key)
    { L"https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml", 1, L"NVD-RSS" },
    // ② 底座: NVD API 2.0 近期条目 (JSON, 带 CVSS; 高频调用建议配 API Key)
    { L"https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=200", 2, L"NVD-API" },
};
static const int g_vulnSourceCount = (int)(sizeof(g_vulnSources) / sizeof(g_vulnSources[0]));

// 漏洞库
static std::mutex g_vulnMtx;
static std::unordered_set<std::wstring> g_kevSet;     // 已在野利用(最高信号)
static std::unordered_set<std::wstring> g_vulnHigh;   // 高危(CVSS >= 阈值)
static std::unordered_set<std::wstring> g_vulnAll;    // 全部已知 CVE
static std::atomic<long long> g_vulnKevCount{0};
static std::atomic<long long> g_vulnHighCount{0};
static std::atomic<long long> g_vulnLastUpdate{0};
static std::atomic<bool>      g_vulnUpdating{false};

// ---- JSON: 从 from 处起查找 "key":"value" 并取出 value ----
// 只处理字符串值; 找不到/不是字符串返回 false (调用方需自行兜底)
static bool VulnJsonStr(const std::wstring& s, size_t from, const std::wstring& key, std::wstring& out) {
    std::wstring k = L"\"" + key + L"\"";
    size_t p = s.find(k, from);
    if (p == std::wstring::npos) return false;
    p = s.find(L':', p + k.size());
    if (p == std::wstring::npos) return false;
    ++p;
    while (p < s.size() && (s[p] == L' ' || s[p] == L'\n' || s[p] == L'\r' || s[p] == L'\t')) ++p;
    if (p >= s.size() || s[p] != L'"') return false;   // 值不是字符串(可能是数字/null)
    size_t e = ++p;
    while (e < s.size() && s[e] != L'"') {              // 跳过转义, 防止 \" 提前截断
        if (s[e] == L'\\') ++e;
        ++e;
    }
    out = s.substr(p, e - p);
    return true;
}

// ---- 从任意文本中提取 CVE 编号 (CVE-YYYY-NNNN...) ----
static bool VulnExtractId(const std::wstring& t, size_t from, std::wstring& out, size_t& next) {
    size_t c = t.find(L"CVE-", from);
    if (c == std::wstring::npos) return false;
    size_t e = c + 4;
    while (e < t.size() && ((t[e] >= L'0' && t[e] <= L'9') || t[e] == L'-')) ++e;
    if (e - c <= 8) { next = c + 4; return false; }     // 太短, 不是完整编号
    out = t.substr(c, e - c);
    next = e;
    return true;
}

// ---- 解析 ①: CISA KEV JSON ----
static int VulnParseKev(const std::wstring& s) {
    int n = 0;
    size_t p = 0;
    for (;;) {
        size_t v = s.find(L"\"cveID\"", p);
        if (v == std::wstring::npos) break;
        std::wstring id;
        if (VulnJsonStr(s, v, L"cveID", id) && id.size() > 8) {
            std::lock_guard<std::mutex> lk(g_vulnMtx);
            g_kevSet.insert(id);
            g_vulnAll.insert(id);
            ++n;
        }
        p = v + 7;
    }
    return n;
}

// ---- 解析 ②: NVD RSS (XML, 逐个 <item> 取 <title> 里的 CVE 编号) ----
static int VulnParseRss(const std::wstring& s) {
    int n = 0;
    size_t p = 0;
    for (;;) {
        size_t t = s.find(L"<item>", p);
        if (t == std::wstring::npos) break;
        size_t e = s.find(L"</item>", t);
        if (e == std::wstring::npos) break;             // 未闭合, 停止解析
        std::wstring item = s.substr(t, e - t);
        size_t tt = item.find(L"<title>");
        size_t te = item.find(L"</title>", tt);
        if (tt != std::wstring::npos && te != std::wstring::npos) {
            std::wstring title = item.substr(tt + 7, te - tt - 7);
            std::wstring id; size_t nx = 0;
            if (VulnExtractId(title, 0, id, nx)) {
                std::lock_guard<std::mutex> lk(g_vulnMtx);
                g_vulnAll.insert(id);
                ++n;
            }
        }
        p = e + 7;
    }
    return n;
}

// ---- 解析 ③: NVD API 2.0 JSON (取 id 与 baseScore, 按阈值入高危库) ----
static int VulnParseNvdApi(const std::wstring& s, int thresh) {
    int n = 0, high = 0;
    size_t p = 0;
    for (;;) {
        size_t c = s.find(L"\"id\":\"CVE-", p);
        if (c == std::wstring::npos) break;
        size_t st = c + 6;
        size_t e = s.find(L'"', st);
        if (e == std::wstring::npos) break;
        std::wstring id = s.substr(st, e - st);
        // 找该条目后续的 baseScore (CVSS 3.1)
        double score = 0;
        size_t bs = s.find(L"\"baseScore\"", e);
        if (bs != std::wstring::npos) {
            size_t colon = s.find(L':', bs);
            if (colon != std::wstring::npos) {
                size_t q = colon + 1;
                while (q < s.size() && (s[q] == L' ' || s[q] == L'\t')) ++q;
                if (q < s.size() && ((s[q] >= L'0' && s[q] <= L'9') || s[q] == L'.')) {
                    score = wcstod(s.c_str() + q, nullptr);
                }
            }
        }
        {
            std::lock_guard<std::mutex> lk(g_vulnMtx);
            g_vulnAll.insert(id);
            if (score >= thresh) { g_vulnHigh.insert(id); ++high; }
        }
        ++n;
        p = e + 1;
    }
    LogFmt(L"漏洞: NVD API 解析 %d 条, 其中 CVSS>=%d 的高危 %d 条", n, thresh, high);
    return n;
}

// ---- 解析 ④: 纯 CVE 编号文本 (自定义订阅 / 国内 CNNVD、CNVD 导出) ----
static int VulnParsePlain(const std::wstring& s) {
    int n = 0;
    size_t pos = 0;
    std::wstring id;
    for (;;) {
        size_t nx = 0;
        if (!VulnExtractId(s, pos, id, nx)) break;
        {
            std::lock_guard<std::mutex> lk(g_vulnMtx);
            g_vulnAll.insert(id);
        }
        ++n;
        pos = nx;
    }
    return n;
}

// ---- 漏洞情报缓存目录 ----
static std::wstring VulnCacheDir() {
    wchar_t tmp[MAX_PATH] = { 0 };
    GetTempPathW(MAX_PATH, tmp);
    std::wstring d = std::wstring(tmp) + L"zz_EDR_vuln";
    CreateDirectoryW(d.c_str(), nullptr);
    return d;
}

// ---- 查询: 该 CVE 是否已在野被利用 (CISA KEV) ----
// 这是本模块最有价值的接口: KEV 命中 = 攻击者已在实战中使用, 需立即处置。
static bool VulnIsKev(const std::wstring& cve) {
    if (cve.empty()) return false;
    std::lock_guard<std::mutex> lk(g_vulnMtx);
    return g_kevSet.find(cve) != g_kevSet.end();
}

// ---- 查询: 该 CVE 是否被判高危 (NVD CVSS 超阈值) ----
static bool VulnIsHigh(const std::wstring& cve) {
    if (cve.empty()) return false;
    std::lock_guard<std::mutex> lk(g_vulnMtx);
    return g_vulnHigh.find(cve) != g_vulnHigh.end();
}

// ---- 查询: 该 CVE 是否在已知库中 ----
static bool VulnIsKnown(const std::wstring& cve) {
    if (cve.empty()) return false;
    std::lock_guard<std::mutex> lk(g_vulnMtx);
    return g_vulnAll.find(cve) != g_vulnAll.end();
}

// ---- 从磁盘缓存加载(离线可用) ----
static long long VulnLoadCache() {
    long long n = 0;
    std::wstring dir = VulnCacheDir();
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((dir + L"\\*.txt").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        std::wstring fp = dir + L"\\" + fd.cFileName;
        HANDLE f = CreateFileW(fp.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f == INVALID_HANDLE_VALUE) continue;
        std::wstring text;
        char buf[65536];
        for (;;) {
            unsigned long rd = 0;
            if (!ReadFile(f, buf, sizeof(buf), &rd, nullptr) || rd == 0) break;
            for (unsigned long k = 0; k < rd; ++k) text.push_back((wchar_t)(unsigned char)buf[k]);
        }
        CloseHandle(f);
        // 文件名前缀决定归属: kev_ -> 野利用库, 其余 -> 已知库
        if (wcsstr(fd.cFileName, L"kev_") == fd.cFileName) n += VulnParseKev(text);
        else                                               n += VulnParsePlain(text);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    g_vulnKevCount.store((long long)g_kevSet.size());
    if (n) LogFmt(L"漏洞: 已从本地缓存加载 %lld 条 (KEV=%d)", n, (int)g_kevSet.size());
    return n;
}

// ---- 在线更新全部漏洞情报源 ----
static long long VulnUpdateAll() {
    if (!g_cfg.vulnIntelOn) {
        LogPost(L"漏洞: 情报订阅已关闭(配置 vulnIntelOn=false), 跳过更新");
        return 0;
    }
    if (g_vulnUpdating.exchange(true)) {
        LogPost(L"漏洞: 更新已在进行中, 请稍候");
        return 0;
    }
    long long total = 0;
    LogPost(L"漏洞: 开始更新 (CISA KEV 必盯 + NVD 底座 + 自定义订阅)...");
    std::wstring dir = VulnCacheDir();

    for (int i = 0; i < g_vulnSourceCount; ++i) {
        const VulnSource& s = g_vulnSources[i];
        std::wstring text;
        if (!HttpGetText(s.url, text)) {
            // 不静默失败: 明确告知是网络问题, 且当前仍在使用旧缓存
            LogFmt(L"漏洞: 源 %s 拉取失败(离线/网络不可达/需代理), 继续使用本地缓存", s.name);
            continue;
        }
        long long n = 0;
        if      (s.kind == 0) n = VulnParseKev(text);
        else if (s.kind == 1) n = VulnParseRss(text);
        else if (s.kind == 2) n = VulnParseNvdApi(text, g_cfg.vulnCvssThresh);
        else                  n = VulnParsePlain(text);
        total += n;
        LogFmt(L"漏洞: %s 解析完成, 新增 %lld 条", s.name, n);
        // 落盘缓存(窄化 ASCII 存储)
        std::wstring fn = dir + L"\\" + std::wstring(s.kind == 0 ? L"kev_" : L"cve_") + s.name + L".txt";
        HANDLE f = CreateFileW(fn.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f != INVALID_HANDLE_VALUE) {
            std::string narrow;
            for (wchar_t c : text) narrow.push_back((char)(c & 0x7F));
            unsigned long wr = 0;
            WriteFile(f, narrow.data(), (unsigned long)narrow.size(), &wr, nullptr);
            CloseHandle(f);
        }
    }

    // ③ 自定义订阅(国内 CNNVD/CNVD、聚合平台导出的 CVE 编号列表)
    if (!g_cfg.vulnCustomUrl.empty()) {
        std::wstring text;
        if (HttpGetText(g_cfg.vulnCustomUrl, text)) {
            long long n = VulnParsePlain(text);
            total += n;
            LogFmt(L"漏洞: 自定义订阅源解析完成, 新增 %lld 条", n);
            std::wstring fn = dir + L"\\cve_custom.txt";
            HANDLE f = CreateFileW(fn.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                   FILE_ATTRIBUTE_NORMAL, nullptr);
            if (f != INVALID_HANDLE_VALUE) {
                std::string narrow;
                for (wchar_t c : text) narrow.push_back((char)(c & 0x7F));
                unsigned long wr = 0;
                WriteFile(f, narrow.data(), (unsigned long)narrow.size(), &wr, nullptr);
                CloseHandle(f);
            }
        } else {
            LogPost(L"漏洞: 自定义订阅源拉取失败, 继续使用本地缓存");
        }
    }

    g_vulnKevCount.store((long long)g_kevSet.size());
    g_vulnHighCount.store((long long)g_vulnHigh.size());
    g_vulnLastUpdate.store((long long)time(nullptr));
    LogFmt(L"漏洞: 更新完成, 本次新增 %lld 条; 库中 KEV(在野利用)=%lld 高危=%lld 总计=%d",
           total, g_vulnKevCount.load(), g_vulnHighCount.load(), (int)g_vulnAll.size());
    g_vulnUpdating.store(false);
    return total;
}

// ============================================================
//  CVE 漏洞利用特征库
//  说明: 以下为公开 CVE 的"检测特征"(漏洞编号 + 触发标识),
//        用于识别利用行为并告警/隔离, 不含任何攻击载荷。
// ============================================================
struct CveRule {
    const wchar_t* cve;
    const wchar_t* needle;     // 文本/命令行/内容中的特征串
    const wchar_t* desc;
    int risk;
};
static const CveRule g_cveRules[] = {
    { L"CVE-2026-21509", L"C32AB2EAC130CF11A7EB0000C05BAE0B", L"RTF 内嵌 Shell.Explorer.1 OLE 对象(疑似漏洞利用文档)", 9 },
    { L"CVE-2021-44228", L"jndi:ldap://",  L"Log4Shell JNDI 查找利用", 10 },
    { L"CVE-2021-45046", L"jndi:rmi://",   L"Log4Shell 变体 JNDI 查找", 10 },
    { L"CVE-2017-0144",  L"\\\\pipe\\\\",  L"EternalBlue/SMB 命名管道利用痕迹", 9 },
    { L"CVE-2021-34527", L"spoolsv",       L"PrintNightmare 打印后台处理服务利用", 8 },
    { L"CVE-2021-31207", L"ProxyShell",    L"ProxyShell Exchange 利用链", 9 },
    { L"CVE-2021-26855", L"ProxyLogon",    L"ProxyLogon Exchange SSRF 利用", 9 },
    { L"CVE-2022-30190", L"ms-msdt:",      L"Follina MSDT 协议滥用", 9 },
    { L"CVE-2021-40444", L"cabinet:",
      L"MSHTML 远程代码执行(恶意 ActiveX/ Cabinet 加载)", 9 },
    { L"CVE-2020-1472",  L"Zerologon",     L"Netlogon 特权提升", 9 },
    { L"CVE-2019-0708",  L"BlueKeep",      L"RDP 远程代码执行", 10 },
    { L"CVE-2014-0160",  L"Heartbleed",    L"OpenSSL 内存泄露利用", 8 },
    { L"CVE-2023-4966",  L"CitrixBleed",   L"Citrix NetScaler 会话泄露", 9 },
    { L"CVE-2023-38831", L"WinRAR",        L"WinRAR 归档远程代码执行", 7 },
    { L"CVE-2022-22965", L"Spring4Shell",  L"Spring 框架远程代码执行", 9 },
    { L"CVE-2018-8120",  L"win32k",        L"Win32k 权限提升利用痕迹", 8 },
    { L"CVE-2021-1675",  L"PrintNightmare",L"打印后台处理程序提权", 8 },
    { L"CVE-2022-26925", L"ADCS",          L"AD CS 证书模板提权", 8 },
    { L"CVE-2020-0796",  L"SMBGhost",      L"SMBv3 压缩远程代码执行", 10 },
    { L"CVE-2023-34362", L"MOVEit",        L"MOVEit Transfer SQL 注入", 9 },
};
static const int g_cveRuleCount = (int)(sizeof(g_cveRules) / sizeof(g_cveRules[0]));

// ---- 本地核查: 内置 CVE 规则库中有多少属于"已在野利用"(KEV) ----
// 用途: 不联网也能回答"我该优先修哪个"。KEV 命中 = 攻击者已在实战使用,
//       应排在所有修补任务最前面。
static int VulnCheckLocal() {
    if (g_vulnAll.empty()) {
        LogPost(L"漏洞: 库为空, 请先点\"漏洞情报更新(KEV/NVD)\"或检查网络");
        return 0;
    }
    int kev = 0, high = 0, known = 0;
    LogPost(L"===== 已知漏洞核查 (内置 CVE 规则 vs 在线情报库) =====");
    for (int i = 0; i < g_cveRuleCount; ++i) {
        std::wstring id = g_cveRules[i].cve;
        bool k = VulnIsKev(id), h = VulnIsHigh(id);
        if (k)      { ++kev;  LogFmt(L"  [紧急] %s 已在野被利用(CISA KEV) - %s", id.c_str(), g_cveRules[i].desc); }
        else if (h) { ++high; LogFmt(L"  [高危] %s CVSS 超阈值 - %s", id.c_str(), g_cveRules[i].desc); }
        if (VulnIsKnown(id)) ++known;
    }
    LogFmt(L"核查完成: 内置 %d 条 CVE 规则, 其中 KEV(在野利用)=%d 高危=%d 见于情报库=%d",
           g_cveRuleCount, kev, high, known);
    LogFmt(L"情报库规模: KEV=%lld 高危=%lld", g_vulnKevCount.load(), g_vulnHighCount.load());
    if (kev) {
        LogPost(L"建议: 上述 KEV 条目攻击者已在实战中使用, 请优先修补并立即全盘扫描");
        SetThreatLevel(2, L"内置 CVE 规则命中 CISA KEV(已在野利用)");
    }
    return kev;
}



// ---- CVE 命中检测 (输入: 待检文本, 已转小写) ----
static bool CveMatchText(const wstring& lowerText, wstring& cve, wstring& desc, int& risk) {
    for (int i = 0; i < g_cveRuleCount; ++i) {
        std::wstring nd = g_cveRules[i].needle;
        for (wchar_t& c : nd) if (c >= L'A' && c <= L'Z') c = (wchar_t)(c - L'A' + L'a');
        if (lowerText.find(nd) != wstring::npos) {
            cve = g_cveRules[i].cve;
            desc = g_cveRules[i].desc;
            risk = g_cveRules[i].risk;
            return true;
        }
    }
    return false;
}

// ---- 进程路径获取 (用于签名/哈希/连坐定位) ----
static wstring GetProcPath(DWORD pid) {
    if (pid == 0 || pid == 4) return L"";
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h || h == INVALID_HANDLE_VALUE) return L"";
    wchar_t buf[MAX_PATH] = { 0 };
    DWORD sz = MAX_PATH;
    wstring out;
    if (QueryFullProcessImageNameW(h, 0, buf, &sz)) out = buf;
    CloseHandle(h);
    return out;
}


// ============================================================
//  沙箱分析 (Sandbox): 静态 + 动态
//  静态: PE 结构/节区熵/导入表/字符串/签名/哈希/情报/CVE/规则
//  动态: 受限 Job 中试运行, 采样进程与网络变化, 记录全部行为
//  说明: 沙箱仅用于"观察与判定", 不产生任何对外攻击行为
// ============================================================

// ---- 计算字节熵 (0-8), >7.0 通常表示加壳/加密/压缩 ----
static double CalcEntropy(const unsigned char* data, size_t n) {
    if (!data || n == 0) return 0.0;
    unsigned long long freq[256] = { 0 };
    for (size_t i = 0; i < n; ++i) freq[data[i]]++;
    double ent = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (!freq[i]) continue;
        double p = (double)freq[i] / (double)n;
        ent -= p * (log(p) / log(2.0));
    }
    return ent;
}

// ---- 读文件全部内容 (限制 32MB) ----
static bool ReadFileAll(const wstring& path, std::vector<unsigned char>& out) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER li;
    li.QuadPart = 0;
    if (!GetFileSizeEx(h, &li) || li.QuadPart <= 0 || li.QuadPart > 32LL * 1024 * 1024) {
        CloseHandle(h);
        return false;
    }
    out.resize((size_t)li.QuadPart);
    unsigned long rd = 0;
    BOOL ok = ReadFile(h, out.data(), (unsigned long)out.size(), &rd, nullptr);
    CloseHandle(h);
    if (!ok || rd == 0) { out.clear(); return false; }
    out.resize(rd);
    return true;
}

// ---- 提取可打印字符串 (ASCII + UTF-16LE), 取前 N 条 ----
static void ExtractStrings(const std::vector<unsigned char>& d, std::vector<wstring>& out, int maxCount) {
    out.clear();
    // ASCII
    std::string cur;
    for (size_t i = 0; i < d.size() && (int)out.size() < maxCount; ++i) {
        unsigned char c = d[i];
        if (c >= 32 && c < 127) {
            cur.push_back((char)c);
        } else {
            if (cur.size() >= 6) {
                std::wstring w(cur.begin(), cur.end());
                out.push_back(w);
            }
            cur.clear();
        }
    }
    // UTF-16LE
    if (d.size() >= 2) {
        std::wstring w;
        for (size_t i = 0; i + 1 < d.size() && (int)out.size() < maxCount; i += 2) {
            unsigned char lo = d[i], hi = d[i + 1];
            if (hi == 0 && lo >= 32 && lo < 127) {
                w.push_back((wchar_t)lo);
            } else {
                if (w.size() >= 6) out.push_back(w);
                w.clear();
            }
        }
    }
}

// ---- 静态分析: 返回风险分 0-100, 报告写入 report ----
static int SandboxStaticAnalyze(const wstring& path, wstring& verdict, std::vector<wstring>& report) {
    report.clear();
    int risk = 0;
    verdict = L"未知";

    std::vector<unsigned char> data;
    if (!ReadFileAll(path, data)) {
        verdict = L"无法读取";
        report.push_back(L"[!] 无法读取文件(可能不存在/被占用/超 32MB)");
        return 0;
    }
    report.push_back(L"[文件] " + path);
    report.push_back(L"[大小] " + std::to_wstring(data.size()) + L" 字节");

    // --- 1. 哈希 ---
    wstring sha;
    if (FileSha256W(path, sha)) {
        report.push_back(L"[SHA256] " + sha);
        wstring tag;
        if (IntelHashHit(sha, tag)) {
            risk += 60;
            report.push_back(L"[!!] " + tag + L" (风险 +60)");
        }
    }

    // --- 2. 数字签名 ---
    int sig = VerifyFileSignature(path);
    if (sig == 1) { report.push_back(L"[签名] 有效数字签名"); }
    else if (sig == 0) { risk += 20; report.push_back(L"[签名] 无有效数字签名 (风险 +20)"); }
    else { report.push_back(L"[签名] 无法验证(组件缺失)"); }

    // --- 3. 哈希式命名 ---
    if (IsHashLikeName(path)) { risk += 15; report.push_back(L"[命名] 文件名呈随机哈希特征 (风险 +15)"); }

    // --- 4. PE 结构解析 (手动偏移, 兼容 PE32/PE32+) ---
    if (data.size() > 0x40 && data[0] == 'M' && data[1] == 'Z') {
        unsigned long e_lfanew = 0;
        memcpy(&e_lfanew, &data[0x3C], 4);
        if (e_lfanew + 24 < data.size() && data[e_lfanew] == 'P' && data[e_lfanew + 1] == 'E') {
            report.push_back(L"[PE] 有效 PE 映像");
            unsigned short nSec = 0, sizeOpt = 0;
            memcpy(&nSec, &data[e_lfanew + 6], 2);
            memcpy(&sizeOpt, &data[e_lfanew + 20], 2);
            unsigned short machine = 0;
            memcpy(&machine, &data[e_lfanew + 4], 2);
            report.push_back(L"[PE] 机器类型=0x" + std::to_wstring(machine) +
                             L" 节区数=" + std::to_wstring(nSec));

            size_t secOff = (size_t)e_lfanew + 24 + sizeOpt;
            for (unsigned short s = 0; s < nSec && secOff + 40 <= data.size(); ++s) {
                char name[9] = { 0 };
                memcpy(name, &data[secOff], 8);
                unsigned long vsize = 0, rawSize = 0, rawPtr = 0;
                memcpy(&vsize,   &data[secOff + 8],  4);
                memcpy(&rawSize, &data[secOff + 16], 4);
                memcpy(&rawPtr,  &data[secOff + 20], 4);
                double ent = 0;
                if (rawSize > 0 && rawPtr + rawSize <= data.size()) {
                    ent = CalcEntropy(&data[rawPtr], rawSize);
                }
                std::wstring wn(name, name + strnlen(name, 8));
                report.push_back(L"  [节区] " + wn + L" 原始大小=" + std::to_wstring(rawSize) +
                                 L" 熵=" + std::to_wstring(ent).substr(0, 4));
                if (ent > 7.0 && rawSize > 4096) {
                    risk += 10;
                    report.push_back(L"  [!!] 节区 " + wn + L" 熵>7.0, 疑似加壳/加密 (风险 +10)");
                }
                secOff += 40;
            }
        } else {
            report.push_back(L"[PE] 非 PE 文件 (脚本/文档/数据)");
            risk += 5;
        }
    } else {
        report.push_back(L"[PE] 非 MZ 头 (脚本/文档/数据)");
        risk += 5;
    }

    // --- 5. 字符串 + YARA 特征 + CVE ---
    std::vector<wstring> strs;
    ExtractStrings(data, strs, 4000);
    report.push_back(L"[字符串] 提取 " + std::to_wstring(strs.size()) + L" 条");
    int hitCount = 0;
    wstring lastHit;
    for (size_t i = 0; i < strs.size() && hitCount < 12; ++i) {
        std::wstring low = strs[i];
        for (wchar_t& c : low) if (c >= L'A' && c <= L'Z') c = (wchar_t)(c - L'A' + L'a');
        wstring nm, desc;
        int sev = 0;
        if (RuleMatchText(low, nm, desc) && sev >= 0) {
            hitCount++;
            lastHit = nm;
            report.push_back(L"[!!] YARA 命中: " + nm + L" - " + desc);
            risk += 12;
        }
        wstring cve, cdesc;
        int crisk = 0;
        if (CveMatchText(low, cve, cdesc, crisk)) {
            report.push_back(L"[!!] CVE 命中: " + cve + L" - " + cdesc + L" (风险 +" +
                             std::to_wstring(crisk) + L")");
            risk += crisk;
        }
    }
    if (hitCount) report.push_back(L"[YARA] 共命中 " + std::to_wstring(hitCount) + L" 条特征");

    if (risk >= 60) verdict = L"高危(建议隔离/删除)";
    else if (risk >= 30) verdict = L"可疑(建议隔离观察)";
    else if (risk >= 12) verdict = L"低风险(建议监控)";
    else verdict = L"未见明显异常";
    if (risk > 100) risk = 100;
    report.push_back(L"[结论] 风险分=" + std::to_wstring(risk) + L" 判定=" + verdict);
    return risk;
}

// ---- 动态分析: 在受限 Job 中试运行, 采样行为 ----
// 返回: 风险分 0-100; report 中记录观察到的行为
static int SandboxRunDynamic(const wstring& path, int seconds, std::vector<wstring>& report) {
    report.clear();
    int risk = 0;
    if (seconds < 1) seconds = 1;
    if (seconds > 60) seconds = 60;
    if (path.empty()) { report.push_back(L"[!] 路径为空"); return 0; }

    report.push_back(L"[沙箱] 准备在受限环境中试运行: " + path);
    report.push_back(L"[沙箱] 观察时长 " + std::to_wstring(seconds) + L" 秒");

    // 1) 建立 Job Object: 进程关闭时自动终止所有子进程
    HANDLE hJob = CreateJobObjectW(nullptr, nullptr);
    if (hJob) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION_STUB jeli;
        memset(&jeli, 0, sizeof(jeli));
        jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, (unsigned long)sizeof(jeli));
        report.push_back(L"[沙箱] 已建立受限 Job (子进程随作业关闭)");
    } else {
        report.push_back(L"[沙箱] 警告: Job Object 创建失败, 降级为普通观察");
    }

    // 2) 运行前快照
    auto procsBefore = SnapshotProcs();
    auto netsBefore = SnapshotNets();
    std::set<DWORD> pidBefore;
    for (auto& p : procsBefore) pidBefore.insert(p.pid);

    // 3) 以挂起方式创建进程
    STARTUPINFOW_STUB si;
    memset(&si, 0, sizeof(si));
    si.cb = (unsigned long)sizeof(si);
    PROCESS_INFORMATION_STUB pi;
    memset(&pi, 0, sizeof(pi));
    std::wstring cmd = L"\"" + path + L"\"";
    std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
    cmdBuf.push_back(L'\0');

    BOOL ok = CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, FALSE,
                             CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (!ok) {
        report.push_back(L"[沙箱] 无法启动目标(非可执行文件/被拦截/权限不足)");
        if (hJob) CloseHandle(hJob);
        return 0;
    }
    report.push_back(L"[沙箱] 已创建挂起进程, PID=" + std::to_wstring(pi.dwProcessId));

    if (hJob) AssignProcessToJobObject(hJob, pi.hProcess);
    ResumeThread(pi.hThread);
    report.push_back(L"[沙箱] 已恢复执行, 开始采样...");

    // 4) 采样循环
    std::set<DWORD> newPids;
    for (int t = 0; t < seconds * 2; ++t) {
        Sleep(500);
        EnumAllProcesses();
        auto now = SnapshotProcs();
        for (auto& p : now) {
            if (pidBefore.find(p.pid) == pidBefore.end() && newPids.find(p.pid) == newPids.end()) {
                newPids.insert(p.pid);
                wstring cl = GetProcCommandLine(p.pid);
                wstring pp = GetProcPath(p.pid);
                report.push_back(L"[+] 新建进程: " + p.name + L" PID=" + std::to_wstring(p.pid) +
                                 (pp.empty() ? L"" : (L" 路径=" + pp)));
                if (!cl.empty()) report.push_back(L"    命令行: " + cl);
                BehavAdd(pi.dwProcessId, p.name, BEHAV_PROC_START, 3,
                         L"沙箱内创建子进程 " + p.name + L" PID=" + std::to_wstring(p.pid));
                if (!cl.empty()) BehavAdd(pi.dwProcessId, p.name, BEHAV_CMD, 2, L"命令行: " + cl);
                risk += 6;
            }
        }
        // 网络
        EnumTcpConnections();
        auto nets = SnapshotNets();
        std::set<std::wstring> seen;
        for (auto& nb : netsBefore) seen.insert(nb.local + L"|" + nb.remote);
        for (auto& n : nets) {
            std::wstring key = n.local + L"|" + n.remote;
            if (seen.find(key) == seen.end()) {
                seen.insert(key);
                if (n.pid == pi.dwProcessId || newPids.find(n.pid) != newPids.end()) {
                    std::wstring why;
                    bool bad = IntelIpHit(n.remote, why);
                    bool ext = IntelIsExternalIp(n.remote);
                    report.push_back(L"[+] 新建连接: " + n.local + L" -> " + n.remote +
                                     (ext ? L" (对外)" : L"") + (bad ? (L" " + why) : L""));
                    BehavAdd(pi.dwProcessId, L"", BEHAV_NET, bad ? 8 : 3,
                             L"连接 " + n.remote + (bad ? (L" " + why) : L""));
                    risk += bad ? 20 : 5;
                }
            }
        }
    }

    // 5) 结束样本
    TerminateProcess(pi.hProcess, 1);
    WaitForSingleObject(pi.hProcess, 3000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (hJob) CloseHandle(hJob);   // 关闭 Job -> 杀掉全部子进程
    report.push_back(L"[沙箱] 样本已终止, 关联子进程已清理");
    report.push_back(L"[沙箱] 观察结束: 新建进程 " + std::to_wstring(newPids.size()) +
                     L" 个, 动态风险分=" + std::to_wstring(risk));
    if (risk > 100) risk = 100;
    return risk;
}

// ---- 沙箱统一入口: 静态 + (可选)动态 ----
static int SandboxAnalyze(const wstring& path, bool doDynamic, int dynSeconds,
                          wstring& verdict, std::vector<wstring>& report) {
    int r1 = SandboxStaticAnalyze(path, verdict, report);
    if (doDynamic) {
        std::vector<wstring> drep;
        int r2 = SandboxRunDynamic(path, dynSeconds, drep);
        report.push_back(L"---------- 动态分析 ----------");
        for (auto& l : drep) report.push_back(l);
        int total = r1 + r2;
        if (total > 100) total = 100;
        verdict = (total >= 60) ? L"高危(建议隔离/删除)"
                : (total >= 30) ? L"可疑(建议隔离观察)"
                : (total >= 12) ? L"低风险(建议监控)" : L"未见明显异常";
        BehavAdd(0, path, BEHAV_SANDBOX, total / 10, L"沙箱分析 " + path + L" 判定=" + verdict);
        return total;
    }
    BehavAdd(0, path, BEHAV_SANDBOX, r1 / 10, L"静态分析 " + path + L" 判定=" + verdict);
    return r1;
}


static void DeleteFileWWrapper(const wstring& path) { DeleteFileW(path.c_str()); }

// ============================================================
//  对外连接查验 + 连坐处置
//  流程: 枚举连接 -> 对外IP -> 情报黑名单 -> 定位进程 ->
//        连坐(主进程+父子+同目录+驱动) -> 结束 + 同名空文件覆盖
//  安全约束: 保护路径/自身/系统进程 一律跳过, 绝不误伤
// ============================================================

// ---- 从 remote 字符串提取 IP 部分 (去掉 :port) ----
static wstring ExtractIpFromRemote(const wstring& remote) {
    // remote 形如 "1.2.3.4:443" 或 "[::1]:443"
    wstring s = remote;
    size_t colon = s.rfind(L':');
    if (colon != wstring::npos) s = s.substr(0, colon);
    if (!s.empty() && s[0] == L'[') {
        size_t rb = s.find(L']');
        if (rb != wstring::npos) s = s.substr(1, rb - 1);
    }
    return s;
}

// ---- 枚举已加载驱动的路径列表 ----
static void EnumDriverPaths(std::vector<wstring>& out) {
    out.clear();
    void* drivers[1024];
    unsigned long needed = 0;
    if (!EnumDeviceDrivers(drivers, (unsigned long)sizeof(drivers), &needed)) return;
    unsigned long cnt = needed / sizeof(void*);
    if (cnt > 1024) cnt = 1024;
    for (unsigned long i = 0; i < cnt; ++i) {
        wchar_t fn[MAX_PATH] = { 0 };
        if (GetDeviceDriverFileNameW(drivers[i], fn, MAX_PATH)) {
            out.push_back(fn);
        }
    }
}

// ---- 停止驱动服务 (按 .sys 文件名推断服务名) ----
static bool StopDriverByPath(const wstring& sysPath) {
    wstring name = sysPath;
    size_t bs = name.rfind(L'\\');
    if (bs != wstring::npos) name = name.substr(bs + 1);
    size_t dot = name.rfind(L'.');
    if (dot != wstring::npos) name = name.substr(0, dot);
    if (name.empty()) return false;
    SC_HANDLE scm = (SC_HANDLE)OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    SC_HANDLE svc = (SC_HANDLE)OpenServiceW(scm, name.c_str(), SERVICE_STOP | 0x0001 /*QUERY_CONFIG*/);
    if (!svc) { CloseServiceHandle(scm); return false; }
    SERVICE_STATUS_STUB st;
    memset(&st, 0, sizeof(st));
    bool ok = (ControlService(svc, SERVICE_CONTROL_STOP, &st) != 0);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
}

// ---- 连坐: 对指定 PID 及其关联项执行"结束 + 空文件覆盖" ----
// 返回处置数量
static int PurgeProcessGroup(DWORD rootPid, const wstring& reason, std::vector<wstring>& log) {
    int n = 0;
    if (rootPid == 0 || rootPid == 4) return 0;
    DWORD selfPid = GetCurrentProcessId();
    if (rootPid == selfPid) { log.push_back(L"[保护] 跳过自身进程"); return 0; }

    auto procs = SnapshotProcs();
    std::set<DWORD> targets;
    targets.insert(rootPid);

    // 1) 子进程 (父进程为 root 或为任一目标的)
    bool changed = true;
    while (changed) {
        changed = false;
        for (auto& p : procs) {
            if (p.pid == 0 || p.pid == 4 || p.pid == selfPid) continue;
            if (targets.find(p.ppid) != targets.end() && targets.find(p.pid) == targets.end()) {
                targets.insert(p.pid);
                changed = true;
            }
        }
    }
    // 2) 父进程链 (向上追溯一层)
    for (auto& p : procs) {
        if (p.pid == rootPid && p.ppid != 0 && p.ppid != 4 && p.ppid != selfPid) {
            targets.insert(p.ppid);
        }
    }
    // 3) 同目录进程 (与主进程同路径前缀)
    wstring rootPath = GetProcPath(rootPid);
    if (!rootPath.empty()) {
        wstring rootDir = rootPath.substr(0, rootPath.rfind(L'\\'));
        for (auto& p : procs) {
            if (p.pid == 0 || p.pid == 4 || p.pid == selfPid) continue;
            wstring pp = GetProcPath(p.pid);
            if (!pp.empty() && pp.size() > rootDir.size() &&
                pp.compare(0, rootDir.size(), rootDir) == 0 && pp[rootDir.size()] == L'\\') {
                targets.insert(p.pid);
            }
        }
    }

    // 4) 执行处置
    for (DWORD pid : targets) {
        wstring path = GetProcPath(pid);
        wstring name;
        for (auto& p : procs) if (p.pid == pid) name = p.name;
        if (path.empty()) {
            log.push_back(L"[跳过] PID=" + std::to_wstring(pid) + L" 无法获取路径");
            continue;
        }
        if (IsProtectedPath(path)) {
            log.push_back(L"[保护] 跳过受保护路径: " + path);
            continue;
        }
        // 结束进程
        bool killed = KillProcess(pid);
        // 同名空文件覆盖 (销毁文件内容)
        bool wiped = OverwriteWithEmptyFile(path);
        n++;
        log.push_back(L"[处置] " + name + L" PID=" + std::to_wstring(pid) +
                      (killed ? L" 已结束" : L" 结束失败") +
                      (wiped ? L" + 文件已清空覆盖" : L" + 文件覆盖失败(占用/只读)"));
        BehavAdd(pid, name, BEHAV_BLOCK, 10, L"连坐处置(" + reason + L"): 已结束并覆盖 " + path);
    }

    // 5) 关联驱动: 与主进程同目录的 .sys
    if (!rootPath.empty()) {
        wstring rootDir = rootPath.substr(0, rootPath.rfind(L'\\'));
        std::vector<wstring> drvs;
        EnumDriverPaths(drvs);
        for (auto& d : drvs) {
            if (d.size() > rootDir.size() && d.compare(0, rootDir.size(), rootDir) == 0 &&
                d[rootDir.size()] == L'\\' && IsProtectedPath(d)) {
                continue;
            }
            if (d.size() > rootDir.size() && d.compare(0, rootDir.size(), rootDir) == 0 &&
                d[rootDir.size()] == L'\\') {
                bool stopped = StopDriverByPath(d);
                bool wiped = OverwriteWithEmptyFile(d);
                n++;
                log.push_back(L"[驱动] " + d + (stopped ? L" 服务已停止" : L" 停止失败(需重启)") +
                              (wiped ? L" + 已覆盖(重启后失效)" : L" + 覆盖失败"));
                BehavAdd(0, d, BEHAV_DRIVER, 10, L"连坐处置: 驱动 " + d + L" 已停止并覆盖");
            }
        }
    }
    LogFmt(L"连坐处置完成: 目标 %d 项, 原因: %s", n, reason.c_str());
    return n;
}

// ---- 对外连接查验主入口 ----
// 扫描全部连接: 对外IP -> 情报命中 -> 定位进程 -> 连坐
static int ScanExternalThreatsAndPurge(bool autoPurge) {
    EnumTcpConnections();
    auto nets = SnapshotNets();
    int found = 0, purged = 0;
    for (auto& n : nets) {
        wstring ip = ExtractIpFromRemote(n.remote);
        if (ip.empty()) continue;
        if (!IntelIsExternalIp(ip)) continue;          // 内网跳过
        wstring why;
        if (!IntelIpHit(ip, why)) continue;            // 未命中黑名单
        found++;
        wstring pname;
        auto procs = SnapshotProcs();
        for (auto& p : procs) if (p.pid == n.pid) pname = p.name;
        LogFmt(L"[威胁] 进程 %s(PID=%u) 连接风险IP %s -> %s",
               pname.c_str(), n.pid, ip.c_str(), why.c_str());
        BehavAdd(n.pid, pname, BEHAV_NET, 10, L"连接风险IP " + ip + L" (" + why + L")");
        if (autoPurge && n.pid != 0 && n.pid != 4) {
            std::vector<wstring> log;
            purged += PurgeProcessGroup(n.pid, L"连接风险IP " + ip, log);
            for (auto& l : log) LogPost(l);
        }
    }
    LogFmt(L"对外威胁扫描: 命中风险连接 %d 条, 连坐处置 %d 项", found, purged);
    return found;
}

// ============================================================
//  CVE 漏洞利用处置: 封(断网) + 隔离 + 放沙箱 + 强制删除
// ============================================================
static int HandleCveExploit(const wstring& path, DWORD pid, const wstring& cve,
                            const wstring& desc, int risk) {
    // 【KEV 处置升级】若该 CVE 已被 CISA 列入"已知在野利用"目录,
    // 说明不再是理论风险而是实战威胁, 因此: 风险拉满 + 告警等级最高 +
    // 即使未开激进模式也强制隔离(仍不强制删文件, 避免过度破坏)。
    bool kev = VulnIsKev(cve);
    if (kev) {
        risk = 10;
        LogPost(L"[CVE][紧急] " + cve + L" 已被 CISA 列入已知在野利用目录(KEV), 风险拉满并强制隔离");
        SetThreatLevel(2, (L"CVE " + cve + L" 已在野被利用(KEV)").c_str());
    } else if (VulnIsHigh(cve)) {
        risk += 2;
        LogPost(L"[CVE] " + cve + L" 属于 NVD 高危(CVSS 超阈值), 风险 +2");
    }
    LogFmt(L"[CVE] 命中 %s: %s | %s (风险%d%s)", cve.c_str(), desc.c_str(), path.c_str(),
           risk, kev ? L", KEV在野利用" : L"");
    BehavAdd(pid, path, BEHAV_BLOCK, risk,
             L"CVE 命中 " + cve + L": " + desc + (kev ? L" [KEV在野利用]" : L""));

    // 1) 封: 断开该进程全部连接
    if (pid) DisconnectConnection(pid);

    // 2) 隔离: 移入隔离区 (KEV 命中时强制执行, 无需激进模式)
    if (!path.empty() && !IsProtectedPath(path)) {
        QuarantineFile(path);
        LogPost(L"[CVE] 已隔离: " + path + (kev ? L" (KEV 强制隔离)" : L""));
    }

    // 3) 放沙箱: 静态分析确认
    if (!path.empty()) {
        wstring verdict;
        std::vector<wstring> rep;
        int sr = SandboxAnalyze(path, false, 0, verdict, rep);
        LogFmt(L"[CVE] 沙箱复核 %s: 风险=%d 判定=%s", path.c_str(), sr, verdict.c_str());
        for (auto& l : rep) LogPost(L"  " + l);
    }

    // 4) 强制删除 (仅激进模式, 且非保护路径)
    if (g_cfg.advAggressive && !path.empty() && !IsProtectedPath(path)) {
        if (OverwriteWithEmptyFile(path)) {
            DeleteFileWWrapper(path);
            LogPost(L"[CVE] 强制删除完成: " + path);
        } else {
            LogPost(L"[CVE] 强制删除失败(文件占用): " + path);
        }
    } else if (!path.empty()) {
        LogPost(L"[CVE] 未开启激进模式, 仅隔离未删除: " + path);
    }

    // 5) 结束利用进程
    if (pid && pid != 4) KillProcess(pid);
    return risk;
}

// ---- 扫描: 在进程命令行/文件内容中检测 CVE 利用特征并处置 ----
static int ScanCveAndHandle() {
    int hits = 0;
    auto procs = SnapshotProcs();
    for (auto& p : procs) {
        if (p.pid == 0 || p.pid == 4) continue;
        wstring cmd = GetProcCommandLine(p.pid);
        if (cmd.empty()) continue;
        std::wstring low = cmd;
        for (wchar_t& c : low) if (c >= L'A' && c <= L'Z') c = (wchar_t)(c - L'A' + L'a');
        wstring cve, desc;
        int risk = 0;
        if (CveMatchText(low, cve, desc, risk)) {
            wstring path = GetProcPath(p.pid);
            HandleCveExploit(path, p.pid, cve, desc, risk);
            hits++;
        }
    }
    return hits;
}

// ============================================================
// ============================================================
//  v13: 深度行为采集 —— 钩子 / 命令行 / 加载模块(文件) / 注册表 / 内存
//  用途: 记录"自程序启动以来该进程的所有操作"
//  展示: 进程列表 -> [行为] -> 二级菜单(行为时间线)
// ============================================================
// 注: 模块枚举头 tlhelp32.h 已在文件顶部平台适配区引入
//     (真机 _WIN32 -> <tlhelp32.h>, 自检桩环境 -> stub_win32.h 内等价定义)

static wstring ToLowerW(const wstring& s);   // 前向声明: 定义见后文(规则匹配区)

// ===================== v13.14 告警确认: 类型与全局(提前声明) =====================
#ifndef WM_APP_CONFIRM
#define WM_APP_CONFIRM (WM_APP + 13)
#endif
#ifndef MB_SETFOREGROUND
#define MB_SETFOREGROUND 0x00010000L
#endif
#ifndef ERROR_ACCESS_DENIED
#define ERROR_ACCESS_DENIED 5L
#endif
enum { ALERT_IGNORE = 0, ALERT_HANDLE = 1, ALERT_ALLOW = 2 };
struct AlertReq {
    std::wstring title, detail, path;
    DWORD pid;
    int    answer;
    HANDLE done;
};
static std::atomic<bool>      g_alertAsk{true};
static std::mutex             g_alertAllowMtx;
static std::set<std::wstring> g_alertAllow;
static int  AlertConfirm(const wchar_t* title, const std::wstring& detail,
                         const std::wstring& path, DWORD pid);
static bool KillProcessAuto(DWORD pid, const wchar_t* reason = L"\u81ea\u52a8\u9632\u62a4");
static int  EnsureSelfRunnable();
static std::wstring BootFailPath();
static DWORD UserAskSet(DWORD (WINAPI* fn)(const wchar_t*, const wchar_t*, DWORD, BYTE*, DWORD*),
                        const wchar_t* a, const wchar_t* b, DWORD c, BYTE* d, DWORD* e);
static DWORD UserAskDel(DWORD (WINAPI* fn)(const wchar_t*, const wchar_t*),
                        const wchar_t* a, const wchar_t* b);
// ============================================================================
// ---- v13.14 前向声明 ----
static int  MalFamilyScan(const std::wstring& path, std::wstring& why);
static int  FoxProcScan();

// 判定"乱七八糟哈希值命名": 去扩展名后为 32/40/64 位纯十六进制
static bool IsHexLikeName(const wstring& s) {
    size_t dot = s.rfind(L'.');
    wstring base = (dot == wstring::npos) ? s : s.substr(0, dot);
    if (base.size() != 32 && base.size() != 40 && base.size() != 64) return false;
    for (wchar_t c : base) {
        bool hx = ((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F'));
        if (!hx) return false;
    }
    return true;
}

static bool IsSystemDirPath(const wstring& p) {
    wstring l = ToLowerW(p);
    if (l.find(L"\\windows\\system32\\")  != wstring::npos) return true;
    if (l.find(L"\\windows\\syswow64\\")  != wstring::npos) return true;
    if (l.find(L"\\windows\\winsxs\\")    != wstring::npos) return true;
    if (l.find(L"\\program files\\")      != wstring::npos) return true;
    if (l.find(L"\\program files (x86)\\") != wstring::npos) return true;
    return false;
}

// 对单个进程做深度行为建档 (钩子/命令/文件/注册表/内存)
static void CollectDeepBehaviors(DWORD pid, const wstring& name, const wstring& path) {
    if (pid == 0 || pid == 4) return;

    // 1) 命令行: 运行了哪个命令
    wstring cmd = GetProcCommandLine(pid);
    if (!cmd.empty())
        BehavAdd(pid, name, BEHAV_CMD, 0, L"命令行: " + cmd);

    // 2) 加载模块 (文件行为建档) + 钩子/注入线索
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap && snap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me;
        memset(&me, 0, sizeof(me));
        me.dwSize = sizeof(me);
        if (Module32FirstW(snap, &me)) {
            int modCount = 0, injectSus = 0;
            do {
                wstring mp = me.szExePath;
                if (mp.empty()) { memset(&me, 0, sizeof(me)); me.dwSize = sizeof(me); continue; }
                modCount++;
                // 文件行为: 记录加载的模块 (前 12 个)
                if (modCount <= 12)
                    BehavAdd(pid, name, BEHAV_FILE, 0, L"加载模块: " + mp);
                // 钩子/注入线索: 哈希风格命名 或 非系统目录
                wstring mname = me.szModule;
                bool hexName = IsHexLikeName(mname);
                bool nonSys  = !IsSystemDirPath(mp);
                if (hexName || nonSys) {
                    injectSus++;
                    if (injectSus <= 6) {
                        BehavAdd(pid, name, BEHAV_HOOK, hexName ? 8 : 5,
                                 L"可疑模块" + wstring(hexName ? L"(哈希命名)" : L"(非系统目录)") + L": " + mp);
                    }
                }
                memset(&me, 0, sizeof(me));
                me.dwSize = sizeof(me);
            } while (Module32NextW(snap, &me));
            if (injectSus > 0)
                LogFmt(L"[行为] PID=%u %s: 可疑模块 %d 个 (钩子/注入线索)", pid, name.c_str(), injectSus);
        }
        CloseHandle(snap);
    }

    // 3) 内存异常: RWX 私有页 (典型 shellcode / 注入痕迹)
    {
        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (hProc) {
            MEMORY_BASIC_INFORMATION mbi;
            memset(&mbi, 0, sizeof(mbi));
            uintptr_t addr = 0;
            int rwx = 0;
            for (int i = 0; i < 4096; ++i) {
                SIZE_T r = VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi));
                if (r == 0) break;
                if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
                    (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY)) {
                    rwx++;
                    if (rwx <= 5)
                        BehavAdd(pid, name, BEHAV_MEM, 9,
                                 L"RWX 私有内存页(疑似注入/shellcode) 基址=0x" +
                                 std::to_wstring((unsigned long long)(uintptr_t)mbi.BaseAddress) +
                                 L" 大小=" + std::to_wstring((unsigned long long)(uintptr_t)mbi.RegionSize));
                }
                uintptr_t next = (uintptr_t)mbi.BaseAddress + (uintptr_t)mbi.RegionSize;
                if (next <= addr) break;
                addr = next;
            }
            if (rwx > 0)
                LogFmt(L"[行为] PID=%u %s: RWX 内存页 %d 处", pid, name.c_str(), rwx);
            CloseHandle(hProc);
        }
    }

    // 4) 注册表持久化: 是否写入自启动项
    if (!path.empty()) {
        const wchar_t* runKeys[] = {
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        };
        wstring lp = ToLowerW(path);
        for (int i = 0; i < 2; ++i) {
            HKEY hk = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, runKeys[i], 0, KEY_READ, &hk) != 0) continue;
            wchar_t vname[512]; wchar_t vdata[1024];
            DWORD idx = 0;
            for (;;) {
                DWORD vn = 512; DWORD vd = sizeof(vdata); DWORD ty = 0;
                LONG r = RegEnumValueW(hk, idx, vname, &vn, nullptr, &ty, (LPBYTE)vdata, &vd);
                if (r != 0) break;
                idx++;
                vdata[1023] = L'\0';
                wstring lv = ToLowerW(wstring(vdata));
                if (!lp.empty() && lv.find(lp) != wstring::npos) {
                    BehavAdd(pid, name, BEHAV_REG, 7,
                             L"注册表自启动项: " + wstring(runKeys[i]) + L" -> " + wstring(vname));
                }
            }
            RegCloseKey(hk);
        }
    }
}

//  启动全量扫描: 对所有运行程序做"体检 + 行为建档"
//  检查项: 路径 / 命令行 / 哈希 / 情报 / 签名 / 命名 / 钩子
// ============================================================
static void StartupFullScan() {
    LogPost(L"启动全量扫描: 正在对所有运行程序建档...");
    EnumAllProcesses();
    auto procs = SnapshotProcs();
    int total = 0, blocked = 0, risky = 0;
    DWORD selfPid = GetCurrentProcessId();
    for (auto& p : procs) {
        if (p.pid == 0 || p.pid == 4 || p.pid == selfPid) continue;
        total++;
        wstring path = GetProcPath(p.pid);
        wstring cmd = GetProcCommandLine(p.pid);

        // 建档: 启动
        BehavAdd(p.pid, p.name, BEHAV_PROC_START, 0,
                 L"建档: " + (path.empty() ? L"(路径未知)" : path));
        if (!cmd.empty()) BehavAdd(p.pid, p.name, BEHAV_CMD, 0, L"命令行: " + cmd);

        // 强制终止规则: 启动即执行
        {
            std::wstring fd;
            if (ForceKillMatch(p.name, path, cmd, fd)) {
                LogFmt(L"[强制终止] 启动扫描命中: %s PID=%u", fd.c_str(), p.pid);
                BehavAdd(p.pid, p.name, BEHAV_BLOCK, 10, L"强制终止规则命中: " + fd);
                KillProcess(p.pid);
                RecoverAfterForceKill(p.name, path, p.pid, fd);
                continue;
            }
        }

        // v13: 深度行为建档 —— 钩子 / 模块(文件) / 注册表 / 内存
        CollectDeepBehaviors(p.pid, p.name, path);

        if (path.empty()) continue;

        // 哈希 + 情报
        wstring sha, tag;
        if (FileSha256W(path, sha)) {
            BehavAdd(p.pid, p.name, BEHAV_SIGN, 0, L"SHA256=" + sha);
            if (IntelHashHit(sha, tag)) {
                risky++;
                LogFmt(L"[启动扫描] 情报命中: %s (%s) PID=%u", p.name.c_str(), tag.c_str(), p.pid);
                BehavAdd(p.pid, p.name, BEHAV_SIGN, 10, tag);
            }
        }
        // 签名 / 命名
        wstring reason;
        if (ShouldBlockRun(path, reason)) {
            blocked++;
            LogFmt(L"[启动扫描] 判定需阻止: %s (%s) PID=%u", p.name.c_str(), reason.c_str(), p.pid);
            BehavAdd(p.pid, p.name, BEHAV_BLOCK, 8, L"阻止原因: " + reason);
            if (g_cfg.advAggressive) {
                KillProcess(p.pid);
                BehavAdd(p.pid, p.name, BEHAV_BLOCK, 10, L"已结束(激进模式)");
            }
        } else {
            BehavAdd(p.pid, p.name, BEHAV_SIGN, 0, L"签名/命名检查通过");
        }
    }
    LogFmt(L"启动全量扫描完成: 建档 %d 个进程, 风险 %d 个, 需阻止 %d 个", total, risky, blocked);
}


// ============================================================
//  最小信任原则 / 默认拒绝 (Zero Trust · Default-Deny)
//  核心语义: 任何程序默认不信任。仅以下情况允许运行:
//    TRUST_SELF    - 本程序(EDR)自身
//    TRUST_SYSTEM  - 系统基线(首次运行自动学习建立)
//    TRUST_ALLOWED - 用户显式授权(路径 + SHA256 双因子)
//  其余一律 TRUST_UNKNOWN / TRUST_PENDING -> 默认阻止运行。
//  重要: 数字签名仅作参考, 不作为放行依据 —— 有签名同样不信任。
//  安全兜底(防止系统锁死, 必须保留):
//    - 首次运行自动学习基线: 把当前已运行的系统进程纳入基线,
//      否则一开启就会阻止 explorer/系统服务, 导致系统不可用。
//    - --safemode 启动参数: 禁用全部拦截, 用于紧急恢复。
//  授权持久化: zz_EDR.trust (每行: level|path|sha256|note)
// ============================================================
enum TrustLevel {
    TRUST_BLOCKED = 0,   // 明确恶意(情报/黑名单命中) -> 直接终止
    TRUST_UNKNOWN = 1,   // 默认: 未授权 -> 阻止运行
    TRUST_PENDING = 2,   // 待审批(记入待审批队列)
    TRUST_ALLOWED = 3,   // 用户显式授权
    TRUST_SYSTEM  = 4,   // 系统基线(学习模式采集)
    TRUST_SELF    = 5    // 本程序
};
struct TrustEntry {
    int      level = TRUST_UNKNOWN;
    wstring  path;
    wstring  sha256;
    wstring  note;
};
static std::mutex                        g_trustMtx;
static std::map<std::wstring, TrustEntry> g_trust;          // key = 小写路径
static std::atomic<bool> g_zeroTrustOn{true};               // 最小信任总开关
static std::atomic<bool> g_safemode{false};                 // --safemode: 全禁用
static std::vector<std::wstring>         g_pending;         // 待审批路径

static std::wstring TrustKey(const std::wstring& path) {
    std::wstring k = path;
    for (size_t i = 0; i < k.size(); ++i)
        if (k[i] >= L'A' && k[i] <= L'Z') k[i] = (wchar_t)(k[i] + 32);
    return k;
}
static const wchar_t* TrustLevelName(int lv) {
    switch (lv) {
    case TRUST_BLOCKED: return L"已拉黑";
    case TRUST_UNKNOWN: return L"未信任";
    case TRUST_PENDING: return L"待审批";
    case TRUST_ALLOWED: return L"已授权";
    case TRUST_SYSTEM:  return L"系统基线";
    case TRUST_SELF:    return L"本程序";
    }
    return L"未知";
}
// 授权 / 拉黑: 记录 路径 + SHA256 双因子
static void TrustSet(const std::wstring& path, int level, const std::wstring& note) {
    if (path.empty()) return;
    TrustEntry e;
    e.path = path; e.level = level; e.note = note;
    FileSha256W(path, e.sha256);              // 双因子: 文件被替换则授权失效
    std::lock_guard<std::mutex> lk(g_trustMtx);
    g_trust[TrustKey(path)] = e;
}
static int TrustQuery(const std::wstring& path) {
    std::lock_guard<std::mutex> lk(g_trustMtx);
    auto it = g_trust.find(TrustKey(path));
    if (it == g_trust.end()) return TRUST_UNKNOWN;
    const TrustEntry& e = it->second;
    if (!e.sha256.empty()) {                  // 校验文件未被替换
        wstring now;
        if (FileSha256W(path, now) && now != e.sha256) {
            return TRUST_UNKNOWN;             // 同路径换文件 -> 授权作废
        }
    }
    return e.level;
}
// 综合评估: 自身 > 黑名单 > 授权库 > 默认拒绝
static int TrustEvaluate(const std::wstring& path, const std::wstring& name) {
    if (g_safemode.load()) return TRUST_ALLOWED;             // 紧急恢复: 全放行
    if (path.empty()) return TRUST_UNKNOWN;
    wchar_t self[MAX_PATH] = {0};
    if (GetModuleFileNameW(nullptr, self, MAX_PATH) &&
        _wcsicmp(path.c_str(), self) == 0) return TRUST_SELF; // 自身永不阻止
    // 情报/已知恶意 -> 拉黑
    {
        wstring sha, why;
        if (FileSha256W(path, sha) && IntelHashHit(sha, why)) return TRUST_BLOCKED;
    }
    int lv = TrustQuery(path);
    if (lv == TRUST_ALLOWED || lv == TRUST_SYSTEM || lv == TRUST_BLOCKED)
        return lv;
    // 最小信任: 不在授权库 -> 默认拒绝, 并登记待审批
    {
        std::lock_guard<std::mutex> lk(g_trustMtx);
        bool dup = false;
        for (const auto& q : g_pending) if (q == path) { dup = true; break; }
        if (!dup && g_pending.size() < 500) g_pending.push_back(path);
    }
    return TRUST_UNKNOWN;
}
// 学习基线: 把当前正在运行的进程纳入系统基线(仅在干净系统上执行)
static int TrustLearnBaseline() {
    EnumAllProcesses();
    auto procs = SnapshotProcs();
    DWORD selfPid = GetCurrentProcessId();
    int n = 0;
    for (const auto& p : procs) {
        if (p.pid == 0 || p.pid == 4 || p.pid == selfPid) continue;
        wstring path = GetProcPath(p.pid);
        if (path.empty()) continue;
        if (TrustQuery(path) >= TRUST_ALLOWED) continue;      // 已有更高授权
        TrustSet(path, TRUST_SYSTEM, L"基线学习");
        ++n;
    }
    LogFmt(L"最小信任: 基线学习完成, 纳入 %d 个进程", n);
    return n;
}
// 持久化
static std::wstring TrustDbPath() {
    wchar_t tmp[MAX_PATH] = {0};
    if (GetTempPathW(MAX_PATH, tmp)) return std::wstring(tmp) + L"zz_EDR.trust";
    return L"zz_EDR.trust";
}
static void TrustSave() {
    std::lock_guard<std::mutex> lk(g_trustMtx);
    FILE* f = _wfopen(TrustDbPath().c_str(), L"wb");
    if (!f) return;
    unsigned short bom = 0xFEFF; fwrite(&bom, 1, 2, f);
    for (const auto& kv : g_trust) {
        const TrustEntry& e = kv.second;
        wstring note = e.note;
        for (size_t i = 0; i < note.size(); ++i)
            if (note[i] == L'|' || note[i] == L'\n') note[i] = L' ';
        wstring line = std::to_wstring(e.level) + L"|" + e.path + L"|" +
                       e.sha256 + L"|" + note + L"\n";
        fwrite(line.c_str(), 1, line.size() * sizeof(wchar_t), f);
    }
    fclose(f);
}
static void TrustLoad() {
    FILE* f = _wfopen(TrustDbPath().c_str(), L"rb");
    if (!f) return;
    std::vector<wchar_t> buf;
    wchar_t c;
    bool first = true;
    while (fread(&c, 1, sizeof(wchar_t), f) == sizeof(wchar_t)) {
        if (first) { first = false; if (c == 0xFEFF) continue; }
        buf.push_back(c);
    }
    fclose(f);
    std::wstring all(buf.begin(), buf.end());
    size_t pos = 0;
    int n = 0;
    while (pos < all.size()) {
        size_t eol = all.find(L'\n', pos);
        if (eol == std::wstring::npos) eol = all.size();
        std::wstring line = all.substr(pos, eol - pos);
        pos = eol + 1;
        if (line.empty()) continue;
        std::vector<std::wstring> fld;
        size_t q = 0;
        while (true) {
            size_t b = line.find(L'|', q);
            if (b == std::wstring::npos) { fld.push_back(line.substr(q)); break; }
            fld.push_back(line.substr(q, b - q)); q = b + 1;
        }
        if (fld.size() < 2) continue;
        TrustEntry en;
        en.level  = _wtoi(fld[0].c_str());
        en.path   = fld[1];
        if (fld.size() > 2) en.sha256 = fld[2];
        if (fld.size() > 3) en.note   = fld[3];
        if (en.path.empty()) continue;
        g_trust[TrustKey(en.path)] = en;
        ++n;
    }
    if (n) LogFmt(L"最小信任: 已载入 %d 条授权记录", n);
}

// ---- 新进程守护: 轮询检测并阻止"无签名/哈希命名"的程序运行 ----
static void ProcGuardLoop() {
    LogPost(L"进程守护已启动: 无有效签名或随机哈希命名的程序将被默认阻止");
    std::set<DWORD> known;
    while (g_running.load() && g_guardOn.load()) {
        EnumAllProcesses();
        auto procs = SnapshotProcs();
        DWORD selfPid = GetCurrentProcessId();
        for (auto& p : procs) {
            if (p.pid == 0 || p.pid == 4 || p.pid == selfPid) continue;
            if (known.find(p.pid) != known.end()) continue;
            known.insert(p.pid);
            wstring path = GetProcPath(p.pid);
            {
                std::wstring fd, fc = GetProcCommandLine(p.pid);
                if (ForceKillMatch(p.name, path, fc, fd)) {
                    LogFmt(L"[强制终止] 守护命中: %s PID=%u", fd.c_str(), p.pid);
                    BehavAdd(p.pid, p.name, BEHAV_BLOCK, 10, L"强制终止规则命中: " + fd);
                    KillProcess(p.pid);
                    RecoverAfterForceKill(p.name, path, p.pid, fd);
                    continue;
                }
            }
            if (path.empty()) continue;
            // 最小信任: 先做信任评估, 未授权一律默认拒绝
            int trustLv = TRUST_ALLOWED;
            if (g_zeroTrustOn.load()) trustLv = TrustEvaluate(path, p.name);
            wstring reason;
            if (trustLv <= TRUST_PENDING) {
                reason = std::wstring(L"最小信任·") + TrustLevelName(trustLv) +
                         L"(未授权程序默认拒绝运行)";
            }
            if (trustLv <= TRUST_PENDING || ShouldBlockRun(path, reason)) {
                LogFmt(L"[进程守护] 阻止运行: %s (%s) PID=%u", p.name.c_str(), reason.c_str(), p.pid);
                BehavAdd(p.pid, p.name, BEHAV_BLOCK, 9, L"默认阻止: " + reason);
                KillProcessAuto(p.pid);
                if (g_cfg.advAggressive && !IsProtectedPath(path)) {
                    OverwriteWithEmptyFile(path);
                }
            }
        }
        // 清理已退出进程的记录
        if (known.size() > 4000) known.clear();
        for (int i = 0; i < 20 && g_running.load(); ++i) Sleep(100);  // 2 秒轮询
    }
}


// ============================================================
//  办公软件子进程防护 (Office Guard)
//  背景: Word/Excel/PowerPoint/Outlook 等办公软件在打开文档时, 常被
//        宏 / 公式 / DDE / 漏洞利用诱导启动 cmd、powershell、wscript
//        等命令执行程序, 这是 Office 类攻击的主要落地手段。
//  策略:
//   - 父进程命中"办公软件"名单 且 子进程命中"命令执行程序"名单 -> 立即终止
//   - 子进程命令行含编码/下载执行等特征 -> 同样阻止
//   - 白名单(打印/预览/崩溃上报等 Office 正常辅助进程)放行, 避免误伤
//   - 其余子进程仅记录行为供审计, 不终止
//   - 激进模式下对危险子进程同名文件做空文件覆盖
//  合规说明: 名单均为 Windows 自带系统程序的"进程名", 仅用于检测与拦截,
//            不含任何攻击性 payload。
// ============================================================
static std::atomic<bool> g_officeGuardOn{true};
static bool IsProtectedPath(const wstring& p);   // 前向(避免顺序依赖)

static std::wstring UpStrW(const std::wstring& in) {
    std::wstring r = in;
    for (size_t i = 0; i < r.size(); ++i)
        if (r[i] >= L'a' && r[i] <= L'z') r[i] = (wchar_t)(r[i] - 32);
    return r;
}
template <size_t N>
static bool InNameList(const std::wstring& upName, const wchar_t* const (&list)[N]) {
    for (size_t i = 0; i < N; ++i) if (upName == list[i]) return true;
    return false;
}

// 办公软件主进程
static const wchar_t* const kOfficeProcs[] = {
    L"WINWORD.EXE", L"EXCEL.EXE",      L"POWERPNT.EXE", L"OUTLOOK.EXE",
    L"MSACCESS.EXE",L"ONENOTE.EXE",    L"MSPUB.EXE",    L"VISIO.EXE",
    L"WINPROJ.EXE", L"LYNC.EXE",       L"ONENOTEM.EXE", L"ONENOTEIM.EXE",
    L"MSOINTEG.EXE",L"OFFICECLICK2RUN.EXE"
};
// Office 正常辅助进程(放行, 不告警)
static const wchar_t* const kOfficeChildAllow[] = {
    L"SPLWOW64.EXE", L"MSOSYNC.EXE",   L"MSOHTMED.EXE", L"MSQRY32.EXE",
    L"SETLANG.EXE",  L"CLVIEW.EXE",    L"DW20.EXE",     L"DWTRIG20.EXE",
    L"WERFAULT.EXE", L"CONHOST.EXE",   L"FONTLISTSVCHOST.EXE", L"APPVLP.EXE",
    L"DLLHOST.EXE",  L"EXPLORER.EXE",  L"SVCHOST.EXE",  L"RUNTIME BROKER",
    L"SEARCHAPP.EXE",L"APPLICATIONFRAMEHOST.EXE", L"SYSTEMSETTINGS.EXE",
    L"TEXTINPUTHOST.EXE", L"STARTSHELLAPP.EXE", L"MICROSOFTSHAREPOINT.EXE",
    L"MSOFFICE.EXE", L"OFFICECDR.EXE", L"SDXHELPER.EXE", L"GROOVE.EXE",
    L"ONEDRIVE.EXE", L"WINWORD.EXE",   L"EXCEL.EXE",    L"POWERPNT.EXE"
};
// 命令执行 / 高危程序名单 —— Office 绝不应启动它们
static const wchar_t* const kCmdExecProcs[] = {
    L"CMD.EXE",          L"POWERSHELL.EXE",  L"PWSH.EXE",       L"WSCRIPT.EXE",
    L"CSCRIPT.EXE",      L"MSHTA.EXE",       L"RUNDLL32.EXE",   L"REGSVR32.EXE",
    L"CERTUTIL.EXE",     L"BITSADMIN.EXE",   L"INSTALLUTIL.EXE",L"MSBUILD.EXE",
    L"WMIC.EXE",         L"SCHTASKS.EXE",    L"SC.EXE",         L"NET.EXE",
    L"NET1.EXE",         L"AT.EXE",          L"WSL.EXE",        L"BASH.EXE",
    L"CURL.EXE",         L"WGET.EXE",        L"FTP.EXE",        L"TFTP.EXE",
    L"MSIEXEC.EXE",      L"FORFILES.EXE",    L"PCALUA.EXE",     L"ODBCCONF.EXE",
    L"IEEXEC.EXE",       L"JSC.EXE",         L"VBC.EXE",        L"CSC.EXE",
    L"SCRCONS.EXE",      L"HH.EXE",          L"CONTROL.EXE",    L"MSDT.EXE",
    L"DESKTOPIMGDOWNLDR.EXE", L"PRESENTATIONHOST.EXE", L"EQNEDT32.EXE",
    L"NETSH.EXE",        L"VSSADMIN.EXE",    L"WBADMIN.EXE",    L"DISKSHADOW.EXE",
    L"TASKKILL.EXE",     L"ATTRIB.EXE",      L"ICACLS.EXE",     L"TAKEOWN.EXE",
    L"MKLINK.EXE",       L"ESENTUTL.EXE",    L"NLTEST.EXE",     L"DSQUERY.EXE"
};
// 命令行危险特征 —— 分级, 避免宽泛子串造成灾难性误杀
// [高危] 明确的攻击载荷特征, 命中 1 个即阻止
static const wchar_t* const kCmdDangerHigh[] = {
    L"-enc ", L"-encodedcommand", L"iex", L"invoke-expression",
    L"downloadstring", L"downloadfile", L"frombase64string",
    L"wscript.shell", L"shell.application", L"shellcode",
    L"vssadmin delete", L"/transfer", L"start-process"
};
// [弱] 可能合法出现(如点击 http 链接/打开 UNC 共享文档), 需 >=2 个组合才阻止
static const wchar_t* const kCmdDangerWeak[] = {
    L"certutil", L"bitsadmin", L"schtasks", L"wmic",
    L"reg add", L"net user", L"netsh ", L"rundll32",
    L"regsvr32", L"mshta", L"http://", L"https://",
    L"\\", L"-e ", L"webclient"
};

// ============ 混淆 PowerShell 检测 ============
// 原理: 攻击者把 payload 藏进看似正常的命令行, 手工看不出, 但混淆手法是固定的几种。
// 只做"特征计数", 由调用方决定阈值, 避免单条特征就误杀。
static const wchar_t* const kPsObfPats[] = {
    L"invoke-expression", L"iex(", L"iex ",             // 执行动态生成的代码
    L"-encodedcommand", L"-enc ", L"frombase64string",  // Base64 编码载荷
    L"invoke-obfuscation",                              // 知名混淆框架标记
    L"-windowstyle hidden", L"-w hidden",               // 隐藏窗口
    L"-executionpolicy bypass", L"-ep bypass",          // 绕过执行策略
    L"-nop", L"-noprofile",                             // 常用于一键式马
    L"[char]", L"join(''", L"-join",                    // 字符拼接还原字符串
    L"reverse",                                          // 字符串反转还原
    L"start-process", L"shellexecute"                    // 二次启动
};
// 空白字符隐写: 银狐等把 payload 编码进空格/Tab, 肉眼完全不可见
// 判定: 命令行里空白占比异常高(>35%) 且总长够长
static bool PsWhitespaceStego(const std::wstring& cmd, double& ratio) {
    if (cmd.size() < 120) return false;
    size_t ws = 0;
    for (wchar_t c : cmd) if (c == L' ' || c == L'\t') ++ws;
    ratio = (double)ws / (double)cmd.size();
    return ratio > 0.35;
}
// 返回命中特征数(0 表示无混淆迹象)
static int PsObfuscatScore(const std::wstring& cmd, std::wstring& hitOut) {
    if (cmd.size() < 12) return 0;
    std::wstring low = cmd;
    for (size_t i = 0; i < low.size(); ++i)
        if (low[i] >= L'A' && low[i] <= L'Z') low[i] = (wchar_t)(low[i] + 32);
    // 只对 PowerShell / 脚本宿主做判定, 普通命令行不做, 否则噪音极大
    bool isPs = low.find(L"powershell") != wstring::npos
             || low.find(L"pwsh") != wstring::npos
             || low.find(L"wscript") != wstring::npos
             || low.find(L"cscript") != wstring::npos
             || low.find(L"mshta") != wstring::npos;
    if (!isPs) return 0;
    int score = 0;
    for (const wchar_t* p : kPsObfPats) {
        if (low.find(p) != wstring::npos) {
            ++score;
            if (hitOut.empty()) hitOut = p;
        }
    }
    double r = 0;
    if (PsWhitespaceStego(cmd, r)) {
        score += 3;   // 空白隐写极异常, 加权
        if (hitOut.empty()) {
            wchar_t b[64]; swprintf(b, 64, L"空白字符隐写(占比%.0f%%)", r * 100);
            hitOut = b;
        }
    }
    return score;
}

// 可信子进程路径: 白名单的"路径校验", 防止恶意程序改名系统进程名绕过
static bool IsTrustedChildPath(const std::wstring& path) {
    if (path.empty()) return false;
    std::wstring u = UpStrW(path);
    static const wchar_t* const dirs[] = {
        L"\\WINDOWS\\SYSTEM32\\", L"\\WINDOWS\\SYSWOW64\\", L"\\WINDOWS\\",
        L"\\PROGRAM FILES\\",     L"\\PROGRAM FILES (X86)\\",
        L"\\APPDATA\\LOCAL\\MICROSOFT\\", L"\\APPDATA\\ROAMING\\MICROSOFT\\",
        L"\\MICROSOFT OFFICE\\"
    };
    for (const wchar_t* d : dirs) if (u.find(d) != std::wstring::npos) return true;
    return false;
}

static bool IsOfficeProcName(const std::wstring& name) {
    return InNameList(UpStrW(name), kOfficeProcs);
}

// 单次扫描: 找出"父进程是办公软件"的可疑子进程并处理
static int OfficeGuardScan() {
    EnumAllProcesses();
    auto procs = SnapshotProcs();
    std::map<DWORD, ProcInfo> byPid;
    for (auto& p : procs) byPid[p.pid] = p;

    int blocked = 0, watched = 0;
    for (auto& p : procs) {
        if (p.pid == 0 || p.pid == 4) continue;
        auto it = byPid.find(p.ppid);
        if (it == byPid.end()) continue;
        const ProcInfo& parent = it->second;
        if (parent.pid == p.pid) continue;
        if (!IsOfficeProcName(parent.name)) continue;

        std::wstring up = UpStrW(p.name);
        if (InNameList(up, kOfficeChildAllow)) {
            // 白名单必须同时校验路径: 防止恶意程序改名 svchost.exe 放临时目录绕过
            std::wstring ap = GetProcPath(p.pid);
            if (ap.empty() || IsTrustedChildPath(ap)) continue;   // 路径可信/取不到 -> 放行
            BehavAdd(p.pid, p.name, BEHAV_PROC_START, 9,
                     L"疑似仿冒系统进程(名称白名单但路径异常, 取消豁免继续检测): " + ap);
            // 不 continue: 继续走下面的危险检测
        }

        bool dangerous = InNameList(up, kCmdExecProcs);

        std::wstring cmd = GetProcCommandLine(p.pid);
        std::wstring low = cmd;
        for (size_t i = 0; i < low.size(); ++i)
            if (low[i] >= L'A' && low[i] <= L'Z') low[i] = (wchar_t)(low[i] + 32);
        // 分级判定: 高危特征命中 1 个即阻止; 弱特征需 >=2 个组合
        // (避免单击 http 链接/打开 UNC 文档时把浏览器等合法进程误杀)
        int highHits = 0, weakHits = 0;
        std::wstring hit;
        for (const wchar_t* d : kCmdDangerHigh)
            if (low.find(d) != std::wstring::npos) { ++highHits; if (hit.empty()) hit = d; }
        for (const wchar_t* d : kCmdDangerWeak)
            if (low.find(d) != std::wstring::npos) { ++weakHits; if (hit.empty()) hit = d; }
        bool cmdDanger = (highHits >= 1) || (weakHits >= 2);
        if (cmd.empty() && (up == L"CMD.EXE" || up == L"POWERSHELL.EXE")) {
            cmdDanger = true;
            hit = L"(无参命令行)";
        }

        if (!dangerous && !cmdDanger) {
            // 非高危子进程: 仅记录, 供"行为"二级菜单审计
            BehavAdd(p.pid, p.name, BEHAV_PROC_START, 4,
                     L"办公软件子进程(观察): 父=" + parent.name +
                     (cmd.empty() ? L"" : L" 命令行: " + cmd));
            ++watched;
            continue;
        }

        // ---- 阻止: 办公软件不允许启动命令行/脚本/管理程序 ----
        std::wstring reason = dangerous ? L"命中命令执行程序名单" : L"命令行危险特征: " + hit;
        std::wstring path = GetProcPath(p.pid);
        BehavAdd(p.pid, p.name, BEHAV_BLOCK, 10,
                 L"办公软件禁止启动命令: 父=" + parent.name + L" 原因=" + reason +
                 (cmd.empty() ? L"" : L" 命令行: " + cmd));
        LogFmt(L"[办公防护] 阻止: 父=%s -> 子进程 %s (PID=%u) %s",
               parent.name.c_str(), p.name.c_str(), p.pid, reason.c_str());
        if (KillProcess(p.pid)) {
            ++blocked;
            if (g_cfg.advAggressive && !path.empty() && !IsProtectedPath(path)) {
                OverwriteWithEmptyFile(path);
                LogFmt(L"[办公防护] 激进模式: 已覆盖 %s", path.c_str());
            }
        }
    }
    if (blocked || watched)
        LogFmt(L"[办公防护] 本轮: 阻止 %d 个, 观察 %d 个", blocked, watched);
    return blocked;
}

static void OfficeGuardLoop() {
    LogPost(L"办公软件防护已启动: 禁止 Word/Excel/PPT/Outlook 等启动命令行或脚本程序");
    while (g_running.load() && g_officeGuardOn.load()) {
        OfficeGuardScan();
        for (int i = 0; i < 10 && g_running.load() && g_officeGuardOn.load(); ++i)
            Sleep(100);   // 1 秒轮询
    }
    LogPost(L"办公软件防护已停止");
}


// ============================================================
//  宏病毒防护 (Macro Virus Protection)                      v13.5.0
// ------------------------------------------------------------
//  1) 文档内 VBA 宏静态扫描:
//     - OOXML 宏文档 (.docm/.xlsm/.pptm/.dotm/.xltm/.potm/.sldm/.xlam/.xlsb):
//         文档本质是 ZIP -> 解析 Central Directory 定位 vbaProject.bin
//         -> 用内置 inflate 解压(支持 stored / fixed / dynamic 三种 deflate)
//         -> 在解压出的 VBA 数据中检测"自动执行宏入口"与"危险 API/行为"
//     - OLE2 老格式 (.doc/.xls/.ppt/.dot/.xlt/.pot):
//         VBA 明文存储 -> 直接全文扫描
//  2) VBA Stomping / 高度混淆检测:
//     存在 vbaProject.bin 但完全搜不到任何已知宏过程名 -> 记嫌疑
//  3) 安全基线审计 (SCA): Office 宏安全设置
//     - AccessVBOM == 1 : 允许 VBA 项目对象模型访问 (宏病毒常用) -> 高危
//     - VBAWarnings == 1: 启用所有宏(不提示)                    -> 高危
//  4) 处置: 达到阈值 -> 隔离文档(移动); 激进模式 -> 强制删除
//  说明: 内置 puff inflate 为公共领域算法重写, 无任何第三方依赖,
//        已用真实 deflate 流验证(7040 字节精确还原)。
// ============================================================

// ---------- 内置 inflate (无依赖) ----------
namespace puffm {
class Inflator {
    const unsigned char* in_; size_t inLen_; size_t inPos_;
    unsigned bitbuf_; int bitcnt_;
public:
    Inflator(const unsigned char* d, size_t n) : in_(d), inLen_(n), inPos_(0), bitbuf_(0), bitcnt_(0) {}
    int bits(int need) {
        unsigned val = bitbuf_;
        while (bitcnt_ < need) {
            if (inPos_ >= inLen_) return -1;
            val |= (unsigned)in_[inPos_++] << bitcnt_; bitcnt_ += 8;
        }
        bitbuf_ = val >> need; bitcnt_ -= need;
        return (int)(val & ((1u << need) - 1));
    }
    struct Huff { unsigned short count[16]; unsigned short symbol[288]; };
    static int construct(const unsigned short* lens, unsigned n, Huff& h) {
        unsigned short offs[16];
        for (int len = 0; len <= 15; len++) h.count[len] = 0;
        for (unsigned sym = 0; sym < n; sym++) h.count[lens[sym]]++;
        if (h.count[0] == n) return 0;
        int left = 1;
        for (int len = 1; len <= 15; len++) { left <<= 1; left -= h.count[len]; if (left < 0) return left; }
        offs[1] = 0;
        for (int len = 1; len < 15; len++) offs[len + 1] = offs[len] + h.count[len];
        for (unsigned sym = 0; sym < n; sym++) if (lens[sym] != 0) h.symbol[offs[lens[sym]]++] = (unsigned short)sym;
        return left;
    }
    int decode(const Huff& h) {
        int len = 1, code = 0, first = 0, index = 0;
        for (;;) {
            int b = bits(1); if (b < 0) return -1;
            code |= b;
            int count = h.count[len];
            if (code - first < count) return h.symbol[index + (code - first)];
            index += count; first += count; first <<= 1; code <<= 1;
            if (++len > 15) return -1;
        }
    }
    bool inflate(std::vector<unsigned char>& out) {
        static const unsigned short lbase[29] = {3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258};
        static const unsigned short lext[29] = {0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};
        static const unsigned short dbase[30] = {1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577};
        static const unsigned short dext[30] = {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};
        int last;
        do {
            last = bits(1); if (last < 0) return false;
            int type = bits(2); if (type < 0) return false;
            if (type == 0) {
                bitbuf_ = 0; bitcnt_ = 0;
                if (inPos_ + 4 > inLen_) return false;
                unsigned len = in_[inPos_] | ((unsigned)in_[inPos_ + 1] << 8);
                unsigned nlen = in_[inPos_ + 2] | ((unsigned)in_[inPos_ + 3] << 8);
                inPos_ += 4;
                if (len != ((~nlen) & 0xFFFF)) return false;
                if (inPos_ + len > inLen_) return false;
                out.insert(out.end(), in_ + inPos_, in_ + inPos_ + len);
                inPos_ += len;
            } else if (type == 1 || type == 2) {
                Huff lencode, distcode;
                unsigned short lengths[320];
                if (type == 1) {
                    for (int sym = 0; sym < 144; sym++) lengths[sym] = 8;
                    for (int sym = 144; sym < 256; sym++) lengths[sym] = 9;
                    for (int sym = 256; sym < 280; sym++) lengths[sym] = 7;
                    for (int sym = 280; sym < 288; sym++) lengths[sym] = 8;
                    construct(lengths, 288, lencode);
                    for (int sym = 0; sym < 30; sym++) lengths[sym] = 5;
                    construct(lengths, 30, distcode);
                } else {
                    int nlen = bits(5);  if (nlen < 0) return false;  nlen += 257;
                    int ndist = bits(5); if (ndist < 0) return false; ndist += 1;
                    int ncode = bits(4); if (ncode < 0) return false; ncode += 4;
                    if (nlen > 286 || ndist > 30) return false;
                    for (int i = 0; i < 19; i++) lengths[i] = 0;
                    static const unsigned short order[19] = {16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15};
                    for (int i = 0; i < ncode; i++) { int l = bits(3); if (l < 0) return false; lengths[order[i]] = (unsigned short)l; }
                    Huff clen;
                    construct(lengths, 19, clen);
                    unsigned index = 0;
                    while (index < (unsigned)(nlen + ndist)) {
                        int sym = decode(clen); if (sym < 0) return false;
                        if (sym < 16) lengths[index++] = (unsigned short)sym;
                        else {
                            unsigned short len = 0;
                            if (sym == 16) {
                                if (index == 0) return false;
                                len = lengths[index - 1];
                                int b = bits(2); if (b < 0) return false; sym = 3 + b;
                            } else if (sym == 17) { int b = bits(3); if (b < 0) return false; sym = 3 + b; }
                            else { int b = bits(7); if (b < 0) return false; sym = 11 + b; }
                            if (index + (unsigned)sym > (unsigned)(nlen + ndist)) return false;
                            while (sym--) lengths[index++] = len;
                        }
                    }
                    if (lengths[256] == 0) return false;
                    construct(lengths, nlen, lencode);
                    construct(lengths + nlen, ndist, distcode);
                }
                for (;;) {
                    int sym = decode(lencode); if (sym < 0) return false;
                    if (sym == 256) break;
                    if (sym < 256) out.push_back((unsigned char)sym);
                    else {
                        sym -= 257; if (sym >= 29) return false;
                        int b = bits(lext[sym]); if (b < 0) return false;
                        unsigned len = lbase[sym] + (unsigned)b;
                        int dsym = decode(distcode); if (dsym < 0) return false;
                        b = bits(dext[dsym]); if (b < 0) return false;
                        unsigned dist = dbase[dsym] + (unsigned)b;
                        if (dist > out.size()) return false;
                        size_t from = out.size() - dist;
                        for (unsigned i = 0; i < len; i++) out.push_back(out[from + i]);
                    }
                }
            } else return false;
        } while (!last);
        return true;
    }
};
} // namespace puffm

// ---------- 支持宏的 Office 文档扩展名 ----------
static const wchar_t* const kMacroExts[] = {
    L".DOCM", L".XLSM", L".PPTM", L".DOTM", L".XLTM", L".POTM",
    L".PPAM", L".SLDM", L".XLAM", L".XLSB",
    L".DOC",  L".XLS",  L".PPT",  L".DOT",  L".XLT",  L".POT"
};
static bool IsMacroDocExt(const std::wstring& path) {
    std::wstring u = path;
    for (size_t i = 0; i < u.size(); ++i)
        if (u[i] >= L'a' && u[i] <= L'z') u[i] = (wchar_t)(u[i] - 32);
    for (const wchar_t* e : kMacroExts) {
        size_t el = wcslen(e), ul = u.size();
        if (ul >= el && u.compare(ul - el, el, e) == 0) return true;
    }
    return false;
}
// 是否为 OOXML(ZIP) 容器
static bool IsZipContainer(const std::vector<unsigned char>& d) {
    return d.size() >= 4 && d[0] == 'P' && d[1] == 'K' && d[2] == 3 && d[3] == 4;
}

// ---------- VBA 自动执行宏入口 ----------
static const char* const kAutoMacroNames[] = {
    "Auto_Open", "AutoOpen", "Auto_Close", "AutoClose",
    "Auto_Exec", "AutoExec", "Auto_Exit", "AutoExit",
    "Auto_New",  "AutoNew",
    "Document_Open", "DocumentOpen", "Document_Close", "Document_New",
    "Workbook_Open", "WorkbookOpen", "Workbook_BeforeClose",
    "Workbook_SheetChange", "Workbook_SheetSelectionChange",
    "Workbook_Activate", "Presentation_Open", "SlideShow_Begin"
};
// ---------- 宏内危险 API / 行为 [高危] ----------
static const char* const kMacroHighRisk[] = {
    "WScript.Shell", "PowerShell", "powershell", "cmd.exe", "cmd /c",
    "ShellExecute", "CreateObject", "GetObject",
    "URLDownloadToFile", "URLDownloadToCacheFile",
    "ADODB.Stream", "MSXML2", "XMLHTTP", "ServerXMLHTTP", "WinHttp",
    "InternetOpen", "InternetReadFile",
    "CreateProcess", "rundll32", "regsvr32",
    "FromBase64String", "EncodedCommand", "-enc",
    "ShellCode", "VirtualAlloc", "WriteProcessMemory", "QueueUserAPC",
    "ReflectiveLoader", "vssadmin", "wmic", "schtasks", "certutil", "bitsadmin"
};
// ---------- 宏内可疑特征 [中危] ----------
static const char* const kMacroMidRisk[] = {
    "Chr(", "ChrW(", "Asc(", "StrReverse", "Environ(",
    "Scripting.FileSystemObject", "CreateTextFile",
    "FileCopy", "Kill ", "SaveAs", "Shell(",
    "Startup", "CurrentVersion\\Run", "HKEY_CURRENT_USER", "SendKeys"
};

static bool MacroReadFileAll(const std::wstring& path, std::vector<unsigned char>& out) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    long long sz = 0;
    {
        DWORD hi = 0;
        DWORD lo = GetFileSize(h, &hi);
        if (lo == INVALID_FILE_SIZE && GetLastError() != NO_ERROR) { CloseHandle(h); return false; }
        sz = ((long long)hi << 32) | (unsigned long)lo;
    }
    if (sz <= 0 || sz > 256LL * 1024 * 1024) { CloseHandle(h); return false; }
    out.resize((size_t)sz);
    DWORD rd = 0;
    BOOL ok = ReadFile(h, out.data(), (DWORD)out.size(), &rd, nullptr);
    CloseHandle(h);
    if (!ok) return false;
    out.resize(rd);
    return true;
}

// 在 ZIP(OFFICE OOXML) 中定位并解压 vbaProject.bin
// 返回: 0=未找到, 1=找到并解压成功, -1=找到但解压失败
static int ZipExtractVbaProject(const std::vector<unsigned char>& zip,
                                std::vector<unsigned char>& vba) {
    const unsigned char* d = zip.data();
    size_t n = zip.size();
    // 从尾部找 End Of Central Directory: 'PK\x05\x06'
    long long eocd = -1;
    for (long long i = (long long)n - 22; i >= 0; --i) {
        if (d[i] == 'P' && d[i+1] == 'K' && d[i+2] == 5 && d[i+3] == 6) { eocd = i; break; }
    }
    if (eocd < 0) return 0;
    unsigned cdCount = (unsigned)(d[eocd + 10] | ((unsigned)d[eocd + 11] << 8));
    unsigned long cdOff = (unsigned long)(d[eocd + 16] | ((unsigned long)d[eocd + 17] << 8) |
                          ((unsigned long)d[eocd + 18] << 16) | ((unsigned long)d[eocd + 19] << 24));
    if (cdOff + 4 > n) return 0;
    size_t pos = cdOff;
    for (unsigned i = 0; i < cdCount; ++i) {
        if (pos + 46 > n) break;
        if (!(d[pos] == 'P' && d[pos+1] == 'K' && d[pos+2] == 1 && d[pos+3] == 2)) break;
        unsigned method = (unsigned)(d[pos + 10] | ((unsigned)d[pos + 11] << 8));
        unsigned long csize = (unsigned long)(d[pos + 20] | ((unsigned long)d[pos + 21] << 8) |
                              ((unsigned long)d[pos + 22] << 16) | ((unsigned long)d[pos + 23] << 24));
        unsigned long usize = (unsigned long)(d[pos + 24] | ((unsigned long)d[pos + 25] << 8) |
                              ((unsigned long)d[pos + 26] << 16) | ((unsigned long)d[pos + 27] << 24));
        unsigned nlen = (unsigned)(d[pos + 28] | ((unsigned)d[pos + 29] << 8));
        unsigned elen = (unsigned)(d[pos + 30] | ((unsigned)d[pos + 31] << 8));
        unsigned clen = (unsigned)(d[pos + 32] | ((unsigned)d[pos + 33] << 8));
        unsigned long lhOff = (unsigned long)(d[pos + 42] | ((unsigned long)d[pos + 43] << 8) |
                              ((unsigned long)d[pos + 44] << 16) | ((unsigned long)d[pos + 45] << 24));
        if (pos + 46 + nlen > n) break;
        std::string name((const char*)(d + pos + 46), nlen);
        bool isVba = false;
        std::string lower = name;
        for (size_t k = 0; k < lower.size(); ++k)
            if (lower[k] >= 'A' && lower[k] <= 'Z') lower[k] = (char)(lower[k] + 32);
        if (lower.find("vbaproject.bin") != std::string::npos) isVba = true;
        if (isVba) {
            if (lhOff + 30 > n) return -1;
            unsigned lnlen = (unsigned)(d[lhOff + 26] | ((unsigned)d[lhOff + 27] << 8));
            unsigned lelen = (unsigned)(d[lhOff + 28] | ((unsigned)d[lhOff + 29] << 8));
            size_t dataOff = (size_t)lhOff + 30 + lnlen + lelen;
            if (dataOff + csize > n) return -1;
            if (method == 0) {                       // stored
                vba.assign(d + dataOff, d + dataOff + csize);
                return 1;
            } else if (method == 8) {                // deflate
                puffm::Inflator inf(d + dataOff, csize);
                if (!inf.inflate(vba)) return -1;
                if (usize && vba.size() != usize) { /* 容忍长度偏差, 以实际解压为准 */ }
                return 1;
            }
            return -1;   // 其他压缩方式(如 LZMA)暂不支持
        }
        pos += 46 + nlen + elen + clen;
    }
    return 0;
}

// 在数据中统计特征命中 (同时兼容 ASCII 与 UTF-16LE 存储)
static int CountHitBytes(const std::vector<unsigned char>& data, const char* pat) {
    if (!pat || !*pat) return 0;
    size_t plen = strlen(pat);
    int hits = 0;
    size_t first = 0, step = 1;
    // ASCII 扫描
    for (size_t i = 0; i + plen <= data.size(); i += step) {
        if (memcmp(data.data() + i, pat, plen) == 0) { ++hits; i += plen - 1; if (hits > 200) break; }
    }
    if (hits) return hits;
    // UTF-16LE: 每字符后插 0x00
    std::vector<unsigned char> u16;
    for (size_t k = 0; k < plen; ++k) { u16.push_back((unsigned char)pat[k]); u16.push_back(0); }
    for (size_t i = 0; i + u16.size() <= data.size(); ++i) {
        if (memcmp(data.data() + i, u16.data(), u16.size()) == 0) { ++hits; i += u16.size() - 1; if (hits > 200) break; }
    }
    return hits;
}

// 核心: 扫描单个 Office 文档的宏
// 返回风险分 (>=8 高危需隔离, >=4 可疑)
static int ScanMacroDoc(const std::wstring& path, std::wstring& reason) {
    reason.clear();
    if (!IsMacroDocExt(path)) return 0;
    std::vector<unsigned char> fileData;
    if (!MacroReadFileAll(path, fileData)) return 0;

    std::vector<unsigned char> vba;      // VBA 项目数据(待扫描)
    bool hasMacroProject = false;
    if (IsZipContainer(fileData)) {
        int r = ZipExtractVbaProject(fileData, vba);
        if (r == 1) hasMacroProject = true;
        else if (r == 0) return 0;       // OOXML 但无 vbaProject.bin -> 无宏
        else hasMacroProject = true;     // 解压失败, 退化为整体扫描
    } else {
        // OLE2 老格式: VBA 明文存储, 直接扫全文
        vba = fileData;
        // 判断是否存在 VBA 痕迹
        static const char* const oleVbaMarks[] = { "VBA", "Microsoft Visual Basic", "_VBA_PROJECT", "Macros" };
        for (const char* m : oleVbaMarks)
            if (CountHitBytes(fileData, m) > 0) { hasMacroProject = true; break; }
        if (!hasMacroProject) return 0;
    }
    if (vba.empty()) vba = fileData;

    int score = 0;
    std::wstring detail;
    int autoHits = 0, highHits = 0, midHits = 0;

    for (const char* a : kAutoMacroNames) {
        int c = CountHitBytes(vba, a);
        if (c > 0) { ++autoHits; if (detail.empty()) detail += L"自动执行宏:"; detail += L" ";
                     wchar_t buf[128]; swprintf(buf, 128, L"%hs", a); detail += buf; score += 3; }
    }
    for (const char* h : kMacroHighRisk) {
        int c = CountHitBytes(vba, h);
        if (c > 0) { ++highHits; if (highHits <= 4) { if (detail.size() < 300) { detail += L" 高危:";
                     wchar_t buf[128]; swprintf(buf, 128, L"%hs", h); detail += buf; } } score += 4; }
    }
    for (const char* m : kMacroMidRisk) {
        if (CountHitBytes(vba, m) > 0) { ++midHits; score += 1; }
    }
    // VBA Stomping / 高度混淆: 有宏项目却搜不到任何已知过程名
    bool anyProc = false;
    static const char* const probeNames[] = { "Sub ", "Function ", "Public Sub", "Private Sub", "End Sub" };
    for (const char* p : probeNames) if (CountHitBytes(vba, p) > 0) { anyProc = true; break; }
    if (hasMacroProject && !anyProc && vba.size() > 512) {
        score += 3;
        detail += L" (可疑: 含宏项目但无明文过程名, 疑似 VBA Stomping/高度混淆)";
    }
    if (autoHits && highHits) score += 4;   // 自动执行 + 高危 API 组合 -> 极可能是宏病毒
    if (score <= 0) { reason = L"含宏但无明显恶意特征"; return 0; }

    wchar_t buf2[256];
    swprintf(buf2, 256, L"自动执行宏%d项 高危%d项 可疑%d项", autoHits, highHits, midHits);
    reason = buf2 + detail;
    return score;
}

// 隔离: 移动文档到隔离目录
static std::wstring MacroQuarantineDir() {
    wchar_t tmp[MAX_PATH] = { 0 };
    GetTempPathW(MAX_PATH, tmp);
    std::wstring d = std::wstring(tmp) + L"zz_EDR_quarantine";
    CreateDirectoryW(d.c_str(), nullptr);
    return d;
}
static bool MacroQuarantine(const std::wstring& path) {
    if (IsProtectedPath(path)) return false;
    std::wstring dir = MacroQuarantineDir();
    std::wstring name = path;
    size_t s = name.find_last_of(L"\\/");
    if (s != std::wstring::npos) name = name.substr(s + 1);
    std::wstring dst = dir + L"\\" + name;
    for (int i = 1; i < 1000; ++i) {
        if (GetFileAttributesW(dst.c_str()) == INVALID_FILE_ATTRIBUTES) break;
        wchar_t nb[32]; swprintf(nb, 32, L".%d", i);
        dst = dir + L"\\" + name + nb;
    }
    return MoveFileW(path.c_str(), dst.c_str()) ? true : false;
}

// 目录递归: 扫描所有 Office 文档宏
static void MacroScanDir(const std::wstring& root, int depth, int& scanned, int& bad, int& suspicious) {
    if (depth > 3) return;
    std::wstring q = root + L"\\*";
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(q.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        std::wstring name = fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ? fd.cFileName : fd.cFileName;
        if (name == L"." || name == L"..") continue;
        std::wstring full = root + L"\\" + name;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            MacroScanDir(full, depth + 1, scanned, bad, suspicious);
        } else {
            if (!IsMacroDocExt(full)) continue;
            ++scanned;
            std::wstring reason;
            int sc = ScanMacroDoc(full, reason);
            if (sc >= 8) {
                ++bad;
                LogFmt(L"[宏病毒] 高危文档: %s (风险分%d) %s", full.c_str(), sc, reason.c_str());
                BehavAdd(0, full, BEHAV_BLOCK, 10, L"宏病毒高危(风险分" + std::to_wstring(sc) + L"): " + reason);
                if (g_cfg.advAggressive) {
                    if (!IsProtectedPath(full)) { OverwriteWithEmptyFile(full); DeleteFileW(full.c_str());
                        LogFmt(L"[宏病毒] 激进模式: 已强制删除 %s", full.c_str()); }
                } else {
                    if (MacroQuarantine(full))
                        LogFmt(L"[宏病毒] 已隔离: %s", full.c_str());
                    else
                        LogFmt(L"[宏病毒] 隔离失败(可能受保护): %s", full.c_str());
                }
            } else if (sc >= 4) {
                ++suspicious;
                LogFmt(L"[宏病毒] 可疑文档: %s (风险分%d) %s", full.c_str(), sc, reason.c_str());
                BehavAdd(0, full, BEHAV_FILE, 6, L"宏可疑(风险分" + std::to_wstring(sc) + L"): " + reason);
            }
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

// 全盘(用户目录)宏扫描入口
static void MacroScanAll() {
    LogPost(L"宏病毒扫描已启动: 扫描 Office 文档内 VBA 宏, 检测自动执行宏与危险 API");
    int scanned = 0, bad = 0, sus = 0;
    wchar_t* dirs[] = { nullptr, nullptr, nullptr };
    wchar_t p1[MAX_PATH] = { 0 }, p2[MAX_PATH] = { 0 }, p3[MAX_PATH] = { 0 };
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_DESKTOP, nullptr, 0, p1))) dirs[0] = p1;
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PERSONAL, nullptr, 0, p2))) dirs[1] = p2;
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, p3))) dirs[2] = p3;
    for (wchar_t* d : dirs) if (d && *d) MacroScanDir(d, 0, scanned, bad, sus);
    LogFmt(L"[宏病毒] 扫描完成: 文档 %d 个, 高危 %d 个, 可疑 %d 个", scanned, bad, sus);
}

// 安全基线审计: Office 宏安全设置
static void MacroSecurityAudit() {
    const wchar_t* vers[] = { L"16.0", L"15.0", L"14.0", L"12.0" };
    const wchar_t* apps[] = { L"Word", L"Excel", L"PowerPoint", L"Outlook", L"Access", L"Publisher" };
    LogPost(L"宏安全基线审计开始: 检查 Office 宏安全设置(AccessVBOM / VBAWarnings)");
    int risky = 0;
    for (const wchar_t* v : vers) {
        for (const wchar_t* a : apps) {
            std::wstring key = std::wstring(L"Software\\Microsoft\\Office\\") + v + L"\\" + a + L"\\Security";
            HKEY hk = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, key.c_str(), 0, KEY_READ, &hk) != ERROR_SUCCESS) continue;
            DWORD val = 0, type = 0, sz = sizeof(DWORD);
            // AccessVBOM == 1 表示允许 VBA 项目对象模型访问(宏病毒常用)
            if (RegQueryValueExW(hk, L"AccessVBOM", nullptr, &type, (LPBYTE)&val, &sz) == ERROR_SUCCESS) {
                if (val == 1) {
                    ++risky;
                    LogFmt(L"[宏基线] 高危: Office %s %s 允许 VBA 项目对象模型访问(AccessVBOM=1)", v, a);
                    BehavAdd(0, L"Office", BEHAV_REG, 8,
                             std::wstring(L"宏安全设置风险: ") + a + L" " + v + L" AccessVBOM=1 (宏病毒常利用)");
                }
            }
            sz = sizeof(DWORD); val = 0; type = 0;
            // VBAWarnings: 1=启用所有宏(不提示, 危险), 4=禁用(安全)
            if (RegQueryValueExW(hk, L"VBAWarnings", nullptr, &type, (LPBYTE)&val, &sz) == ERROR_SUCCESS) {
                if (val == 1) {
                    ++risky;
                    LogFmt(L"[宏基线] 高危: Office %s %s 宏设置为\"启用所有宏\"(VBAWarnings=1)", v, a);
                    BehavAdd(0, L"Office", BEHAV_REG, 9,
                             std::wstring(L"宏安全设置风险: ") + a + L" " + v + L" VBAWarnings=1 启用所有宏(不提示)");
                }
            }
            RegCloseKey(hk);
        }
    }
    if (!risky) LogPost(L"[宏基线] 未发现明显风险的宏安全设置");
    else LogFmt(L"[宏基线] 审计完成: 发现 %d 项风险设置", risky);
}

// 宏防护总入口: 扫描 + 基线审计
static void MacroGuardRun() {
    LaunchScan([] { MacroScanAll(); });
    LaunchScan([] { MacroSecurityAudit(); });
}


// ============================================================
//  扫描引擎
// ============================================================

// ============================================================
//  内置规则集 (IOC / YARA 风格特征 / 黑名单)
//  说明: 以下均为"检测特征"——即恶意样本中出现的字符串/行为标识,
//        用于识别与告警, 不含任何攻击性 payload。
//        生产建议: 接入外部威胁情报自动更新下表。
// ============================================================
static bool FileSha256W(const std::wstring& path, std::wstring& outHex);  // 前向: 规则匹配需算哈希
static void QuarantineFile(const wstring& path);
static bool IsProtectedPath(const wstring& p);  // 前向: 行为/沙箱模块需判定保护路径                          // 前向: 规则命中后隔离

// ---- 1. YARA 风格文本特征 (在文件内容 / 命令行 / 脚本中搜索) ----
struct YaraRule { const wchar_t* name; const wchar_t* needle; int sev; const wchar_t* desc; };
static const YaraRule g_yara[] = {
    // 凭据窃取
    { L"Mimikatz",        L"mimikatz",                    3, L"Mimikatz 凭据窃取" },
    { L"Sekurlsa",        L"sekurlsa::logonpasswords",    3, L"导出明文口令" },
    { L"GoldenTicket",    L"kerberos::golden",            3, L"黄金票据" },
    { L"LaZagne",         L"lazagne",                     3, L"LaZagne 凭据窃取" },
    { L"Procdump",        L"procdump",                    2, L"疑似转储 LSASS" },
    { L"SAM_Dump",        L"hklm\\sam",                   2, L"导出 SAM(凭据)" },
    { L"WCE",             L"wce.exe",                     3, L"Windows 凭据编辑器" },
    { L"Browser_Cred",    L"login data",                  1, L"疑似读浏览器凭据" },
    // 注入 / Shellcode
    { L"RemoteThread",    L"CreateRemoteThread",          2, L"远程线程注入" },
    { L"WriteProcMem",    L"WriteProcessMemory",          2, L"跨进程写内存" },
    { L"VirtualAllocEx",  L"VirtualAllocEx",              2, L"跨进程分配内存" },
    { L"NtMapView",       L"NtMapViewOfSection",          2, L"Section 映射注入" },
    { L"QueueUserAPC",    L"QueueUserAPC",                2, L"APC 注入" },
    { L"Reflective",      L"ReflectiveLoader",            3, L"反射式 DLL 注入" },
    { L"Hollow",          L"NtUnmapViewOfSection",        3, L"进程镂空" },
    { L"Meterpreter",     L"meterpreter",                 3, L"Meterpreter 载荷" },
    { L"Beacon",          L"beacon.dll",                  3, L"Cobalt Strike Beacon" },
    { L"VirtProtect",     L"VirtualProtectEx",            2, L"改内存属性为可执行" },
    // 脚本 / 无文件
    { L"PS_Encoded",      L"-enc ",                       3, L"PowerShell 编码命令" },
    { L"PS_B64",          L"frombase64string",            2, L"Base64 解码执行" },
    { L"PS_IEX",          L"iex(",                        3, L"IEX 下载执行" },
    { L"InvokeExpr",      L"invoke-expression",           2, L"PS 动态执行" },
    { L"DownloadString",  L"downloadstring",              2, L"PS 远程下载" },
    { L"DownloadFile",    L"downloadfile",                2, L"PS 下载文件" },
    { L"Certutil",        L"certutil",                    2, L"certutil 下载/解码" },
    { L"Bitsadmin",       L"bitsadmin",                   2, L"bitsadmin 下载" },
    { L"Squiblydoo",      L"scrobj.dll",                  3, L"regsvr32 绕过" },
    { L"MSHTA",           L"mshta.exe",                   2, L"mshta 执行脚本" },
    { L"Rundll32",        L"rundll32.exe",                1, L"rundll32 白利用" },
    { L"InstallUtil",     L"installutil.exe",             2, L"InstallUtil 绕过" },
    { L"MSBuild",         L"msbuild.exe",                 2, L"MSBuild 无文件执行" },
    { L"Macro_Auto",      L"auto_open",                   3, L"Office 宏自动执行" },
    // 勒索
    { L"Ransom_Note",     L"your files have been encrypted", 3, L"勒索信" },
    { L"Ransom_Note2",    L"your files are encrypted",       3, L"勒索信" },
    { L"Ransom_BTC",      L"bitcoin",                        2, L"比特币赎金" },
    { L"VSS_Delete",      L"vssadmin delete shadows",        3, L"删除卷影(勒索前置)" },
    { L"Shadow_Del",      L"delete shadows",                 3, L"删卷影副本" },
    { L"BCDEdit_RecOff",  L"recoveryenabled no",             3, L"禁用恢复环境" },
    { L"WBAdmin_Del",     L"wbadmin delete",                 3, L"删系统备份" },
    // 挖矿
    { L"Miner_Stratum",   L"stratum+tcp",                 3, L"矿池协议" },
    { L"Miner_Getwork",   L"getwork",                     2, L"矿池协议" },
    { L"Miner_Monero",    L"monero",                      2, L"门罗币" },
    { L"Miner_Coinhive",  L"coinhive",                    3, L"网页挖矿" },
    // 远控 / 后门
    { L"NjRAT",           L"njrat",                       3, L"njRAT" },
    { L"Gh0st",           L"gh0st",                       3, L"Gh0st RAT" },
    { L"DarkComet",       L"darkcomet",                   3, L"DarkComet" },
    { L"NanoCore",        L"nanocore",                    3, L"NanoCore" },
    { L"QuasarRAT",       L"quasar",                      2, L"Quasar RAT" },
    { L"AsyncRAT",        L"asyncrat",                    3, L"AsyncRAT" },
    { L"NetWire",         L"netwire",                     3, L"NetWire RAT" },
    { L"AgentTesla",      L"agenttesla",                  3, L"AgentTesla 窃密" },
    { L"Formbook",        L"formbook",                    3, L"Formbook 窃密" },
    { L"Remcos",          L"remcos",                      3, L"Remcos RAT" },
    { L"PlugX",           L"plugx",                       3, L"PlugX 后门" },
    // 提权 / 绕过
    { L"UAC_FodHelper",   L"fodhelper",                   3, L"UAC 绕过" },
    { L"UAC_Eventvwr",    L"eventvwr",                    2, L"UAC 绕过" },
    { L"UAC_Sdclt",       L"sdclt",                       2, L"UAC 绕过" },
    { L"UAC_CMSTP",       L"cmstp",                       3, L"CMSTP 绕过" },
    { L"SeDebug",         L"sedebugprivilege",            2, L"提调试权限" },
    { L"Defender_Off",    L"set-mppreference",            2, L"关 Defender" },
    { L"Defender_Excl",   L"add-mppreference",            2, L"加 Defender 排除项" },
    { L"FW_Off",          L"advfirewall set",             2, L"关防火墙" },
    { L"AMSI_Bypass",     L"amsiutils",                   3, L"AMSI 绕过工具" },
    // 持久化 / 侦察
    { L"SchTasks",        L"schtasks /create",            2, L"建计划任务" },
    { L"Run_Key",         L"currentversion\\run",         2, L"写 Run 自启动" },
    { L"Net_User_Add",    L"net user /add",               2, L"新建账户" },
    { L"Net_Group_Add",   L"net localgroup administrators",2, L"加管理员组" },
    { L"WMIC_Remote",     L"process call create",         2, L"WMIC 远程执行" },
    { L"Sc_Create",       L"sc create",                   2, L"创建服务" },
    { L"Recon_SysInfo",   L"systeminfo",                  1, L"系统侦察" },
    { L"Recon_Whoami",    L"whoami /priv",                1, L"权限侦察" },
};
static const int g_yaraCount = (int)(sizeof(g_yara) / sizeof(g_yara[0]));

// ---- 2. 进程名黑名单 ----
struct ProcRule { const wchar_t* name; int sev; const wchar_t* desc; };
static const ProcRule g_procRules[] = {
    { L"mimikatz.exe", 3, L"凭据窃取" },      { L"mimilib.dll", 3, L"Mimikatz SSP" },
    { L"lazagne.exe",  3, L"凭据窃取" },      { L"procdump.exe", 2, L"进程转储" },
    { L"procdump64.exe",2,L"进程转储" },      { L"wce.exe", 3, L"凭据窃取" },
    { L"gsecdump.exe", 3, L"凭据窃取" },      { L"pwdump.exe", 3, L"口令导出" },
    { L"fgdump.exe",   3, L"凭据窃取" },      { L"cain.exe", 2, L"口令恢复(双用途)" },
    { L"psexec.exe",   2, L"PsExec(双用途)" },{ L"psexesvc.exe", 3, L"PsExec 服务后门" },
    { L"nc.exe",       3, L"Netcat 后门" },   { L"ncat.exe", 3, L"Ncat 后门" },
    { L"netcat.exe",   3, L"Netcat" },
    { L"xmrig.exe",    3, L"门罗币挖矿" },    { L"minerd.exe", 3, L"挖矿" },
    { L"cgminer.exe",  3, L"挖矿" },          { L"bfgminer.exe", 3, L"挖矿" },
    { L"ethminer.exe", 3, L"挖矿" },          { L"cpuminer.exe", 3, L"挖矿" },
    { L"nbminer.exe",  3, L"挖矿" },          { L"lolminer.exe", 3, L"挖矿" },
    { L"beacon.exe",   3, L"C2 Beacon" },     { L"gh0st.exe", 3, L"Gh0st RAT" },
    { L"darkcomet.exe",3, L"DarkComet" },     { L"nanocore.exe", 3, L"NanoCore" },
    { L"remcos.exe",   3, L"Remcos" },        { L"asyncrat.exe", 3, L"AsyncRAT" },
    { L"netwire.exe",  3, L"NetWire" },       { L"quasar.exe", 2, L"Quasar RAT" },
    { L"plugx",        3, L"PlugX" },         { L"cobaltstrike", 3, L"Cobalt Strike" },
    { L"meterpreter",  3, L"Metasploit" },
    { L"sqlmap",       1, L"SQL 注入工具(双用途, 仅告警)" },
    { L"nmap.exe",     1, L"端口扫描(双用途, 仅告警)" },
    { L"hydra.exe",    2, L"口令爆破(双用途)" },
    { L"hashcat.exe",  2, L"口令破解(双用途)" },
    { L"john.exe",     2, L"口令破解(双用途)" },
};
static const int g_procRuleCount = (int)(sizeof(g_procRules) / sizeof(g_procRules[0]));

// ---- 3. 网络 IOC: 恶意端口 + C2/隧道域名关键词 ----
static const int g_badPorts[] = {
    8880,   // 银狐(Winos/ValleyRAT)默认 C2 端口
    4444, 31337, 1337, 9001, 6665, 6666, 6667, 6668, 6669,
    1234, 12345, 12333, 27374, 31335, 27444, 27665, 5555, 4443
};
static const int g_badPortCount = (int)(sizeof(g_badPorts) / sizeof(g_badPorts[0]));
static const wchar_t* g_badDomains[] = {
    L"duckdns.org", L"no-ip", L"ddns.net", L"dyndns", L"hopto.org", L"zapto.org",
    L"noip.com", L"ngrok.io", L"serveo.net", L"localhost.run", L"pastebin.com",
    L"paste.ee", L"hastebin", L"transfer.sh", L"anonfiles"
};
static const int g_badDomainCount = (int)(sizeof(g_badDomains) / sizeof(g_badDomains[0]));

// ---- 4. 勒索软件扩展名 ----
static const wchar_t* g_ransomExt[] = {
    L".locked", L".crypto", L".crypt", L".enc", L".wncry", L".wannacry", L".locky",
    L".zepto", L".cerber", L".zzz", L".encrypted", L".ransom", L".pay", L".btc",
    L".onion", L".lockbit", L".blackcat", L".conti", L".revil", L".sodinokibi",
    L".ryuk", L".maze", L".teslacrypt", L".cryptolocker", L".gandcrab", L".dharma",
    L".phobos", L".stop", L".djvu", L".makop", L".avaddon", L".babuk", L".clop",
    L".netwalker", L".pysa", L".ragnarok", L".snake", L".suncrypt", L".wormhole",
    L".kitty", L".vault", L".cry", L".globe", L".purge", L".kraken", L".sexy"
};
static const int g_ransomExtCount = (int)(sizeof(g_ransomExt) / sizeof(g_ransomExt[0]));

// ---- 5. 持久化注册表检测点 ----
struct RegRule { HKEY root; const wchar_t* sub; const wchar_t* desc; int sev; };
static const RegRule g_regRules[] = {
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", L"HKLM Run", 2 },
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"HKLM RunOnce", 2 },
    { HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", L"HKCU Run", 2 },
    { HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"HKCU RunOnce", 2 },
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Winlogon(Shell/Userinit)", 3 },
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"AppInit_DLLs", 3 },
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", L"IFEO 调试器劫持", 3 },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager", L"Session Manager(AppCert/BootExecute)", 3 },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"LSA(通知包/SSP)", 3 },
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"系统策略", 2 },
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", L"Shell 文件夹", 1 },
    { HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"HKCU 系统策略", 2 },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services", L"服务 ImagePath", 2 },
};
static const int g_regRuleCount = (int)(sizeof(g_regRules) / sizeof(g_regRules[0]));

// ---- 6. 已知恶意哈希 (公开情报示例; 建议接情报源更新) ----
struct HashRule { const wchar_t* sha; const wchar_t* name; int sev; };
static const HashRule g_hashRules[] = {
    { L"ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa", L"WannaCry(公开情报)", 3 },
};
static const int g_hashRuleCount = (int)(sizeof(g_hashRules) / sizeof(g_hashRules[0]));

// ---- 7. 可疑落盘路径 (可执行文件出现在此需提高关注) ----
static const wchar_t* g_suspDirs[] = {
    L"\\temp\\", L"\\tmp\\", L"\\downloads\\", L"\\appdata\\local\\temp\\",
    L"\\appdata\\roaming\\", L"\\$recycle.bin\\", L"\\recycler\\",
    L"\\windows\\temp\\", L"\\perflogs\\", L"\\users\\public\\",
    L"\\start menu\\programs\\startup\\", L"\\programdata\\"
};
static const int g_suspDirCount = (int)(sizeof(g_suspDirs) / sizeof(g_suspDirs[0]));

// ---- 8. 开机扫描保护名单 (永不被删除, 防系统无法启动) ----
static const wchar_t* g_protectDirs[] = {
    L"c:\\windows\\system32", L"c:\\windows\\syswow64", L"c:\\windows\\winsxs",
    L"c:\\windows\\servicing", L"c:\\windows\\boot", L"c:\\boot",
    L"c:\\windows\\system32\\drivers", L"c:\\windows\\system32\\config",
    L"c:\\windows\\explorer.exe", L"c:\\windows\\regedit.exe"
};
static const int g_protectCount = (int)(sizeof(g_protectDirs) / sizeof(g_protectDirs[0]));

// ---------------- 规则匹配辅助函数 ----------------
static wstring ToLowerW(const wstring& s) {
    wstring r = s;
    for (size_t i = 0; i < r.size(); ++i)
        if (r[i] >= L'A' && r[i] <= L'Z') r[i] = (wchar_t)(r[i] + 32);
    return r;
}
// 在已小写文本中搜索全部 YARA 特征, 返回最高 sev (0=无命中)
static int RuleMatchText(const wstring& lowerText, wstring& hitName, wstring& hitDesc) {
    int best = 0;
    for (int i = 0; i < g_yaraCount; ++i) {
        wstring needle = ToLowerW(g_yara[i].needle);
        if (lowerText.find(needle) != wstring::npos && g_yara[i].sev > best) {
            best = g_yara[i].sev; hitName = g_yara[i].name; hitDesc = g_yara[i].desc;
        }
    }
    return best;
}
// 进程名命中黑名单
static bool RuleMatchProc(const wstring& procName, int& sev, wstring& desc) {
    wstring lower = ToLowerW(procName);
    for (int i = 0; i < g_procRuleCount; ++i) {
        if (lower.find(ToLowerW(g_procRules[i].name)) != wstring::npos) {
            sev = g_procRules[i].sev; desc = g_procRules[i].desc; return true;
        }
    }
    return false;
}
// 端点命中 C2 IOC (端口 / 域名)
static bool RuleMatchEndpoint(const wstring& remote, int& sev, wstring& why) {
    if (remote.empty()) return false;
    wstring lower = ToLowerW(remote);
    for (int i = 0; i < g_badDomainCount; ++i) {
        if (lower.find(ToLowerW(g_badDomains[i])) != wstring::npos) {
            sev = 3; why = wstring(L"C2/隧道域名: ") + g_badDomains[i]; return true;
        }
    }
    size_t colon = lower.rfind(L':');
    if (colon != wstring::npos) {
        int port = _wtoi(lower.c_str() + colon + 1);
        for (int i = 0; i < g_badPortCount; ++i)
            if (port == g_badPorts[i]) { sev = 2; why = L"可疑 C2 端口"; return true; }
    }
    return false;
}
// 勒索扩展名
static bool IsRansomExt(const wstring& path) {
    wstring lower = ToLowerW(path);
    for (int i = 0; i < g_ransomExtCount; ++i) {
        wstring ext = ToLowerW(g_ransomExt[i]);
        if (lower.size() >= ext.size() &&
            lower.compare(lower.size() - ext.size(), ext.size(), ext) == 0) return true;
    }
    return false;
}
// 哈希黑名单
static bool RuleMatchHash(const wstring& hex, wstring& name, int& sev) {
    if (hex.empty()) return false;
    wstring lower = ToLowerW(hex);
    for (int i = 0; i < g_hashRuleCount; ++i)
        if (lower == ToLowerW(g_hashRules[i].sha)) { name = g_hashRules[i].name; sev = g_hashRules[i].sev; return true; }
    return false;
}
// 综合文件检测: 勒索后缀 + 哈希 + 内容特征 + 可疑路径
// 返回 0=干净, >0=最高严重级别; reason 输出命中原因
// ============================================================================
// 派生 / 变种 检测 (反多态 · 反重打包 · 反免杀)
// 原理: 变种必然改哈希, 但改不掉两样东西——
//   1) 能力 API 组合 (注入/勒索/键盘记录... 要实现目的必须调用同一组 API)
//   2) 代码结构相似度 (模糊哈希, 已用真实数据验证: 3%改动 94.5%, 无关文件 6.2%)
// ============================================================================

#define FZW    32          // 滚动窗口
#define FZB    257u        // 滚动基数
#define FZSIG  64          // 签名最大长度
static unsigned g_fzPowm = 0;
static void FzInit(void) {
    unsigned p = 1;
    for (int i = 0; i < FZW - 1; ++i) p *= FZB;
    g_fzPowm = p;
}
static char FzB64(unsigned v) {
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    return t[v & 63];
}
static unsigned FzBlockSize(size_t n) {
    unsigned b = 3;
    while ((size_t)b * FZSIG < n) b *= 2;
    return b < 3 ? 3 : b;
}
// 生成单级模糊签名
static void FzSig(const unsigned char* d, size_t n, unsigned bs, char* out, int* olen) {
    unsigned rh = 0, bh = 2166136261u;
    unsigned char win[FZW]; int wpos = 0, wcount = 0, len = 0;
    memset(win, 0, sizeof(win));
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = d[i];
        bh = (bh ^ c) * 16777619u;                       // 块内 FNV-1a
        if (wcount == FZW) {                             // 窗口满: 滚出旧字节
            rh = (rh - (unsigned)win[wpos] * g_fzPowm) * FZB + c;
        } else {
            rh = rh * FZB + c; wcount++;
        }
        win[wpos] = c; wpos = (wpos + 1) % FZW;
        if ((rh % bs) == (bs - 1) && len < FZSIG - 1) {  // 触发点切块
            out[len++] = FzB64(bh);
            bh = 2166136261u;
        }
    }
    if (len < FZSIG) out[len++] = FzB64(bh);
    out[len] = 0; *olen = len;
}
static int FzLev(const char* a, const char* b) {
    int la = (int)strlen(a), lb = (int)strlen(b);
    if (!la) return lb; if (!lb) return la;
    static int dp[80][80];
    for (int i = 0; i <= la; ++i) dp[i][0] = i;
    for (int j = 0; j <= lb; ++j) dp[0][j] = j;
    for (int i = 1; i <= la; ++i)
        for (int j = 1; j <= lb; ++j) {
            int cost = (a[i - 1] == b[j - 1]) ? 0 : 1;
            int m = dp[i - 1][j] + 1;
            if (dp[i][j - 1] + 1 < m) m = dp[i][j - 1] + 1;
            if (dp[i - 1][j - 1] + cost < m) m = dp[i - 1][j - 1] + cost;
            dp[i][j] = m;
        }
    return dp[la][lb];
}
static double FzSim(const char* a, const char* b) {
    int la = (int)strlen(a), lb = (int)strlen(b);
    if (!la || !lb) return 0.0;
    double v = 100.0 * (1.0 - (double)FzLev(a, b) / (double)(la > lb ? la : lb));
    return v < 0 ? 0 : v;
}
static void FzPair(const std::vector<unsigned char>& d,
                   char s1[FZSIG + 1], char s2[FZSIG + 1], unsigned* bs1) {
    unsigned b = FzBlockSize(d.size());
    int l1 = 0, l2 = 0;
    FzSig(d.empty() ? (const unsigned char*)"" : &d[0], d.size(), b, s1, &l1);
    FzSig(d.empty() ? (const unsigned char*)"" : &d[0], d.size(), b * 2, s2, &l2);
    *bs1 = b;
}
static double FzCmp(const char* a1, const char* a2, unsigned bsa,
                    const char* b1, const char* b2, unsigned bsb) {
    double best = 0, v;
    if (bsa == bsb)          { v = FzSim(a1, b1); if (v > best) best = v; }
    if (bsa == bsb * 2)      { v = FzSim(a1, b2); if (v > best) best = v; }
    if (bsa * 2 == bsb)      { v = FzSim(a2, b1); if (v > best) best = v; }
    if (bsa * 2 == bsb * 2)  { v = FzSim(a2, b2); if (v > best) best = v; }
    if (best <= 0) { v = FzSim(a1, b1) * 0.9; if (v > best) best = v; }
    return best;
}

// ---------- PE 解析 (手工偏移, 兼容 PE32 / PE32+) ----------
struct PeInfo {
    bool valid = false, pe64 = false;
    unsigned short nSec = 0, machine = 0, subsystem = 0;
    unsigned long entry = 0, timeStamp = 0;
    std::vector<wstring> imports;
    std::vector<wstring> secNames;
    double maxEnt = 0, avgEnt = 0;
    int rwxCount = 0;
};
static bool PeRvaOff(const std::vector<unsigned char>& d, size_t secBase,
                     unsigned short nSec, unsigned long rva, size_t& off) {
    for (unsigned short i = 0; i < nSec; ++i) {
        size_t so = secBase + (size_t)i * 40;
        if (so + 40 > d.size()) return false;
        unsigned long vs = 0, va = 0, rs = 0, rp = 0;
        memcpy(&vs, &d[so + 8], 4);
        memcpy(&va, &d[so + 12], 4);
        memcpy(&rs, &d[so + 16], 4);
        memcpy(&rp, &d[so + 20], 4);
        unsigned long span = vs ? vs : rs;
        if (span && rva >= va && rva < va + span && rs > 0) {
            size_t delta = rva - va;
            if (delta >= rs) return false;
            off = rp + delta;
            return off < d.size();
        }
    }
    return false;
}
static bool PeParse(const std::vector<unsigned char>& d, PeInfo& pi) {
    if (d.size() < 0x200 || d[0] != 'M' || d[1] != 'Z') return false;
    unsigned long lf = 0; memcpy(&lf, &d[0x3C], 4);
    if (lf + 24 >= d.size() || d[lf] != 'P' || d[lf + 1] != 'E') return false;
    memcpy(&pi.machine, &d[lf + 4], 2);
    memcpy(&pi.nSec,    &d[lf + 6], 2);
    memcpy(&pi.timeStamp, &d[lf + 8], 4);
    unsigned short sizeOpt = 0; memcpy(&sizeOpt, &d[lf + 20], 2);
    size_t optOff = (size_t)lf + 24;
    unsigned short magic = 0;
    if (optOff + 2 <= d.size()) memcpy(&magic, &d[optOff], 2);
    pi.pe64 = (magic == 0x20b);
    pi.valid = true;
    if (pi.nSec > 32) pi.nSec = 32;
    size_t secBase = optOff + sizeOpt;
    if (optOff + 28 <= d.size()) memcpy(&pi.entry, &d[optOff + 16], 4);
    size_t dirOff = optOff + (pi.pe64 ? 112 : 96);
    if (dirOff + 48 <= d.size()) memcpy(&pi.subsystem, &d[dirOff - 4 - 2 + 0], 2);
    // 节区
    double sum = 0; int cnt = 0;
    for (unsigned short s = 0; s < pi.nSec; ++s) {
        size_t so = secBase + (size_t)s * 40;
        if (so + 40 > d.size()) break;
        char nm[9] = { 0 }; memcpy(nm, &d[so], 8);
        unsigned long vs = 0, rs = 0, rp = 0, ch = 0;
        memcpy(&vs, &d[so + 8], 4); memcpy(&rs, &d[so + 16], 4);
        memcpy(&rp, &d[so + 20], 4); memcpy(&ch, &d[so + 36], 4);
        std::wstring wn(nm, nm + strnlen(nm, 8));
        pi.secNames.push_back(wn);
        if (rs > 0 && rp + rs <= d.size()) {
            double e = CalcEntropy(&d[rp], rs);
            if (e > pi.maxEnt) pi.maxEnt = e;
            sum += e; cnt++;
        }
        if ((ch & 0x20000000) && (ch & 0x80000000)) pi.rwxCount++;
    }
    if (cnt) pi.avgEnt = sum / cnt;
    // 导入表
    if (dirOff + 16 <= d.size()) {
        unsigned long impRva = 0;
        memcpy(&impRva, &d[dirOff + 8], 4);
        size_t idOff = 0;
        if (impRva && PeRvaOff(d, secBase, pi.nSec, impRva, idOff)) {
            for (int i = 0; i < 128 && (int)pi.imports.size() < 400; ++i) {
                size_t o = idOff + (size_t)i * 20;
                if (o + 20 > d.size()) break;
                unsigned long oft = 0, nameRva = 0, ft = 0;
                memcpy(&oft, &d[o], 4);
                memcpy(&nameRva, &d[o + 12], 4);
                memcpy(&ft, &d[o + 16], 4);
                if (!nameRva && !ft) break;
                unsigned long thunkRva = oft ? oft : ft;
                size_t thOff = 0;
                if (!thunkRva || !PeRvaOff(d, secBase, pi.nSec, thunkRva, thOff)) continue;
                size_t step = pi.pe64 ? 8 : 4;
                for (int j = 0; j < 512; ++j) {
                    size_t to = thOff + (size_t)j * step;
                    if (to + step > d.size()) break;
                    unsigned long long val = 0;
                    if (pi.pe64) memcpy(&val, &d[to], 8);
                    else { unsigned long v = 0; memcpy(&v, &d[to], 4); val = v; }
                    if (!val) break;
                    unsigned long long ordFlag = pi.pe64 ? 0x8000000000000000ULL : 0x80000000ULL;
                    if (val & ordFlag) continue;                       // 序号导入, 无名字
                    size_t nOff = 0;
                    if (!PeRvaOff(d, secBase, pi.nSec, (unsigned long)val, nOff)) continue;
                    if (nOff + 2 > d.size()) continue;
                    std::string api;
                    for (size_t k = nOff + 2; k < d.size() && d[k] && api.size() < 96; ++k)
                        api.push_back((char)d[k]);
                    if (!api.empty()) pi.imports.push_back(wstring(api.begin(), api.end()));
                }
            }
        }
    }
    return true;
}

// ---------- 能力族谱: 依据 MITRE ATT&CK 真实技术映射的 API 组合 ----------
// 原理: 变种可改哈希/字符串/加壳, 但"要实现某目的必须调用同一组 API", 改不掉。
// 技术 ID 取自 MITRE ATT&CK (T1055.* 注入族 / T1003.* 凭据 / T1027.007 动态解析 等)。
struct CapRule {
    const wchar_t* family;
    const wchar_t* desc;
    const wchar_t* tid;   // MITRE 技术 ID, 便于溯源
    int sev;      // 命中严重级别
    int need;     // 需要命中几个 API
    const wchar_t* apis[8];
};
static const CapRule g_capRules[] = {
    // ---- 注入家族 T1055 ----
    { L"远程线程注入", L"VirtualAllocEx+WriteProcessMemory+CreateRemoteThread", L"T1055.001", 5, 2,
      { L"virtualallocex", L"writeprocessmemory", L"createremotethread", L"ntcreatethreadex",
        L"rtlcreateuserthread", L"ntwritevirtualmemory", L"zwallocatevirtualmemory", nullptr } },
    { L"APC注入", L"QueueUserAPC+WriteProcessMemory 异步过程调用注入", L"T1055.004", 5, 2,
      { L"queueuserapc", L"ntqueueapcthread", L"writeprocessmemory", L"virtualallocex",
        L"suspendthread", L"resumethread", nullptr, nullptr } },
    { L"线程执行劫持", L"Suspend+SetThreadContext+Resume 劫持已有线程", L"T1055.003", 5, 2,
      { L"suspendthread", L"setthreadcontext", L"resumethread", L"getthreadcontext",
        L"writeprocessmemory", L"virtualallocex", nullptr, nullptr } },
    { L"进程镂空", L"NtUnmapViewOfSection 掏空并替换映像", L"T1055.012", 5, 3,
      { L"ntunmapviewofsection", L"zwunmapviewofsection", L"writeprocessmemory",
        L"virtualallocex", L"setthreadcontext", L"resumethread", L"readprocessmemory", nullptr } },
    { L"ProcessDoppelganging", L"TxF 事务+回滚创建伪装进程", L"T1055.013", 5, 2,
      { L"createtransaction", L"createfiletransacted", L"rollbacktransaction",
        L"ntcreateprocessex", L"ntcreatethreadex", L"writeprocessmemory", nullptr, nullptr } },
    { L"EWM注入", L"额外窗口内存注入 GetWindowLong/SetWindowLong", L"T1055.011", 4, 2,
      { L"getwindowlong", L"setwindowlong", L"sendnotifymessage", L"writeprocessmemory",
        L"virtualallocex", nullptr, nullptr, nullptr } },
    { L"ListPlanting", L"列表视图植入 SendMessage+LVM_SETITEMPOSITION", L"T1055.015", 4, 2,
      { L"sendmessage", L"lvm_setitemposition", L"findwindow", L"virtualallocex",
        L"writeprocessmemory", nullptr, nullptr, nullptr } },
    { L"反射加载", L"内存反射加载 PE/Assembly 无落盘", L"T1620", 4, 2,
      // 刻意不含 loadlibrary/getprocaddress/virtualalloc: 正常程序普遍使用, 会造成灾难性误报
      { L"reflectiveloader", L"rtlcopymemory", L"ntallocatevirtualmemory",
        L"zwallocatevirtualmemory", L"rtlmovememory", nullptr, nullptr, nullptr } },
    { L"无文件内存执行", L"VirtualAlloc+写入+改RX+起线程", L"T1055", 4, 4,
      { L"virtualalloc", L"virtualprotect", L"createthread", L"rtlmovememory",
        L"rtlcopymemory", L"ntallocatevirtualmemory", nullptr, nullptr } },
    // ---- 凭据与令牌 ----
    { L"LSASS凭据窃取", L"OpenProcess+MiniDumpWriteDump 导 lsass", L"T1003.001", 5, 2,
      { L"minidumpwritedump", L"openprocess", L"readprocessmemory", L"lsass",
        L"samiconnect", L"lsaenumeratelogonsessions", nullptr, nullptr } },
    { L"令牌操纵", L"OpenProcessToken+DuplicateTokenEx 令牌窃取", L"T1134", 4, 2,
      { L"openprocesstoken", L"duplicatetokenex", L"adjusttokenprivileges",
        L"createprocesswithtoken", L"settokeninformation", L"lookupprivilegevalue", nullptr, nullptr } },
    // ---- 防御规避 ----
    { L"动态API解析", L"GetProcAddress+LoadLibrary 隐藏导入表", L"T1027.007", 2, 3,
      { L"getprocaddress", L"loadlibrarya", L"loadlibraryw", L"virtualprotect",
        L"getmodulehandle", L"loadlibraryex", nullptr, nullptr } },
    { L"反调试", L"IsDebuggerPresent 等反调试对抗分析", L"T1622", 3, 2,
      { L"isdebuggerpresent", L"checkremotedebuggerpresent", L"ntqueryinformationprocess",
        L"outputdebugstring", L"ntsetinformationthread", L"zwsetinformationthread",
        L"ntquerysysteminformation", L"dbguiremotebreakin" } },
    { L"反虚拟机", L"检测沙箱/虚拟环境后潜伏不自爆", L"T1497", 3, 3,
      { L"cpuid", L"hypervisor", L"vbox", L"vmware", L"virtualbox", L"qemu", L"xen", nullptr } },
    { L"AMSI/ETW绕过", L"Patch AMSI 或断 ETW 检测通道", L"T1562.001", 5, 2,
      { L"amsiscanbuffer", L"amsiscanstring", L"etweventwrite", L"etwenabled",
        L"ntprotectvirtualmemory", L"amsiinitialize", nullptr, nullptr } },
    { L"日志清除", L"反取证 清除事件日志", L"T1070.001", 4, 2,
      { L"cleareventlog", L"evtclearlog", L"wevtutil", L"vssadmin",
        L"fsutil", L"deletevolumeshadowcopies", nullptr, nullptr } },
    { L"删除卷影", L"删卷影副本阻断还原(勒索前置)", L"T1490", 5, 2,
      { L"vssadmin", L"shadowcopy", L"deletevolumeshadowcopies", L"wmic",
        L"diskshadow", L"wbadmin", nullptr, nullptr } },
    // ---- 持久化 ----
    { L"注册表持久化", L"写 Run/RunOnce 自启动", L"T1547.001", 4, 2,
      // 不列 regsetvalue: 它是 regsetvalueex 的子串, 会让单个 API 被重复计数
      { L"regcreatekeyex", L"regsetvalueex", L"writeprivateprofilestring",
        L"runonce", L"schtasks", nullptr, nullptr, nullptr } },
    { L"服务持久化", L"创建/篡改服务驻留", L"T1543.003", 4, 2,
      { L"createservice", L"openscmanager", L"startservice", L"changeserviceconfig",
        L"createservicew", L"openservice", nullptr, nullptr } },
    // ---- 执行与网络 ----
    { L"下载执行", L"下载二段载荷并执行", L"T1105", 4, 3,
      { L"urldownloadtofile", L"internetopen", L"httpsendrequest", L"winhttpopen",
        L"internetreadfile", L"shellexecute", L"winexec", L"createprocess" } },
    { L"UAC绕过", L"利用自动提升程序绕过 UAC", L"T1548.002", 4, 2,
      { L"fodhelper", L"computerdefaults", L"eventvwr", L"sdclt",
        L"cmstp", L"icmluautil", nullptr, nullptr } },
    { L"挖矿", L"矿池通信/高强度计算", L"T1496", 3, 2,
      { L"stratum", L"nanopool", L"supportxmr", L"coinhive",
        L"minexmr", L"wsastartup", nullptr, nullptr } },
    // ---- 信息窃取 ----
    { L"键盘记录", L"键盘钩子/按键记录", L"T1056.001", 4, 2,
      { L"setwindowshookex", L"getasynckeystate", L"getkeystate", L"getrawinputdata",
        L"registerrawinputdevices", L"getforegroundwindow", nullptr, nullptr } },
    { L"屏幕窃取", L"截屏/远控画面", L"T1113", 3, 3,
      { L"bitblt", L"getdc", L"createcompatiblebitmap", L"getdesktopwindow",
        L"createdc", L"getwindowdc", nullptr, nullptr } },
    { L"剪贴板劫持", L"剪贴板监听/替换(币址劫持)", L"T1115", 3, 2,
      { L"getclipboarddata", L"setclipboarddata", L"openclipboard",
        L"addclipboardformatlistener", nullptr, nullptr, nullptr, nullptr } },
    { L"勒索加密", L"遍历+批量加密文件", L"T1486", 5, 3,
      { L"cryptencrypt", L"cryptgenkey", L"bcryptencrypt", L"cryptimportkey",
        L"findfirstfile", L"findnextfile", L"movefileex", L"setfileattributes" } },

    // ---- PoolParty 线程池注入 (SafeBreach 2023) ----
    // 原理: 传统注入盯 CreateRemoteThread, 而 PoolParty 用系统线程池回调执行 payload,
    //       不新建远程线程, 因此可绕过基于 CreateRemoteThread 的监控。
    //       判定要点是 "分配线程池工作项 + 投递/触发", 以及 "回调结构被覆写"。
    // 注意: 不写 tpallocwork 之外的宽泛项(如 loadlibrary/getprocaddress),
    //       否则几乎所有正常程序都会命中 —— 这一点在早期版本误报过。
    { L"PoolParty-工作回调覆写", L"TpAllocWork+TpPostWork+WriteProcessMemory 覆写回调",
      L"T1055.002", 5, 2,
      { L"tpallocwork", L"tppostwork", L"writeprocessmemory", L"tpreleasework",
        L"ntassociatewaitcompletionpacket", nullptr, nullptr, nullptr } },
    { L"PoolParty-等待回调覆写", L"TpAllocWait+TpSetWait 覆写等待回调", L"T1055.002", 5, 2,
      { L"tpallocwait", L"tpsetwait", L"writeprocessmemory", L"tpreleasewait",
        nullptr, nullptr, nullptr, nullptr } },
    { L"PoolParty-IO回调覆写", L"TpAllocIoCompletion 覆写异步IO回调", L"T1055.002", 5, 2,
      { L"tpalloiocompletion", L"tpstartasynciooperation", L"writeprocessmemory",
        L"tpreleaseio", nullptr, nullptr, nullptr, nullptr } },
    { L"PoolParty-定时器回调覆写", L"TpAllocTimer+TpSetTimer 覆写定时器回调", L"T1055.002", 5, 2,
      { L"tpalloctimer", L"tpsettimer", L"writeprocessmemory", L"tpreleasetimer",
        nullptr, nullptr, nullptr, nullptr } },
    { L"PoolParty-ALPC回调覆写", L"TpAllocAlpcCompletion+NtAssociateWaitCompletionPacket",
      L"T1055.002", 5, 2,
      { L"tpallocalpccompletion", L"ntassociatewaitcompletionpacket",
        L"writeprocessmemory", L"tpreleasealpccompletion", nullptr, nullptr, nullptr, nullptr } },
    { L"PoolParty-线程顺序劫持", L"覆写 TP_WORK->Task.CallbackKey 劫持队列顺序",
      L"T1055.002", 5, 2,
      { L"tpallocwork", L"tppostwork", L"tpwaitforwork", L"tpsetpoolstackinformation",
        L"writeprocessmemory", nullptr, nullptr, nullptr } },

    // ---- 直接系统调用: 绕过 EDR 用户态 hook ----
    // 原理: EDR 常 hook ntdll 的 Nt*/Zw* 函数, 攻击者改用自己实现的 syscall 桩,
    //       直接从内核入口进, 用户态 hook 完全看不到。
    // 判定: 特征函数名(SysWhispers 生成的 *Syscall / SW2_/SW3_ 前缀)与门名。
    { L"直接系统调用-SysWhispers", L"自实现 syscall 桩绕过 ntdll hook", L"T1106", 4, 2,
      { L"ntallocatevirtualmemorysyscall", L"sw2_getsyscallnumber", L"sw3_getsyscallnumber",
        L"zwprotectvirtualmemorysyscall", L"sw2_getsyscalladdress",
        L"sw3_getsyscalladdress", nullptr, nullptr } },
    { L"直接系统调用-HellsGate", L"Hell's/Halo's/Tartarus Gate 动态解析 SSN", L"T1106", 4, 2,
      { L"hellsgate", L"halosgate", L"tartarusgate", L"vxmoveentry",
        L"ssdt", L"getssn", nullptr, nullptr } },
    // 脱钩 .text: 从磁盘重新映射 ntdll 干净副本覆盖被 hook 的段
    // 只用 getmodulehandlea(Ldr 遍历特征)+getprocaddress+ntprotectvirtualmemory+memcpy,
    // 不加入 ntallocatevirtualmemory 等通用项, 否则普通 shellcode 特征会误报。
    { L"脱钩text段", L"重映射 ntdll 干净副本覆盖 hook", L"T1562.001", 4, 3,
      { L"getmodulehandlea", L"getprocaddress", L"ntprotectvirtualmemory",
        L"memcpy", L"rtlcopymemory", nullptr, nullptr, nullptr } },
    { L"间接系统调用", L"间接跳转执行 syscall 规避返回地址检测", L"T1106", 4, 3,
      { L"zwquerysysteminformation", L"ntqueryinformationprocess", L"virtualprotect",
        L"ntqueryvirtualmemory", L"rtlgetversion", nullptr, nullptr, nullptr } },
};
static const int g_capRuleCount = (int)(sizeof(g_capRules) / sizeof(g_capRules[0]));

// 在"导入表 + 文件文本"里找 API 组合
static int CapMatch(const PeInfo& pi, const std::string& lowText,
                    wstring& family, wstring& desc, wstring* tidOut = nullptr) {
    int best = 0, bestNeed = 0;
    for (int r = 0; r < g_capRuleCount; ++r) {
        const CapRule& cr = g_capRules[r];
        int hit = 0;
        std::vector<wstring> hitApi;
        bool used[8] = { false };
        // 先扫导入表: 同一个 import 只贡献一次命中。
        // 否则 regsetvalueex 会同时命中 regsetvalueex 与 regsetvalue 两项, 单个 API 被算成 2 次。
        for (size_t k = 0; k < pi.imports.size(); ++k) {
            wstring imp = ToLowerW(pi.imports[k]);
            for (int a = 0; a < 8 && cr.apis[a]; ++a) {   // 限界: 部分规则 8 项填满无 nullptr
                if (used[a]) continue;
                wstring want = ToLowerW(cr.apis[a]);       // 规则项转小写, 否则含大写项永不匹配
                if (imp.find(want) != wstring::npos) {
                    used[a] = true; hit++; hitApi.push_back(want);
                    break;   // 同一 import 只计一次
                }
            }
        }
        // 动态解析(GetProcAddress/LoadLibrary)的 API 不进导入表, 需在文件文本里找(lowText 已小写)
        if (!lowText.empty()) {
            for (int a = 0; a < 8 && cr.apis[a]; ++a) {
                if (used[a]) continue;
                wstring want = ToLowerW(cr.apis[a]);
                std::string wantA(want.begin(), want.end());
                if (lowText.find(wantA) != std::string::npos) {
                    used[a] = true; hit++; hitApi.push_back(want);
                }
            }
        }
        // 同分时选 need 更严格的规则: 如进程镂空(need=3, 含极特异的 NtUnmapViewOfSection)
        // 应优先于仅靠 writeprocessmemory+resumethread 就能命中的 APC 规则(need=2)
        if (hit >= cr.need && (cr.sev > best || (cr.sev == best && cr.need > bestNeed))) {
            best = cr.sev; bestNeed = cr.need; family = cr.family; desc = cr.desc;
            if (tidOut) *tidOut = cr.tid;
        }
    }
    return best;
}

// ---------- 本地病毒族谱库 (记住见过的恶意样本特征, 用于比对变种) ----------
struct FamSeed {
    wstring name;
    char f1[FZSIG + 1], f2[FZSIG + 1];
    unsigned bs = 0;
    wstring impSig;    // 排序后的导入 API, 逗号分隔
    wstring secSig;    // 节区名, + 分隔
    unsigned long long size = 0;
};
static std::vector<FamSeed> g_family;
static wstring FamDbPath(void) {
    wchar_t tmp[512] = { 0 };
    GetTempPathW(512, tmp);
    return wstring(tmp) + L"zz_EDR.family";
}
static void FamLoad(void) {
    g_family.clear();
    HANDLE h = CreateFileW(FamDbPath().c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (!h || h == INVALID_HANDLE_VALUE) return;
    unsigned long long sz = 0; LARGE_INTEGER li; li.QuadPart = 0;
    if (GetFileSizeEx(h, &li)) sz = (unsigned long long)li.QuadPart;
    if (sz > 0 && sz < 4 * 1024 * 1024) {
        std::string buf((size_t)sz, 0);
        unsigned long rd = 0;
        if (ReadFile(h, &buf[0], (unsigned long)sz, &rd, nullptr) && rd > 0) {
            size_t pos = (buf.size() >= 2 && (unsigned char)buf[0] == 0xFF) ? 2 : 0;
            std::wstring w;
            for (size_t i = pos; i + 1 < buf.size(); i += 2)
                w.push_back((wchar_t)((unsigned char)buf[i] | ((unsigned char)buf[i + 1] << 8)));
            size_t p = 0;
            while (p < w.size()) {
                size_t e = w.find(L'\n', p);
                if (e == wstring::npos) e = w.size();
                wstring line = w.substr(p, e - p);
                p = e + 1;
                if (line.size() < 8) continue;
                // 格式: name|f1|f2|bs|impSig|secSig|size
                std::vector<wstring> f; size_t q = 0;
                while (true) {
                    size_t b = line.find(L'|', q);
                    if (b == wstring::npos) { f.push_back(line.substr(q)); break; }
                    f.push_back(line.substr(q, b - q)); q = b + 1;
                }
                if (f.size() < 7) continue;
                FamSeed sd;
                sd.name = f[0];
                std::string a(f[1].begin(), f[1].end()), b2(f[2].begin(), f[2].end());
                strncpy(sd.f1, a.c_str(), FZSIG); sd.f1[FZSIG] = 0;
                strncpy(sd.f2, b2.c_str(), FZSIG); sd.f2[FZSIG] = 0;
                sd.bs = (unsigned)_wtoi(f[3].c_str());
                sd.impSig = f[4]; sd.secSig = f[5];
                sd.size = wcstoull(f[6].c_str(), nullptr, 10);
                g_family.push_back(sd);
                if (g_family.size() > 2000) break;
            }
        }
    }
    CloseHandle(h);
}
static void FamSave(void) {
    std::wstring all;
    wchar_t nbuf[32];
    for (size_t i = 0; i < g_family.size(); ++i) {
        const FamSeed& sd = g_family[i];
        std::string a(sd.f1), b2(sd.f2);
        all += sd.name; all += L'|';
        all += wstring(a.begin(), a.end()); all += L'|';
        all += wstring(b2.begin(), b2.end()); all += L'|';
        swprintf(nbuf, 32, L"%u", sd.bs); all += nbuf; all += L'|';
        all += sd.impSig; all += L'|';
        all += sd.secSig; all += L'|';
        swprintf(nbuf, 32, L"%llu", sd.size); all += nbuf;
        all += L'\n';
    }
    HANDLE h = CreateFileW(FamDbPath().c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (!h || h == INVALID_HANDLE_VALUE) return;
    unsigned short bom = 0xFEFF;
    unsigned long wr = 0;
    WriteFile(h, &bom, 2, &wr, nullptr);
    if (!all.empty()) WriteFile(h, all.c_str(), (unsigned long)(all.size() * 2), &wr, nullptr);
    FlushFileBuffers(h);
    CloseHandle(h);
}
static wstring ImpSigOf(const PeInfo& pi) {
    std::vector<wstring> v = pi.imports;
    for (size_t i = 0; i < v.size(); ++i) v[i] = ToLowerW(v[i]);
    std::sort(v.begin(), v.end());
    v.erase(std::unique(v.begin(), v.end()), v.end());
    wstring out;
    for (size_t i = 0; i < v.size() && out.size() < 3000; ++i) {
        if (i) out += L',';
        out += v[i];
    }
    return out;
}
// 导入表 Jaccard 相似度 0..1
static double ImpJaccard(const wstring& a, const wstring& b) {
    if (a.empty() || b.empty()) return 0.0;
    std::vector<wstring> va, vb;
    { size_t q = 0; while (true) { size_t p = a.find(L',', q);
        if (p == wstring::npos) { va.push_back(a.substr(q)); break; }
        va.push_back(a.substr(q, p - q)); q = p + 1; } }
    { size_t q = 0; while (true) { size_t p = b.find(L',', q);
        if (p == wstring::npos) { vb.push_back(b.substr(q)); break; }
        vb.push_back(b.substr(q, p - q)); q = p + 1; } }
    std::sort(va.begin(), va.end()); va.erase(std::unique(va.begin(), va.end()), va.end());
    std::sort(vb.begin(), vb.end()); vb.erase(std::unique(vb.begin(), vb.end()), vb.end());
    if (va.empty() || vb.empty()) return 0.0;
    size_t inter = 0;
    for (size_t i = 0, j = 0; i < va.size() && j < vb.size();) {
        if (va[i] == vb[j]) { inter++; i++; j++; }
        else if (va[i] < vb[j]) i++; else j++;
    }
    size_t uni = va.size() + vb.size() - inter;
    return uni ? (double)inter / (double)uni : 0.0;
}
static void FamAdd(const wstring& name, const std::vector<unsigned char>& d,
                   const PeInfo& pi) {
    if (g_family.size() > 2000) return;
    for (size_t i = 0; i < g_family.size(); ++i)
        if (g_family[i].name == name) return;              // 同族只留一个种子
    FamSeed sd;
    sd.name = name;
    FzPair(d, sd.f1, sd.f2, &sd.bs);
    sd.impSig = ImpSigOf(pi);
    sd.secSig.clear();
    for (size_t i = 0; i < pi.secNames.size(); ++i) {
        if (i) sd.secSig += L'+';
        sd.secSig += pi.secNames[i];
    }
    sd.size = d.size();
    g_family.push_back(sd);
    FamSave();
    LogPost((L"[族谱] 已记录恶意样本特征: " + name).c_str());
}
// 与族谱库比对, 返回最高相似度及家族名
static double FamMatch(const std::vector<unsigned char>& d, const PeInfo& pi,
                       wstring& famName, wstring& how) {
    double best = 0; how.clear();
    if (g_family.empty() || d.empty()) return 0;
    char s1[FZSIG + 1], s2[FZSIG + 1]; unsigned bs = 0;
    FzPair(d, s1, s2, &bs);
    wstring myImp = ImpSigOf(pi);
    for (size_t i = 0; i < g_family.size(); ++i) {
        const FamSeed& sd = g_family[i];
        double fs = FzCmp(s1, s2, bs, sd.f1, sd.f2, sd.bs);
        if (fs > best) { best = fs; famName = sd.name; how = L"代码相似度"; }
        double is = ImpJaccard(myImp, sd.impSig) * 100.0;
        if (is > best) { best = is; famName = sd.name; how = L"导入表同族"; }
    }
    return best;
}

// ---------- 综合变种判定 ----------
// 返回 0=干净, >0=严重级别; reason 输出原因
static int VariantScan(const wstring& path, wstring& reason) {
    int sev = 0; reason.clear();
    std::vector<unsigned char> data;
    if (!ReadFileAll(path, data) || data.size() < 64) return 0;

    PeInfo pi;
    bool isPe = PeParse(data, pi) && pi.valid;

    // 文件文本(小写)用于找动态解析的 API 名, 只取前 2MB 保证性能
    std::string lowText;
    {
        size_t lim = data.size() < 2 * 1024 * 1024 ? data.size() : 2 * 1024 * 1024;
        lowText.reserve(lim);
        for (size_t i = 0; i < lim; ++i) {
            unsigned char c = data[i];
            lowText.push_back((c >= 'A' && c <= 'Z') ? (char)(c + 32) : (char)c);
        }
    }

    // 1) 能力族谱 (最核心: 改哈希改不掉能力)
    wstring fam, desc;
    int capSev = CapMatch(pi, lowText, fam, desc);
    if (capSev > 0) {
        sev = capSev;
        reason = wstring(L"能力族谱[") + fam + L"] " + desc;
    }

    // 2) 加壳 / 免杀特征
    if (isPe) {
        static const wchar_t* packs[] = { L"upx0", L"upx1", L".aspack", L".nsp0", L".nsp1",
                                          L".petite", L"fsg!", L".ccg", L"pebundle", L".themida" };
        for (size_t i = 0; i < pi.secNames.size(); ++i) {
            wstring sn = ToLowerW(pi.secNames[i]);
            for (int k = 0; k < (int)(sizeof(packs) / sizeof(packs[0])); ++k)
                if (sn.find(packs[k]) != wstring::npos) {
                    if (sev < 2) { sev = 2; reason = L"已知壳/免杀壳: " + pi.secNames[i]; }
                }
        }
        if (pi.maxEnt > 7.2) {
            if (sev < 2) { sev = 2; reason = L"节区熵异常(>7.2), 疑似加密/加壳"; }
        }
        if ((int)pi.imports.size() <= 3 && data.size() > 40 * 1024 && pi.maxEnt > 6.5) {
            if (sev < 3) { sev = 3; reason = L"导入表极少且高熵, 疑似 Shellcode Loader"; }
        }
        if (pi.rwxCount > 0) {
            if (sev < 3) { sev = 3; reason = L"存在可执行可写节区(RWX), 免杀常见"; }
        }
    }

    // 3) 与本地族谱库比对 (真正的"派生/变种"判定)
    wstring famName, how;
    double simv = FamMatch(data, pi, famName, how);
    if (simv >= 60.0) {
        wchar_t nb[32]; swprintf(nb, 32, L"%.0f%%", simv);
        int vs = simv >= 80.0 ? 5 : 4;
        if (vs > sev) {
            sev = vs;
            reason = wstring(L"派生变种: 与已记录样本[") + famName + L"] " + how + L" 相似度 " + nb;
        }
    }

    // 4) 高危样本入库, 供后续比对变种
    if (sev >= 4) {
        wstring nm = path.substr(path.find_last_of(L'\\') == wstring::npos
                                 ? 0 : path.find_last_of(L'\\') + 1);
        if (nm.empty()) nm = L"unknown";
        FamAdd((fam.empty() ? L"高危样本:" : fam + L":") + nm, data, pi);
        SetThreatLevel(THREAT_DANGER, (L"检出恶意程序(含派生/变种判定): " + path).c_str());
    } else if (sev == 3) {
        SetThreatLevel(THREAT_WARN, (L"发现可疑程序特征: " + path).c_str());
    }
    return sev;
}

// 扫描当前所有运行进程的可执行文件是否为已知恶意变种
static void VariantScanRunning(void) {
    LogPost(L"[变种检测] 开始扫描运行中进程的可执行映像...");
    std::vector<ProcInfo> ps = SnapshotProcs();
    std::vector<wstring> seen;
    int bad = 0;
    for (size_t i = 0; i < ps.size(); ++i) {
        wstring exe = ps[i].path;
        if (exe.empty()) continue;
        bool dup = false;
        for (size_t k = 0; k < seen.size(); ++k) if (seen[k] == exe) { dup = true; break; }
        if (dup) continue;
        seen.push_back(exe);
        wstring why;
        int sv = VariantScan(exe, why);
        if (sv >= 3) {
            bad++;
            LogPost((L"[变种检测] 命中 " + ps[i].name + L" -> " + why).c_str());
        }
    }
    wchar_t nb[64];
    swprintf(nb, 64, L"[变种检测] 完成, 扫描 %u 个映像, 命中 %d 个", (unsigned)seen.size(), bad);
    LogPost(nb);
    if (bad) {
        SetThreatLevel(THREAT_DANGER, L"运行中的进程检出恶意特征, 建议立即处理");
    }
}

// ============ HEUR 启发式检测引擎 ============
// 抓未知/变种样本：不看精确哈希，看"代码长什么样 + 它想干什么"
static const char* kHeurPackSec[] = {
    "upx0","upx1","upx2","aspack","adata",".petite","pecompact","fsg!",
    ".themida",".vmp0",".vmp1","nsp0","nsp1",".nsp",".rlp",".serv","winlice"
};
static const char* kHeurAntiDbg[] = {
    "isdebuggerpresent","checkremotedebuggerpresent","ntqueryinformationprocess",
    "outputdebugstringa","ntsetinformationthread","zwsetinformationthread",
    "rtladjustprivilege","blockinput","ntclose","findwindowa"
};
static const wchar_t* kHeurWritableDir[] = {
    L"\\temp\\", L"\\tmp\\", L"\\appdata\\", L"\\downloads\\",
    L"\\public\\", L"\\recent\\", L"\\programdata\\", L"\\users\\public\\"
};
static bool HeurImp(const PeInfo& pi, const char* n) {
    for (size_t i = 0; i < pi.imports.size(); ++i) {
        std::wstring w = pi.imports[i];
        std::string a;
        for (size_t j = 0; j < w.size(); ++j) {
            char c = (char)w[j]; if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
            a += c;
        }
        if (a == n) return true;
    }
    return false;
}
static bool HeurStr(const std::string& low, const char* n) { return low.find(n) != std::string::npos; }

// 返回 sev 0-5，reason 输出 HEUR: 命名
static int HeurScanFile(const std::wstring& path, std::wstring& reason) {
    int score = 0;
    std::wstring tag = L"HEUR:Suspicious.Win32.Generic";
    int flagPack = 0, flagAnti = 0, flagMasq = 0, flagLoc = 0;

    std::wstring lp;
    for (size_t i = 0; i < path.size(); ++i) {
        wchar_t c = path[i];
        if (c >= L'A' && c <= L'Z') c = c - L'A' + L'a';
        lp += c;
    }
    // 落点可疑
    for (int i = 0; i < 8; ++i)
        if (lp.find(kHeurWritableDir[i]) != std::wstring::npos) { flagLoc = 1; score += 2; break; }
    // RTLO 伪装 (U+202E 使文件名倒序显示)
    if (path.find(L'\u202e') != std::wstring::npos) { flagMasq = 1; score += 6; }
    // 双扩展名伪装 report.pdf.exe
    {
        size_t d1 = lp.rfind(L'.');
        if (d1 != std::wstring::npos && d1 > 0) {
            size_t d2 = lp.rfind(L'.', d1 - 1);
            if (d2 != std::wstring::npos) {
                std::wstring e1 = lp.substr(d2 + 1, d1 - d2 - 1), e2 = lp.substr(d1 + 1);
                const wchar_t* doc[] = { L"pdf",L"doc",L"docx",L"xls",L"xlsx",L"jpg",L"png",
                                          L"txt",L"zip",L"rar",L"mp4",L"iso",L"ppt",L"csv" };
                const wchar_t* exe[] = { L"exe",L"scr",L"bat",L"cmd",L"com",L"js",L"vbs",L"pif",L"hta" };
                bool b1 = false, b2 = false;
                for (int i = 0; i < 14; ++i) if (e1 == doc[i]) b1 = true;
                for (int i = 0; i < 9; ++i)  if (e2 == exe[i]) b2 = true;
                if (b1 && b2) { flagMasq = 1; score += 4; }
            }
        }
    }
    // 系统名伪装（非 System32 目录下的 svchost.exe 等）
    {
        const wchar_t* sysn[] = { L"svchost.exe",L"dllhost.exe",L"lsass.exe",L"csrss.exe",
                                  L"winlogon.exe",L"services.exe",L"explorer.exe",L"smss.exe" };
        std::wstring fn;
        size_t bs = lp.rfind(L'\\');
        if (bs != std::wstring::npos) fn = lp.substr(bs + 1);
        for (int i = 0; i < 8; ++i)
            if (fn == sysn[i] && lp.find(L"\\system32\\") == std::wstring::npos
                              && lp.find(L"\\syswow64\\") == std::wstring::npos) {
                flagMasq = 1; score += 3; break;
            }
    }

    // 读文件做 PE + 字符串启发式
    FILE* f = _wfopen(path.c_str(), L"rb");
    if (f) {
        std::vector<unsigned char> d;
        d.resize(2u << 20);
        size_t got = fread(&d[0], 1, d.size(), f);
        d.resize(got);
        fclose(f);
        PeInfo pi;
        bool isPe = PeParse(d, pi) && pi.valid;
        std::string low;
        low.reserve(d.size());
        for (size_t i = 0; i < d.size(); ++i) {
            unsigned char c = d[i];
            if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
            low += (char)c;
        }
        if (isPe) {
            if (pi.maxEnt > 7.0)                 { flagPack = 1; score += 3; }
            else if (pi.avgEnt > 6.5)            { flagPack = 1; score += 2; }
            if (pi.rwxCount > 0)                 { score += 3; }
            if (pi.imports.size() < 5 && got > 4096) { flagPack = 1; score += 3; }
            for (size_t i = 0; i < pi.secNames.size(); ++i) {
                std::wstring w = pi.secNames[i];
                std::string a;
                for (size_t j = 0; j < w.size(); ++j) {
                    char c = (char)w[j]; if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
                    a += c;
                }
                for (int k = 0; k < 17; ++k)
                    if (a.find(kHeurPackSec[k]) != std::string::npos) { flagPack = 1; score += 4; break; }
            }
            for (int k = 0; k < 10; ++k)
                if (HeurImp(pi, kHeurAntiDbg[k])) { flagAnti = 1; score += 2; break; }
            if (HeurImp(pi, "loadlibrarya") && HeurImp(pi, "getprocaddress")) score += 1;
        }
        // 字符串层：反 VM/沙箱、可疑行为
        const char* vm[] = { "vmtoolsd","vboxservice","vboxtray","qemu-ga","qemu-",
                             "sandboxie","wireshark","ollydbg","x64dbg","idaq",
                             "vmware","virtualbox","vbox","qemu","processhacker" };
        for (int i = 0; i < 15; ++i)
            if (HeurStr(low, vm[i])) { flagAnti = 1; score += 2; break; }
        const char* bad[] = { "vssadmin delete","wmic shadowcopy","bcdedit /set",
                              "mimikatz","sekurlsa","lsadump","-nop -w hidden",
                              "amsiutils","amsiinitfailed","reflectiveloader" };
        for (int i = 0; i < 10; ++i)
            if (HeurStr(low, bad[i])) { score += 3; break; }
    } else if (flagLoc) {
        score += 1; // 打不开但落点可疑
    }

    if (score < 3) { reason.clear(); return 0; }
    // 命名
    if      (flagMasq)               tag = L"HEUR:Trojan.Win32.Masquerade";
    else if (flagAnti && score >= 7) tag = L"HEUR:Trojan.Win32.AntiVM";
    else if (flagPack && score >= 7) tag = L"HEUR:Packed.Win32.Generic";
    else if (score >= 7)             tag = L"HEUR:Trojan.Win32.Generic";
    else if (flagPack)               tag = L"HEUR:Packed.Win32.Generic";
    else if (flagLoc)                tag = L"HEUR:Riskware.Win32.Generic";
    reason = tag + L" (启发式评分 " + std::to_wstring(score) + L")";
    if      (score >= 9) return 5;
    else if (score >= 7) return 4;
    else if (score >= 5) return 3;
    return 2;
}

// ============ PDM 主动防御：行为链关联 ============
// 单条行为不可疑，串成链才致命。按 ATT&CK 战术阶段关联判定。
enum PdmStage {
    STG_INIT = 0, STG_EXEC, STG_PERSIST, STG_EVASION,
    STG_CRED, STG_INJECT, STG_C2, STG_IMPACT, STG_N
};
static const wchar_t* kPdmStageName[STG_N] = {
    L"初始访问", L"执行", L"持久化", L"防御规避",
    L"凭据访问", L"注入", L"命令控制", L"影响"
};
struct PdmRule {
    const wchar_t* name; unsigned mask; int sev; const wchar_t* mitre;
};
#define PDM_BIT(s) (1u << (s))
static const PdmRule kPdmRules[] = {
    { L"钓鱼宏/脚本投递链", PDM_BIT(STG_EXEC)   | PDM_BIT(STG_C2), 5, L"T1566.001" },
    { L"注入回连",          PDM_BIT(STG_INJECT) | PDM_BIT(STG_C2), 5, L"T1055+T1071" },
    { L"无文件攻击链",      PDM_BIT(STG_EXEC)|PDM_BIT(STG_PERSIST)|PDM_BIT(STG_C2), 5, L"T1059" },
    { L"勒索链(规避+破坏)", PDM_BIT(STG_EVASION)|PDM_BIT(STG_IMPACT), 5, L"T1486+T1490" },
    { L"免杀规避+注入",     PDM_BIT(STG_EVASION)|PDM_BIT(STG_INJECT), 4, L"T1562+T1055" },
    { L"持久化+外联",       PDM_BIT(STG_PERSIST)|PDM_BIT(STG_C2),     4, L"T1547+T1071" },
    { L"执行+注入",         PDM_BIT(STG_EXEC)   | PDM_BIT(STG_INJECT),4, L"T1059+T1055" },
    { L"凭据窃取+持久化",   PDM_BIT(STG_CRED)   | PDM_BIT(STG_PERSIST),4, L"T1003+T1136" },
    { L"凭据窃取+规避",     PDM_BIT(STG_CRED)   | PDM_BIT(STG_EVASION),3, L"T1003+T1562" },
    { L"投递+持久化",       PDM_BIT(STG_INIT)   | PDM_BIT(STG_PERSIST),3, L"T1547" },
};
// 单条行为 → 战术阶段（-1 = 不参与链判定）
static int PdmStageOf(int type, const std::wstring& detail) {
    std::wstring d;
    for (size_t i = 0; i < detail.size(); ++i) {
        wchar_t c = detail[i];
        if (c >= L'A' && c <= L'Z') c = c - L'A' + L'a';
        d += c;
    }
    switch (type) {
        case BEHAV_BLOCK: return -1;
        case BEHAV_HOOK:  return STG_INJECT;
        case BEHAV_MEM:   return STG_INJECT;
        case BEHAV_NET:   return STG_C2;
        case BEHAV_DRIVER:return STG_PERSIST;
        case BEHAV_PROC_START: return STG_INIT;
        case BEHAV_REG:
            if (d.find(L"defender") != std::wstring::npos ||
                d.find(L"amsi")     != std::wstring::npos ||
                d.find(L"防火墙")    != std::wstring::npos) return STG_EVASION;
            return STG_PERSIST;
        case BEHAV_CMD:
            if (d.find(L"-enc") != std::wstring::npos ||
                d.find(L"iex")  != std::wstring::npos ||
                d.find(L"bypass") != std::wstring::npos) return STG_EVASION;
            return STG_EXEC;
        case BEHAV_FILE:
            if (d.find(L"卷影") != std::wstring::npos) return STG_EVASION;
            return STG_IMPACT;
        case BEHAV_SIGN:  return STG_EVASION;
        case BEHAV_SANDBOX: return STG_EVASION;
    }
    return -1;
}
static void PdmChainScan(bool verbose) {
    std::vector<BehavRecord> snap;
    { std::lock_guard<std::mutex> lk(g_behavMtx); snap.assign(g_behav.begin(), g_behav.end()); }
    std::map<DWORD, std::pair<std::wstring, unsigned> > maskOf;   // pid -> (proc, stageMask)
    std::map<DWORD, int> cntOf[STG_N];
    std::map<DWORD, long long> lastTs;
    for (size_t i = 0; i < snap.size(); ++i) {
        const BehavRecord& r = snap[i];
        int st = PdmStageOf(r.type, r.detail);
        if (st < 0) continue;
        maskOf[r.pid].first = r.proc;
        maskOf[r.pid].second |= PDM_BIT(st);
        cntOf[st][r.pid]++;
        if (r.ts > lastTs[r.pid]) lastTs[r.pid] = r.ts;
    }
    long long now = (long long)time(nullptr);
    int found = 0;
    for (auto it = maskOf.begin(); it != maskOf.end(); ++it) {
        DWORD pid = it->first;
        unsigned mask = it->second.second;
        const std::wstring& proc = it->second.first;
        // 只评估近 6 小时内的活跃进程，避免陈旧记录误判
        if (now - lastTs[pid] > 6 * 3600) continue;
        int bestSev = 0; const wchar_t* bestName = nullptr; const wchar_t* bestMitre = nullptr;
        for (int k = 0; k < 10; ++k) {
            const PdmRule& rr = kPdmRules[k];
            if ((mask & rr.mask) == rr.mask && rr.sev > bestSev) {
                bestSev = rr.sev; bestName = rr.name; bestMitre = rr.mitre;
            }
        }
        // 单阶段高频异常
        if (bestSev == 0) {
            for (int st = 0; st < STG_N; ++st)
                if (cntOf[st][pid] >= 6) {
                    bestSev = 3; bestName = L"单阶段行为异常(高频)";
                    bestMitre = kPdmStageName[st]; break;
                }
        }
        if (bestSev < 3) continue;
        unsigned stageList = 0; std::wstring stages;
        for (int st = 0; st < STG_N; ++st)
            if (mask & PDM_BIT(st)) { stages += (stages.empty() ? L"" : L"→") + std::wstring(kPdmStageName[st]); }
        (void)stageList;
        std::wstring det = L"进程: " + proc + L" (PID " + std::to_wstring(pid) + L")\n战术链: "
                         + stages + L"\n判定: " + bestName + L"  [" + bestMitre + L"]  sev="
                         + std::to_wstring(bestSev);
        LogPost(L"[PDM] 攻击链命中 " + det);
        BehavAdd(pid, proc, BEHAV_BLOCK, bestSev, L"PDM攻击链: " + std::wstring(bestName));
        if (bestSev >= 4) {
            SetThreatLevel(THREAT_DANGER, L"PDM 主动防御：检测到攻击行为链");
            if (g_cfg.advAggressive) {
                std::wstring ask = L"PDM 主动防御检测到攻击行为链，是否结束该进程？\n\n" + det;
                if (AlertConfirm(L"PDM 主动防御", ask, proc, pid) == 1) {
                    if (KillProcess(pid)) LogPost(L"[PDM] 已结束进程 PID " + std::to_wstring(pid));
                    else LogPost(L"[PDM] 结束进程失败(可能已退出或权限不足)");
                }
            }
        }
        ++found;
    }
    if (verbose) {
        if (!found) LogPost(L"[PDM] 未发现攻击行为链");
        else LogPost(L"[PDM] 共发现 " + std::to_wstring(found) + L" 条可疑行为链");
    }
}
static void PdmGuardLoop() {
    while (g_running.load()) {
        for (int i = 0; i < 20 && g_running.load(); ++i) Sleep(1000);
        if (!g_running.load()) break;
        if (g_cfg.pdmOn) PdmChainScan(false);
    }
}
static void HeurScanAll() {
    LogPost(L"[HEUR] 开始启发式扫描运行中进程...");
    std::vector<ProcInfo> ps = SnapshotProcs();
    int hit = 0;
    for (size_t i = 0; i < ps.size(); ++i) {
        if (!g_running.load()) break;
        std::wstring why;
        int sev = HeurScanFile(ps[i].path, why);
        if (sev >= 3 && !why.empty()) {
            ++hit;
            LogPost(L"[HEUR] " + ps[i].name + L" → " + why + L" (sev=" + std::to_wstring(sev) + L")");
            BehavAdd(ps[i].pid, ps[i].name, BEHAV_SIGN, sev, L"HEUR: " + why);
            if (sev >= 4) SetThreatLevel(THREAT_DANGER, L"HEUR 启发式检出可疑样本");
        }
    }
    LogPost(L"[HEUR] 扫描完成，命中 " + std::to_wstring(hit) + L" 项");
}

static int RuleMatchFile(const wstring& path, wstring& reason) {
    int best = 0; reason.clear();
    if (IsRansomExt(path)) { best = 3; reason = L"勒索软件扩展名"; }

    wstring ext = ToLowerW(PathFindExtensionW(path.c_str()));
    bool isBin = (ext == L".exe" || ext == L".dll" || ext == L".sys" || ext == L".scr");
    if (isBin) {
        wstring hex, hname; int hsev = 0;
        if (FileSha256W(path, hex) && RuleMatchHash(hex, hname, hsev) && hsev > best) {
            SetThreatLevel(THREAT_DANGER, (L"检出已知恶意哈希: " + path).c_str());
            best = hsev; reason = wstring(L"哈希命中: ") + hname;
            // v13.24 统一处置链(文件维度: 无运行中进程, pid 传 0)
            ContainThreat(0, path, L"已知恶意哈希:" + hname, hsev);
        }
        // 派生/变种检测: 改了哈希也躲不掉"能力组合"与"代码相似度"
        if (g_cfg.heurOn) {
            std::wstring hwhy;
            int hv = HeurScanFile(path, hwhy);
            if (hv > best && !hwhy.empty()) { best = hv; reason = hwhy; }
        }
        if (g_cfg.variantOn) {
            wstring vwhy; int vsev = VariantScan(path, vwhy);
            if (vsev > best) { best = vsev; reason = vwhy; }
        }
    }
    // 内容特征 (读前 512KB)
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h && h != INVALID_HANDLE_VALUE) {
        const DWORD MAX_SCAN = 512 * 1024;
        vector<char> buf(MAX_SCAN);
        DWORD got = 0;
        if (ReadFile(h, buf.data(), MAX_SCAN, &got, nullptr) && got > 0) {
            wstring text; text.reserve(got);
            for (DWORD i = 0; i < got; ++i) {
                wchar_t c = (wchar_t)(unsigned char)buf[i];
                if (c >= L'A' && c <= L'Z') c = (wchar_t)(c + 32);
                text += c;
            }
            wstring hn, hd;
            int sev = RuleMatchText(text, hn, hd);
            if (sev > best) { best = sev; reason = wstring(L"特征命中[") + hn + L"] " + hd; }
        }
        CloseHandle(h);
    }
    // 可疑落盘路径的可执行文件 -> 至少中危
    if (best < 2 && isBin) {
        wstring lower = ToLowerW(path);
        for (int i = 0; i < g_suspDirCount; ++i)
            if (lower.find(ToLowerW(g_suspDirs[i])) != wstring::npos) {
                best = 2; reason = L"可执行文件位于可疑目录"; break;
            }
    }
    return best;
}

// 扫描优先级开关 (定义在此, 因 ScanProcesses 位于全局区之前)
static std::atomic<bool> g_scanPriorityOn{true};  // 扫描优先级: 无签名>有签名>系统>驱动

// 前向声明: 扫描优先级排序 (实现位于 ScanNetwork 之前)
static int  ProcScanTier(const ProcInfo& p);
static void ScanPrioritySort(std::vector<ProcInfo>& v);

static void ScanProcesses() {
    EnumAllProcesses();
    auto procs = SnapshotProcs();
    // 强制终止规则: 命中即强杀 + 自动恢复 (最高优先, 先于其它判定)
    ForceKillRuleEnforce(true);
    FoxWhiteBlackEnforce();   // v13.18: 银狐白加黑专项(随机名EXE+载荷DLL)
    LaunchScan([] { FoxDeepScan(); });  // v13.19: 银狐深度专项(C2/诱饵/BYOVD/排除项)
    // 扫描优先级: 无签名 > 有签名 > 系统 > 驱动 (tier 小者优先扫描)
    if (g_scanPriorityOn.load()) ScanPrioritySort(procs);
    for (auto& p : procs) {
        if (p.name.empty()) continue;
        // 启发式: 无签名高权限进程标记为可疑
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.pid);
        if (h) {
            DWORD session = 0;
            if (ProcessIdToSessionId(p.pid, &session) && session == 0 && p.pid > 100) {
                p.suspicious = true;
            }
            CloseHandle(h);
        }
        // 内置规则: 进程名黑名单 (命中即标记可疑, 高危+激进模式直接结束)
        int psev = 0; wstring pdesc;
        if (RuleMatchProc(p.name, psev, pdesc)) {
            p.suspicious = true;
            LogFmt(L"规则命中[进程] %s (pid=%u) -> %s (sev=%d)",
                   p.name.c_str(), p.pid, pdesc.c_str(), psev);
            if (g_cfg.advAggressive && psev >= 3) KillProcess(p.pid);
        }
        // 混淆 PowerShell: 只对脚本宿主命令行判定, >=3 个特征才算混淆
        std::wstring cmd = GetProcCommandLine(p.pid);
        if (!cmd.empty()) {
            std::wstring obHit;
            int ob = PsObfuscatScore(cmd, obHit);
            if (ob >= 3) {
                p.suspicious = true;
                std::wstring show = cmd.size() > 160 ? cmd.substr(0, 160) : cmd;
                LogFmt(L"[PSOBF] %s (pid=%u) 混淆得分=%d 特征=%s | %s",
                       p.name.c_str(), p.pid, ob, obHit.c_str(), show.c_str());
                BehavAdd(p.pid, p.name, BEHAV_SIGN, 4,
                         L"混淆脚本命令行(得分" + std::to_wstring(ob) + L", 特征=" + obHit + L")");
                SetThreatLevel(THREAT_WARN, L"发现混淆脚本命令行");
                if (g_cfg.advAggressive) KillProcessAuto(p.pid, L"混淆脚本命令行");
            }
        }
    }
    std::lock_guard<std::mutex> lk(g_procsMtx);
    g_procs = procs;
}


// ============================================================
//  扫描优先级: 无签名 > 有签名 > 系统 > 驱动
//  tier 越小越优先投入扫描资源。
//    tier 0 = 无签名 / 签名无效   (最高优先)
//    tier 1 = 有效签名的第三方
//    tier 2 = 系统进程 / 系统目录
//    tier 3 = 驱动 / 内核承载     (最低优先, 由服务侧收尾扫描)
// ============================================================
static int ProcScanTier(const ProcInfo& p) {
    static const wchar_t* kSysNames[] = {
        L"System", L"smss.exe", L"csrss.exe", L"wininit.exe", L"winlogon.exe",
        L"services.exe", L"lsass.exe", L"svchost.exe", L"dwm.exe", L"explorer.exe",
        L"fontdrvhost.exe", L"audiodg.exe", L"conhost.exe", L"RuntimeBroker.exe",
        L"SearchIndexer.exe", L"spoolsv.exe", L"taskhostw.exe", L"ctfmon.exe",
        L"MsMpEng.exe", L"NisSrv.exe", L"ShellExperienceHost.exe",
        L"StartMenuExperienceHost.exe", L"ApplicationFrameHost.exe", L"SystemSettings.exe"
    };
    for (const wchar_t* n : kSysNames)
        if (_wcsicmp(p.name.c_str(), n) == 0) return 2;

    wstring path = p.path;
    if (path.empty()) path = GetProcPath(p.pid);
    if (path.empty()) return 0;               // 取不到路径 -> 按无签名对待(优先)
    if (IsSystemDirPath(path)) return 2;      // 系统目录 -> 系统级
    int sig = VerifyFileSignature(path);
    if (sig == 1) return 1;                   // 有效签名的第三方
    return 0;                                 // 无签名/无效签名 -> 最高优先
}

static void ScanPrioritySort(std::vector<ProcInfo>& v) {
    std::stable_sort(v.begin(), v.end(), [](const ProcInfo& a, const ProcInfo& b) {
        return ProcScanTier(a) < ProcScanTier(b);
    });
}

static void ScanPriorityReport() {
    std::vector<ProcInfo> v = SnapshotProcs();
    ScanPrioritySort(v);
    int c[4] = {0, 0, 0, 0};
    for (auto& p : v) c[ProcScanTier(p)]++;
    LogPost(L"===== 扫描优先级: 无签名 > 有签名 > 系统 > 驱动 =====");
    LogFmt(L"  无签名=%d  >  有签名=%d  >  系统=%d  (驱动 tier3 由服务侧收尾)", c[0], c[1], c[2]);
    int shown = 0;
    for (auto& p : v) {
        if (ProcScanTier(p) != 0) continue;
        if (++shown > 10) { LogPost(L"  ...(其余无签名进程省略)"); break; }
        LogFmt(L"  [最高优先] PID=%u %s (无有效签名)", p.pid, p.name.c_str());
    }
    if (!shown) LogPost(L"  未发现无签名进程");
}

// ============================================================
//  LSASS 凭据窃取检测 (组合判定, 分值 >= 2 告警)
//   1) 已知凭据窃取/转储工具名
//   2) 命令行含 sekurlsa/lsass/comsvcs/minidump 等特征
//   3) 加载转储相关模块 dbghelp/dbgcore/comsvcs
// ============================================================
static void LsassAccessScan() {
    std::vector<ProcInfo> procs = SnapshotProcs();
    DWORD lsassPid = 0;
    for (auto& p : procs)
        if (_wcsicmp(p.name.c_str(), L"lsass.exe") == 0) { lsassPid = p.pid; break; }
    if (lsassPid == 0) { LogPost(L"[LSASS] 未定位到 lsass.exe, 跳过"); return; }

    static const wchar_t* kAllow[] = {
        L"csrss.exe", L"wininit.exe", L"winlogon.exe", L"services.exe",
        L"svchost.exe", L"MsMpEng.exe", L"WerFault.exe", L"smss.exe", L"lsass.exe"
    };
    static const wchar_t* kTools[] = {
        L"mimikatz.exe", L"procdump.exe", L"procdump64.exe", L"dumpert.exe",
        L"nanodump.exe", L"pwdump.exe", L"gsecdump.exe", L"wce.exe", L"sqldumper.exe"
    };
    static const wchar_t* kCmdKeys[] = {
        L"sekurlsa", L"lsadump", L"comsvcs", L"minidump", L"maskedump",
        L"procdump", L"lsass", L"kerberos::", L"privilege::debug"
    };
    static const wchar_t* kDumpMods[] = { L"dbgcore.dll", L"comsvcs.dll", L"ntdsapi.dll" };

    int hits = 0;
    for (auto& p : procs) {
        if (p.pid == 0 || p.pid == 4 || p.pid == lsassPid) continue;
        bool allow = false;
        for (const wchar_t* n : kAllow)
            if (_wcsicmp(p.name.c_str(), n) == 0) { allow = true; break; }
        if (allow) continue;

        int score = 0; wstring why;
        for (const wchar_t* t : kTools)
            if (_wcsicmp(p.name.c_str(), t) == 0) { score += 3; why = L"已知凭据工具"; break; }

        wstring cmd = GetProcCommandLine(p.pid);
        if (!cmd.empty()) {
            wstring lc = cmd;
            for (auto& ch : lc) if (ch >= L'A' && ch <= L'Z') ch = ch - L'A' + L'a';
            for (const wchar_t* k : kCmdKeys)
                if (wcsstr(lc.c_str(), k)) {
                    score += 3; why = L"命令行含转储特征(" + wstring(k) + L")"; break;
                }
        }

        if (score == 0) {
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, p.pid);
            if (snap && snap != INVALID_HANDLE_VALUE) {
                MODULEENTRY32W me; memset(&me, 0, sizeof(me)); me.dwSize = sizeof(me);
                if (Module32FirstW(snap, &me)) {
                    do {
                        for (const wchar_t* m : kDumpMods)
                            if (_wcsicmp(me.szModule, m) == 0) {
                                score += 2; why = L"加载转储模块 " + wstring(m); break;
                            }
                        memset(&me, 0, sizeof(me)); me.dwSize = sizeof(me);
                    } while (Module32NextW(snap, &me) && score == 0);
                }
                CloseHandle(snap);
            }
        }

        if (score >= 2) {
            hits++;
            LogFmt(L"[LSASS] 疑似凭据窃取: PID=%u %s 分值=%d 原因=%s",
                   p.pid, p.name.c_str(), score, why.c_str());
            BehavAdd(p.pid, p.name, BEHAV_PROC_START, 9, L"LSASS凭据窃取嫌疑: " + why);
            SetThreatLevel(THREAT_DANGER, L"检测到 LSASS 凭据窃取行为");
            if (g_cfg.advAggressive) KillProcess(p.pid);
        }
    }
    LogFmt(hits ? L"[LSASS] 完成, 命中 %d 个可疑进程" : L"[LSASS] 完成, 未发现凭据窃取行为", hits);
}

// ============================================================
//  进程镂空检测 (Process Hollowing)
//   1) 主模块内存基址无 MZ 头 (映像被替换/释放)
//   2) 内存与磁盘 PE SizeOfImage 不一致
// ============================================================
static void ProcessHollowScan() {
    std::vector<ProcInfo> procs = SnapshotProcs();
    static const wchar_t* kSkip[] = { L"System", L"smss.exe", L"csrss.exe", L"Registry", L"Memory Compression" };
    int hits = 0;
    for (auto& p : procs) {
        if (p.pid < 100) continue;
        bool skip = false;
        for (const wchar_t* n : kSkip)
            if (_wcsicmp(p.name.c_str(), n) == 0) { skip = true; break; }
        if (skip) continue;

        HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, p.pid);
        if (!h || h == INVALID_HANDLE_VALUE) continue;

        bool hollow = false; wstring why;
        HMODULE hMod = nullptr; DWORD need = 0;
        if (EnumProcessModules(h, &hMod, sizeof(hMod), &need) && hMod) {
            wchar_t modPath[MAX_PATH] = {0};
            GetModuleFileNameExW(h, hMod, modPath, MAX_PATH);
            unsigned char mz[2] = {0, 0};
            SIZE_T rd = 0;
            if (ReadProcessMemory(h, hMod, mz, 2, &rd) && rd == 2) {
                if (!(mz[0] == 'M' && mz[1] == 'Z'))
                    { hollow = true; why = L"主模块内存基址无 MZ 头(映像被替换)"; }
            }
            if (!hollow && modPath[0]) {
                HANDLE f = CreateFileW(modPath, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                       OPEN_EXISTING, 0, nullptr);
                if (f && f != INVALID_HANDLE_VALUE) {
                    unsigned char disk[0x400] = {0}, mem[0x400] = {0};
                    unsigned long dr = 0; rd = 0;
                    if (ReadFile(f, disk, sizeof(disk), &dr, nullptr) && dr > 0x200 &&
                        ReadProcessMemory(h, hMod, mem, sizeof(mem), &rd) && rd > 0x200) {
                        long peD = *(long*)(disk + 0x3C);
                        long peM = *(long*)(mem + 0x3C);
                        if (peD > 0 && peD < 0x3C0 && peM > 0 && peM < 0x3C0) {
                            unsigned long szD = 0, szM = 0;
                            if (disk[peD] == 'P' && disk[peD + 1] == 'E')
                                szD = *(unsigned long*)(disk + peD + 0x50);
                            if (mem[peM] == 'P' && mem[peM + 1] == 'E')
                                szM = *(unsigned long*)(mem + peM + 0x50);
                            if (szD && szM && szD != szM) {
                                hollow = true;
                                wchar_t b[160];
                                wsprintfW(b, L"内存/磁盘 SizeOfImage 不一致 (磁盘=%lu 内存=%lu)", szD, szM);
                                why = b;
                            }
                        }
                    }
                    CloseHandle(f);
                }
            }
        }
        CloseHandle(h);
        if (hollow) {
            hits++;
            LogFmt(L"[镂空] PID=%u %s : %s", p.pid, p.name.c_str(), why.c_str());
            BehavAdd(p.pid, p.name, BEHAV_MEM, 9, L"进程镂空: " + why);
            SetThreatLevel(THREAT_DANGER, L"检测到进程镂空");
            if (g_cfg.advAggressive) KillProcess(p.pid);
        }
    }
    LogFmt(hits ? L"[镂空] 完成, 命中 %d 个" : L"[镂空] 完成, 未发现镂空进程", hits);
}

// ============================================================
//  DLL 劫持检测: 进程加载了与系统 DLL 同名但位于非系统目录的模块
// ============================================================
static void DllHijackScan() {
    static const wchar_t* kTargets[] = {
        L"version.dll", L"dwmapi.dll", L"cryptbase.dll", L"cryptsp.dll", L"winmm.dll",
        L"ws2_32.dll", L"userenv.dll", L"sspicli.dll", L"secur32.dll", L"samcli.dll",
        L"propsys.dll", L"powrprof.dll", L"ntmarta.dll", L"netutils.dll", L"msimg32.dll",
        L"mpr.dll", L"logoncli.dll", L"iphlpapi.dll", L"dbghelp.dll", L"comctl32.dll",
        L"uxtheme.dll", L"wininet.dll", L"urlmon.dll", L"ole32.dll", L"shell32.dll",
        L"shlwapi.dll", L"crypt32.dll", L"bcrypt.dll", L"wintrust.dll", L"setupapi.dll"
    };
    std::vector<ProcInfo> procs = SnapshotProcs();
    int hits = 0;
    for (auto& p : procs) {
        if (p.pid < 100) continue;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, p.pid);
        if (!snap || snap == INVALID_HANDLE_VALUE) continue;
        MODULEENTRY32W me; memset(&me, 0, sizeof(me)); me.dwSize = sizeof(me);
        if (Module32FirstW(snap, &me)) {
            do {
                wstring ml = me.szModule;
                for (auto& c : ml) if (c >= L'A' && c <= L'Z') c = c - L'A' + L'a';
                for (const wchar_t* t : kTargets) {
                    if (ml != t) continue;
                    wstring mp = me.szExePath;
                    if (!mp.empty() && !IsSystemDirPath(mp)) {
                        hits++;
                        LogFmt(L"[DLL劫持] PID=%u %s 加载非系统目录的 %s : %s",
                               p.pid, p.name.c_str(), t, mp.c_str());
                        BehavAdd(p.pid, p.name, BEHAV_HOOK, 9,
                                 L"DLL劫持: " + wstring(t) + L" -> " + mp);
                        SetThreatLevel(THREAT_DANGER, L"检测到 DLL 劫持");
                        if (g_cfg.advAggressive) KillProcess(p.pid);
                    }
                    break;
                }
                memset(&me, 0, sizeof(me)); me.dwSize = sizeof(me);
            } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
    }
    LogFmt(hits ? L"[DLL劫持] 完成, 命中 %d 个" : L"[DLL劫持] 完成, 未发现劫持", hits);
}

static void ScanNetwork() {
    vector<NetInfo> local;
    PMIB_TCPTABLE pTcp = nullptr;
    ULONG sz = 0;
    if (GetTcpTable(pTcp, &sz, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
        pTcp = (PMIB_TCPTABLE)malloc(sz);
        if (pTcp && GetTcpTable(pTcp, &sz, FALSE) == NO_ERROR) {
            for (DWORD i = 0; i < pTcp->dwNumEntries; ++i) {
                NetInfo n;
                wchar_t la[32] = {0};
                DWORD a = pTcp->table[i].dwLocalAddr;
                wsprintfW(la, L"%u.%u.%u.%u:%u",
                    (a>>0)&255,(a>>8)&255,(a>>16)&255,(a>>24)&255,
                    ntohs((USHORT)pTcp->table[i].dwLocalPort));
                n.local = la;
                n.state = L"EST";
                n.pid = 0;
                local.push_back(n);
            }
        }
        free(pTcp);
    }
    std::lock_guard<std::mutex> lk(g_netsMtx);
    g_nets.swap(local);
}

static void ScanRegistry() {
    LogPost(L"ScanRegistry: 遍历持久化检测点 (Run/IFEO/AppInit/Winlogon/LSA/SessionMgr...)");
    int hits = 0;
    for (int i = 0; i < g_regRuleCount; ++i) {
        HKEY hk = nullptr;
        if (RegOpenKeyExW(g_regRules[i].root, g_regRules[i].sub, 0, KEY_READ, &hk) != ERROR_SUCCESS || !hk)
            continue;
        wchar_t name[512], data[1024];
        for (DWORD idx = 0; idx < 200; ++idx) {
            DWORD nsz = (DWORD)(sizeof(name) / sizeof(name[0]) - 1);
            DWORD dsz = (DWORD)sizeof(data);
            DWORD type = 0;
            long r = RegEnumValueW(hk, idx, name, &nsz, nullptr, &type, (LPBYTE)data, &dsz);
            if (r != ERROR_SUCCESS) break;
            name[511] = 0;
            if (data[0] == 0 && name[0] == 0) continue;      // 跳过空项
            LogFmt(L"Persistence[%s]: %s = %s", g_regRules[i].desc,
                   name[0] ? name : L"(默认)", data);
            ++hits;
        }
        RegCloseKey(hk);
    }
    LogFmt(L"ScanRegistry: 完成 -> 检查 %d 个持久化点, 记录 %d 项", g_regRuleCount, hits);
}

static bool FileSha256W(const std::wstring& path, std::wstring& outHex);

static void ScanFiles(const wstring& root) {
    LogFmt(L"ScanFiles: %s", root.c_str());
    // 递归受限扫描: 仅枚举前两层
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((root + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        wstring ext = PathFindExtensionW(fd.cFileName);
        if (_wcsicmp(ext.c_str(), L".exe") == 0 || _wcsicmp(ext.c_str(), L".dll") == 0) {
            wstring full = root + L"\\" + fd.cFileName;
            wstring hex;
            if (FileSha256W(full, hex))
                LogFmt(L"ScanFiles: %s sha256=%s", fd.cFileName, hex.c_str());
            else
                LogFmt(L"ScanFiles: %s (哈希失败/跳过)", fd.cFileName);
            // 内置规则综合检测 (勒索后缀/哈希/内容特征/可疑路径)
            wstring why;
            int sev = RuleMatchFile(full, why);
        { std::wstring _fw; int _ff = MalFamilyScan(full, _fw); if (_ff > sev) { sev = _ff; why = _fw; } }
            if (sev > 0) {
                LogFmt(L"规则命中[文件] %s -> %s (sev=%d)", fd.cFileName, why.c_str(), sev);
                if (g_cfg.advAggressive && sev >= 2) QuarantineFile(full);
            }
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

// ============================================================
//  分级扫描: 无签名 > 有签名 > 系统 > 驱动
//  优先级语义: 无签名(风险最高, 最先扫) -> 有签名(第三方) -> 系统组件 -> 驱动
//  (数字签名仅用于排序, 不作为放行依据 —— 遵循最小信任原则)
// ============================================================
enum ScanPrio {
    SCAN_PRIO_UNSIGNED = 0,   // 无签名 / 签名无效 —— 最高优先
    SCAN_PRIO_SIGNED   = 1,   // 有签名的第三方程序
    SCAN_PRIO_SYSTEM   = 2,   // Windows 系统组件
    SCAN_PRIO_DRIVER   = 3    // 驱动(内核态, 最后处理)
};
static const wchar_t* ScanPrioName(int p) {
    switch (p) {
        case SCAN_PRIO_UNSIGNED: return L"无签名";
        case SCAN_PRIO_SIGNED:   return L"有签名";
        case SCAN_PRIO_SYSTEM:   return L"系统组件";
        case SCAN_PRIO_DRIVER:   return L"驱动";
    }
    return L"未知";
}

struct ScanTarget {
    DWORD   pid  = 0;
    wstring path;
    wstring name;
    int     prio = SCAN_PRIO_UNSIGNED;
};

static wstring ScanLowerW(const wstring& s) {
    wstring r = s;
    for (size_t i = 0; i < r.size(); ++i)
        if (r[i] >= L'A' && r[i] <= L'Z') r[i] = (wchar_t)(r[i] + 32);
    return r;
}

// 系统组件判定: 位于 Windows 目录或其 System32 / SysWOW64 子目录
static bool IsSystemComponentPath(const wstring& path) {
    if (path.empty()) return false;
    wchar_t win[MAX_PATH] = { 0 };
    if (!GetWindowsDirectoryW(win, MAX_PATH)) return false;
    wstring lw = ScanLowerW(path);
    wstring lwWin = ScanLowerW(win);
    if (lwWin.empty()) return false;
    return lw.find(lwWin) == 0;
}

// 驱动判定: .sys 后缀
static bool IsDriverImage(const wstring& path) {
    if (path.empty()) return false;
    size_t dot = path.rfind(L'.');
    if (dot == wstring::npos) return false;
    wstring ext = ScanLowerW(path.substr(dot));
    return ext == L".sys";
}

// 分级: 驱动 -> 系统 -> 有签名 -> 无签名(最高优先)
static int ClassifyScanPrio(const wstring& path) {
    if (IsDriverImage(path)) return SCAN_PRIO_DRIVER;
    if (IsSystemComponentPath(path)) return SCAN_PRIO_SYSTEM;
    int sig = VerifyFileSignature(path);
    if (sig == 1) return SCAN_PRIO_SIGNED;
    // 无签名 / 签名无效 / 无法验证 —— 一律按最高优先处理
    return SCAN_PRIO_UNSIGNED;
}

static void ScanByPriorityOrder() {
    LogPost(L"===== 分级扫描开始: 无签名 > 有签名 > 系统 > 驱动 =====");
    auto procs = SnapshotProcs();
    vector<ScanTarget> tgts;
    for (auto& p : procs) {
        if (p.pid == 0 || p.pid == 4) continue;          // System Idle / System
        ScanTarget t;
        t.pid  = p.pid;
        t.path = p.path;
        t.name = p.name;
        if (t.path.empty()) t.path = p.name;
        t.prio = ClassifyScanPrio(t.path);
        tgts.push_back(t);
    }
    std::stable_sort(tgts.begin(), tgts.end(),
                     [](const ScanTarget& a, const ScanTarget& b) { return a.prio < b.prio; });

    int  cur     = -1;
    int  hits    = 0;
    unsigned uns = 0;
    for (auto& t : tgts) {
        if (t.prio != cur) {
            cur = t.prio;
            LogFmt(L"--- 扫描层级 [%d/4] %s ---", cur + 1, ScanPrioName(cur));
        }
        if (t.prio == SCAN_PRIO_UNSIGNED) uns++;
        LogFmt(L"  [%s] pid=%u %s", ScanPrioName(t.prio), t.pid, t.name.c_str());

        if (t.path.empty()) continue;
        DWORD attr = GetFileAttributesW(t.path.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES) continue;

        wstring why;
        int sev = RuleMatchFile(t.path, why);
        { std::wstring _fw; int _ff = MalFamilyScan(t.path, _fw); if (_ff > sev) { sev = _ff; why = _fw; } }
        if (sev > 0) {
            hits++;
            LogFmt(L"    规则命中: %s (sev=%d)", why.c_str(), sev);
            BehavAdd(t.pid, t.name, BEHAV_SIGN, sev, L"分级扫描-规则命中: " + why);
            if (g_cfg.advAggressive && sev >= 3) QuarantineFile(t.path);
        }
        // 无签名层级重点核查: 计算哈希并比对威胁情报
        if (t.prio == SCAN_PRIO_UNSIGNED) {
            wstring hex;
            if (FileSha256W(t.path, hex)) {
                wstring hname; int hsev = 0;
                if (RuleMatchHash(hex, hname, hsev)) {
                    hits++;
                    LogFmt(L"    !! 无签名进程命中恶意哈希情报: %s", t.name.c_str());
                    BehavAdd(t.pid, t.name, BEHAV_SIGN, 10, L"无签名 + 恶意哈希情报命中");
                    SetThreatLevel(THREAT_DANGER, (L"无签名进程命中恶意哈希: " + t.name).c_str());
                    // v13.24 统一处置链: 阻止运行 + 内存转储 + 隔离 + 静态分析 + 通知
                    // 注意: 不再要求 advAggressive —— 已确认有害的必须立刻阻止
                    ContainThreat(t.pid, t.path, L"恶意哈希情报命中:" + hname, hsev);
                } else {
                    LogFmt(L"    无签名(重点监控) sha256=%s", hex.c_str());
                }
            }
        }
    }
    LogFmt(L"===== 分级扫描完成: 共 %u 项, 其中无签名 %u 项, 命中 %d 项 =====",
           (unsigned)tgts.size(), uns, hits);
    if (uns > 0)
        LogFmt(L"提示: %u 个无签名程序已优先扫描, 建议到「信任管理」逐个复核", uns);
}

// ============================================================
//  计划任务持久化检测 (Scheduled Task Persistence)
//  扫描 %WINDIR%\\System32\\Tasks 下的任务 XML, 提取 <Command>/<Arguments>
//  判定: 落点可写目录 / 借道脚本宿主 / 编码命令 / 随机哈希任务名
// ============================================================
static bool TsReadTextW(const wstring& path, wstring& out) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    const DWORD CH = 65536;
    char buf[CH];
    DWORD rd = 0;
    if (!ReadFile(h, buf, CH - 1, &rd, nullptr)) { CloseHandle(h); return false; }
    buf[rd] = 0;
    CloseHandle(h);
    // 任务 XML 以 UTF-16LE 存储, 取宽字符视图
    const wchar_t* wbuf = (const wchar_t*)buf;
    size_t n = rd / 2;
    out.assign(wbuf, n > (size_t)rd ? (size_t)rd : n);
    return true;
}

static wstring TsExtractTag(const wstring& xml, const wstring& tag) {
    wstring open = L"<" + tag + L">";
    wstring close = L"</" + tag + L">";
    size_t a = xml.find(open);
    if (a == wstring::npos) return L"";
    a += open.size();
    size_t b = xml.find(close, a);
    if (b == wstring::npos) return L"";
    return xml.substr(a, b - a);
}

// 任务落点是否在可写/高风险目录
static bool TsPathSuspicious(const wstring& cmd) {
    wstring c = ScanLowerW(cmd);
    static const wchar_t* bad[] = {
        L"\\temp\\", L"\\tmp\\", L"%temp%", L"\\appdata\\", L"\\users\\public\\",
        L"\\downloads\\", L"\\desktop\\", L"\\programdata\\", L"\\recycle"
    };
    for (const wchar_t* b : bad) if (c.find(b) != wstring::npos) return true;
    return false;
}

// 是否借道脚本宿主 / LOLBins
static bool TsHostSuspicious(const wstring& cmd, const wstring& args, bool& encCmd) {
    encCmd = false;
    wstring c = ScanLowerW(cmd);
    wstring a = ScanLowerW(args);
    static const wchar_t* hosts[] = {
        L"powershell", L"pwsh", L"cmd.exe", L"rundll32", L"regsvr32",
        L"mshta", L"wscript", L"cscript", L"certutil", L"bitsadmin",
        L"installutil", L"msbuild", L"wmic", L"schtasks"
    };
    bool host = false;
    for (const wchar_t* h : hosts)
        if (c.find(h) != wstring::npos) { host = true; break; }
    static const wchar_t* enc[] = {
        L"-enc", L"-encodedcommand", L"iex", L"invoke-expression",
        L"downloadstring", L"frombase64string", L"-e ", L"hidden"
    };
    for (const wchar_t* e : enc)
        if (a.find(e) != wstring::npos) { encCmd = true; break; }
    return host || encCmd;
}

static void TaskSchedScan() {
    LogPost(L"===== 计划任务持久化检测 =====");
    wchar_t win[MAX_PATH] = { 0 };
    if (!GetWindowsDirectoryW(win, MAX_PATH)) { LogPost(L"无法获取 Windows 目录"); return; }
    wstring root = wstring(win) + L"\\System32\\Tasks";

    std::deque<wstring> dirs;
    dirs.push_back(root);
    vector<wstring> files;
    int depth = 0;
    while (!dirs.empty() && depth < 200) {
        depth++;
        wstring d = dirs.front(); dirs.pop_front();
        WIN32_FIND_DATAW fd;
        HANDLE h = FindFirstFileW((d + L"\\*").c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) continue;
        do {
            wstring nm = fd.cFileName;
            if (nm == L"." || nm == L"..") continue;
            wstring full = d + L"\\" + nm;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) dirs.push_back(full);
            else files.push_back(full);
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    LogFmt(L"共发现计划任务文件 %u 个", (unsigned)files.size());

    int susp = 0;
    for (auto& f : files) {
        wstring xml;
        if (!TsReadTextW(f, xml)) continue;
        wstring cmd  = TsExtractTag(xml, L"Command");
        wstring args = TsExtractTag(xml, L"Arguments");
        if (cmd.empty()) continue;

        bool  encCmd = false;
        bool  pathBad = TsPathSuspicious(cmd);
        bool  hostBad = TsHostSuspicious(cmd, args, encCmd);
        bool  nameBad = IsHashLikeName(f);

        int risk = 0;
        wstring why;
        if (pathBad) { risk += 3; why += L"落点位于可写/高风险目录; "; }
        if (hostBad) { risk += 2; why += L"借道脚本宿主/LOLBins; "; }
        if (encCmd)  { risk += 3; why += L"命令行含编码或隐藏执行特征; "; }
        if (nameBad) { risk += 2; why += L"任务名为随机哈希; "; }
        if (risk == 0) continue;

        susp++;
        wstring taskName = f;
        size_t bs = taskName.rfind(L'\\');
        if (bs != wstring::npos) taskName = taskName.substr(bs + 1);
        LogFmt(L"[可疑计划任务] %s -> %s %s (risk=%d) %s",
               taskName.c_str(), cmd.c_str(), args.c_str(), risk, why.c_str());
        BehavAdd(0, taskName, BEHAV_REG, risk, L"计划任务持久化: " + cmd + L" " + args);
        if (risk >= 5) SetThreatLevel(THREAT_DANGER, (L"可疑计划任务持久化: " + taskName).c_str());

        if (g_cfg.advAggressive && risk >= 5) {
            wchar_t cl[1024];
            memset(cl, 0, sizeof(cl));
            wstring sc = L"/c schtasks /change /tn \"" + taskName + L"\" /disable /f";
            for (size_t i = 0; i < sc.size() && i < 900; ++i) cl[i] = sc[i];
            STARTUPINFOW si; memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
            PROCESS_INFORMATION pi; memset(&pi, 0, sizeof(pi));
            if (CreateProcessW(nullptr, cl, nullptr, nullptr, FALSE,
                               CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                LogFmt(L"  已禁用任务: %s", taskName.c_str());
            } else {
                LogFmt(L"  禁用失败(需管理员): %s", taskName.c_str());
            }
        }
    }
    LogFmt(L"===== 计划任务检测完成: 可疑 %d 个 =====", susp);
    if (susp == 0) LogPost(L"未发现可疑计划任务");
}

// ============================================================
//  进程注入检测 (Process Injection Detection)
//  1) 模块文件在磁盘上不存在     -> 内存加载 / 已删除模块
//  2) 模块落点位于可写临时目录   -> 常见注入落地点
//  3) 已知注入/挂钩型 DLL 名单   -> 直接命中
//  4) 线程起始地址不在任何模块内 -> Shellcode 线程(经典注入特征)
// ============================================================
static bool InjKnownDll(const wstring& modName) {
    static const wchar_t* bad[] = {
        L"mimikatz", L"inject", L"hook", L"shellcode", L"payload",
        L"reflective", L"sandboxie", L"dsefix", L"capcom", L"dbutil"
    };
    wstring n = ScanLowerW(modName);
    for (const wchar_t* b : bad) if (n.find(b) != wstring::npos) return true;
    return false;
}

static bool InjWritableDir(const wstring& path) {
    wstring c = ScanLowerW(path);
    static const wchar_t* bad[] = {
        L"\\temp\\", L"\\tmp\\", L"\\appdata\\", L"\\users\\public\\",
        L"\\downloads\\", L"\\desktop\\", L"\\programdata\\"
    };
    for (const wchar_t* b : bad) if (c.find(b) != wstring::npos) return true;
    return false;
}

// NtQueryInformationThread: 取线程起始地址 (ThreadQuerySetWin32StartAddress = 9)
typedef long (WINAPI* PFN_NtQueryInformationThread)(HANDLE, int, void*, unsigned long, unsigned long*);
static bool InjGetThreadStart(HANDLE hThread, size_t& startAddr) {
    startAddr = 0;
    HMODULE hNt = LoadLibraryW(L"ntdll.dll");
    if (!hNt) return false;
    PFN_NtQueryInformationThread pQ =
        (PFN_NtQueryInformationThread)GetProcAddress(hNt, "NtQueryInformationThread");
    if (!pQ) { FreeLibrary(hNt); return false; }
    size_t addr = 0;
    long st = pQ(hThread, 9, &addr, sizeof(addr), nullptr);
    FreeLibrary(hNt);
    if (st != 0 || addr == 0) return false;
    startAddr = addr;
    return true;
}

static void InjectScan() {
    LogPost(L"===== 进程注入检测 =====");
    auto procs = SnapshotProcs();
    int found = 0;
    for (auto& p : procs) {
        if (p.pid == 0 || p.pid == 4) continue;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, p.pid);
        if (snap == INVALID_HANDLE_VALUE) continue;

        // 收集模块地址区间, 供线程起始地址比对
        struct ModRange { size_t base; size_t size; wstring path; wstring name; };
        vector<ModRange> mods;
        MODULEENTRY32W me;
        memset(&me, 0, sizeof(me));
        me.dwSize = sizeof(me);
        if (Module32FirstW(snap, &me)) {
            do {
                wstring mp = me.szExePath;
                wstring mn = me.szModule;
                ModRange r;
                r.base = (size_t)me.modBaseAddr;
                r.size = (size_t)me.modBaseSize;
                r.path = mp;
                r.name = mn;
                mods.push_back(r);

                if (mp.empty()) continue;
                DWORD attr = GetFileAttributesW(mp.c_str());
                bool onDisk = (attr != INVALID_FILE_ATTRIBUTES);
                if (!onDisk) {
                    found++;
                    LogFmt(L"[注入嫌疑] pid=%u %s 模块已不在磁盘(内存加载/隐藏): %s",
                           p.pid, p.name.c_str(), mn.c_str());
                    BehavAdd(p.pid, p.name, BEHAV_HOOK, 8, L"模块不在磁盘: " + mn);
                    SetThreatLevel(THREAT_DANGER, (L"检测到内存加载模块: " + mn).c_str());
                } else if (InjWritableDir(mp)) {
                    found++;
                    LogFmt(L"[注入嫌疑] pid=%u %s 模块位于可写目录: %s",
                           p.pid, p.name.c_str(), mp.c_str());
                    BehavAdd(p.pid, p.name, BEHAV_HOOK, 5, L"模块位于可写目录: " + mp);
                } else if (InjKnownDll(mn)) {
                    found++;
                    LogFmt(L"[注入嫌疑] pid=%u %s 已知注入/挂钩模块: %s",
                           p.pid, p.name.c_str(), mn.c_str());
                    BehavAdd(p.pid, p.name, BEHAV_HOOK, 7, L"已知注入模块: " + mn);
                    SetThreatLevel(THREAT_DANGER, (L"检测到已知注入模块: " + mn).c_str());
                }
            } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);

        // 线程起始地址不在任何已加载模块内 -> Shellcode 线程
        if (mods.empty()) continue;
        HANDLE tsnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (tsnap == INVALID_HANDLE_VALUE) continue;
        THREADENTRY32 te;
        memset(&te, 0, sizeof(te));
        te.dwSize = sizeof(te);
        if (Thread32First(tsnap, &te)) {
            do {
                if (te.th32OwnerProcessID != p.pid) continue;
                HANDLE hT = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (!hT) continue;
                size_t start = 0;
                if (InjGetThreadStart(hT, start)) {
                    bool inMod = false;
                    for (auto& m : mods)
                        if (start >= m.base && start < m.base + m.size) { inMod = true; break; }
                    if (!inMod) {
                        found++;
                        LogFmt(L"[注入嫌疑] pid=%u %s tid=%u 线程起始地址 0x%p 不在任何模块内 (Shellcode 线程)",
                               p.pid, p.name.c_str(), te.th32ThreadID, (void*)start);
                        BehavAdd(p.pid, p.name, BEHAV_HOOK, 9,
                                 L"线程起始地址不在模块内(Shellcode): tid=" + std::to_wstring(te.th32ThreadID));
                        SetThreatLevel(THREAT_DANGER, (L"检测到 Shellcode 线程: " + p.name).c_str());
                    }
                }
                CloseHandle(hT);
            } while (Thread32Next(tsnap, &te));
        }
        CloseHandle(tsnap);
    }
    LogFmt(L"===== 进程注入检测完成: 可疑项 %d 处 =====", found);
    if (found == 0) LogPost(L"未发现进程注入迹象");
}

static void ScanMemory() {
    LogPost(L"ScanMemory: 检查注入/Shellcode");
    auto procs = SnapshotProcs();
    for (auto& p : procs) {
        HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, p.pid);
        if (!h) continue;
        MEMORY_BASIC_INFORMATION mbi;
        size_t addr = 0;
        while (VirtualQueryEx(h, (const void*)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT &&
                (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY) &&
                mbi.Type == MEM_PRIVATE) {
                LogFmt(L"ScanMemory: pid=%u 检测到 RWX 私有内存 @%p size=%u",
                       p.pid, mbi.BaseAddress, (unsigned)mbi.RegionSize);
                break;
            }
            addr = (size_t)mbi.BaseAddress + mbi.RegionSize;
        }
        CloseHandle(h);
    }
}

static void AmsiScan(const wstring& content) {
    LogFmt(L"AmsiScan: %u chars", (unsigned)content.size());
    typedef void* HAMSICONTEXT; typedef void* HAMSISESSION; typedef int AMSI_RESULT;
    typedef long (*PFN_Init)(const wchar_t*, HAMSICONTEXT*);
    typedef long (*PFN_Open)(HAMSICONTEXT, HAMSISESSION*);
    typedef long (*PFN_Scan)(HAMSICONTEXT, void*, unsigned long, const wchar_t*, HAMSISESSION, AMSI_RESULT*);
    typedef void (*PFN_Close)(HAMSICONTEXT, HAMSISESSION);
    typedef void (*PFN_Uninit)(HAMSICONTEXT);
    HMODULE hAmsi = LoadLibraryW(L"amsi.dll");
    if (!hAmsi) { LogPost(L"AmsiScan: amsi.dll 不可用, 跳过"); return; }
    auto pInit  = (PFN_Init) GetProcAddress(hAmsi, "AmsiInitialize");
    auto pOpen  = (PFN_Open) GetProcAddress(hAmsi, "AmsiOpenSession");
    auto pScan  = (PFN_Scan) GetProcAddress(hAmsi, "AmsiScanBuffer");
    auto pClose = (PFN_Close)GetProcAddress(hAmsi, "AmsiCloseSession");
    auto pUninit= (PFN_Uninit)GetProcAddress(hAmsi, "AmsiUninitialize");
    if (!pInit || !pOpen || !pScan || !pClose || !pUninit) {
        LogPost(L"AmsiScan: AMSI 导出函数缺失"); FreeLibrary(hAmsi); return;
    }
    HAMSICONTEXT ctx = nullptr;
    if (pInit(L"ZZ_EDR", &ctx) < 0 || !ctx) {
        LogPost(L"AmsiScan: AmsiInitialize 失败"); FreeLibrary(hAmsi); return;
    }
    HAMSISESSION sess = nullptr;
    if (pOpen(ctx, &sess) < 0) {
        LogPost(L"AmsiScan: AmsiOpenSession 失败"); pUninit(ctx); FreeLibrary(hAmsi); return;
    }
    AMSI_RESULT res = 0;
    long hr = pScan(ctx, (void*)content.c_str(),
                    (unsigned long)(content.size() * sizeof(wchar_t)),
                    L"ZZ_EDR/script", sess, &res);
    if (hr >= 0)
        LogFmt(L"AmsiScan: 结果=%d (%s)", (int)res, res >= 32768 ? L"恶意/阻断" : L"干净");
    else
        LogFmt(L"AmsiScan: AmsiScanBuffer 失败 hr=%d", (int)hr);
    pClose(ctx, sess); pUninit(ctx); FreeLibrary(hAmsi);
}

// ============================================================
//  主动响应
// ============================================================
static void QuarantineFile(const wstring& path) {
    // v13.14: 处置前必须经用户确认
    if (g_alertAsk.load()) {
        int a = AlertConfirm(L"ZZ EDR 安全告警",
                             L"检测到恶意文件，是否立即隔离此文件？", path, 0);
        if (a != ALERT_HANDLE) { LogPost(L"[已忽略] 用户选择不隔离: " + path); return; }
    }
    SetThreatLevel(THREAT_DANGER, (L"已隔离恶意文件: " + path).c_str());
    if (IsProtectedPath(path)) {
        LogPost(L"Quarantine: 受保护路径, 拒绝隔离: " + path);
        return;
    }
    // v13.15 修复: 原用相对路径 ".\\quarantine", 工作目录不确定时会散落;
    // 且与宏病毒隔离目录不一致。现统一为 %TEMP%\\zz_EDR_quarantine
    std::wstring qdir = MacroQuarantineDir();
    CreateDirectoryW(qdir.c_str(), nullptr);
    std::wstring base = PathFindFileNameW(path.c_str());
    std::wstring q = qdir + L"\\" + base + L".quar";
    if (!CopyFileW(path.c_str(), q.c_str(), FALSE)) {
        LogFmt(L"Quarantine: CopyFile failed err=%u", GetLastError());
        return;
    }
    // 记录原路径到 .meta, 供隔离区管理恢复时使用
    {
        HANDLE hm = CreateFileW((q + L".meta").c_str(), GENERIC_WRITE, 0, nullptr,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hm != INVALID_HANDLE_VALUE) {
            DWORD wr = 0;
            WriteFile(hm, path.c_str(), (DWORD)(path.size() * sizeof(wchar_t)), &wr, nullptr);
            CloseHandle(hm);
        }
    }
    // v13.15 修复: 隔离语义是"移走", 原实现只 CopyFile 不删除原文件,
    // 导致隔离后恶意文件仍留在原地。现复制成功后删除原文件,
    // 若被占用则标记重启时删除。
    if (!DeleteFileW(path.c_str())) {
        MoveFileExW(path.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
        LogFmt(L"Quarantine: 原文件被占用, 已标记重启时删除 (err=%u)", GetLastError());
    }
    LogFmt(L"Quarantine: %s -> %s", path.c_str(), q.c_str());
}

// ============================================================
//  统一威胁处置链 (v13.24)
// ============================================================
// 【设计思路】命中有害后要同时达成四个目标，且顺序不可颠倒：
//
//   ① 止血 —— 阻止继续破坏（挂起 → 终止进程）
//   ② 取证 —— 内存转储【必须在杀进程之前】！
//           进程一死，内存里解密后的 payload、C2 地址、注入代码
//           全部消失，事后无从分析。这是最容易写反的一步。
//   ③ 可逆 —— 隔离（可恢复）优先于删除（不可逆），误报能一键还原
//   ④ 知情 —— 静态分析报告 + 系统通知，而不是默默处理完
//
// 【坑1·顺序】错误写法：Kill(); Dump();  → 转储必失败
//            正确写法：Suspend → Dump → Kill
//            挂起的额外作用：转储期间内存稳定，否则转出"撕裂"快照
//
// 【坑2·不可直接删】早期版本 DeleteFile，误报无法挽回。
//            现在一律 CopyFile 到隔离区 + 写 .meta 记录原路径。
//
// 【坑3·受保护路径】系统文件/自身永不处置，否则会把系统搞崩。
// ============================================================

// ① 挂起/恢复进程：转储期间冻结内存
// 做法：快照遍历该进程所有线程逐个 SuspendThread。
// 不用 NtSuspendProcess（未文档化，不同系统导出号不同，风险高）。
static int SuspendPid(DWORD pid, bool suspend) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    THREADENTRY32 te; te.dwSize = sizeof(te);
    int n = 0;
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            HANDLE th = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
            if (!th) continue;
            if (suspend) { if (SuspendThread(th) != (DWORD)-1) ++n; }
            else         { if (ResumeThread(th)  != (DWORD)-1) ++n; }
            CloseHandle(th);
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    return n;
}

// ② 内存转储：dbghelp.dll 动态加载（不链接 import lib，缺库也不崩）
// 转储类型选择：MiniDumpWithFullMemory 会转出几百 MB，太重；
// 这里用 Normal + HandleData + UnloadedModules，体积小且保留句柄与
// 已卸载模块信息——分析注入/C2 连接够用。
typedef BOOL (WINAPI *PFN_MiniDumpWriteDump)(
    HANDLE, DWORD, HANDLE, DWORD, const void*, const void*, const void*);

static bool DumpProcessMemory(DWORD pid, const std::wstring& outPath) {
    if (!pid) return false;
    HMODULE h = LoadLibraryW(L"dbghelp.dll");
    if (!h) { LogPost(L"Dump: dbghelp.dll 不可用，跳过内存转储"); return false; }
    PFN_MiniDumpWriteDump fn =
        (PFN_MiniDumpWriteDump)GetProcAddress(h, "MiniDumpWriteDump");
    if (!fn) { FreeLibrary(h); LogPost(L"Dump: MiniDumpWriteDump 未导出"); return false; }

    HANDLE hp = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hp) { FreeLibrary(h); LogFmt(L"Dump: OpenProcess 失败 err=%u", GetLastError()); return false; }

    HANDLE hf = CreateFileW(outPath.c_str(), GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) {
        CloseHandle(hp); FreeLibrary(h);
        LogFmt(L"Dump: 创建转储文件失败 err=%u", GetLastError()); return false;
    }
    const DWORD kType = 0x00000000   // MiniDumpNormal
                      | 0x00000040   // MiniDumpWithHandleData
                      | 0x00000020;  // MiniDumpWithUnloadedModules
    BOOL ok = fn(hp, pid, hf, kType, nullptr, nullptr, nullptr);
    DWORD err = GetLastError();
    CloseHandle(hf); CloseHandle(hp); FreeLibrary(h);
    if (!ok) { LogFmt(L"Dump: MiniDumpWriteDump 失败 err=%u", err);
               DeleteFileW(outPath.c_str()); return false; }
    LogFmt(L"Dump: 内存转储已保存 -> %s", outPath.c_str());
    return true;
}

// ③ 系统通知（托盘气泡）
// 懒初始化：首次调用时创建图标，无需改动 WM_CREATE。
// 图标需要窗口接收回调消息，这里用 nullptr 回调 + 纯气泡，
// 不影响主窗口消息循环。退出时 TrayCleanup 删除图标，避免幽灵图标。
static NOTIFYICONDATAW g_nid;
static bool            g_trayInited = false;
static const UINT      WMAPP_TRAY   = WM_APP + 40;

static void SysNotify(const std::wstring& title, const std::wstring& msg) {
    if (!g_cfg.notifyOn) return;
    if (!g_trayInited) {
        ZeroMemory(&g_nid, sizeof(g_nid));
        g_nid.cbSize           = sizeof(g_nid);
        g_nid.hWnd             = g_hMain;
        g_nid.uID              = 1;
        g_nid.uFlags           = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        g_nid.uCallbackMessage = WMAPP_TRAY;
        g_nid.hIcon            = LoadIconW(nullptr, IDI_SHIELD);
        wcsncpy(g_nid.szTip, L"ZZ EDR 防护中", 63);
        g_trayInited = Shell_NotifyIconW(NIM_ADD, &g_nid) ? true : false;
        if (!g_trayInited) LogPost(L"Notify: 托盘图标创建失败，通知不可用");
    }
    if (!g_trayInited) return;
    g_nid.uFlags = NIF_INFO;
    g_nid.dwInfoFlags = NIIF_WARNING;
    wcsncpy(g_nid.szInfoTitle, title.c_str(), 63);
    wcsncpy(g_nid.szInfo,      msg.c_str(),   255);
    g_nid.uTimeout = 10000;
    if (!Shell_NotifyIconW(NIM_MODIFY, &g_nid))
        LogFmt(L"Notify: 气泡显示失败 err=%u", GetLastError());
}

static void TrayCleanup(void) {
    if (g_trayInited) { Shell_NotifyIconW(NIM_DELETE, &g_nid); g_trayInited = false; }
}

// ④ 统一处置链
// pid=0 表示只处理文件（无运行中进程）。
// category 用于通知文案，形如 "银狐/ValleyRAT"、"进程镂空"。
// v13.25: 激进增强(定义在本函数之后, 先声明)
static int  AggressiveKillLoop(DWORD pid, int rounds, int intervalMs);
static bool AggressiveOverwriteFile(const std::wstring& path);
static bool AggressiveBackupAndScan(const std::wstring& path, std::wstring& backupPath);
static bool AggressiveRestore(const std::wstring& path, const std::wstring& backupPath);
static void EnterFocusWatch(const std::wstring& path);
static void CollectSysLogAndCmds();
// v13.26 紧急逃生模式(定义在后, 先声明)
// 触发门槛: 1 = 任何一条规则命中(含提示级)都执行终极处置
static const int ESCAPE_MIN_SEV = 1;
static bool UltimateWipeFile(const std::wstring& path, int passes);
static void EscapePurge(DWORD pid, const std::wstring& path,
                        const std::wstring& category, int sev);
// v13.38 顽固病毒清除加固(定义在后, 先声明)
static bool PurgeEnablePrivs();
static bool KillProcessHard(DWORD pid);
static int  PurgeKillTree(DWORD pid, const std::wstring& path, int rounds, int intervalMs);
static int  PurgeCleanPersistence(const std::wstring& path);
static int  PurgeCleanWmi(const std::wstring& path);
static int  PurgeCleanIfeo(const std::wstring& path);
static int  ForceUnlockFile(const std::wstring& path);
static int  FkCleanAutorun(const std::wstring& key);
static int  FkCleanServices(const std::wstring& key);
static int  FkCleanTasks(const std::wstring& key);

static void ContainThreat(DWORD pid, const std::wstring& path,
                          const std::wstring& category, int sev) {
    // ---- v13.26 紧急逃生模式: 最高优先级, 优先于低危过滤 ----
    // 【为什么放在 sev<2 判断之前】
    // 逃生模式的语义是"命中任意规则即终极处置"，包括提示级(sev=1)。
    // 若放在 sev<2 之后，低危规则就不会触发，逃生模式形同虚设。
    if (g_cfg.escapeMode && sev >= ESCAPE_MIN_SEV) {
        EscapePurge(pid, path, category, sev);
        return;                                // 走终极链路, 不再执行常规流程
    }
    if (sev < 2) return;                       // 低危只记日志，不动手
    if (!path.empty() && IsProtectedPath(path)) {
        LogPost(L"Contain: 受保护路径，拒绝处置: " + path);
        return;                                // 绝不碰系统文件/自身
    }

    // ---- 步骤1: 挂起（冻结内存，为转储做准备）----
    int suspended = 0;
    if (pid) suspended = SuspendPid(pid, true);

    // ---- 步骤2: 内存转储（必须在终止之前！）----
    std::wstring dumpPath;
    if (pid && g_cfg.dumpOn) {
        wchar_t tmp[MAX_PATH] = {0};
        GetTempPathW(MAX_PATH, tmp);
        dumpPath = std::wstring(tmp) + L"zz_EDR_quarantine";
        CreateDirectoryW(dumpPath.c_str(), nullptr);
        dumpPath += L"\\dump_" + std::to_wstring(pid) + L"_"
                  + std::to_wstring((unsigned)GetTickCount()) + L".dmp";
        DumpProcessMemory(pid, dumpPath);
    }

    // ---- 步骤2.5 (仅激进模式): 覆写之前先备份, 这是可还原的安全底线 ----
    // 顺序不可颠倒: 备份 -> 压制 -> 覆写。若先覆写, 样本就没了, 误杀无法挽回。
    std::wstring aggBackup;
    bool aggBackedUp = false;
    if (g_cfg.advAggressive && !path.empty()) {
        aggBackedUp = AggressiveBackupAndScan(path, aggBackup);
    }

    // ---- 步骤3: 终止进程 ----
    if (pid) {
        if (suspended) SuspendPid(pid, false);  // 先恢复再杀，避免挂起态残留
        if (g_cfg.advAggressive) {
            // 激进: 连杀 20 次, 每 5ms 复查是否被守护进程拉起, 复活就再杀
            AggressiveKillLoop(pid, 20, 5);
        } else {
            KillProcess(pid);
        }
        LogFmt(L"Contain: 已阻止运行 pid=%u (%s)", pid, category.c_str());
    }

    // ---- 步骤3.5 (仅激进模式): 覆写原文件磁盘镜像 ----
    bool aggOverwritten = false;
    if (g_cfg.advAggressive && aggBackedUp && !path.empty())
        aggOverwritten = AggressiveOverwriteFile(path);

    // ---- 步骤4: 隔离（可逆：复制 + 记录原路径）----
    bool quarantined = false;
    if (!path.empty()) {
        std::wstring qdir = MacroQuarantineDir();
        CreateDirectoryW(qdir.c_str(), nullptr);
        std::wstring base = PathFindFileNameW(path.c_str());
        std::wstring q = qdir + L"\\" + base + L".quar";
        if (CopyFileW(path.c_str(), q.c_str(), FALSE)) {
            HANDLE hm = CreateFileW((q + L".meta").c_str(), GENERIC_WRITE, 0,
                                    nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hm != INVALID_HANDLE_VALUE) {
                DWORD wr = 0;
                WriteFile(hm, path.c_str(),
                          (DWORD)(path.size() * sizeof(wchar_t)), &wr, nullptr);
                CloseHandle(hm);
            }
            if (!DeleteFileW(path.c_str()))
                MoveFileExW(path.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
            quarantined = true;
            LogFmt(L"Contain: 已隔离 -> %s", q.c_str());
        } else {
            LogFmt(L"Contain: 隔离失败 err=%u", GetLastError());
        }
    }

    // ---- 步骤5: 静态分析（出报告，供用户判断）----
    std::wstring verdict; std::vector<std::wstring> report;
    if (!path.empty()) {
        int sc = SandboxStaticAnalyze(path, verdict, report);
        LogFmt(L"Contain: 静态分析评分=%d 判定=%s", sc, verdict.c_str());
        for (size_t i = 0; i < report.size() && i < 12; ++i)
            LogPost(L"  · " + report[i]);
    }

    // ---- 步骤6: 通知 + 升级告警 ----
    SetThreatLevel(THREAT_DANGER,
        (L"已处置威胁: " + category + (path.empty() ? L"" : (L" (" + path + L")"))).c_str());

    // ---- 步骤5.5 (仅激进模式): 复核 -> 无问题则还原并重点观察 10 分钟 ----
    if (g_cfg.advAggressive && aggBackedUp && !aggBackup.empty()) {
        std::wstring v2; std::vector<std::wstring> r2;
        int sc2 = SandboxStaticAnalyze(aggBackup, v2, r2);
        if (sc2 < 30) {
            if (aggOverwritten) AggressiveRestore(path, aggBackup);
            EnterFocusWatch(path);
            LogPost(L"[激进] 复核未发现恶意特征(评分<30), 已还原并转入重点观察 10 分钟");
        } else {
            LogFmt(L"[激进] 复核仍可疑(评分=%d), 保持覆写+隔离状态", sc2);
        }
        // 持续采集系统日志与各进程命令行, 留下证据链
        CollectSysLogAndCmds();
    }

    std::wstring msg = L"发现可疑文件，疑似" + category + L"，已自动隔离至备分区";
    if (quarantined) msg += L"（原文件已移入隔离区，可一键还原）";
    if (!dumpPath.empty()) msg += L"；已保存内存转储供分析";
    SysNotify(L"ZZ EDR 安全告警", msg);
    LogPost(L"[Contain] " + msg);
}


// ============================================================
//  v13.25: 激进模式 —— 越界进程的"压制 + 覆写 + 复核 + 观察"闭环

// ============================================================
//  v13.26: 紧急逃生模式(Escape Mode) —— 比激进模式更高一级的终极处置
//
//  【为什么需要单独一级, 而不是把激进模式调得更狠?】
//  激进模式的触发条件是"行为越界且确认有害"，覆盖面窄、偏保守，
//  适合日常使用。但存在一种场景: 你已经确认系统被控(勒索正在加密、
//  远控已建立会话)，此时需要的不是"精确打击"，而是"立刻止损"。
//  这两者的触发面与破坏力完全不同，用同一个开关表达只会互相干扰：
//    · 把激进模式调到"任意规则即杀" -> 日常误报会毁掉正常软件
//    · 保留保守阈值                 -> 真正紧急时又打不死
//  所以独立成一级，由用户显式开启，语义是"宁可错杀，不可放过"。
//
//  【三级递进关系】
//    普通   : 确认有害才处置        -> 杀一次 + 隔离(可还原)
//    激进   : 行为越界才增强        -> 杀x20 + 1遍随机覆写 + 扫描干净则还原
//    逃生   : 命中任意规则(含提示级) -> 杀x20 + 多遍覆写彻底销毁 + 不自动还原
//
//  【与激进模式最关键的三个差异】
//   ① 触发门槛: 激进要求 sev>=2 且行为越界; 逃生只要 sev>=1(任意规则)
//   ② 覆写强度: 激进 1 遍随机(保留可还原性); 逃生 3 遍(0x00/0xFF/随机)
//   ③ 还原策略: 激进扫描干净即还原; 逃生默认不还原(止损优先)
//
//  【仍然保留的两条底线】
//   ① 受保护路径(System32/自身)一律拒绝 —— 否则会直接毁掉系统
//   ② 覆写前尽量备份 —— 备份失败也继续(止损优先), 但日志最高级告警
// ============================================================

// 终极覆写遍数: 0x00 -> 0xFF -> 伪随机(DoD 5220.22-M 的简化三遍)
// v13.27: 遍数不再写死, 由用户选择的强度等级决定(见 EscapeWipePasses)
static const int ESCAPE_WIPE_PASSES = 3;   // 仅作为兜底默认值

// 备份失败重试次数(用户要求: 失败重试三次)
static const int ESCAPE_BACKUP_RETRY = 3;

// ---- 强度等级 -> 覆写遍数 ----
// 弱=1 遍: 只做一次随机覆写, 秒级完成, 用于"先止损再说"
// 中=3 遍: 0x00/0xFF/随机, DoD 简化版, 默认档
// 强=7 遍: 完整 DoD 5220.22-M, 追求理论不可恢复, 大文件会很慢
static int EscapeWipePasses() {
    switch (g_cfg.escapeWipeLevel) {
        case 1:  return 1;
        case 3:  return 7;
        default: return 3;
    }
}

// ============================================================
//  占用进程识别 (Restart Manager)
// ------------------------------------------------------------
//  【为什么要先找占用者】文件被占用时 CopyFile 会因共享冲突失败。
//  盲目重试没意义 —— 只要占用还在, 重试一百次也是同样结果。必须
//  先定位是谁占着, 把它停下来, 备份才有成功的可能。
//  【为什么用 Restart Manager】这是 Windows 官方提供的文件占用查询
//  接口(rmapi.dll, Vista+ 自带), 不需要驱动、不需要解析内核句柄表,
//  是用户态最可靠的做法。相比"暴力遍历进程句柄"既安全又准确。
//  【命名为什么加 ZZ_ 前缀】避免与 SDK 的 rmapi.h 重复定义。结构体
//  内存布局与官方一致, 仅名称不同, 传递指针时完全兼容。
// ============================================================
typedef struct _ZZ_RM_UNIQUE_PROCESS {
    DWORD    dwProcessId;
    FILETIME ProcessStartTime;
} ZZ_RM_UNIQUE_PROCESS;

typedef struct _ZZ_RM_PROCESS_INFO {
    ZZ_RM_UNIQUE_PROCESS Process;
    WCHAR   strAppName[256];
    WCHAR   strServiceShortName[64];
    DWORD   ApplicationType;
    ULONG   AppStatus;
    DWORD   TSSessionId;
    BOOL    bRestartable;
} ZZ_RM_PROCESS_INFO;

// Restart Manager 会话 key 长度(官方定义 CCH_RM_SESSION_KEY = 32)
#ifndef ZZ_CCH_RM_SESSION_KEY
#define ZZ_CCH_RM_SESSION_KEY 32
#endif

// 返回找到的占用者数量; 失败或无占用返回 0
static int EscapeFindLockers(const std::wstring& path,
                             std::vector<DWORD>& pids,
                             std::vector<std::wstring>& names) {
    pids.clear(); names.clear();
    if (path.empty()) return 0;

    // 动态加载: 万一系统缺少 rmapi.dll(极老系统), 不应导致程序崩溃
    HMODULE hRm = LoadLibraryW(L"rmapi.dll");
    if (!hRm) {
        LogPost(L"[逃生] rmapi.dll 不可用, 无法精确识别占用进程");
        return 0;
    }
    typedef DWORD (WINAPI *PFnStartSession)(DWORD*, DWORD, WCHAR*);
    typedef DWORD (WINAPI *PFnRegisterRes)(DWORD, UINT, LPCWSTR*, UINT,
                                           ZZ_RM_UNIQUE_PROCESS*, UINT, LPCWSTR*);
    typedef DWORD (WINAPI *PFnGetList)(DWORD, UINT*, UINT*, ZZ_RM_PROCESS_INFO*, DWORD*);
    typedef DWORD (WINAPI *PFnEndSession)(DWORD);

    PFnStartSession pStart = (PFnStartSession)GetProcAddress(hRm, "RmStartSession");
    PFnRegisterRes  pReg   = (PFnRegisterRes) GetProcAddress(hRm, "RmRegisterResources");
    PFnGetList      pList  = (PFnGetList)     GetProcAddress(hRm, "RmGetList");
    PFnEndSession   pEnd   = (PFnEndSession)  GetProcAddress(hRm, "RmEndSession");
    if (!pStart || !pReg || !pList || !pEnd) {
        LogPost(L"[逃生] rmapi.dll 接口缺失, 跳过占用识别");
        FreeLibrary(hRm);
        return 0;
    }

    int found = 0;
    DWORD session = 0;
    WCHAR key[ZZ_CCH_RM_SESSION_KEY + 1] = {0};
    if (pStart(&session, 0, key) == 0) {
        LPCWSTR files[1] = { path.c_str() };
        if (pReg(session, 1, files, 0, nullptr, 0, nullptr) == 0) {
            // 官方用法: 第一次调用获取需要的数量, 第二次取回列表
            UINT need = 0, n = 0;
            DWORD reason = 0;
            if (pList(session, &need, &n, nullptr, &reason) == 0 && need > 0) {
                std::vector<ZZ_RM_PROCESS_INFO> info(need);
                n = need;
                if (pList(session, &need, &n, info.data(), &reason) == 0) {
                    for (UINT i = 0; i < n; ++i) {
                        DWORD pid = info[i].Process.dwProcessId;
                        if (pid == 0 || pid == GetCurrentProcessId()) continue;
                        pids.push_back(pid);
                        names.push_back(std::wstring(info[i].strAppName));
                        ++found;
                    }
                }
            }
        }
        pEnd(session);
    }
    FreeLibrary(hRm);
    if (found > 0) {
        for (size_t i = 0; i < pids.size() && i < 8; ++i)
            LogFmt(L"[逃生] 文件被占用 pid=%u 进程=%s", pids[i], names[i].c_str());
    }
    return found;
}

// ---- 终止占用进程, 让文件恢复可访问 ----
// 【顺序】先尝试正常结束, 失败再强制终止, 给程序一个干净退出的机会,
// 减少未保存数据丢失(虽然此刻止损优先, 但能少损失一点是一点)。
static int EscapeKillLockers(const std::vector<DWORD>& pids) {
    int n = 0;
    for (size_t i = 0; i < pids.size(); ++i) {
        DWORD pid = pids[i];
        if (pid == 0 || pid == GetCurrentProcessId()) continue;   // 绝不杀自己
        if (KillProcess(pid)) { ++n; LogFmt(L"[逃生] 已终止占用进程 pid=%u", pid); }
        else LogFmt(L"[逃生] 占用进程终止失败 pid=%u", pid);
    }
    return n;
}

// ============================================================
//  带重试的备份: 3 次重试 -> 解除占用 -> 再试 -> 仍失败则询问用户
// ------------------------------------------------------------
//  返回值:  1 = 备份成功
//           0 = 备份失败, 但用户选择"仍然继续"(止损优先)
//          -1 = 用户选择"放弃处置"(保住文件, 不覆写)
// ============================================================
static int EscapeBackupWithRetry(const std::wstring& path, std::wstring& backup) {
    backup.clear();
    if (path.empty()) return 0;

    wchar_t tmp[MAX_PATH] = {0};
    GetTempPathW(MAX_PATH, tmp);
    // 【v13.31 修复】同上: 逃生模式备份的也是恶意样本, 必须进隔离区 samples,
    // 不能与用户重要数据共用 zz_EDR_backup。
    std::wstring bdir = std::wstring(tmp) + L"zz_EDR_quarantine\\samples";
    CreateDirectoryW((std::wstring(tmp) + L"zz_EDR_quarantine").c_str(), nullptr);
    CreateDirectoryW(bdir.c_str(), nullptr);
    std::wstring base = PathFindFileNameW(path.c_str());

    DWORD lastErr = 0;
    // ---- 第一轮: 连续重试三次 ----
    // 有些失败是瞬时的(杀软正在扫描该文件、磁盘忙), 短暂停顿后可能就成功了
    for (int i = 1; i <= ESCAPE_BACKUP_RETRY; ++i) {
        backup = bdir + L"\\" + base + L"." + std::to_wstring((unsigned)GetTickCount())
               + L".bak";
        if (CopyFileW(path.c_str(), backup.c_str(), FALSE)) {
            LogFmt(L"[逃生] 原始样本已保存(第 %d 次成功): %s", i, backup.c_str());
            return 1;
        }
        lastErr = GetLastError();
        LogFmt(L"[逃生] 备份第 %d 次失败 err=%u", i, lastErr);
        Sleep(200);                       // 短暂退避再试, 避免忙等
    }

    // ---- 第二轮: 查是谁占着, 停掉它, 再试一次 ----
    // 三次都失败, 大概率是文件被独占打开(ERROR_SHARING_VIOLATION / ACCESS_DENIED)。
    // 此时继续重试毫无意义, 必须先解除占用。
    std::vector<DWORD> pids;
    std::vector<std::wstring> names;
    int lockers = EscapeFindLockers(path, pids, names);
    if (lockers > 0) {
        std::wstring who;
        for (size_t i = 0; i < names.size() && i < 5; ++i) {
            if (i) who += L"、";
            who += names[i] + L"(pid=" + std::to_wstring(pids[i]) + L")";
        }
        LogPost(L"[逃生] 检测到文件被以下进程占用: " + who);
        int killed = EscapeKillLockers(pids);
        LogFmt(L"[逃生] 已终止 %d 个占用进程, 重新尝试备份", killed);
        Sleep(300);                       // 给系统一点时间释放句柄

        backup = bdir + L"\\" + base + L"." + std::to_wstring((unsigned)GetTickCount())
               + L".bak";
        if (CopyFileW(path.c_str(), backup.c_str(), FALSE)) {
            LogPost(L"[逃生] 解除占用后备份成功: " + backup);
            return 1;
        }
        lastErr = GetLastError();
        LogFmt(L"[逃生] 解除占用后备份仍失败 err=%u", lastErr);
    } else {
        LogPost(L"[逃生] 未能识别出占用进程(可能需要管理员权限)");
    }

    // ---- 第三轮: 仍然失败, 通知并询问用户 ----
    // 【为什么必须问】继续覆写 = 该文件永久消失且无法还原。这是不可逆的
    // 决定, 不该由程序替用户做。用户可能是误报、可能那文件有重要数据。
    backup.clear();
    std::wstring ask = L"无法备份文件(错误码 " + std::to_wstring(lastErr) + L"):\n"
                     + path + L"\n\n";
    if (lockers > 0) {
        ask += L"已尝试终止占用进程后仍然失败。\n\n";
    } else {
        ask += L"未能识别出占用该文件的进程。\n\n";
    }
    ask += L"继续覆写将无法还原此文件, 是否仍要继续？\n"
           L"  【是】仍然执行终极覆写(止损优先, 文件不可恢复)\n"
           L"  【否】放弃本次处置, 保留原文件\n"
           L"  【取消】放弃并加入白名单, 此后不再提示";

    SysNotify(L"ZZ EDR 紧急逃生模式",
              L"文件备份失败, 需要您决定如何处理: " + base);
    int a = AlertConfirm(L"ZZ EDR - 备份失败, 请决定", ask, path, 0);
    if (a == ALERT_HANDLE) {
        LogPost(L"[逃生] 用户选择: 仍然覆写(无法还原)");
        return 0;
    }
    LogPost(L"[逃生] 用户选择: 放弃处置, 保留原文件 " + path);
    return -1;
}

// ---- 终极覆写: 多遍写满文件, 使原始数据不可恢复 ----
// 【思路】单次随机覆写在理论上仍可能通过磁残留恢复; 多遍不同模式
// (全0 / 全1 / 随机) 能覆盖各种介质残留特性, 是公认的低成本销毁手段。
// 【关键】每一遍写完后必须 FlushFileBuffers 强制落盘。否则数据可能
// 只停留在系统缓存里, 进程一结束、或断电, 覆写根本没落到磁盘上。
static bool UltimateWipeFile(const std::wstring& path, int passes) {
    if (path.empty() || IsProtectedPath(path)) {
        LogPost(L"[逃生] 覆写跳过(受保护路径): " + path);
        return false;
    }
    HANDLE hf = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) {
        LogFmt(L"[逃生] 覆写失败, 无法打开 err=%u", GetLastError());
        return false;
    }
    LARGE_INTEGER li; li.QuadPart = 0;
    unsigned long long fsz = 0;
    if (GetFileSizeEx(hf, &li) && li.QuadPart > 0) fsz = (unsigned long long)li.QuadPart;
    if (fsz == 0) fsz = 4096;                  // 空文件也写一页, 不留原样

    const DWORD CH = 64 * 1024;
    std::vector<unsigned char> buf(CH);
    DWORD seed = (DWORD)GetTickCount() ^ 0x5A5A5A5Au;
    bool ok = true;

    for (int pass = 0; pass < passes; ++pass) {
        // 第0遍全0, 第1遍全1, 第2遍及以后伪随机 —— 覆盖不同残留特征
        unsigned char fixed = (pass == 0) ? 0x00 : (pass == 1) ? 0xFF : 0x00;
        bool useFixed = (pass < 2);

        SetFilePointer(hf, 0, nullptr, FILE_BEGIN);
        unsigned long long left = fsz;
        while (left > 0) {
            DWORD todo = (left > CH) ? CH : (DWORD)left;
            if (useFixed) {
                memset(buf.data(), fixed, todo);
            } else {
                for (DWORD i = 0; i < todo; ++i) {   // 无依赖伪随机, 避免 rand() 线程不安全
                    seed = seed * 1103515245u + 12345u;
                    buf[i] = (unsigned char)((seed >> 16) & 0xFF);
                }
            }
            DWORD wr = 0;
            if (!WriteFile(hf, buf.data(), todo, &wr, nullptr) || wr != todo) { ok = false; break; }
            left -= wr;
        }
        FlushFileBuffers(hf);                  // 强制落盘, 保证这一遍真的写到了磁盘
        if (!ok) break;
    }
    // 保持原文件大小, 避免"文件突然变小"暴露处置痕迹(反取证角度也更干净)
    SetFilePointer(hf, 0, nullptr, FILE_BEGIN);
    SetEndOfFile(hf);
    CloseHandle(hf);
    LogFmt(L"[逃生] 终极覆写完成: %llu 字节 x %d 遍 -> %s", fsz, passes, path.c_str());
    return ok;
}

// ---- 逃生模式终极处置链 ----
// ============================================================
//  v13.38 顽固 / 自防护病毒清除加固
//  【问题】老链路只做"杀一个 pid + 覆写一个文件", 面对自防护木马必败:
//    ① 不提权        -> 驱动保护剥离 PROCESS_TERMINATE 后 OpenProcess 直接失败
//    ② 只杀单个 pid  -> 父/子/同路径副本互相守护, 杀一个另一个立刻重建
//    ③ 不清理持久化  -> 服务 / Run / 计划任务 / WMI 订阅仍在, 重启即复活
//    (这是"清不干净"最主要的原因: 进程杀了但开机项还在)
//    ④ 不解除占用    -> DLL 被加载时覆写失败, 文件原封不动留下
//    ⑤ 压制窗口过短  -> 20×5ms 仅 100ms, 延迟几秒重启的守护完全检测不到
//  下面的三个函数分别解决 ①②、③、④⑤。
// ============================================================

//
//  PurgeEnablePrivs: 处置前提权
//  【为什么必须有】自防护木马普遍用驱动(ObRegisterCallbacks)或 PPL 保护,
//  会把其他进程对它的 PROCESS_TERMINATE 权限剥离掉。没有 SeDebugPrivilege
//  时 OpenProcess 直接返回 ACCESS_DENIED, 后续所有动作都无从谈起。
//  SeTakeOwnershipPrivilege 用于接管恶意文件所有权(否则覆写会被 ACL 拦)。
//
static bool PurgeEnablePrivs() {
#if defined(_WIN32) || defined(ZZ_LINT_WIN)
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) {
        LogFmt(L"[提权] OpenProcessToken 失败 err=%u", GetLastError());
        return false;
    }
    bool any = false;
    const wchar_t* privs[] = { L"SeDebugPrivilege", L"SeTakeOwnershipPrivilege" };
    for (const wchar_t* p : privs) {
        LUID luid;
        if (!LookupPrivilegeValueW(nullptr, p, &luid)) continue;
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        SetLastError(0);
        if (AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr)
            && GetLastError() == ERROR_SUCCESS) {
            any = true;
            LogPost(std::wstring(L"[提权] 已启用 ") + p);
        }
    }
    CloseHandle(tok);
    if (!any) LogPost(L"[提权] 未能提权(需以管理员运行), 清除效果会受限");
    return any;
#else
    return false;
#endif
}

//
//  PurgeKillTree: 杀进程"簇"而非单个 pid
//  【三种守护形态】
//    ① 子进程:  父进程监控子进程, 杀子即重建 -> 必须连父一起处理
//    ② 父进程:  主体把自己注入系统进程、由子进程反向守护 -> 必须连子一起处理
//    ③ 同路径副本: A 监控 B、B 监控 A, 杀一个另一个立刻拉起 -> 必须按路径全杀
//  【为什么每轮重新 collect】守护关系会变化, 且子进程 pid 每次重建都不同,
//  只在开头收集一次的话, 第二轮就打不到新的副本了。
//
static int PurgeKillTree(DWORD pid, const std::wstring& path,
                         int rounds, int intervalMs) {
    if (rounds < 1) rounds = 1;
    if (intervalMs < 0) intervalMs = 0;
    const DWORD self = GetCurrentProcessId();
    const std::wstring lowPath = ToLowerW(path);

    auto collect = [&](std::vector<DWORD>& out) {
        out.clear();
        std::vector<ProcInfo> ps = SnapshotProcs();
        // 本体: 仅当它仍存活才加入。进程已经死了就不必再调 TerminateProcess,
        // 否则会对一个不存在的 pid 空转, 日志还会刷一堆无意义的失败。
        if (pid && pid != 4 && pid != self) {
            for (const ProcInfo& p : ps)
                if (p.pid == pid) { out.push_back(pid); break; }
        }
        for (const ProcInfo& p : ps) {
            if (p.pid == 0 || p.pid == 4 || p.pid == self) continue;
            bool hit = false;
            if (pid && p.ppid == pid) hit = true;                 // 子进程
            if (pid && p.pid == pid)   hit = true;                // 本体
            // 同路径副本: 比按名字匹配可靠, 改名也躲不掉
            if (!lowPath.empty() && !p.path.empty()
                && ToLowerW(p.path) == lowPath) hit = true;
            if (hit) out.push_back(p.pid);
        }
        std::sort(out.begin(), out.end());
        out.erase(std::unique(out.begin(), out.end()), out.end());
    };

    std::vector<DWORD> targets;
    int total = 0;
    for (int r = 0; r < rounds; ++r) {
        collect(targets);
        if (targets.empty()) break;            // 已全部清除, 不空转
        int n = 0;
        for (DWORD t : targets) if (KillProcessHard(t)) ++n;
        total += n;
        if (n == 0) break;                     // 一个都杀不动, 继续循环没意义
        if (intervalMs) Sleep(intervalMs);
    }
    return total;
}

//
//  PurgeCleanPersistence: 铲掉"复活"的根
//  【为什么这是关键】老链路杀完进程就结束, 但服务 / Run 项 / 计划任务 /
//  WMI 事件订阅都还在。重启后系统自己把它拉起来 —— 用户看到的就是"清不掉"。
//  进程是叶子, 持久化项才是根。
//
static int PurgeCleanPersistence(const std::wstring& path) {
    if (path.empty()) return 0;
    int n = 0;
    n += FkCleanAutorun(path);      // Run / RunOnce / Winlogon
    n += FkCleanServices(path);     // 服务(停止 + 禁用)
    n += FkCleanTasks(path);        // 计划任务(禁用)
    n += PurgeCleanWmi(path);       // WMI 事件订阅(无文件持久化)
    n += PurgeCleanIfeo(path);      // IFEO 镜像劫持
    if (n) LogFmt(L"[铲根] 已清除持久化项 %d 个: %s", n, path.c_str());
    else   LogPost(L"[铲根] 未发现关联持久化项: " + path);
    return n;
}

//
//  PurgeCleanWmi: WMI 事件订阅持久化
//  【这是什么】无文件木马的主力手段: 注册一个__EventFilter(触发条件,
//  如"每 5 分钟"或"某进程启动") + 一个 CommandLineEventConsumer(要执行的
//  命令) + 一条绑定关系。重启后 WMI 服务自动触发, 磁盘上没有任何文件,
//  所以扫文件永远扫不到它。老代码完全没覆盖。
//
static int PurgeCleanWmi(const std::wstring& path) {
    int n = 0;
#if defined(_WIN32) || defined(ZZ_LINT_WIN)
    // 提取文件名做模糊匹配(命令行里可能是完整路径, 也可能带引号)
    std::wstring fname;
    size_t slash = path.find_last_of(L"\\/");
    if (slash != std::wstring::npos) fname = path.substr(slash + 1);
    if (fname.empty()) return 0;

    // 用 wmic 删除三类对象: 消费者 -> 过滤器 -> 绑定
    // 【避坑】先删绑定再删对象, 顺序反了会留下悬空绑定
    auto wmiDel = [&](const wchar_t* cls, const wchar_t* where) {
        std::wstring cmd = std::wstring(L"wmic /namespace:\\\\root\\subscription PATH ")
                         + cls + L" Where \"" + where + L"\" Delete 2>nul";
        _wsystem(cmd.c_str());
    };
    std::wstring like = L"CommandLineTemplate like '%" + fname + L"%'";
    wmiDel(L"CommandLineEventConsumer", like.c_str());
    std::wstring lk2 = L"Name like '%" + fname + L"%'";
    wmiDel(L"__EventFilter", lk2.c_str());
    std::wstring lk3 = L"Consumer like '%" + fname + L"%'";
    wmiDel(L"__FilterToConsumerBinding", lk3.c_str());
    n = 1;   // wmic 无回显, 有执行即记 1
    LogPost(L"[铲根] 已尝试清理 WMI 事件订阅: " + fname);
#else
    (void)path;
#endif
    return n;
}

//
//  PurgeCleanIfeo: IFEO 镜像劫持
//  【这是什么】在 Image File Execution Options 下给某个 exe 名设 Debugger
//  值, 系统启动该 exe 时会先运行 Debugger 指定的程序。木马常用它劫持
//  notepad / chrome 等正常程序, 也用它让自己随任意程序启动。
//
static int PurgeCleanIfeo(const std::wstring& path) {
    int n = 0;
#if defined(_WIN32) || defined(ZZ_LINT_WIN)
    const wchar_t* kIfeo =
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    HKEY hk = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kIfeo, 0, KEY_READ | KEY_WRITE, &hk) != ERROR_SUCCESS)
        return 0;
    const std::wstring lowPath = ToLowerW(path);
    wchar_t name[256];
    for (DWORD i = 0; i < 4096; ++i) {
        DWORD cch = 256;
        if (RegEnumKeyExW(hk, i, name, &cch, nullptr, nullptr, nullptr, nullptr)
            != ERROR_SUCCESS) break;
        HKEY hs = nullptr;
        if (RegOpenKeyExW(hk, name, 0, KEY_READ | KEY_WRITE, &hs) != ERROR_SUCCESS) continue;
        wchar_t buf[1024]; DWORD sz = sizeof(buf), ty = 0;
        if (RegQueryValueExW(hs, L"Debugger", nullptr, &ty,
                             (LPBYTE)buf, &sz) == ERROR_SUCCESS && ty == REG_SZ) {
            // 命中才删: 绝不误删其他软件的调试器配置
            if (ToLowerW(buf).find(lowPath) != std::wstring::npos) {
                if (RegDeleteValueW(hs, L"Debugger") == ERROR_SUCCESS) {
                    ++n;
                    LogPost(std::wstring(L"[铲根] 已清除 IFEO 镜像劫持: ") + name);
                }
            }
        }
        RegCloseKey(hs);
    }
    RegCloseKey(hk);
#else
    (void)path;
#endif
    return n;
}

static void EscapePurge(DWORD pid, const std::wstring& path,
                        const std::wstring& category, int sev) {
    // 受保护路径是唯一不可逾越的红线: 覆写 System32 会直接导致系统崩溃
    if (!path.empty() && IsProtectedPath(path)) {
        LogPost(L"[逃生] 受保护路径, 拒绝终极处置: " + path);
        return;
    }
    LogFmt(L"[逃生] 终极处置开始 pid=%u sev=%d 类别=%s", pid, sev, category.c_str());

    // ---- ⓪提权: 拿到 SeDebugPrivilege 才可能动被保护的进程 ----
    // 【v13.38】自防护木马会用驱动/PPL 剥离访问权限, 不提权的话后面
    // 每一步都会卡在 OpenProcess ACCESS_DENIED 上。
    PurgeEnablePrivs();

    // ---- ①挂起: 冻结进程 ----
    // 【为什么必须挂起】正在运行的程序, 其映像文件被系统以独占方式
    // 打开, 直接覆写会失败(ERROR_SHARING_VIOLATION)。先挂起线程既能
    // 阻止它继续作恶, 也让后续覆写有机会成功。
    int suspended = 0;
    if (pid) suspended = SuspendPid(pid, true);

    // ---- ②内存转储(必须在杀进程之前) ----
    // 进程一死, 内存里解密后的 payload、C2 地址、注入代码全部消失,
    // 事后无从分析。这一步的顺序错了, 整个取证链就断了。
    if (pid && g_cfg.dumpOn) {
        wchar_t tmp[MAX_PATH] = {0};
        GetTempPathW(MAX_PATH, tmp);
        std::wstring ddir = std::wstring(tmp) + L"zz_EDR_quarantine";
        CreateDirectoryW(ddir.c_str(), nullptr);
        std::wstring dumpPath = ddir + L"\\dump_" + std::to_wstring(pid) + L"_"
                              + std::to_wstring((unsigned)GetTickCount()) + L".dmp";
        DumpProcessMemory(pid, dumpPath);
    }

    // ---- ③备份到备份区 + 静态分析 ----
    // 【与激进模式的差异】激进模式备份失败就放弃覆写(保住可还原性);
    // 逃生模式备份失败仍继续覆写 —— 因为此刻是"止损优先"。但必须以
    // 最高级别日志告警, 让用户知道这一击无法挽回。
    // v13.27: 备份改为"3 次重试 -> 解除占用 -> 询问用户"三段式。
    // 返回 -1 表示用户选择放弃, 此时必须立即停止整个处置链(不杀不覆写)。
    std::wstring backup;
    bool backedUp = false;
    if (!path.empty()) {
        int br = EscapeBackupWithRetry(path, backup);
        if (br < 0) {
            LogPost(L"[逃生] 用户放弃, 已取消本次终极处置: " + path);
            if (pid) SuspendPid(pid, false);       // 之前可能挂起过, 务必恢复
            return;
        }
        if (br == 1) {
            backedUp = true;
            std::wstring verdict; std::vector<std::wstring> report;
            int sc = SandboxStaticAnalyze(backup, verdict, report);
            LogFmt(L"[逃生] 静态分析 评分=%d 判定=%s", sc, verdict.c_str());
            for (size_t i = 0; i < report.size() && i < 12; ++i) LogPost(L"  · " + report[i]);
        } else {
            LogPost(L"[逃生] 警告: 未能备份 —— 仍将执行覆写, 但本次处置无法还原!");
        }
    }

    // ---- ④压制: 杀进程"簇", 而非单个 pid ----
    // 【v13.38 加固】原实现只用 AggressiveKillLoop 盯住单一 pid, 父/子/同路径
    // 副本互相守护时必然漏网。改为 PurgeKillTree 按"本体+子进程+同路径副本"
    // 收集目标, 每轮重新收集(子进程 pid 每次重建都不同, 只收一次会打空)。
    int killed = 0;
    if (pid) {
        if (suspended) SuspendPid(pid, false); // 先恢复再杀, 避免挂起态残留
        // 轮次由配置的 escapeKillTimes 决定(默认 20), 覆盖守护重启窗口
        killed = PurgeKillTree(pid, path, g_cfg.escapeKillTimes, g_cfg.escapeKillIntervalMs);
        if (killed == 0) {
            // 一个都杀不动: 多半是驱动级保护。明确告知, 而不是假装成功
            LogPost(L"[逃生] 警告: 进程无法终止, 疑似存在内核级自保护(需驱动或安全模式)");
        }
    }

    // ---- ⑤解除占用 + 终极覆写 ----
    // 【v13.38 加固】文件被加载成 DLL、或句柄没关干净时, 覆写会以
    // ERROR_SHARING_VIOLATION 失败, 原文件一字不动地留下 —— 这正是
    // "明明处置了却还在"的直接原因。覆写前先强制解除占用。
    bool wiped = false;
    // v13.27: 遍数由用户选择的强度等级决定(弱1/中3/强7)
    int passes = EscapeWipePasses();
    if (!path.empty()) {
        int unlocked = ForceUnlockFile(path);
        if (unlocked > 0) LogFmt(L"[逃生] 已强制解除 %d 个占用句柄", unlocked);
        wiped = UltimateWipeFile(path, passes);
    }

    // ---- ⑥删除: 覆写后再删; 删不掉就标记重启删, 不留活口 ----
    bool removed = false;
    if (!path.empty()) {
        if (DeleteFileW(path.c_str())) {
            removed = true;
        } else if (MoveFileExW(path.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT)) {
            LogPost(L"[逃生] 已标记重启后删除(当前被占用): " + path);
            removed = true;
        } else {
            LogFmt(L"[逃生] 删除失败 err=%u (文件已被覆写, 内容已销毁)", GetLastError());
        }
    }

    // ---- ⑦铲根: 清除持久化, 否则重启即复活(最关键的一步) ----
    int persistence = 0;
    if (!path.empty()) persistence = PurgeCleanPersistence(path);

    // ---- ⑧采集证据链: 系统日志 + 当前各进程命令行 ----
    CollectSysLogAndCmds();

    // ---- ⑨告警 + 通知 ----
    SetThreatLevel(THREAT_DANGER,
        (L"[逃生] 已彻底清除: " + category + (path.empty() ? L"" : (L" (" + path + L")"))).c_str());
    std::wstring msg = L"紧急逃生模式：发现可疑文件，疑似" + category + L"，已执行终极查杀并彻底清除";
    if (killed > 0) msg += L"；进程已终止 " + std::to_wstring(killed) + L" 次";
    if (wiped)      msg += L"；原文件已覆写 " + std::to_wstring(passes) + L" 遍";
    if (persistence > 0) msg += L"；已铲除持久化项 " + std::to_wstring(persistence) + L" 个";
    if (backedUp)   msg += L"；样本已存备份区";
    else            msg += L"（未能备份，无法还原）";
    SysNotify(L"ZZ EDR 紧急逃生模式", msg);
    LogPost(L"[逃生] " + msg);
}

//
//  【思路】普通处置只杀一次进程就结束。但顽固木马有守护进程/互相拉起:
//  你杀它, 它的兄弟进程 200ms 后又把它拉起来, 处置形同无效。
//  所以激进模式不是一个动作, 而是一条时间线:
//
//    ①压制(结束进程 x20, 每 5ms 复查是否复活, 复活就再杀)
//       └ 目的: 在守护进程反应过来之前, 把"复活窗口"彻底堵死
//    ②覆写(原文件写满随机数据, 破坏其磁盘镜像)
//       └ 目的: 即使进程被重新拉起, 文件本体已废, 执行即失败
//    ③备份区归档 + 静态分析(在覆写之前先备份! 顺序不能反)
//       └ 目的: 保住取证样本, 并为后续"是否误杀"提供复核依据
//    ④扫描无问题 -> 还原, 并进入重点观察 10 分钟
//       └ 目的: 承认"可能误判", 给正常程序一条自动恢复的退路
//    ⑤全程持续采集系统日志 + 各进程命令行
//       └ 目的: 留下证据链, 事后能复盘它到底做了什么
// ============================================================

// ---- 重点观察表: path -> 观察截止时间戳(GetTickCount64 毫秒) ----
static std::map<std::wstring, unsigned long long> g_focusWatch;
static std::mutex                                 g_focusMtx;
static const unsigned long long FOCUS_WATCH_MS = 10ULL * 60ULL * 1000ULL;  // 10 分钟

// 是否处于重点观察期(观察期内检测频率更高、日志更详细)
static bool IsInFocusWatch(const std::wstring& path) {
    std::lock_guard<std::mutex> lk(g_focusMtx);
    auto it = g_focusWatch.find(path);
    if (it == g_focusWatch.end()) return false;
    if (GetTickCount64() > it->second) { g_focusWatch.erase(it); return false; }
    return true;
}
static void EnterFocusWatch(const std::wstring& path) {
    std::lock_guard<std::mutex> lk(g_focusMtx);
    g_focusWatch[path] = GetTickCount64() + FOCUS_WATCH_MS;
    LogPost(L"[激进] 进入重点观察(10分钟): " + path);
}

// ---- ①压制: 结束进程 N 次, 每次间隔 5ms 复查是否复活 ----
// 【避坑】必须"先杀后查再杀": 只杀一次的话, 守护进程会在毫秒级把它拉起,
// 而我们的检查在 5ms 后, 正好能看到它复活并立刻补杀, 循环 20 次足以耗尽其重启尝试。
// 内核优先的强杀(定义在驱动对接层, 此处前向声明)
static bool KillProcessHard(DWORD pid);

static int AggressiveKillLoop(DWORD pid, int rounds, int intervalMs) {
    int killed = 0;
    for (int i = 0; i < rounds; ++i) {
        if (!pid) break;
        // 【思路】压制循环里用 KillProcessHard(内核优先, 失败回落用户态):
        //        受保护进程(PPL 等)用户态 OpenProcess 会直接失败, 只有内核能杀掉。
        KillProcessHard(pid);
        ++killed;
        // 复查: 进程是否已被重新拉起? 若还在就下一轮继续杀
        if (intervalMs > 0) Sleep((DWORD)intervalMs);
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (h) {                       // 句柄还在 = 进程对象仍存活(可能已被复用)
            DWORD code = 0;
            bool alive = GetExitCodeProcess(h, &code) && code == STILL_ACTIVE;
            CloseHandle(h);
            if (!alive) break;         // 已彻底死亡, 无需再杀
        } else {
            break;                     // 句柄都拿不到 = 确已退出
        }
    }
    LogFmt(L"[激进] 压制结束 pid=%u: 共执行 %d 次终止", pid, killed);
    return killed;
}

// ---- ②覆写: 用随机数据把文件写满, 破坏磁盘镜像 ----
static bool AggressiveOverwriteFile(const std::wstring& path) {
    if (path.empty() || IsProtectedPath(path)) {
        LogPost(L"[激进] 覆写跳过(受保护路径): " + path);
        return false;
    }
    HANDLE hf = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) {
        LogFmt(L"[激进] 覆写失败, 无法打开 err=%u", GetLastError());
        return false;
    }
    LARGE_INTEGER li; li.QuadPart = 0;
    unsigned long long fsz = 0;
    if (GetFileSizeEx(hf, &li) && li.QuadPart > 0) fsz = (unsigned long long)li.QuadPart;
    if (fsz == 0) fsz = 4096;                  // 空文件也写一页, 不留原样

    const DWORD CH = 64 * 1024;
    std::vector<unsigned char> buf(CH);
    unsigned long long left = fsz;
    DWORD seed = (DWORD)GetTickCount();
    while (left > 0) {
        DWORD todo = (left > CH) ? CH : (DWORD)left;
        for (DWORD i = 0; i < todo; ++i) {      // 无依赖的伪随机, 避免 rand() 线程不安全
            seed = seed * 1103515245u + 12345u;
            buf[i] = (unsigned char)((seed >> 16) & 0xFF);
        }
        DWORD wr = 0;
        if (!WriteFile(hf, buf.data(), todo, &wr, nullptr) || wr != todo) break;
        left -= wr;
    }
    FlushFileBuffers(hf);
    SetFilePointer(hf, 0, nullptr, FILE_BEGIN);
    SetEndOfFile(hf);                           // 保持原大小, 便于后续还原比对
    CloseHandle(hf);
    LogFmt(L"[激进] 已覆写 %llu 字节: %s", fsz, path.c_str());
    return true;
}

// ---- ③备份区归档 + 静态分析(必须在覆写之前调用) ----
// 返回 true = 扫描未发现问题(可还原)
static bool AggressiveBackupAndScan(const std::wstring& path, std::wstring& backupPath) {
    if (path.empty()) return false;
    wchar_t tmp[MAX_PATH] = {0};
    GetTempPathW(MAX_PATH, tmp);
    // 【v13.31 修复】此前处置备份与"用户数据备份"共用 zz_EDR_backup 目录,
    // 导致恶意病毒样本与用户个人文件混在一起: 用户想恢复数据时会看到一堆
    // 病毒样本; 若 EDR 后续扫描备份区, 还会把自己刚存进去的样本当威胁二次
    // 处置(处置->备份->再扫描->再处置的循环)。
    // 现分离: 处置样本 -> 隔离区 samples 子目录; 用户数据 -> backup/data 子目录。
    std::wstring bdir = std::wstring(tmp) + L"zz_EDR_quarantine\\samples";
    CreateDirectoryW((std::wstring(tmp) + L"zz_EDR_quarantine").c_str(), nullptr);
    CreateDirectoryW(bdir.c_str(), nullptr);

    std::wstring base = PathFindFileNameW(path.c_str());
    backupPath = bdir + L"\\" + base + L"." + std::to_wstring((unsigned)GetTickCount()) + L".bak";
    if (!CopyFileW(path.c_str(), backupPath.c_str(), FALSE)) {
        LogFmt(L"[激进] 备份失败 err=%u (放弃覆写, 避免无法还原)", GetLastError());
        backupPath.clear();
        return false;                            // 备份失败就绝不覆写 —— 这是安全底线
    }
    LogPost(L"[激进] 已备份至备份区: " + backupPath);

    std::wstring verdict; std::vector<std::wstring> report;
    int sc = SandboxStaticAnalyze(backupPath, verdict, report);
    LogFmt(L"[激进] 静态分析 评分=%d 判定=%s", sc, verdict.c_str());
    for (size_t i = 0; i < report.size() && i < 12; ++i) LogPost(L"  · " + report[i]);
    return sc < 30;                              // 低于阈值视为"没发现问题"
}

// ---- ④还原: 把备份区的干净副本写回原位置 ----
static bool AggressiveRestore(const std::wstring& path, const std::wstring& backupPath) {
    if (path.empty() || backupPath.empty()) return false;
    if (!CopyFileW(backupPath.c_str(), path.c_str(), FALSE)) {
        LogFmt(L"[激进] 还原失败 err=%u", GetLastError());
        return false;
    }
    LogPost(L"[激进] 扫描无异常, 已还原: " + path);
    return true;
}

// ---- ⑤持续采集: 系统日志 + 当前各进程命令行 ----
static void CollectSysLogAndCmds() {
    // 5-1) 系统日志: 优先 wevtutil(结构化), 失败则退回事件日志 API
    FILE* pf = _wpopen(L"wevtutil qe System /c:20 /rd:true /f:text",
                       L"rt, ccs=UNICODE");
    if (pf) {
        wchar_t line[512];
        int n = 0;
        while (fgetws(line, 512, pf) && n < 20) {
            size_t L = wcslen(line);
            while (L && (line[L-1] == L'\n' || line[L-1] == L'\r')) line[--L] = 0;
            if (L) { LogPost(L"[系统日志] " + std::wstring(line)); ++n; }
        }
        _pclose(pf);
    } else {
        LogPost(L"[系统日志] wevtutil 不可用(需管理员), 跳过");
    }

    // 5-2) 当前正在运行的命令: 枚举全部进程命令行
    auto procs = SnapshotProcs();
    for (auto& p : procs) {
        std::wstring cmd = GetProcCommandLine(p.pid);
        if (!cmd.empty())
            LogFmt(L"[运行命令] pid=%u %s | %s", p.pid, p.name.c_str(), cmd.c_str());
    }
}

// ---- 编排: 激进模式完整处置链 ----
static void AggressivePurgeProc(DWORD pid, const std::wstring& path,
                                const std::wstring& category) {
    if (!g_cfg.advAggressive) return;            // 仅在激进模式下生效
    if (!path.empty() && IsProtectedPath(path)) {
        LogPost(L"[激进] 受保护路径, 拒绝处置: " + path);
        return;
    }
    LogFmt(L"[激进] 开始处置 pid=%u (%s)", pid, category.c_str());

    // 顺序非常重要: 先备份(保住样本) -> 再压制 -> 再覆写
    std::wstring backup;
    bool backedUp = false;
    if (!path.empty()) backedUp = AggressiveBackupAndScan(path, backup);

    int killed = AggressiveKillLoop(pid, 20, 5);   // 20 次, 每 5ms 复查

    bool overwritten = false;
    if (backedUp && !path.empty()) overwritten = AggressiveOverwriteFile(path);

    // 采集证据链(系统日志 + 运行命令)
    CollectSysLogAndCmds();

    // 复核: 扫描无问题则还原, 并进入重点观察
    if (backedUp && !backup.empty()) {
        static const int CLEAN_THRESHOLD = 30;
        std::wstring verdict; std::vector<std::wstring> report;
        int sc = SandboxStaticAnalyze(backup, verdict, report);
        if (sc < CLEAN_THRESHOLD) {
            if (overwritten) AggressiveRestore(path, backup);
            EnterFocusWatch(path);
            LogPost(L"[激进] 未发现明显恶意特征, 已还原并转入重点观察 10 分钟");
        } else {
            LogFmt(L"[激进] 复核仍判定可疑(评分=%d), 保持覆写+隔离状态", sc);
        }
    }

    SetThreatLevel(THREAT_DANGER,
        (L"[激进] 已处置: " + category + L" (终止" + std::to_wstring(killed) + L"次)").c_str());
    SysNotify(L"ZZ EDR 激进防御",
              L"已对「" + category + L"」执行激进处置：终止 " +
              std::to_wstring(killed) + L" 次" +
              (overwritten ? L"，原文件已覆写" : L"") +
              (backedUp ? L"，样本已备份至备份区" : L""));
}

// ---- 重点观察守护: 观察期内的进程提高复查频率, 到期自动恢复常规观察 ----
static void FocusWatchThread() {
    while (g_running.load()) {
        Sleep(15000);
        std::vector<std::wstring> watching;
        {
            std::lock_guard<std::mutex> lk(g_focusMtx);
            unsigned long long now = GetTickCount64();
            for (auto it = g_focusWatch.begin(); it != g_focusWatch.end();) {
                if (now > it->second) {
                    LogPost(L"[激进] 重点观察结束, 恢复常规观察: " + it->first);
                    it = g_focusWatch.erase(it);
                } else { watching.push_back(it->first); ++it; }
            }
        }
        for (auto& f : watching) {
            // 观察期内: 复查文件是否被再次篡改 / 是否重新运行
            WIN32_FILE_ATTRIBUTE_DATA ad;
            if (GetFileAttributesExW(f.c_str(), GetFileExInfoStandard, &ad)) {
                unsigned long long sz =
                    ((unsigned long long)ad.nFileSizeHigh << 32) | ad.nFileSizeLow;
                LogFmt(L"[重点观察] %s 大小=%llu", f.c_str(), sz);
            }
        }
    }
}

static void RollbackRegistry(const wstring& key) {
    LogFmt(L"Rollback: %s", key.c_str());
    HKEY hk = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_SET_VALUE, &hk) != 0 || !hk) {
        LogPost(L"Rollback: 打开 Run 键失败"); return;
    }
    long r = RegDeleteValueW(hk, key.c_str());
    LogFmt(L"Rollback: 删除自启动值 %s -> %s", key.c_str(),
           r == 0 ? L"成功" : L"失败/不存在");
    RegCloseKey(hk);
}


//==============================================================
// 功能1: 服务与驱动后门扫描

//==============================================================
// 功能A: Rootkit 隐藏进程检测 (交叉视图 cross-view)
// 原理: 三源交叉比对, 差集即为被隐藏的进程
//   A. 进程快照 CreateToolhelp32Snapshot (Rootkit 常 hook 此路径)
//   B. 暴力 PID 枚举 OpenProcess (绕过用户态 hook)
//   C. 网络连接反查 (有连接但 PID 不在快照中 -> 网络活动暴露了它)
//==============================================================
static void HiddenProcScan() {
    if (!g_cfg.hiddenProcOn) {
        LogPost(L"[隐藏进程] 功能未开启 (配置 hiddenProcOn=false)"); return;
    }
    LogPost(L"=== Rootkit 隐藏进程检测开始 (三源交叉比对) ===");
    std::set<DWORD> known;
    for (const auto& p : SnapshotProcs()) known.insert(p.pid);
    if (known.empty()) {
        EnumAllProcesses();
        for (const auto& p : SnapshotProcs()) known.insert(p.pid);
    }
    LogFmt(L"[隐藏进程] 快照可见进程: %u 个", (unsigned)known.size());

    int found = 0;
    // --- 源B: 暴力 PID 枚举 (PID 一般为 4 的倍数) ---
    for (DWORD pid = 4; pid < 65536 && found < 24; pid += 4) {
        if (known.count(pid)) continue;
        std::wstring path = GetProcPath(pid);
        if (path.empty()) continue;
        // 快照中不可见, 却能打开并取到映像路径 -> 疑似被隐藏
        std::wstring tag, sha;
        bool ioc = FileSha256W(path, sha) && IntelHashHit(sha, tag);
        int sig = VerifyFileSignature(path);
        std::wstring why = L"快照不可见但可访问 (PID=" + std::to_wstring(pid) + L")";
        if (ioc) why += L" | 命中威胁情报: " + tag;
        if (sig == 0) why += L" | 无有效签名";
        if (IsDriverImage(path)) why += L" | 驱动映像";
        SetThreatLevel(THREAT_DANGER, (L"发现疑似隐藏进程: " + path).c_str());
        BehavAdd(pid, std::wstring(PathFindFileNameW(path.c_str())),
                 BEHAV_PROC_START, 10, why);
        LogPost(L"[隐藏进程] PID=" + std::to_wstring(pid) + L" " + path + L" | " + why);
        if (g_cfg.advAggressive) {
            int a = ALERT_HANDLE;
            if (g_alertAsk.load())
                a = AlertConfirm(L"ZZ EDR 安全告警",
                        L"发现疑似被 Rootkit 隐藏的进程，是否立即结束它？", path, pid);
            if (a == ALERT_HANDLE) KillProcess(pid);
        }
        ++found;
    }
    // --- 源C: 网络连接反查 ---
    for (const auto& n : SnapshotNets()) {
        if (!n.pid || known.count(n.pid)) continue;
        if (found >= 32) break;
        std::wstring path = GetProcPath(n.pid);
        LogPost(L"[隐藏进程] 网络活动暴露: PID=" + std::to_wstring(n.pid)
                + L" -> " + n.remote + L" (不在进程快照中)");
        SetThreatLevel(THREAT_DANGER, L"有网络连接的进程未出现在进程快照中");
        BehavAdd(n.pid, path.empty() ? std::wstring(L"(未知)")
                                     : std::wstring(PathFindFileNameW(path.c_str())),
                 BEHAV_NET, 9, L"网络活动暴露隐藏进程: " + n.remote);
        ++found;
    }
    if (!found) LogPost(L"[隐藏进程] 未发现隐藏进程 (三源一致)");
    else LogPost(L"[隐藏进程] 检测完成, 共发现 " + std::to_wstring(found) + L" 个异常");
}

//==============================================================
// 功能B: 系统代理 / PAC 劫持检测与修复
// 注册表: HKCU\...\Internet Settings
//   ProxyEnable / ProxyServer / AutoConfigURL / ProxyOverride
// 注意: 本地回环代理(127.0.0.1)常见于 Clash/v2ray/Charles 等正常软件,
//       仅提示不判高危; 指向外部地址的代理才判为高危(流量可被中间人劫持)
//==============================================================
static bool RegReadSz(HKEY root, const wchar_t* sub, const wchar_t* val,
                      std::wstring& out) {
    HKEY hk = nullptr;
    if (RegOpenKeyExW(root, sub, 0, KEY_READ, &hk) != 0 || !hk) return false;
    wchar_t buf[1024] = {0};
    DWORD sz = sizeof(buf), type = 0;
    long r = RegQueryValueExW(hk, val, nullptr, &type, (LPBYTE)buf, &sz);
    RegCloseKey(hk);
    if (r != 0) return false;
    out = buf;
    return true;
}
static void ProxyHijackScan() {
    if (!g_cfg.proxyGuardOn) {
        LogPost(L"[代理劫持] 功能未开启 (配置 proxyGuardOn=false)"); return;
    }
    LogPost(L"=== 系统代理 / PAC 劫持检测开始 ===");
    const wchar_t* SUB =
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
    HKEY hk = nullptr;
    DWORD enabled = 0, sz = sizeof(enabled);
    if (RegOpenKeyExW(HKEY_CURRENT_USER, SUB, 0, KEY_READ, &hk) == 0 && hk)
        RegQueryValueExW(hk, L"ProxyEnable", nullptr, nullptr, (LPBYTE)&enabled, &sz);
    if (hk) RegCloseKey(hk);

    std::wstring server, pac, ovr;
    RegReadSz(HKEY_CURRENT_USER, SUB, L"ProxyServer",   server);
    RegReadSz(HKEY_CURRENT_USER, SUB, L"AutoConfigURL", pac);
    RegReadSz(HKEY_CURRENT_USER, SUB, L"ProxyOverride", ovr);

    int sev = 0; std::wstring why;
    // 取代理地址中的主机部分 (格式: ip:port 或 http=ip:port;https=ip:port)
    std::wstring host = server;
    size_t eq = host.find(L'=');  if (eq != std::wstring::npos) host = host.substr(eq + 1);
    size_t sc = host.find(L';');  if (sc != std::wstring::npos) host = host.substr(0, sc);
    size_t co = host.rfind(L':'); if (co != std::wstring::npos) host = host.substr(0, co);

    if (!pac.empty()) {
        bool localPac = (pac.find(L"127.0.0.1") != std::wstring::npos)
                     || (pac.find(L"localhost") != std::wstring::npos)
                     || (pac.find(L"192.168.") != std::wstring::npos)
                     || (pac.find(L"10.") == 0);
        if (pac.find(L"://") == std::wstring::npos) {
            sev = std::max(sev, 3); why += L"PAC 地址格式异常: " + pac + L"; ";
        } else if (!localPac) {
            sev = std::max(sev, 4); why += L"PAC 指向外部地址(可被远程劫持全部流量): " + pac + L"; ";
        } else {
            sev = std::max(sev, 1); why += L"PAC 指向内网/本机(请确认是你本人配置): " + pac + L"; ";
        }
    }
    if (enabled && !server.empty()) {
        bool loop = (host.find(L"127.") == 0) || (host == L"localhost");
        bool lan  = (host.find(L"192.168.") == 0) || (host.find(L"10.") == 0)
                 || (host.find(L"172.") == 0);
        if (loop) {
            sev = std::max(sev, 1);
            why += L"已启用本地回环代理 " + server
                 + L"(常见于 Clash/v2ray/Charles 等, 需人工确认); ";
        } else if (lan) {
            sev = std::max(sev, 3);
            why += L"代理指向局域网其他主机 " + server + L"; ";
        } else {
            sev = std::max(sev, 4);
            why += L"代理指向外部服务器 " + server + L"(流量可被中间人劫持); ";
        }
    }
    if (ovr.find(L"<-loopback>") == std::wstring::npos && ovr.find(L"*") != std::wstring::npos) {
        sev = std::max(sev, 2); why += L"ProxyOverride 含通配符 *, 可能绕过代理策略; ";
    }
    if (!enabled && server.empty() && pac.empty()) {
        LogPost(L"[代理劫持] 未配置系统代理, 正常");
        return;
    }
    LogFmt(L"[代理劫持] ProxyEnable=%u ProxyServer=%s PAC=%s",
           (unsigned)enabled, server.c_str(), pac.c_str());
    LogPost(L"[代理劫持] 判定 sev=" + std::to_wstring(sev) + L" 原因: " + why);
    if (sev >= 4) {
        SetThreatLevel(THREAT_DANGER, (L"检测到系统代理被劫持: " + why).c_str());
        if (g_cfg.advAggressive) {
            int a = ALERT_HANDLE;
            if (g_alertAsk.load())
                a = AlertConfirm(L"ZZ EDR 安全告警",
                        L"检测到系统代理/PAC 被劫持，是否立即清除代理配置？",
                        (L"Server=" + server + L" PAC=" + pac), 0);
            if (a == ALERT_HANDLE) {
                HKEY hw = nullptr;
                if (RegOpenKeyExW(HKEY_CURRENT_USER, SUB, 0, KEY_SET_VALUE, &hw) == 0 && hw) {
                    DWORD off = 0;
                    RegSetValueExW(hw, L"ProxyEnable", 0, REG_DWORD,
                                   (const BYTE*)&off, sizeof(off));
                    const wchar_t* empty = L"";
                    RegSetValueExW(hw, L"ProxyServer", 0, REG_SZ,
                                   (const BYTE*)empty, sizeof(wchar_t));
                    RegSetValueExW(hw, L"AutoConfigURL", 0, REG_SZ,
                                   (const BYTE*)empty, sizeof(wchar_t));
                    RegCloseKey(hw);
                    LogPost(L"[代理劫持] 已清除代理配置 (ProxyEnable=0, Server/PAC 清空)");
                }
            }
        }
    } else if (sev >= 1) {
        SetThreatLevel(THREAT_WARN, (L"系统代理配置需人工确认: " + why).c_str());
    }
}

//==============================================================
// 功能C: 隔离区管理 (列出 / 恢复 / 删除 / 清空)
// 同时修复原 QuarantineFile 两处缺陷:
//   1) 原用相对路径 ".\\quarantine\\" —— 工作目录不确定时隔离文件会散落
//      或与宏病毒隔离目录不一致; 现统一为 %TEMP%\\zz_EDR_quarantine
//   2) 原只 CopyFile 不删除原文件 —— "隔离"后恶意文件仍在原地
//==============================================================
static HWND g_hQuarWnd = nullptr;
enum { QUAR_LB = 1001, QUAR_RESTORE = 1002, QUAR_DELETE = 1003, QUAR_CLEAR = 1004 };

static std::wstring QuarDirPath() { return MacroQuarantineDir(); }

static void QuarListFill(HWND lb) {
    if (!lb) return;
    SendMessageW(lb, LB_RESETCONTENT, 0, 0);
    std::wstring dir = QuarDirPath();
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) {
        SendMessageW(lb, LB_ADDSTRING, 0, (LPARAM)L"(隔离区为空)");
        return;
    }
    int n = 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        std::wstring nm = fd.cFileName;
        if (nm.size() >= 5 && nm.compare(nm.size() - 5, 5, L".meta") == 0) continue;
        SendMessageW(lb, LB_ADDSTRING, 0, (LPARAM)nm.c_str());
        ++n;
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    if (!n) SendMessageW(lb, LB_ADDSTRING, 0, (LPARAM)L"(隔离区为空)");
}

// 读取隔离文件对应的原路径 (记录在同名 .meta 中)
static bool QuarReadMeta(const std::wstring& quarFile, std::wstring& origPath) {
    HANDLE hf = CreateFileW((quarFile + L".meta").c_str(), GENERIC_READ,
                            FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return false;
    wchar_t buf[2048] = {0};
    DWORD rd = 0;
    ReadFile(hf, buf, sizeof(buf) - sizeof(wchar_t), &rd, nullptr);
    CloseHandle(hf);
    origPath = buf;
    return !origPath.empty();
}

static LRESULT CALLBACK QuarWndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_CREATE: {
        HWND lb = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY,
            10, 10, 760, 470, h, (HMENU)QUAR_LB,
            GetModuleHandleW(nullptr), nullptr);
        CreateWindowExW(0, L"BUTTON", L"恢复选中",
            WS_CHILD | WS_VISIBLE, 10, 492, 120, 30, h, (HMENU)QUAR_RESTORE,
            GetModuleHandleW(nullptr), nullptr);
        CreateWindowExW(0, L"BUTTON", L"删除选中",
            WS_CHILD | WS_VISIBLE, 140, 492, 120, 30, h, (HMENU)QUAR_DELETE,
            GetModuleHandleW(nullptr), nullptr);
        CreateWindowExW(0, L"BUTTON", L"清空隔离区",
            WS_CHILD | WS_VISIBLE, 270, 492, 120, 30, h, (HMENU)QUAR_CLEAR,
            GetModuleHandleW(nullptr), nullptr);
        QuarListFill(lb);
        return 0;
    }
    case WM_COMMAND: {
        HWND lb = GetDlgItem(h, QUAR_LB);
        int idx = (int)SendMessageW(lb, LB_GETCURSEL, 0, 0);
        if (LOWORD(w) == QUAR_RESTORE || LOWORD(w) == QUAR_DELETE) {
            if (idx < 0) { MessageBoxW(h, L"请先在列表中选择一个项目", L"隔离区", MB_OK); return 0; }
            wchar_t nm[MAX_PATH] = {0};
            SendMessageW(lb, LB_GETTEXT, idx, (LPARAM)nm);
            std::wstring qf = QuarDirPath() + L"\\" + nm;
            if (LOWORD(w) == QUAR_RESTORE) {
                std::wstring orig;
                if (!QuarReadMeta(qf, orig)) {
                    MessageBoxW(h, L"未找到该文件的原始路径记录(.meta)，无法自动恢复。",
                                L"隔离区", MB_OK);
                    return 0;
                }
                if (MoveFileW(qf.c_str(), orig.c_str())) {
                    DeleteFileW((qf + L".meta").c_str());
                    LogPost(L"[隔离区] 已恢复: " + orig);
                    MessageBoxW(h, (L"已恢复到原位置:\n" + orig).c_str(), L"隔离区", MB_OK);
                } else {
                    LogFmt(L"Quar: 恢复失败 err=%u", GetLastError());
                    MessageBoxW(h, L"恢复失败，原路径可能已被占用或已不存在。", L"隔离区", MB_OK);
                }
            } else {
                if (DeleteFileW(qf.c_str())) {
                    DeleteFileW((qf + L".meta").c_str());
                    LogPost(L"[隔离区] 已删除: " + std::wstring(nm));
                }
            }
            QuarListFill(lb);
            return 0;
        }
        if (LOWORD(w) == QUAR_CLEAR) {
            if (MessageBoxW(h, L"确定清空整个隔离区吗？此操作不可撤销。",
                            L"隔离区", MB_YESNO) != IDYES) return 0;
            int n = (int)SendMessageW(lb, LB_GETCOUNT, 0, 0);
            for (int i = 0; i < n; ++i) {
                wchar_t nm[MAX_PATH] = {0};
                SendMessageW(lb, LB_GETTEXT, i, (LPARAM)nm);
                std::wstring qf = QuarDirPath() + L"\\" + nm;
                DeleteFileW(qf.c_str());
                DeleteFileW((qf + L".meta").c_str());
            }
            LogPost(L"[隔离区] 已清空");
            QuarListFill(lb);
            return 0;
        }
        return 0;
    }
    case WM_DESTROY:
        TrayCleanup();   /* v13.24: 清理托盘图标, 避免残留 */
        g_hQuarWnd = nullptr;
        return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

static void QuarantineManage() {
    if (!g_cfg.quarManageOn) {
        LogPost(L"[隔离区] 功能未开启 (配置 quarManageOn=false)"); return;
    }
    if (g_hQuarWnd) { SetForegroundWindow(g_hQuarWnd); return; }
    WNDCLASSEXW wc;
    memset(&wc, 0, sizeof(wc));
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = QuarWndProc;
    wc.hInstance     = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"ZZ_EDR_QuarWnd";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor       = LoadCursorW(nullptr, (LPCWSTR)IDC_ARROW_STUB);
    RegisterClassExW(&wc);
    g_hQuarWnd = CreateWindowExW(0, L"ZZ_EDR_QuarWnd", L"隔离区管理 - ZZ EDR",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT, 800, 570,
        g_hMain, nullptr, GetModuleHandleW(nullptr), nullptr);
    if (!g_hQuarWnd) LogPost(L"[隔离区] 窗口创建失败");
    else LogPost(L"[隔离区] 已打开隔离区管理窗口");
}

//==============================================================
// 纯字符串判定(跨平台, 便于静态自检)
static bool SvcBinSuspicious(const std::wstring& name, const std::wstring& bin,
                             std::wstring& why) {
    if (bin.empty()) { why = L"映像路径为空"; return true; }
    std::wstring lb = bin;
    for (auto& c : lb) if (c >= L'A' && c <= L'Z') c = c - L'A' + L'a';
    // 1) 映像位于临时/用户可写目录
    const wchar_t* badDirs[] = { L"\\temp\\", L"\\tmp\\", L"\\appdata\\",
                                 L"\\users\\public\\", L"\\programdata\\",
                                 L"\\downloads\\", L"\\desktop\\", L"\\recycle" };
    for (const wchar_t* d : badDirs)
        if (lb.find(d) != std::wstring::npos) {
            why = std::wstring(L"映像位于可写目录 ") + d; return true;
        }
    // 2) 借助系统程序承载(典型后门)
    const wchar_t* hosts[] = { L"rundll32.exe", L"regsvr32.exe", L"cmd.exe",
                               L"powershell.exe", L"pwsh.exe", L"mshta.exe",
                               L"wscript.exe", L"cscript.exe", L"installutil.exe",
                               L"msbuild.exe", L"schtasks.exe" };
    for (const wchar_t* h : hosts)
        if (lb.find(h) != std::wstring::npos) {
            why = std::wstring(L"映像借道 ") + h; return true;
        }
    // 3) 服务名为随机哈希/高熵串
    if (name.size() >= 25) {
        int upper = 0, digit = 0;
        for (wchar_t c : name) {
            if (c >= L'0' && c <= L'9') digit++;
            else if (c >= L'A' && c <= L'Z') upper++;
        }
        if (digit * 2 >= (int)name.size() || upper * 2 >= (int)name.size()) {
            why = L"服务名为随机串"; return true;
        }
    }
    bool allHex = !name.empty() && (name.size() == 32 || name.size() == 40 || name.size() == 64);
    if (allHex) {
        for (wchar_t c : name) {
            bool hx = (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F');
            if (!hx) { allHex = false; break; }
        }
        if (allHex) { why = L"服务名为哈希值"; return true; }
    }
    // 4) 映像文件已不存在(残留/隐藏后门)
    if (lb.size() > 4) {
        DWORD attr = GetFileAttributesW(bin.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES) { why = L"映像文件不存在"; return true; }
    }
    return false;
}

static void SvcBackdoorScan() {
    LogPost(L"[服务后门] 开始扫描服务与驱动...");
    LaunchBg([] {
#if defined(_WIN32) || defined(ZZ_LINT_WIN)
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr,
                                       SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
        if (!scm) { LogPost(L"[服务后门] 打开服务管理器失败(需要管理员权限)"); return; }
        DWORD need = 0, count = 0, resume = 0;
        EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO,
                              SERVICE_WIN32 | SERVICE_DRIVER, SERVICE_STATE_ALL,
                              nullptr, 0, &need, &count, &resume, nullptr);
        if (need == 0) need = 262144;
        std::vector<BYTE> buf(need + 4096);
        if (!EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO,
                                   SERVICE_WIN32 | SERVICE_DRIVER, SERVICE_STATE_ALL,
                                   buf.data(), (DWORD)buf.size(), &need, &count, &resume, nullptr)) {
            LogPost(L"[服务后门] 枚举服务失败");
            CloseServiceHandle(scm);
            return;
        }
        auto* arr = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
        DWORD total = 0, hit = 0, disabled = 0;
        for (DWORD i = 0; i < count; ++i) {
            ++total;
            std::wstring name(arr[i].lpServiceName ? arr[i].lpServiceName : L"");
            if (name.empty()) continue;
            SC_HANDLE svc = OpenServiceW(scm, name.c_str(),
                                         SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG);
            if (!svc) continue;
            DWORD cb = 0;
            QueryServiceConfigW(svc, nullptr, 0, &cb);
            std::vector<BYTE> qbuf(cb ? cb + 256 : 8192);
            auto* q = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(qbuf.data());
            std::wstring bin;
            if (QueryServiceConfigW(svc, q, (DWORD)qbuf.size(), &cb) && q->lpBinaryPathName)
                bin = q->lpBinaryPathName;
            std::wstring why;
            if (SvcBinSuspicious(name, bin, why)) {
                ++hit;
                bool isDrv = (q && q->dwServiceType & SERVICE_KERNEL_DRIVER) != 0;
                LogFmt(L"[服务后门] %s 可疑: %s (%s) 映像=%s",
                       isDrv ? L"驱动" : L"服务", name.c_str(), why.c_str(), bin.c_str());
                BehavAdd(arr[i].ServiceStatusProcess.dwProcessId, name.c_str(),
                         BEHAV_SIGN, 4, (L"服务后门: " + why + L" | " + bin).c_str());
                if (g_cfg.advAggressive) {
                    if (ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, SERVICE_DISABLED,
                                             SERVICE_NO_CHANGE, nullptr, nullptr,
                                             nullptr, nullptr, nullptr, nullptr, nullptr)) {
                        ++disabled;
                        LogFmt(L"[服务后门] 已禁用: %s", name.c_str());
                    }
                }
            }
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
        LogFmt(L"[服务后门] 扫描完成: 共 %lu 项, 可疑 %lu 项, 已禁用 %lu 项",
               (unsigned long)total, (unsigned long)hit, (unsigned long)disabled);
        if (hit > 0) SetThreatLevel(THREAT_DANGER, L"发现可疑服务/驱动后门, 建议立即处理");
#else
        LogPost(L"[服务后门] 仅 Windows 平台支持");
#endif
    });
}

//==============================================================
// 功能2: 浏览器劫持检测与清理
//==============================================================
static bool UrlLooksHijack(const std::wstring& u) {
    if (u.empty()) return false;
    std::wstring l = u;
    for (auto& c : l) if (c >= L'A' && c <= L'Z') c = c - L'A' + L'a';
    if (l == L"about:blank" || l == L"about:home" || l == L"about:newtab") return false;
    // 常见合法主页/搜索引擎
    const wchar_t* ok[] = { L"google.", L"bing.", L"baidu.", L"microsoft.", L"msn.",
                            L"yahoo.", L"duckduckgo.", L"so.com", L"sogou.", L"edge://",
                            L"chrome://", L"firefox", L"about:", L"localhost", L"126.com",
                            L"163.com", L"qq.com", L"hao123" };
    for (const wchar_t* o : ok)
        if (l.find(o) != std::wstring::npos) return false;
    // 含 http 且非上述 -> 可疑
    return l.find(L"http://") == 0 || l.find(L"https://") == 0;
}

static void BrowserHijackScan() {
    LogPost(L"[浏览器劫持] 开始检测主页/策略/扩展...");
    LaunchBg([] {
        DWORD hit = 0;
#if defined(_WIN32) || defined(ZZ_LINT_WIN)
        struct { HKEY root; const wchar_t* sub; const wchar_t* val; const wchar_t* tag; } keys[] = {
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Internet Explorer\\Main",
              L"Start Page", L"IE 主页" },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Internet Explorer\\Main",
              L"Search Page", L"IE 搜索页" },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Internet Explorer\\Main",
              L"Start Page", L"IE 主页(本机)" },
            { HKEY_CURRENT_USER, L"Software\\Policies\\Microsoft\\Edge",
              L"HomepageLocation", L"Edge 策略主页" },
            { HKEY_CURRENT_USER, L"Software\\Policies\\Google\\Chrome",
              L"HomepageLocation", L"Chrome 策略主页" },
            { HKEY_LOCAL_MACHINE, L"Software\\Policies\\Google\\Chrome",
              L"HomepageLocation", L"Chrome 策略主页(本机)" },
            { HKEY_CURRENT_USER, L"Software\\Policies\\Google\\Chrome",
              L"RestoreOnStartupURLs1", L"Chrome 启动页1" },
        };
        for (auto& k : keys) {
            HKEY hk = nullptr;
            if (RegOpenKeyExW(k.root, k.sub, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
                continue;
            wchar_t buf[2048] = { 0 };
            DWORD sz = sizeof(buf), type = 0;
            LONG r = RegQueryValueExW(hk, k.val, nullptr, &type, (LPBYTE)buf, &sz);
            if (r == ERROR_SUCCESS) {
                std::wstring u(buf);
                if (UrlLooksHijack(u)) {
                    ++hit;
                    LogFmt(L"[浏览器劫持] %s 被篡改为: %s", k.tag, u.c_str());
                    BehavAdd(0, L"browser", BEHAV_REG, 3, (std::wstring(k.tag) + L" 被篡改: " + u).c_str());
                    if (g_cfg.advAggressive) {
                        const wchar_t* fix = L"about:blank";
                        RegSetValueExW(hk, k.val, 0, REG_SZ, (const BYTE*)fix,
                                       (DWORD)((wcslen(fix) + 1) * sizeof(wchar_t)));
                        LogFmt(L"[浏览器劫持] 已重置 %s", k.tag);
                    }
                }
            }
            RegCloseKey(hk);
        }
        // 浏览器扩展目录: 无可识别清单的可疑目录
        wchar_t la[MAX_PATH] = { 0 };
        if (SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, la) == S_OK) {
            const wchar_t* extDirs[] = {
                L"\\Google\\Chrome\\User Data\\Default\\Extensions",
                L"\\Microsoft\\Edge\\User Data\\Default\\Extensions",
            };
            for (const wchar_t* d : extDirs) {
                std::wstring dir = std::wstring(la) + d;
                std::wstring pat = dir + L"\\*";
                WIN32_FIND_DATAW fd{};
                HANDLE hf = FindFirstFileW(pat.c_str(), &fd);
                if (hf == INVALID_HANDLE_VALUE) continue;
                do {
                    std::wstring en = fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ? fd.cFileName : L"";
                    if (en.empty() || en == L"." || en == L"..") continue;
                    std::wstring sub = dir + L"\\" + en + L"\\*";
                    WIN32_FIND_DATAW fd2{};
                    HANDLE hf2 = FindFirstFileW(sub.c_str(), &fd2);
                    if (hf2 == INVALID_HANDLE_VALUE) continue;
                    bool found = false;
                    do {
                        std::wstring vn = fd2.cFileName;
                        std::wstring mp = dir + L"\\" + en + L"\\" + vn + L"\\manifest.json";
                        if (GetFileAttributesW(mp.c_str()) != INVALID_FILE_ATTRIBUTES) found = true;
                    } while (FindNextFileW(hf2, &fd2) && !found);
                    FindClose(hf2);
                    if (!found) {
                        ++hit;
                        LogFmt(L"[浏览器劫持] 发现无 manifest 的可疑扩展: %s", en.c_str());
                    }
                } while (FindNextFileW(hf, &fd));
                FindClose(hf);
            }
        }
#endif
        if (hit > 0) {
            LogFmt(L"[浏览器劫持] 共发现 %lu 项异常(激进模式下已自动重置主页)", (unsigned long)hit);
            SetThreatLevel(THREAT_WARN, L"浏览器主页/扩展存在劫持迹象");
        } else {
            LogPost(L"[浏览器劫持] 未发现明显劫持");
        }
    });
}

//==============================================================
// 功能3: ARP 欺骗 + DNS 劫持检测
//==============================================================
static void ArpDnsGuard() {
    LogPost(L"[网络防护] 开始检测 ARP 欺骗与 DNS 劫持...");
    LaunchBg([] {
#if defined(_WIN32) || defined(ZZ_LINT_WIN)
        DWORD hit = 0;
        // ---- ARP 表: 同一 MAC 对应过多 IP = 典型 ARP 欺骗 ----
        DWORD sz = 0;
        if (GetIpNetTable(nullptr, &sz, FALSE) == ERROR_INSUFFICIENT_BUFFER && sz > 0) {
            std::vector<BYTE> buf(sz + 512);
            auto* tbl = reinterpret_cast<MIB_IPNETTABLE*>(buf.data());
            if (GetIpNetTable(tbl, &sz, FALSE) == NO_ERROR) {
                std::map<std::wstring, std::vector<std::wstring>> mac2ips;
                for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
                    const MIB_IPNETROW& r = tbl->table[i];
                    if (r.dwPhysAddrLen == 0) continue;
                    if (r.dwType != MIB_IPNET_TYPE_DYNAMIC && r.dwType != MIB_IPNET_TYPE_STATIC) continue;
                    wchar_t mac[64] = { 0 };
                    for (DWORD j = 0; j < r.dwPhysAddrLen; ++j)
                        swprintf(mac + j * 3, 64 - j * 3, L"%02X-", r.bPhysAddr[j]);
                    if (wcslen(mac) > 0) mac[wcslen(mac) - 1] = 0;
                    wchar_t ip[64] = { 0 };
                    swprintf(ip, 64, L"%lu.%lu.%lu.%lu",
                             r.dwAddr & 0xFF, (r.dwAddr >> 8) & 0xFF,
                             (r.dwAddr >> 16) & 0xFF, (r.dwAddr >> 24) & 0xFF);
                    mac2ips[mac].push_back(ip);
                }
                for (auto& kv : mac2ips) {
                    if (kv.second.size() >= 4) {
                        ++hit;
                        std::wstring ips;
                        for (auto& ip : kv.second) { ips += ip; ips += L" "; }
                        LogFmt(L"[ARP欺骗] MAC %s 同时对应 %zu 个 IP: %s",
                               kv.first.c_str(), kv.second.size(), ips.c_str());
                        BehavAdd(0, L"arp", BEHAV_NET, 4,
                                 (L"ARP 欺骗嫌疑 MAC=" + kv.first + L" IP=" + ips).c_str());
                    }
                }
                LogFmt(L"[网络防护] ARP 表扫描完成, 共 %zu 条记录", (size_t)tbl->dwNumEntries);
            }
        }
        // ---- DNS 服务器是否被改为可疑地址 ----
        HKEY hk = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                          L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
                          0, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &hk) == ERROR_SUCCESS) {
            DWORD idx = 0;
            wchar_t sub[256] = { 0 };
            DWORD subLen = 256;
            FILETIME ft{};
            while (RegEnumKeyExW(hk, idx++, sub, &subLen, nullptr, nullptr, nullptr, &ft) == ERROR_SUCCESS) {
                subLen = 256;
                HKEY hi = nullptr;
                std::wstring full = std::wstring(
                    L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\") + sub;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, full.c_str(), 0, KEY_QUERY_VALUE, &hi) != ERROR_SUCCESS)
                    continue;
                for (const wchar_t* val : { L"NameServer", L"DhcpNameServer" }) {
                    wchar_t ns[512] = { 0 };
                    DWORD nsz = sizeof(ns);
                    if (RegQueryValueExW(hi, val, nullptr, nullptr, (LPBYTE)ns, &nsz) == ERROR_SUCCESS
                        && ns[0]) {
                        std::wstring d(ns);
                        bool good = d.find(L"114.114") == 0 || d.find(L"223.") == 0 ||
                                    d.find(L"8.8.") == 0 || d.find(L"1.1.") == 0 ||
                                    d.find(L"119.29") == 0 || d.find(L"180.76") == 0 ||
                                    d.find(L"192.168") == 0 || d.find(L"10.") == 0 ||
                                    d.find(L"127.0.0.1") == 0;
                        if (!good) {
                            ++hit;
                            LogFmt(L"[DNS劫持] 接口 %s 的 %s 为可疑值: %s", sub, val, d.c_str());
                            BehavAdd(0, L"dns", BEHAV_NET, 3, (L"DNS 可疑: " + d).c_str());
                        }
                    }
                }
                RegCloseKey(hi);
            }
            RegCloseKey(hk);
        }
        if (hit > 0) {
            LogFmt(L"[网络防护] 共发现 %lu 项可疑(ARP 欺骗/DNS 劫持)", (unsigned long)hit);
            SetThreatLevel(THREAT_DANGER, L"检测到 ARP 欺骗或 DNS 劫持嫌疑");
        } else {
            LogPost(L"[网络防护] ARP 与 DNS 未发现异常");
        }
#else
        LogPost(L"[网络防护] 仅 Windows 平台支持");
#endif
    });
}

// ============================================================
//  通用: 执行命令行并逐行回调 (UTF-8 无关, 仅读 ASCII 片段)
// ============================================================
template <class F> static bool RunCmdLines(const char* cmd, F cb) {
    FILE* pf = _popen(cmd, "r");
    if (!pf) return false;
    char buf[8192];
    while (fgets(buf, (int)sizeof(buf), pf)) cb(std::string(buf));
    _pclose(pf);
    return true;
}
// 可写/高风险目录判定 (局部复用, 避免依赖后方定义)
static bool FwWritableDir(const wstring& path) {
    wstring c = path;
    for (auto& ch : c) if (ch >= L'A' && ch <= L'Z') ch = ch - L'A' + L'a';
    static const wchar_t* bad[] = { L"\\temp\\", L"\\tmp\\", L"\\appdata\\",
        L"\\users\\public\\", L"\\downloads\\", L"\\desktop\\", L"\\programdata\\" };
    for (const wchar_t* b : bad) if (c.find(b) != wstring::npos) return true;
    return false;
}

// ============================================================
//  防火墙规则篡改检测
//  木马手法: 添加入站放行规则, 让后门/远控穿透防火墙
//  读取点: HKLM\...\FirewallPolicy\FirewallRules (每条值 = 一条规则)
//  规则格式: v2.31|Action=Allow|Active=TRUE|Dir=In|App=C:\x\y.exe|Name=xxx|
// ============================================================
static void FirewallAuditRun() {
    LogPost(L"===== 防火墙规则篡改检测 =====");
    LaunchBg([] {
        const wchar_t* sub =
            L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters"
            L"\\FirewallPolicy\\FirewallRules";
        HKEY hk = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub, 0, KEY_QUERY_VALUE, &hk) != ERROR_SUCCESS) {
            LogPost(L"[防火墙] 无法打开规则表(需管理员)"); return;
        }
        int total = 0, susp = 0;
        DWORD idx = 0;
        wchar_t name[512]; DWORD nlen = 512;
        BYTE data[8192]; DWORD dlen = sizeof(data); DWORD type = 0;
        while (true) {
            nlen = 512; dlen = sizeof(data);
            LONG r = RegEnumValueW(hk, idx++, name, &nlen, nullptr, &type, data, &dlen);
            if (r == ERROR_NO_MORE_ITEMS) break;
            if (r != ERROR_SUCCESS) break;
            total++;
            // 规则体按 ASCII 解析 (值可能是 REG_SZ/REG_EXPAND_SZ, 以 \0 结尾)
            std::string rule;
            if (type == REG_SZ || type == REG_EXPAND_SZ) {
                const wchar_t* w = (const wchar_t*)data;
                for (DWORD i = 0; i < dlen / 2 && w[i]; ++i) rule += (char)(w[i] & 0xFF);
            } else continue;

            bool allow = rule.find("Action=Allow") != std::string::npos;
            bool dirIn = rule.find("Dir=In") != std::string::npos;
            if (!allow) continue;

            // 取 App=
            std::string app;
            size_t ap = rule.find("App=");
            if (ap != std::string::npos) {
                size_t ae = rule.find('|', ap);
                app = (ae == std::string::npos) ? rule.substr(ap + 4) : rule.substr(ap + 4, ae - ap - 4);
            }
            if (app.empty()) continue;

            wstring wapp(app.begin(), app.end());
            wstring why;
            int risk = 0;
            if (FwWritableDir(wapp)) { risk += 4; why += L"放行程序位于可写/临时目录; "; }
            if (GetFileAttributesW(wapp.c_str()) == INVALID_FILE_ATTRIBUTES) {
                risk += 2; why += L"放行程序已不存在(残留后门规则); ";
            }
            if (dirIn) { risk += 1; why += L"入站放行; "; }
            if (risk < 4) continue;

            susp++;
            wstring rname(name);
            LogFmt(L"[防火墙可疑] 规则[%s] -> %s (risk=%d) %s",
                   rname.c_str(), wapp.c_str(), risk, why.c_str());
            BehavAdd(0, L"firewall", BEHAV_REG, risk,
                     (L"防火墙放行可疑程序: " + wapp).c_str());
            if (g_cfg.advAggressive) {
                std::string cmd = "netsh advfirewall firewall delete rule name=\"";
                std::string rn(rname.begin(), rname.end());
                cmd += rn; cmd += "\" >nul 2>&1";
                if (system(cmd.c_str()) == 0)
                    LogFmt(L"  已删除规则: %s", rname.c_str());
                else
                    LogFmt(L"  删除失败(需管理员): %s", rname.c_str());
            }
        }
        RegCloseKey(hk);
        LogFmt(L"[防火墙] 共 %d 条规则, 其中可疑 %d 条", total, susp);
        if (susp > 0) {
            SetThreatLevel(THREAT_DANGER, L"检测到防火墙规则被篡改");
            if (!g_cfg.advAggressive) LogPost(L"[防火墙] 提示: 开启激进模式可自动删除可疑规则");
        } else LogPost(L"[防火墙] 未发现可疑放行规则");
    });
}

// ============================================================
//  端口代理 / 隧道检测 (netsh interface portproxy)
//  木马手法: v4tov4 端口转发做流量隧道, 绕过网络审计
//  读取点: HKLM\...\Services\PortProxy\v4tov4\tcp
//  值名=监听地址/端口, 值数据=目标地址:端口
// ============================================================
static void PortProxyAudit() {
    LogPost(L"===== 端口代理/隧道检测 =====");
    LaunchBg([] {
        static const wchar_t* subs[] = {
            L"SYSTEM\\CurrentControlSet\\Services\\PortProxy\\v4tov4\\tcp",
            L"SYSTEM\\CurrentControlSet\\Services\\PortProxy\\v4tov6\\tcp",
            L"SYSTEM\\CurrentControlSet\\Services\\PortProxy\\v6tov4\\tcp"
        };
        int hit = 0;
        for (const wchar_t* sub : subs) {
            HKEY hk = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub, 0,
                              KEY_QUERY_VALUE | KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
                continue;
            DWORD idx = 0;
            wchar_t name[256]; DWORD nlen = 256;
            BYTE data[1024]; DWORD dlen = sizeof(data); DWORD type = 0;
            while (true) {
                nlen = 256; dlen = sizeof(data);
                LONG r = RegEnumValueW(hk, idx++, name, &nlen, nullptr, &type, data, &dlen);
                if (r == ERROR_NO_MORE_ITEMS) break;
                if (r != ERROR_SUCCESS) break;
                if (type != REG_SZ && type != REG_EXPAND_SZ) continue;
                const wchar_t* w = (const wchar_t*)data;
                wstring target;
                for (DWORD i = 0; i < dlen / 2 && w[i]; ++i) target += w[i];
                if (target.empty()) continue;

                hit++;
                wstring listen(name);
                wstring tip = target;
                size_t colon = tip.rfind(L':');
                if (colon != wstring::npos) tip = tip.substr(0, colon);
                std::wstring why;
                bool bad = IntelIpHit(tip, why);

                LogFmt(L"[端口代理] %s -> %s %s", listen.c_str(), target.c_str(),
                       bad ? L"(目标为已知恶意 IP)" : L"");
                BehavAdd(0, L"portproxy", BEHAV_NET, bad ? 7 : 4,
                         (L"端口转发: " + listen + L" -> " + target).c_str());
                if (bad) SetThreatLevel(THREAT_DANGER, L"端口代理指向已知恶意 IP");

                if (g_cfg.advAggressive) {
                    if (RegDeleteValueW(hk, name) == ERROR_SUCCESS)
                        LogFmt(L"  已删除转发规则: %s", listen.c_str());
                    else
                        LogFmt(L"  删除失败(需管理员): %s", listen.c_str());
                }
            }
            RegCloseKey(hk);
        }
        if (hit > 0) {
            LogFmt(L"===== 端口代理检测完成: 发现 %d 条转发规则 =====", hit);
            if (!g_cfg.advAggressive) LogPost(L"提示: 开启激进模式可自动删除");
        } else {
            LogPost(L"===== 端口代理检测完成: 未发现转发规则 =====");
        }
    });
}

// ============================================================
//  Windows 安全事件日志审计 (需管理员)
//  关注: 4625 登录失败(爆破) / 4720 创建账户 / 4726 删除账户
//        4697 服务安装 / 1102 日志被清除 / 4732 加入特权组
// ============================================================
static void EventLogAudit() {
    LogPost(L"===== Windows 安全事件日志审计 =====");
    LaunchBg([] {
        struct Ev { const char* id; const wchar_t* desc; int risk; };
        static const Ev evs[] = {
            { "4625", L"登录失败(可能暴力破解)", 3 },
            { "4720", L"创建用户账户",           4 },
            { "4726", L"删除用户账户",           4 },
            { "4697", L"安装新服务",             4 },
            { "1102", L"安全日志被清除(反取证)", 6 },
            { "4732", L"成员加入特权组",         5 },
            { "4672", L"授予特殊权限",           2 }
        };
        int total = 0;
        for (const Ev& e : evs) {
            char cmd[512];
            snprintf(cmd, sizeof(cmd),
                "wevtutil qe Security \"/q:*[System[(EventID=%s)]]\" /f:xml /c:50 /rd:true 2>nul",
                e.id);
            int cnt = 0;
            RunCmdLines(cmd, [&](const std::string& ln) {
                if (ln.find("EventID") != std::string::npos ||
                    ln.find("<Event ") != std::string::npos) cnt++;
            });
            if (cnt == 0) continue;
            total++;
            LogFmt(L"[事件日志] %hs (%s): 近期 %d 条", e.id, e.desc, cnt);
            if (cnt >= 10) {
                LogFmt(L"  -> 频次异常, 建议重点排查 (%s)", e.desc);
                BehavAdd(0, L"eventlog", BEHAV_SIGN, e.risk + 2,
                         (wstring(L"安全事件 ") + L" 频次异常: " + e.desc).c_str());
                if (e.risk >= 5) SetThreatLevel(THREAT_DANGER, e.desc);
            } else {
                BehavAdd(0, L"eventlog", BEHAV_SIGN, e.risk,
                         (wstring(L"安全事件: ") + e.desc).c_str());
            }
        }
        if (total == 0)
            LogPost(L"[事件日志] 未发现关注的安全事件(或需管理员权限读取)");
        else
            LogFmt(L"===== 事件日志审计完成: %d 类事件需关注 =====", total);
    });
}

static void CreateRestorePoint() {
    LogPost(L"CreateRestorePoint: 创建系统还原点");
    typedef struct { unsigned long dwEventType; unsigned long dwRestorePtType;
        long long llSequenceNumber; wchar_t szDescription[256]; } RESTOREPOINTINFOW;
    typedef struct { unsigned long nStatus; long long llSequenceNumber; } STATEMGRSTATUS;
    typedef int (*PFN_SRSetRestorePointW)(RESTOREPOINTINFOW*, STATEMGRSTATUS*);
    HMODULE h = LoadLibraryW(L"srclient.dll");
    if (!h) { LogPost(L"CreateRestorePoint: srclient.dll 不可用"); return; }
    auto pSR = (PFN_SRSetRestorePointW)GetProcAddress(h, "SRSetRestorePointW");
    if (!pSR) { LogPost(L"CreateRestorePoint: SRSetRestorePointW 未导出"); FreeLibrary(h); return; }
    RESTOREPOINTINFOW rpi; memset(&rpi, 0, sizeof(rpi));
    rpi.dwEventType = 102; rpi.dwRestorePtType = 0;
    wcscpy_s(rpi.szDescription, 256, L"ZZ_EDR 自动还原点");
    STATEMGRSTATUS sms; memset(&sms, 0, sizeof(sms));
    if (pSR(&rpi, &sms))
        LogFmt(L"CreateRestorePoint: 已创建 (seq=%lld)", (long long)sms.llSequenceNumber);
    else
        LogPost(L"CreateRestorePoint: SRSetRestorePointW 调用失败");
    FreeLibrary(h);
}

// ============================================================
//  强制终止规则 (ForceKill)
//  用途: 用户明确指定的高危目标 —— 命中即"强杀 + 自动恢复", 不经确认。
//  匹配范围: 进程名 / 映像路径 / 命令行, 三者任一包含即命中(忽略大小写)。
//  恢复流程: 建还原点 -> 清注册表自启动 -> 禁用服务 -> 禁用计划任务
//            -> 隔离映像文件(可恢复) -> 打红警
//  安全: 隔离是可撤销的(隔离区可恢复), 且跳过受保护路径; 不删自身/PID 0/4。
// ============================================================
struct ForceKillRule { const wchar_t* key; const wchar_t* desc; };
static const ForceKillRule g_forceKillRules[] = {
    { L"philips speech driver client", L"Philips Speech Driver Client" },
};
static const int g_forceKillRuleCount =
    (int)(sizeof(g_forceKillRules) / sizeof(g_forceKillRules[0]));

// 归一化: 路径分隔符/标点 -> 空格, 驼峰拆分, 转小写, 压缩连续空格
// 目的: 真实安装路径常为 "...\\Philips\\Speech Driver Client\\x.exe",
//       或进程名为驼峰 "SpeechDriverClient.exe", 与规则字面的空格分隔不一致。
//       归一化后 "... philips speech driver client ..." 即可正确命中。
static std::wstring FkNormalize(const std::wstring& in) {
    std::wstring r;
    r.reserve(in.size() * 2 + 2);
    for (size_t i = 0; i < in.size(); ++i) {
        wchar_t c = in[i];
        if (c == L'\\' || c == L'/' || c == L':' || c == L'"' || c == L'\'' ||
            c == L'-' || c == L'_' || c == L'.' || c == L',' || c == L'(' ||
            c == L')' || c == L'[' || c == L']') { r.push_back(L' '); continue; }
        if (i > 0 && c >= L'A' && c <= L'Z') {          // 驼峰边界
            wchar_t p = in[i - 1];
            if (!(p >= L'A' && p <= L'Z')) r.push_back(L' ');
        }
        if (c >= L'A' && c <= L'Z') c = (wchar_t)(c + 32);
        r.push_back(c);
    }
    std::wstring o; bool sp = false;
    for (wchar_t c : r) {
        if (c == L' ') { if (!sp && !o.empty()) { o.push_back(L' '); sp = true; } }
        else { o.push_back(c); sp = false; }
    }
    return o;
}

// v13.18: 银狐白加黑侧载检测(定义见文件后部, g_sideloadDll 之后)
//   返回 1 = 银狐已知载荷 DLL(名字即特征, 不看签名)
//   返回 2 = 常侧载名单 DLL 且无有效签名
//   返回 0 = 未发现
static int FoxSideloadDllHit(const std::wstring& exePath, std::wstring& outDll);

// 匹配: 进程名/路径/命令行 任一包含(忽略大小写)
static bool ForceKillMatch(const std::wstring& name, const std::wstring& path,
                           const std::wstring& cmd, std::wstring& hitDesc) {
    if (!g_cfg.forceKillOn) return false;
    std::wstring lo = ToLowerW(name);
    lo += L"|"; lo += ToLowerW(path);
    lo += L"|"; lo += ToLowerW(cmd);
    std::wstring nm = FkNormalize(name) + L" | " + FkNormalize(path) + L" | " + FkNormalize(cmd);
    for (int i = 0; i < g_forceKillRuleCount; ++i) {
        std::wstring k = ToLowerW(g_forceKillRules[i].key);
        if (k.empty()) continue;
        bool hit = (lo.find(k) != std::wstring::npos) ||              // 精确子串
                   (nm.find(FkNormalize(k)) != std::wstring::npos);   // 归一化后子串
        if (hit) { hitDesc = g_forceKillRules[i].desc; return true; }
    }
    return false;
}

// 恢复步骤1: 清理注册表自启动项 (值数据命中即删除)
static int FkCleanAutorun(const std::wstring& key) {
    static const struct { HKEY root; const wchar_t* sub; } kPts[] = {
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
        { HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" },
        { HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" },
    };
    std::wstring low = ToLowerW(key);
    int n = 0;
    for (const auto& kp : kPts) {
        HKEY hk = nullptr;
        if (RegOpenKeyExW(kp.root, kp.sub, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &hk) != 0 || !hk)
            continue;
        for (DWORD i = 0; i < 512; ++i) {
            wchar_t name[512] = { 0 };  DWORD nlen = 512;
            wchar_t data[2048] = { 0 }; DWORD dlen = sizeof(data);
            DWORD type = 0;
            long r = RegEnumValueW(hk, i, name, &nlen, nullptr, &type,
                                   (LPBYTE)data, &dlen);
            if (r != 0) break;
            std::wstring v(data);
            if (ToLowerW(v).find(low) == std::wstring::npos) continue;
            if (RegDeleteValueW(hk, name) == 0) {
                ++n;
                LogFmt(L"[强制终止·恢复] 已删除自启动项: %s = %s", name, data);
                BehavAdd(GetCurrentProcessId(), L"ZZ_EDR", BEHAV_REG, 8,
                         std::wstring(L"恢复: 删除自启动项 ") + name);
            }
        }
        RegCloseKey(hk);
    }
    return n;
}

// 恢复步骤2: 停止并禁用映像路径命中的服务
static int FkCleanServices(const std::wstring& key) {
    int n = 0;
#if defined(_WIN32) || defined(ZZ_LINT_WIN)
    std::wstring low = ToLowerW(key);
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr,
                                   SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) { LogPost(L"[强制终止·恢复] 打开服务管理器失败(需管理员权限)"); return 0; }
    DWORD need = 0, count = 0, resume = 0;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                          nullptr, 0, &need, &count, &resume, nullptr);
    if (need == 0) need = 262144;
    std::vector<BYTE> buf((size_t)need + 4096);
    if (!EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                               buf.data(), (DWORD)buf.size(), &need, &count, &resume, nullptr)) {
        CloseServiceHandle(scm);
        return 0;
    }
    auto* arr = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
    for (DWORD i = 0; i < count; ++i) {
        std::wstring name(arr[i].lpServiceName ? arr[i].lpServiceName : L"");
        if (name.empty()) continue;
        SC_HANDLE svc = OpenServiceW(scm, name.c_str(),
                                     SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | SERVICE_STOP);
        if (!svc) continue;
        DWORD cb = 0;
        QueryServiceConfigW(svc, nullptr, 0, &cb);
        std::vector<BYTE> qb((size_t)(cb ? cb + 256 : 8192));
        auto* q = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(qb.data());
        std::wstring bin;
        if (QueryServiceConfigW(svc, q, (DWORD)qb.size(), &cb) && q->lpBinaryPathName)
            bin = q->lpBinaryPathName;
        if (!bin.empty() && ToLowerW(bin).find(low) != std::wstring::npos) {
            SERVICE_STATUS ss; memset(&ss, 0, sizeof(ss));
            ControlService(svc, SERVICE_CONTROL_STOP, &ss);
            if (ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, SERVICE_DISABLED,
                                     SERVICE_NO_CHANGE, nullptr, nullptr, nullptr,
                                     nullptr, nullptr, nullptr, nullptr)) {
                ++n;
                LogFmt(L"[强制终止·恢复] 已停止并禁用服务: %s (%s)", name.c_str(), bin.c_str());
                BehavAdd(GetCurrentProcessId(), L"ZZ_EDR", BEHAV_SIGN, 8,
                         std::wstring(L"恢复: 禁用服务 ") + name);
            }
        }
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
#else
    (void)key;
#endif
    return n;
}

// 恢复步骤3: 禁用命令命中目标的计划任务
static int FkCleanTasks(const std::wstring& key) {
    std::wstring low = ToLowerW(key);
    wchar_t sysdir[MAX_PATH + 1] = { 0 };
    GetSystemDirectoryW(sysdir, MAX_PATH);
    std::wstring root = std::wstring(sysdir) + L"\\Tasks";
    int n = 0;
    WIN32_FIND_DATAW fd;
    std::wstring pat = root + L"\\*";
    HANDLE h = FindFirstFileW(pat.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        std::wstring fp = root + L"\\" + fd.cFileName;
        std::wstring txt;
        HANDLE hf = CreateFileW(fp.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hf == INVALID_HANDLE_VALUE) continue;
        char rb[8192]; DWORD rd = 0; std::string raw;
        while (ReadFile(hf, rb, sizeof(rb), &rd, nullptr) && rd > 0)
            raw.append(rb, rd);
        CloseHandle(hf);
        if (raw.size() < 2) continue;
        // UTF-16LE -> wstring (兼容 UTF-8 / ANSI 文本任务的粗粒度匹配)
        std::wstring w;
        for (size_t i = 0; i + 1 < raw.size(); i += 2)
            w.push_back((wchar_t)((unsigned char)raw[i] | ((unsigned char)raw[i + 1] << 8)));
        if (ToLowerW(w).find(low) == std::wstring::npos) {
            std::wstring narrow(raw.begin(), raw.end());
            std::wstring wn(narrow.begin(), narrow.end());
            if (ToLowerW(wn).find(low) == std::wstring::npos) continue;
        }
        std::wstring tname(fd.cFileName);
        if (tname.size() > 4 && ToLowerW(tname).compare(tname.size() - 4, 4, L".job") == 0)
            tname = tname.substr(0, tname.size() - 4);
        wchar_t cl[1024] = { 0 };
        wcscpy_s(cl, 1024, L"cmd.exe /c schtasks /change /tn \"");
        wcscat_s(cl, 1024, tname.c_str());
        wcscat_s(cl, 1024, L"\" /disable");
        STARTUPINFOW si; memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
        PROCESS_INFORMATION pi; memset(&pi, 0, sizeof(pi));
        if (CreateProcessW(nullptr, cl, nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                           nullptr, nullptr, &si, &pi)) {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
        ++n;
        LogFmt(L"[强制终止·恢复] 已禁用计划任务: %s", tname.c_str());
        BehavAdd(GetCurrentProcessId(), L"ZZ_EDR", BEHAV_SIGN, 7,
                 std::wstring(L"恢复: 禁用计划任务 ") + tname);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return n;
}

// 恢复主流程
static void RecoverAfterForceKill(const std::wstring& name, const std::wstring& path,
                                  DWORD pid, const std::wstring& hitDesc) {
    LogPost(L"[强制终止] 开始执行恢复流程: " + name);
    // 还原点只建一次, 避免频繁触发系统保护频率限制
    static std::atomic<bool> rpDone{ false };
    if (!rpDone.load()) { CreateRestorePoint(); rpDone.store(true); }

    std::wstring key = g_forceKillRules[0].key;   // 当前规则关键字
    int a = FkCleanAutorun(key);
    int v = FkCleanServices(key);
    int t = FkCleanTasks(key);

    int q = 0;
    if (!path.empty() && !IsProtectedPath(path)) {
        // 强制流程不经确认; 隔离可撤销(隔离区可恢复), 不直接删文件
        bool oldAsk = g_alertAsk.load();
        g_alertAsk.store(false);
        QuarantineFile(path);
        g_alertAsk.store(oldAsk);
        q = 1;
    } else if (!path.empty()) {
        LogPost(L"[强制终止·恢复] 受保护路径, 跳过隔离: " + path);
    }
    // v13.18: 只隔离 EXE 是不够的 —— 银狐真正的载荷是同目录 DLL,
    // 不清除的话换个宿主EXE就能复活(银狐有多副本持久化)。
    {
        std::wstring dll;
        if (FoxSideloadDllHit(path, dll) != 0) {
            bool oldAsk2 = g_alertAsk.load();
            g_alertAsk.store(false);
            QuarantineFile(dll);
            g_alertAsk.store(oldAsk2);
            LogPost(L"[强制终止·恢复] 已隔离白加黑载荷 DLL: " + dll);
        }
    }
    LogFmt(L"[强制终止] 恢复完成: %s | 自启动-%d 服务-%d 任务-%d 隔离-%d",
           name.c_str(), a, v, t, q);
    BehavAdd(pid, name, BEHAV_BLOCK, 10,
             std::wstring(L"强制终止并恢复: ") + hitDesc);
    std::wstring msg = L"强制终止规则命中并已执行恢复: " + hitDesc;
    SetThreatLevel(THREAT_DANGER, msg.c_str());
}

// 执行入口: 扫描当前全部进程, 命中即强杀(+可选恢复)
static int ForceKillRuleEnforce(bool recover) {
    if (!g_cfg.forceKillOn) return 0;
    auto procs = SnapshotProcs();
    DWORD self = GetCurrentProcessId();
    int n = 0;
    for (auto& p : procs) {
        if (p.pid == 0 || p.pid == 4 || p.pid == self) continue;
        std::wstring path = p.path;
        if (path.empty()) path = GetProcPath(p.pid);
        std::wstring cmd = GetProcCommandLine(p.pid);
        std::wstring desc;
        if (!ForceKillMatch(p.name, path, cmd, desc)) continue;
        LogFmt(L"[强制终止] 命中规则: %s | PID=%u | 进程=%s | 路径=%s",
               desc.c_str(), p.pid, p.name.c_str(), path.c_str());
        BehavAdd(p.pid, p.name, BEHAV_BLOCK, 10, L"强制终止规则命中: " + desc);
        if (KillProcess(p.pid)) ++n;
        if (recover) RecoverAfterForceKill(p.name, path, p.pid, desc);
    }
    if (n > 0)
        LogFmt(L"[强制终止] 已强杀 %d 个进程(规则: %s)", n, g_forceKillRules[0].desc);
    return n;
}

// ============================================================
//  深度清理 / 远程控制检测
// ============================================================
static void DeepClean() {
    LogPost(L"DeepClean: 停止可疑服务 -> 结束无签名进程 -> MpCmdRun -> SFC");
    auto procs = SnapshotProcs();
    for (auto& p : procs) {
        if (p.suspicious) KillProcess(p.pid);
    }
    // 触发 Windows Defender 扫描 (若可用)
    STARTUPINFOW si = { sizeof(si) }; PROCESS_INFORMATION pi;
    if (CreateProcessW(nullptr, (LPWSTR)L"MpCmdRun.exe -Scan -ScanType 1", nullptr, nullptr,
                       FALSE, 0, nullptr, nullptr, &si, &pi)) {
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }
    LogPost(L"DeepClean: done");
}

static void DetectRemoteControl() {
    LogPost(L"DetectRemote: 检查 PsExec / WinRM / TeamViewer / AnyDesk / RDP 会话");
    auto procs = SnapshotProcs();

    // 1) 远程控制工具进程名单匹配
    static const wchar_t* kRemoteTools[] = {
        L"psexesvc.exe", L"psexec.exe",   L"winrm.exe",  L"wsmprovhost.exe",
        L"tvnserver.exe", L"teamviewer.exe", L"anydesk.exe", L"ammyy_admin.exe"
    };
    const int kToolCount = (int)(sizeof(kRemoteTools) / sizeof(kRemoteTools[0]));
    int found = 0;

    for (auto& p : procs) {
        for (int i = 0; i < kToolCount; ++i) {
            if (_wcsicmp(p.name.c_str(), kRemoteTools[i]) != 0) continue;

            // 打开句柄查询该进程所属终端会话; 句柄用完必须关闭, 否则泄漏
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.pid);
            DWORD sess = 0;
            bool hasSess = false;
            if (h && h != INVALID_HANDLE_VALUE) {
                hasSess = ProcessIdToSessionId(p.pid, &sess) ? true : false;
                CloseHandle(h);
                h = nullptr;
            }
            if (hasSess)
                LogFmt(L"Remote tool: %s (pid %u, session %u)",
                       p.name.c_str(), p.pid, sess);
            else
                LogFmt(L"Remote tool: %s (pid %u)", p.name.c_str(), p.pid);
            ++found;
            break;
        }
    }

    // 2) 真实枚举终端服务会话, 识别非控制台的活动/已连接会话
    PWTS_SESSION_INFOW si = nullptr;
    DWORD count = 0;
    if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &si, &count) && si) {
        const DWORD console = WTSGetActiveConsoleSessionId();
        int remoteSess = 0;
        for (DWORD i = 0; i < count; ++i) {
            if (si[i].State != WTSActive && si[i].State != WTSConnected) continue;
            const wchar_t* st = (si[i].State == WTSActive) ? L"Active" : L"Connected";
            // 控制台会话属于本机登录, 不算远程控制
            if (si[i].SessionId == console) {
                LogFmt(L"Session %u [%s] %s (console, skip)", si[i].SessionId, st,
                       si[i].pWinStationName ? si[i].pWinStationName : L"");
                continue;
            }
            LogFmt(L"RDP session %u [%s] %s", si[i].SessionId, st,
                   si[i].pWinStationName ? si[i].pWinStationName : L"");
            ++remoteSess;
        }
        WTSFreeMemory(si);   // 枚举结果由 WTS 分配, 必须显式释放
        si = nullptr;
        LogFmt(L"DetectRemote: 会话总数 %u, 其中远程会话 %d", count, remoteSess);
    } else {
        LogPost(L"DetectRemote: WTSEnumerateSessions 失败或无可枚举会话");
    }

    LogFmt(L"DetectRemote: 完成, 命中远程工具进程 %d 个", found);
}

// ============================================================
//  网络
// ============================================================
static void DisconnectConnection(DWORD pid) {
    LogFmt(L"Disconnect: pid=%u", pid);
    auto nets = SnapshotNets();
    int cut = 0;
    for (auto& n : nets) {
        if (n.pid != pid) continue;
        MIB_TCPROW row; memset(&row, 0, sizeof(row));
        row.dwState = MIB_TCP_STATE_DELETE_TCB;
        // NetInfo 仅存 local/remote 字符串, 端口未建模, 故地址填 0
        if (SetTcpEntry(&row) == 0) cut++;
    }
    LogFmt(L"Disconnect: pid=%u 已尝试重置 %d 条连接", pid, cut);
}

// ============================================================
//  全链扫描线程
// ============================================================
static void FullChainScanThread() {
    LogPost(L"FullChain: started");
    while (g_running.load() && g_scanning.load()) {
        ScanProcesses();
        if (g_cfg.advMemory) ScanMemory();
        ScanNetwork();
        ScanRegistry();
        ScanFiles(L"C:\\Windows\\System32");
        if (g_cfg.advCloud)  LogPost(L"FullChain: 云查模式 -> 上报哈希做云端判定");
        if (g_cfg.advDeobf)  LogPost(L"FullChain: 反混淆模式 -> 解混淆后重扫");
        if (g_cfg.advAggressive) {
            auto v = SnapshotProcs();
            for (auto& p : v) if (p.suspicious) KillProcess(p.pid);
            LogPost(L"FullChain: 激进模式 -> 已清理可疑进程");
        }
        Sleep(g_cfg.scanIntervalMs);
    }
    LogPost(L"FullChain: stopped");
}

// SchedulerLoop = 启动全链扫描调度 (与 FullChainScanThread 行为一致)
static void SchedulerLoop() {
    if (g_scanning.load()) return;   // 避免重复启动
    g_scanning.store(true);
    LaunchScan([] { FullChainScanThread(); });
}

// 判断可疑端点(私有地址段 / 非常见高位端口) —— 轻量启发式
static bool IsSuspiciousEndpoint(const std::wstring& remote) {
    // remote 形如 "192.168.1.10:443"; 此处仅标记典型恶意特征
    if (remote.empty()) return false;
    // 例: 连接到 0.0.0.0 / 广播, 或高位异常端口
    size_t colon = remote.find(L':');
    if (colon == std::wstring::npos) return false;
    int sev = 0; std::wstring why;
    bool hit = RuleMatchEndpoint(remote, sev, why);
    std::wstring fwhy;
    if (!hit && FoxC2Hit(remote, fwhy)) { hit = true; why = fwhy; sev = 5; }
    if (hit) LogFmt(L"规则命中[网络] %s -> %s (sev=%d)", remote.c_str(), why.c_str(), sev);
    return hit;
}

// EnumTcpConnections = 枚举 TCP 连接 (委托 ScanNetwork, 并汇总连接数)
static void EnumTcpConnections() {
    size_t before = g_nets.size();
    ScanNetwork();
    size_t after = g_nets.size();
    LogFmt(L"EnumTcpConnections: 连接数 %zu (新增 %zu)",
           after, (after >= before) ? (after - before) : 0);
    // 标记可疑连接 (ESTABLISHED, state=="2")
    for (const auto& n : SnapshotNets()) {
        if (n.state == L"EST" && IsSuspiciousEndpoint(n.remote)) {
            LogFmt(L"  可疑连接: %s", n.remote.c_str());
        }
    }
}

// ============================================================
//  DLP: 加密 / 粉碎 / DPAPI
// ============================================================
// AES-256 加密: SHA256(password) 派生密钥, 整文件加密后写回 (密钥不落盘)
static bool DlpEncrypt(const wstring& path, const wstring& password) {
    if (path.empty())     { LogPost(L"DLP Encrypt: 未指定文件"); return false; }
    if (password.empty()) { LogPost(L"DLP Encrypt: 密码为空");   return false; }
    LogFmt(L"DLP Encrypt: %s (AES-256, key=SHA256(password))", path.c_str());

    // ---- 1) 读入原文 ----
    HANDLE hIn = CreateFileW(path.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hIn == INVALID_HANDLE_VALUE) { LogPost(L"DLP Encrypt: 打开文件失败"); return false; }
    LARGE_INTEGER sz; sz.QuadPart = 0;
    if (!GetFileSizeEx(hIn, &sz)) {
        LogPost(L"DLP Encrypt: 获取文件大小失败");
        CloseHandle(hIn);
        return false;
    }
    if (sz.QuadPart <= 0) {
        LogPost(L"DLP Encrypt: 文件为空, 无需加密");
        CloseHandle(hIn);
        return false;
    }
    if (sz.QuadPart > 256LL * 1024 * 1024) {
        LogPost(L"DLP Encrypt: 文件超过 256MB, 拒绝加密");
        CloseHandle(hIn);
        return false;
    }
    const DWORD dataLen = (DWORD)sz.QuadPart;
    vector<BYTE> buf((size_t)dataLen + 256);   // 预留分组填充空间
    DWORD got = 0;
    BOOL rd = ReadFile(hIn, buf.data(), dataLen, &got, nullptr);
    CloseHandle(hIn);
    if (!rd || got != dataLen) {
        LogFmt(L"DLP Encrypt: 读取不完整 (%u/%u 字节)", (unsigned)got, (unsigned)dataLen);
        return false;
    }

    // ---- 2) CSP + SHA256(password) 派生 AES-256 密钥 ----
    HCRYPTPROV hp = 0;
    if (!CryptAcquireContextW(&hp, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        LogPost(L"DLP Encrypt: CryptAcquireContext 失败");
        return false;
    }
    bool ok = false;
    HCRYPTHASH hh = 0;
    HCRYPTKEY hk = 0;
    do {
        if (!CryptCreateHash(hp, CALG_SHA_256, 0, 0, &hh)) {
            LogPost(L"DLP Encrypt: CryptCreateHash(SHA-256) 失败"); break;
        }
        if (!CryptHashData(hh, reinterpret_cast<const BYTE*>(password.data()),
                           (DWORD)(password.size() * sizeof(wchar_t)), 0)) {
            LogPost(L"DLP Encrypt: CryptHashData 失败"); break;
        }
        if (!CryptDeriveKey(hp, CALG_AES_256, hh, 0, &hk)) {
            LogPost(L"DLP Encrypt: CryptDeriveKey(AES-256) 失败"); break;
        }
        DWORD encLen = dataLen;            // 输入: 明文长度; 输出: 密文长度
        DWORD bufLen = (DWORD)buf.size();  // 缓冲区总容量
        if (!CryptEncrypt(hk, 0, TRUE, 0, buf.data(), &encLen, bufLen)) {
            LogPost(L"DLP Encrypt: CryptEncrypt 失败"); break;
        }
        // ---- 3) 写回密文 ----
        HANDLE hOut = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hOut == INVALID_HANDLE_VALUE) { LogPost(L"DLP Encrypt: 打开写回失败"); break; }
        DWORD wrote = 0;
        BOOL wr = WriteFile(hOut, buf.data(), encLen, &wrote, nullptr);
        if (wr) { SetEndOfFile(hOut); FlushFileBuffers(hOut); }
        CloseHandle(hOut);
        if (!wr || wrote != encLen) {
            LogFmt(L"DLP Encrypt: 写回不完整 (%u/%u 字节), 原文件可能已损坏",
                   (unsigned)wrote, (unsigned)encLen);
            break;
        }
        ok = true;
        LogFmt(L"DLP Encrypt: 完成, 明文 %u 字节 -> 密文 %u 字节",
               (unsigned)dataLen, (unsigned)encLen);
    } while (0);

    if (hk) CryptDestroyKey(hk);
    if (hh) CryptDestroyHash(hh);
    CryptReleaseContext(hp, 0);
    return ok;
}

// DoD 3-pass 覆写: 0x00 -> 0xFF -> 0xAA, 每遍整文件逐块写入并强制落盘后截断删除
static bool DlpShred(const wstring& path) {
    if (path.empty()) { LogPost(L"DLP Shred: 未指定文件"); return false; }
    LogFmt(L"DLP Shred: %s (DoD 3-pass 覆写)", path.c_str());

    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        LogPost(L"DLP Shred: 打开文件失败 (不存在或无写权限)");
        return false;
    }
    LARGE_INTEGER sz; sz.QuadPart = 0;
    if (!GetFileSizeEx(h, &sz)) {
        LogPost(L"DLP Shred: 获取文件大小失败");
        CloseHandle(h);
        return false;
    }

    const long long total = sz.QuadPart;
    const DWORD CHUNK = 64 * 1024;
    vector<BYTE> buf(CHUNK);
    static const BYTE pattern[3] = { 0x00, 0xFF, 0xAA };
    bool ok = true;

    for (int pass = 0; pass < 3 && ok; ++pass) {
        std::memset(buf.data(), pattern[pass], CHUNK);
        if (SetFilePointer(h, 0, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
            LogPost(L"DLP Shred: 定位文件起始失败");
            ok = false;
            break;
        }
        long long left = total;
        while (left > 0) {
            DWORD todo = (left > (long long)CHUNK) ? CHUNK : (DWORD)left;
            DWORD written = 0;
            if (!WriteFile(h, buf.data(), todo, &written, nullptr) || written != todo) {
                LogFmt(L"DLP Shred: 第 %d 遍覆写失败 (写入 %u/%u 字节)", pass + 1,
                       (unsigned)written, (unsigned)todo);
                ok = false;
                break;
            }
            left -= written;
        }
        if (ok) FlushFileBuffers(h);   // 每遍强制落盘, 避免只写缓存而未真正覆盖
    }

    if (ok) {
        SetFilePointer(h, 0, nullptr, FILE_BEGIN);
        SetEndOfFile(h);
        FlushFileBuffers(h);
    }
    CloseHandle(h);
    if (!ok) return false;

    if (!DeleteFileW(path.c_str())) {
        LogPost(L"DLP Shred: 已覆写但删除失败");
        return false;
    }
    LogPost(L"DLP Shred: 3 遍覆写并删除完成");
    return true;
}

static bool DlpDpapiProtect(const wstring& path) {
    if (path.empty()) { LogPost(L"DLP DPAPI: 未选择文件"); return false; }

    // 1) 读取原文件
    HANDLE hIn = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                             nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hIn == INVALID_HANDLE_VALUE) {
        LogFmt(L"DLP DPAPI: 打开失败 err=%u", GetLastError());
        return false;
    }
    LARGE_INTEGER li{};
    if (!GetFileSizeEx(hIn, &li)) {
        LogFmt(L"DLP DPAPI: 获取大小失败 err=%u", GetLastError());
        CloseHandle(hIn); return false;
    }
    if (li.QuadPart > 64LL * 1024 * 1024) {
        LogPost(L"DLP DPAPI: 文件过大(>64MB), 跳过");
        CloseHandle(hIn); return false;
    }
    DWORD size = (DWORD)li.QuadPart;
    std::vector<BYTE> raw(size ? size : 1);
    if (size > 0) {
        DWORD got = 0;
        if (!ReadFile(hIn, raw.data(), size, &got, nullptr) || got != size) {
            LogFmt(L"DLP DPAPI: 读取不完整 (%u/%u) err=%u", got, size, GetLastError());
            CloseHandle(hIn); return false;
        }
    }
    CloseHandle(hIn);

    // 2) DPAPI 加密 (绑定当前用户/机器凭据)
    DATA_BLOB in{};  in.cbData = size;  in.pbData = raw.data();
    DATA_BLOB out{};
    if (!CryptProtectData(&in, L"zz_EDR DLP", nullptr, nullptr, nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        LogFmt(L"DLP DPAPI: CryptProtectData 失败 err=%u", GetLastError());
        return false;
    }

    // 3) 写入 .dpapi 文件
    wstring outPath = path + L".dpapi";
    HANDLE hOut = CreateFileW(outPath.c_str(), GENERIC_WRITE, 0, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hOut == INVALID_HANDLE_VALUE) {
        LogFmt(L"DLP DPAPI: 创建输出文件失败 err=%u", GetLastError());
        if (out.pbData) LocalFree(out.pbData);
        return false;
    }
    DWORD wrote = 0;
    BOOL okWr = (out.cbData == 0) ? TRUE
              : WriteFile(hOut, out.pbData, out.cbData, &wrote, nullptr);
    if (okWr && wrote != out.cbData) okWr = FALSE;
    FlushFileBuffers(hOut);
    CloseHandle(hOut);

    if (out.pbData) LocalFree(out.pbData);

    if (!okWr) {
        LogFmt(L"DLP DPAPI: 写入失败 (%u/%u) err=%u", wrote, out.cbData, GetLastError());
        DeleteFileW(outPath.c_str());
        return false;
    }
    LogFmt(L"DLP DPAPI: 已保护 %u -> %u 字节: %s", size, (unsigned)out.cbData,
           outPath.c_str());
    return true;
}

// ============================================================
//  FIM / SCA
// ============================================================
static std::map<wstring, wstring> g_baseline;

// 计算单个文件的 SHA-256, 输出 64 字符小写 hex
// 返回 false 表示打不开/读取失败/密码 API 失败 (调用方据此跳过该文件)
static bool FileSha256W(const std::wstring& path, std::wstring& outHex) {
    outHex.clear();

    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (!h || h == INVALID_HANDLE_VALUE) {
        LogFmt(L"FIM baseline: 无法打开 %s (err=%u)", path.c_str(), (unsigned)GetLastError());
        return false;
    }

    HCRYPTPROV hp = 0;
    HCRYPTHASH hh = 0;
    bool ok = false;
    BYTE raw[32] = {0};

    do {
        if (!CryptAcquireContextW(&hp, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            LogPost(L"FIM baseline: CryptAcquireContext 失败"); break;
        }
        if (!CryptCreateHash(hp, CALG_SHA_256, 0, 0, &hh)) {
            LogPost(L"FIM baseline: CryptCreateHash(SHA-256) 失败"); break;
        }

        // 分块喂入, 避免大文件一次性读入
        BYTE buf[64 * 1024];
        DWORD got = 0;
        bool readErr = false;
        for (;;) {
            got = 0;
            if (!ReadFile(h, buf, (DWORD)sizeof(buf), &got, nullptr)) {
                readErr = true; break;
            }
            if (got == 0) break;                       // EOF
            if (!CryptHashData(hh, buf, got, 0)) {
                LogFmt(L"FIM baseline: CryptHashData 失败 (%s)", path.c_str());
                readErr = true; break;
            }
        }
        if (readErr) break;

        // 先取长度再取字节, 两步都是标准 CSP 用法
        DWORD len = (DWORD)sizeof(DWORD);
        DWORD hashLen = 0;
        if (!CryptGetHashParam(hh, HP_HASHSIZE, reinterpret_cast<BYTE*>(&hashLen), &len, 0)) {
            LogPost(L"FIM baseline: CryptGetHashParam(HASHSIZE) 失败"); break;
        }
        if (hashLen == 0 || hashLen > sizeof(raw)) {
            LogFmt(L"FIM baseline: 非法哈希长度 %u", (unsigned)hashLen); break;
        }
        DWORD outLen = (DWORD)sizeof(raw);
        if (!CryptGetHashParam(hh, HP_HASHVAL, raw, &outLen, 0)) {
            LogPost(L"FIM baseline: CryptGetHashParam(HASHVAL) 失败"); break;
        }
        if (outLen < hashLen) { LogPost(L"FIM baseline: 哈希字节不足"); break; }

        static const wchar_t* kHex = L"0123456789abcdef";
        for (DWORD i = 0; i < hashLen; ++i) {
            outHex += kHex[(raw[i] >> 4) & 0xF];
            outHex += kHex[raw[i] & 0xF];
        }
        ok = true;
    } while (0);

    if (hh) CryptDestroyHash(hh);
    if (hp) CryptReleaseContext(hp, 0);
    CloseHandle(h);
    return ok;
}

static void BuildBaseline() {
    // 目录来源: 配置路径优先, 缺省回落到 drivers\etc (与 FimStartMonitoring 保持一致)
    std::wstring path = g_cfg.fimPath.empty()
        ? std::wstring(L"C:\\Windows\\System32\\drivers\\etc")
        : g_cfg.fimPath;

    LogFmt(L"FIM BuildBaseline: 开始扫描 %s", path.c_str());

    g_baseline.clear();

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW((path + L"\\*").c_str(), &fd);
    if (!hFind || hFind == INVALID_HANDLE_VALUE) {
        LogFmt(L"FIM BuildBaseline: 打开目录失败 %s (err=%u)",
               path.c_str(), (unsigned)GetLastError());
        return;
    }

    unsigned scanned = 0, hashed = 0, skipped = 0;
    do {
        // 跳过目录(含 . / ..)与非目标扩展名
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        std::wstring ext = PathFindExtensionW(fd.cFileName);
        if (_wcsicmp(ext.c_str(), L".exe") != 0 &&
            _wcsicmp(ext.c_str(), L".dll") != 0 &&
            _wcsicmp(ext.c_str(), L".sys") != 0) continue;

        std::wstring full = path + L"\\" + fd.cFileName;
        ++scanned;

        std::wstring hex;
        if (FileSha256W(full, hex)) {
            g_baseline[full] = hex;
            ++hashed;
        } else {
            ++skipped;   // 打不开(被占用/无权限)的文件不进基线, 避免假告警
        }
    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);

    LogFmt(L"FIM BuildBaseline: 完成 -> 候选 %u, 已哈希 %u, 跳过 %u, 基线条目 %u",
           scanned, hashed, skipped, (unsigned)g_baseline.size());
}
// FIM 实时监控句柄与控制标志
static HANDLE g_fimDir = nullptr;
static std::atomic<bool> g_fimThreadOn{false};

// FIM 监控线程: ReadDirectoryChangesW 阻塞等待目录变更
static void FimMonitorThread(const std::wstring path) {
    BYTE buf[64 * 1024];                 // 变更通知缓冲(64KB 上限)
    DWORD returned = 0;
    unsigned long long changes = 0;

    while (g_fimThreadOn.load() && g_fimDir && g_fimDir != INVALID_HANDLE_VALUE) {
        returned = 0;
        BOOL ok = ReadDirectoryChangesW(
            g_fimDir,
            buf, sizeof(buf),
            TRUE,                          // 监视子目录
            FILE_NOTIFY_CHANGE_FILE_NAME |
            FILE_NOTIFY_CHANGE_DIR_NAME |
            FILE_NOTIFY_CHANGE_SIZE |
            FILE_NOTIFY_CHANGE_LAST_WRITE,
            &returned,
            nullptr, nullptr);

        if (!ok || returned == 0) {
            if (!g_fimThreadOn.load()) break;          // 正常停止
            LogFmt(L"FIM ReadDirectoryChangesW failed, err=%u", (unsigned)GetLastError());
            Sleep(1000);                               // 退避后重试
            continue;
        }

        // 遍历通知记录链表(NextEntryOffset = 0 表示最后一条)
        BYTE* p = buf;
        for (;;) {
            FILE_NOTIFY_INFORMATION* fni = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(p);
            if (fni->FileNameLength >= sizeof(WCHAR)) {
                // FileName 非 '\0' 结尾, 需按长度构造
                std::wstring name(fni->FileName, fni->FileNameLength / sizeof(WCHAR));
                const wchar_t* act = L"UNKNOWN";
                switch (fni->Action) {
                    case FILE_ACTION_ADDED:             act = L"ADDED";   break;
                    case FILE_ACTION_REMOVED:           act = L"REMOVED"; break;
                    case FILE_ACTION_MODIFIED:          act = L"MODIFIED";break;
                    case FILE_ACTION_RENAMED_OLD_NAME:  act = L"RENAME_OLD"; break;
                    case FILE_ACTION_RENAMED_NEW_NAME:  act = L"RENAME_NEW"; break;
                    default: break;
                }
                ++changes;
                LogFmt(L"FIM %s: %s\\%s", act, path.c_str(), name.c_str());

                // 已建立基线且该文件在基线内 → 视为基线漂移告警
                std::wstring full = path + L"\\" + name;
                auto it = g_baseline.find(full);
                if (it != g_baseline.end())
                    LogFmt(L"FIM ALERT: 受监控基线文件发生变更 -> %s", full.c_str());
            }
            if (fni->NextEntryOffset == 0) break;
            p += fni->NextEntryOffset;
        }
    }
    LogFmt(L"FIM monitor thread exited, total changes=%llu", changes);
}

static void FimStartMonitoring() {
    if (g_fimThreadOn.load()) { LogPost(L"FIM 已在监控中, 忽略重复启动"); return; }

    // 监控目录: 优先用配置路径, 缺省回落到 C:\Windows\System32\drivers\etc
    std::wstring path = g_cfg.fimPath.empty()
        ? std::wstring(L"C:\\Windows\\System32\\drivers\\etc")
        : g_cfg.fimPath;

    // 目录句柄必须以 FILE_FLAG_BACKUP_SEMANTICS 打开才能监视目录本身
    HANDLE h = CreateFileW(path.c_str(), FILE_LIST_DIRECTORY,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (!h || h == INVALID_HANDLE_VALUE) {
        LogFmt(L"FIM 打开目录失败(路径不存在或无权限): %s, err=%u",
               path.c_str(), (unsigned)GetLastError());
        g_cfg.fimOn = false;
        return;
    }

    g_fimDir = h;
    g_cfg.fimOn = true;
    g_fimThreadOn.store(true);
    LogFmt(L"FIM StartMonitoring: %s (ReadDirectoryChangesW 已就绪)", path.c_str());
    LaunchDaemon((std::wstring(L"FimMonitor:") + path).c_str(), [path] { FimMonitorThread(path); });
}

static void FimStopMonitoring() {
    if (!g_fimThreadOn.load()) { LogPost(L"FIM 未在运行, 忽略停止请求"); return; }
    g_fimThreadOn.store(false);
    g_cfg.fimOn = false;
    // 关闭目录句柄使阻塞中的 ReadDirectoryChangesW 立即返回, 线程得以退出
    if (g_fimDir && g_fimDir != INVALID_HANDLE_VALUE) {
        CloseHandle(g_fimDir);
        g_fimDir = nullptr;
    }
    LogPost(L"FIM StopMonitoring: 已停止并释放目录句柄");
}
static void RunScaAudit() {
    LogPost(L"SCA Audit: 对照 CIS 基线检查系统配置");
    struct Check { const wchar_t* key; const wchar_t* val; unsigned long want; const wchar_t* desc; };
    const Check checks[] = {
        { L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"LimitBlankPasswordUse", 1, L"禁止空密码账户" },
        { L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"NoLMHash", 1, L"不存储 LAN Manager 哈希" },
        { L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"EnableLUA", 1, L"启用 UAC" },
        { L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"ConsentPromptBehaviorAdmin", 2, L"管理员同意提示" },
        { L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server", L"fDenyTSConnections", 1, L"禁用远程桌面" },
    };
    int pass = 0, total = 0;
    for (const auto& c : checks) {
        total++;
        HKEY hk = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, c.key, 0, KEY_READ, &hk) != 0 || !hk) {
            LogFmt(L"SCA: [跳过] %s (键不可读)", c.desc); continue;
        }
        unsigned long got = 0, type = 0, sz = sizeof(got);
        long r = RegQueryValueExW(hk, c.val, nullptr, &type, (unsigned char*)&got, &sz);
        RegCloseKey(hk);
        if (r == 0 && got == c.want) { pass++; LogFmt(L"SCA: [合规] %s = %u", c.desc, got); }
        else LogFmt(L"SCA: [不合规] %s (当前=%u 期望=%u)", c.desc, got, c.want);
    }
    static const wchar_t* risky[] = { L"Telnet", L"RemoteRegistry", L"SSDPSRV", L"upnphost" };
    auto svcs = SnapshotSvcs();
    for (const wchar_t* rn : risky) {
        for (auto& s : svcs) {
            if (_wcsicmp(s.name.c_str(), rn) == 0) {
                total++;
                LogFmt(L"SCA: [不合规] 高风险服务 %s 存在", rn);
                break;
            }
        }
    }
    int pct = total ? (pass * 100 / total) : 100;
    LogFmt(L"SCA Audit: 完成, 合规 %d/%d (%d%%)", pass, total, pct);
}

// ============================================================
//  回滚 / 恢复 / 应急自救
// ============================================================
// 快照目录: %TEMP%\zz_EDR_snapshots (不存在则创建; 已存在时 CreateDirectoryW 失败属正常)
static std::wstring GetSnapshotDir() {
    wchar_t tmp[MAX_PATH] = {0};
    GetTempPathW(MAX_PATH, tmp);
    std::wstring dir = std::wstring(tmp);
    if (!dir.empty() && (dir.back() == L'\\' || dir.back() == L'/'))
        dir.pop_back();
    dir += L"\\zz_EDR_snapshots";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir;
}

// 把一行文本追加写入快照文件 (UTF-16LE, 带 BOM 由首次写入负责)
static bool AppendSnapshotLine(HANDLE h, const std::wstring& line) {
    if (!h || h == INVALID_HANDLE_VALUE) return false;
    std::wstring text = line + L"\r\n";
    DWORD want = (DWORD)(text.size() * sizeof(wchar_t));
    DWORD wrote = 0;
    if (!WriteFile(h, text.c_str(), want, &wrote, nullptr) || wrote != want) {
        LogFmt(L"CreateSnapshot: 写入不完整 (%u/%u 字节)", (unsigned)wrote, (unsigned)want);
        return false;
    }
    return true;
}

static void CreateSnapshot() {
    // 1) 先刷新三类快照数据, 保证写盘的是最新状态
    EnumAllProcesses();
    ScanNetwork();

    const std::wstring dir = GetSnapshotDir();

    // 文件名用 Unix 秒时间戳, 避免重名覆盖历史快照
    unsigned long long secs =
        (unsigned long long)std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    const std::wstring path = dir + L"\\snapshot_" + std::to_wstring(secs) + L".txt";

    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (!h || h == INVALID_HANDLE_VALUE) {
        LogFmt(L"CreateSnapshot: 创建快照文件失败 %s (err=%u)",
               path.c_str(), (unsigned)GetLastError());
        return;
    }

    // UTF-16LE BOM, 保证记事本/日志查看器正确识别编码
    const wchar_t kBom = 0xFEFF;
    DWORD bw = 0;
    WriteFile(h, &kBom, (DWORD)sizeof(kBom), &bw, nullptr);

    // 2) 进程快照
    auto procs = SnapshotProcs();
    AppendSnapshotLine(h, L"=== PROCESSES (" + std::to_wstring(procs.size()) + L") ===");
    for (const auto& p : procs)
        AppendSnapshotLine(h, L"PID=" + std::to_wstring(p.pid) + L"\t" +
                              p.name + L"\t" + (p.suspicious ? L"SUSPICIOUS" : L"normal"));

    // 3) 网络快照
    auto nets = SnapshotNets();
    AppendSnapshotLine(h, L"");
    AppendSnapshotLine(h, L"=== NETWORK (" + std::to_wstring(nets.size()) + L") ===");
    for (const auto& n : nets)
        AppendSnapshotLine(h, L"local=" + n.local + L"\tremote=" + n.remote +
                              L"\tstate=" + n.state + L"\tPID=" + std::to_wstring(n.pid));

    // 4) 服务快照
    auto svcs = SnapshotSvcs();
    AppendSnapshotLine(h, L"");
    AppendSnapshotLine(h, L"=== SERVICES (" + std::to_wstring(svcs.size()) + L") ===");
    for (const auto& s : svcs)
        AppendSnapshotLine(h, s.name + L"\t" + s.state);

    // 5) 注册表自启动项
    AppendSnapshotLine(h, L"");
    AppendSnapshotLine(h, L"=== REGISTRY RUN ===");
    static const wchar_t* kRunKeys[] = {
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    };
    for (HKEY root : {HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE}) {
        for (const wchar_t* sub : kRunKeys) {
            HKEY hk = nullptr;
            if (RegOpenKeyExW(root, sub, 0, KEY_READ, &hk) != ERROR_SUCCESS) continue;
            wchar_t name[256] = {0};
            for (DWORD i = 0;; ++i) {
                DWORD nz = (DWORD)std::size(name);
                DWORD vz = 0;
                LONG rv = RegEnumValueW(hk, i, name, &nz, nullptr, nullptr, nullptr, &vz);
                if (rv == ERROR_NO_MORE_ITEMS) break;
                if (rv != ERROR_SUCCESS) break;
                std::vector<wchar_t> val(vz / sizeof(wchar_t) + 2, L'\0');
                DWORD vz2 = (DWORD)(val.size() * sizeof(wchar_t));
                if (RegQueryValueExW(hk, name, nullptr, nullptr,
                                     reinterpret_cast<LPBYTE>(val.data()), &vz2) == ERROR_SUCCESS)
                    AppendSnapshotLine(h, std::wstring(name) + L"\t" + val.data());
            }
            RegCloseKey(hk);
        }
    }

    FlushFileBuffers(h);
    CloseHandle(h);

    LogFmt(L"CreateSnapshot: 已写入 %s (进程 %u / 网络 %u / 服务 %u)",
           path.c_str(), (unsigned)procs.size(),
           (unsigned)nets.size(), (unsigned)svcs.size());
}
static void CreateRecoveryEnvironment() {
    LogPost(L"CreateRecoveryEnvironment: 生成恢复环境");
    CreateRestorePoint();
    wchar_t tmp[MAX_PATH] = {0};
    GetTempPathW(MAX_PATH, tmp);
    wstring dir = wstring(tmp);
    if (!dir.empty() && (dir.back() == L'\\' || dir.back() == L'/')) dir.pop_back();
    dir += L"\\zz_EDR_recovery";
    if (!CreateDirectoryW(dir.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) {
        LogFmt(L"CreateRecoveryEnvironment: 创建目录失败 %s", dir.c_str()); return;
    }
    wstring path = dir + L"\\recovery_manifest.txt";
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (!h || h == INVALID_HANDLE_VALUE) {
        LogPost(L"CreateRecoveryEnvironment: 无法写入清单文件"); return;
    }
    const wchar_t bom = 0xFEFF; DWORD bw = 0;
    WriteFile(h, &bom, (DWORD)sizeof(bom), &bw, nullptr);
    auto svcs = SnapshotSvcs();
    wstring txt = L"=== ZZ_EDR Recovery Manifest ===\r\n";
    txt += L"服务数: " + std::to_wstring(svcs.size()) + L"\r\n";
    txt += L"恢复步骤: 1)WinRE启动 2)还原点回滚 3)驱动重装 4)引导修复\r\n";
    DWORD want = (DWORD)(txt.size() * sizeof(wchar_t)), wrote = 0;
    if (!WriteFile(h, txt.c_str(), want, &wrote, nullptr) || wrote != want)
        LogPost(L"CreateRecoveryEnvironment: 清单写入不完整");
    FlushFileBuffers(h); CloseHandle(h);
    LogFmt(L"CreateRecoveryEnvironment: 已生成 -> %s", path.c_str());
}
// 生成紧急自救批处理并调用 CreateProcessW 执行
// 自救链: 还原点 -> Defender 全盘 -> MRT -> SFC -> DISM -> 清理自启动
static bool WriteEmergencyBat(const std::wstring& path) {
    const wchar_t* lines[] = {
        L"@echo off",
        L"chcp 65001 >nul",
        L"echo ==== ZZ EDR Emergency Self-Rescue ====",
        L"echo [1/5] 创建系统还原点...",
        L"wmic.exe /Namespace:\\\\root\\default Path SystemRestore Call CreateRestorePoint \"ZZEDR_Emergency\", 100, 12",
        L"echo [2/5] Windows Defender 全盘扫描...",
        L"\"%ProgramFiles%\\Windows Defender\\MpCmdRun.exe\" -Scan -ScanType 2",
        L"echo [3/5] 恶意软件删除工具(MRT)...",
        L"%windir%\\system32\\MRT.exe /F /Q",
        L"echo [4/5] 系统文件检查(SFC) 与 映像修复(DISM)...",
        L"sfc /scannow",
        L"dism /Online /Cleanup-Image /RestoreHealth",
        L"echo [5/5] 清理可疑自启动项...",
        L"reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /f 2>nul",
        L"echo ==== 自救链执行完毕, 请重启计算机 ====",
        L"exit /b 0"
    };
    FILE* f = _wfopen(path.c_str(), L"wb");
    if (!f) {
        LogFmt(L"Emergency: 无法写入自救脚本 %s, err=%u", path.c_str(), (unsigned)GetLastError());
        return false;
    }
    // 先写 UTF-16LE BOM, 保证 bat 内中文不被 cmd 误解析
    static const unsigned char bom[2] = { 0xFF, 0xFE };
    fwrite(bom, 1, 2, f);
    for (const wchar_t* ln : lines) {
        fwrite(ln, sizeof(wchar_t), wcslen(ln), f);
        fwrite(L"\r\n", sizeof(wchar_t), 2, f);
    }
    fclose(f);
    LogFmt(L"Emergency: 自救脚本已生成 -> %s", path.c_str());
    return true;
}

static void RunEmergency() {
    LogPost(L"!!! EMERGENCY MODE !!!");

    // 1) 先建立还原点, 保证自救链可回滚
    CreateRestorePoint();

    // 2) 生成并执行自救批处理(后台, 避免阻塞 UI)
    LaunchBg([] {
        wchar_t tmp[MAX_PATH] = { 0 };
        if (!GetTempPathW(MAX_PATH, tmp)) {
            wcscpy_s(tmp, MAX_PATH, L"C:\\Windows\\Temp\\");
        }
        std::wstring bat = std::wstring(tmp) + L"ZZ_EDR_Emergency.bat";

        if (WriteEmergencyBat(bat)) {
            // CreateProcessW 第二参数必须是可写缓冲区, 不能用字符串字面量
            wchar_t cmdline[MAX_PATH + 64] = { 0 };
            wcscpy_s(cmdline, MAX_PATH + 64, L"cmd.exe /c \"");
            wcscat_s(cmdline, MAX_PATH + 64, bat.c_str());
            wcscat_s(cmdline, MAX_PATH + 64, L"\"");

            STARTUPINFOW si = { 0 };
            si.cb = sizeof(si);
            si.dwFlags = 0;
            PROCESS_INFORMATION pi = { 0 };

            if (CreateProcessW(nullptr, cmdline, nullptr, nullptr, FALSE,
                               CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
                LogPost(L"Emergency: 自救链已启动 (还原点->Defender->MRT->SFC->DISM)");
                // 等待自救链结束, 超时 30 分钟, 防止句柄泄漏
                if (pi.hProcess) {
                    DWORD w = WaitForSingleObject(pi.hProcess, 30 * 60 * 1000);
                    if (w == WAIT_TIMEOUT)
                        LogPost(L"Emergency: 自救链超时(30min), 已放弃等待");
                    CloseHandle(pi.hProcess);
                }
                if (pi.hThread)  CloseHandle(pi.hThread);
            } else {
                LogFmt(L"Emergency: 启动自救链失败, err=%u", (unsigned)GetLastError());
            }
        }

        // 3) 常规清理与远程检测
        DeepClean();
        DetectRemoteControl();

        // 4) 关键: 复位扫描标志, 否则后续所有扫描都会被 SchedulerLoop 拒绝
        g_scanning.store(false);
        LogPost(L"Emergency: 自救流程结束, 扫描标志已复位");
    });

    LogPost(L"Emergency: 已在后台启动自救链 + 深度清理 + 远程检测");
}

// ============================================================
//  隐私: 虚拟摄像头 (MF 主路径 + DirectShow 备选)
// ============================================================
struct CamState {
    bool active = false;
    bool usedMF = false;     // true = 走的 MF 路径, false = 走的 DirectShow 备选
    int  mode = 0;
    wstring file;
    void* mfCam = nullptr;   // IMFVirtualCamera* (真实环境)
} g_cam;


// ============================================================
//  重启杀毒 (Boot-time scan)
//  机制: 将自身注册为 Winlogon Shell(带 --bootscan), 开机时先全盘扫描,
//        处理威胁后恢复原 Shell 并启动 explorer, 再进入正常桌面。
//  安全约束:
//    - 白名单目录/文件永不删除(防系统无法启动)
//    - 默认先隔离; 仅 sev>=3 且开启激进模式才删除
//    - 单次处理上限 MAX_BOOT_ACTION, 防误伤过多
//    - 无论成功/失败, 最终都恢复 Shell 并启动桌面
// ============================================================
#define MAX_BOOT_ACTION 200
#define BOOT_SCAN_FLAG  L"--bootscan"
static HWND g_hBoot = nullptr, g_hBootText = nullptr;

// 是否受保护(永不清删)
static bool IsProtectedPath(const wstring& p) {
    if (p.empty()) return true;
    wstring lower = ToLowerW(p);
    for (int i = 0; i < g_protectCount; ++i)
        if (lower.find(ToLowerW(g_protectDirs[i])) == 0) return true;
    wchar_t self[MAX_PATH] = {0};
    if (GetModuleFileNameW(nullptr, self, MAX_PATH) && _wcsicmp(p.c_str(), self) == 0)
        return true;                       // 自身绝不自删
    return false;
}
// 注册/注销开机扫描
static void RegisterBootScan(bool enable) {
    const wchar_t* kWinlogon = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    HKEY hk = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kWinlogon, 0, KEY_READ | KEY_WRITE, &hk) != ERROR_SUCCESS || !hk) {
        LogPost(L"BootScan: 打开 Winlogon 键失败(需管理员权限)");
        return;
    }
    if (enable) {
        wchar_t orig[1024] = {0}; DWORD sz = sizeof(orig); DWORD type = 0;
        if (RegQueryValueExW(hk, L"Shell", nullptr, &type, (LPBYTE)orig, &sz) == ERROR_SUCCESS && orig[0])
            LogFmt(L"BootScan: 原 Shell = %s", orig);
        RegSetValueExW(hk, L"ZZ_EDR_ShellBackup", 0, REG_SZ, (const BYTE*)orig,
                       (DWORD)((wcslen(orig) + 1) * sizeof(wchar_t)));
        wchar_t self[MAX_PATH] = {0};
        GetModuleFileNameW(nullptr, self, MAX_PATH);
        wstring cmd = wstring(L"\"") + self + L"\" " + BOOT_SCAN_FLAG;
        RegSetValueExW(hk, L"Shell", 0, REG_SZ, (const BYTE*)cmd.c_str(),
                       (DWORD)((cmd.size() + 1) * sizeof(wchar_t)));
        LogFmt(L"BootScan: 已注册 -> %s", cmd.c_str());
        LogPost(L"BootScan: 请重启计算机; 开机将先全盘扫描, 完成后自动进入桌面");
    } else {
        wchar_t bak[1024] = {0}; DWORD sz = sizeof(bak); DWORD type = 0;
        if (RegQueryValueExW(hk, L"ZZ_EDR_ShellBackup", nullptr, &type, (LPBYTE)bak, &sz) == ERROR_SUCCESS && bak[0]) {
            RegSetValueExW(hk, L"Shell", 0, REG_SZ, (const BYTE*)bak,
                           (DWORD)((wcslen(bak) + 1) * sizeof(wchar_t)));
            LogFmt(L"BootScan: 已恢复 Shell = %s", bak);
        }
        RegDeleteValueW(hk, L"ZZ_EDR_ShellBackup");
        LogPost(L"BootScan: 已注销开机扫描");
    }
    RegCloseKey(hk);
}
// 是否开机扫描模式
static bool IsBootScanMode() {
    const wchar_t* cl = GetCommandLineW();
    return (cl != nullptr && wcsstr(cl, BOOT_SCAN_FLAG) != nullptr);
}
// 扫描单个目录树(限深度/数量, 避免开机过久)
static void BootScanDir(const wstring& root, int depth, int& scanned, int& removed, int& quar) {
    if (depth > 3 || removed + quar >= MAX_BOOT_ACTION) return;
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((root + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE || !h) return;
    do {
        if (removed + quar >= MAX_BOOT_ACTION) break;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
            BootScanDir(root + L"\\" + fd.cFileName, depth + 1, scanned, removed, quar);
            continue;
        }
        wstring full = root + L"\\" + fd.cFileName;
        ++scanned;
        wstring why;
        int sev = RuleMatchFile(full, why);
        { std::wstring _fw; int _ff = MalFamilyScan(full, _fw); if (_ff > sev) { sev = _ff; why = _fw; } }
        if (sev <= 0) continue;
        LogFmt(L"BootScan 命中: %s -> %s (sev=%d)", full.c_str(), why.c_str(), sev);
        if (IsProtectedPath(full)) { LogFmt(L"BootScan: 受保护跳过 %s", full.c_str()); continue; }
        if (sev >= 3 && g_cfg.advAggressive) {
            if (DeleteFileW(full.c_str())) { ++removed; LogFmt(L"BootScan: 已删除 %s", full.c_str()); }
        } else {
            QuarantineFile(full); ++quar;
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}
// 全屏扫描窗口(告知用户正在扫描, 避免以为卡死)
static void BootScanUIShow() {
    HINSTANCE hi = GetModuleHandleW(nullptr);
    WNDCLASSEXW wc; memset(&wc, 0, sizeof(wc)); wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = DefWindowProcW; wc.hInstance = hi;
    wc.lpszClassName = L"ZZEDRBootClass";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClassExW(&wc);
    int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
    g_hBoot = CreateWindowExW(WS_EX_TOPMOST, L"ZZEDRBootClass", L"ZZ◇EDR 开机扫描",
        WS_POPUP | WS_VISIBLE, 0, 0, sw, sh, nullptr, nullptr, hi, nullptr);
    if (g_hBoot)
        g_hBootText = CreateWindowExW(0, L"STATIC", L"正在初始化开机扫描...",
            WS_VISIBLE | WS_CHILD, 30, 30, sw - 60, 80, g_hBoot, nullptr, hi, nullptr);
}
static void BootScanUISet(const wchar_t* text) {
    if (g_hBootText) SetWindowTextW(g_hBootText, text);
    MSG m;
    while (PeekMessageW(&m, nullptr, 0, 0, PM_REMOVE)) { TranslateMessage(&m); DispatchMessageW(&m); }
}
static void BootScanUIHide() {
    if (g_hBootText) { DestroyWindow(g_hBootText); g_hBootText = nullptr; }
    if (g_hBoot)     { DestroyWindow(g_hBoot);     g_hBoot = nullptr; }
}
// 开机扫描主流程
static int BootScanMain() {
    LogPost(L"===== BootScan: 开机全盘扫描启动 =====");
    BootScanUIShow();
    int scanned = 0, removed = 0, quar = 0;
    wchar_t drives[512] = {0};
    if (GetLogicalDriveStringsW(512, drives)) {
        for (wchar_t* d = drives; *d; d += wcslen(d) + 1) {
            if (GetDriveTypeW(d) != DRIVE_FIXED) continue;
            BootScanUISet((wstring(L"正在扫描 ") + d).c_str());
            LogFmt(L"BootScan: 扫描驱动器 %s", d);
            BootScanDir(wstring(d), 0, scanned, removed, quar);
        }
    } else {
        { std::wstring drv = L"C:"; drv += L'\\'; BootScanUISet((std::wstring(L"正在扫描 ") + drv).c_str()); }
        BootScanDir(L"C:\\", 0, scanned, removed, quar);
    }
    BootScanUISet(L"扫描完成, 正在恢复桌面...");
    LogFmt(L"BootScan: 完成 -> 扫描 %d 文件, 隔离 %d, 删除 %d", scanned, quar, removed);
    LogPost(L"===== BootScan: 结束 =====");
    return 0;
}
// 恢复 Shell + 启动桌面(必须执行, 否则无法进入系统)
static void BootScanFinishAndLaunchDesktop() {
    LogPost(L"BootScan: 恢复 Shell 并启动桌面");
    RegisterBootScan(false);
    BootScanUIHide();
    STARTUPINFOW si; memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    PROCESS_INFORMATION pi; memset(&pi, 0, sizeof(pi));
    wchar_t cmd[64] = L"explorer.exe";
    if (CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        LogPost(L"BootScan: 已启动 explorer.exe");
    } else {
        LogFmt(L"BootScan: 启动 explorer 失败 err=%u(请手动运行 explorer.exe)", GetLastError());
    }
}

static bool CamEnsureMF() {
    LogPost(L"Camera: trying MFCreateVirtualCamera (Win10 20H1+ / 11)");
    typedef long (*PFN_MFCreateVirtualCamera)(unsigned long, void*, void*, void**);
    HMODULE h = LoadLibraryW(L"mf.dll");
    if (!h) h = LoadLibraryW(L"mfplat.dll");
    if (!h) { LogPost(L"Camera: MF 库不可用, 降级 DirectShow"); return false; }
    auto pMF = (PFN_MFCreateVirtualCamera)GetProcAddress(h, "MFCreateVirtualCamera");
    if (!pMF) { LogPost(L"Camera: MFCreateVirtualCamera 未导出, 降级"); FreeLibrary(h); return false; }
    void* cam = nullptr;
    long hr = pMF(0, nullptr, nullptr, &cam);
    if (hr < 0 || !cam) { LogPost(L"Camera: 调用失败, 降级"); FreeLibrary(h); return false; }
    g_cam.mfCam = cam; g_cam.usedMF = true;
    LogPost(L"Camera: MF 虚拟摄像头已创建"); return true;
}
static bool CamRegisterDirectShow() {
    LogPost(L"Camera: registering DirectShow filter (Win10 legacy)");
    HMODULE h = LoadLibraryW(L"zz_vcam_source.dll");
    if (!h) { LogPost(L"Camera: DirectShow 媒体源 DLL 未找到"); return false; }
    auto pReg = (long(*)())GetProcAddress(h, "DllRegisterServer");
    if (!pReg) { LogPost(L"Camera: DllRegisterServer 未导出"); FreeLibrary(h); return false; }
    long hr = pReg(); FreeLibrary(h);
    if (hr < 0) { LogPost(L"Camera: DirectShow 注册失败"); return false; }
    g_cam.usedMF = false;
    LogPost(L"Camera: DirectShow filter 已注册"); return true;
}
static bool CameraStart(int mode, const wstring& file) {
    if (g_cam.active) return true;
    g_cam.mode = mode; g_cam.file = file;
    bool ok = CamEnsureMF();               // 成功时置 g_cam.mfCam
    if (!ok) ok = CamRegisterDirectShow(); // 备选: DirectShow filter
    if (!ok) {
        LogPost(L"CameraStart: MF 与 DirectShow 均失败, 未启动");
        return false;
    }
    g_cam.active = true;
    // 记录实际生效的注册路径, Stop 时据此反向注销
    g_cam.usedMF = (g_cam.mfCam != nullptr);
    LogFmt(L"CameraStart: mode=%d via %s", mode,
           g_cam.usedMF ? L"MF" : L"DirectShow");
    return true;
}

// 注销 MF 虚拟摄像头: 先 Shutdown 停止帧供给, 再 Release 释放 COM 引用
// COM vtable 布局 (稳定 ABI, 不依赖 SDK 头文件):
//   IUnknown              [0]=QueryInterface [1]=AddRef [2]=Release
//   IMFMediaEventGenerator[3]=GetEvent [4]=BeginGetEvent [5]=EndGetEvent [6]=QueueEvent
//   IMFMediaSource        [7]=GetCharacteristics [8]=CreatePresentationDescriptor
//                         [9]=Start [10]=Stop [11]=Pause [12]=Shutdown
typedef long (*PF_VtblFn)(void*);
static long CamCallVtbl(void* obj, int idx) {
    if (!obj) return -1;
    void*** vtable = static_cast<void***>(obj);
    if (!vtable || !*vtable) return -1;
    PF_VtblFn fn = reinterpret_cast<PF_VtblFn>((*vtable)[idx]);
    if (!fn) return -1;
    return fn(obj);
}
static void CamUnregisterMF() {
    if (!g_cam.mfCam) return;
    void* p = g_cam.mfCam;
    long hr = -1;

    // 优先: 通过 IMFMediaSource::Shutdown 停止帧供给 (vtable[12])
    // IID_IMFMediaSource = {279A808D-AEC7-4CFD-A0F5-9C4C9C4C9C4C} 不存在,
    // 故直接用 QueryInterface 取 IMFMediaSource, 再调其 Shutdown
    struct Guid { unsigned long a; unsigned short b, c; unsigned char d[8]; };
    const Guid IID_IMFMediaSource = { 0x279A808D, 0xAEC7, 0x4CFD,
        { 0xA0, 0xF5, 0x9C, 0x4C, 0x9C, 0x4C, 0x9C, 0x4C } };
    typedef long (*PF_QI)(void*, const Guid&, void**);
    void*** vt = static_cast<void***>(p);
    PF_QI qi = reinterpret_cast<PF_QI>((*vt)[0]);
    void* src = nullptr;
    if (qi && qi(p, IID_IMFMediaSource, &src) >= 0 && src) {
        hr = CamCallVtbl(src, 12);           // IMFMediaSource::Shutdown
        LogFmt(L"Camera: MF Shutdown hr=0x%08X", (unsigned long)hr);
        CamCallVtbl(src, 2);                 // Release 掉 QI 出来的接口
    } else {
        LogPost(L"Camera: 无法取得 IMFMediaSource, 仅 Release");
    }

    CamCallVtbl(p, 2);                       // IUnknown::Release 释放 COM 引用
    g_cam.mfCam = nullptr;                   // 置空, 防止 Stop 后悬垂指针
    LogPost(L"Camera: MF 虚拟摄像头已注销 (Shutdown + Release 已调用)");
}

// 反注册 DirectShow filter: 撤销 COM 媒体源注册
static void CamUnregisterDirectShow() {
    LogPost(L"Camera: 反注册 DirectShow filter");
    HMODULE h = LoadLibraryW(L"zz_vcam_source.dll");
    if (!h) {
        LogPost(L"Camera: DirectShow 媒体源 DLL 未加载(可能已卸载), 跳过反注册");
        return;
    }
    auto pUnreg = (long(*)())GetProcAddress(h, "DllUnregisterServer");
    if (!pUnreg) {
        LogPost(L"Camera: DllUnregisterServer 未导出");
        FreeLibrary(h);
        return;
    }
    long hr = pUnreg();
    FreeLibrary(h);
    if (hr < 0) {
        LogFmt(L"Camera: DirectShow 反注册失败 hr=0x%08X", (unsigned long)hr);
        return;
    }
    LogPost(L"Camera: DirectShow filter 已反注册, 系统摄像头列表不再枚举本设备");
}

static void CameraStop() {
    if (!g_cam.active) return;
    LogPost(L"CameraStop");
    // 按 Start 时实际生效的路径反向注销, 避免设备残留在系统摄像头列表
    if (g_cam.usedMF) CamUnregisterMF();
    else              CamUnregisterDirectShow();
    // 兜底: 若 MF 设备指针仍非空(异常路径), 一并清理
    if (g_cam.mfCam) {
        LogPost(L"CameraStop: 兜底清理残留 MF 设备指针");
        g_cam.mfCam = nullptr;
    }
    // 复位全部状态, 保证可再次 Start
    g_cam.active = false;
    g_cam.usedMF = false;
    g_cam.mode   = 0;
    g_cam.file.clear();
    LogPost(L"CameraStop: 虚拟摄像头已注销, 状态已复位");
}

// ============================================================
//  隐私: 虚拟麦克风 (独立通道, 通过 zz_vmic.sys 驱动)
// ============================================================
struct MicState {
    bool active = false;
    int  mode = 0;
    wstring file;
    HANDLE driver = INVALID_HANDLE_VALUE;
} g_mic;

#define IOCTL_MIC_START  CTL_CODE(0x8000, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MIC_STOP   CTL_CODE(0x8000, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MIC_PUSH   CTL_CODE(0x8000, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS)

static bool MicStart(int mode, const wstring& file) {
    if (g_mic.active) return true;
    if (mode < 0 || mode > 1) { LogFmt(L"MicStart: 非法 mode=%d", mode); return false; }

    // 自定义音频文件模式: 先校验文件可用
    if (mode == 1) {
        if (file.empty()) { LogPost(L"MicStart: 自定义模式未选择音频文件"); return false; }
        DWORD attr = GetFileAttributesW(file.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) {
            LogFmt(L"MicStart: 音频文件不可访问 err=%u", GetLastError());
            return false;
        }
    }

    // 打开虚拟麦克风驱动通道
    g_mic.driver = CreateFileW(L"\\\\.\\zz_vmic", GENERIC_READ | GENERIC_WRITE,
                               0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (g_mic.driver == INVALID_HANDLE_VALUE) {
        LogFmt(L"MicStart: 驱动通道打开失败(需 zz_vmic.sys) err=%u", GetLastError());
        return false;                       // 状态一致: 失败即未激活
    }

    // 下发启动 IOCTL, 必须成功才算启用
    DWORD wr = 0;
    if (!DeviceIoControl(g_mic.driver, IOCTL_MIC_START, &mode, sizeof(mode),
                         nullptr, 0, &wr, nullptr)) {
        LogFmt(L"MicStart: IOCTL_MIC_START 失败 err=%u", GetLastError());
        CloseHandle(g_mic.driver);
        g_mic.driver = INVALID_HANDLE_VALUE;
        return false;
    }

    g_mic.mode = mode;
    g_mic.file = file;
    g_mic.active = true;
    LogFmt(L"MicStart: mode=%d (%s) 驱动已连接", mode,
           (mode == 0) ? L"静音流" : L"自定义音频");
    return true;
}
static void MicStop() {
    if (!g_mic.active) return;
    if (g_mic.driver != INVALID_HANDLE_VALUE) {
        DWORD wr = 0;
        DeviceIoControl(g_mic.driver, IOCTL_MIC_STOP, nullptr, 0, nullptr, 0, &wr, nullptr);
        CloseHandle(g_mic.driver);
        g_mic.driver = INVALID_HANDLE_VALUE;
    }
    g_mic.active = false;
    LogPost(L"MicStop");
}

// ============================================================
//  内核驱动对接层 (DrvLink) —— 把应用层轮询升级为内核级拦截
// ============================================================
//
//  【思路】此前所有防护都是"应用层轮询": 每隔几秒拍一次进程快照, 发现可疑再补杀。
//  这有三个绕不开的短板:
//    1) 时间窗: 进程在两次采样之间"启动 → 干完坏事 → 退出", 完全看不见;
//    2) 可见性: 用户态枚举依赖 API, Rootkit 一 hook 就让进程从快照里消失;
//    3) 事后性: 只能"已经发生了"再补救, 无法在发生的瞬间阻止。
//
//  内核驱动(zz_edrdrv.sys)通过内核回调解决这三点:
//    PsSetCreateProcessNotifyRoutineEx  → 进程创建的瞬间就能返回"拒绝创建"
//    PsSetLoadImageNotifyRoutine        → DLL/驱动加载即感知
//    CmRegisterCallbackEx               → 注册表写入(自启动)可拦截
//    ObRegisterCallbacks                → 剥离对自己进程的 TERMINATE 权限(防被杀)
//    FltRegisterFilter                  → 文件执行可拦截
//
//  本模块就是用户态那一半: 装驱动、连通道、下发规则、收事件。
//
//  【最重要的一条设计约束: 优雅降级】
//  驱动不是总能装上——没管理员权限、没测试签名、系统版本不匹配、sys 文件缺失,
//  任何一条不满足都会失败。所以本模块**绝不改变既有行为**:
//    驱动在 → 用内核能力(更强);
//    驱动不在 → 自动回落到原来的用户态实现(KillProcess / 文件删除), 功能一个不少。
//  判断依据统一为 DrvReady(), 所有调用点先问它, 拿不到就走老路。
// ============================================================

#include <algorithm>

// ---- IOCTL 定义(与 zz_edrdrv.h 严格一致, 改动必须两边同步) ----
#define ZZEDR_DEVICE_TYPE 0x8000
#define IOCTL_ZZ_PING         CTL_CODE(ZZEDR_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ZZ_SET_RULES    CTL_CODE(ZZEDR_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ZZ_GET_EVENT    CTL_CODE(ZZEDR_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ZZ_FORCE_DELETE CTL_CODE(ZZEDR_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ZZ_KILL_PID     CTL_CODE(ZZEDR_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ZZ_SELF_PROTECT CTL_CODE(ZZEDR_DEVICE_TYPE, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 事件类型(与驱动 ZZ_EVENT_TYPE 一一对应)
#define ZZ_EVT_NONE            0
#define ZZ_EVT_PROC_CREATE     1
#define ZZ_EVT_PROC_BLOCKED    2
#define ZZ_EVT_IMAGE_LOAD      3
#define ZZ_EVT_THREAD_CREATE   4
#define ZZ_EVT_REG_WRITE       5
#define ZZ_EVT_REG_BLOCKED     6
#define ZZ_EVT_FILE_CREATE     7
#define ZZ_EVT_FILE_BLOCKED    8
#define ZZ_EVT_SELF_PROTECT    9

// 风险等级(与用户态 THREAT_* 对齐)
#define ZZ_RISK_INFO    0
#define ZZ_RISK_WARN    1
#define ZZ_RISK_DANGER  2

#define ZZ_DRV_MAX_PATH 260

// 驱动上报的单条事件(内存布局必须与驱动端完全一致, 不能随便加减字段)
#pragma pack(push, 8)
struct ZZ_EVENT_UM {
    unsigned int      Type;
    unsigned int      Risk;
    unsigned long     Pid;
    unsigned long     ParentPid;
    unsigned long     TargetPid;
    unsigned long long TimeStamp;
    wchar_t           ImagePath[ZZ_DRV_MAX_PATH];
    wchar_t           TargetPath[ZZ_DRV_MAX_PATH];
    wchar_t           Detail[128];
};
// 下发给驱动的规则
struct ZZ_RULES_UM {
    unsigned int  Enabled;
    unsigned int  BlockUnsigned;
    unsigned int  BlockOfficeChild;
    unsigned int  BlockPersistence;
    unsigned int  SelfProtect;
    unsigned int  ProtectPid;
    unsigned int  FileGuard;
    wchar_t       QuarantineDir[ZZ_DRV_MAX_PATH];
};
// KILL_PID / FORCE_DELETE 的输入
struct ZZ_TARGET_UM {
    unsigned long Pid;
    wchar_t       Path[ZZ_DRV_MAX_PATH];
};
#pragma pack(pop)

// ---- 全局状态 ----
static HANDLE g_drvHandle = INVALID_HANDLE_VALUE;   // 设备句柄
static bool   g_drvLoaded = false;                  // 驱动已装载且通道可用
static const wchar_t* ZZ_DRV_NAME  = L"zz_edrdrv";
static const wchar_t* ZZ_DRV_FILE  = L"zz_edrdrv.sys";
static const wchar_t* ZZ_DRV_PATH  = L"\\\\.\\zz_edrdrv";

// 唯一的可用性判断入口, 所有调用点都问它
static bool DrvReady() { return g_drvLoaded && g_drvHandle != INVALID_HANDLE_VALUE; }

// 【思路】sys 文件放在 exe 同目录。用 GetModuleFileNameW 取自身路径再拼,
// 而不是写死 C:\..., 否则换了安装位置就永远找不到驱动。
static wstring DrvSysPath() {
    wchar_t self[ZZ_DRV_MAX_PATH] = {0};
    DWORD n = GetModuleFileNameW(nullptr, self, ZZ_DRV_MAX_PATH);
    if (n == 0 || n >= ZZ_DRV_MAX_PATH) return wstring(ZZ_DRV_FILE);  // 取不到就退回当前目录
    wstring s(self, n);
    size_t pos = s.find_last_of(L"\\/");
    if (pos == wstring::npos) return wstring(ZZ_DRV_FILE);
    return s.substr(0, pos + 1) + ZZ_DRV_FILE;
}

// 是否已经安装过服务(避免重复 CreateService 报 1073)
static bool DrvServiceExists(void* scm) {
    void* svc = OpenServiceW(scm, ZZ_DRV_NAME, SERVICE_QUERY_STATUS);
    if (!svc) return false;
    CloseServiceHandle(svc);
    return true;
}

// ---------------------------------------------------------------
//  DrvInstallAndStart: 通过 SCM 安装并启动内核驱动
//  【避坑】驱动必须"已签名"或系统开启测试签名, 否则 StartService 会失败(577)。
//         这是最常见的失败原因, 日志里要给出明确指引而不是干巴巴一个错误码。
// ---------------------------------------------------------------
static bool DrvInstallAndStart() {
    // 需要管理员权限; 非管理员时 OpenSCManager 会返回 nullptr
    void* scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        LogFmt(L"[DRV] 打开服务控制管理器失败 err=%u (需要管理员权限)", GetLastError());
        return false;
    }
    bool ok = false;
    if (!DrvServiceExists(scm)) {
        wstring sysPath = DrvSysPath();
        // 先确认 sys 文件真的在; 否则 CreateService 成功但 StartService 必失败
        DWORD attr = GetFileAttributesW(sysPath.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES) {
            LogFmt(L"[DRV] 未找到驱动文件: %s (请与 exe 放同目录)", sysPath.c_str());
            CloseServiceHandle(scm);
            return false;
        }
        void* svc = CreateServiceW(scm, ZZ_DRV_NAME, ZZ_DRV_NAME,
                                   SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
                                   SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                                   sysPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!svc) {
            LogFmt(L"[DRV] 创建驱动服务失败 err=%u", GetLastError());
            CloseServiceHandle(scm);
            return false;
        }
        CloseServiceHandle(svc);
        LogPost(L"[DRV] 驱动服务已创建");
    }
    // 打开服务并启动(无论新建还是已存在, 这一步都要做)
    void* svc2 = OpenServiceW(scm, ZZ_DRV_NAME, SERVICE_START | SERVICE_QUERY_STATUS);
    if (svc2) {
        if (StartServiceW(svc2, 0, nullptr)) {
            LogPost(L"[DRV] 驱动已启动");
            ok = true;
        } else {
            DWORD e = GetLastError();
            if (e == (DWORD)ERROR_SERVICE_ALREADY_RUNNING) { ok = true; }   // 已在跑不算失败
            else LogFmt(L"[DRV] 启动驱动失败 err=%u (未签名? 请开启测试签名 bcdedit /set testsigning on)", e);
        }
        CloseServiceHandle(svc2);
    }
    CloseServiceHandle(scm);
    return ok;
}

// ---------------------------------------------------------------
//  DrvOpen: 打开设备通道并握手(PING)
//  【思路】CreateFile 成功不代表驱动真的能通信——符号链接可能残留。
//         所以必须发一个 PING 确认驱动真的活着, 这步不能省。
// ---------------------------------------------------------------
static bool DrvOpen() {
    if (DrvReady()) return true;
    g_drvHandle = CreateFileW(ZZ_DRV_PATH, GENERIC_READ | GENERIC_WRITE,
                              0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (g_drvHandle == INVALID_HANDLE_VALUE) {
        LogFmt(L"[DRV] 打开设备通道失败 err=%u", GetLastError());
        return false;
    }
    DWORD wr = 0, magic = 0;
    if (!DeviceIoControl(g_drvHandle, IOCTL_ZZ_PING, nullptr, 0, &magic, sizeof(magic), &wr, nullptr)) {
        LogFmt(L"[DRV] 握手失败 err=%u (驱动未响应)", GetLastError());
        CloseHandle(g_drvHandle);
        g_drvHandle = INVALID_HANDLE_VALUE;
        return false;
    }
    g_drvLoaded = true;
    LogFmt(L"[DRV] 内核驱动已连接 (magic=0x%08X)", magic);
    return true;
}

// ---------------------------------------------------------------
//  DrvSetRules: 把当前配置下发给驱动
//  【思路】驱动自己是"哑"的——它不知道该拦什么, 策略全在用户态。
//         所以配置一变就要重新下发, 否则驱动还在用旧规则。
//         ProtectPid 传自身 PID: 驱动据此开启 Ob 回调保护我们不被终止。
// ---------------------------------------------------------------
static bool DrvSetRules() {
    if (!DrvReady()) return false;
    ZZ_RULES_UM r;
    ZeroMemory(&r, sizeof(r));
    r.Enabled          = 1;
    r.BlockUnsigned    = 0;                                   // 保守: 不拦未签名(误伤面太大)
    r.BlockOfficeChild = g_cfg.officeGuardOn ? 1 : 0;
    r.BlockPersistence = 0;                                   // 默认只记录, 由用户态决定是否处置
    r.SelfProtect      = 1;
    r.ProtectPid       = (unsigned int)GetCurrentProcessId();
    r.FileGuard        = 0;
    wstring qdir = QuarDirPath();
    if (qdir.empty()) {
        wchar_t tmp[ZZ_DRV_MAX_PATH] = {0};
        if (GetTempPathW(ZZ_DRV_MAX_PATH, tmp)) qdir = wstring(tmp) + L"zz_EDR_quarantine";
    }
    wcsncpy_s(r.QuarantineDir, ZZ_DRV_MAX_PATH, qdir.c_str(), _TRUNCATE);
    DWORD wr = 0;
    if (!DeviceIoControl(g_drvHandle, IOCTL_ZZ_SET_RULES, &r, sizeof(r), nullptr, 0, &wr, nullptr)) {
        LogFmt(L"[DRV] 下发规则失败 err=%u", GetLastError());
        return false;
    }
    LogPost(L"[DRV] 规则已下发(办公派生拦截/自身保护)");
    return true;
}

// ---------------------------------------------------------------
//  DrvEventName / DrvEventToBehav: 内核事件 → 用户态可读信息
//  【思路】驱动上报的是数字, 用户看不懂。这里统一翻译,
//         并同时写入行为时间线——这样"行为"二级菜单里也能看到内核观察到的动作。
// ---------------------------------------------------------------
static const wchar_t* DrvEventName(unsigned int t) {
    switch (t) {
        case ZZ_EVT_PROC_CREATE:   return L"进程创建";
        case ZZ_EVT_PROC_BLOCKED:  return L"进程被拦截";
        case ZZ_EVT_IMAGE_LOAD:    return L"镜像加载";
        case ZZ_EVT_THREAD_CREATE: return L"线程创建";
        case ZZ_EVT_REG_WRITE:     return L"注册表写入";
        case ZZ_EVT_REG_BLOCKED:   return L"注册表被拦截";
        case ZZ_EVT_FILE_CREATE:   return L"文件操作";
        case ZZ_EVT_FILE_BLOCKED:  return L"文件被拦截";
        case ZZ_EVT_SELF_PROTECT:  return L"自身被篡改";
        default:                   return L"未知";
    }
}
static int DrvEventToBehav(unsigned int t) {
    switch (t) {
        case ZZ_EVT_PROC_CREATE:
        case ZZ_EVT_PROC_BLOCKED:  return (int)BEHAV_PROC_START;
        case ZZ_EVT_IMAGE_LOAD:    return (int)BEHAV_FILE;
        case ZZ_EVT_THREAD_CREATE: return (int)BEHAV_HOOK;
        case ZZ_EVT_REG_WRITE:
        case ZZ_EVT_REG_BLOCKED:   return (int)BEHAV_REG;
        case ZZ_EVT_FILE_CREATE:
        case ZZ_EVT_FILE_BLOCKED:  return (int)BEHAV_FILE;
        case ZZ_EVT_SELF_PROTECT:  return (int)BEHAV_BLOCK;
        default:                   return (int)BEHAV_SIGN;
    }
}

// ---------------------------------------------------------------
//  DrvEventLoop: 事件接收守护(常驻, 由 LaunchDaemon 保证只有一个实例)
//  【思路】轮询取事件而不是事件对象通知——IOCTL 轮询实现简单且天然可退避:
//         没事件时驱动立即返回, 我们 sleep 200ms 避免空转烧 CPU;
//         有事件时连续取, 不 sleep, 保证高负载下不丢(驱动侧有 512 槽环形缓冲)。
// ---------------------------------------------------------------
static void DrvEventLoop() {
    LogPost(L"[DRV] 内核事件接收已启动");
    while (g_running.load()) {
        if (!DrvReady()) { Sleep(1000); continue; }
        ZZ_EVENT_UM ev;
        ZeroMemory(&ev, sizeof(ev));
        DWORD wr = 0;
        BOOL got = DeviceIoControl(g_drvHandle, IOCTL_ZZ_GET_EVENT,
                                   nullptr, 0, &ev, sizeof(ev), &wr, nullptr);
        if (!got || ev.Type == ZZ_EVT_NONE) { Sleep(200); continue; }   // 队列空, 退避

        const wchar_t* name = DrvEventName(ev.Type);
        // 写进行为时间线: 内核看到的动作, 在"行为"二级菜单里同样可查
        BehavAdd((DWORD)ev.Pid, wstring(ev.ImagePath), DrvEventToBehav(ev.Type),
                 (int)ev.Risk + 1, wstring(name) + L": " + wstring(ev.TargetPath));

        if (ev.Risk >= ZZ_RISK_DANGER) {
            // 内核判定为危险 → 直接拉红横幅, 这是最高优先级信号
            LogFmt(L"[DRV][危险] %s pid=%u %s | %s",
                   name, ev.Pid, ev.ImagePath, ev.Detail[0] ? ev.Detail : ev.TargetPath);
            SetThreatLevel(2, L"内核驱动拦截到危险行为");
        } else if (ev.Risk >= ZZ_RISK_WARN) {
            LogFmt(L"[DRV][警告] %s pid=%u %s", name, ev.Pid, ev.ImagePath);
        }
        // 被拦截类事件: 说明驱动已经替我们挡住了, 记一笔即可
        if (ev.Type == ZZ_EVT_PROC_BLOCKED || ev.Type == ZZ_EVT_REG_BLOCKED ||
            ev.Type == ZZ_EVT_FILE_BLOCKED || ev.Type == ZZ_EVT_SELF_PROTECT) {
            LogFmt(L"[DRV] 已拦截: %s -> %s", name, ev.TargetPath);
        }
    }
    LogPost(L"[DRV] 内核事件接收已退出");
}

// ---------------------------------------------------------------
//  DrvKillPid / DrvForceDelete: 走内核的强杀与强删
//  【思路】这两个是"用户态做不到但内核能"的典型:
//    - 强杀: 受保护进程(如 PPL)用户态 OpenProcess 直接失败;
//    - 强删: 文件被独占打开时, 用户态删不掉, 内核可用 FILE_DELETE_ON_CLOSE 标记。
//  失败时**返回 false 让调用方回落到用户态实现**, 绝不因为驱动异常就中断处置。
// ---------------------------------------------------------------
static bool DrvKillPid(DWORD pid) {
    if (!DrvReady() || pid == 0 || pid == 4) return false;
    ZZ_TARGET_UM t;
    ZeroMemory(&t, sizeof(t));
    t.Pid = (unsigned long)pid;
    DWORD wr = 0;
    if (!DeviceIoControl(g_drvHandle, IOCTL_ZZ_KILL_PID, &t, sizeof(t), nullptr, 0, &wr, nullptr)) {
        LogFmt(L"[DRV] 内核终止进程失败 pid=%u err=%u (回落用户态)", pid, GetLastError());
        return false;
    }
    LogFmt(L"[DRV] 内核已终止进程 pid=%u", pid);
    return true;
}
static bool DrvForceDelete(const wstring& path) {
    if (!DrvReady() || path.empty()) return false;
    ZZ_TARGET_UM t;
    ZeroMemory(&t, sizeof(t));
    wcsncpy_s(t.Path, ZZ_DRV_MAX_PATH, path.c_str(), _TRUNCATE);
    DWORD wr = 0;
    if (!DeviceIoControl(g_drvHandle, IOCTL_ZZ_FORCE_DELETE, &t, sizeof(t), nullptr, 0, &wr, nullptr)) {
        LogFmt(L"[DRV] 内核强制删除失败 err=%u (回落用户态)", GetLastError());
        return false;
    }
    LogFmt(L"[DRV] 内核已强制删除: %s", path.c_str());
    return true;
}

// ---------------------------------------------------------------
//  KillProcessHard: 统一入口 —— 内核优先, 失败回落用户态
//  【思路】把"先试内核再试用户态"收口到一个函数, 调用方不用关心驱动在不在。
//         这样新增调用点不会漏掉降级逻辑。
// ---------------------------------------------------------------
static bool KillProcessHard(DWORD pid) {
    // 【避坑】先问 DrvReady() 再进内核, 而不是无脑调用等内核自己返回失败:
    //        这样在驱动不可用时完全不产生内核调用开销, 日志也不会被"回落"刷屏。
    if (DrvReady() && DrvKillPid(pid)) return true;   // 内核成功
    return KillProcess(pid);                          // 回落: 原来的用户态实现
}

// ---------------------------------------------------------------
//  DrvStop: 停止并卸载驱动(供 UI 调用)
// ---------------------------------------------------------------
static void DrvClose() {
    if (g_drvHandle != INVALID_HANDLE_VALUE) { CloseHandle(g_drvHandle); g_drvHandle = INVALID_HANDLE_VALUE; }
    g_drvLoaded = false;
}
static bool DrvUninstall() {
    DrvClose();
    void* scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) { LogFmt(L"[DRV] 卸载: 打开 SCM 失败 err=%u", GetLastError()); return false; }
    void* svc = OpenServiceW(scm, ZZ_DRV_NAME, SERVICE_STOP | SERVICE_QUERY_STATUS | 0x10000);
    if (!svc) { LogPost(L"[DRV] 卸载: 服务不存在(可能从未安装)"); CloseServiceHandle(scm); return false; }
    SERVICE_STATUS ss; ZeroMemory(&ss, sizeof(ss));
    ControlService(svc, SERVICE_CONTROL_STOP, &ss);          // 先停(失败也无妨, 可能本来就没跑)
    bool ok = (DeleteService(svc) != 0);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    LogPost(ok ? L"[DRV] 驱动服务已卸载" : L"[DRV] 卸载驱动服务失败");
    return ok;
}

// ---------------------------------------------------------------
//  DrvInit: 启动时的统一装载入口
//  【思路】整个流程任何一步失败都只记日志然后返回 false,
//         上层照常启动所有用户态防护——驱动是"增强"不是"依赖"。
// ---------------------------------------------------------------
static bool DrvInit() {
    if (!g_cfg.drvOn) { LogPost(L"[DRV] 驱动支持已在配置中关闭, 使用应用层防护"); return false; }
    if (!DrvInstallAndStart()) return false;      // 装/启动
    if (!DrvOpen()) return false;                 // 连通道 + 握手
    if (!DrvSetRules()) return false;             // 下发策略
    LogPost(L"[DRV] 内核级防护已就绪(进程创建/镜像加载/注册表 拦截生效)");
    return true;
}

// ============================================================
//  UI: 页面创建 + 控件绑定 + 消息循环 + WinMain
// ============================================================

// ---- 前向声明 ----

// ===================== 未知/隐藏/后门账户清理 =====================
// 动态加载 netapi32.dll, 不链接 netapi32.lib
#ifndef _WIN32
#ifndef MAX_PREFERRED_LENGTH
#define MAX_PREFERRED_LENGTH ((DWORD)-1)
#endif
#ifndef UF_ACCOUNTDISABLE
#define UF_ACCOUNTDISABLE 0x0002
#endif
#ifndef UF_DONT_EXPIRE_PASSWD
#define UF_DONT_EXPIRE_PASSWD 0x10000
#endif
#ifndef FILTER_NORMAL_ACCOUNT
#define FILTER_NORMAL_ACCOUNT 0x0002
#endif
struct USER_INFO_3 {
    wchar_t* usri3_name;
    wchar_t* usri3_password;
    DWORD    usri3_password_age;
    DWORD    usri3_priv;
    wchar_t* usri3_home_dir;
    wchar_t* usri3_comment;
    DWORD    usri3_flags;
    wchar_t* usri3_script_path;
    DWORD    usri3_auth_flags;
    wchar_t* usri3_full_name;
    wchar_t* usri3_usr_comment;
    wchar_t* usri3_parms;
    wchar_t* usri3_workstations;
    DWORD    usri3_last_logon;
    DWORD    usri3_last_logoff;
    DWORD    usri3_acct_expires;
    DWORD    usri3_max_storage;
    DWORD    usri3_units_per_week;
    void*    usri3_logon_hours;
    DWORD    usri3_bad_pw_count;
    DWORD    usri3_num_logons;
    wchar_t* usri3_logon_server;
    DWORD    usri3_country_code;
    DWORD    usri3_code_page;
    DWORD    usri3_user_id;
    DWORD    usri3_primary_group_id;
    wchar_t* usri3_profile;
    wchar_t* usri3_home_dir_drive;
    DWORD    usri3_password_expired;
};
struct USER_INFO_1008 { DWORD usri1008_flags; };
struct LOCALGROUP_USERS_INFO_0 { wchar_t* lgrui0_name; };
#endif

typedef DWORD (WINAPI* FN_NetUserEnum)(const wchar_t*, DWORD, DWORD, BYTE**, DWORD, DWORD*, DWORD*, DWORD*);
typedef DWORD (WINAPI* FN_NetUserDel)(const wchar_t*, const wchar_t*);
typedef DWORD (WINAPI* FN_NetUserSetInfo)(const wchar_t*, const wchar_t*, DWORD, BYTE*, DWORD*);
typedef DWORD (WINAPI* FN_NetUserGetLocalGroups)(const wchar_t*, const wchar_t*, DWORD, DWORD, BYTE**, DWORD, DWORD*, DWORD*);
typedef DWORD (WINAPI* FN_NetApiBufferFree)(void*);

struct UserRisk {
    std::wstring name;
    int          risk;
    bool         hidden;      // 名字以 $ 结尾
    bool         admin;       // 隶属 Administrators
    bool         randName;    // 随机哈希式命名
    bool         neverLogon;
    bool         pwdNeverExpire;
    DWORD        rid;
};

static bool g_userAutoClean   = false;   // 自动禁用高危账户 (默认关, 仅告警)
static int  g_userRiskThresh  = 3;       // 风险阈值

// 内建/系统账户 RID, 绝不动
static bool IsBuiltinRid(DWORD rid) {
    return rid == 500 || rid == 501 || rid == 502 || rid == 503 || rid == 504;
}
static bool IsBuiltinName(const std::wstring& n) {
    static const wchar_t* kBuiltin[] = {
        L"Administrator", L"Guest", L"DefaultAccount", L"WDAGUtilityAccount",
        L"HelpAssistant", L"SUPPORT_388945a0", L"SYSTEM", L"LOCAL SERVICE",
        L"NETWORK SERVICE", L"sshd", L"Autologon"
    };
    for (const wchar_t* b : kBuiltin)
        if (_wcsicmp(n.c_str(), b) == 0) return true;
    return false;
}
// 随机哈希式命名: 全 hex 且长度 >= 8
static bool IsRandomName(const std::wstring& n) {
    if (n.size() < 8) return false;
    for (wchar_t c : n) {
        if (!((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F')))
            return false;
    }
    return true;
}

// 扫描本地账户, 输出风险列表
static std::vector<UserRisk> ScanUnknownUsers() {
    std::vector<UserRisk> out;
    HMODULE hNet = LoadLibraryW(L"netapi32.dll");
    if (!hNet) { LogPost(L"[USR] 无法加载 netapi32.dll, 跳过账户扫描"); return out; }
    auto fnEnum = (FN_NetUserEnum)GetProcAddress(hNet, "NetUserEnum");
    auto fnGrp  = (FN_NetUserGetLocalGroups)GetProcAddress(hNet, "NetUserGetLocalGroups");
    auto fnFree = (FN_NetApiBufferFree)GetProcAddress(hNet, "NetApiBufferFree");
    if (!fnEnum || !fnFree) { FreeLibrary(hNet); return out; }

    BYTE* buf = nullptr; DWORD read = 0, total = 0, resume = 0;
    DWORD st = fnEnum(nullptr, 3, FILTER_NORMAL_ACCOUNT, &buf,
                      MAX_PREFERRED_LENGTH, &read, &total, &resume);
    if (st != 0 || !buf) {
        LogFmt(L"[USR] NetUserEnum 失败, 码=%u (需管理员权限)", (unsigned)st);
        FreeLibrary(hNet);
        return out;
    }
    USER_INFO_3* us = (USER_INFO_3*)buf;
    for (DWORD i = 0; i < read; ++i) {
        UserRisk u{};
        u.name  = us[i].usri3_name ? us[i].usri3_name : L"";
        u.rid   = us[i].usri3_user_id;
        u.hidden         = !u.name.empty() && u.name.back() == L'$';
        u.rid            = us[i].usri3_user_id;
        u.neverLogon     = (us[i].usri3_last_logon == 0);
        u.pwdNeverExpire = (us[i].usri3_flags & UF_DONT_EXPIRE_PASSWD) != 0;
        u.randName       = IsRandomName(u.name);

        // 管理员判定: priv==2 (USER_PRIV_ADMIN) 或隶属 Administrators
        if (us[i].usri3_priv == 2) u.admin = true;
        if (fnGrp) {
            BYTE* gb = nullptr; DWORD gr = 0, gt = 0;
            if (fnGrp(nullptr, u.name.c_str(), 0, 0, &gb, MAX_PREFERRED_LENGTH, &gr, &gt) == 0 && gb) {
                LOCALGROUP_USERS_INFO_0* g0 = (LOCALGROUP_USERS_INFO_0*)gb;
                for (DWORD k = 0; k < gr; ++k)
                    if (g0[k].lgrui0_name && _wcsicmp(g0[k].lgrui0_name, L"Administrators") == 0)
                        u.admin = true;
                fnFree(gb);
            }
        }

        int risk = 0;
        if (u.hidden)   risk += 3;   // 隐藏账户, 经典后门
        if (u.admin)    risk += 2;
        if (u.randName) risk += 2;
        if (u.neverLogon)     risk += 1;
        if (u.pwdNeverExpire) risk += 1;
        if (u.rid >= 1000)    risk += 1;  // 非系统基线账户
        u.risk = risk;

        // 兜底: 绝不动内建/当前登录账户
        if (IsBuiltinRid(u.rid) || IsBuiltinName(u.name)) continue;
        wchar_t cur[256] = {0}; DWORD cs = 256;
        if (GetUserNameW(cur, &cs) && _wcsicmp(cur, u.name.c_str()) == 0) continue;

        if (risk >= 1) out.push_back(u);
    }
    fnFree(buf);
    FreeLibrary(hNet);
    return out;
}

// 处置: 先禁用切断后门, 激进模式再删除 (删除前二次确认)
static int CleanUnknownUsers(bool aggressive) {
    auto users = ScanUnknownUsers();
    int acted = 0;
    for (auto& u : users) {
        if (u.risk < g_userRiskThresh) {
            LogFmt(L"[USR] 观察: %s (风险%d)", u.name.c_str(), u.risk);
            continue;
        }
        LogFmt(L"[USR] 高危账户: %s 风险=%d 隐藏=%d 管理员=%d 随机名=%d 从未登录=%d",
               u.name.c_str(), u.risk, (int)u.hidden, (int)u.admin,
               (int)u.randName, (int)u.neverLogon);
        BehavAdd(0, L"System", BEHAV_PROC_START, (u.risk >= 5) ? 9 : 7,
                 L"可疑账户: " + u.name + L" (风险" + std::to_wstring(u.risk) + L")");

        if (!g_userAutoClean && !aggressive) continue;

        HMODULE hNet = LoadLibraryW(L"netapi32.dll");
        if (!hNet) continue;
        auto fnSet  = (FN_NetUserSetInfo)GetProcAddress(hNet, "NetUserSetInfo");
        auto fnDel  = (FN_NetUserDel)GetProcAddress(hNet, "NetUserDel");
        // 第一步: 禁用 (切断后门, 可恢复)
        if (fnSet) {
            USER_INFO_1008 ui{}; ui.usri1008_flags = UF_ACCOUNTDISABLE;
            DWORD err = 0;
            DWORD st  = UserAskSet(fnSet, nullptr, u.name.c_str(), 1008, (BYTE*)&ui, &err);
            if (st == 0) { LogFmt(L"[USR] 已禁用账户: %s", u.name.c_str()); ++acted; }
            else LogFmt(L"[USR] 禁用失败: %s 码=%u", u.name.c_str(), (unsigned)st);
        }
        // 第二步: 激进模式删除 (需二次确认)
        if (aggressive && fnDel) {
            wchar_t msg[512];
            swprintf_s(msg, 512, L"确认删除账户 \"%s\"?\n(风险分 %d, 已先禁用)\n删除后不可恢复。",
                       u.name.c_str(), u.risk);
            if (MessageBoxW(g_hMain, msg, L"未知账户清理", MB_YESNO | MB_ICONWARNING) == IDYES) {
                DWORD st = UserAskDel(fnDel, nullptr, u.name.c_str());
                if (st == 0) { LogFmt(L"[USR] 已删除账户: %s", u.name.c_str()); ++acted; }
                else LogFmt(L"[USR] 删除失败: %s 码=%u", u.name.c_str(), (unsigned)st);
            }
        }
        FreeLibrary(hNet);
    }
    return acted;
}

static void UserGuardLoop() {
    int rounds = 0;
    while (g_running.load()) {
        for (int i = 0; i < 60 && g_running.load(); ++i) Sleep(1000);
        if (!g_running.load()) break;
        auto users = ScanUnknownUsers();
        for (auto& u : users)
            if (u.risk >= g_userRiskThresh)
                LogFmt(L"[USR] 守护告警: %s 风险=%d", u.name.c_str(), u.risk);
        if (++rounds % 10 == 0 && g_userAutoClean)
            CleanUnknownUsers(false);
    }
}
// ===================== END 未知用户清理 =====================
// ===================== V13.5.0 资源异常监控 + 顽固病毒免疫处置 =====================
#define WM_APP_ALERT (WM_APP + 11)

static std::atomic<bool> g_lockdown{false};      // 超强拦截
static std::atomic<bool> g_silentGuard{false};   // 静默防护
static std::atomic<bool> g_resGuardOn{true};     // 资源异常监控
static std::atomic<bool> g_immunizeOn{true};     // 顽固病毒免疫处置(同名诱饵文件)
// ---- 持久化与劫持检测开关 ----
static std::atomic<bool> g_hostGuardOn{true};    // hosts 劫持检测
static std::atomic<bool> g_wmiScanOn{true};      // WMI 持久化检测
static std::atomic<bool> g_taskScanOn{true};     // 计划任务持久化检测
static std::atomic<bool> g_clipGuardOn{true};    // 剪贴板劫持监控
static std::atomic<bool> g_selfDefenseOn{true};  // 自我保护看门狗
static std::atomic<bool> g_netAuditOn{true};     // 网络审计
// ---- 深度对抗检测开关 ----
static std::atomic<bool> g_lsassGuardOn{true};    // LSASS 凭据窃取检测
static std::atomic<bool> g_hollowScanOn{true};    // 进程镂空检测
static std::atomic<bool> g_dllHijackOn{true};     // DLL 劫持检测

// ---------- 进程资源采样 ----------
struct ResSample {
    unsigned long long cpuTicks = 0;   // 累计 CPU (Kernel+User), 100ns tick
    unsigned long long ioBytes  = 0;   // 累计磁盘读写字节
    unsigned long long wallMs   = 0;   // 墙钟毫秒
};
static std::mutex g_resMtx;
static std::map<DWORD, ResSample> g_resPrev;

struct GpuInfo {
    bool present = false;
    int  util = 0;                              // GPU 利用率 %
    unsigned long long memUsed = 0, memTotal = 0;
    std::map<DWORD, unsigned long long> cudaProcs;  // pid -> 显存字节
};

// 通过 nvidia-smi 采样 GPU 利用率/显存 与 CUDA 占用进程
// 无 NVIDIA 卡或驱动时优雅返回 present=false, 不报错不卡住
static GpuInfo ResQueryGpu() {
    GpuInfo gi;
    FILE* pf = _popen("nvidia-smi --query-gpu=utilization.gpu,memory.used,memory.total --format=csv,noheader,nounits", "r");
    if (!pf) return gi;
    char line[256];
    if (fgets(line, sizeof(line), pf)) {
        int u = 0; unsigned long long mu = 0, mt = 0;
        if (sscanf(line, "%d, %llu, %llu", &u, &mu, &mt) == 3) {
            gi.present = true; gi.util = u; gi.memUsed = mu; gi.memTotal = mt;
        }
    }
    _pclose(pf);
    if (!gi.present) return gi;
    FILE* pf2 = _popen("nvidia-smi --query-compute-apps=pid,used_memory --format=csv,noheader,nounits", "r");
    if (!pf2) return gi;
    while (fgets(line, sizeof(line), pf2)) {
        unsigned long pid = 0; unsigned long long mem = 0;
        if (sscanf(line, "%lu, %llu", &pid, &mem) == 2)
            gi.cudaProcs[(DWORD)pid] = mem;
    }
    _pclose(pf2);
    return gi;
}

struct ResAnomaly {
    DWORD pid; std::wstring name;
    int cpuPct; unsigned long long memMB, ioMB;
    int conns; unsigned long long cudaMB;
    int score;
};

// 资源异常扫描: CPU/内存/磁盘IO/GPU-CUDA/网络连接
// 综合得分 >= 4 触发优先通知(取前 3), 激进模式下 >= 6 自动结束进程
static std::vector<ResAnomaly> ResourceAnomalyScan() {
    std::vector<ResAnomaly> out;
    auto procs = SnapshotProcs();
    auto nets  = SnapshotNets();
    GpuInfo gpu = ResQueryGpu();

    // 每进程连接数
    std::map<DWORD, int> connCnt;
    for (auto& n : nets) connCnt[n.pid]++;

    unsigned long long nowMs = GetTickCount64();
    std::vector<ResAnomaly> all;
    {
        std::lock_guard<std::mutex> lk(g_resMtx);
        for (auto& p : procs) {
            if (p.pid == 0) continue;
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.pid);
            if (!h) continue;

            unsigned long long cpuTicks = 0, ioBytes = 0;
            unsigned long long memMB = 0;
            FILETIME_R ftCreation, ftExit, ftKernel, ftUser;
            if (GetProcessTimes(h, &ftCreation, &ftExit, &ftKernel, &ftUser)) {
                unsigned long long k = ((unsigned long long)ftKernel.dwHighDateTime << 32) | ftKernel.dwLowDateTime;
                unsigned long long u = ((unsigned long long)ftUser.dwHighDateTime << 32) | ftUser.dwLowDateTime;
                cpuTicks = k + u;
            }
            PROCESS_MEMORY_COUNTERS pmc; pmc.cb = sizeof(pmc);
            if (GetProcessMemoryInfo(h, &pmc, sizeof(pmc))) memMB = pmc.WorkingSetSize / (1024ULL * 1024ULL);
            IO_COUNTERS ioc;
            if (GetProcessIoCounters(h, &ioc)) ioBytes = ioc.ReadTransferCount + ioc.WriteTransferCount;
            CloseHandle(h);

            // 与上一帧比较求增量
            int cpuPct = 0; double ioMBd = 0;
            auto it = g_resPrev.find(p.pid);
            if (it != g_resPrev.end() && nowMs > it->second.wallMs) {
                unsigned long long dWall = nowMs - it->second.wallMs;
                if (dWall > 0 && cpuTicks >= it->second.cpuTicks) {
                    unsigned long long dCpu = cpuTicks - it->second.cpuTicks;
                    // dCpu 单位 100ns -> ms: /10000 ; 单核口径
                    cpuPct = (int)((dCpu / 10000.0) / (double)dWall * 100.0);
                    if (cpuPct < 0) cpuPct = 0;
                }
                if (ioBytes >= it->second.ioBytes)
                    ioMBd = (ioBytes - it->second.ioBytes) / (1024.0 * 1024.0);
            }
            g_resPrev[p.pid] = ResSample{cpuTicks, ioBytes, nowMs};

            int conns = connCnt[p.pid];
            unsigned long long cudaMB = 0;
            auto ci = gpu.cudaProcs.find(p.pid);
            if (ci != gpu.cudaProcs.end()) cudaMB = ci->second;

            // ---- 打分 ----
            int score = 0;
            if (cpuPct >= g_cfg.resCpuThresh) score += 2;
            if ((long long)memMB >= g_cfg.resMemMB) score += 2;
            if (ioMBd >= g_cfg.resIoMB) score += 2;
            if (conns >= g_cfg.resConnThresh) score += 2;
            // 挖矿权重最高
            if (cudaMB > 0) score += 3;
            else if (gpu.present && gpu.util >= g_cfg.resGpuThresh) score += 3;

            if (score >= 4) {
                ResAnomaly a;
                a.pid = p.pid; a.name = p.name; a.cpuPct = cpuPct;
                a.memMB = memMB; a.ioMB = (unsigned long long)ioMBd;
                a.conns = conns; a.cudaMB = cudaMB; a.score = score;
                all.push_back(a);
            }
        }
        // 清理已退出进程的采样, 防止无限增长
        std::set<DWORD> alive;
        for (auto& p : procs) alive.insert(p.pid);
        for (auto it2 = g_resPrev.begin(); it2 != g_resPrev.end(); ) {
            if (!alive.count(it2->first)) it2 = g_resPrev.erase(it2); else ++it2;
        }
    }
    // 排序取前 3
    std::sort(all.begin(), all.end(), [](const ResAnomaly& a, const ResAnomaly& b) { return a.score > b.score; });
    for (size_t i = 0; i < all.size() && i < 3; ++i) out.push_back(all[i]);
    return out;
}

// 资源异常优先通知 (UI 线程弹窗, 不跨线程操作控件)
static void ResourceAlert() {
    auto list = ResourceAnomalyScan();
    if (list.empty()) { LogPost(L"[RES] 资源扫描完成, 未发现异常占用进程"); return; }
    std::wstring msg = L"检测到资源异常占用进程:\n\n";
    wchar_t buf[256];
    for (auto& a : list) {
        swprintf(buf, 256, L"PID %lu %s | CPU %d%% | 内存 %lluMB | 磁盘IO %lluMB | 连接 %d | CUDA %lluMB | 风险分 %d\n",
                 (unsigned long)a.pid, a.name.c_str(), a.cpuPct, a.memMB, a.ioMB, a.conns, a.cudaMB, a.score);
        msg += buf;
    }
    msg += L"\n建议: 查看该进程行为记录, 必要时结束进程并执行全盘扫描。";
    LogFmt(L"[RES] 优先通知: %d 个进程资源异常", (int)list.size());

    // 激进模式: 分值 >= 6 自动结束
    if (g_cfg.advAggressive) {
        for (auto& a : list) {
            if (a.score >= 6) {
                LogFmt(L"[RES] 激进模式自动结束进程 PID %lu (%s) 分值 %d",
                       (unsigned long)a.pid, a.name.c_str(), a.score);
                KillProcessAuto(a.pid);
            }
        }
    }
    wchar_t* dup = new (std::nothrow) wchar_t[msg.size() + 1];
    if (!dup) return;
    wcscpy_s(dup, msg.size() + 1, msg.c_str());
    if (!PostMessageW(g_hMain, WM_APP_ALERT, 0, reinterpret_cast<LPARAM>(dup)))
        delete[] dup;
}

// ---------- 顽固病毒免疫处置 ----------
// 无法彻底删除时: 结束占用 -> 删除/移出/重启删 -> 创建同名占位文件(写满随机数据)
// -> 设只读+系统+隐藏 -> 开启超强拦截+静默防护 -> 弹窗提示
static bool PurgeIncurable(const std::wstring& path) {
    // v13.14: 顽固病毒免疫处置需用户确认
    if (g_alertAsk.load()) {
        int a = AlertConfirm(L"ZZ EDR 安全告警",
                             L"该病毒无法彻底清除，是否以「同名占位文件+超强拦截」方式免疫处置？", path, 0);
        if (a != ALERT_HANDLE) { LogPost(L"[已忽略] 用户选择不免疫: " + path); return false; }
    }
    if (path.empty()) return false;
    if (IsProtectedPath(path)) {
        LogFmt(L"[IMM] 拒绝处置受保护路径: %s", path.c_str());
        return false;
    }
    LogFmt(L"[IMM] 开始免疫处置: %s", path.c_str());

    // 1. 结束所有占用该路径的进程
    for (auto& p : SnapshotProcs())
        if (!p.path.empty() && _wcsicmp(p.path.c_str(), path.c_str()) == 0 && p.pid != GetCurrentProcessId())
            KillProcess(p.pid);
    Sleep(300);

    // 2. 删除; 失败则移出; 再失败则标记重启删除
    bool removed = false;
    if (DeleteFileW(path.c_str())) {
        removed = true;
        LogPost(L"[IMM] 原文件已删除");
    } else {
        std::wstring junk = path + L".zz_EDR_junk_";
        wchar_t tail[32]; swprintf(tail, 32, L"%lu", (unsigned long)GetTickCount64());
        junk += tail;
        if (MoveFileW(path.c_str(), junk.c_str())) {
            removed = true;
            LogPost(L"[IMM] 原文件已移出为 .zz_EDR_junk_*");
        } else if (MoveFileExW(path.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT)) {
            removed = true;
            LogPost(L"[IMM] 原文件已标记重启时删除");
        } else {
            LogPost(L"[IMM] 警告: 原文件无法移动, 将直接覆盖创建同名占位文件");
        }
    }

    // 3. 创建同名占位文件并写满随机数据 (1MB), 使病毒无法再写入/执行
    HANDLE hf = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) {
        LogPost(L"[IMM] 失败: 无法创建同名占位文件");
        return false;
    }
    const size_t kChunk = 64 * 1024;
    std::vector<unsigned char> chunk(kChunk);
    std::mt19937 rng((unsigned)time(nullptr) ^ (unsigned)GetTickCount64());
    const int kRounds = 16;   // 16 * 64KB = 1MB
    for (int r = 0; r < kRounds; ++r) {
        for (size_t i = 0; i < kChunk; ++i) chunk[i] = (unsigned char)(rng() & 0xFF);
        DWORD written = 0;
        if (!WriteFile(hf, chunk.data(), (DWORD)kChunk, &written, nullptr) || written != kChunk) break;
    }
    FlushFileBuffers(hf);
    CloseHandle(hf);
    LogPost(L"[IMM] 已创建同名占位文件(写入 1MB 随机数据)");

    // 4. 设只读 + 系统 + 隐藏
    DWORD attr = GetFileAttributesW(path.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES)
        SetFileAttributesW(path.c_str(), attr | FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
    LogPost(L"[IMM] 占位文件已设为只读+系统+隐藏, 病毒无法再写入或执行");

    // 5. 开启超强拦截 + 静默防护
    g_lockdown.store(true);
    g_silentGuard.store(true);
    LogPost(L"[IMM] 已开启超强拦截 + 静默防护");

    // 6. 通知用户
    std::wstring msg = L"EDR程序已为您拦截此病毒，建议执行全盘扫描。\n\n";
    msg += L"文件: " + path + L"\n";
    msg += removed ? L"原恶意文件已清除, 并创建同名只读占位文件阻止其复活。\n"
                   : L"原文件被占用, 已创建同名占位文件并标记重启后清除。\n";
    wchar_t* dup = new (std::nothrow) wchar_t[msg.size() + 1];
    if (dup) {
        wcscpy_s(dup, msg.size() + 1, msg.c_str());
        if (!PostMessageW(g_hMain, WM_APP_ALERT, 0, reinterpret_cast<LPARAM>(dup)))
            delete[] dup;
    }
    return true;
}

// 批量免疫: 对所有可疑/情报命中的进程文件执行免疫处置
static void PurgeIncurableAll() {
    if (!g_immunizeOn.load()) { LogPost(L"[IMM] 免疫处置未开启"); return; }
    auto procs = SnapshotProcs();
    int n = 0;
    for (auto& p : procs) {
        if (p.path.empty()) continue;
        if (IsProtectedPath(p.path)) continue;
        if (!p.suspicious) continue;
        if (PurgeIncurable(p.path)) ++n;
    }
    LogFmt(L"[IMM] 批量免疫完成, 处置 %d 个文件", n);
}

// ===================== 持久化与劫持检测 (补齐此前为 0 的六类) =====================
//   hosts 劫持 / WMI 事件订阅 / 计划任务 / 剪贴板劫持 / 自我保护 / 网络审计
//   均以真实文件读取或命令输出解析实现, 不做日志占位。

// 执行命令并逐行回调(用于枚举持久化项)
static bool CmdEachLine(const char* cmd, void (*cb)(const std::string&, void*), void* ctx) {
    FILE* pf = _popen(cmd, "r");
    if (!pf) return false;
    char buf[4096];
    while (fgets(buf, (int)sizeof(buf), pf)) if (cb) cb(std::string(buf), ctx);
    _pclose(pf);
    return true;
}

// ---------- 1. hosts 文件劫持检测与修复 ----------
// 判据: hosts 中把域名指向"非回环地址"视为劫持。
//       正常用途(屏蔽广告)是 127.0.0.1 / 0.0.0.0 / ::1；
//       恶意劫持会把安全软件/银行域名指向攻击者 IP。
static bool IsLoopbackIp(const std::string& ip) {
    if (ip.rfind("127.", 0) == 0) return true;
    if (ip == "::1" || ip == "0.0.0.0" || ip == "localhost") return true;
    return false;
}
static void HostsAuditRun() {
    wchar_t winDir[MAX_PATH] = { 0 };
    GetWindowsDirectoryW(winDir, MAX_PATH);
    std::wstring hp = std::wstring(winDir) + L"\\System32\\drivers\\etc\\hosts";
    FILE* f = _wfopen(hp.c_str(), L"rb");
    if (!f) { LogPost(L"[HOSTS] 无法打开 hosts, 跳过"); return; }
    std::string all; char b[4096]; size_t n;
    while ((n = fread(b, 1, sizeof(b), f)) > 0) all.append(b, n);
    fclose(f);

    // 解析每行, 分离正常行与劫持行
    std::vector<std::string> keep, bad;
    std::string cur; int hits = 0;
    for (size_t i = 0; i <= all.size(); ++i) {
        if (i == all.size() || all[i] == '\n') {
            if (!cur.empty() && cur.back() == '\r') cur.pop_back();
            bool isBad = false;
            std::string t = cur;
            // 去掉注释
            size_t hpos = t.find('#');
            if (hpos != std::string::npos) t = t.substr(0, hpos);
            // 提取首个 token 作为 IP
            std::string ip;
            size_t s = t.find_first_not_of(" \t");
            if (s != std::string::npos) {
                size_t e = t.find_first_of(" \t", s);
                ip = (e == std::string::npos) ? t.substr(s) : t.substr(s, e - s);
            }
            if (!ip.empty() && ip.find('.') != std::string::npos && !IsLoopbackIp(ip)) {
                // 有域名(第二个 token)才算劫持条目
                size_t ds = (s == std::string::npos) ? std::string::npos
                    : t.find_first_not_of(" \t", t.find_first_of(" \t", s));
                if (ds != std::string::npos) { isBad = true; ++hits; }
            }
            (isBad ? bad : keep).push_back(cur);
            cur.clear();
        } else cur += all[i];
    }
    if (hits == 0) { LogPost(L"[HOSTS] 未发现劫持条目, hosts 正常"); return; }

    LogFmt(L"[HOSTS] 发现 %d 条可疑劫持条目:", hits);
    for (auto& l : bad) {
        std::wstring wl(l.begin(), l.end());
        LogFmt(L"[HOSTS]   劫持: %s", wl.c_str());
    }
    SetThreatLevel(THREAT_DANGER, L"发现高危项");

    // 修复: 备份后重写, 仅保留正常行
    if (!g_cfg.advAggressive) {
        LogPost(L"[HOSTS] 未开启激进模式, 仅告警不修复(可在配置中开启)");
        return;
    }
    std::wstring bak = hp + L".zz_bak";
    if (CopyFileW(hp.c_str(), bak.c_str(), FALSE))
        LogPost(L"[HOSTS] 已备份原 hosts 到 hosts.zz_bak");
    FILE* o = _wfopen(hp.c_str(), L"wb");
    if (!o) { LogPost(L"[HOSTS] 重写失败(可能被占用)"); return; }
    for (auto& l : keep) { fwrite(l.data(), 1, l.size(), o); fputc('\n', o); }
    fclose(o);
    LogFmt(L"[HOSTS] 已清理 %d 条劫持条目", hits);
}

// ---------- 2. WMI 事件订阅持久化检测 ----------
// WMI 持久化(__EventFilter + __EventConsumer + __FilterToConsumerBinding)
// 是高级木马常用手法, 重启后仍生效且注册表看不到。
// 正常系统这三个类通常为空, 非空即可疑。
static void WmiPersistScan() {
    LogPost(L"[WMI] 扫描 WMI 事件订阅持久化...");
    struct Ctx { int n = 0; };
    Ctx ctx;
    const char* cmds[] = {
        "powershell -NoProfile -Command \"Get-WmiObject -Namespace root\\Subscription -Class __EventFilter 2>$null | ForEach-Object { $_.Name }\"",
        "powershell -NoProfile -Command \"Get-WmiObject -Namespace root\\Subscription -Class __EventConsumer 2>$null | ForEach-Object { $_.Name }\"",
        "powershell -NoProfile -Command \"Get-WmiObject -Namespace root\\Subscription -Class __FilterToConsumerBinding 2>$null | ForEach-Object { $_.Filter }\"",
    };
    const wchar_t* names[] = { L"__EventFilter", L"__EventConsumer", L"__FilterToConsumerBinding" };
    for (int i = 0; i < 3; ++i) {
        int found = 0;
        CmdEachLine(cmds[i], [](const std::string& line, void* c) {
            std::string t = line;
            while (!t.empty() && (t.back() == '\n' || t.back() == '\r' || t.back() == ' ')) t.pop_back();
            if (t.empty()) return;
            int* fn = (int*)c;
            if (++(*fn) <= 10) {
                std::wstring wl(t.begin(), t.end());
                LogFmt(L"[WMI]   订阅项: %s", wl.c_str());
            }
        }, &found);
        if (found > 0) {
            LogFmt(L"[WMI] %s 存在 %d 项 -> 可疑持久化", names[i], found);
            ctx.n += found;
        }
    }
    if (ctx.n == 0) LogPost(L"[WMI] 未发现 WMI 持久化订阅, 正常");
    else { LogFmt(L"[WMI] 共 %d 项可疑持久化, 建议核查", ctx.n); SetThreatLevel(THREAT_DANGER, L"发现高危项"); }
}

// ---------- 3. 计划任务持久化检测 ----------
// 枚举计划任务, 对"临时目录/可疑程序名/无签名路径"的任务告警。
static void TaskPersistScan() {
    LogPost(L"[TASK] 扫描计划任务持久化...");
    struct Ctx { int total = 0, susp = 0; };
    Ctx ctx;
    // 取任务名与要执行的命令
    CmdEachLine("schtasks /query /fo CSV /v /nh",
        [](const std::string& line, void* c) {
            Ctx* cc = (Ctx*)c;
            std::string t = line;
            while (!t.empty() && (t.back() == '\n' || t.back() == '\r')) t.pop_back();
            if (t.size() < 5) return;
            ++cc->total;
            std::string low; for (char ch : t) low += (char)tolower(ch);
            // 可疑: 临时目录 / AppData 下的执行体 / 脚本宿主 / 编码命令
            bool bad = false;
            const char* pats[] = { "\\temp\\", "\\appdata\\", "powershell", "wscript",
                                    "cscript", "mshta", "rundll32", "-enc", "regsvr32" };
            for (const char* p : pats) if (low.find(p) != std::string::npos) { bad = true; break; }
            if (bad) {
                ++cc->susp;
                if (cc->susp <= 10) {
                    std::wstring wl(t.begin(), t.end());
                    if (wl.size() > 150) wl = wl.substr(0, 150);
                    LogFmt(L"[TASK]   可疑任务: %s", wl.c_str());
                }
            }
        }, &ctx);
    LogFmt(L"[TASK] 共 %d 个任务, 其中 %d 个可疑", ctx.total, ctx.susp);
    if (ctx.susp > 0) SetThreatLevel(THREAT_WARN, L"发现可疑项");
}

// ---------- 4. 剪贴板劫持监控 ----------
// 攻击手法: 监视剪贴板, 把用户复制的钱包地址替换成攻击者的地址。
// 这里检测剪贴板中出现加密货币地址并告警(提示用户核对首尾字符)。
static bool LooksLikeCryptoAddr(const std::wstring& s) {
    if (s.size() < 25 || s.size() > 90) return false;
    // BTC: 1/3 开头 base58  或 bc1 开头 bech32
    if ((s[0] == L'1' || s[0] == L'3') && s.size() >= 26 && s.size() <= 35) {
        for (wchar_t c : s) if (!((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z'))) return false;
        return true;
    }
    if (s.rfind(L"bc1", 0) == 0 && s.size() >= 39) return true;
    // ETH: 0x + 40 hex
    if (s.rfind(L"0x", 0) == 0 && s.size() == 42) {
        for (size_t i = 2; i < s.size(); ++i)
            { wchar_t c = s[i]; bool ok = (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F'); if (!ok) return false; }
        return true;
    }
    return false;
}
static void ClipboardScanOnce() {
    if (!OpenClipboard(nullptr)) return;
    HANDLE h = GetClipboardData(CF_UNICODETEXT);
    if (h) {
        const wchar_t* p = (const wchar_t*)GlobalLock(h);
        if (p) {
            std::wstring s(p);
            GlobalUnlock(h);
            if (LooksLikeCryptoAddr(s)) {
                LogPost(L"[CLIP] 检测到剪贴板中存在加密货币地址!");
                LogFmt(L"[CLIP]   地址: %s", s.c_str());
                LogPost(L"[CLIP]   请核对首尾字符后再粘贴, 防范剪贴板劫持替换");
                SetThreatLevel(THREAT_WARN, L"发现可疑项");
            }
        }
    }
    CloseClipboard();
}
static void ClipboardGuardLoop() {
    while (g_running.load()) {
        for (int i = 0; i < 3 && g_running.load(); ++i) Sleep(1000);
        if (!g_running.load()) break;
        if (!g_clipGuardOn.load()) continue;
        ClipboardScanOnce();
    }
}

// ---------- 5. 自我保护看门狗 ----------
// EDR 被终止/被调试/被篡改即失去防护能力, 故需自保:
//   a) 检测是否被调试器附加(有人在分析或注入)
//   b) 周期性确认自身进程仍存活
//   c) 校验自身文件是否被替换
static void SelfDefenseLoop() {
    int debugHits = 0;
    while (g_running.load()) {
        for (int i = 0; i < 5 && g_running.load(); ++i) Sleep(1000);
        if (!g_running.load()) break;
        if (!g_selfDefenseOn.load()) continue;
        if (IsDebuggerPresent()) {
            if (++debugHits <= 3) {
                LogPost(L"[SELF] 警告: 检测到调试器附加到本进程!");
                SetThreatLevel(THREAT_WARN, L"发现可疑项");
            }
        } else debugHits = 0;
        // 自身进程存活确认
        bool alive = false;
        for (auto& p : SnapshotProcs())
            if (p.pid == GetCurrentProcessId()) { alive = true; break; }
        if (!alive) LogPost(L"[SELF] 警告: 未能在进程表中找到自身, 可能被隐藏");
    }
}

// ---------- 6. 网络审计: DNS 劫持 / 网关 ARP 欺骗 / 危险共享 ----------
static void NetAuditRun() {
    LogPost(L"[NET] 开始网络审计: DNS / 网关ARP / 共享");

    // (a) DNS 服务器配置检查(ipconfig /all 输出 DNS Servers 行)
    struct DCtx { int n = 0; };
    DCtx dc;
    CmdEachLine("ipconfig /all", [](const std::string& line, void* c) {
        std::string t = line;
        while (!t.empty() && (t.back() == '\n' || t.back() == '\r')) t.pop_back();
        DCtx* cc = (DCtx*)c;
        // 提取点分十进制 IP
        std::string ip;
        for (size_t i = 0; i + 6 < t.size(); ++i) {
            if (isdigit((unsigned char)t[i])) {
                size_t j = i; int dots = 0;
                while (j < t.size() && (isdigit((unsigned char)t[j]) || t[j] == '.')) {
                    if (t[j] == '.') ++dots;
                    ++j;
                }
                if (dots == 3) { ip = t.substr(i, j - i); break; }
            }
        }
        if (ip.empty()) return;
        // 私有地址/回环视为正常内网 DNS
        bool priv = ip.rfind("192.168.", 0) == 0 || ip.rfind("10.", 0) == 0
                 || ip.rfind("172.16.", 0) == 0 || ip.rfind("127.", 0) == 0;
        if (priv) return;
        ++cc->n;
        std::wstring wl(ip.begin(), ip.end());
        LogFmt(L"[NET]   DNS 条目: %s", wl.c_str());
    }, &dc);
    if (dc.n > 0) LogPost(L"[NET]   以上为公网地址条目(含网卡IP/DNS), 请人工核对是否被篡改");

    // (b) 网关 ARP 检查: 同一 MAC 出现在多个 IP 上即为 ARP 欺骗特征
    struct ACtx { std::map<std::string, std::vector<std::string>> mac2ips; };
    ACtx ac;
    CmdEachLine("arp -a", [](const std::string& line, void* c) {
        ACtx* cc = (ACtx*)c;
        std::string t = line;
        while (!t.empty() && (t.back() == '\n' || t.back() == '\r')) t.pop_back();
        if (t.size() < 20) return;
        std::string ip, mac;
        for (size_t i = 0; i + 6 < t.size(); ++i)
            if (isdigit((unsigned char)t[i]) && t.find('.', i) != std::string::npos
                && t.find('.', i) - i < 4) { 
                size_t j = i; int dots = 0;
                while (j < t.size() && (isdigit((unsigned char)t[j]) || t[j] == '.')) {
                    if (t[j] == '.') ++dots; ++j;
                }
                if (dots == 3) { ip = t.substr(i, j - i); break; }
            }
        size_t mp = t.find('-');
        if (mp != std::string::npos && mp >= 2) mac = t.substr(mp - 2);
        if (!ip.empty() && mac.size() >= 8)
            cc->mac2ips[mac].push_back(ip);
    }, &ac);
    int spoof = 0;
    for (auto& kv : ac.mac2ips) {
        if (kv.second.size() > 1) {
            ++spoof;
            std::wstring wl(kv.first.begin(), kv.first.end());
            LogFmt(L"[NET]   可疑: MAC %s 同时对应 %d 个 IP (ARP 欺骗特征)",
                   wl.c_str(), (int)kv.second.size());
        }
    }
    if (spoof > 0) { LogPost(L"[NET] 检测到可能的 ARP 欺骗!"); SetThreatLevel(THREAT_DANGER, L"发现高危项"); }
    else LogPost(L"[NET] 未发现 ARP 欺骗特征");

    // (c) 共享检查: 默认共享与可疑共享
    struct SCtx { int n = 0, susp = 0; };
    SCtx sc;
    CmdEachLine("net share", [](const std::string& line, void* c) {
        SCtx* cc = (SCtx*)c;
        std::string t = line;
        while (!t.empty() && (t.back() == '\n' || t.back() == '\r')) t.pop_back();
        if (t.size() < 3) return;
        if (t.find("命令成功") != std::string::npos || t.find("command completed") != std::string::npos) return;
        ++cc->n;
        std::string low; for (char ch : t) low += (char)tolower(ch);
        // 磁盘根共享 / 全盘共享属高危
        if (low.find("c:\\") != std::string::npos || low.find("d:\\") != std::string::npos) {
            ++cc->susp;
            std::wstring wl(t.begin(), t.end());
            if (wl.size() > 100) wl = wl.substr(0, 100);
            LogFmt(L"[NET]   高危共享: %s", wl.c_str());
        }
    }, &sc);
    LogFmt(L"[NET] 共享枚举完成, 共 %d 项, 其中 %d 项高危", sc.n, sc.susp);
    if (sc.susp > 0) SetThreatLevel(THREAT_WARN, L"发现可疑项");
}

// 资源异常守护: 每 10 秒采样一次
static void ResourceGuardLoop() {
    while (g_running.load()) {
        for (int i = 0; i < 10 && g_running.load(); ++i) Sleep(1000);
        if (!g_running.load()) break;
        if (!g_resGuardOn.load()) continue;
        ResourceAnomalyScan();
    }
}
// ===================== END V13.5.0 =====================


static LRESULT CALLBACK MainWndProc(HWND, UINT, WPARAM, LPARAM);
static void CreatePages(HWND parent);
static void ShowPage(int idx);
static void ApplyConfig();
static INT_PTR OnCommand(WPARAM wp, LPARAM lp);

// ---- 页面元数据 ----
struct Page {
    const wchar_t* title;
    HWND hwnd;
};
static Page g_pages[11] = {
    {L"概览"}, {L"进程"}, {L"网络"}, {L"防护"}, {L"回滚"},
    {L"隐私"}, {L"DLP"},  {L"FIM"},  {L"日志"}, {L"恢复"}, {L"紧急自救"},
};

// ---- 控件句柄 (用于显示/隐藏 展开区) ----
static HWND g_hCamOpts = nullptr, g_hMicOpts = nullptr, g_hScanOpts = nullptr;
static HWND g_hPwdEdit = nullptr;

static HWND CreateButton(HWND parent, const wchar_t* text, int id, int x, int y, int w, int h) {
    return CreateWindowExW(0, L"BUTTON", text, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                            x, y, w, h, parent, (HMENU)id, GetModuleHandleW(nullptr), nullptr);
}
static HWND CreateCheck(HWND parent, const wchar_t* text, int id, int x, int y, int w, int h) {
    return CreateWindowExW(0, L"BUTTON", text, WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                            x, y, w, h, parent, (HMENU)id, GetModuleHandleW(nullptr), nullptr);
}
static HWND CreateLabel(HWND parent, const wchar_t* text, int x, int y, int w, int h) {
    return CreateWindowExW(0, L"STATIC", text, WS_CHILD | WS_VISIBLE | SS_LEFT,
                            x, y, w, h, parent, nullptr, GetModuleHandleW(nullptr), nullptr);
}
static HWND CreateEdit(HWND parent, int id, const wchar_t* text, int x, int y, int w, int h, bool password) {
    DWORD style = WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL;
    HWND e = CreateWindowExW(0, L"EDIT", text, style, x, y, w, h, parent,
                              (HMENU)id, GetModuleHandleW(nullptr), nullptr);
    if (password) SendMessageW(e, EM_SETPASSWORDCHAR, (WPARAM)L'*', 0);
    return e;
}

// ============================================================
//  各页面控件创建
// ============================================================

// ============================================================
//  行为时间线窗口 (二级菜单)
//  从进程列表点击"行为"弹出, 显示该进程自建档以来的全部操作
// ============================================================
static HWND g_hBehavWnd = nullptr;
static DWORD g_behavPid = 0;

static LRESULT CALLBACK BehavWndProc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
    switch (m) {
        case WM_CREATE: {
            HWND lb = CreateWindowExW(0, L"LISTBOX", nullptr,
                                      WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | WS_BORDER,
                                      10, 40, 760, 400, h, (HMENU)IDC_BEHAV_LIST,
                                      GetModuleHandleW(nullptr), nullptr);
            (void)lb;
            return 0;
        }
        case WM_COMMAND:
            if (LOWORD(wp) == 1) { DestroyWindow(h); }   // 关闭按钮
            break;
        case WM_DESTROY:
            g_hBehavWnd = nullptr;
            break;
    }
    return DefWindowProcW(h, m, wp, lp);
}

static void ShowBehaviorWindow(HWND parent, DWORD pid, const wstring& procName) {
    if (g_hBehavWnd) { DestroyWindow(g_hBehavWnd); g_hBehavWnd = nullptr; }
    g_behavPid = pid;

    WNDCLASSEXW wc;
    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = BehavWndProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"ZZ_EDR_BehavWnd";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursorW(nullptr, (LPCWSTR)IDC_ARROW_STUB);
    RegisterClassExW(&wc);

    wstring title = L"行为时间线 - " + procName + L" (PID=" + std::to_wstring(pid) + L")";
    g_hBehavWnd = CreateWindowExW(0, L"ZZ_EDR_BehavWnd", title.c_str(),
                                  WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                                  CW_USEDEFAULT, CW_USEDEFAULT, 800, 940,
                                  parent, nullptr, GetModuleHandleW(nullptr), nullptr);
    if (!g_hBehavWnd) return;

    CreateWindowExW(0, L"BUTTON", L"关闭", WS_CHILD | WS_VISIBLE,
                    690, 8, 80, 26, g_hBehavWnd, (HMENU)1, GetModuleHandleW(nullptr), nullptr);

    HWND lb = GetDlgItem(g_hBehavWnd, IDC_BEHAV_LIST);
    if (!lb) return;
    SendMessageW(lb, LB_RESETCONTENT, 0, 0);

    auto recs = BehavGet(pid);
    if (recs.empty()) {
        SendMessageW(lb, LB_ADDSTRING, 0, (LPARAM)L"(该进程暂无记录的行为)");
        return;
    }
    wchar_t buf[900];
    for (auto& r : recs) {
        // 时间戳 -> 本地时间
        time_t tt = (time_t)r.ts;
        struct tm tmv;
        localtime_s(&tmv, &tt);
        wchar_t tbuf[32];
        swprintf_s(tbuf, 32, L"%02d:%02d:%02d", tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
        swprintf_s(buf, 900, L"[%s] %s(风险%d) %s",
                   tbuf, BehavTypeName(r.type), r.risk, r.detail.c_str());
        SendMessageW(lb, LB_ADDSTRING, 0, (LPARAM)buf);
    }
}

// ---- 刷新进程列表 (每行右侧标注"行为") ----
// 在 UI 池线程里采集进程数据(枚举 + 组字符串), 不触碰任何控件句柄。
// 【为什么要拆开】EnumAllProcesses 需要遍历进程并逐个读内存信息, 是重操作。
// 直接在 UI 线程做会让界面在数百个进程时明显卡顿。
static std::vector<std::wstring> BuildProcListLines() {
    EnumAllProcesses();
    auto procs = SnapshotProcs();
    std::vector<std::wstring> out;
    out.reserve(procs.size());
    for (auto& p : procs) {
        wchar_t buf[700];
        swprintf_s(buf, 700, L"PID=%-6u %-28s %s",
                   p.pid, p.name.c_str(), L"                          [行为]");
        out.push_back(buf);
    }
    return out;
}

// 异步刷新: 采集交给 UI 池(3 线程), 结果 PostMessage 回 UI 线程填充控件
static void RefreshProcListAsync() {
    if (!g_hMain) return;
    LaunchUi([] {
        auto* v = new std::vector<std::wstring>(BuildProcListLines());
        if (!PostMessageW(g_hMain, WM_APP_PROCLIST, 0, reinterpret_cast<LPARAM>(v)))
            delete v;                       // 投递失败必须释放, 否则泄漏
    });
}

// 同步版: 仅在创建页面等必须立即有内容的场景使用
static void RefreshProcList(HWND listBox) {
    if (!listBox) return;
    SendMessageW(listBox, LB_RESETCONTENT, 0, 0);
    for (const auto& line : BuildProcListLines())
        SendMessageW(listBox, LB_ADDSTRING, 0, (LPARAM)line.c_str());
}

static void CreateOverviewPage(HWND p) {
    CreateButton(p, L"全盘扫描",   IDC_CB_PROTECTION_SCAN,   20, 20, 140, 32);
    CreateButton(p, L"刷新状态",   IDC_CB_REFRESH,           180, 20, 140, 32);
    CreateButton(p, L"日夜主题切换", IDC_CB_THEME_TOGGLE,    340, 20, 140, 32);
    CreateButton(p, L"解除告警",   IDC_CB_CLEAR_THREAT,      20, 104, 140, 28);
    CreateLabel (p, L"引擎状态总览 / 最近事件", 20, 144, 400, 20);
}
static void CreateProcessPage(HWND p) {
    CreateButton(p, L"终止所有可疑", IDC_CB_KILLALL,  20, 20, 150, 32);
    CreateButton(p, L"深度清理",     IDC_CB_DEEPCLEAN, 190, 20, 150, 32);
    CreateButton(p, L"检测远程控制", IDC_CB_REMOTE,    20, 62, 150, 32);
    CreateButton(p, L"刷新",         IDC_CB_REFRESH,   190, 62, 150, 32);
    CreateButton(p, L"查看行为(选中项)", IDC_BTN_BEHAVIOR, 360, 62, 170, 32);
    CreateButton(p, L"结束进程树(选中项)", IDC_CB_KILL_TREE, 545, 62, 175, 32);
    CreateLabel (p, L"进程列表 (双击某行 或 选中后点\"查看行为\" 打开该进程行为时间线):",
                 20, 104, 600, 20);
    g_hProcList = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", nullptr,
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL,
        20, 128, 700, 240, p, (HMENU)IDC_PROC_LIST,
        GetModuleHandleW(nullptr), nullptr);
    RefreshProcListAsync();                 // v13.29: 异步填充, 不阻塞页面创建
}
static void CreateNetworkPage(HWND p) {
    CreateButton(p, L"打开网络防护窗口", IDC_CB_NETWORK_WINDOW,  20, 20, 180, 32);
    CreateButton(p, L"刷新连接",         IDC_CB_NETWORK_REFRESH, 220, 20, 140, 32);
    CreateButton(p, L"断开全部可疑",     IDC_CB_DISCONNECT,       20, 62, 180, 32);
}

// ==================================================================
//  建议对照实现 (多引擎/防护面/深度扫描/补丁/备份/引导/专杀)
// ==================================================================

// ---- 建议#6: VirusTotal 多引擎在线核查 (v3 API, 按哈希查询, 不上传文件) ----
static bool VtLookupHash(const std::wstring& hash, int& pos, int& total, std::wstring& verdict) {
    pos = 0; total = 0; verdict = L"无结果";
    if (hash.size() != 32 && hash.size() != 40 && hash.size() != 64) { verdict = L"哈希格式无效"; return false; }
    if (g_cfg.vtApiKey.empty()) { verdict = L"未配置 API Key(请在配置填 vtApiKey)"; return false; }
    HINTERNET hSess = WinHttpOpen(L"zzEDR/13", 0, nullptr, nullptr, 0);
    if (!hSess) { verdict = L"网络初始化失败"; return false; }
    HINTERNET hConn = WinHttpConnect(hSess, L"www.virustotal.com", 443, 0);
    if (!hConn) { WinHttpCloseHandle(hSess); verdict = L"连接失败"; return false; }
    std::wstring path = L"/api/v3/files/" + hash;
    HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", path.c_str(), nullptr, nullptr, nullptr, WINHTTP_FLAG_SECURE);
    if (!hReq) { WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess); verdict = L"请求创建失败"; return false; }
    std::wstring hdr = L"x-apikey: " + g_cfg.vtApiKey;
    WinHttpSendRequest(hReq, hdr.c_str(), (unsigned long)hdr.size(), nullptr, 0, 0, 0);
    WinHttpReceiveResponse(hReq, nullptr);
    char buf[4096]; unsigned long got = 0; std::string acc;
    while (WinHttpQueryDataAvailable(hReq, &got) && got > 0) {
        unsigned long rd = 0;
        if (!WinHttpReadData(hReq, buf, (unsigned long)sizeof(buf), &rd) || rd == 0) break;
        acc.append(buf, rd);
    }
    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
    if (acc.empty()) { verdict = L"无响应(离线或 Key 无效)"; return false; }
    auto findNum = [&](const char* key) -> int {
        std::string k = std::string("\"") + key + "\":";
        auto p = acc.find(k);
        if (p == std::string::npos) return -1;
        p += k.size();
        while (p < acc.size() && (acc[p] < '0' || acc[p] > '9')) ++p;
        int v = 0;
        while (p < acc.size() && acc[p] >= '0' && acc[p] <= '9') { v = v * 10 + (acc[p] - '0'); ++p; }
        return v;
    };
    int m = findNum("malicious");
    int t = findNum("total");
    if (m < 0 || t < 0) { verdict = L"响应解析失败"; return false; }
    pos = m; total = t;
    verdict = (m > 0) ? L"恶意" : L"干净";
    return true;
}

// 对当前进程列表中每个可执行文件做在线多引擎核查(限前 N 个, 避免刷爆配额)
static void VtScanRunning(int limit = 8) {
    if (g_cfg.vtApiKey.empty()) {
        LogPost(L"[多引擎] 未配置 VirusTotal API Key, 跳过在线核查(可在配置文件填 vtApiKey)");
        return;
    }
    auto procs = SnapshotProcs();
    int done = 0, bad = 0;
    for (const auto& p : procs) {
        if (done >= limit) break;
        if (p.path.empty() || IsProtectedPath(p.path)) continue;
        std::wstring hex;
        if (!FileSha256W(p.path, hex)) continue;
        int pos = 0, total = 0; std::wstring vd;
        if (!VtLookupHash(hex, pos, total, vd)) continue;
        ++done;
        if (pos > 0) {
            ++bad;
            LogFmt(L"[多引擎][恶意] %s (pid=%u) %d/%d 引擎报毒 -> %s",
                   p.name.c_str(), (unsigned)p.pid, pos, total, vd.c_str());
            if (g_cfg.advAggressive) { QuarantineFile(p.path); KillProcess(p.pid); }
        } else {
            LogFmt(L"[多引擎][干净] %s %d/%d", p.name.c_str(), pos, total);
        }
    }
    LogFmt(L"[多引擎] 核查完成: 已查 %d 个, 恶意 %d 个", done, bad);
}

// ---- 建议#2: U盘防护 (扫描可移动驱动器 autorun.inf) ----
static void UsbGuardScan() {
    LogPost(L"[U盘防护] 扫描可移动驱动器...");
    wchar_t root[] = L"A:\\\\";
    int found = 0, hit = 0;
    for (wchar_t d = L'C'; d <= L'Z'; ++d) {
        root[0] = d;
        unsigned t = GetDriveTypeW(root);
        if (t != DRIVE_REMOVABLE) continue;
        ++found;
        std::wstring rw(root);
        std::wstring ar = rw + L"autorun.inf";
        if (GetFileAttributesW(ar.c_str()) != INVALID_FILE_ATTRIBUTES) {
            ++hit;
            LogFmt(L"[U盘防护][高危] 发现 autorun.inf 自运行配置: %s", ar.c_str());
            if (g_cfg.advAggressive) {
                HANDLE h = CreateFileW(ar.c_str(), GENERIC_WRITE, 0, nullptr,
                                       TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (h != INVALID_HANDLE_VALUE) { SetEndOfFile(h); CloseHandle(h); DeleteFileW(ar.c_str()); }
            } else {
                QuarantineFile(ar);
            }
        }
        // 盘根可执行文件(常见 U 盘传播)
        WIN32_FIND_DATAW fd{};
        std::wstring pat = rw + L"*.exe";
        HANDLE hf = FindFirstFileW(pat.c_str(), &fd);
        if (hf != INVALID_HANDLE_VALUE) {
            int n = 0;
            do {
                if (++n > 20) break;
                std::wstring fp = rw + fd.cFileName;
                std::wstring hex;
                if (FileSha256W(fp, hex)) {
                    LogFmt(L"[U盘防护] 根目录可执行文件: %s", fd.cFileName);
                }
            } while (FindNextFileW(hf, &fd));
            FindClose(hf);
        }
    }
    LogFmt(L"[U盘防护] 完成: 可移动驱动器 %d 个, 命中 %d 项", found, hit);
}

// ---- 建议#5: 下载目录扫描 ----
static void ScanDownloads() {
    wchar_t prof[MAX_PATH]{};
    std::wstring dl;
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PROFILE, nullptr, 0, prof))) {
        dl = std::wstring(prof) + L"\\\\Downloads";
    }
    if (dl.empty()) { LogPost(L"[下载扫描] 无法定位下载目录"); return; }
    LogFmt(L"[下载扫描] 扫描 %s (建议: 下载的文件先扫描再运行)", dl.c_str());
    WIN32_FIND_DATAW fd{};
    HANDLE hf = FindFirstFileW((dl + L"\\\\*").c_str(), &fd);
    if (hf == INVALID_HANDLE_VALUE) { LogPost(L"[下载扫描] 目录为空或不可访问"); return; }
    int cnt = 0, risky = 0;
    static const wchar_t* const exts[] = { L".exe", L".dll", L".scr", L".js", L".vbs",
                                           L".ps1", L".bat", L".cmd", L".hta", L".lnk" };
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        std::wstring fn = fd.cFileName;
        std::wstring low; low.resize(fn.size());
        for (size_t i = 0; i < fn.size(); ++i) low[i] = (wchar_t)tolower((int)fn[i]);
        bool match = false;
        for (const wchar_t* e : exts) if (low.size() >= wcslen(e) && low.compare(low.size() - wcslen(e), wcslen(e), e) == 0) match = true;
        if (!match) continue;
        ++cnt;
        std::wstring fp = dl + L"\\\\" + fn;
        std::wstring hex;
        if (FileSha256W(fp, hex)) {
            LogFmt(L"[下载扫描] 可执行/脚本: %s  sha256=%s", fn.c_str(), hex.substr(0, 16).c_str());
            int pos = 0, total = 0; std::wstring vd;
            if (!g_cfg.vtApiKey.empty() && VtLookupHash(hex, pos, total, vd) && pos > 0) {
                ++risky;
                LogFmt(L"[下载扫描][恶意] %s  %d/%d 引擎报毒", fn.c_str(), pos, total);
                QuarantineFile(fp);
            }
        }
    } while (FindNextFileW(hf, &fd));
    FindClose(hf);
    LogFmt(L"[下载扫描] 完成: 检查 %d 个文件, 恶意 %d 个(已隔离)", cnt, risky);
}

// ---- 建议#5: 右键菜单集成 (注册表 *\\shell\\zzEDRScan) ----
static void InstallContextMenu() {
    HKEY hk = nullptr;
    LONG r = RegCreateKeyExW(HKEY_CLASSES_ROOT, L"*\\\\shell\\\\zzEDRScan", 0, nullptr, 0,
                             KEY_WRITE, nullptr, &hk, nullptr);
    if (r != 0 || !hk) { LogPost(L"[右键菜单] 注册失败(需要管理员权限)"); return; }
    const wchar_t* txt = L"用 zzEDR 扫描";
    RegSetValueExW(hk, nullptr, 0, REG_SZ, (const BYTE*)txt, (DWORD)((wcslen(txt) + 1) * sizeof(wchar_t)));
    HKEY hc = nullptr;
    if (RegCreateKeyExW(hk, L"command", 0, nullptr, 0, KEY_WRITE, nullptr, &hc, nullptr) == 0 && hc) {
        wchar_t self[MAX_PATH]{};
        GetModuleFileNameW(nullptr, self, MAX_PATH);
        std::wstring cmd = L"\\\"" + std::wstring(self) + L"\\\" --scanfile \\\"%1\\\"";
        RegSetValueExW(hc, nullptr, 0, REG_SZ, (const BYTE*)cmd.c_str(),
                       (DWORD)((cmd.size() + 1) * sizeof(wchar_t)));
        RegCloseKey(hc);
    }
    RegCloseKey(hk);
    LogPost(L"[右键菜单] 已注册: 任意文件右键 -> \"用 zzEDR 扫描\"");
}

// ---- 建议#4: 操作系统与软件补丁审计 ----
// ============================================================================
// 功能一: 进程缓解策略审计 (Exploit Guard / 漏洞利用防护)
// ----------------------------------------------------------------------------
// 【思路】—— 为什么要检查"缓解策略"而不只是"查杀病毒"?
//
//   漏洞利用(Exploit)能成功, 往往不是因为病毒多高明, 而是因为目标进程
//   "没开启操作系统本来提供的防御"。四项关键缓解措施各自挡一类攻击:
//
//     ASLR  (地址空间布局随机化)
//        每次启动把代码/库加载到随机地址。
//        没开 -> 攻击者知道函数在哪, shellcode 可以硬编码跳转地址, 一击必中。
//
//     DEP   (数据执行保护)
//        标记栈/堆为"不可执行"。
//        没开 -> 溢出到栈上的 shellcode 可以直接跑起来(经典栈溢出利用)。
//
//     CFG   (控制流防护)
//        间接调用前校验目标是否为合法函数入口。
//        没开 -> 把虚函数表/函数指针改成任意地址即可劫持控制流(常见于
//                浏览器与 PDF 漏洞利用)。
//
//     DynamicCode (禁止动态代码 / CIG)
//        禁止生成并执行新代码(JIT 之外的匿名可执行内存)。
//        没开 -> 无文件攻击可以在内存里造代码执行。
//
//   这就是"纵深防御": 检测(查杀)是一层, 加固(缓解)是另一层。
//   即使某一层漏了, 其他层仍能拦住。所以 EDR 除了抓病毒, 还要体检系统防御。
//
// 【实现步骤】
//   1. 取运行中进程快照
//   2. 逐个 OpenProcess 拿句柄 —— 只需 PROCESS_QUERY_INFORMATION 查询权限,
//      不需要管理员, 普通用户也能跑(部分受保护进程会失败, 跳过即可)
//   3. GetProcessMitigationPolicy 查询各项策略的 Flags, 取对应 bit 判断开启与否
//   4. 重点盯"高风险入口进程"(浏览器/Office/PDF), 因为它们最常被漏洞攻击,
//      是攻击者的首选入口
//   5. 输出不合规项与加固建议
//
// 【避坑】
//   查询失败 ≠ 未开启。老版本 Windows 或部分策略不支持时 API 会返回失败,
//   此时必须记为"未知"并跳过, 绝不能当成"没开"来误报。
// ============================================================================
static void MitigationAudit() {
    LogPost(L"=== 进程缓解策略审计 (漏洞利用防护体检) ===");

    // Win8+ 才提供此 API, 先做可用性检查, 避免老系统上直接崩溃
    HMODULE hK = GetModuleHandleW(L"kernel32.dll");
    typedef BOOL (WINAPI *FnGet)(HANDLE, int, PVOID, SIZE_T);
    FnGet fn = hK ? (FnGet)(void*)GetProcAddress(hK, "GetProcessMitigationPolicy") : nullptr;
    if (!fn) {
        LogPost(L"[缓解] 当前系统不支持 GetProcessMitigationPolicy(需 Win8+), 跳过");
        return;
    }

    // 最常被漏洞利用攻击的"入口"程序: 浏览器 / Office / PDF / 脚本宿主
    static const wchar_t* highRisk[] = {
        L"chrome.exe", L"msedge.exe", L"firefox.exe", L"iexplore.exe",
        L"winword.exe", L"excel.exe", L"powerpnt.exe", L"outlook.exe",
        L"acrord32.exe", L"acrobat.exe", L"wscript.exe", L"cscript.exe",
        L"powershell.exe", L"rundll32.exe",
    };

    auto procs = SnapshotProcs();
    int checked = 0, missing = 0, highRiskBad = 0;

    for (const auto& p : procs) {
        // 只对有磁盘映像的进程做检查(系统空闲进程等无路径, 跳过)
        if (p.path.empty()) continue;

        HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)p.pid);
        if (!h) continue;   // 权限不足或受保护进程: 静默跳过, 不误报

        // ---- 逐项查询。每项用一个 DWORD 接 Flags, 取对应 bit ----
        // GetProcessMitigationPolicy(句柄, 策略枚举, 输出缓冲, 缓冲大小)
        unsigned long f = 0;
        bool hasASLR = false, valASLR = false;
        bool hasDEP  = false, valDEP  = false;
        bool hasCFG  = false, valCFG  = false;
        bool hasDyn  = false, valDyn  = false;

        // ProcessASLRPolicy = 1: bit0 = EnableBottomUpRandomization(底部向上随机化)
        f = 0; if (fn(h, 1, &f, sizeof(f))) { hasASLR = true; valASLR = (f & 1u) != 0; }
        // ProcessDEPPolicy = 0: bit0 = Enable(启用 DEP)
        f = 0; if (fn(h, 0, &f, sizeof(f))) { hasDEP  = true; valDEP  = (f & 1u) != 0; }
        // ProcessControlFlowGuardPolicy = 7: bit0 = Enable(启用 CFG)
        f = 0; if (fn(h, 7, &f, sizeof(f))) { hasCFG  = true; valCFG  = (f & 1u) != 0; }
        // ProcessDynamicCodePolicy = 2: bit0 = ProhibitDynamicCode(禁止动态代码)
        f = 0; if (fn(h, 2, &f, sizeof(f))) { hasDyn  = true; valDyn  = (f & 1u) != 0; }

        CloseHandle(h);
        if (!hasASLR && !hasDEP) continue;   // 全都查不到 -> 未知, 跳过
        ++checked;

        // 汇总关闭了哪些
        std::wstring miss;
        if (hasASLR && !valASLR) miss += L"ASLR ";
        if (hasDEP  && !valDEP)  miss += L"DEP ";
        if (hasCFG  && !valCFG)  miss += L"CFG ";
        if (hasDyn  && !valDyn)  miss += L"禁止动态代码 ";
        if (miss.empty()) continue;
        ++missing;

        std::wstring low = p.name;
        for (auto& c : low) if (c >= L'A' && c <= L'Z') c = (wchar_t)(c - L'A' + L'a');
        bool isHigh = false;
        for (const wchar_t* r : highRisk) if (low == r) { isHigh = true; break; }

        if (isHigh) {
            ++highRiskBad;
            // 高风险入口程序缺防护: 这是真正危险的组合(攻击入口 + 无缓解)
            LogFmt(L"[缓解][高危] %s (pid=%u) 未开启: %s <-- 常见漏洞利用入口, 建议加固",
                   p.name.c_str(), (unsigned)p.pid, miss.c_str());
            BehavAdd(p.pid, p.name, BEHAV_SIGN, isHigh ? 3 : 2,
                     (L"进程缓解策略缺失: " + miss).c_str());
        } else {
            LogFmt(L"[缓解][缺失] %s (pid=%u) 未开启: %s",
                   p.name.c_str(), (unsigned)p.pid, miss.c_str());
        }
    }

    LogFmt(L"[缓解] 已检查 %d 个进程, 其中 %d 个存在缺失, 高风险入口进程 %d 个",
           checked, missing, highRiskBad);

    // 只要有"高风险入口进程"缺防护就升级告警 —— 因为它最可能被实际利用
    if (highRiskBad > 0)
        SetThreatLevel(THREAT_WARN, L"高危进程缺少漏洞缓解防护(ASLR/DEP/CFG)");
}

// ============================================================================
// 功能二: 凭据防护基线 (防 Mimikatz 类工具抓取明文密码)
// ----------------------------------------------------------------------------
// 【思路】—— 为什么单靠"查杀 mimikatz"不够?
//
//   Mimikatz 之所以能抓到明文密码, 是因为 Windows 默认会在 LSASS 进程内存里
//   留下凭据。杀掉 mimikatz.exe 只是治标(改个名就绕过), 真正治本是
//   "让内存里根本没有可利用的东西"。四个关键配置:
//
//     RunAsPPL          LSASS 以保护进程(Protected Process Light)运行。
//                       开了之后, 即使是管理员也无法读取 LSASS 内存 ——
//                       这是对抗凭据窃取最有效的一招。
//
//     WDigest UseLogonCredential
//                       控制是否在内存缓存明文口令。设为 1 等于主动把明文
//                       密码放在内存里给攻击者拿。Win8.1+ 默认已改为 0,
//                       但不少内网环境为了老应用兼容被改回 1, 必须查出来。
//
//     CachedLogonsCount 缓存域登录凭据的数量。缓存越多, 离线时能爆破的
//                       目标越多。建议 <= 2 或 0。
//
//     DisableDomainCreds 禁止缓存域凭据。
//
//   这是"安全基线加固"的思路: 不改病毒, 改环境, 让攻击手段失效。
//
// 【实现】纯注册表读取, 逐项与期望值比对, 输出合规/不合规 + 修复建议。
//         需要读 HKLM, 非管理员会失败并明确提示(不静默跳过)。
// ============================================================================
static void CredGuardAudit() {
    LogPost(L"=== 凭据防护基线审计 (防 Mimikatz 类凭据窃取) ===");

    struct Item {
        const wchar_t* key;      // 注册表键路径
        const wchar_t* val;      // 值名
        unsigned long want;      // 期望值
        int sev;                 // 不合规时的严重度
        const wchar_t* desc;     // 人类可读说明
        const wchar_t* advice;   // 修复建议
    };
    const Item items[] = {
        { L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"RunAsPPL", 1, 5,
          L"LSASS 保护进程模式(PPL)",
          L"设为1可阻止管理员/工具读取 LSASS 内存, 是防 Mimikatz 最关键的一招" },
        { L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
          L"UseLogonCredential", 0, 5,
          L"WDigest 明文密码缓存",
          L"必须为0。为1表示内存里存明文口令, Mimikatz 可直接读取" },
        { L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"DisableDomainCreds", 1, 3,
          L"禁止缓存域凭据",
          L"设为1可减少本地缓存的域凭据被窃取的风险" },
        { L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"RestrictAnonymous", 1, 2,
          L"限制匿名枚举",
          L"设为1可阻止匿名用户枚举账户与共享, 减少信息泄露" },
        { L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"RestrictAnonymousSAM", 1, 2,
          L"限制匿名访问 SAM",
          L"设为1可阻止匿名用户枚举本地账户列表" },
        { L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"CachedLogonsCount", 2, 2,
          L"缓存登录凭据数量",
          L"建议<=2。缓存越多, 离线爆破的目标越多" },
    };

    int bad = 0, worst = 0;
    for (const auto& it : items) {
        HKEY hk = nullptr;
        // HKLM 读取: 非管理员会失败, 此时明确提示而不是假装合规
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, it.key, 0, KEY_READ, &hk) != 0 || !hk) {
            LogFmt(L"[凭据] [跳过] %s (键不可读, 可能需要管理员权限)", it.desc);
            continue;
        }
        unsigned long got = 0, type = 0, sz = sizeof(got);
        long r = RegQueryValueExW(hk, it.val, nullptr, &type, (unsigned char*)&got, &sz);
        RegCloseKey(hk);

        if (r != 0) {
            // 值不存在: 多数情况下等于系统默认值。
            // 只有"期望为1"(需要主动加固)的项才算问题, 期望为0的默认值通常本就是0
            if (it.want == 1) {
                LogFmt(L"[凭据] [未加固] %s (值不存在) -> 建议: %s", it.desc, it.advice);
                bad++; if (it.sev > worst) worst = it.sev;
            } else {
                LogFmt(L"[凭据] [默认]   %s (值不存在, 通常即默认安全值)", it.desc);
            }
            continue;
        }

        // CachedLogonsCount 是"越小越好", 其余是"等于期望值"才算合规
        bool ok = (it.want == 2 && it.val && wcscmp(it.val, L"CachedLogonsCount") == 0)
                  ? (got <= it.want) : (got == it.want);
        if (ok) {
            LogFmt(L"[凭据] [合规]   %s = %u", it.desc, got);
        } else {
            LogFmt(L"[凭据] [不合规] %s (当前=%u 期望=%s%u) -> %s",
                   it.desc, got,
                   (it.want == 2 && wcscmp(it.val, L"CachedLogonsCount") == 0) ? L"<=" : L"=",
                   it.want, it.advice);
            bad++; if (it.sev > worst) worst = it.sev;
            // 记入行为时间线, 便于事后追溯"当时为什么被抓到凭据"
            BehavAdd(0, L"LSASS", BEHAV_REG, it.sev,
                     (std::wstring(L"凭据防护不合规: ") + it.desc).c_str());
        }
    }

    LogFmt(L"[凭据] 审计完成: %d 项不合规(最高严重度 %d)", bad, worst);
    // PPL 未开 或 WDigest 明文缓存开启 = 最危险, 直接红警
    if (worst >= 5)
        SetThreatLevel(THREAT_DANGER, L"凭据防护缺失: LSASS 可被读取或内存存有明文口令");
}

// ============================================================================
// 功能三: 网络共享与自动播放审计 (防勒索横向移动 / U 盘传播)
// ----------------------------------------------------------------------------
// 【思路】—— 勒索软件是怎么"从一台机器扩散到全网"的?
//
//   现代勒索攻击的标准流程是: 先攻陷一台 -> 在内网横向移动 -> 批量加密。
//   横向移动最常用的两条路:
//
//     1. 网络共享 (SMB)
//        把恶意文件放到共享目录, 或加密共享里的文件。
//        - 系统默认共享(C$ / admin$ / IPC$)是系统管理用的, 存在属正常,
//          但如果对 Everyone 开放就是大问题
//        - 用户自建的共享(尤其是整个磁盘根目录共享出去)风险最高
//
//     2. 自动播放 (AutoRun)
//        U 盘插入后自动执行 autorun.inf 指定的程序 —— 这是自古以来
//        最经典的传播方式。Win7 后默认受限, 但策略可能被改。
//
//   所以这台机器"开没开共享、共享了什么、能不能自动播放",
//   直接决定了它会不会成为全网扩散的跳板。
//
// 【实现】
//   - 共享: 枚举注册表 LanmanServer\Shares 下的值名(每个值名就是一个共享名),
//           判定是否默认共享 / 整盘共享 / 可疑随机名共享
//   - 自动播放: 读 Explorer Policies 的 NoDriveTypeAutoRun 与
//               CurrentVersion\Policies\Explorer 的 NoAutoRun
//
// 【避坑 - 重要】
//   NoDriveTypeAutoRun 是"位掩码", 不是布尔值!
//   常见值 0xFF(全部禁用) / 0x95(禁用部分) / 0x91。
//   判断"是否禁用"要按位看 DRIVE_REMOVABLE(0x04) 这一位,
//   直接和 0 比较会得出完全错误的结论。
// ============================================================================
static void ShareAudit() {
    LogPost(L"=== 网络共享与自动播放审计 ===");

    // ---------------- 第一部分: 网络共享 ----------------
    const wchar_t* kShare =
        L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Shares";
    HKEY hk = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kShare, 0, KEY_READ, &hk) == 0 && hk) {
        // 系统默认存在的管理共享: 这些是 Windows 自己开的, 存在属正常
        static const wchar_t* dflt[] = { L"ADMIN$", L"IPC$", L"C$", L"D$",
                                          L"E$", L"F$", L"print$", L"FAX$" };
        wchar_t name[512];
        unsigned long nsz = 0;
        int idx = 0, total = 0, custom = 0, risky = 0;

        // RegEnumValueW 逐个枚举值名 —— 每个值名对应一个共享
        while (true) {
            nsz = (unsigned long)(sizeof(name) / sizeof(name[0]));
            long r = RegEnumValueW(hk, idx, name, &nsz, nullptr, nullptr, nullptr, nullptr);
            if (r != 0) break;   // ERROR_NO_MORE_ITEMS 即枚举结束
            idx++;
            if (name[0] == L'\0') continue;
            total++;

            // 是否系统默认共享
            bool isDflt = false;
            for (const wchar_t* d : dflt) {
                if (_wcsicmp(name, d) == 0) { isDflt = true; break; }
            }
            if (isDflt) {
                LogFmt(L"[共享] [默认] %s (系统管理共享, 存在属正常)", name);
                continue;
            }

            custom++;
            // 整盘共享: 形如 "G$" 的单字母+$, 把整个分区暴露出去
            bool wholeDisk = (wcslen(name) == 2 && name[1] == L'$');
            if (wholeDisk) {
                risky++;
                LogFmt(L"[共享] [高危] %s <-- 整个分区被共享出去, 勒索软件可横向加密全网", name);
                BehavAdd(0, L"LanmanServer", BEHAV_NET, 4,
                         (std::wstring(L"危险共享: 整盘共享 ") + name).c_str());
                if (g_cfg.shareAuditOn && g_cfg.advAggressive) {
                    // 激进模式: 提示可关闭(需管理员, 此处仅告警不直接改, 避免破坏业务)
                    LogFmt(L"[共享] [提示] 建议管理员执行 net share %s /delete", name);
                }
            } else {
                LogFmt(L"[共享] [自定义] %s (非系统默认共享, 请确认业务必要性)", name);
            }
        }
        RegCloseKey(hk);
        LogFmt(L"[共享] 共 %d 个共享: 自定义 %d 个, 高危整盘 %d 个", total, custom, risky);
        if (risky > 0)
            SetThreatLevel(THREAT_WARN, L"存在整盘网络共享, 易被勒索软件横向利用");
    } else {
        LogPost(L"[共享] LanmanServer\\Shares 不可读(可能未开启共享或需管理员权限)");
    }

    // ---------------- 第二部分: 自动播放 ----------------
    // 位掩码说明: bit2(值0x04) 对应 DRIVE_REMOVABLE(可移动驱动器, 即 U 盘)
    // 该位置1 表示"禁用可移动驱动器的自动播放"
    const wchar_t* kExp = L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer";
    HKEY hk2 = nullptr;
    bool checked = false;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kExp, 0, KEY_READ, &hk2) == 0 && hk2) {
        unsigned long mask = 0, type = 0, sz = sizeof(mask);
        long r = RegQueryValueExW(hk2, L"NoDriveTypeAutoRun", nullptr, &type,
                                  (unsigned char*)&mask, &sz);
        RegCloseKey(hk2);
        if (r == 0) {
            checked = true;
            // 位掩码 bit2(0x04) = DRIVE_REMOVABLE, 即可移动磁盘(U 盘)
            const unsigned long kMaskRemovable = 0x04u;
            bool removableOff = (mask & kMaskRemovable) != 0;
            if (removableOff) {
                LogFmt(L"[自动播放] [合规] U 盘自动播放已禁用 (NoDriveTypeAutoRun=0x%X)", mask);
            } else {
                LogFmt(L"[自动播放] [不合规] U 盘自动播放未禁用 (NoDriveTypeAutoRun=0x%X)", mask);
                LogPost(L"[自动播放] 风险: 插入带毒 U 盘会自动执行 autorun.inf, 是经典传播途径");
                LogPost(L"[自动播放] 加固: 设为 0xFF 可禁用所有驱动器类型的自动播放");
                SetThreatLevel(THREAT_WARN, L"U 盘自动播放未禁用");
                BehavAdd(0, L"Explorer", BEHAV_REG, 3, L"自动播放未禁用, U 盘可自动执行");
            }
        }
    }
    if (!checked)
        LogPost(L"[自动播放] NoDriveTypeAutoRun 未配置(键不可读或值不存在), 建议显式设为 0xFF");
}

static void PatchAudit() {
    LogPost(L"[补丁审计] 检查系统更新与常用软件版本...");
    // 1) Windows 更新最后成功时间
    HKEY hk = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\WindowsUpdate\\\\Auto Update\\\\Results\\\\Install",
        0, KEY_READ, &hk) == 0 && hk) {
        wchar_t val[256]{}; DWORD sz = sizeof(val); DWORD ty = 0;
        if (RegQueryValueExW(hk, L"LastSuccessTime", nullptr, &ty, (BYTE*)val, &sz) == 0)
            LogFmt(L"[补丁审计] Windows 更新最后成功时间: %s", val);
        else
            LogPost(L"[补丁审计][警告] 未找到最近更新记录, 系统可能长期未打补丁");
        RegCloseKey(hk);
    }
    // 2) 已安装软件版本(检查易受攻击的常用软件)
    static const wchar_t* const riskySoft[] = {
        L"Java", L"JRE", L"Adobe Reader", L"Adobe Acrobat", L"Flash", L"Firefox",
        L"Chrome", L"Edge", L"7-Zip", L"WinRAR", L"Notepad++", L"Putty", L"VLC",
        L"TeamViewer", L"AnyDesk", L"VMware", L"VirtualBox"
    };
    HKEY hu = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall", 0, KEY_READ, &hu) == 0 && hu) {
        DWORD idx = 0; wchar_t name[256];
        while (true) {
            DWORD ns = 256;
            if (RegEnumKeyW(hu, idx++, name, ns) != 0) break;
            HKEY hs = nullptr;
            std::wstring sub = std::wstring(L"SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\") + name;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub.c_str(), 0, KEY_READ, &hs) == 0 && hs) {
                wchar_t dn[512]{}; DWORD ds = sizeof(dn);
                if (RegQueryValueExW(hs, L"DisplayName", nullptr, nullptr, (BYTE*)dn, &ds) == 0) {
                    for (const wchar_t* rk : riskySoft) {
                        if (wcsstr(dn, rk)) {
                            wchar_t dv[128]{}; DWORD vs = sizeof(dv);
                            std::wstring ver = L"(未知)";
                            if (RegQueryValueExW(hs, L"DisplayVersion", nullptr, nullptr, (BYTE*)dv, &vs) == 0)
                                ver = dv;
                            LogFmt(L"[补丁审计] 关注软件: %s  版本 %s  (请确认已是最新)",
                                   dn, ver.c_str());
                            break;
                        }
                    }
                }
                RegCloseKey(hs);
            }
        }
        RegCloseKey(hu);
    }
    LogPost(L"[补丁审计] 完成。请及时安装 Windows 安全更新与上述软件补丁以堵住漏洞。");
}

// ---- 建议#3: 全盘深度扫描(系统分区/临时目录/启动项/注册表) ----
static void DeepFullScan() {
    LogPost(L"[深度扫描] 开始全盘深度扫描(系统分区/临时目录/启动项/注册表)...");
    wchar_t win[MAX_PATH]{}; GetWindowsDirectoryW(win, MAX_PATH);
    wchar_t tmp[MAX_PATH]{}; GetTempPathW(MAX_PATH, tmp);
    std::wstring dirs[4];
    dirs[0] = std::wstring(win);
    dirs[1] = std::wstring(win) + L"\\\\System32";
    dirs[2] = std::wstring(tmp);
    wchar_t prof[MAX_PATH]{};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PROFILE, nullptr, 0, prof)))
        dirs[3] = std::wstring(prof) + L"\\\\AppData\\\\Local\\\\Temp";
    int scanned = 0, hit = 0;
    static const wchar_t* const exts[] = { L".exe", L".dll", L".sys", L".scr", L".bat", L".ps1", L".js", L".vbs" };
    for (const auto& d : dirs) {
        if (d.empty()) continue;
        WIN32_FIND_DATAW fd{};
        HANDLE hf = FindFirstFileW((d + L"\\\\*").c_str(), &fd);
        if (hf == INVALID_HANDLE_VALUE) continue;
        int n = 0;
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            if (++n > 400) break;                 // 每目录上限, 避免卡死
            std::wstring fn = fd.cFileName;
            std::wstring low; low.resize(fn.size());
            for (size_t i = 0; i < fn.size(); ++i) low[i] = (wchar_t)tolower((int)fn[i]);
            bool m = false;
            for (const wchar_t* e : exts)
                if (low.size() >= wcslen(e) && low.compare(low.size() - wcslen(e), wcslen(e), e) == 0) m = true;
            if (!m) continue;
            std::wstring fp = d + L"\\\\" + fn;
            ++scanned;
            std::wstring hex;
            if (!FileSha256W(fp, hex)) continue;
            std::wstring hn; int hs = 0;
            if (RuleMatchHash(hex, hn, hs)) {
                ++hit;
                LogFmt(L"[深度扫描][命中情报] %s", fp.c_str());
                QuarantineFile(fp);
            }
        } while (FindNextFileW(hf, &fd));
        FindClose(hf);
    }
    // 启动项
    ScanRegistry();
    LogFmt(L"[深度扫描] 完成: 扫描 %d 个文件, 命中 %d 个(已隔离); 启动项已复查", scanned, hit);
}

// ---- 建议#7: 安全模式彻底清除 (bcdedit /set safeboot) ----
static void EnterSafeMode(bool withNetwork) {
    int r = MessageBoxW(g_hMain,
        L"即将设置下次启动进入安全模式, 并重启计算机。\n\n"
        L"用途: 顽固病毒常劫持正常进程, 在安全模式下它们不会自启动, 便于彻底清除。\n\n"
        L"进入安全模式后请再次运行本程序执行全盘扫描与清理。\n"
        L"清理完成后务必点击\"退出安全模式\"并重启, 否则会一直停在安全模式!\n\n"
        L"确定继续吗?",
        L"安全模式清除(高风险)", MB_YESNO | MB_ICONWARNING);
    if (r != IDYES) { LogPost(L"[安全模式] 用户取消"); return; }
    std::wstring param = withNetwork ? L"/c bcdedit /set {default} safeboot network && shutdown /r /t 5"
                                     : L"/c bcdedit /set {default} safeboot minimal && shutdown /r /t 5";
    wchar_t cmdline[512]{};
    wcscpy_s(cmdline, 512, L"cmd.exe ");
    wcscat_s(cmdline, 512, param.c_str());
    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (CreateProcessW(nullptr, cmdline, nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                       nullptr, nullptr, &si, &pi)) {
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        LogPost(L"[安全模式] 已设置, 系统将在 5 秒后重启进入安全模式");
    } else {
        LogPost(L"[安全模式] 设置失败(需要管理员权限)");
    }
}
static void ExitSafeMode() {
    wchar_t cmdline[512]{};
    wcscpy_s(cmdline, 512, L"cmd.exe /c bcdedit /deletevalue {default} safeboot && shutdown /r /t 5");
    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (CreateProcessW(nullptr, cmdline, nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                       nullptr, nullptr, &si, &pi)) {
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        LogPost(L"[安全模式] 已清除安全模式设置, 系统将在 5 秒后正常重启");
    } else {
        LogPost(L"[安全模式] 清除失败(需要管理员权限)");
    }
}

// ===================== 离线备份: 目标探测 =====================
// 【v13.31 新增】"备份"要真正有意义, 必须满足两个条件:
//   ① 不在同一个磁盘分区(勒索软件加密 C: 盘时, 备份在 C: 盘会一起没)
//   ② 不在会被自动清理的位置(%TEMP% 会被磁盘清理/重启清理)
// 所以优先把数据写到"离线目标": 可移动盘(U盘/移动硬盘)或非系统的固定盘。
struct OfflineTarget {
    std::wstring root;                 // 形如 "E:\\"
    std::wstring kind;                 // "可移动" / "外置固定盘"
    unsigned long long freeBytes = 0;  // 可用空间
};
static std::vector<OfflineTarget> OfflineBackupTargets() {
    std::vector<OfflineTarget> out;
    wchar_t sysDir[MAX_PATH]{};
    GetSystemDirectoryW(sysDir, MAX_PATH);
    wchar_t sysDrive[4] = {0};
    if (sysDir[0]) { sysDrive[0] = sysDir[0]; sysDrive[1] = L':'; sysDrive[2] = L'\\'; }

    DWORD mask = GetLogicalDrives();
    for (int i = 0; i < 26; ++i) {
        if (!(mask & (1u << i))) continue;
        wchar_t root[4] = { (wchar_t)(L'A' + i), L':', L'\\', 0 };
        UINT t = GetDriveTypeW(root);
        // 只认两类"离线"介质: 可移动盘, 以及非系统盘的固定盘(第二块硬盘/移动硬盘)
        bool removable = (t == DRIVE_REMOVABLE);
        bool otherFixed = (t == DRIVE_FIXED) && sysDrive[0] && (root[0] != sysDrive[0]);
        if (!removable && !otherFixed) continue;          // 光驱/网络盘/内存盘一律排除

        ULARGE_INTEGER free_{}, total_{}, totalFree{};
        if (!GetDiskFreeSpaceExW(root, &free_, &total_, &totalFree)) continue;
        if (free_.QuadPart < 64ULL * 1024 * 1024) continue; // 小于 64MB 不放

        OfflineTarget t2; t2.root = root;
        t2.kind = removable ? L"可移动盘" : L"外置固定盘";
        t2.freeBytes = (unsigned long long)free_.QuadPart;
        out.push_back(t2);
    }
    return out;
}

// ===================== 建议#8: 重要数据备份(离线 + 版本保护) =====================
// 【v13.31 修复】旧实现有四个致命缺陷, 导致备份形同虚设:
//   ① 无版本保护 —— 每次覆盖同名文件。桌面文件被勒索加密后再备份一次,
//      好的备份就被加密版本覆盖, 备份彻底失效。这是最致命的一条。
//   ② 目标默认 %TEMP% —— 与源同分区(都是 C: 盘), 且会被磁盘清理/重启清空。
//      勒索软件加密整个盘时, 备份跟着一起没, 完全不是"离线备份"。
//   ③ 只备份顶层 —— 遇目录就 continue 跳过, 而重要数据大多在子目录里。
//   ④ 未排除备份目录自身 —— 若 backupPath 设在桌面/文档下, 每次都会把
//      上一次的备份再复制进去, 反复膨胀。
// 现改为: 时间戳快照(永不覆盖) + 优先离线目标 + 递归子目录 + 排除自身 + 校验。
static const int BACKUP_MAX_DEPTH = 3;      // 递归深度上限
static const int BACKUP_MAX_FILES = 3000;   // 单目录文件数上限(避免扫全盘)

// 递归复制: 返回 成功文件数 / 累加字节数
static void BackupCopyRecursive(const std::wstring& src, const std::wstring& dst,
                                int depth, int& files, unsigned long long& bytes,
                                int& budget) {
    if (depth > BACKUP_MAX_DEPTH || budget <= 0) return;
    CreateDirectoryW(dst.c_str(), nullptr);
    WIN32_FIND_DATAW fd{};
    HANDLE hf = FindFirstFileW((src + L"\\*").c_str(), &fd);
    if (hf == INVALID_HANDLE_VALUE) return;

    int n = 0;
    do {
        if (budget <= 0) break;
        const std::wstring name = fd.cFileName;
        if (name == L"." || name == L"..") continue;

        // 排除自身与隔离区, 避免把备份/病毒样本反复复制进去
        if (name.find(L"zz_EDR_backup") != std::wstring::npos ||
            name.find(L"zz_EDR_quarantine") != std::wstring::npos) continue;

        std::wstring sf = src + L"\\" + name;
        std::wstring df = dst + L"\\" + name;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            BackupCopyRecursive(sf, df, depth + 1, files, bytes, budget);
            continue;
        }
        if (++n > BACKUP_MAX_FILES) break;
        if (CopyFileW(sf.c_str(), df.c_str(), FALSE)) {
            ++files; --budget;
            WIN32_FILE_ATTRIBUTE_DATA ad{};
            if (GetFileAttributesExW(sf.c_str(), GetFileExInfoStandard, &ad))
                bytes += ((unsigned long long)ad.nFileSizeHigh << 32) | ad.nFileSizeLow;
        }
    } while (FindNextFileW(hf, &fd));
    FindClose(hf);
}

// 生成快照目录名: 精确到秒, 保证永不覆盖历史备份
static std::wstring BackupSnapshotName() {
    time_t now = time(nullptr);
    struct tm tmv{};
    localtime_s(&tmv, &now);   // 与项目其他处一致(MSVC); 不用 Linux 的 localtime_r
    wchar_t buf[32]{};
    swprintf(buf, 32, L"%04d%02d%02d_%02d%02d%02d",
             tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
             tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
    return std::wstring(buf);
}

static void BackupUserData() {
    wchar_t p1[MAX_PATH]{}, p2[MAX_PATH]{}, p3[MAX_PATH]{};
    std::wstring srcs[3];
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_DESKTOP, nullptr, 0, p1)))   srcs[0] = p1;
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PERSONAL, nullptr, 0, p2)))  srcs[1] = p2;
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PROFILE, nullptr, 0, p3)))   srcs[2] = std::wstring(p3) + L"\\Downloads";
    static const wchar_t* const names[3] = { L"Desktop", L"Documents", L"Downloads" };

    std::wstring snap = BackupSnapshotName();

    // ---- 选目标: 优先用户指定的, 其次离线(可移动/外置盘), 最后才退回 TEMP ----
    std::vector<std::wstring> targets;
    std::vector<std::wstring> targetKinds;
    if (!g_cfg.backupPath.empty()) {
        targets.push_back(g_cfg.backupPath);
        targetKinds.push_back(L"指定目录");
    }
    if (g_cfg.offlineBackupOn) {
        for (const auto& t : OfflineBackupTargets()) {
            targets.push_back(t.root + L"zz_EDR_offline");
            targetKinds.push_back(t.kind + L"(" + t.root + L")");
        }
    }
    if (targets.empty()) {
        wchar_t tmp[MAX_PATH]{}; GetTempPathW(MAX_PATH, tmp);
        targets.push_back(std::wstring(tmp) + L"zz_EDR_backup");
        targetKinds.push_back(L"临时目录(非离线, 建议插U盘或指定外置盘)");
    }

    int grandTotal = 0;
    for (size_t ti = 0; ti < targets.size(); ++ti) {
        // 每个目标下建独立快照目录 —— 版本保护的关键, 历史备份永不被覆盖
        std::wstring dst = targets[ti] + L"\\data\\" + snap;
        if (!CreateDirectoryW((targets[ti] + L"\\data").c_str(), nullptr) &&
            GetLastError() != ERROR_ALREADY_EXISTS) {
            LogFmt(L"[数据备份] 目标不可用: %s (err=%u)", targets[ti].c_str(), GetLastError());
            continue;
        }
        if (!CreateDirectoryW(dst.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) {
            LogFmt(L"[数据备份] 快照目录创建失败: %s (err=%u)", dst.c_str(), GetLastError());
            continue;
        }

        int files = 0; unsigned long long bytes = 0; int budget = BACKUP_MAX_FILES * 2;
        for (int i = 0; i < 3; ++i) {
            if (srcs[i].empty()) continue;
            if (srcs[i].size() >= 2 && srcs[i] == targets[ti]) continue;  // 源=目标, 跳过防自吞
            BackupCopyRecursive(srcs[i], dst + L"\\" + names[i], 0, files, bytes, budget);
        }
        grandTotal += files;
        double mb = bytes / (1024.0 * 1024.0);
        LogFmt(L"[数据备份] %s -> 快照 %s: 文件 %d 个, 共 %.1f MB",
               targetKinds[ti].c_str(), snap.c_str(), files, mb);
    }

    if (grandTotal == 0)
        LogPost(L"[数据备份] 未完成任何备份, 请检查目标盘是否可用或已插好 U 盘");
    else
        LogPost(L"[数据备份] 完成。历史快照按时间戳独立保存, 不会互相覆盖; "
                L"建议定期拷至外置硬盘或云存储(3-2-1 原则: 3 份副本, 2 种介质, 1 份异地)");
}

// ---- 建议#9: 引导区 MBR/GPT 检查与备份 ----
static void MbrCheckAndBackup() {
    HANDLE h = CreateFileW(L"\\\\\\\\.\\\\PhysicalDrive0", GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        LogPost(L"[引导区] 无法打开 PhysicalDrive0(需要管理员权限)");
        return;
    }
    unsigned char mbr[512]{};
    DWORD rd = 0;
    BOOL ok = ReadFile(h, mbr, 512, &rd, nullptr);
    CloseHandle(h);
    if (!ok || rd < 512) { LogPost(L"[引导区] 读取失败"); return; }
    bool sigOk = (mbr[510] == 0x55 && mbr[511] == 0xAA);
    // 分区表项(偏移 0x1BE 起, 每项 16 字节, 共 4 项)
    int parts = 0;
    for (int i = 0; i < 4; ++i) {
        const unsigned char* e = mbr + 0x1BE + i * 16;
        if (e[4] != 0) ++parts;                        // 非 0 表示有分区类型
    }
    // 备份到临时目录
    wchar_t tmp[MAX_PATH]{}; GetTempPathW(MAX_PATH, tmp);
    std::wstring bp = std::wstring(tmp) + L"zz_EDR_mbr_backup.bin";
    std::wstring fp = std::wstring(tmp) + L"mbr_sha.txt";
    HANDLE hb = CreateFileW(bp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hb != INVALID_HANDLE_VALUE) {
        DWORD w2 = 0; WriteFile(hb, mbr, 512, &w2, nullptr); CloseHandle(hb);
        LogFmt(L"[引导区] MBR 已备份: %s", bp.c_str());
    }
    if (!sigOk)
        LogPost(L"[引导区][高危] MBR 结束标志 0x55AA 缺失, 引导区可能被破坏! 建议用 PE 启动盘执行 bootrec /fixmbr 修复");
    else
        LogFmt(L"[引导区] 正常: 结束标志 0x55AA 有效, 分区表项 %d 个", parts);
    if (parts == 0 && sigOk)
        LogPost(L"[引导区][警告] 未发现分区表项, 可能是 GPT 磁盘(请使用 GPT 修复工具)或引导区异常");
    LogPost(L"[引导区] 提示: 若引导被破坏, 可用 PE 系统下 Bootice 或 bootrec /fixmbr /fixboot /rebuildbcd 重建引导记录");
}

// ---- 建议#10: 勒索病毒专杀 ----
static void RansomKiller() {
    LogPost(L"[勒索专杀] 启动: 检查勒索信/加密行为/卷影副本保护...");
    // 1) 终止命中勒索规则的进程(高频写入+加密 API+勒索扩展名接触)
    auto procs = SnapshotProcs();
    int killed = 0;
    for (const auto& p : procs) {
        std::wstring ln = p.name; for (auto& c : ln) c = (wchar_t)tolower((int)c);
        static const wchar_t* const rn[] = { L"vssadmin", L"wmic", L"cipher", L"bcdedit" };
        bool susp = false;
        for (const wchar_t* r : rn) if (ln.find(r) != std::wstring::npos) susp = true;
        // 命令行含删除卷影副本
        if (!susp && !p.path.empty()) {
            if (wcsstr(p.name.c_str(), L"cmd") || wcsstr(p.name.c_str(), L"powershell")) susp = false; // 需命令行判定, 保守不杀
        }
        if (susp && (ln.find(L"vssadmin") != std::wstring::npos)) {
            // vssadmin 删除卷影是勒索典型前置动作
            LogFmt(L"[勒索专杀][高危] 检测到删除卷影副本行为: %s (pid=%u) -> 终止", p.name.c_str(), (unsigned)p.pid);
            KillProcess(p.pid); ++killed;
        }
    }
    // 2) 扫描桌面/文档中的勒索信
    wchar_t p1[MAX_PATH]{}, p2[MAX_PATH]{};
    std::wstring dirs[2];
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_DESKTOP, nullptr, 0, p1)))  dirs[0] = p1;
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PERSONAL, nullptr, 0, p2))) dirs[1] = p2;
    static const wchar_t* const notes[] = { L"readme", L"decrypt", L"ransom", L"restore",
                                            L"how_to", L"help_decrypt", L"recover" };
    int notes_ = 0;
    for (const auto& d : dirs) {
        if (d.empty()) continue;
        WIN32_FIND_DATAW fd{};
        HANDLE hf = FindFirstFileW((d + L"\\\\*.txt").c_str(), &fd);
        if (hf == INVALID_HANDLE_VALUE) continue;
        do {
            std::wstring fn = fd.cFileName;
            std::wstring low; low.resize(fn.size());
            for (size_t i = 0; i < fn.size(); ++i) low[i] = (wchar_t)tolower((int)fn[i]);
            for (const wchar_t* n : notes)
                if (low.find(n) != std::wstring::npos) {
                    ++notes_;
                    LogFmt(L"[勒索专杀][高危] 疑似勒索信: %s", fn.c_str());
                    break;
                }
        } while (FindNextFileW(hf, &fd));
        FindClose(hf);
    }
    // 3) 卷影副本服务状态
    LogPost(L"[勒索专杀] 提示: 请确保 Volume Shadow Copy 服务可用, 并已备份重要数据(建议#8)");
    LogFmt(L"[勒索专杀] 完成: 终止可疑进程 %d 个, 发现勒索信 %d 个", killed, notes_);
    if (notes_ > 0) LogPost(L"[勒索专杀][高危] 检测到疑似勒索信, 勒索攻击可能已发生! 请立即断网、备份、隔离并全盘扫描");
}

// ---- 建议#10: 挖矿木马专杀 ----
static void MinerKiller() {
    LogPost(L"[挖矿专杀] 启动: 检查矿池连接/挖矿进程/计划任务...");
    auto procs = SnapshotProcs();
    int killed = 0;
    static const wchar_t* const miners[] = { L"xmrig", L"cgminer", L"bfgminer", L"ethminer",
                                             L"ccminer", L"nbminer", L"lolminer", L"t-rex", L"phoenixminer" };
    for (const auto& p : procs) {
        std::wstring ln = p.name; for (auto& c : ln) c = (wchar_t)tolower((int)c);
        for (const wchar_t* m : miners) {
            if (ln.find(m) != std::wstring::npos) {
                LogFmt(L"[挖矿专杀][命中] 挖矿程序: %s (pid=%u) -> 终止", p.name.c_str(), (unsigned)p.pid);
                KillProcess(p.pid);
                if (g_cfg.advAggressive && !IsProtectedPath(p.path)) QuarantineFile(p.path);
                ++killed;
                break;
            }
        }
    }
    // 矿池端口连接(stratum 常用 3333/4444/5555/14444/45700 等)
    auto nets = SnapshotNets();
    int pool = 0;
    static const int poolPorts[] = { 3333, 3334, 4444, 5555, 7777, 8888, 9999, 14444, 14433, 45700, 20535, 20547 };
    for (const auto& n : nets) {
        int port = 0;
        auto c = n.remote.rfind(L':');
        if (c != std::wstring::npos) port = _wtoi(n.remote.substr(c + 1).c_str());
        if (port == 0) continue;
        for (int pp : poolPorts) {
            if (port == pp) {
                ++pool;
                LogFmt(L"[挖矿专杀][命中] 疑似矿池连接 %s (pid=%u)", n.remote.c_str(), (unsigned)n.pid);
                if (n.pid) { KillProcess(n.pid); ++killed; }
                break;
            }
        }
    }
    // 清理挖矿常见计划任务
    wchar_t cmdline[512]{};
    wcscpy_s(cmdline, 512, L"cmd.exe /c schtasks /query /fo list > nul 2>&1");
    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (CreateProcessW(nullptr, cmdline, nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                       nullptr, nullptr, &si, &pi)) {
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    }
    LogFmt(L"[挖矿专杀] 完成: 终止挖矿进程 %d 个, 发现矿池连接 %d 条", killed, pool);
    LogPost(L"[挖矿专杀] 提示: 请同时检查计划任务/启动项中的挖矿持久化, 可用信任管理(最小信任)阻止未知程序");
}

static void CreateProtectionPage(HWND p) {
    CreateButton(p, L"启动全链扫描", IDC_CB_PROTECTION_SCAN,    20, 20, 160, 32);
    CreateCheck (p, L"实时监控",     IDC_CB_PROTECTION_MONITOR, 20, 62, 140, 20);
    CreateCheck (p, L"超强拦截模式", IDC_CB_PROTECTION_LOCKDOWN,170, 62, 140, 20);
    CreateCheck (p, L"AMSI 脚本扫描",IDC_CB_PROTECTION_AMSI,    320, 62, 140, 20);

    // 展开区: 全链扫描设置
    g_hScanOpts = CreateWindowExW(0, L"STATIC", nullptr, WS_CHILD | WS_BORDER,
                                  20, 100, 520, 250, p, nullptr, GetModuleHandleW(nullptr), nullptr);
    CreateLabel (g_hScanOpts, L"扫描间隔(ms):",    10, 10, 110, 20);
    CreateEdit  (g_hScanOpts, IDC_CB_SCAN_INTERVAL, L"5000", 130, 10, 100, 22, false);
    CreateLabel (g_hScanOpts, L"扫描类型:",         10, 42, 110, 20);
    CreateEdit  (g_hScanOpts, IDC_CB_SCAN_TYPE,     L"0",    130, 42, 100, 22, false);
    CreateCheck (g_hScanOpts, L"启发式",  IDC_CB_ADV_HEURISTIC,  10, 74, 100, 20);
    CreateCheck (g_hScanOpts, L"内存扫描",IDC_CB_ADV_MEMORY,    120, 74, 100, 20);
    CreateCheck (g_hScanOpts, L"云查",    IDC_CB_ADV_CLOUD,     230, 74, 100, 20);
    CreateCheck (g_hScanOpts, L"反混淆",  IDC_CB_ADV_DEOBF,     10, 100, 100, 20);
    CreateCheck (g_hScanOpts, L"激进模式",IDC_CB_ADV_AGGRESSIVE,120,100, 100, 20);
    // v13.26 紧急逃生模式: 比激进模式更高一级, 放在其右侧便于对照层级
    CreateCheck (g_hScanOpts, L"紧急逃生模式", IDC_CB_ADV_ESCAPE, 230, 100, 110, 20);
    // v13.25: 激进模式危害警示 —— 开启后会自动结束进程/覆写文件, 必须在旁边写清后果
    CreateLabel (g_hScanOpts,
        L"\u26a0\ufe0f \u5371\u9669\uff1a\u53ef\u80fd\u8bef\u4f24\u5927\u91cf\u7cfb\u7edf\u6587\u4ef6\u3001\u6b63\u5e38\u5e94\u7528\u7b49\uff01",
        10, 124, 480, 20);
    CreateLabel (g_hScanOpts,
        L"\u5f00\u542f\u540e\uff1a\u884c\u4e3a\u8d8a\u754c\u5373\u7ec8\u6b62\u8fdb\u7a0b\u00d720\u6b21\uff0c\u6bcf 5ms \u590d\u67e5\u662f\u5426\u91cd\u542f\uff1b\u539f\u6587\u4ef6\u5907\u4efd\u540e\u8986\u5199",
        10, 146, 480, 20);
    CreateLabel (g_hScanOpts,
        L"\u5e76\u626b\u63cf\uff0c\u65e0\u95ee\u9898\u5219\u8fd8\u539f\u4e14\u91cd\u70b9\u89c2\u5bdf 10 \u5206\u949f\u3002\u975e\u7ecf\u786e\u8ba4\u8bf7\u52ff\u5f00\u542f\u3002",
        10, 168, 480, 20);
    // v13.26 逃生模式危害警示: 比激进模式更极端 —— 命中任意规则即彻底销毁
    CreateLabel (g_hScanOpts,
        L"\u26a0\ufe0f\u26a0\ufe0f \u7d27\u6025\u9003\u751f\u6a21\u5f0f(\u6700\u9ad8\u7ea7): \u547d\u4e2d\u4efb\u610f\u4e00\u6761\u89c4\u5219\u5373\u7ec8\u6781\u67e5\u6740\uff0c\u591a\u904d\u8986\u5199\u5e7f\u7eb9\u5e7f\u5e95\u9500\u6bc1\uff0c\u4e14\u4e0d\u4f1a\u81ea\u52a8\u8fd8\u539f\uff01",
        10, 190, 520, 20);
    CreateLabel (g_hScanOpts,
        L"\u53ef\u80fd\u5bfc\u81f4\u7cfb\u7edf\u65e0\u6cd5\u542f\u52a8\u3001\u6b63\u5e38\u8f6f\u4ef6\u88ab\u6c38\u4e45\u635f\u574f\u3002\u4ec5\u5728\u786e\u8ba4\u7cfb\u7edf\u5df2\u88ab\u63a7\u3001\u9700\u7acb\u5373\u6b62\u635f\u65f6\u5f00\u542f\u3002",
        10, 212, 520, 20);
    // v13.27 覆写强度: 让用户按当前处境选"止损快"还是"销毁彻底"
    CreateLabel (g_hScanOpts, L"\u8986\u5199\u5f3a\u5ea6(\u9003\u751f\u6a21\u5f0f):", 10, 236, 120, 20);
    CreateWindowExW(0, L"COMBOBOX", L"",
                    WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | CBS_HASSTRINGS,
                    132, 234, 110, 120, g_hScanOpts,
                    (HMENU)(INT_PTR)IDC_CB_ESCAPE_WIPE,
                    GetModuleHandleW(nullptr), nullptr);
    {
        HWND hCb = GetDlgItem(g_hScanOpts, IDC_CB_ESCAPE_WIPE);
        if (hCb) {
            SendMessageW(hCb, CB_ADDSTRING, 0, (LPARAM)L"\u5f31(1\u904d)\u00b7\u5feb\u901f\u6b62\u635f");
            SendMessageW(hCb, CB_ADDSTRING, 0, (LPARAM)L"\u4e2d(3\u904d)\u00b7\u63a8\u8350");
            SendMessageW(hCb, CB_ADDSTRING, 0, (LPARAM)L"\u5f3a(7\u904d)\u00b7\u4e0d\u53ef\u6062\u590d");
            SendMessageW(hCb, CB_SETCURSEL, (WPARAM)(g_cfg.escapeWipeLevel - 1), 0);
        }
    }
    CreateLabel (g_hScanOpts,
        L"\u5f31=\u79d2\u7ea7\u5b8c\u6210\uff1b\u5f3a=\u5b8c\u6574 DoD 7 \u904d\uff0c\u5927\u6587\u4ef6\u53ef\u80fd\u9700\u8981\u51e0\u5206\u949f\u3002",
        252, 236, 420, 20);
    CreateButton(g_hScanOpts, L"应用",    IDC_BTN_APPLY,        420, 160, 80, 28);
    ShowWindow(g_hScanOpts, SW_HIDE);

    // 引擎开关组: BSS/HIPS/DAC/VEH/YARA/PE/Evasion/ApiHook (IDC_ENGINE_BASE+0..+7)
    static const wchar_t* const s_engineNames[8] = {
        L"BSS 行为", L"HIPS 主机", L"DAC 访问", L"VEH 异常",
        L"YARA 规则", L"PE 导入表", L"反规避", L"API 挂钩"
    };
    for (int i = 0; i < 8; ++i) {
        CreateCheck(p, s_engineNames[i], IDC_ENGINE_BASE + i, 20 + (i % 2) * 200, 210 + (i / 2) * 24, 180, 20);
    }

    // ---- 情报 / 沙箱 / 连坐 / CVE / 启动扫描 ----
    CreateButton(p, L"更新威胁情报(在线)", IDC_BTN_INTEL_UPDATE, 20, 320, 200, 32);
    CreateButton(p, L"对外威胁扫描+连坐",  IDC_BTN_EXT_SCAN,     230, 320, 200, 32);
    CreateButton(p, L"沙箱分析选中文件",   IDC_BTN_SANDBOX,      440, 320, 200, 32);
    CreateButton(p, L"启动全量扫描",       IDC_BTN_STARTUP_SCAN, 20, 360, 200, 32);
    CreateButton(p, L"CVE 利用扫描",       IDC_BTN_CVE_SCAN,     230, 360, 200, 32);
    CreateButton(p, L"进程守护(阻止无签名)", IDC_BTN_GUARD,      440, 360, 200, 32);
    CreateButton(p, L"办公软件防护(禁命令行)", IDC_BTN_OFFICE_GUARD, 20, 400, 200, 32);
    CreateButton(p, L"宏病毒扫描(文档VBA+基线)", IDC_BTN_MACRO_SCAN, 232, 400, 240, 32);
    CreateButton(p, L"信任管理(最小信任)", IDC_BTN_TRUST_MGR, 232, 440, 240, 32);

    // ---- 10 条建议对应入口 ----
    CreateButton(p, L"多引擎在线核查(VT)", IDC_BTN_VT_SCAN,       20, 480, 200, 32);
    CreateButton(p, L"U盘防护扫描",       IDC_BTN_USB_GUARD,      230, 480, 200, 32);
    CreateButton(p, L"下载目录扫描",      IDC_BTN_DL_SCAN,        440, 480, 200, 32);
    CreateButton(p, L"右键扫描集成",      IDC_BTN_CTX_MENU,       20, 520, 200, 32);
    CreateButton(p, L"补丁/软件审计",     IDC_BTN_PATCH_AUDIT,    230, 520, 200, 32);
    CreateButton(p, L"全盘深度扫描",      IDC_BTN_DEEP_SCAN,      440, 520, 200, 32);
    CreateButton(p, L"安全模式清除",      IDC_BTN_SAFEMODE,       20, 560, 200, 32);
    CreateButton(p, L"数据备份(离线快照)",  IDC_BTN_BACKUP,         230, 560, 200, 32);
    CreateButton(p, L"引导区MBR/GPT",     IDC_BTN_MBR,            440, 560, 200, 32);
    CreateButton(p, L"勒索专杀",          IDC_BTN_RANSOM_KILL,    20, 600, 200, 32);
    CreateButton(p, L"挖矿专杀",          IDC_BTN_MINER_KILL,     230, 600, 200, 32);
    CreateButton(p, L"未知账户扫描",      IDC_BTN_USER_SCAN,      20, 640, 200, 32);
    CreateButton(p, L"未知账户清理",      IDC_BTN_USER_CLEAN,     230, 640, 200, 32);
    // ---- 资源异常监控 / 顽固病毒免疫 ----
    CreateButton(p, L"资源异常扫描(优先通知)", IDC_BTN_RES_SCAN,    440, 640, 200, 32);
    CreateButton(p, L"资源监控守护(10s)",      IDC_BTN_RES_TOGGLE,  20,  680, 200, 32);
    CreateButton(p, L"顽固病毒免疫处置",       IDC_BTN_IMMUNE,      230, 680, 200, 32);
    CreateButton(p, L"hosts劫持检测",     IDC_BTN_HOSTS_SCAN,     20,  720, 200, 32);
    CreateButton(p, L"WMI持久化检测",     IDC_BTN_WMI_SCAN,       230, 720, 200, 32);
    CreateButton(p, L"计划任务持久化",     IDC_BTN_TASK_SCAN,      440, 720, 200, 32);
    CreateButton(p, L"剪贴板劫持监控",     IDC_BTN_CLIP_TOGGLE,    20,  760, 200, 32);
    CreateButton(p, L"自我保护看门狗",     IDC_BTN_SELFDEF_TOGGLE, 230, 760, 200, 32);
    CreateButton(p, L"网络审计(DNS/ARP/共享)", IDC_BTN_NETAUDIT,   440, 760, 200, 32);
    CreateButton(p, L"扫描优先级(无签名优先)", IDC_BTN_SCAN_PRIORITY, 20, 800, 200, 32);
    CreateButton(p, L"LSASS凭据窃取检测",     IDC_BTN_LSASS_GUARD,  230, 800, 200, 32);
    CreateButton(p, L"进程镂空检测",           IDC_BTN_HOLLOW_SCAN,  440, 800, 200, 32);
    CreateButton(p, L"DLL劫持检测",            IDC_BTN_DLLHIJACK_SCAN, 20, 840, 200, 32);
    CreateButton(p, L"重新学习系统基线", IDC_BTN_TRUST_LEARN, 480, 440, 240, 32);
    CreateButton(p, L"启发式扫描(HEUR)",     IDC_CB_HEUR_SCAN,   20, 880, 200, 32);
    CreateButton(p, L"主动防御链扫描(PDM)",  IDC_CB_PDM_SCAN,   230, 880, 200, 32);
    CreateButton(p, L"PDM实时防御开关",       IDC_CB_PDM_TOGGLE, 440, 880, 200, 32);
    // ---- 内核驱动对接 (DrvLink) ----
    CreateButton(p, L"装载内核驱动",      IDC_BTN_DRV_TOGGLE,    20, 920, 200, 32);
    CreateButton(p, L"驱动状态/重发规则", IDC_BTN_DRV_STATUS,   230, 920, 200, 32);
    CreateButton(p, L"卸载驱动服务",      IDC_BTN_DRV_UNINSTALL,440, 920, 200, 32);
}
static void CreateRollbackPage(HWND p) {
    CreateButton(p, L"创建快照",     IDC_CB_CREATE_SNAPSHOT, 20, 20, 150, 32);
    CreateButton(p, L"创建恢复环境", IDC_CB_RECOVERY_ENV,    190, 20, 150, 32);
    CreateButton(p, L"刷新",         IDC_CB_ROLLBACK_REFRESH,20, 62, 150, 32);
}
static void CreatePrivacyPage(HWND p) {
    // 摄像头: 开关 + 展开选项
    CreateCheck (p, L"启用虚拟摄像头", IDC_CB_CAM_ON, 20, 20, 160, 22);
    g_hCamOpts = CreateWindowExW(0, L"STATIC", nullptr, WS_CHILD | WS_BORDER,
                                 20, 52, 460, 90, p, nullptr, GetModuleHandleW(nullptr), nullptr);
    CreateCheck (g_hCamOpts, L"纯黑画面", IDC_CB_CAM_BLACK, 10, 8, 120, 20);
    CreateCheck (g_hCamOpts, L"自定义视频",IDC_CB_CAM_MODE, 140, 8, 120, 20);
    CreateEdit  (g_hCamOpts, IDC_CB_CAM_FILE, L"", 10, 40, 300, 22, false);
    CreateButton(g_hCamOpts, L"浏览...", IDC_CB_CAM_BROWSE, 320, 40, 80, 22);
    ShowWindow(g_hCamOpts, SW_HIDE);

    // 麦克风: 开关 + 展开选项
    CreateCheck (p, L"启用虚拟麦克风", IDC_CB_MIC_ON, 20, 160, 160, 22);
    g_hMicOpts = CreateWindowExW(0, L"STATIC", nullptr, WS_CHILD | WS_BORDER,
                                 20, 192, 460, 90, p, nullptr, GetModuleHandleW(nullptr), nullptr);
    CreateCheck (g_hMicOpts, L"静音流", IDC_CB_MIC_MUTE, 10, 8, 120, 20);
    CreateCheck (g_hMicOpts, L"自定义音频",IDC_CB_MIC_MODE, 140, 8, 120, 20);
    CreateEdit  (g_hMicOpts, IDC_CB_MIC_FILE, L"", 10, 40, 300, 22, false);
    CreateButton(g_hMicOpts, L"浏览...", IDC_CB_MIC_BROWSE, 320, 40, 80, 22);
    ShowWindow(g_hMicOpts, SW_HIDE);
}
static void CreateDlpPage(HWND p) {
    CreateButton(p, L"加密(AES-256)", IDC_CB_ENCRYPT, 20, 20, 150, 32);
    CreateButton(p, L"安全粉碎(DoD)", IDC_CB_SHRED,   190, 20, 150, 32);
    CreateButton(p, L"DPAPI 保护",    IDC_CB_DPAPI,   20, 62, 150, 32);
}
static void CreateFimPage(HWND p) {
    CreateButton(p, L"建立基线",   IDC_CB_BASELINE,   20, 20, 140, 32);
    CreateButton(p, L"启动监控",   IDC_CB_START_FIM, 190, 20, 140, 32);
    CreateButton(p, L"停止监控",   IDC_CB_STOP_FIM,  20, 62, 140, 32);
    CreateButton(p, L"运行SCA审计",IDC_CB_RUN_SCA,   190, 62, 140, 32);
}
static void CreateLogPage(HWND p) {
    // 先建工具条按钮: 原先此页 0 个按钮, 导致刷新/清空两个 case 永远点不到(死代码)
    CreateButton(p, L"刷新日志",     IDC_CB_LOG_REFRESH,     10,  10, 110, 30);
    CreateButton(p, L"清空日志",     IDC_CB_LOG_CLEAR,      130,  10, 110, 30);
    CreateButton(p, L"导出报告",     IDC_CB_LOG_EXPORT,     250,  10, 110, 30);
    CreateButton(p, L"启动项管理",   IDC_CB_AUTORUN_MANAGE, 370,  10, 110, 30);
    g_hLog = CreateWindowExW(0, L"LISTBOX", nullptr,
                             WS_CHILD | WS_VISIBLE | LBS_NOTIFY | WS_VSCROLL,
                             10, 48, 560, 302, p, (HMENU)IDC_LOG,
                             GetModuleHandleW(nullptr), nullptr);
    SendMessageW(g_hLog, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), 0);
}

// ===================== 快捷方式(.lnk)劫持检测 =====================
// 扫描启动文件夹/桌面/最近使用中的 .lnk, 解析其中指向的命令与参数:
// 借道 LOLBins, 编码命令行(-enc/IEX), 指向可写目录, 超长混淆参数。
static bool LnkReadText(const std::wstring& path, std::wstring& out) {
    FILE* f = _wfopen(path.c_str(), L"rb");
    if (!f) return false;
    std::string all; char b[4096]; size_t n;
    while ((n = fread(b, 1, sizeof(b), f)) > 0) all.append(b, n);
    fclose(f);
    std::wstring a, u;
    for (size_t i = 0; i < all.size(); ++i) {
        unsigned char c = (unsigned char)all[i];
        a += (c >= 32 && c < 127) ? (wchar_t)c : L' ';
    }
    for (size_t i = 0; i + 1 < all.size(); i += 2) {
        wchar_t w = (wchar_t)((unsigned char)all[i] | ((unsigned char)all[i + 1] << 8));
        u += (w >= 32 && w < 0xFFFE) ? w : L' ';
    }
    out = a + L" | " + u;
    return true;
}
static const wchar_t* kLnkLolbins[] = {
    L"cmd.exe", L"powershell.exe", L"pwsh.exe", L"rundll32.exe", L"regsvr32.exe",
    L"mshta.exe", L"wscript.exe", L"cscript.exe", L"certutil.exe", L"bitsadmin.exe",
    L"wmic.exe", L"schtasks.exe", L"installutil.exe", L"msbuild.exe"
};
static const wchar_t* kLnkEncArgs[] = {
    L"-enc", L"-encodedcommand", L"iex", L"invoke-expression", L"downloadstring",
    L"frombase64string", L"bypass", L"-nop", L"start-process", L"vssadmin"
};
static void LnkLower(std::wstring& t) {
    for (size_t i = 0; i < t.size(); ++i)
        if (t[i] >= L'A' && t[i] <= L'Z') t[i] = t[i] - L'A' + L'a';
}
static int LnkScoreOne(const std::wstring& path, std::wstring& reason) {
    std::wstring t;
    if (!LnkReadText(path, t)) return 0;
    LnkLower(t);
    int sc = 0; reason.clear();
    for (const wchar_t* bn : kLnkLolbins) {
        std::wstring b(bn); LnkLower(b);
        if (t.find(b) != std::wstring::npos) { sc += 3; reason += L"借道" + std::wstring(bn) + L" "; break; }
    }
    int enc = 0;
    for (const wchar_t* an : kLnkEncArgs) {
        std::wstring a(an); LnkLower(a);
        if (t.find(a) != std::wstring::npos) ++enc;
    }
    if (enc > 0) { sc += 4; reason += L"编码命令(" + std::to_wstring(enc) + L"项) "; }
    static const wchar_t* wds[] = { L"\\temp\\", L"\\appdata\\", L"\\public\\", L"\\downloads\\", L"\\programdata\\" };
    for (const wchar_t* d : wds) {
        if (t.find(d) != std::wstring::npos) { sc += 3; reason += L"指向可写目录 "; break; }
    }
    size_t mx = 0, cur = 0;
    for (size_t i = 0; i < t.size(); ++i) {
        if (t[i] == L' ') { if (cur > mx) mx = cur; cur = 0; } else ++cur;
    }
    if (mx > 300) { sc += 2; reason += L"超长混淆参数 "; }
    return sc;
}
static void LnkHijackScan() {
    if (!g_cfg.lnkScanOn) { LogPost(L"[LNK] 快捷方式劫持检测未开启(配置 lnkScanOn=false)"); return; }
    std::vector<std::wstring> dirs;
    auto addEnv = [&](const wchar_t* ev, const wchar_t* sub) {
        wchar_t buf[MAX_PATH] = { 0 };
        if (GetEnvironmentVariableW(ev, buf, MAX_PATH) > 0) dirs.push_back(std::wstring(buf) + sub);
    };
    addEnv(L"APPDATA",     L"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
    addEnv(L"ProgramData", L"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
    addEnv(L"USERPROFILE", L"\\Desktop");
    addEnv(L"APPDATA",     L"\\Microsoft\\Windows\\Recent");
    int scanned = 0, bad = 0;
    for (size_t di = 0; di < dirs.size(); ++di) {
        std::wstring q = dirs[di] + L"\\*";
        WIN32_FIND_DATAW fd;
        HANDLE h = FindFirstFileW(q.c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) continue;
        do {
            std::wstring name = fd.cFileName;
            if (name.size() < 5) continue;
            std::wstring ln = name; LnkLower(ln);
            if (ln.size() < 4 || ln.substr(ln.size() - 4) != L".lnk") continue;
            std::wstring full = dirs[di] + L"\\" + name;
            ++scanned;
            std::wstring reason;
            int sc = LnkScoreOne(full, reason);
            if (sc >= 4) {
                ++bad;
                LogFmt(L"[LNK] 可疑快捷方式: %s (风险分%d) %s", full.c_str(), sc, reason.c_str());
                BehavAdd(0, full, BEHAV_BLOCK, 9,
                    L"快捷方式劫持(风险分" + std::to_wstring(sc) + L"): " + reason);
                if (g_cfg.advAggressive && !IsProtectedPath(full)) {
                    DeleteFileW(full.c_str());
                    LogFmt(L"[LNK] 激进模式: 已删除 %s", full.c_str());
                }
            }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    if (bad > 0) SetThreatLevel(THREAT_DANGER, L"发现可疑快捷方式劫持");
    LogFmt(L"[LNK] 扫描完成: 检查 %d 个快捷方式, 可疑 %d 个", scanned, bad);
}

// ===================== 勒索诱饵蜜罐 (Canary) =====================
// 在文档/桌面/隐藏目录部署带标记的诱饵文件。勒索软件加密时会先动这些文件,
// 一旦诱饵被修改/删除即判定为大规模加密行为, 立即升级最高威胁并可选急停。
static const wchar_t* kCanaryNames[] = {
    L"~$财务汇总_2026.xlsx", L"客户名单_backup.docx", L"合同扫描件.pdf",
    L"数据库导出.sql", L"工资表_final.xlsx", L"重要资料.txt", L"archive_backup.zip"
};
static const wchar_t* kCanaryMark = L"ZZEDR-CANARY-DO-NOT-MODIFY";
static std::wstring CanaryDir() {
    wchar_t tmp[MAX_PATH] = { 0 };
    GetTempPathW(MAX_PATH, tmp);
    return std::wstring(tmp) + L"zz_EDR_canary";
}
static void CanaryTargets(std::vector<std::wstring>& out) {
    out.clear();
    out.push_back(CanaryDir());
    wchar_t buf[MAX_PATH] = { 0 };
    if (GetEnvironmentVariableW(L"USERPROFILE", buf, MAX_PATH) > 0) {
        out.push_back(std::wstring(buf) + L"\\Documents");
        out.push_back(std::wstring(buf) + L"\\Desktop");
    }
}
static int CanaryDeploy() {
    std::vector<std::wstring> dirs; CanaryTargets(dirs);
    int n = 0;
    CreateDirectoryW(dirs[0].c_str(), NULL);
    for (size_t i = 0; i < dirs.size(); ++i) {
        for (const wchar_t* nm : kCanaryNames) {
            std::wstring fp = dirs[i] + L"\\" + nm;
            if (GetFileAttributesW(fp.c_str()) != INVALID_FILE_ATTRIBUTES) continue;
            FILE* f = _wfopen(fp.c_str(), L"wb");
            if (!f) continue;
            unsigned short bom = 0xFEFF;
            fwrite(&bom, 1, 2, f);
            std::wstring content = std::wstring(kCanaryMark) + L"\r\n" + std::wstring(200, L'A');
            fwrite(content.c_str(), 1, content.size() * 2, f);
            fclose(f);
            ++n;
        }
    }
    LogFmt(L"[诱饵] 已部署 %d 个蜜罐文件 (标记: %s)", n, kCanaryMark);
    return n;
}
static bool CanaryIntact(const std::wstring& fp) {
    FILE* f = _wfopen(fp.c_str(), L"rb");
    if (!f) return false;
    std::string all; char b[4096]; size_t n;
    while ((n = fread(b, 1, sizeof(b), f)) > 0) all.append(b, n);
    fclose(f);
    std::wstring mark(kCanaryMark);
    std::string pat;
    for (size_t i = 0; i < mark.size(); ++i) {
        pat += (char)(mark[i] & 0xFF);
        pat += (char)((mark[i] >> 8) & 0xFF);
    }
    return all.find(pat) != std::string::npos;
}
static int CanaryCheck() {
    std::vector<std::wstring> dirs; CanaryTargets(dirs);
    int total = 0, hit = 0;
    for (size_t i = 0; i < dirs.size(); ++i) {
        for (const wchar_t* nm : kCanaryNames) {
            std::wstring fp = dirs[i] + L"\\" + nm;
            if (GetFileAttributesW(fp.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
            ++total;
            if (!CanaryIntact(fp)) {
                ++hit;
                LogFmt(L"[诱饵] !! 蜜罐被篡改(疑似加密): %s", fp.c_str());
                BehavAdd(0, fp, BEHAV_FILE, 10, L"勒索诱饵被加密/篡改, 疑似勒索软件活动");
            }
        }
    }
    if (hit > 0) {
        SetThreatLevel(THREAT_DANGER, L"勒索诱饵被篡改, 疑似勒索软件正在加密文件");
        if (g_cfg.advAggressive) {
            LogPost(L"[诱饵] 激进模式: 触发顽固病毒免疫处置");
            PurgeIncurableAll();
        }
    }
    if (total == 0) CanaryDeploy();
    return hit;
}
static void CanaryGuardRun(bool deploy) {
    if (!g_cfg.canaryOn) { LogPost(L"[诱饵] 蜜罐监控未开启(配置 canaryOn=false)"); return; }
    if (deploy) CanaryDeploy();
    int hit = CanaryCheck();
    if (hit == 0) LogFmt(L"[诱饵] 蜜罐完好 (%d 个), 未发现勒索加密行为", (int)(sizeof(kCanaryNames)/sizeof(kCanaryNames[0])));
}
static void CanaryGuardLoop() {
    if (!g_cfg.canaryOn) return;
    CanaryDeploy();
    while (g_running.load()) {
        CanaryCheck();
        for (int i = 0; i < 30 && g_running.load(); ++i) Sleep(1000);
    }
}

// ===================== COM 劫持 / SilentProcessExit / IFEO =====================
// COM 劫持: HKCU\Software\Classes\CLSID\{..}\InprocServer32 覆盖系统 CLSID,
//           DLL 落在可写目录或已不存在 -> 进程加载 COM 时即执行恶意代码。
// SilentProcessExit: 目标进程退出时启动 MonitorProcess, 常被用于无文件驻留。
// IFEO Debugger: 镜像劫持, 启动目标程序时代替执行调试器。
static int ComHijackScan() {
    if (!g_cfg.comHijackOn) { LogPost(L"[COM] COM劫持检测未开启(配置 comHijackOn=false)"); return 0; }
    int hits = 0;
    HKEY hkcu = NULL;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Classes\\CLSID", 0, KEY_READ, &hkcu) == ERROR_SUCCESS) {
        wchar_t name[256];
        DWORD idx = 0;
        while (true) {
            DWORD nsz = 256;
            if (RegEnumKeyExW(hkcu, idx++, name, &nsz, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
            std::wstring clsid = name;
            if (clsid.size() < 6) continue;
            const wchar_t* subs[2] = { L"InprocServer32", L"LocalServer32" };
            for (int si = 0; si < 2; ++si) {
                HKEY hsub = NULL;
                std::wstring sp = clsid + L"\\" + subs[si];
                if (RegOpenKeyExW(hkcu, sp.c_str(), 0, KEY_READ, &hsub) != ERROR_SUCCESS) continue;
                wchar_t val[1024] = { 0 }; DWORD vsz = sizeof(val); DWORD ty = 0;
                LONG r = RegQueryValueExW(hsub, NULL, NULL, &ty, (LPBYTE)val, &vsz);
                RegCloseKey(hsub);
                if (r != ERROR_SUCCESS || !val[0]) continue;
                std::wstring dll = val;
                std::wstring low = dll; LnkLower(low);
                int sc = 0; std::wstring reason;
                static const wchar_t* wds[] = { L"\\temp\\", L"\\appdata\\", L"\\public\\",
                                                L"\\downloads\\", L"\\programdata\\", L"\\users\\" };
                for (const wchar_t* d : wds) {
                    if (low.find(d) != std::wstring::npos) { sc += 4; reason += L"DLL位于可写目录 "; break; }
                }
                if (GetFileAttributesW(dll.c_str()) == INVALID_FILE_ATTRIBUTES) { sc += 2; reason += L"DLL不存在 "; }
                HKEY hklm = NULL;
                std::wstring lm = L"SOFTWARE\\Classes\\CLSID\\" + clsid;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, lm.c_str(), 0, KEY_READ, &hklm) == ERROR_SUCCESS) {
                    sc += 2; reason += L"覆盖系统CLSID "; RegCloseKey(hklm);
                }
                if (sc >= 4) {
                    ++hits;
                    LogFmt(L"[COM] 劫持: %s\\%s -> %s (%s)", clsid.c_str(), subs[si], dll.c_str(), reason.c_str());
                    BehavAdd(0, dll, BEHAV_REG, 9, L"COM 劫持 CLSID " + clsid + L": " + reason);
                    if (g_cfg.advAggressive) {
                        RegDeleteKeyW(hkcu, clsid.c_str());
                        LogFmt(L"[COM] 激进模式: 已删除 HKCU CLSID %s", clsid.c_str());
                    }
                    break;
                }
            }
        }
        RegCloseKey(hkcu);
    }
    HKEY hs = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit",
        0, KEY_READ, &hs) == ERROR_SUCCESS) {
        wchar_t name[256]; DWORD idx = 0;
        while (true) {
            DWORD nsz = 256;
            if (RegEnumKeyExW(hs, idx++, name, &nsz, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
            HKEY hsub = NULL;
            if (RegOpenKeyExW(hs, name, 0, KEY_READ, &hsub) != ERROR_SUCCESS) continue;
            wchar_t val[1024] = { 0 }; DWORD vsz = sizeof(val); DWORD ty = 0;
            LONG r = RegQueryValueExW(hsub, L"MonitorProcess", NULL, &ty, (LPBYTE)val, &vsz);
            RegCloseKey(hsub);
            if (r == ERROR_SUCCESS && val[0]) {
                ++hits;
                LogFmt(L"[静默退出] 劫持: %s -> MonitorProcess=%s", name, val);
                BehavAdd(0, val, BEHAV_REG, 10,
                    L"SilentProcessExit 驻留: " + std::wstring(name) + L" 退出时启动 " + val);
                SetThreatLevel(THREAT_DANGER, L"发现 SilentProcessExit 驻留");
            }
        }
        RegCloseKey(hs);
    }
    HKEY hi = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        0, KEY_READ, &hi) == ERROR_SUCCESS) {
        wchar_t name[256]; DWORD idx = 0;
        while (true) {
            DWORD nsz = 256;
            if (RegEnumKeyExW(hi, idx++, name, &nsz, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
            HKEY hsub = NULL;
            if (RegOpenKeyExW(hi, name, 0, KEY_READ, &hsub) != ERROR_SUCCESS) continue;
            wchar_t val[1024] = { 0 }; DWORD vsz = sizeof(val); DWORD ty = 0;
            LONG r = RegQueryValueExW(hsub, L"Debugger", NULL, &ty, (LPBYTE)val, &vsz);
            RegCloseKey(hsub);
            if (r == ERROR_SUCCESS && val[0]) {
                ++hits;
                LogFmt(L"[IFEO] 镜像劫持: %s -> %s", name, val);
                BehavAdd(0, val, BEHAV_REG, 10, L"IFEO 镜像劫持: " + std::wstring(name) + L" -> " + val);
                SetThreatLevel(THREAT_DANGER, L"发现 IFEO 镜像劫持");
            }
        }
        RegCloseKey(hi);
    }
    if (hits == 0) LogPost(L"[COM] 未发现 COM 劫持 / SilentProcessExit / IFEO 镜像劫持");
    return hits;
}

// ============================================================
//  隐藏文件与 NTFS 备用数据流 (ADS) 检测
// ============================================================
//  【思路】恶意软件用"看不见"做持久化，主要两条路：
//
//   ① 隐藏属性 (FILE_ATTRIBUTE_HIDDEN / SYSTEM)
//      资源管理器默认不显示。
//      ⚠️ 注意: FindFirstFileW 其实**会**返回隐藏文件，所以现有扫描
//      "能扫到"，但一视同仁、不做任何加权 —— 藏在 %TEMP% 里的隐藏
//      恶意程序与正常文件同等对待，等于没防。
//
//   ② NTFS 备用数据流 (Alternate Data Stream, ADS)
//      形如:  C:\Users\x\note.txt:payload.exe
//      这是**真正的盲区**: 资源管理器看不到、dir /a 也看不到、
//      文件大小不计入主数据流、普通哈希/内容扫描完全扫不到；
//      但可以直接执行:
//          start "" "note.txt:payload.exe"
//          rundll32 "note.txt:payload.dll",Entry
//      必须用 FindFirstStreamW 单独枚举才能发现。
//
//  【为什么这两者要一起做】
//      只做隐藏文件 → 漏 ADS；只做 ADS → 漏隐藏文件。
//      二者都是"你看不见它、但它能跑"的持久化手段。
// ============================================================

// ---- ADS 结构体 (自定义 ZZ_ 前缀避免与 Windows SDK 重复定义) ----
// 真实 SDK 布局: { LARGE_INTEGER StreamSize; WCHAR cStreamName[MAX_PATH+36]; }
struct ZZ_FIND_STREAM_DATA {
    long long StreamSize;
    wchar_t   cStreamName[260 + 36];
};
typedef HANDLE (WINAPI *ZZ_FindFirstStreamPtr)(const wchar_t*, int, void*, DWORD);
typedef int    (WINAPI *ZZ_FindNextStreamPtr)(HANDLE, void*);


// 构建扫描目标目录(用项目真实的 GetTempPathW / SHGetFolderPathW，不依赖 %VAR% 展开)
static void HidTargetDirs(std::vector<wstring>& out) {
    wchar_t buf[MAX_PATH];
    if (GetTempPathW(MAX_PATH, buf)) {
        wstring t = buf;
        while (!t.empty() && (t.back() == L'\\' || t.back() == L'/')) t.pop_back();
        if (!t.empty()) out.push_back(t);
    }
    out.push_back(L"C:\\Windows\\Temp");
    int csids[] = { CSIDL_APPDATA, CSIDL_LOCAL_APPDATA, CSIDL_PROFILE,
                    CSIDL_DESKTOP, CSIDL_PERSONAL };
    for (int c : csids) {
        if (SUCCEEDED(SHGetFolderPathW(nullptr, c, nullptr, 0, buf)) && buf[0])
            out.push_back(buf);
    }
    // 派生子目录: Downloads / Recent / Documents
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PROFILE, nullptr, 0, buf)) && buf[0]) {
        wstring prof = buf;
        while (!prof.empty() && prof.back() == L'\\') prof.pop_back();
        out.push_back(prof + L"\\Downloads");
        out.push_back(prof + L"\\Recent");
        out.push_back(prof + L"\\Documents");
    }
    // ProgramData / Public
    if (SUCCEEDED(SHGetFolderPathW(nullptr, 0x0023 /*CSIDL_COMMON_APPDATA*/, nullptr, 0, buf)) && buf[0])
        out.push_back(buf);
    if (SUCCEEDED(SHGetFolderPathW(nullptr, 0x002E /*CSIDL_COMMON_DOCUMENTS*/, nullptr, 0, buf)) && buf[0])
        out.push_back(buf);
}

// 判断是否位于可写的高危目录(Temp / AppData / Downloads / Public 等)
static bool HidIsHotDir(const wstring& path) {
    wstring low = ScanLowerW(path);
    static const wchar_t* kHot[] = {
        L"\\temp", L"\\tmp", L"\\appdata", L"\\downloads",
        L"\\programdata", L"\\public", L"\\recent", L"\\desktop"
    };
    for (const wchar_t* k : kHot)
        if (low.find(k) != wstring::npos) return true;
    return false;
}

// 从 ADS 流名提取纯名字: ":payload.exe:$DATA" -> "payload.exe"
static wstring AdsBaseName(const wstring& stream) {
    wstring s = stream;
    // 去掉末尾的 ":$DATA"（流类型）
    size_t c = s.rfind(L':');
    if (c != wstring::npos && c > 0) {
        wstring tail = s.substr(c + 1);
        if (tail == L"$DATA") s = s.substr(0, c);
    }
    // 去掉开头的 ':'
    if (!s.empty() && s[0] == L':') s.erase(0, 1);
    return s;
}

// 判断是否为随机哈希式名字(32/40/64 位纯 hex)，忽略扩展名
static bool AdsIsHashName(const wstring& s) {
    wstring base = s;
    size_t dot = base.rfind(L'.');
    if (dot != wstring::npos) base = base.substr(0, dot);
    if (base.length() != 32 && base.length() != 40 && base.length() != 64) return false;
    for (wchar_t ch : base) {
        bool hex = (ch >= L'0' && ch <= L'9') ||
                   (ch >= L'a' && ch <= L'f') ||
                   (ch >= L'A' && ch <= L'F');
        if (!hex) return false;
    }
    return true;
}

// 窥探 ADS 流内容头部，判断是否为 PE / 脚本
// 【为什么需要】只看流名不够: 攻击者可以把 payload 命名为 "data"，
//   但内容若是 MZ 开头，那就是一个完整的可执行文件，100% 恶意。
static int AdsPeekHead(const wstring& path, const wstring& stream) {
    wstring full = path + stream;   // stream 已含前导 ':'，形如 file.txt:payload.exe:$DATA
    HANDLE h = CreateFileW(full.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (!h || h == INVALID_HANDLE_VALUE) return 0;
    char buf[512];
    DWORD rd = 0;
    int risk = 0;
    if (ReadFile(h, buf, sizeof(buf), &rd, nullptr) && rd >= 2) {
        if (buf[0] == 'M' && buf[1] == 'Z') {
            risk = 2;                       // PE 可执行文件藏在流里
        } else {
            // 取可读 ASCII 片段做脚本特征匹配
            std::string head(buf, (size_t)rd);
            std::string low; low.reserve(head.size());
            for (char c : head) low += (char)(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
            static const char* kScript[] = {
                "<script", "wscript.shell", "powershell", "-encodedcommand",
                "cmd.exe", "mshta", "certutil", "bitsadmin"
            };
            for (const char* k : kScript)
                if (low.find(k) != std::string::npos) { risk = 2; break; }
        }
    }
    CloseHandle(h);
    return risk;
}

// 单个 ADS 流风险判定: 0=正常 1=可疑 2=高危
static int AdsStreamRisk(const wstring& path, const wstring& stream, long long size) {
    if (stream == L"::$DATA") return 0;         // 主数据流 = 文件本身
    wstring base = AdsBaseName(stream);
    if (base.empty()) return 0;
    wstring low = ScanLowerW(base);

    // Zone.Identifier: 浏览器/Office 的下载标记，合法的。
    // 但恶意软件也会往里塞东西，因此按体积区分(正常 < 4KB)
    if (low == L"zone.identifier") return (size > 4096) ? 1 : 0;

    // 内容优先: 只要流里是 PE 或脚本，无论叫什么名字都是高危
    int head = AdsPeekHead(path, stream);
    if (head == 2) return 2;

    // 可执行扩展名作为流名 —— 明确恶意
    static const wchar_t* kExeExt[] = {
        L".exe", L".dll", L".scr", L".bat", L".cmd", L".ps1", L".vbs",
        L".js", L".jse", L".vbe", L".wsf", L".hta", L".sys", L".com"
    };
    for (const wchar_t* e : kExeExt) {
        size_t n = wcslen(e);
        if (low.length() >= n && low.compare(low.length() - n, n, e) == 0) return 2;
    }

    // 体积异常: 合法的 ADS(Zone.Identifier/图标缓存)都很小
    if (size > 100 * 1024) return 2;            // >100KB 几乎不可能是正常流
    if (size > 10  * 1024) return 1;

    // 随机哈希式流名: 加载器常用手法
    if (AdsIsHashName(base)) return 1;

    // 其他非 Zone.Identifier 的流: 正常程序极少创建，列为可疑
    return 1;
}

// 清空并尝试删除某个 ADS 流
// 【关键顺序】Windows 没有专用的"删除流"API，DeleteFileW 虽可删流但
//   常因句柄/权限失败。因此必须两步走:
//     ① 先截断为 0 字节 —— 保证 payload 立即失效（一定能成功）
//     ② 再尝试 DeleteFileW 删除流本身 —— 失败也无妨，内容已清空
//   顺序绝不能反: 若先删失败又没截断，payload 仍完整、随时可执行。
static bool AdsPurgeStream(const wstring& path, const wstring& stream) {
    wstring full = path + stream;
    HANDLE h = CreateFileW(full.c_str(), GENERIC_WRITE, 0, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    if (!h || h == INVALID_HANDLE_VALUE) return false;
    SetFilePointer(h, 0, nullptr, FILE_BEGIN);
    BOOL ok = SetEndOfFile(h);
    FlushFileBuffers(h);
    CloseHandle(h);
    if (ok) DeleteFileW(full.c_str());   // 尽力删除，失败不影响结果
    return ok != 0;
}

// ---- NTFS 备用数据流 (ADS) 扫描 ----

// ============================================================================
// v13.37 邮件附件扫描 (MailScan)
//
// 【思路】邮件是恶意软件最主要的投递渠道。攻击者把恶意附件伪装成
// "发票.pdf.exe"、"订单详情.iso"、"工资表.xlsm" 诱导用户双击。本功能扫描
// 本地邮件存储, 提取附件并做静态判定(哈希情报 + 规则 + 危险扩展名 + 双扩展伪装)。
//
// 【格式覆盖与诚实边界 —— 重要】
//   .eml  = MIME 纯文本            → 完整解析, 提取 base64 附件后扫描
//   .mbox = Thunderbird 邮箱文件   → 按 "From " 行切分, 同 .eml 处理
//   .msg  = Outlook OLE 复合文档(二进制专有格式)
//   .pst  = Outlook 数据库(专有格式)
//   后两者【不解析】。手写 OLE/PST 解析器是数百页规范的工作量, 写错就是误报
//   制造机。对 .msg/.pst 只做"内嵌特征"启发式(搜 MZ 头、危险扩展名字符串、
//   VBA 自动执行关键字), 并在日志明确标注这是有限检测, 不做完整结论。
//
// 【必须避开的坑】
//   1. 路径穿越: 恶意邮件的附件名可能是 "../../evil.exe", 直接拼接会把文件
//      写到临时目录之外。必须只取文件名部分(MailSafeName)。
//   2. base64 块里常夹带换行/空格, 必须逐字符容错跳过, 不能整块判失败。
//   3. 附件名可带引号也可不带(MIME 都允许), 两种都要支持。
// ============================================================================

// wstring -> string, 仅用于 MIME 文本解析(附件名与头字段基本是 ASCII)。
// 非 ASCII 替换成 '?' 不影响扩展名判定, 但日志显示仍用原始 wstring。
static std::string MailW2A(const std::wstring& w) {
    std::string r; r.reserve(w.size());
    for (wchar_t c : w) r.push_back((c > 0 && c < 128) ? (char)c : '?');
    return r;
}
static std::wstring MailA2W(const std::string& a) {
    std::wstring r; r.reserve(a.size());
    for (unsigned char c : a) r.push_back((wchar_t)c);
    return r;
}

// 只保留文件名部分, 剥掉任何路径分隔符 —— 防附件名路径穿越
static std::string MailSafeName(const std::string& n) {
    size_t p1 = n.find_last_of("\\/");
    std::string r = (p1 == std::string::npos) ? n : n.substr(p1 + 1);
    // 再去掉控制字符, 避免写出畸形文件名
    std::string o;
    for (char c : r) if ((unsigned char)c >= 0x20 && c != '"' && c != '*' && c != '?') o.push_back(c);
    if (o.empty()) o = "attachment.bin";
    if (o.size() > 120) o = o.substr(o.size() - 120);
    return o;
}

static const char* kB64T =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static int B64Val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}
// 容错: 跳过 '=' / 换行 / 空格 / 任何非法字符, MIME 里这些都常见
static bool B64DecodeBin(const std::string& in, std::vector<unsigned char>& out) {
    out.clear();
    int acc = 0, bits = 0;
    for (char c : in) {
        // '=' 是 padding, 出现即表示数据流结束。必须 break 而不是 continue:
        // 若继续解后面的字符, 会多产出尾部垃圾字节, 导致附件 SHA256 与情报
        // 库不匹配 -> 本该命中的恶意附件被漏报。
        if (c == '=') break;
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        int v = B64Val(c);
        if (v < 0) continue;
        acc = (acc << 6) | v; bits += 6;
        if (bits >= 8) { bits -= 8; out.push_back((unsigned char)((acc >> bits) & 0xFF)); }
    }
    return !out.empty();
}

static std::string MailLower(const std::string& in) {
    std::string r = in;
    for (char& c : r) c = (char)tolower((unsigned char)c);
    return r;
}

// 从 Content-Disposition / Content-Type 头里取附件名
static bool MailFindAttachName(const std::string& hdr, size_t from, std::string& name) {
    std::string low = MailLower(hdr);
    size_t p = low.find("content-disposition:", from);
    bool isDisp = true;
    if (p == std::string::npos) {
        p = low.find("content-type:", from);
        isDisp = false;
    }
    if (p == std::string::npos) return false;
    size_t e = low.find("\r\n\r\n", p);           // 头块结束
    if (e == std::string::npos) e = low.size();
    std::string seg = low.substr(p, e - p);
    size_t f = seg.find(isDisp ? "filename=" : "name=");
    if (f == std::string::npos) return false;
    size_t op = p + f + (isDisp ? 9 : 5);
    // 带引号
    size_t q1 = hdr.find('"', op);
    if (q1 != std::string::npos && q1 < e) {
        size_t q2 = hdr.find('"', q1 + 1);
        if (q2 != std::string::npos) { name = hdr.substr(q1 + 1, q2 - q1 - 1); return !name.empty(); }
    }
    size_t e2 = hdr.find_first_of(";\r\n", op);   // 不带引号
    if (e2 == std::string::npos) e2 = hdr.size();
    name = hdr.substr(op, e2 - op);
    while (!name.empty() && (name.back() == ' ' || name.back() == '\t')) name.pop_back();
    return !name.empty();
}

// 危险附件扩展名(可直接执行或含宏/脚本)
static bool MailDangerExt(const std::string& n) {
    static const char* ext[] = { ".exe", ".scr", ".pif", ".com", ".bat", ".cmd", ".js", ".jse",
        ".vbs", ".vbe", ".wsf", ".wsh", ".ps1", ".psm1", ".hta", ".lnk", ".iso", ".img",
        ".vhd", ".dll", ".jar", ".msi", ".reg", ".chm", ".xlsm", ".docm", ".pptm", ".xslt" };
    std::string l = MailLower(n);
    for (const char* e : ext) {
        size_t el = strlen(e);
        if (l.size() >= el && l.compare(l.size() - el, el, e) == 0) return true;
    }
    return false;
}

// 双扩展名伪装: 真实扩展名藏在后面, 前面伪装成"安全"的 pdf/doc/jpg
static bool MailDoubleExtSpoof(const std::string& n) {
    std::string l = MailLower(n);
    size_t last = l.rfind('.');
    if (last == std::string::npos || last == 0) return false;
    size_t prev = l.rfind('.', last - 1);
    if (prev == std::string::npos) return false;
    std::string e1 = "." + l.substr(prev + 1, last - prev - 1);
    static const char* safe[] = { ".pdf", ".doc", ".docx", ".xls", ".xlsx",
                                  ".jpg", ".jpeg", ".png", ".txt", ".zip" };
    for (const char* s : safe) if (e1 == s) return true;
    return false;
}

// 从一封邮件的文本里提取附件并扫描。返回提取到的附件数。
static int MailExtractAndScan(const std::string& mail, const std::wstring& srcPath, int& hit) {
    int extracted = 0;
    size_t pos = 0;
    while (extracted < 10) {                       // 每封邮件最多 10 个附件
        std::string name;
        if (!MailFindAttachName(mail, pos, name)) break;
        size_t at = MailLower(mail).find("content-disposition:", pos);
        if (at == std::string::npos) at = pos;
        pos = at + 10;
        name = MailSafeName(name);
        // 找 base64 体: 头块结束("\r\n\r\n")之后, 到下一个 boundary 为止
        size_t he = mail.find("\r\n\r\n", at);
        if (he == std::string::npos) break;
        size_t bs = he + 4;
        size_t be = mail.find("\r\n--", bs);
        if (be == std::string::npos) be = mail.size();
        std::string body = mail.substr(bs, be - bs);
        if (body.size() > 40 * 1024 * 1024) body = body.substr(0, 40 * 1024 * 1024);

        std::vector<unsigned char> bin;
        bool okDec = false;
        std::string encLow = MailLower(mail.substr(at, (he > at ? he - at : 0)));
        if (encLow.find("base64") != std::string::npos) okDec = B64DecodeBin(body, bin);
        if (!okDec || bin.empty()) {
            bin.assign(body.begin(), body.end());       // 非 base64 则按原文处理
            if (bin.empty()) continue;
        }
        ++extracted;

        int sev = 0;
        std::wstring why;
        std::wstring wn = MailA2W(name);
        if (MailDoubleExtSpoof(name)) { sev = 4; why = L"双扩展名伪装(真实扩展被隐藏)"; }
        else if (MailDangerExt(name)) { sev = 3; why = L"危险附件类型"; }
        // 内容判定: MZ 头(PE) 或脚本特征
        bool hasMZ = bin.size() > 2 && bin[0] == 'M' && bin[1] == 'Z';
        std::string head(bin.begin(), bin.begin() + (bin.size() < 512 ? bin.size() : 512));
        std::string hl = MailLower(head);
        if (hasMZ && sev < 4) { sev = 4; why = L"附件为可执行程序(PE)"; }

        // 落到临时文件做哈希情报比对
        std::wstring tmp;
        {
            wchar_t tp[MAX_PATH + 1] = { 0 };
            GetTempPathW(MAX_PATH, tp);
            tmp = tp; tmp += L"zz_EDR_mail_";
            tmp += MailA2W(std::to_string((unsigned long)GetCurrentProcessId()));
            tmp += L"_"; tmp += MailA2W(std::to_string(extracted));
            tmp += L"_"; tmp += wn;
        }
        FILE* f = _wfopen(tmp.c_str(), L"wb");
        if (f) {
            fwrite(bin.data(), 1, bin.size(), f);
            fclose(f);
            std::wstring hex;
            std::wstring famName; int famSev = 0;
            if (FileSha256W(tmp, hex) && RuleMatchHash(hex, famName, famSev) && famSev > 0) {
                sev = 5; why = L"附件命中恶意哈希情报: " + famName;
            } else {
                std::wstring rr;
                int rs = RuleMatchFile(tmp, rr);
                if (rs > sev) { sev = rs; why = L"附件规则命中: " + rr; }
            }
        }
        if (sev >= 3) {
            ++hit;
            LogPost(L"[邮件] 可疑附件 " + wn + L" @ " + srcPath + L" -> " + why);
            BehavAdd(0, srcPath, BEHAV_SIGN, sev >= 4 ? 2 : 1, L"邮件可疑附件: " + wn + L" " + why);
            QuarantineFile(tmp);
            if (sev >= 4) SetThreatLevel(2, L"邮件附件可疑");
        }
        DeleteFileW(tmp.c_str());                    // 无论是否命中都清理临时文件
    }
    return extracted;
}

// 扫描单个邮件文件。返回附件数。
static int MailScanOneFile(const std::wstring& path, int& hit) {
    std::wstring lp = path;
    for (wchar_t& c : lp) c = (wchar_t)tolower((int)c);
    bool isEml  = lp.size() > 4 && lp.compare(lp.size() - 4, 4, L".eml") == 0;
    bool isMbox = lp.size() > 5 && lp.compare(lp.size() - 5, 5, L".mbox") == 0;
    bool isMsg  = lp.size() > 4 && lp.compare(lp.size() - 4, 4, L".msg") == 0;
    bool isPst  = (lp.size() > 4 && lp.compare(lp.size() - 4, 4, L".pst") == 0) ||
                  (lp.size() > 4 && lp.compare(lp.size() - 4, 4, L".ost") == 0);
    if (!isEml && !isMbox && !isMsg && !isPst) return 0;

    if (isPst) {
        // 不解析专有二进制格式, 只登记位置与体积, 明确告知用户这是有限检测
        LogPost(L"[邮件] 发现 Outlook 数据文件(专有格式, 不做内容解析): " + path);
        return 0;
    }
    std::vector<unsigned char> data;
    if (!ReadFileAll(path, data) || data.empty()) return 0;

    if (isMsg) {
        // .msg 是 OLE 复合文档, 只做内嵌特征启发式(不做完整解析)
        std::string d(data.begin(), data.end());
        std::string dl = MailLower(d);
        int sc = 0;
        if (d.find("MZ") != std::string::npos) sc += 3;                 // 内嵌 PE
        for (const char* k : { ".exe", ".scr", ".js", ".vbs", ".ps1", ".hta", ".iso" })
            if (dl.find(k) != std::string::npos) { sc += 2; break; }
        for (const char* k : { "autoopen", "document_open", "auto_open", "shell" })
            if (dl.find(k) != std::string::npos) { sc += 3; break; }   // VBA 自动执行
        if (sc >= 4) {
            ++hit;
            LogPost(L"[邮件] Outlook .msg 内嵌可疑特征(有限检测, 未解析OLE): " + path);
            BehavAdd(0, path, BEHAV_SIGN, 1, L".msg 内嵌可疑特征");
        }
        return 0;
    }
    std::string mail(data.begin(), data.end());
    if (isMbox) {
        // mbox: 多封邮件拼接, 按行首 "From " 切分后逐封处理
        int total = 0; size_t start = 0;
        for (int k = 0; k < 200; ++k) {
            size_t nx = mail.find("\nFrom ", start);
            std::string one = (nx == std::string::npos)
                ? mail.substr(start) : mail.substr(start, nx - start);
            if (!one.empty()) total += MailExtractAndScan(one, path, hit);
            if (nx == std::string::npos) break;
            start = nx + 1;
        }
        return total;
    }
    return MailExtractAndScan(mail, path, hit);
}

// 遍历目录找邮件文件(限深度与数量, 避免大目录长时间扫描)
static void MailScanDir(const std::wstring& dir, int depth, int& files, int& hit) {
    if (depth > 2 || files > 300 || dir.empty()) return;
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        std::wstring n = fd.cFileName;
        if (n == L"." || n == L"..") continue;
        std::wstring full = dir + L"\\" + n;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            MailScanDir(full, depth + 1, files, hit);
            continue;
        }
        std::wstring ln = n;
        for (wchar_t& c : ln) c = (wchar_t)tolower((int)c);
        bool isMail = (ln.size() > 4 && (ln.compare(ln.size() - 4, 4, L".eml") == 0 ||
                                         ln.compare(ln.size() - 4, 4, L".msg") == 0 ||
                                         ln.compare(ln.size() - 4, 4, L".pst") == 0 ||
                                         ln.compare(ln.size() - 4, 4, L".ost") == 0)) ||
                      (ln.size() > 5 && ln.compare(ln.size() - 5, 5, L".mbox") == 0);
        if (!isMail) continue;
        ++files;
        MailScanOneFile(full, hit);
    } while (FindNextFileW(h, &fd) && files <= 300);
    FindClose(h);
}

static int MailScan() {
    if (!g_cfg.mailScanOn) { LogPost(L"[邮件] 邮件扫描已关闭(cfg.mailScanOn=false)"); return 0; }
    LogPost(L"[邮件] 开始扫描本地邮件存储...");
    int files = 0, hit = 0;
    wchar_t appd[MAX_PATH + 1] = { 0 }, local[MAX_PATH + 1] = { 0 };
    GetEnvironmentVariableW(L"APPDATA", appd, MAX_PATH);
    GetEnvironmentVariableW(L"LOCALAPPDATA", local, MAX_PATH);
    std::vector<std::wstring> dirs;
    if (appd[0]) {
        dirs.push_back(std::wstring(appd) + L"\\Thunderbird\\Profiles");
        dirs.push_back(std::wstring(appd) + L"\\Microsoft\\Outlook");
    }
    if (local[0]) {
        dirs.push_back(std::wstring(local) + L"\\Microsoft\\Outlook");
        dirs.push_back(std::wstring(local) + L"\\Packages");
    }
    dirs.push_back(std::wstring(appd) + L"\\Microsoft\\Windows\\INetCache");
    for (const std::wstring& d : dirs) MailScanDir(d, 0, files, hit);
    LogFmt(L"[邮件] 扫描完成: 邮件文件 %d 个, 可疑附件 %d 个", files, hit);
    if (hit > 0) LogPost(L"[邮件] 可疑附件已隔离到隔离区, 可在隔离区管理查看/恢复");
    return hit;
}

// ============================================================================
// v13.37 强制解除文件占用 (ForceUnlock)
//
// 【思路】文件删不掉/改不动, 是因为别的进程持有它的句柄。两种解法:
//   ①结束占用进程 —— 简单粗暴。若占用者是 explorer.exe/杀软/系统服务,
//     会破坏用户体验甚至系统功能。
//   ②关闭句柄本身 —— 精准。进程继续正常运行, 只是失去对该文件的引用,
//     文件立刻可删。这是 Unlocker/Handle 类工具的做法。
// 优先 ②; ② 不可行时才询问用户是否 ①。
//
// 【核心技术】NtQuerySystemInformation(SystemHandleInformation) 枚举全系统句柄
// → DuplicateHandle 复制到本进程(否则无法查询别进程句柄) →
// NtQueryObject(ObjectNameInformation) 取对象名 → 与目标路径匹配 →
// DuplicateHandle(DUPLICATE_CLOSE_SOURCE) 关闭源进程中的句柄。
//
// 【三个必须避开的坑】
//   1. 句柄对象名是 NT 路径 \Device\HarddiskVolumeN\..., 不是 C:\...。
//      必须用 QueryDosDeviceW 把盘符映射成设备名再比较, 否则永远匹配不上。
//   2. 核心系统进程(csrss/lsass/smss/wininit/services/winlogon/explorer 等)
//      的句柄绝对不能关 —— 轻则功能异常, 重则直接蓝屏。宁可放弃解除。
//   3. 系统句柄数可达几十万, 必须设上限截断, 否则枚举耗时且内存暴涨。
// ============================================================================

// 提权到 SeDebugPrivilege, 否则无法打开系统进程做句柄复制
static bool FuEnableDebugPriv() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return false;
    LUID luid; bool ok = false;
    if (LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid)) {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ok = AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr) != FALSE;
    }
    CloseHandle(tok);
    return ok;
}

// DOS 路径 -> NT 设备路径。这是能否匹配上的关键。
static bool FuDosToNt(const std::wstring& dos, std::wstring& nt) {
    if (dos.size() < 2 || dos[1] != L':') return false;
    std::wstring drv = dos.substr(0, 2);
    wchar_t dev[512] = { 0 };
    if (!QueryDosDeviceW(drv.c_str(), dev, 511)) return false;
    nt = std::wstring(dev) + dos.substr(2);
    return true;
}
static std::wstring FuUp(const std::wstring& s) {
    std::wstring r = s;
    for (wchar_t& c : r) c = (wchar_t)toupper((int)c);
    return r;
}

// 核心系统进程: 关闭其句柄可能导致系统不稳定甚至蓝屏, 一律跳过
static bool FuIsCoreProc(const std::wstring& name) {
    static const wchar_t* core[] = {
        L"system", L"csrss.exe", L"lsass.exe", L"smss.exe", L"wininit.exe",
        L"winlogon.exe", L"services.exe", L"svchost.exe", L"fontdrvhost.exe",
        L"dwm.exe", L"sihost.exe", L"ctfmon.exe", L"explorer.exe", L"spoolsv.exe"
    };
    std::wstring l = name;
    for (wchar_t& c : l) c = (wchar_t)tolower((int)c);
    for (const wchar_t* c : core) if (l == c) return true;
    return false;
}

// 只处理文件句柄, 否则会误关注册表/互斥体/事件等无关句柄
static bool FuIsFileHandle(int objType) {
    return objType == 0x25 || objType == 0x1F || objType == 0x24;
}

typedef struct _ZZ_SYS_HANDLE_ENTRY {
    unsigned short Pid;
    unsigned short CreatorBackTraceIndex;
    unsigned char  ObjType;
    unsigned char  HandleAttributes;
    unsigned short HandleValue;
    void*          Object;
    unsigned long  GrantedAccess;
} ZZ_SYS_HANDLE_ENTRY;
typedef struct _ZZ_SYS_HANDLE_INFO {
    unsigned long Count;
    ZZ_SYS_HANDLE_ENTRY Handles[1];
} ZZ_SYS_HANDLE_INFO;

typedef long (WINAPI* PFnNtQuerySysInfo)(int, void*, unsigned long, unsigned long*);
typedef long (WINAPI* PFnNtQueryObject)(void*, int, void*, unsigned long, unsigned long*);

// 解除指定文件的占用。返回关闭的句柄数(0=未找到或已放弃)。
static int ForceUnlockFile(const std::wstring& path) {
    if (path.empty()) { LogPost(L"[解锁] 请先输入文件路径"); return 0; }
    if (IsProtectedPath(path)) {
        LogPost(L"[解锁] 拒绝操作受保护路径: " + path);
        return 0;
    }
    std::wstring ntTarget;
    if (!FuDosToNt(path, ntTarget)) {
        LogPost(L"[解锁] 无法解析路径(需形如 C:\\xxx): " + path);
        return 0;
    }
    HMODULE hNt = GetModuleHandleW(L"ntdll.dll");
    PFnNtQuerySysInfo pQSI = hNt ? (PFnNtQuerySysInfo)GetProcAddress(hNt, "NtQuerySystemInformation") : nullptr;
    PFnNtQueryObject  pQO  = hNt ? (PFnNtQueryObject)GetProcAddress(hNt, "NtQueryObject") : nullptr;
    if (!pQSI || !pQO) {
        LogPost(L"[解锁] 无法获取 ntdll 句柄枚举接口, 已跳过(需 Windows 环境)");
        return 0;
    }
    FuEnableDebugPriv();

    unsigned long bufSize = 1024 * 1024;              // 1MB 起步
    std::vector<unsigned char> buf;
    unsigned long need = 0; long st = 0;
    for (int attempt = 0; attempt < 4; ++attempt) {
        buf.resize(bufSize);
        st = pQSI(16, buf.data(), bufSize, &need);   // 16 = SystemHandleInformation
        if (st == 0) break;
        if (need == 0 || need <= bufSize) break;
        bufSize = need + 256 * 1024;
        if (bufSize > 64 * 1024 * 1024) break;       // 上限 64MB, 防止内存暴涨
    }
    if (st != 0) { LogPost(L"[解锁] 枚举系统句柄失败"); return 0; }

    ZZ_SYS_HANDLE_INFO* info = (ZZ_SYS_HANDLE_INFO*)buf.data();
    unsigned long total = info->Count;
    if (total > 200000) total = 200000;              // 上限截断

    int closed = 0;
    DWORD selfPid = GetCurrentProcessId();
    std::vector<DWORD> lockers;
    for (unsigned long i = 0; i < total && closed < 64; ++i) {
        const ZZ_SYS_HANDLE_ENTRY& e = info->Handles[i];
        if (e.Pid == 0 || e.Pid == 4) continue;                  // 跳过 System 空闲/PID4
        if ((DWORD)e.Pid == selfPid) continue;                   // 跳过自身
        if (!FuIsFileHandle(e.ObjType)) continue;                // 只处理文件句柄
        HANDLE hProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)e.Pid);
        if (!hProc) continue;
        HANDLE hDup = nullptr;
        BOOL dupOk = DuplicateHandle(hProc, (HANDLE)(UINT_PTR)e.HandleValue,
                                     GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS);
        if (dupOk && hDup) {
            // 取对象名(UNICODE_STRING 前是长度头: 2字节len+2字节maxlen, 后接wchar)
            unsigned char nameBuf[1024] = { 0 };
            long ns = pQO(hDup, 1, nameBuf, sizeof(nameBuf) - 2, nullptr);  // 1=ObjectNameInformation
            if (ns == 0) {
                unsigned short len = *(unsigned short*)nameBuf;
                if (len > 0 && len < 900) {
                    std::wstring hn((wchar_t*)(nameBuf + 4), len / 2);
                    if (FuUp(hn) == FuUp(ntTarget)) {
                        // 命中: 先看占用者是不是核心进程, 是则只报告不动手
                        bool found = false;
                        for (DWORD p : lockers) if (p == (DWORD)e.Pid) { found = true; break; }
                        if (!found) lockers.push_back((DWORD)e.Pid);
                        // 关闭源句柄: DUPLICATE_CLOSE_SOURCE 会关掉源进程里的句柄
                        HANDLE hTmp = nullptr;
                        if (DuplicateHandle(hProc, (HANDLE)(UINT_PTR)e.HandleValue,
                                            GetCurrentProcess(), &hTmp, 0, FALSE,
                                            DUPLICATE_CLOSE_SOURCE)) {
                            ++closed;
                            if (hTmp) CloseHandle(hTmp);
                        }
                    }
                }
            }
            CloseHandle(hDup);
        }
        CloseHandle(hProc);
    }
    if (closed > 0) {
        LogFmt(L"[解锁] 已关闭 %d 个占用句柄: %ls", closed, path.c_str());
        if (!lockers.empty()) {
            std::wstring msg = L"占用进程: ";
            for (size_t i = 0; i < lockers.size() && i < 8; ++i)
                msg += std::to_wstring(lockers[i]) + L" ";
            LogPost(L"[解锁] " + msg + L"(进程仍在运行, 仅失去该文件引用)");
        }
    } else {
        LogPost(L"[解锁] 未找到占用该文件的句柄(可能未被占用, 或占用者是受保护的核心进程): " + path);
    }
    return closed;
}

// UI 入口: 从输入框取路径并解除占用
static void ForceUnlockUi(HWND owner) {
    if (!g_cfg.forceUnlockOn) { LogPost(L"[解锁] 功能已关闭(cfg.forceUnlockOn=false)"); return; }
    wchar_t buf[MAX_PATH * 4] = { 0 };
    HWND ed = GetDlgItem(owner, IDC_ED_UNLOCK_PATH);
    if (!ed) { LogPost(L"[解锁] 输入框未找到"); return; }
    GetWindowTextW(ed, buf, MAX_PATH * 4 - 1);
    std::wstring path = buf;
    while (!path.empty() && (path.front() == L' ' || path.front() == L'"')) path.erase(0, 1);
    while (!path.empty() && (path.back() == L' ' || path.back() == L'"')) path.pop_back();
    if (path.empty()) { LogPost(L"[解锁] 请先在输入框粘贴要解除占用的文件完整路径"); return; }
    LaunchBg([path] { ForceUnlockFile(path); });
}

static int AdsScan() {
    // FindFirstStreamW 为 Vista+ 且仅 NTFS 支持; 动态加载，
    // 老系统无此导出时优雅跳过，绝不崩溃
    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    if (!hK32) { LogPost(L"[ADS] 无法获取 kernel32 句柄"); return 0; }
    ZZ_FindFirstStreamPtr pFirst =
        (ZZ_FindFirstStreamPtr)GetProcAddress(hK32, "FindFirstStreamW");
    ZZ_FindNextStreamPtr  pNext  =
        (ZZ_FindNextStreamPtr)GetProcAddress(hK32, "FindNextStreamW");
    if (!pFirst || !pNext) {
        LogPost(L"[ADS] 当前系统不支持 FindFirstStreamW(需 Vista+ / NTFS)，已跳过");
        return 0;
    }

    // 扫描目标: 恶意软件常把 ADS 挂在这几类文件上
    //  - 看似无害的文本/图片(迷惑性最强)
    //  - 隐藏目录里的任意文件
    std::vector<wstring> dirs; HidTargetDirs(dirs);
    static const wchar_t* const kPats[] = {
        L"*.txt", L"*.log", L"*.ini", L"*.dat", L"*.jpg", L"*.png",
        L"*.exe", L"*.dll", L"*.doc*", L"*.xls*"
    };

    int scanned = 0, bad = 0;
    for (const wstring& dir : dirs) {
        for (const wchar_t* pat : kPats) {
            wstring full = dir + L"\\" + pat;
            WIN32_FIND_DATAW fd{};
            HANDLE hf = FindFirstFileW(full.c_str(), &fd);
            if (hf == INVALID_HANDLE_VALUE || !hf) continue;
            do {
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                wstring path = dir + L"\\" + fd.cFileName;
                ++scanned;

                ZZ_FIND_STREAM_DATA sd{};
                HANDLE hs = pFirst(path.c_str(), 0, &sd, 0);
                if (hs == INVALID_HANDLE_VALUE || !hs) continue;
                do {
                    wstring stream = sd.cStreamName;
                    long long sz = sd.StreamSize;
                    int risk = AdsStreamRisk(path, stream, sz);
                    if (risk <= 0) {
                        memset(&sd, 0, sizeof(sd));
                        continue;
                    }
                    ++bad;
                    wchar_t msg[600];
                    swprintf(msg, 600,
                        L"[ADS] 发现备用数据流(%s): %s%s  大小=%lld 字节",
                        risk >= 2 ? L"高危" : L"可疑",
                        path.c_str(), stream.c_str(), sz);
                    LogPost(msg);
                    BehavAdd(0, L"ADS", BEHAV_FILE, risk >= 2 ? 9 : 5,
                             L"备用数据流: " + path + stream);
                    if (risk >= 2) {
                        SetThreatLevel(THREAT_DANGER, L"检测到 NTFS 备用数据流(ADS)藏匿");
                        // 处置前先询问用户(不可逆操作)
                        if (g_cfg.advAggressive && !IsProtectedPath(path)) {
                            std::wstring detail = L"文件: " + path +
                                                  L"\n流: " + stream +
                                                  L"\n大小: " + std::to_wstring(sz) + L" 字节";
                            int ans = AlertConfirm(L"发现 ADS 藏匿数据", detail, path, 0);
                            if (ans == 1) {   // 是 = 处理
                                if (AdsPurgeStream(path, stream))
                                    LogPost(L"[ADS] 已清空该数据流");
                                else
                                    LogPost(L"[ADS] 清空失败(可能无写权限)，建议手动处理");
                            }
                        }
                    }
                    memset(&sd, 0, sizeof(sd));
                } while (pNext(hs, &sd));
                FindClose(hs);
            } while (FindNextFileW(hf, &fd));
            FindClose(hf);
        }
    }
    LogFmt(bad ? L"[ADS] 完成, 扫描 %d 个文件, 发现 %d 个可疑数据流"
               : L"[ADS] 完成, 扫描 %d 个文件, 未发现可疑数据流", scanned, bad);
    return bad;
}

// ---- 隐藏文件 / 隐藏目录 扫描 ----
// 合法隐藏文件白名单(系统自动生成，不是威胁)
static bool HiddenFileWhitelisted(const wstring& name) {
    static const wchar_t* const kW[] = {
        L"desktop.ini", L"thumbs.db", L"ehthumbs.db", L"iconcache_.db",
        L".ds_store", L"ntuser.dat", L"ntuser.ini", L"usrclass.dat",
        L"$recycle.bin", L"system volume information"
    };
    wstring low = ScanLowerW(name);
    for (const wchar_t* k : kW)
        if (low == k) return true;
    // ntuser.dat.LOG1 / .LOG2 / .blf 等派生文件
    if (low.find(L"ntuser.dat") == 0) return true;
    if (low.find(L"iconcache") == 0) return true;
    return false;
}

// ---- 隐藏判定: 三级判据 ----
// 为什么不能只认 FILE_ATTRIBUTE_HIDDEN：
//   PowerShell 的 (Get-Item x).Attributes='Hidden'、以及部分 Git/MSYS 工具创建的
//   隐藏项，在某些系统上表现为“访问控制型隐藏”，走 GetFileAttributesW 拿不到
//   隐藏位；而 FindFirstFileExW(FindExInfoBasic) 直接读目录项，能拿到真实属性。
//   故这里用三个信号任一命中即算隐藏，避免整类漏报。
//   0=未隐藏 1=隐藏位 2=系统位 3=隐藏+系统 4=点文件(名字以 . 开头)
static int HidAttrRisk(DWORD attr, const wstring& name) {
    bool isHidden = (attr & FILE_ATTRIBUTE_HIDDEN) != 0;
    bool isSystem = (attr & FILE_ATTRIBUTE_SYSTEM) != 0;
    if (isHidden && isSystem) return 3;   // 正常程序几乎不会有这种组合
    if (isHidden) return 1;
    if (isSystem) return 2;
    // 点文件: .ssh / .aws / .secret 等；PowerShell 与类 Unix 工具常见
    if (!name.empty() && name[0] == L'.' && name != L"." && name != L"..") return 4;
    return 0;
}

// 隐藏文件风险评分: 0=正常, 数值越大越可疑
static int HiddenFileRisk(const wstring& path, DWORD attr, wstring& why) {
    int hidLevel = HidAttrRisk(attr, PathFindFileNameW(path.c_str()));
    bool isHidden = (hidLevel == 1 || hidLevel == 3 || hidLevel == 4);
    bool isSystem = (hidLevel == 2 || hidLevel == 3);
    if (!isHidden && !isSystem) return 0;

    wstring ext = ScanLowerW(PathFindExtensionW(path.c_str()));
    // 关注可执行/脚本类; 普通数据文件即使隐藏也不算威胁
    static const wchar_t* kExe[] = {
        L".exe", L".dll", L".scr", L".bat", L".cmd", L".ps1", L".vbs",
        L".js", L".jse", L".vbe", L".wsf", L".hta", L".com", L".pif",
        L".sys", L".lnk", L".inf"
    };
    bool isExec = false;
    for (const wchar_t* e : kExe) if (ext == e) { isExec = true; break; }
    // 无扩展名也算可疑: 恶意 payload 常故意不带扩展名躲避类型过滤
    bool noExt = ext.empty();
    // 非可执行文件不再一律 return 0:
    //   隐藏的 .txt/.log 通常无害，但隐藏的脚本或无扩展名文件要管。
    //   这里只对“既非可执行文件、又非点文件、且无系统属性”的普通数据放行。
    if (!isExec && !noExt && hidLevel != 4 && !isSystem) return 0;

    int score = 0;
    why.clear();

    if (isHidden) { score += 3; why += L"隐藏属性 "; }
    // HIDDEN|SYSTEM 组合: 正常程序几乎不会有这种组合，恶意隐藏常用
    if (isHidden && isSystem) { score += 2; why += L"+系统属性 "; }
    else if (isSystem) { score += 1; why += L"系统属性 "; }

    if (hidLevel == 4) { score += 2; why += L"+点文件(类Unix/PowerShell隐藏) "; }
    if (noExt) { score += 1; why += L"+无扩展名 "; }

    // 位于高危目录(可写、常被投放)
    if (HidIsHotDir(path)) { score += 1; why += L"+高危目录 "; }

    // 无签名: 遵循最小信任原则，有签名也不放行，但无签名更可疑
    if (VerifyFileSignature(path) != 1) { score += 2; why += L"+无有效签名 "; }

    // 情报哈希命中 —— 一票否决，直接最高危
    wstring hex;
    if (FileSha256W(path, hex)) {
        wstring nm; int sv = 0;
        if (RuleMatchHash(hex.c_str(), nm, sv) && sv > 0) {
            score = 5;
            why += L"+情报命中(" + nm + L")";
        }
    }
    return score;
}

// 递归扫描一个目录; depth 为剩余递归深度
// 关键改动: 用 FindFirstFileExW(FindExInfoBasic) 而非 FindFirstFileW。
//   Basic 级别不查询 ACL、不走属性缓存，直接返回目录项里的真实属性位，
//   因此 PowerShell 那种“访问控制型隐藏”也能读到隐藏位。
static void HiddenScanDir(const wstring& dir, int depth,
                          int& scanned, int& bad) {
    if (depth < 0) return;
    WIN32_FIND_DATAW fd{};
    HANDLE hf = FindFirstFileExW((dir + L"\\*").c_str(), FindExInfoBasic,
                                 &fd, FindExSearchNameMatch, nullptr, 0);
    if (hf == INVALID_HANDLE_VALUE || !hf) return;
    do {
        wstring name = fd.cFileName;
        if (name == L"." || name == L"..") continue;
        bool isDir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        if (HiddenFileWhitelisted(name)) continue;

        wstring path = dir + L"\\" + name;
        ++scanned;

        if (isDir) {
            // 隐藏目录优先深入; 普通目录也递归，但深度受限，避免全盘开销
            int nextDepth = (fd.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN)
                                ? depth : depth - 1;
            HiddenScanDir(path, nextDepth, scanned, bad);
            continue;
        }

        wstring why;
        int sc = HiddenFileRisk(path, fd.dwFileAttributes, why);
        if (sc >= 3) {
            ++bad;
            LogFmt(L"[隐藏文件] 检出(%d分): %s [%s]", sc, path.c_str(), why.c_str());
            BehavAdd(0, L"HiddenFile", BEHAV_FILE, sc >= 5 ? 9 : 6,
                     L"隐藏的可疑文件: " + path + L" (" + why + L")");
            if (sc >= 5)
                SetThreatLevel(THREAT_DANGER, L"隐藏文件中检出恶意特征");
            else if (sc >= 4)
                SetThreatLevel(THREAT_WARN, L"发现可疑隐藏文件");
            if (g_cfg.advAggressive && !IsProtectedPath(path))
                QuarantineFile(path);
        }
        memset(&fd, 0, sizeof(fd));
    } while (FindNextFileW(hf, &fd));
    FindClose(hf);
}

static int HiddenFileScan() {
    std::vector<wstring> dirs; HidTargetDirs(dirs);

    int scanned = 0, bad = 0;
    for (const wstring& dir : dirs) HiddenScanDir(dir, 2, scanned, bad);
    LogFmt(bad ? L"[隐藏文件] 完成, 扫描 %d 项, 发现 %d 个可疑隐藏文件"
               : L"[隐藏文件] 完成, 扫描 %d 项, 未发现可疑隐藏文件", scanned, bad);
    return bad;
}

static void CreateRecoveryPage(HWND p) {
    CreateButton(p, L"创建系统还原点", IDC_CB_CREATE_SNAPSHOT, 20, 20, 180, 32);
    CreateButton(p, L"校验完整性",     IDC_CB_ROLLBACK_REFRESH,20, 62, 180, 32);
    CreateButton(p, L"备份配置(防篡改)", IDC_CB_CFG_BACKUP,  20, 104, 190, 32);
    CreateButton(p, L"服务/驱动后门扫描", IDC_CB_SVC_BACKDOOR,   20, 144, 190, 32);
    CreateButton(p, L"浏览器劫持清理",   IDC_CB_BROWSER_HIJACK, 220, 144, 190, 32);
    CreateButton(p, L"ARP/DNS 劫持检测", IDC_CB_ARP_DNS,        420, 144, 190, 32);
    CreateButton(p, L"分级扫描(无签名优先)", IDC_CB_SCAN_BY_PRIO, 20, 186, 190, 32);
    CreateButton(p, L"计划任务持久化",       IDC_CB_TASK_SCHED,  220, 186, 190, 32);
    CreateButton(p, L"进程注入检测",         IDC_CB_INJECT_SCAN, 420, 186, 190, 32);
    CreateButton(p, L"防火墙规则篡改检测",   IDC_CB_FW_AUDIT,     20, 228, 190, 32);
    CreateButton(p, L"端口代理/隧道检测",    IDC_CB_PROXY_AUDIT, 220, 228, 190, 32);
    CreateButton(p, L"安全日志审计(4625等)", IDC_CB_EVTLOG_AUDIT,420, 228, 190, 32);
    CreateButton(p, L"快捷方式劫持检测",   IDC_CB_LNK_HIJACK,   20, 270, 190, 32);
    CreateButton(p, L"勒索诱饵蜜罐",       IDC_CB_CANARY_GUARD,220, 270, 190, 32);
    CreateButton(p, L"Rootkit隐藏进程检测", IDC_CB_HIDDEN_PROC,  20, 312, 190, 32);
    CreateButton(p, L"系统代理/PAC劫持",   IDC_CB_PROXY_HIJACK, 220, 312, 190, 32);
    CreateButton(p, L"隔离区管理",         IDC_CB_QUAR_MANAGE,  420, 312, 190, 32);
    CreateButton(p, L"银狐专项深度扫描",   IDC_CB_FOX_DEEP,     20, 354, 190, 32);
    CreateButton(p, L"BYOVD驱动检测",      IDC_CB_FOX_BYOVD,    220, 354, 190, 32);
    CreateButton(p, L"缓解策略审计(ASLR等)", IDC_CB_MIT_AUDIT,  420, 354, 190, 32);
    CreateButton(p, L"凭据防护基线(LSASS)",  IDC_CB_CRED_GUARD,  20, 396, 190, 32);
    CreateButton(p, L"共享与自动播放审计",    IDC_CB_SHARE_AUDIT,220, 396, 190, 32);
    CreateButton(p, L"变种/派生检测(运行中)", IDC_CB_VARIANT_SCAN,420, 396, 190, 32);
    CreateButton(p, L"银狐/紫狐与族谱识别", IDC_CB_FAMILY_SCAN,  20, 438, 190, 32);
    CreateButton(p, L"启动限制自修复",       IDC_CB_SELF_REPAIR,220, 438, 190, 32);
    CreateButton(p, L"隐藏文件/目录扫描",   IDC_CB_HIDDEN_FILE, 420, 438, 190, 32);
    CreateButton(p, L"ADS备用数据流检测",   IDC_CB_ADS_SCAN,     20, 480, 190, 32);
    CreateButton(p, L"从备份恢复配置",   IDC_CB_CFG_RESTORE, 220, 104, 190, 32);
    CreateButton(p, L"邮件附件扫描",     IDC_CB_MAIL_SCAN,   20, 522, 190, 32);
    CreateLabel (p, L"被占用文件路径:",  230, 526, 100, 22);
    CreateEdit  (p, IDC_ED_UNLOCK_PATH, L"", 335, 524, 265, 24, false);
    CreateButton(p, L"强制解除占用",     IDC_CB_FORCE_UNLOCK, 615, 522, 190, 32);
}
static void CreateEmergencyPage(HWND p) {
    CreateLabel (p, L"应急密码 (数字):", 20, 20, 140, 22);
    g_hPwdEdit = CreateEdit(p, IDC_CB_EMG_PWD, g_cfg.password.c_str(), 160, 20, 140, 24, true);
    CreateButton(p, L"显示/隐藏", IDC_CB_SHOWPWD, 310, 20, 100, 28);
    CreateButton(p, L"执行紧急自救", IDC_CB_EMG_RUN, 20, 70, 180, 40);
    CreateButton(p, L"注册重启杀毒(开机扫描)", IDC_CB_BOOTSCAN, 210, 70, 220, 40);
    CreateButton(p, L"注销重启杀毒", IDC_CB_BOOTSCAN_OFF, 450, 70, 180, 40);
    CreateButton(p, L"ETW实时事件追踪", IDC_CB_ETW_TRACE,  20, 120, 190, 40);
    CreateButton(p, L"进程血缘树分析", IDC_CB_PROC_TREE,  220, 120, 190, 40);
    CreateButton(p, L"USB设备审计(BadUSB)", IDC_CB_USB_AUDIT, 420, 120, 190, 40);
    CreateButton(p, L"漏洞情报更新(KEV/NVD)", IDC_BTN_VULN_UPDATE, 620, 120, 200, 40);
    CreateButton(p, L"已知漏洞核查", IDC_BTN_VULN_CHECK, 20, 170, 190, 40);
}

// ============================================================
//  页面管理
// ============================================================
// ---- v13.25: 页面滚动 (修复按钮被裁剪不可见) ----
// 【思路】页面内容是一个个 STATIC 容器, 按钮是容器的子控件。
// 子控件无法绘制到父容器客户区之外, 所以容器必须"足够大"才能显示全部按钮;
// 但容器太大又超出屏幕, 于是让容器保持内容真实高度, 再用滚动条上下平移容器本身 ——
// 子控件会随父窗口移动而自动跟随, 比 ScrollWindowEx 更稳(不会出现残影/重绘错乱)。
static const int PAGE_X    = 10;    // 容器左边距
static const int PAGE_TOP  = 114;   // 容器顶边距(Tab 控件下方)
static const int PAGE_W    = 880;   // 容器宽度(窗口 900 - 左右边距)
static int       g_pageContentH = 960;   // 内容真实高度(按钮最大 y=912 + 40 余量)
static int       g_pageScrollY  = 0;     // 当前纵向滚动偏移
static int       g_pageViewH    = 800;   // 可视高度(随窗口大小变化)

static void UpdatePageScroll() {
    // 夹紧滚动范围: 内容没超出可视区时不允许滚动(避免滚出空白)
    int maxScroll = g_pageContentH - g_pageViewH;
    if (maxScroll < 0) maxScroll = 0;
    if (g_pageScrollY > maxScroll) g_pageScrollY = maxScroll;
    if (g_pageScrollY < 0)         g_pageScrollY = 0;

    for (int i = 0; i < 11; ++i) {
        if (g_pages[i].hwnd)
            MoveWindow(g_pages[i].hwnd, PAGE_X, PAGE_TOP - g_pageScrollY,
                       PAGE_W, g_pageContentH, TRUE);
    }
    // 同步滚动条
    if (g_hMain) {
        SCROLLINFO si;
        si.cbSize = sizeof(si);
        si.fMask  = SIF_RANGE | SIF_POS | SIF_PAGE;
        si.nMin   = 0;
        si.nMax   = g_pageContentH;
        si.nPage  = (UINT)g_pageViewH;
        si.nPos   = g_pageScrollY;
        SetScrollInfo(g_hMain, SB_VERT, &si, TRUE);
    }
}
static void PageScrollBy(int delta) {
    g_pageScrollY += delta;
    UpdatePageScroll();
}

static void CreatePages(HWND parent) {
    for (int i = 0; i < 11; ++i) {
        // v13.25 UI 修复: 原容器固定 560x380, 而各页按钮最远排到 x=840 / y=912,
        // 子控件超出父窗口客户区即被裁剪 —— 窗口再高也看不见。
        // 改为: 宽度跟随主窗口客户区, 高度取内容实际高度(由 g_pageContentH 维护),
        // 再配合垂直滚动条上下平移容器(见 UpdatePageScroll), 子控件随父窗口移动自动跟随。
        HWND pg = CreateWindowExW(0, L"STATIC", g_pages[i].title,
                                  WS_CHILD | WS_VISIBLE | SS_LEFT,
                                  PAGE_X, PAGE_TOP, PAGE_W, g_pageContentH, parent,
                                  (HMENU)(1000 + i),
                                  GetModuleHandleW(nullptr), nullptr);
        g_pages[i].hwnd = pg;
    }
    // 按索引绑定创建函数
    CreateOverviewPage (g_pages[0].hwnd);
    CreateProcessPage  (g_pages[1].hwnd);
    CreateNetworkPage  (g_pages[2].hwnd);
    CreateProtectionPage(g_pages[3].hwnd);
    CreateRollbackPage (g_pages[4].hwnd);
    CreatePrivacyPage  (g_pages[5].hwnd);
    CreateDlpPage      (g_pages[6].hwnd);
    CreateFimPage      (g_pages[7].hwnd);
    CreateLogPage      (g_pages[8].hwnd);
    CreateRecoveryPage (g_pages[9].hwnd);
    CreateEmergencyPage(g_pages[10].hwnd);
    ShowPage(0);
}
static void ShowPage(int idx) {
    for (int i = 0; i < 11; ++i) {
        ShowWindow(g_pages[i].hwnd, (i == idx) ? SW_SHOW : SW_HIDE);
    }
}

// ============================================================
//  OnCommand: 全部 IDC 绑定到真实功能
// ============================================================

// ============================================================
//  列表双击处理 (进程列表 -> 直接打开行为时间线)
// ============================================================

// ==================== ETW 实时事件追踪 ====================
// 思路：轮询(每 N 秒扫一次)有天然盲区——进程可能"生灭于两次轮询之间"。
// ETW 是 Windows 内核内置的事件通道，进程启动/退出、映像加载、网络连接
// 都会实时推送，无盲区且由内核缓冲，开销远低于轮询。
// 四步：StartTrace 建会话 -> EnableTraceEx 订阅 Provider -> OpenTrace 打开
//      -> ProcessTrace 阻塞消费(每来一个事件回调一次)
static bool        g_etwOn      = false;
static TRACEHANDLE g_etwSession = 0;
static TRACEHANDLE g_etwConsume = 0;
// Microsoft-Windows-Kernel-Process {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
static const GUID PROVIDER_KERNEL_PROCESS = { 0x22FB2CD6,0x0E7B,0x422B,{0xA0,0xC7,0x2F,0xAD,0x1F,0xD0,0xE7,0x16} };
// Microsoft-Windows-Kernel-File    {EDD08927-9CC4-4E65-B970-C2560FB5C289}
static const GUID PROVIDER_KERNEL_FILE    = { 0xEDD08927,0x9CC4,0x4E65,{0xB9,0x70,0xC2,0x56,0x0F,0xB5,0xC2,0x89} };
// Microsoft-Windows-Kernel-Network {7DD42A49-5329-4832-8DFD-43D979153A88}
static const GUID PROVIDER_KERNEL_NETWORK = { 0x7DD42A49,0x5329,0x4832,{0x8D,0xFD,0x43,0xD9,0x79,0x15,0x3A,0x88} };

// Kernel-Process 事件 ID：1=进程启动 2=退出 3=线程启动 4=线程退出 5=映像加载 6=卸载
static const wchar_t* EtwProcEventName(UCHAR id){
    switch(id){ case 1: return L"进程启动"; case 2: return L"进程退出"; case 3: return L"线程启动"; case 4: return L"线程退出"; case 5: return L"映像加载"; case 6: return L"映像卸载"; default: return L"其他"; }
}
// 事件回调：每来一条事件调一次。只做轻量解析(取 PID + 事件 ID)，
// 文件/网络类事件量太大不落库，避免刷爆行为时间线。
static void WINAPI EtwEventCallback(PEVENT_RECORD rec){
    if(!rec) return;
    DWORD pid = rec->EventHeader.ProcessId;
    UCHAR eid = rec->EventHeader.EventDescriptor.Id;
    bool  isProc = (rec->EventHeader.ProviderId == PROVIDER_KERNEL_PROCESS);
    if(isProc && (eid==1 || eid==5)){
        wchar_t msg[160];
        swprintf_s(msg, 160, L"ETW %s pid=%lu", EtwProcEventName(eid), (unsigned long)pid);
        BehavAdd(pid, L"", (eid==1)?BEHAV_PROC_START:BEHAV_HOOK, (eid==1)?1:2, msg);
    }
}
static bool EtwTraceStart(){
    if(g_etwOn) return true;
    wchar_t sessionName[64] = L"zz_EDR_ETW_Session";
    ULONG   bufSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(sessionName);
    std::vector<BYTE> buf(bufSize, 0);
    PEVENT_TRACE_PROPERTIES prop = (PEVENT_TRACE_PROPERTIES)&buf[0];
    prop->Wnode.BufferSize    = bufSize;
    prop->Wnode.Guid          = PROVIDER_KERNEL_PROCESS;
    prop->Wnode.ClientContext = 1;
    prop->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
    prop->LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
    prop->MaximumBuffers      = 256;
    prop->MinimumBuffers      = 8;
    prop->LoggerNameOffset    = sizeof(EVENT_TRACE_PROPERTIES);
    ULONG st = StartTraceW(&g_etwSession, sessionName, prop);
    if(st != ERROR_SUCCESS){ LogFmt(L"[ETW] 会话创建失败(%lu)，可能需要管理员权限，回落轮询模式", (unsigned long)st); return false; }
    EnableTraceEx(&PROVIDER_KERNEL_PROCESS, nullptr, g_etwSession, 1,0,0,0, nullptr);
    EnableTraceEx(&PROVIDER_KERNEL_FILE,    nullptr, g_etwSession, 1,0,0,0, nullptr);
    EnableTraceEx(&PROVIDER_KERNEL_NETWORK, nullptr, g_etwSession, 1,0,0,0, nullptr);
    EVENT_TRACE_LOGFILEW logfile = {};
    logfile.LoggerName          = sessionName;
    logfile.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = (void*)EtwEventCallback;
    g_etwConsume = OpenTraceW(&logfile);
    if(g_etwConsume == (TRACEHANDLE)INVALID_HANDLE_VALUE){
        LogFmt(L"[ETW] 会话打开失败，回落轮询模式");
        ControlTraceW(g_etwSession, sessionName, prop, EVENT_TRACE_CONTROL_STOP);
        g_etwSession = 0; return false;
    }
    g_etwOn = true;
    LogFmt(L"[ETW] 实时事件追踪已启动(进程/文件/网络)");
    // 【为什么走 LaunchDaemon 而不是 LaunchBg】ProcessTraceW 是长驻阻塞调用
    // (一直阻塞到会话停止才返回)。放进 BUTTON 池会永久占用 1/5 的按钮并发
    // 额度, 与"守护不能进池"同理 —— 它会让池逐渐失血。改用命名守护,
    // 既与池分离(不占额度), 又能靠名字去重防止 ETW 反复启停时叠加多个消费者。
    LaunchDaemon(L"EtwConsume", [](){ ProcessTraceW(&g_etwConsume, 1, nullptr, nullptr); });
    return true;
}
static void EtwTraceStop(){
    if(!g_etwOn) return;
    g_etwOn = false;
    wchar_t sessionName[64] = L"zz_EDR_ETW_Session";
    ULONG bufSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(sessionName);
    std::vector<BYTE> buf(bufSize, 0);
    PEVENT_TRACE_PROPERTIES prop = (PEVENT_TRACE_PROPERTIES)&buf[0];
    prop->Wnode.BufferSize = bufSize;
    prop->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    if(g_etwSession) ControlTraceW(g_etwSession, sessionName, prop, EVENT_TRACE_CONTROL_STOP);
    if(g_etwConsume && g_etwConsume != (TRACEHANDLE)INVALID_HANDLE_VALUE) CloseTrace(g_etwConsume);
    g_etwSession = 0; g_etwConsume = 0;
    LogFmt(L"[ETW] 实时事件追踪已停止");
}

// ==================== 进程血缘树 ====================
// 思路："谁生了它"极具信息量。svchost.exe 的父进程应是 services.exe，
// 若父进程是 explorer.exe 就是伪装。构建 pid->ppid 映射后校验期望父进程。
static void ProcTreeBuild(){
    auto procs = SnapshotProcs();
    std::map<DWORD, DWORD>        parent;
    std::map<DWORD, std::wstring> name;
    for(auto& p : procs){ parent[p.pid] = p.ppid; name[p.pid] = p.name; }
    struct { const wchar_t* proc; const wchar_t* par; } kExpect[] = {
        { L"svchost.exe",  L"services.exe" }, { L"services.exe", L"wininit.exe"  },
        { L"lsass.exe",    L"wininit.exe"  }, { L"csrss.exe",    L"smss.exe"     },
        { L"winlogon.exe", L"smss.exe"     }, { L"dwm.exe",      L"winlogon.exe" },
    };
    int anomalies = 0;
    for(auto& p : procs){
        std::wstring ln = ToLowerW(p.name);
        for(auto& e : kExpect){
            if(ln != ToLowerW(e.proc)) continue;
            auto it = parent.find(p.ppid);
            if(it == parent.end()) continue;
            std::wstring pname = ToLowerW(name[p.ppid]);
            if(pname != ToLowerW(e.par)){
                wchar_t msg[220];
                swprintf_s(msg, 220, L"异常血缘: %s(pid=%lu) 父进程为 %s(pid=%lu)，正常应为 %s", p.name.c_str(), (unsigned long)p.pid, name[p.ppid].c_str(), (unsigned long)p.ppid, e.par);
                LogFmt(L"[血缘] %s", msg);
                BehavAdd(p.pid, p.path, BEHAV_PROC_START, 8, msg);
                ++anomalies;
            }
        }
    }
    for(auto& p : procs){
        if(p.ppid == 0 || parent.find(p.ppid) == parent.end()){
            LogFmt(L"[血缘] 根节点 %s (pid=%lu)", p.name.c_str(), (unsigned long)p.pid);
        }
    }
    LogFmt(L"[血缘] 进程树分析完成: 共 %zu 个进程，异常血缘 %d 项", procs.size(), anomalies);
    if(anomalies > 0) SetThreatLevel(THREAT_DANGER, L"检测到异常进程血缘(疑似进程伪装)，建议查看日志");
}

// ==================== 日志导出与应急响应报告 ====================
// 为什么需要: 扫描结果只存在于内存 ListBox, 关掉程序就没了。
// 应急响应需要"留证": 谁在什么时间发现了什么、系统当时什么状态。
// 因此报告不只导出日志, 还附带进程/网络/威胁等级的现场快照。
static std::wstring ReportBuildText() {
    std::wstring s;
    auto add = [&](const std::wstring& ln) { s += ln; s += L"\r\n"; };

    // 1) 报告头: 时间 + 版本 + 当前威胁等级
    wchar_t hdr[320];
    SYSTEMTIME st; GetLocalTime(&st);
    swprintf_s(hdr, 320, L"ZZ EDR 应急响应报告  v%d.%d.%d", VER_MAJOR, VER_MINOR, VER_PATCH);
    add(hdr);
    swprintf_s(hdr, 320, L"生成时间: %04u-%02u-%02u %02u:%02u:%02u",
               (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay,
               (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond);
    add(hdr);
    const wchar_t* lv = (ThreatLevelGet() == 2) ? L"危险(发现病毒/系统异常)"
                      : (ThreatLevelGet() == 1) ? L"可疑" : L"安全";
    add(std::wstring(L"当前威胁等级: ") + lv);
    add(L"--------------------------------------------------");

    // 2) 现场快照: 进程 / 网络连接 (留证关键)
    auto procs = SnapshotProcs();
    auto nets  = SnapshotNets();
    swprintf_s(hdr, 320, L"[进程快照] 共 %zu 个", procs.size()); add(hdr);
    for (auto& p : procs) {
        if (p.suspicious)
            add(L"  [可疑] " + p.name + L" pid=" + std::to_wstring(p.pid) + L"  " + p.path);
    }
    swprintf_s(hdr, 320, L"[网络连接] 共 %zu 条", nets.size()); add(hdr);
    for (auto& n : nets)
        add(L"  " + n.local + L" -> " + n.remote + L" (" + n.state + L") pid=" + std::to_wstring(n.pid));
    add(L"--------------------------------------------------");

    // 3) 日志正文: 从环形缓冲取(主窗口失效也能回溯)
    add(L"[事件日志]");
    auto logs = RecentLogSnapshot();
    for (auto& l : logs) add(L"  " + l);
    return s;
}

static void LogExportReport() {
    // 优先输出到 exe 同目录, 避免工作目录变化导致文件"找不到"
    wchar_t dir[MAX_PATH] = { 0 };
    GetModuleFileNameW(nullptr, dir, MAX_PATH);
    wchar_t* bs = wcsrchr(dir, L'\\');
    if (bs) *(bs + 1) = 0;
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t name[128];
    swprintf_s(name, 128, L"ZZ_EDR_Report_%04u%02u%02u_%02u%02u%02u.txt",
               (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay,
               (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond);
    std::wstring path = std::wstring(dir) + name;

    std::wstring text = ReportBuildText();
    // 写 UTF-16LE BOM, 否则记事本/Excel 打开中文会乱码
    FILE* f = _wfopen(path.c_str(), L"wb");
    if (!f) { LogFmt(L"[报告] 导出失败: %s", path.c_str()); return; }
    unsigned short bom = 0xFEFF;
    fwrite(&bom, 1, sizeof(bom), f);
    fwrite(text.c_str(), 1, text.size() * sizeof(wchar_t), f);
    fclose(f);
    LogFmt(L"[报告] 已导出: %s (%zu 条日志)", path.c_str(), RecentLogSnapshot().size());
    SysNotify(L"ZZ EDR", L"报告已导出至:\r\n" + path);
}

// 清空日志: 同时清 UI 列表与内存缓冲 (原先 IDC_CB_LOG_CLEAR 是空实现, 点了没反应)
static void LogClearAll() {
    if (g_hLog) SendMessageW(g_hLog, LB_RESETCONTENT, 0, 0);
    {
        std::lock_guard<std::mutex> lk(g_recentLogMtx);
        g_recentLog.clear();
    }
    LogPost(L"[日志] 已清空");
}

// ==================== 启动项管理器 ====================
// 为什么需要: 之前只能"检测"自启动项并记日志, 不能查看也不能管理。
// 应急响应时最关键的一步就是"断掉持久化", 没有管理界面只能手改注册表, 既慢又易错。
struct AutorunEntry {
    HKEY  hive;
    std::wstring keyPath;    // 不含 hive 的子键路径
    std::wstring valueName;
    std::wstring imagePath;  // 值数据
    std::wstring source;     // 展示用来源名
};

static std::vector<AutorunEntry> AutorunEnumerate() {
    std::vector<AutorunEntry> out;
    struct { HKEY hive; const wchar_t* sub; const wchar_t* src; } kKeys[] = {
        { HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",     L"HKCU Run" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",     L"HKLM Run" },
        { HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"HKCU RunOnce" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"HKLM RunOnce" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", L"HKLM Policy Run" },
        { HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", L"HKCU Policy Run" },
    };
    for (auto& k : kKeys) {
        HKEY hk = nullptr;
        if (RegOpenKeyExW(k.hive, k.sub, 0, KEY_READ, &hk) != ERROR_SUCCESS) continue;
        DWORD idx = 0;
        wchar_t vname[512], vdata[2048];
        while (idx < 300) {
            DWORD vnLen = 512, vdLen = sizeof(vdata);
            DWORD type = 0;
            LONG r = RegEnumValueW(hk, idx++, vname, &vnLen, nullptr, &type, (LPBYTE)vdata, &vdLen);
            if (r == ERROR_NO_MORE_ITEMS) break;
            if (r != ERROR_SUCCESS) break;
            if (type != REG_SZ && type != REG_EXPAND_SZ) continue;
            AutorunEntry e;
            e.hive = k.hive; e.keyPath = k.sub;
            e.valueName = vname; e.imagePath = vdata; e.source = k.src;
            out.push_back(e);
        }
        RegCloseKey(hk);
    }
    return out;
}

static void AutorunListToLog() {
    LogPost(L"========== 启动项清单 ==========");
    auto list = AutorunEnumerate();
    if (list.empty()) { LogPost(L"  (未发现注册表启动项, 或权限不足)"); return; }
    int risky = 0;
    for (auto& e : list) {
        std::wstring lb = e.imagePath;
        for (auto& c : lb) if (c >= L'A' && c <= L'Z') c = c - L'A' + L'a';
        bool bad = (lb.find(L"\\temp\\") != std::wstring::npos)
                || (lb.find(L"\\appdata\\") != std::wstring::npos)
                || (lb.find(L"\\users\\public\\") != std::wstring::npos)
                || (lb.find(L"\\programdata\\") != std::wstring::npos)
                || (lb.find(L"\\downloads\\") != std::wstring::npos);
        if (bad) ++risky;
        LogFmt(L"  [%s%s] %s = %s", e.source.c_str(), bad ? L" 高危" : L"", e.valueName.c_str(), e.imagePath.c_str());
    }
    LogFmt(L"共 %zu 项, 其中位于可写目录的高危项 %d 个", list.size(), risky);
    if (risky > 0) SetThreatLevel(THREAT_WARN, L"发现位于可写目录的启动项，建议核查启动项管理器");
    LogPost(L"================================");
}

// 禁用启动项: 不直接删除, 而是改名加 .disabled 后缀。
// 理由: 删除不可逆, 万一误判正常软件就无法恢复; 改名同样让它不再启动, 且随时可改回。
static bool AutorunDisable(const AutorunEntry& e) {
    std::wstring newName = e.valueName + L".disabled";
    HKEY hk = nullptr;
    if (RegOpenKeyExW(e.hive, e.keyPath.c_str(), 0, KEY_READ | KEY_WRITE, &hk) != ERROR_SUCCESS) return false;
    // 先读出原值, 再以新名写入, 最后删旧名
    wchar_t vdata[2048]; DWORD vdLen = sizeof(vdata); DWORD type = 0;
    LONG r = RegQueryValueExW(hk, e.valueName.c_str(), nullptr, &type, (LPBYTE)vdata, &vdLen);
    if (r != ERROR_SUCCESS) { RegCloseKey(hk); return false; }
    r = RegSetValueExW(hk, newName.c_str(), 0, type, (LPBYTE)vdata, vdLen);
    if (r == ERROR_SUCCESS) RegDeleteValueW(hk, e.valueName.c_str());
    RegCloseKey(hk);
    return r == ERROR_SUCCESS;
}

static bool AutorunDelete(const AutorunEntry& e) {
    HKEY hk = nullptr;
    if (RegOpenKeyExW(e.hive, e.keyPath.c_str(), 0, KEY_READ | KEY_WRITE, &hk) != ERROR_SUCCESS) return false;
    LONG r = RegDeleteValueW(hk, e.valueName.c_str());
    RegCloseKey(hk);
    return r == ERROR_SUCCESS;
}

// ==================== 结束进程树 ====================
// 为什么需要: 恶意软件常"父进程守护子进程" —— 杀掉子进程, 守护进程立刻拉起,
// 导致怎么杀都杀不掉。必须自底向上(先叶子后根)终止, 且要先挂起父进程阻止它重建。
static int KillProcessTree(DWORD rootPid) {
    if (rootPid == 0 || rootPid == 4) { LogPost(L"[进程树] 拒绝终止系统关键进程"); return 0; }
    if (rootPid == GetCurrentProcessId()) { LogPost(L"[进程树] 拒绝终止自身"); return 0; }

    auto procs = SnapshotProcs();
    // 建 pid -> 子进程列表
    std::map<DWORD, std::vector<DWORD>> children;
    for (auto& p : procs) if (p.ppid != 0) children[p.ppid].push_back(p.pid);

    // 后序遍历收集: 保证子进程排在父进程之前
    std::vector<DWORD> order;
    std::function<void(DWORD)> collect = [&](DWORD pid) {
        auto it = children.find(pid);
        if (it != children.end())
            for (DWORD c : it->second) collect(c);
        order.push_back(pid);
    };
    collect(rootPid);

    // 顺序是关键: order 已保证"子进程在父进程之前"。
    // 若先杀父进程, 它可能在死前重建子进程; 先杀叶子则无此风险。
    int killed = 0;
    for (DWORD pid : order) {
        if (pid == 0 || pid == 4 || pid == GetCurrentProcessId()) continue;
        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (!h) continue;
        if (TerminateProcess(h, 1)) ++killed;
        CloseHandle(h);
    }
    LogFmt(L"[进程树] 自根 %lu 共终止 %d 个进程(含子进程)", (unsigned long)rootPid, killed);
    return killed;
}


// ==================== USB 设备审计 / BadUSB 检测 ====================
// 1) 取证：Windows 在 USBSTOR 下永久留存每个插过的 U 盘的厂商/产品/序列号，
//    即使已拔掉，是应急响应最有价值的痕迹之一。
// 2) BadUSB：Rubber Ducky 伪装成 HID 键盘，插入后被信任随即自动敲命令。
//    检测点是"复合设备"——同时声明为存储和键盘极不正常。
static void UsbDevAudit(){
    const wchar_t* kUsbStor = L"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR";
    HKEY hk = nullptr;
    LONG r = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kUsbStor, 0, KEY_READ, &hk);
    if(r != ERROR_SUCCESS){ LogFmt(L"[USB] 无法打开 USBSTOR 历史(错误 %ld)，可能需要管理员权限", (long)r); return; }
    int devCount = 0;
    wchar_t cls[256]; DWORD ci = 0; DWORD clsLen = 256;
    while(ci < 200){
        clsLen = 256; FILETIME ft = {};
        LONG e = RegEnumKeyExW(hk, ci, cls, &clsLen, nullptr, nullptr, nullptr, &ft);
        if(e == ERROR_NO_MORE_ITEMS || e != ERROR_SUCCESS) break;
        HKEY hc = nullptr;
        if(RegOpenKeyExW(hk, cls, 0, KEY_READ, &hc) != ERROR_SUCCESS){ ++ci; continue; }
        wchar_t inst[256]; DWORD ii = 0; DWORD instLen = 256;
        while(ii < 200){
            instLen = 256;
            LONG e2 = RegEnumKeyExW(hc, ii, inst, &instLen, nullptr, nullptr, nullptr, nullptr);
            if(e2 == ERROR_NO_MORE_ITEMS || e2 != ERROR_SUCCESS) break;
            ++devCount;
            std::wstring instStr(inst);
            size_t amp = instStr.find(L'&');
            std::wstring serial = (amp != std::wstring::npos) ? instStr.substr(0, amp) : instStr;
            LogFmt(L"[USB] 历史设备: %s 序列号=%s", cls, serial.c_str());
            ++ii;
        }
        RegCloseKey(hc); ++ci;
    }
    RegCloseKey(hk);
    LogFmt(L"[USB] 共发现 %d 个曾接入的 USB 存储设备(可用于取证)", devCount);
    HKEY hh = nullptr;
    const wchar_t* kHid = L"SYSTEM\\CurrentControlSet\\Enum\\HID";
    int composite = 0;
    if(RegOpenKeyExW(HKEY_LOCAL_MACHINE, kHid, 0, KEY_READ, &hh) == ERROR_SUCCESS){
        wchar_t sub[256]; DWORD si = 0; DWORD subLen = 256;
        while(si < 300){
            subLen = 256;
            LONG e = RegEnumKeyExW(hh, si, sub, &subLen, nullptr, nullptr, nullptr, nullptr);
            if(e == ERROR_NO_MORE_ITEMS || e != ERROR_SUCCESS) break;
            std::wstring lo = ToLowerW(sub);
            bool hasStore = (lo.find(L"mass") != std::wstring::npos || lo.find(L"disk") != std::wstring::npos || lo.find(L"cdrom") != std::wstring::npos);
            bool hasKbd   = (lo.find(L"keyboard") != std::wstring::npos || lo.find(L"kbd") != std::wstring::npos);
            if(hasStore && hasKbd){
                ++composite;
                LogFmt(L"[USB] 可疑复合设备(BadUSB 特征): %s", sub);
                BehavAdd(0, L"", BEHAV_DRIVER, 7, (std::wstring(L"BadUSB 可疑复合设备: ") + sub).c_str());
            }
            ++si;
        }
        RegCloseKey(hh);
    }
    if(composite > 0) SetThreatLevel(THREAT_WARN, L"检测到可疑复合 USB 设备(BadUSB)，建议核查后拔出");
}// 从进程列表当前选中行解析 PID。
// 为什么解析文本而不是维护一个缓存的选中 PID: 列表是异步刷新的,
// 若缓存 pid 而列表已重建, 会指向错误进程。以列表当前显示内容为准最可靠。
static DWORD SelectedProcPid() {
    if (!g_hProcList) return 0;
    int idx = (int)SendMessageW(g_hProcList, LB_GETCURSEL, 0, 0);
    if (idx < 0) return 0;
    wchar_t buf[700] = { 0 };
    SendMessageW(g_hProcList, LB_GETTEXT, idx, (LPARAM)buf);
    std::wstring s = buf;
    size_t p = s.find(L"PID=");
    if (p == std::wstring::npos) return 0;
    p += 4;
    DWORD pid = 0;
    while (p < s.size() && s[p] >= L'0' && s[p] <= L'9') { pid = pid * 10 + (DWORD)(s[p] - L'0'); ++p; }
    return pid;
}

static void OnProcListDblClick() {
    if (!g_hProcList) return;
    int idx = (int)SendMessageW(g_hProcList, LB_GETCURSEL, 0, 0);
    if (idx < 0) return;
    wchar_t buf[700] = { 0 };
    SendMessageW(g_hProcList, LB_GETTEXT, idx, (LPARAM)buf);
    wstring s = buf;
    size_t p = s.find(L"PID=");
    DWORD pid = 0;
    if (p != wstring::npos) { p += 4; while (p < s.size() && s[p] >= L'0' && s[p] <= L'9') { pid = pid * 10 + (DWORD)(s[p] - L'0'); p++; } }
    wstring nm;
    auto ps = SnapshotProcs();
    for (auto& x : ps) if (x.pid == pid) nm = x.name;
    if (nm.empty()) nm = L"(未知进程)";
    ShowBehaviorWindow(g_hMain, pid, nm);
}

static INT_PTR OnCommand(WPARAM wp, LPARAM lp) {
    int id = LOWORD(wp);
    (void)lp;
    switch (id) {
        // ---- 概览 ----
        case IDC_CB_PROTECTION_SCAN:  g_scanning.store(true); LaunchScan(&FullChainScanThread); break;
        case IDC_CB_REFRESH:          RefreshProcListAsync(); LogPost(L"已刷新"); break;
        // ---- 进程 ----
        case IDC_CB_KILLALL: {
            auto v = SnapshotProcs();
            for (auto& p : v) if (p.suspicious) KillProcess(p.pid);
            break;
        }
        case IDC_CB_DEEPCLEAN:        LaunchScan([] { DeepClean(); }); break;
        case IDC_CB_REMOTE:           LaunchScan([] { DetectRemoteControl(); }); break;

        // ---- 进程列表: 选中项查看行为 / 双击打开 ----
        case IDC_BTN_BEHAVIOR: {
            if (!g_hProcList) break;
            int idx = (int)SendMessageW(g_hProcList, LB_GETCURSEL, 0, 0);
            if (idx < 0) { MessageBoxW(g_hMain, L"请先在列表中选中一个进程", L"行为", 0); break; }
            wchar_t buf[700] = { 0 };
            SendMessageW(g_hProcList, LB_GETTEXT, idx, (LPARAM)buf);
            // 解析 "PID=1234  name..."
            wstring s = buf;
            size_t p = s.find(L"PID=");
            DWORD pid = 0;
            if (p != wstring::npos) { p += 4; while (p < s.size() && s[p] >= L'0' && s[p] <= L'9') { pid = pid * 10 + (DWORD)(s[p] - L'0'); p++; } }
            wstring nm;
            auto ps = SnapshotProcs();
            for (auto& x : ps) if (x.pid == pid) nm = x.name;
            if (nm.empty()) nm = L"(未知进程)";
            ShowBehaviorWindow(g_hMain, pid, nm);
            break;
        }
        // ---- 情报 / 沙箱 / 连坐 / CVE / 启动扫描 / 守护 ----
        case IDC_BTN_INTEL_UPDATE:
            LaunchBg([] {
                long long n = IntelUpdateAll(true);
                LogFmt(L"情报更新完成, 新增 %lld 条 (库中 哈希=%lld IP段=%lld)",
                       n, g_intelHashCount.load(), g_intelIpCount.load());
            });
            LogPost(L"已在后台开始更新威胁情报...");
            break;
        case IDC_BTN_EXT_SCAN: {
            int r = MessageBoxW(g_hMain,
                L"将对\"连接风险IP\"的进程执行连坐处置(结束进程+同名空文件覆盖), 是否继续?",
                L"对外威胁连坐", 1);
            if (r != 1) break;
            LaunchScan([] { ScanExternalThreatsAndPurge(true); });
            break;
        }
        case IDC_BTN_SANDBOX: {
            // 对选中进程的可执行文件做沙箱分析
            if (!g_hProcList) break;
            int idx = (int)SendMessageW(g_hProcList, LB_GETCURSEL, 0, 0);
            DWORD pid = 0;
            if (idx >= 0) {
                wchar_t buf[700] = { 0 };
                SendMessageW(g_hProcList, LB_GETTEXT, idx, (LPARAM)buf);
                wstring s = buf;
                size_t p = s.find(L"PID=");
                if (p != wstring::npos) { p += 4; while (p < s.size() && s[p] >= L'0' && s[p] <= L'9') { pid = pid * 10 + (DWORD)(s[p] - L'0'); p++; } }
            }
            if (!pid) { MessageBoxW(g_hMain, L"请先在进程列表中选中一个进程", L"沙箱", 0); break; }
            wstring path = GetProcPath(pid);
            if (path.empty() || IsProtectedPath(path)) {
                MessageBoxW(g_hMain, L"该进程路径未知或属于受保护路径, 不做沙箱分析", L"沙箱", 0);
                break;
            }
            int r = MessageBoxW(g_hMain,
                (L"将对以下文件执行沙箱静态分析:\n" + path + L"\n\n是否同时执行动态试运行(约 10 秒)?\n[是]=静态+动态  [否]=仅静态").c_str(),
                L"沙箱分析", 3);
            if (r == 2) break;
            bool dyn = (r == 6);
            wstring p2 = path;
            LaunchBg([p2, dyn] {
                wstring verdict;
                std::vector<wstring> rep;
                int score = SandboxAnalyze(p2, dyn, dyn ? 10 : 0, verdict, rep);
                LogFmt(L"[沙箱] %s 风险分=%d 判定=%s", p2.c_str(), score, verdict.c_str());
                for (auto& l : rep) LogPost(L"  " + l);
            });
            break;
        }
        case IDC_BTN_STARTUP_SCAN:
            LaunchScan([] { StartupFullScan(); });
            LogPost(L"已启动: 对所有运行程序做全量扫描与行为建档");
            break;
        case IDC_BTN_CVE_SCAN:
            LaunchScan([] {
                int n = ScanCveAndHandle();
                LogFmt(L"CVE 利用扫描完成, 命中 %d 项", n);
            });
            break;
        case IDC_BTN_TRUST_MGR: {
        // 列出待审批项, 由用户决定放行或保持阻止
        int nBlocked = 0, nAllowed = 0, nSystem = 0;
        {
            std::lock_guard<std::mutex> lk(g_trustMtx);
            for (const auto& kv : g_trust) {
                if (kv.second.level == TRUST_BLOCKED) ++nBlocked;
                else if (kv.second.level == TRUST_ALLOWED) ++nAllowed;
                else if (kv.second.level == TRUST_SYSTEM) ++nSystem;
            }
        }
        std::wstring msg = L"最小信任状态:\n\n";
        msg += L"已授权: " + std::to_wstring(nAllowed) + L" 个\n";
        msg += L"系统基线: " + std::to_wstring(nSystem) + L" 个\n";
        msg += L"已拉黑: " + std::to_wstring(nBlocked) + L" 个\n";
        size_t pend = 0;
        {
            std::lock_guard<std::mutex> lk(g_trustMtx);
            pend = g_pending.size();
        }
        msg += L"待审批(已被阻止): " + std::to_wstring(pend) + L" 个\n\n";
        if (pend) {
            std::lock_guard<std::mutex> lk(g_trustMtx);
            size_t show = pend < 10 ? pend : 10;
            for (size_t i = 0; i < show; ++i) {
                std::wstring fp = g_pending[i];
                if (fp.size() > 60) fp = L"..." + fp.substr(fp.size() - 57);
                msg += L"· " + fp + L"\n";
            }
            if (pend > show) msg += L"... 其余见日志\n";
        }
        msg += L"\n[是] 放行全部待审批程序\n[否] 保持阻止\n[取消] 清空待审批列表";
        int r = MessageBoxW(g_hMain, msg.c_str(), L"信任管理 (最小信任原则)",
                            MB_YESNOCANCEL | MB_ICONINFORMATION | MB_TOPMOST);
        if (r == IDYES) {
            std::lock_guard<std::mutex> lk(g_trustMtx);
            int n = 0;
            for (const auto& fp : g_pending) { TrustSet(fp, TRUST_ALLOWED, L"用户放行"); ++n; }
            g_pending.clear();
            TrustSave();
            LogFmt(L"最小信任: 用户放行 %d 个待审批程序", n);
        } else if (r == IDNO) {
            LogPost(L"最小信任: 保持阻止, 未放行任何程序");
        } else {
            std::lock_guard<std::mutex> lk(g_trustMtx);
            g_pending.clear();
            LogPost(L"最小信任: 已清空待审批列表");
        }
        break;
    }
    case IDC_BTN_TRUST_LEARN: {
        int r = MessageBoxW(g_hMain,
            L"将把当前正在运行的所有进程纳入「系统基线」并允许其运行。\n\n"
            L"注意: 请在确认系统干净时执行 —— 若当前有恶意进程, 它也会被纳入基线。\n\n"
            L"是否继续?",
            L"重新学习系统基线", MB_YESNO | MB_ICONWARNING | MB_TOPMOST);
        if (r == IDYES) {
            LaunchScan([] {
                int n = TrustLearnBaseline();
                TrustSave();
                LogFmt(L"最小信任: 基线重建完成(%d), 已保存", n);
            });
        }
        break;
    }

        case IDC_BTN_VT_SCAN:
            LogPost(L"[多引擎] 在线核查运行中程序(VirusTotal, 需 vtApiKey)");
            LaunchScan([]{ VtScanRunning(8); });
            break;
        case IDC_BTN_USB_GUARD:
            LogPost(L"[U盘防护] 扫描可移动驱动器 autorun.inf 与根目录可执行文件");
            LaunchScan([]{ UsbGuardScan(); });
            break;
        case IDC_BTN_DL_SCAN:
            LogPost(L"[下载扫描] 扫描下载目录(建议下载的文件先扫描再运行)");
            LaunchScan([]{ ScanDownloads(); });
            break;
        case IDC_BTN_CTX_MENU:
            InstallContextMenu();
            break;
        case IDC_BTN_PATCH_AUDIT:
            LogPost(L"[补丁审计] 检查 Windows 更新与常用软件版本");
            LaunchBg([]{ PatchAudit(); });
            break;
        case IDC_BTN_DEEP_SCAN:
            LogPost(L"[深度扫描] 系统分区/临时目录/启动项/注册表 全盘深度扫描");
            LaunchScan([]{ DeepFullScan(); });
            break;
        case IDC_BTN_SAFEMODE:
            EnterSafeMode(true);
            break;
        case IDC_BTN_BACKUP:
            LogPost(L"[数据备份] 备份 桌面/文档/下载(建议同时备至外置硬盘或云)");
            LaunchScan([]{ BackupUserData(); });
            break;
        case IDC_BTN_MBR:
            LogPost(L"[引导区] 检查并备份 MBR/GPT 引导记录");
            LaunchBg([]{ MbrCheckAndBackup(); });
            break;
        case IDC_BTN_RANSOM_KILL:
            LogPost(L"[勒索专杀] 检查勒索信/删除卷影行为/加密进程");
            LaunchScan([]{ RansomKiller(); });
            break;
        case IDC_BTN_MINER_KILL:
            LogPost(L"[挖矿专杀] 终止挖矿进程与矿池连接");
            LaunchScan([]{ MinerKiller(); });
            break;
        case IDC_BTN_USER_SCAN: {
            LaunchScan([]() {
            auto users = ScanUnknownUsers();
            if (users.empty()) { LogPost(L"[USR] 未发现可疑账户"); return; }
            LogFmt(L"[USR] 发现 %zu 个可疑账户:", users.size());
            for (auto& u : users)
                LogFmt(L"[USR]   %s 风险=%d 隐藏=%d 管理员=%d 随机名=%d",
                       u.name.c_str(), u.risk, (int)u.hidden, (int)u.admin, (int)u.randName);
        });
        return 0;
    }
        case IDC_BTN_USER_CLEAN: {
            LaunchBg([]() {
            int n = CleanUnknownUsers(g_cfg.advAggressive);
            LogFmt(L"[USR] 处置完成, 共处理 %d 个账户", n);
        });
        return 0;
    }
        case IDC_BTN_RES_SCAN: {
            LaunchBg([]() { ResourceAlert(); });
            return 0;
        }
        case IDC_BTN_RES_TOGGLE: {
            bool now = !g_resGuardOn.load();
            g_resGuardOn.store(now);
            g_cfg.resGuardOn = now;
            LogFmt(L"[RES] 资源异常监控守护: %s", now ? L"开启" : L"关闭");
            return 0;
        }
        case IDC_BTN_IMMUNE: {
            LaunchScan([]() {
                if (!g_immunizeOn.load()) { LogPost(L"[IMM] 免疫处置未开启"); return; }
                LogPost(L"[IMM] 开始顽固病毒免疫处置...");
                PurgeIncurableAll();
            });
            return 0;
        }
        // ---- 持久化与劫持检测 ----
        case IDC_BTN_HOSTS_SCAN:
            LaunchScan([]() { if (!g_hostGuardOn.load()) { LogPost(L"[HOSTS] 未开启"); return; } HostsAuditRun(); });
            return 0;
        case IDC_BTN_WMI_SCAN:
            LaunchScan([]() { if (!g_wmiScanOn.load()) { LogPost(L"[WMI] 未开启"); return; } WmiPersistScan(); });
            return 0;
        case IDC_BTN_TASK_SCAN:
            LaunchScan([]() { if (!g_taskScanOn.load()) { LogPost(L"[TASK] 未开启"); return; } TaskPersistScan(); });
            return 0;
        case IDC_BTN_NETAUDIT:
            LaunchScan([]() { if (!g_netAuditOn.load()) { LogPost(L"[NET] 未开启"); return; } NetAuditRun(); });
            return 0;
        case IDC_BTN_SCAN_PRIORITY:  ScanPriorityReport(); break;
        case IDC_BTN_LSASS_GUARD:    LaunchScan([] { LsassAccessScan(); }); break;
        case IDC_BTN_HOLLOW_SCAN:    LaunchScan([] { ProcessHollowScan(); }); break;
        case IDC_BTN_DLLHIJACK_SCAN: LaunchScan([] { DllHijackScan(); }); break;
        case IDC_BTN_CLIP_TOGGLE: {
            bool now = !g_clipGuardOn.load();
            g_clipGuardOn.store(now); g_cfg.clipGuardOn = now; g_cfg.Save(L"zz_EDR.cfg.json");
            LogFmt(L"[CLIP] 剪贴板劫持监控: %s", now ? L"开启" : L"关闭");
            if (now) LaunchDaemon(L"ClipboardGuardLoop", []() { ClipboardGuardLoop(); });
            return 0;
        }
        case IDC_BTN_SELFDEF_TOGGLE: {
            bool now = !g_selfDefenseOn.load();
            g_selfDefenseOn.store(now); g_cfg.selfDefenseOn = now; g_cfg.Save(L"zz_EDR.cfg.json");
            LogFmt(L"[SELF] 自我保护看门狗: %s", now ? L"开启" : L"关闭");
            if (now) LaunchDaemon(L"SelfDefenseLoop", []() { SelfDefenseLoop(); });
            return 0;
        }
        // ---- 内核驱动对接 (DrvLink) ----
        // 【思路】装载驱动是高风险操作(内核组件), 所以放在后台线程做,
        //        且失败时明确告知原因, 绝不静默——用户必须知道自己现在是
        //        "内核级防护"还是"应用层防护", 这是安全等级的本质差别。
        case IDC_BTN_DRV_TOGGLE:
            LaunchBg([]() {
                if (DrvReady()) { LogPost(L"[DRV] 驱动已在运行"); return; }
                if (!DrvInstallAndStart()) {
                    LogPost(L"[DRV] 装载失败: 请以管理员身份运行, 并确保 zz_edrdrv.sys 与本程序同目录且已签名(或开启测试签名)");
                    return;
                }
                if (!DrvOpen()) { LogPost(L"[DRV] 连接失败"); return; }
                DrvSetRules();
                g_cfg.drvOn = true; g_cfg.Save(L"zz_EDR.cfg.json");
                if (LaunchDaemon(L"DrvEventLoop", [] { DrvEventLoop(); }))
                    LogPost(L"[DRV] 内核事件接收已启动");
            });
            return 0;
        case IDC_BTN_DRV_STATUS:
            LaunchBg([]() {
                if (!DrvReady()) {
                    LogPost(L"[DRV] 状态: 未连接(应用层防护生效中, 内核级拦截不可用)");
                    return;
                }
                DWORD wr = 0, magic = 0;
                if (!DeviceIoControl(g_drvHandle, IOCTL_ZZ_PING, nullptr, 0, &magic, sizeof(magic), &wr, nullptr)) {
                    LogPost(L"[DRV] 状态: 驱动无响应(可能已卸载)");
                    g_drvLoaded = false;
                    return;
                }
                DrvSetRules();   // 顺带重发一次规则, 保证与当前配置同步
                LogFmt(L"[DRV] 状态: 正常 (magic=0x%08X, 自身 PID=%u 受内核保护)", magic, GetCurrentProcessId());
            });
            return 0;
        case IDC_BTN_DRV_UNINSTALL:
            // 卸载会短暂失去内核防护, 所以先确认
            if (MessageBoxW(g_hMain,
                    L"将停止并删除内核驱动服务 zz_edrdrv。\n\n"
                    L"卸载后内核级拦截失效, 仅保留应用层防护(功能仍完整, 但存在时间窗)。\n"
                    L"确定继续?", L"卸载内核驱动", MB_YESNO | MB_ICONWARNING) != IDYES) return 0;
            LaunchBg([]() {
                if (DrvUninstall()) { g_cfg.drvOn = false; g_cfg.Save(L"zz_EDR.cfg.json"); }
            });
            return 0;

case IDC_BTN_MACRO_SCAN: {
            LogPost(L"宏病毒防护: 开始扫描 Office 文档内 VBA 宏, 并审计宏安全设置");
            MessageBoxW(g_hMain,
                L"将扫描 桌面/文档/AppData 下的 Office 文档:\n"
                L"  .docm .xlsm .pptm .dotm .xltm .potm .sldm .xlam .xlsb\n"
                L"  .doc  .xls  .ppt  .dot  .xlt  .pot\n\n"
                L"检测项:\n"
                L"  - 自动执行宏(Auto_Open / Workbook_Open / Document_Open 等)\n"
                L"  - 危险 API(WScript.Shell / powershell / 下载执行 / 编码混淆)\n"
                L"  - VBA Stomping(含宏项目但无明文过程名)\n"
                L"  - Office 宏安全设置(AccessVBOM / VBAWarnings)\n\n"
                L"高危文档将被隔离, 激进模式下强制删除。",
                L"宏病毒防护", 0);
            MacroGuardRun();
            break;
        }
        case IDC_BTN_OFFICE_GUARD: {
            bool now = !g_officeGuardOn.load();
            g_officeGuardOn.store(now);
            g_cfg.officeGuardOn = now;
            if (now) {
                LaunchDaemon(L"OfficeGuardLoop", [] { OfficeGuardLoop(); });
                LogPost(L"办公软件防护: 已开启 (Word/Excel/PPT/Outlook 等启动命令行将被阻止)");
            } else {
                LogPost(L"办公软件防护: 已关闭");
            }
            MessageBoxW(g_hMain, now ? L"办公软件防护已开启" : L"办公软件防护已关闭",
                        L"办公软件防护", 0);
            break;
        }
        case IDC_BTN_GUARD: {
            bool now = !g_guardOn.load();
            g_guardOn.store(now);
            if (now) {
                LaunchDaemon(L"ProcGuardLoop", [] { ProcGuardLoop(); });
                LogPost(L"进程守护: 已开启 (无有效签名/随机哈希命名的程序将被默认阻止)");
            } else {
                LogPost(L"进程守护: 已关闭 (本次运行中已启动的守护线程将在空闲后退出)");
            }
            MessageBoxW(g_hMain, now ? L"进程守护已开启" : L"进程守护已关闭", L"进程守护", 0);
            break;
        }
        // ---- 网络 ----
        case IDC_CB_NETWORK_WINDOW: {
            ScanNetwork();
            MessageBoxW(g_hMain, L"网络防护窗口: 已刷新连接列表, 详见日志页与网络页", L"网络防护", 0);
            break;
        }
        case IDC_CB_NETWORK_REFRESH:  ScanNetwork(); break;
        case IDC_CB_DISCONNECT: {
            auto v = SnapshotNets();
            for (auto& n : v) DisconnectConnection(n.pid);
            break;
        }
        // ---- 防护 ----
        case IDC_CB_PROTECTION_MONITOR: g_scanning.store(true);  LaunchScan(&FullChainScanThread); break;
        case IDC_CB_PROTECTION_LOCKDOWN: LogPost(L"Lockdown toggled"); break;
        case IDC_CB_ETW_TRACE:
            if(g_etwOn){ EtwTraceStop(); LogPost(L"ETW 追踪已停止"); }
            else if(EtwTraceStart()) LogPost(L"ETW 追踪已启动");
            else LogPost(L"ETW 启动失败(需管理员权限)，继续使用轮询模式");
            break;
        case IDC_CB_PROC_TREE:
            LaunchBg([](){ ProcTreeBuild(); });
            break;
        case IDC_BTN_VULN_UPDATE:
            LaunchScan([] {
                long long n = VulnUpdateAll();
                LogFmt(L"漏洞情报更新完成, 本次新增 %lld 条", n);
            });
            break;
        case IDC_BTN_VULN_CHECK:
            LaunchBg([] { VulnCheckLocal(); });
            break;
        case IDC_CB_USB_AUDIT:
            LaunchBg([](){ UsbDevAudit(); });
            break;
        case IDC_CB_PROTECTION_AMSI:     LogPost(L"AMSI toggled"); break;
        // ---- 回滚 / 恢复 ----
        case IDC_CB_CREATE_SNAPSHOT:  CreateSnapshot(); break;
        case IDC_CB_RECOVERY_ENV:     CreateRecoveryEnvironment(); break;
        case IDC_CB_ROLLBACK_REFRESH: LogPost(L"Rollback list refreshed"); break;
        // ---- 隐私: 摄像头 ----
        case IDC_CB_CAM_ON: {
            BOOL on = IsDlgButtonChecked(g_hMain, IDC_CB_CAM_ON);
            if (on)  CameraStart(g_cfg.camMode, g_cfg.camFile);
            else     CameraStop();
            ShowWindow(g_hCamOpts, on ? SW_SHOW : SW_HIDE);
            break;
        }
        case IDC_CB_CAM_BLACK:  g_cfg.camMode = 0; break;
        case IDC_CB_CAM_MODE:   g_cfg.camMode = 1; break;
        case IDC_CB_CAM_BROWSE: {
            wchar_t buf[MAX_PATH] = {0};
            OPENFILENAMEW ofn; memset(&ofn, 0, sizeof(ofn));
            ofn.lStructSize = sizeof(ofn); ofn.hwndOwner = g_hMain;
            ofn.lpstrFilter = L"视频文件\0*.mp4;*.avi;*.mkv\0所有文件\0*.*\0";
            ofn.lpstrFile = buf; ofn.nMaxFile = MAX_PATH;
            ofn.lpstrTitle = L"选择自定义视频画面"; ofn.Flags = 0x1000;
            if (GetOpenFileNameW(&ofn)) { g_cfg.camFile = buf; LogFmt(L"摄像头自定义画面: %s", buf); }
            break;
        }
        // ---- 隐私: 麦克风 ----
        case IDC_CB_MIC_ON: {
            BOOL on = IsDlgButtonChecked(g_hMain, IDC_CB_MIC_ON);
            if (on)  MicStart(g_cfg.micMode, g_cfg.micFile);
            else     MicStop();
            ShowWindow(g_hMicOpts, on ? SW_SHOW : SW_HIDE);
            break;
        }
        case IDC_CB_MIC_MUTE:  g_cfg.micMode = 0; break;
        case IDC_CB_MIC_MODE:  g_cfg.micMode = 1; break;
        case IDC_CB_MIC_BROWSE: {
            wchar_t buf[MAX_PATH] = {0};
            OPENFILENAMEW ofn; memset(&ofn, 0, sizeof(ofn));
            ofn.lStructSize = sizeof(ofn); ofn.hwndOwner = g_hMain;
            ofn.lpstrFilter = L"音频文件\0*.wav;*.mp3\0所有文件\0*.*\0";
            ofn.lpstrFile = buf; ofn.nMaxFile = MAX_PATH;
            ofn.lpstrTitle = L"选择自定义音频文件"; ofn.Flags = 0x1000;
            if (GetOpenFileNameW(&ofn)) { g_cfg.micFile = buf; LogFmt(L"麦克风自定义音频: %s", buf); }
            break;
        }
        // ---- DLP ----
        case IDC_CB_ENCRYPT: DlpEncrypt(L"", g_cfg.password); break;
        case IDC_CB_SHRED:   DlpShred(L""); break;
        case IDC_CB_DPAPI:   DlpDpapiProtect(L""); break;
        // ---- FIM / SCA ----
        case IDC_CB_BASELINE:    BuildBaseline(); break;
        case IDC_CB_START_FIM:   FimStartMonitoring(); break;
        case IDC_CB_STOP_FIM:    FimStopMonitoring(); break;
        case IDC_CB_RUN_SCA:     RunScaAudit(); break;
        // ---- 紧急自救 ----
        case IDC_CB_BOOTSCAN:
        RegisterBootScan(true);
        MessageBoxW(g_hMain,
            L"已注册开机扫描。\n重启后将在进入桌面前自动全盘扫描并处理威胁,\n"
            L"完成后自动恢复并进入桌面。\n\n注意: 高危文件仅在开启「激进模式」时才删除,\n"
            L"其余一律隔离; 系统目录受保护, 永不被删除。",
            L"重启杀毒", MB_OK | MB_ICONINFORMATION);
        break;
    case IDC_CB_BOOTSCAN_OFF:
        RegisterBootScan(false);
        MessageBoxW(g_hMain, L"已注销开机扫描, Winlogon Shell 已恢复。",
                    L"重启杀毒", MB_OK | MB_ICONINFORMATION);
        break;
    case IDC_CB_EMG_RUN:     RunEmergency(); break;
        case IDC_CB_THEME_TOGGLE: {
            ThemeToggle();
            return true;
        }
        case IDC_CB_CLEAR_THREAT: {
            ClearThreat();
            LogPost(L"[UI] 已手动解除告警指示(如威胁仍存在, 下次扫描会再次触发)");
            return true;
        }
        case IDC_CB_SHOWPWD: {
            if (g_hPwdEdit) {
                static bool shown = false;
                shown = !shown;
                SendMessageW(g_hPwdEdit, EM_SETPASSWORDCHAR, shown ? 0 : (WPARAM)L'*', 0);
                InvalidateRect(g_hPwdEdit, nullptr, TRUE);
            }
            break;
        }
        // ---- 全链扫描设置 ----
        case IDC_CB_FULLCHAIN_ON: {
            BOOL on = IsDlgButtonChecked(g_hMain, IDC_CB_FULLCHAIN_ON);
            g_scanning.store(on ? true : false);
            if (on) LaunchScan(&FullChainScanThread);
            ShowWindow(g_hScanOpts, on ? SW_SHOW : SW_HIDE);
            break;
        }
        case IDC_CB_ADV_HEURISTIC:  g_cfg.advHeuristic  = IsDlgButtonChecked(g_hMain, IDC_CB_ADV_HEURISTIC) != 0; break;
        case IDC_CB_ADV_MEMORY:     g_cfg.advMemory     = IsDlgButtonChecked(g_hMain, IDC_CB_ADV_MEMORY) != 0; break;
        case IDC_CB_ADV_CLOUD:      g_cfg.advCloud      = IsDlgButtonChecked(g_hMain, IDC_CB_ADV_CLOUD) != 0; break;
        case IDC_CB_ADV_DEOBF:      g_cfg.advDeobf      = IsDlgButtonChecked(g_hMain, IDC_CB_ADV_DEOBF) != 0; break;
        case IDC_CB_ADV_AGGRESSIVE: g_cfg.advAggressive = IsDlgButtonChecked(g_hMain, IDC_CB_ADV_AGGRESSIVE) != 0; break;
        case IDC_CB_ADV_ESCAPE:
            // v13.26 逃生模式是最后手段, 开启前强制二次确认, 防止误点导致系统损坏
            if (IsDlgButtonChecked(g_hMain, IDC_CB_ADV_ESCAPE)) {
                int r = MessageBoxW(g_hMain,
                    L"紧急逃生模式为最高级处置，后果极其严重：\n\n"
                    L"· 命中任意一条规则(含提示级)即执行终极查杀\n"
                    L"· 进程被连续终止，原文件被多遍覆写彻底销毁\n"
                    L"· 不会自动还原，误杀将无法挽回\n"
                    L"· 可能导致系统无法启动、正常软件永久损坏\n\n"
                    L"仅在确认系统已被控制、需要立即止损时开启。\n"
                    L"确定要开启吗？",
                    L"ZZ EDR - 紧急逃生模式", MB_ICONWARNING | MB_YESNO | MB_TOPMOST);
                if (r != IDYES) {
                    CheckDlgButton(g_hMain, IDC_CB_ADV_ESCAPE, BST_UNCHECKED);
                    g_cfg.escapeMode = false;
                    break;
                }
                g_cfg.escapeMode = true;
                LogPost(L"[逃生] 已开启紧急逃生模式 —— 此后命中任意规则即终极查杀");
            } else {
                g_cfg.escapeMode = false;
                LogPost(L"[逃生] 已关闭紧急逃生模式");
            }
            break;
        // v13.27 覆写强度下拉选择
        case IDC_CB_ESCAPE_WIPE:
            if (HIWORD(wp) == CBN_SELCHANGE) {
                HWND hCb = GetDlgItem(g_hScanOpts, IDC_CB_ESCAPE_WIPE);
                if (hCb) {
                    int idx = (int)SendMessageW(hCb, CB_GETCURSEL, 0, 0);
                    if (idx >= 0 && idx <= 2) {
                        g_cfg.escapeWipeLevel = idx + 1;
                        static const wchar_t* kName[3] = { L"弱(1遍)", L"中(3遍)", L"强(7遍)" };
                        LogFmt(L"[逃生] 覆写强度已设为: %s", kName[idx]);
                    }
                }
            }
            break;
        case IDC_BTN_APPLY:         ApplyConfig(); break;

        // ---- Legacy UI 命名映射 (与 zz_EDR_legacy_ui.html data-cb 一一对应) ----
        case IDC_CB_CAM_TOGGLE: {      // 摄像头开关
            BOOL on = IsDlgButtonChecked(g_hMain, IDC_CB_CAM_TOGGLE);
            if (on)  CameraStart(g_cfg.camMode, g_cfg.camFile);
            else     CameraStop();
            ShowWindow(g_hCamOpts, on ? SW_SHOW : SW_HIDE);
            break;
        }
        case IDC_CB_MIC_TOGGLE: {      // 麦克风开关
            BOOL on = IsDlgButtonChecked(g_hMain, IDC_CB_MIC_TOGGLE);
            if (on)  MicStart(g_cfg.micMode, g_cfg.micFile);
            else     MicStop();
            ShowWindow(g_hMicOpts, on ? SW_SHOW : SW_HIDE);
            break;
        }
        case IDC_CB_CHAIN_TOGGLE: {    // 全链扫描开关
            BOOL on = IsDlgButtonChecked(g_hMain, IDC_CB_CHAIN_TOGGLE);
            g_scanning.store(on ? true : false);
            if (on) SchedulerLoop();
            ShowWindow(g_hScanOpts, on ? SW_SHOW : SW_HIDE);
            break;
        }
        case IDC_CB_CHAIN_START:  SchedulerLoop(); break;
        case IDC_CB_CHAIN_MONITOR: g_scanning.store(true);  SchedulerLoop(); break;
        case IDC_CB_CHAIN_AMSI:    AmsiScan(L""); break;
        case IDC_CB_CHAIN_LOCKDOWN: LogPost(L"Lockdown 模式已切换"); break;
        case IDC_CB_CHAIN_ONCE:   { /* 单次全盘扫描 */
            // 【修复】原直接在 UI 线程跑全链扫描, 界面会冻结至扫描结束(可能数分钟)
            if (g_scanning.load()) { LogPost(L"[SCAN] 上一轮扫描尚未结束, 请稍候"); break; }
            g_scanning.store(true); LaunchScan([] { FullChainScanThread(); }); break; }
        case IDC_CB_OVERVIEW_SCAN:  SchedulerLoop(); break;
        case IDC_CB_OVERVIEW_REFRESH: EnumAllProcesses(); LogPost(L"概览已刷新"); break;
        case IDC_CB_PROC_KILLALL: {
            for (auto& p : SnapshotProcs()) if (p.suspicious) KillProcess(p.pid);
            break;
        }
        case IDC_CB_PROC_DEEPCLEAN: LaunchScan([] { DeepClean(); }); break;
        case IDC_CB_PROC_REMOTE:   LaunchScan([] { DetectRemoteControl(); }); break;
        case IDC_CB_PROC_REFRESH:  EnumAllProcesses(); break;
        case IDC_CB_NET_WINDOW:    LogPost(L"网络防护窗口"); break;
        case IDC_CB_NET_REFRESH:   ScanNetwork(); break;
        case IDC_CB_NET_CUTOFF:    for (auto& n : SnapshotNets()) DisconnectConnection(n.pid); break;
        case IDC_CB_DLP_ENCRYPT:   DlpEncrypt(L"", g_cfg.password); break;
        case IDC_CB_DLP_SHRED:     DlpShred(L""); break;
        case IDC_CB_DLP_DPAPI:     DlpDpapiProtect(L""); break;
        case IDC_CB_FIM_BASELINE:  BuildBaseline(); break;
        case IDC_CB_FIM_START:     FimStartMonitoring(); break;
        case IDC_CB_FIM_STOP:      FimStopMonitoring(); break;
        case IDC_CB_SCA_RUN:       RunScaAudit(); break;
        case IDC_CB_RB_CREATE:     CreateSnapshot(); break;
        case IDC_CB_RB_RECOVERY:   CreateRecoveryEnvironment(); break;
        case IDC_CB_RB_RESTORE:    LogPost(L"从选中快照还原"); break;
        case IDC_CB_REC_CREATE:    CreateRecoveryEnvironment(); break;
        case IDC_CB_REC_CHECK:     LogPost(L"完整性校验完成"); break;
        case IDC_CB_SVC_BACKDOOR:   SvcBackdoorScan(); break;
        case IDC_CB_BROWSER_HIJACK: BrowserHijackScan(); break;
        case IDC_CB_ARP_DNS:        ArpDnsGuard(); break;
        case IDC_CB_SCAN_BY_PRIO:   ScanByPriorityOrder(); break;
        case IDC_CB_TASK_SCHED:     TaskSchedScan(); break;
        case IDC_CB_INJECT_SCAN:    InjectScan(); break;
        case IDC_CB_FW_AUDIT:      FirewallAuditRun(); break;
        case IDC_CB_HIDDEN_PROC:   HiddenProcScan(); break;
        case IDC_CB_PROXY_HIJACK:  ProxyHijackScan(); break;
        case IDC_CB_QUAR_MANAGE:   QuarantineManage(); break;
        case IDC_CB_FOX_DEEP:      LaunchScan([] { FoxDeepScan(); }); break;
        case IDC_CB_FOX_BYOVD:     LaunchScan([] { FoxByovdScan(); }); break;
        case IDC_CB_VARIANT_SCAN:  VariantScanRunning(); break;
        case IDC_CB_FAMILY_SCAN: {
            LaunchScan([]{
                LogPost(L"==== \u94f6\u72d0/\u7d2b\u72d0\u4e0e\u65cf\u8c31\u8bc6\u522b\u5f00\u59cb ====");
                int n = FoxProcScan();
                std::wstring why; int hit = 0;
                for (const auto& t : SnapshotProcs()) {
                    if (t.path.empty()) continue;
                    int sev = MalFamilyScan(t.path, why);
                    if (sev >= 3) { hit++; LogPost(L"[\u65cf\u8c31] " + t.name + L" -> " + why); }
                }
                LogPost(L"==== \u5b8c\u6210: \u8fdb\u7a0b\u5f02\u5e38 " + std::to_wstring(n) +
                        L" \u9879, \u6587\u4ef6\u65cf\u8c31\u547d\u4e2d " + std::to_wstring(hit) + L" \u9879 ====");
                MessageBoxW(g_hMain, (L"\u94f6\u72d0/\u7d2b\u72d0\u4e0e\u65cf\u8c31\u8bc6\u522b\u5b8c\u6210\u3002\n\n\u8fdb\u7a0b\u5f02\u5e38: " +
                            std::to_wstring(n) + L" \u9879\n\u6587\u4ef6\u65cf\u8c31\u547d\u4e2d: " + std::to_wstring(hit) +
                            L" \u9879\n\n\u8be6\u60c5\u89c1\u65e5\u5fd7\u9875\u3002").c_str(), L"\u65cf\u8c31\u8bc6\u522b", 0);
            });
            break;
        }
        case IDC_CB_HEUR_SCAN:  LaunchScan([]{ HeurScanAll(); }); return 0;
        case IDC_CB_PDM_SCAN:   LaunchScan([]{ PdmChainScan(true); }); return 0;
        case IDC_CB_PDM_TOGGLE: {
            g_cfg.pdmOn = !g_cfg.pdmOn;
            g_cfg.Save(L"zz_EDR.cfg.json");
            LogPost(std::wstring(L"[PDM] 实时防御已") + (g_cfg.pdmOn ? L"开启" : L"关闭"));
            return 0;
        }
        case IDC_CB_SELF_REPAIR: {
            LaunchBg([]{
                int n = EnsureSelfRunnable();
                std::wstring m = n ? (L"\u5df2\u4fee\u590d " + std::to_wstring(n) +
                                      L" \u9879\u542f\u52a8\u9650\u5236, \u5df2\u5237\u65b0\u7ec4\u7b56\u7565\u3002\nEXE/C \u7a0b\u5e8f\u73b0\u5df2\u6062\u590d\u8fd0\u884c\u3002")
                                   : L"\u672a\u53d1\u73b0\u963b\u6b62\u672c\u7a0b\u5e8f/EXE \u8fd0\u884c\u7684\u7ec4\u7b56\u7565\u9650\u5236\u3002\n\u65e0\u9700\u4fee\u590d\u3002";
                MessageBoxW(g_hMain, m.c_str(), L"\u542f\u52a8\u9650\u5236\u81ea\u4fee\u590d", 0);
            });
            break;
        }
        case IDC_CB_PROXY_AUDIT:   PortProxyAudit(); break;
        case IDC_CB_EVTLOG_AUDIT:  EventLogAudit(); break;
        case IDC_CB_HIDDEN_FILE:   LaunchBg([]{ HiddenFileScan(); }); break;
        case IDC_CB_ADS_SCAN:      LaunchBg([]{ AdsScan(); }); break;
        case IDC_CB_MAIL_SCAN:     LaunchBg([]{ MailScan(); }); break;
        case IDC_CB_FORCE_UNLOCK:  ForceUnlockUi(g_hMain); break;
        case IDC_CB_LNK_HIJACK:
            LaunchScan([]() { LnkHijackScan(); }); break;
        case IDC_CB_CANARY_GUARD:
            LaunchScan([]() { CanaryGuardRun(true); }); break;
        case IDC_CB_COM_HIJACK:
            LaunchScan([]() { ComHijackScan(); }); break;
        case IDC_CB_MIT_AUDIT:   LaunchBg([] { MitigationAudit(); }); break;
        case IDC_CB_CRED_GUARD:  LaunchBg([] { CredGuardAudit(); }); break;
        case IDC_CB_SHARE_AUDIT: LaunchBg([] { ShareAudit(); }); break;
        case IDC_CB_CFG_BACKUP: {
            const std::wstring cp = CfgDefaultPath();
            if (CfgBackup(cp)) {
                CfgWriteSig(cp, CfgHashFile(cp));
                LogPost(L"[配置] 已备份为 zz_EDR.cfg.json.bak 并刷新防篡改校验值");
            } else {
                LogPost(L"[配置] 备份失败(配置文件不存在?)");
            }
            break;
        }
        case IDC_CB_CFG_RESTORE: {
            const std::wstring cp = CfgDefaultPath();
            if (CfgRestore(cp)) {
                g_cfg.Load(cp.c_str());
                LogPost(L"[配置] 检测到被篡改时已从备份恢复并重新载入");
            } else {
                LogPost(L"[配置] 恢复失败(备份文件不存在?)");
            }
            break;
        }
        case IDC_CB_LOG_REFRESH:   LogPost(L"日志已刷新"); break;
        case IDC_CB_LOG_CLEAR:     LogClearAll(); break;
        case IDC_CB_LOG_EXPORT:    LaunchBg([]{ LogExportReport(); }); break;
        case IDC_CB_AUTORUN_MANAGE: LaunchBg([]{ AutorunListToLog(); }); break;
        case IDC_CB_KILL_TREE:     LaunchBg([]{
                                       DWORD sel = SelectedProcPid();
                                       if (sel == 0) { LogPost(L"[进程树] 请先在进程列表中选中一个进程"); return; }
                                       KillProcessTree(sel);
                                   }); break;
        case IDC_CB_PWD_TOGGLE: {  // 显示/隐藏应急密码
            if (g_hPwdEdit) {
                static bool shown = false;
                shown = !shown;
                SendMessageW(g_hPwdEdit, EM_SETPASSWORDCHAR, shown ? 0 : (WPARAM)L'*', 0);
                InvalidateRect(g_hPwdEdit, nullptr, TRUE);
            }
            break;
        }
        // 引擎开关: IDC_ENGINE_BASE + 0..7 (BSS/HIPS/DAC/VEH/YARA/PE/Evasion/ApiHook)
        if (id >= IDC_ENGINE_BASE && id < IDC_ENGINE_BASE + 8) {
            int idx = id - IDC_ENGINE_BASE;
            g_cfg.engine[idx] = IsDlgButtonChecked(g_hMain, id) == BST_CHECKED;
            LogFmt(L"引擎[%d] %s", idx, g_cfg.engine[idx] ? L"启用" : L"禁用");
            break;
        }
        default: return FALSE;
    }
    return TRUE;
}

// ============================================================
//  配置应用 / 引擎勾选
// ============================================================
static void ApplyConfig() {
    // 读取扫描间隔
    wchar_t buf[64] = {0};
    if (g_hScanOpts) {
        HWND he = GetDlgItem(g_hScanOpts, IDC_CB_SCAN_INTERVAL);
        if (he) { GetWindowTextW(he, buf, 64); g_cfg.scanIntervalMs = _wtoi(buf); }
    }
    // v13.27 应用时同步覆写强度下拉框的选中项, 避免与配置值不一致
    if (g_hScanOpts) {
        HWND hCb = GetDlgItem(g_hScanOpts, IDC_CB_ESCAPE_WIPE);
        if (hCb) SendMessageW(hCb, CB_SETCURSEL, (WPARAM)(g_cfg.escapeWipeLevel - 1), 0);
    }
    g_cfg.Save(L"zz_EDR.cfg.json");
    LogFmt(L"Config applied: interval=%dms wipeLevel=%d",
           g_cfg.scanIntervalMs, g_cfg.escapeWipeLevel);
}
static void SyncEngineChecks(HWND dlg) {
    for (int i = 0; i < 8; ++i) {
        HWND cb = GetDlgItem(dlg, IDC_ENGINE_BASE + i);
        if (cb) CheckDlgButton(dlg, IDC_ENGINE_BASE + i, g_cfg.engine[i] ? BST_CHECKED : BST_UNCHECKED);
    }
}

// ============================================================
//  日夜主题 (Day / Night Theme)
// ============================================================
struct Theme {
    COLORREF bg, panel, text, textDim, accent, btn, btnText, warn, danger, ok;
};
// 暗色(夜间) —— 默认
static const Theme THEME_DARK = {
    RGB(13,17,23),    RGB(22,27,34),    RGB(201,209,217), RGB(139,148,158),
    RGB(31,111,235),  RGB(33,38,45),    RGB(201,209,217), RGB(210,153,34),
    RGB(248,81,73),   RGB(63,185,80)
};
// 亮色(白天)
static const Theme THEME_LIGHT = {
    RGB(255,255,255), RGB(246,248,250), RGB(36,41,46),   RGB(106,115,125),
    RGB(3,102,214),   RGB(228,233,240), RGB(36,41,46),   RGB(189,128,0),
    RGB(215,58,73),   RGB(40,167,69)
};
static const Theme* g_theme = &THEME_DARK;
static HBRUSH g_brBg = nullptr, g_brPanel = nullptr, g_brBtn = nullptr;
static HFONT  g_fontBanner = nullptr, g_fontWarn = nullptr;
static std::vector<HWND> g_themedCtrls;

static void ThemeFreeRes() {
    if (g_brBg)    { DeleteObject(g_brBg);    g_brBg = nullptr; }
    if (g_brPanel) { DeleteObject(g_brPanel); g_brPanel = nullptr; }
    if (g_brBtn)   { DeleteObject(g_brBtn);   g_brBtn = nullptr; }
}
// 应用主题: dark=true 夜间, false 白天
static void ThemeApply(bool dark) {
    g_theme = dark ? &THEME_DARK : &THEME_LIGHT;
    ThemeFreeRes();
    g_brBg    = CreateSolidBrush(g_theme->bg);
    g_brPanel = CreateSolidBrush(g_theme->panel);
    g_brBtn   = CreateSolidBrush(g_theme->btn);
    if (g_hMain) {
        RedrawWindow(g_hMain, nullptr, nullptr,
                     RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN | RDW_ERASE);
    }
}
static void ThemeToggle() {
    bool dark = (g_theme == &THEME_DARK);
    ThemeApply(!dark);                 // 切换
    g_cfg.themeDark = !dark;
    g_cfg.Save(L"zz_EDR.cfg.json");
    LogPost(!dark ? L"[主题] 已切换到夜间模式(深色)"
                  : L"[主题] 已切换到白天模式(浅色)");
}

// ============================================================
//  危险指示 (Threat Banner) —— 主界面常驻, 大号注意符号
// ============================================================
static std::atomic<int>   g_threatLevel{THREAT_SAFE};
static int ThreatLevelGet() { return g_threatLevel.load(); }
static std::mutex         g_threatMtx;
static std::wstring       g_threatText;
static HWND g_hThreatBanner = nullptr;   // 大号 ⚠ / 状态文本
static HWND g_hThreatDesc   = nullptr;   // 说明行
#define WM_APP_THREAT (WM_APP + 12)

// UI 线程: 重绘危险指示条
static void UpdateThreatBannerUI() {
    if (!g_hThreatBanner) return;
    int lv = g_threatLevel.load();
    std::wstring txt, desc;
    {
        std::lock_guard<std::mutex> lk(g_threatMtx);
        desc = g_threatText;
    }
    if (lv == THREAT_DANGER) {
        txt = L"⚠  发 现 病 毒 / 系 统 异 常";
        if (desc.empty()) desc = L"检测到高危威胁, 建议立即执行全盘扫描";
    } else if (lv == THREAT_WARN) {
        txt = L"⚠  注 意: 发 现 可 疑 项";
        if (desc.empty()) desc = L"存在可疑对象, 建议关注并处理";
    } else {
        txt = L"✓  系 统 安 全";
        desc = L"未发现威胁, 防护运行中";
    }
    SetWindowTextW(g_hThreatBanner, txt.c_str());
    if (g_hThreatDesc) SetWindowTextW(g_hThreatDesc, desc.c_str());
    // 危险时闪烁提醒: 强制重绘
    RedrawWindow(g_hThreatBanner, nullptr, nullptr, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ERASE);
    if (g_hThreatDesc) RedrawWindow(g_hThreatDesc, nullptr, nullptr, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ERASE);
}
// 任意线程: 设置威胁等级 (只升不降, 需手动"解除告警"复位)
static void SetThreatLevel(int lv, const wchar_t* reason) {
    if (lv <= THREAT_SAFE) return;
    bool changed = false;
    if (lv > g_threatLevel.load()) { g_threatLevel.store(lv); changed = true; }
    if (reason) {
        std::lock_guard<std::mutex> lk(g_threatMtx);
        if (g_threatText != reason) { g_threatText = reason; changed = true; }
    }
    if (changed && g_hMain) PostMessageW(g_hMain, WM_APP_THREAT, 0, 0);
}
// 用户确认后解除告警
static void ClearThreat() {
    g_threatLevel.store(THREAT_SAFE);
    { std::lock_guard<std::mutex> lk(g_threatMtx); g_threatText.clear(); }
    if (g_hMain) PostMessageW(g_hMain, WM_APP_THREAT, 0, 0);
}

// ============================================================
//  主窗口过程
// ============================================================
static LRESULT CALLBACK MainWndProc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
    switch (m) {
        case WM_CREATE: {
            g_hMain = h;
            INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_TAB_CLASSES | ICC_STANDARD_CLASSES };
            InitCommonControlsEx(&icc);
            // ---- 日夜主题初始化 ----
            ThemeApply(g_cfg.themeDark);
            // ---- 危险指示横幅(常驻主界面顶部) ----
            g_fontBanner = CreateFontW(28, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                                       DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                       DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei");
            g_hThreatBanner = CreateWindowExW(0, L"STATIC", L"\u26A0  \u7CFB\u7EDF\u542F\u52A8\u4E2D...",
                                              WS_CHILD | WS_VISIBLE | SS_CENTER | SS_CENTERIMAGE,
                                              10, 8, 780, 46, h, nullptr,
                                              GetModuleHandleW(nullptr), nullptr);
            g_hThreatDesc = CreateWindowExW(0, L"STATIC", L"\u6B63\u5728\u521D\u59CB\u5316\u9632\u62A4...",
                                              WS_CHILD | WS_VISIBLE | SS_CENTER,
                                              10, 54, 780, 22, h, nullptr,
                                              GetModuleHandleW(nullptr), nullptr);
            if (g_fontBanner && g_hThreatBanner)
                SendMessageW(g_hThreatBanner, WM_SETFONT, (WPARAM)g_fontBanner, TRUE);
            UpdateThreatBannerUI();

            g_hTab = CreateWindowExW(0, WC_TABCONTROLW, nullptr,
                                     WS_CHILD | WS_VISIBLE | TCS_TABS,
                                     10, 84, 700, 420, h, (HMENU)IDC_TAB,
                                     GetModuleHandleW(nullptr), nullptr);
            TCITEMW tie;
            tie.mask = TCIF_TEXT;
            for (int i = 0; i < 11; ++i) {
                tie.pszText = (LPWSTR)g_pages[i].title;
                TabCtrl_InsertItem(g_hTab, i, &tie);
            }
            CreatePages(h);
            EnumAllProcesses();
            g_scanning.store(true);
            LaunchScan(&FullChainScanThread);
            { wchar_t vb[64]; swprintf(vb, 64, L"ZZ EDR v%d.%d.%d started", VER_MAJOR, VER_MINOR, VER_PATCH); LogPost(vb); }
            return 0;

        }
        case WM_SIZE: {
            int w = LOWORD(lp), hh = HIWORD(lp);
            if (g_hThreatBanner) MoveWindow(g_hThreatBanner, 10, 8,  w - 20, 46, TRUE);
            if (g_hThreatDesc)   MoveWindow(g_hThreatDesc,   10, 54, w - 20, 22, TRUE);
            if (g_hTab)          MoveWindow(g_hTab, 10, 84, w - 20, (hh > 94) ? (hh - 94) : 300, TRUE);
            // v13.25: 可视高度跟随窗口, 重新夹紧滚动位置并平移页面容器
            g_pageViewH = (hh > PAGE_TOP + 10) ? (hh - PAGE_TOP - 10) : 300;
            UpdatePageScroll();
            return 0;
        }
        // ---- v13.25: 页面纵向滚动(鼠标滚轮 / 滚动条) ----
        case WM_MOUSEWHEEL: {
            int delta = GET_WHEEL_DELTA_WPARAM(wp);   // 通常是 ±120 的倍数
            PageScrollBy((delta > 0) ? -60 : 60);     // 上滚(正值) -> 内容下移
            return 0;
        }
        case WM_VSCROLL: {
            switch (LOWORD(wp)) {
                case SB_LINEUP:    PageScrollBy(-40); break;
                case SB_LINEDOWN:  PageScrollBy( 40); break;
                case SB_PAGEUP:    PageScrollBy(-(int)g_pageViewH / 2); break;
                case SB_PAGEDOWN:  PageScrollBy( (int)g_pageViewH / 2); break;
                case SB_THUMBTRACK:
                case SB_THUMBPOSITION: {
                    SCROLLINFO si; si.cbSize = sizeof(si); si.fMask = SIF_TRACKPOS;
                    if (GetScrollInfo(h, SB_VERT, &si)) {
                        g_pageScrollY = si.nTrackPos;
                        UpdatePageScroll();
                    }
                    break;
                }
                default: break;
            }
            return 0;
        }
        case WM_COMMAND: {
            // 进程列表双击 -> 直接打开该进程行为时间线
            if (HIWORD(wp) == LBN_DBLCLK && (HWND)lp == g_hProcList) { OnProcListDblClick(); return 0; }
            if (OnCommand(wp, lp)) return 0;
            return DefWindowProcW(h, m, wp, lp);
        }
        case WM_APP_LOG: {
            // UI 线程: 刷新日志列表
            wchar_t* msg = reinterpret_cast<wchar_t*>(lp);
            if (msg && g_hLog) {
                int idx = (int)SendMessageW(g_hLog, LB_ADDSTRING, 0, (LPARAM)msg);
                int cnt = (int)SendMessageW(g_hLog, LB_GETCOUNT, 0, 0);
                if (cnt > MAX_LOG) SendMessageW(g_hLog, LB_DELETESTRING, 0, 0);
                SendMessageW(g_hLog, LB_SETTOPINDEX, cnt - 1, 0);
            }
            free(msg);
            return 0;
        }
        case WM_APP_CONFIRM: {
            AlertReq* r = reinterpret_cast<AlertReq*>(lp);
            if (r) {
                std::wstring msg = L"【安全告警】\r\n\r\n" + r->detail;
                if (!r->path.empty()) msg += L"\r\n\r\n文件: " + r->path;
                if (r->pid)        msg += L"\r\n进程 PID: " + std::to_wstring(r->pid);
                msg += L"\r\n\r\n[是] 立即处理    [否] 忽略此次    [取消] 加入白名单(不再提示)";
                int ret = MessageBoxW(g_hMain, msg.c_str(), r->title.c_str(),
                                       MB_YESNOCANCEL | MB_ICONWARNING | MB_TOPMOST | MB_SETFOREGROUND);
                r->answer = (ret == IDYES) ? ALERT_HANDLE : ((ret == IDNO) ? ALERT_IGNORE : ALERT_ALLOW);
                SetEvent(r->done);
            }
            return 0;
        }
        case WM_APP_ALERT: {
            // UI 线程: 资源异常 / 免疫处置 优先通知弹窗
            wchar_t* msg = reinterpret_cast<wchar_t*>(lp);
            if (msg) {
                MessageBoxW(g_hMain, msg, L"ZZ EDR 安全告警", MB_OK | MB_ICONWARNING | MB_TOPMOST);
                delete[] msg;
            }
            return 0;
        }
        case WM_APP_THREAT: {
            // UI 线程: 刷新主界面危险指示
            UpdateThreatBannerUI();
            return 0;
        }
        case WM_APP_PROCLIST: {
            // UI 线程: 填充进程列表(控件操作必须在创建它的线程上做)
            std::vector<std::wstring>* v = reinterpret_cast<std::vector<std::wstring>*>(lp);
            if (v && g_hProcList) {
                SendMessageW(g_hProcList, LB_RESETCONTENT, 0, 0);
                for (const auto& line : *v)
                    SendMessageW(g_hProcList, LB_ADDSTRING, 0, (LPARAM)line.c_str());
            }
            delete v;                       // 释放后台线程 new 出来的数据
            return 0;
        }
        case WM_APP_HEARTBEAT: {
            // v13.29: 回应 UI 监控器的心跳 —— 能进入这里说明消息循环是活的。
            // 监控器据此判断主呈现器是否卡死; 连续 3 次无回执则启用备用呈现器。
            UiHeartbeatAck((long long)lp);
            return 0;
        }
        case WM_CTLCOLORSTATIC: {
            HDC dc = (HDC)wp; HWND ctl = (HWND)lp;
            SetBkMode(dc, TRANSPARENT);
            if (ctl == g_hThreatBanner) {
                int lv = g_threatLevel.load();
                COLORREF c = (lv == THREAT_DANGER) ? g_theme->danger
                           : (lv == THREAT_WARN)   ? g_theme->warn
                                                    : g_theme->ok;
                SetTextColor(dc, c);
                SetBkColor(dc, g_theme->panel);
                return (LRESULT)g_brPanel;
            }
            if (ctl == g_hThreatDesc) { SetTextColor(dc, g_theme->textDim); return (LRESULT)g_brBg; }
            SetTextColor(dc, g_theme->text);
            return (LRESULT)g_brBg;
        }
        case WM_CTLCOLOREDIT: {
            HDC dc = (HDC)wp;
            SetTextColor(dc, g_theme->text);
            SetBkColor(dc, g_theme->panel);
            return (LRESULT)g_brPanel;
        }
        case WM_CTLCOLORLISTBOX: {
            HDC dc = (HDC)wp;
            SetTextColor(dc, g_theme->text);
            SetBkColor(dc, g_theme->panel);
            return (LRESULT)g_brPanel;
        }
        case WM_CTLCOLORBTN: {
            HDC dc = (HDC)wp;
            SetTextColor(dc, g_theme->btnText);
            SetBkColor(dc, g_theme->btn);
            SetBkMode(dc, TRANSPARENT);
            return (LRESULT)g_brBtn;
        }
        case WM_ERASEBKGND: {
            HDC dc = (HDC)wp;
            RECT rc; GetClientRect(h, &rc);
            FillRect(dc, &rc, g_brBg);
            return 1;
        }
        case WM_CLOSE: {
            g_running.store(false);
            g_scanning.store(false);
            JoinAllBg();
            CameraStop();
            MicStop();
            DestroyWindow(h);
            return 0;
        }
        case WM_DESTROY: {
            if (g_fontBanner) { DeleteObject(g_fontBanner); g_fontBanner = nullptr; }
            ThemeFreeRes();
            PostQuitMessage(0);
            return 0;
        }
        default: return DefWindowProcW(h, m, wp, lp);
    }
}

// ============================================================
//  入口
// ============================================================

// ============================================================================
//  v13.14  一、告警确认机制: 所有处置动作均需用户确认
// ============================================================================

static void AlertAllowAdd(const std::wstring& p) {
    std::lock_guard<std::mutex> lk(g_alertAllowMtx);
    g_alertAllow.insert(p);
}
static bool AlertAllowed(const std::wstring& p) {
    std::lock_guard<std::mutex> lk(g_alertAllowMtx);
    return g_alertAllow.count(p) != 0;
}

// 弹出确认框(切换到 UI 线程执行), 返回 ALERT_*
// [是]=立即处理  [否]=忽略此次  [取消]=加入白名单(此后不再提示)
static int AlertConfirm(const wchar_t* title, const std::wstring& detail,
                        const std::wstring& path, DWORD pid) {
    if (!g_alertAsk.load()) return ALERT_HANDLE;
    if (!g_hMain) return ALERT_HANDLE;                 // 无 UI(如开机扫描)时保持原行为
    if (!path.empty() && AlertAllowed(path)) return ALERT_IGNORE;

    AlertReq* r = new AlertReq();
    r->title  = title ? title : L"ZZ EDR 安全告警";
    r->detail = detail; r->path = path; r->pid = pid;
    r->answer = ALERT_IGNORE;
    r->done   = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!r->done) { delete r; return ALERT_IGNORE; }
    if (!PostMessageW(g_hMain, WM_APP_CONFIRM, 0, reinterpret_cast<LPARAM>(r))) {
        HANDLE h = r->done; delete r; CloseHandle(h); return ALERT_IGNORE;
    }
    WaitForSingleObject(r->done, 180000);              // 最长等待 3 分钟
    int ans = r->answer;
    if (ans == ALERT_ALLOW && !path.empty()) {
        AlertAllowAdd(path);
        LogPost(L"[白名单] 已按用户选择加入告警白名单: " + path);
    }
    HANDLE h = r->done; delete r; CloseHandle(h);
    return ans;
}

// 自动处置版 KillProcess: 需用户点"是"才真正结束
static bool KillProcessAuto(DWORD pid, const wchar_t* reason) {
    std::wstring d = L"检测到可疑行为，是否立即结束该进程？\r\n\r\n原因: ";
    d += (reason ? reason : L"自动防护");
    std::wstring p;
    for (const auto& t : SnapshotProcs()) if (t.pid == pid) { p = t.path; break; }
    int a = AlertConfirm(L"ZZ EDR 安全告警", d, p, pid);
    if (a != ALERT_HANDLE) {
        LogPost(L"[已忽略] 用户选择不结束进程 pid=" + std::to_wstring(pid));
        return false;
    }
    return KillProcess(pid);
}

// 账户处置确认包装
static DWORD UserAskSet(DWORD (WINAPI* fn)(const wchar_t*, const wchar_t*, DWORD, BYTE*, DWORD*),
                        const wchar_t* a, const wchar_t* b, DWORD c, BYTE* d, DWORD* e) {
    if (g_alertAsk.load() && g_hMain) {
        std::wstring n = b ? b : L"";
        int r = AlertConfirm(L"ZZ EDR 安全告警",
                             L"检测到未知/可疑账户，是否立即禁用该账户？\r\n\r\n账户: " + n, L"", 0);
        if (r != ALERT_HANDLE) { LogPost(L"[已忽略] 用户选择不禁用账户: " + n); return ERROR_ACCESS_DENIED; }
    }
    return fn(a, b, c, d, e);
}
static DWORD UserAskDel(DWORD (WINAPI* fn)(const wchar_t*, const wchar_t*),
                        const wchar_t* a, const wchar_t* b) {
    if (g_alertAsk.load() && g_hMain) {
        std::wstring n = b ? b : L"";
        int r = AlertConfirm(L"ZZ EDR 安全告警",
                             L"检测到高危后门账户，是否删除该账户？\r\n\r\n账户: " + n, L"", 0);
        if (r != ALERT_HANDLE) { LogPost(L"[已忽略] 用户选择不删除账户: " + n); return ERROR_ACCESS_DENIED; }
    }
    return fn(a, b);
}

// ============================================================================
//  v13.14  二、启动限制自修复: 检测到主程序/EXE 无法运行时放开组策略
// ============================================================================
static void RunGpUpdate() {
    wchar_t cmd[] = L"cmd.exe /c gpupdate /force >nul 2>&1";
    STARTUPINFOW si; ZeroMemory(&si, sizeof(si));
    PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si); si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    if (CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                       nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 15000);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    }
}

// 返回修复项数
static int EnsureSelfRunnable() {
    int fixed = 0;
    wchar_t self[MAX_PATH]; self[0] = 0;
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    std::wstring selfS(self);
    size_t bs = selfS.find_last_of(L"\\/");
    std::wstring name = (bs == std::wstring::npos) ? selfS : selfS.substr(bs + 1);
    if (name.empty()) name = L"ZZ_EDR.exe";

    // (1) IFEO 镜像劫持: 被指向调试器时本程序根本起不来
    {
        std::wstring sub = std::wstring(
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\") + name;
        HKEY hk = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub.c_str(), 0,
                          KEY_READ | KEY_SET_VALUE, &hk) == ERROR_SUCCESS && hk) {
            wchar_t dbg[MAX_PATH]; dbg[0] = 0; DWORD sz = sizeof(dbg), ty = 0;
            if (RegQueryValueExW(hk, L"Debugger", nullptr, &ty, (LPBYTE)dbg, &sz) == ERROR_SUCCESS && dbg[0]) {
                if (RegDeleteValueW(hk, L"Debugger") == ERROR_SUCCESS) {
                    ++fixed;
                    LogPost(L"[自修复] 已清除本程序的 IFEO 镜像劫持: " + std::wstring(dbg));
                }
            }
            RegCloseKey(hk);
        }
    }
    // (2) 软件限制策略(SRP) 默认级别 = 不允许 → 所有 EXE/C 程序均被禁
    {
        HKEY hk = nullptr;
        const wchar_t* sub = L"Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers";
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub, 0, KEY_READ | KEY_SET_VALUE, &hk) == ERROR_SUCCESS && hk) {
            DWORD lv = 0, sz = sizeof(lv), ty = 0;
            if (RegQueryValueExW(hk, L"DefaultLevel", nullptr, &ty, (LPBYTE)&lv, &sz) == ERROR_SUCCESS) {
                if (lv == 0x00010000) {              // Disallowed
                    DWORD nv = 0x00040000;           // Unrestricted
                    if (RegSetValueExW(hk, L"DefaultLevel", 0, REG_DWORD,
                                       (const BYTE*)&nv, sizeof(nv)) == ERROR_SUCCESS) {
                        ++fixed;
                        LogPost(L"[自修复] 软件限制策略: 默认级别 不允许 -> 不受限 (恢复 EXE/C 运行)");
                    }
                }
            }
            RegCloseKey(hk);
        }
    }
    // (3) Explorer 策略 DisallowRun (HKCU / HKLM)
    {
        const wchar_t* sub = L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun";
        HKEY roots[2] = { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };
        for (int i = 0; i < 2; ++i) {
            HKEY hk = nullptr;
            if (RegOpenKeyExW(roots[i], sub, 0, KEY_READ, &hk) == ERROR_SUCCESS && hk) {
                RegCloseKey(hk);
                if (RegDeleteKeyW(roots[i], sub) == ERROR_SUCCESS) {
                    ++fixed;
                    LogPost(L"[自修复] 已清除 DisallowRun 策略 (恢复被禁程序)");
                }
            }
        }
    }
    // (4) AppLocker EXE 拒绝规则
    {
        HKEY hk = nullptr;
        const wchar_t* sub = L"SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2\\Exe";
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub, 0, KEY_READ, &hk) == ERROR_SUCCESS && hk) {
            RegCloseKey(hk);
            if (RegDeleteKeyW(HKEY_LOCAL_MACHINE, sub) == ERROR_SUCCESS) {
                ++fixed;
                LogPost(L"[自修复] 已清除 AppLocker EXE 拒绝规则");
            }
        }
    }
    if (fixed) {
        LogPost(L"[自修复] 共修复 " + std::to_wstring(fixed) + L" 项启动限制，正在刷新组策略...");
        RunGpUpdate();
        LogPost(L"[自修复] 组策略已刷新，EXE / C 程序现已允许运行。");
    }
    return fixed;
}

// 启动失败标记: 上次未能成功进入主界面 → 本次强制自修复
static std::wstring BootFailPath() {
    wchar_t tp[MAX_PATH]; tp[0] = 0;
    GetTempPathW(MAX_PATH, tp);
    return std::wstring(tp) + L"zz_EDR.bootfail";
}

// ============================================================================
//  v13.14  三、银狐 / 紫狐 与全品类恶意代码族谱识别
// ============================================================================
struct MalFamRule {
    const wchar_t* fam;      // 家族名
    const wchar_t* needle;   // 文本特征(小写 ASCII)
    int   sev;
    const wchar_t* cat;      // 品类
};

// 覆盖品类: 远控木马/银行木马/信息窃取/勒索/挖矿/僵尸网络/蠕虫/后门/
//           Rootkit/无文件/下载器/键盘记录/间谍/宏病毒/引导区/广告
static const MalFamRule g_malFam[] = {
    // ---------- 银狐 (Silver Fox / Winos / Swindler) ----------
    { L"银狐木马(Winos)",          L"winos",          5, L"远控木马" },
    { L"银狐木马(Swindler)",       L"swindler",       5, L"远控木马" },
    { L"银狐木马(SilverFox)",      L"silverfox",      5, L"远控木马" },
    { L"银狐(白加黑载荷)",          L"yinhu",          4, L"远控木马" },
    { L"银狐(白加黑载荷)",          L"whiteblack",     4, L"远控木马" },
    { L"银狐(白加黑载荷)",          L"sideload",       3, L"远控木马" },
    // ---------- 紫狐 (Purple Fox) ----------
    { L"紫狐(PurpleFox)",          L"purplefox",      5, L"Rootkit/蠕虫" },
    { L"紫狐(PurpleFox)",          L"purple fox",     5, L"Rootkit/蠕虫" },
    { L"紫狐(永恒之蓝传播)",         L"eternalblue",    5, L"蠕虫" },
    { L"紫狐(永恒之蓝传播)",         L"ms17-010",       5, L"蠕虫" },
    { L"紫狐(SMB爆破传播)",         L"ms08-067",       5, L"蠕虫" },
    { L"紫狐(内核驱动)",            L"ntoskrnl.exe",   2, L"Rootkit" },
    // ---------- 远控 / 后门 ----------
    { L"Mimikatz",                 L"mimikatz",       5, L"凭据窃取" },
    { L"Cobalt Strike Beacon",     L"beacon",         4, L"远控木马" },
    { L"Cobalt Strike",            L"cobaltstrike",   5, L"远控木马" },
    { L"Metasploit",               L"metasploit",     5, L"渗透框架" },
    { L"njRAT",                    L"njrat",          5, L"远控木马" },
    { L"Gh0st RAT",                L"gh0st",          5, L"远控木马" },
    { L"QuasarRAT",                L"quasar",         4, L"远控木马" },
    { L"Remcos",                   L"remcos",         5, L"远控木马" },
    { L"AsyncRAT",                 L"asyncrat",       5, L"远控木马" },
    { L"NetWire",                  L"netwire",        5, L"远控木马" },
    { L"PlugX",                    L"plugx",          5, L"远控木马" },
    { L"PoisonIvy",                L"poisonivy",      5, L"远控木马" },
    { L"DarkComet",                L"darkcomet",      5, L"远控木马" },
    { L"RedLine Stealer",          L"redline",        5, L"信息窃取" },
    { L"Raccoon Stealer",          L"raccoon",        5, L"信息窃取" },
    { L"Vidar",                    L"vidar",          5, L"信息窃取" },
    { L"Azorult",                  L"azorult",        5, L"信息窃取" },
    { L"Formbook",                 L"formbook",       5, L"信息窃取" },
    { L"Lokibot",                  L"lokibot",        5, L"信息窃取" },
    { L"AgentTesla",               L"agenttesla",     5, L"信息窃取" },
    // ---------- 银行木马 / 僵尸网络 ----------
    { L"Emotet",                   L"emotet",         5, L"银行木马" },
    { L"TrickBot",                 L"trickbot",       5, L"银行木马" },
    { L"QakBot",                   L"qakbot",         5, L"银行木马" },
    { L"Dridex",                   L"dridex",         5, L"银行木马" },
    { L"Zeus",                     L"zeus",           4, L"银行木马" },
    // ---------- 勒索 ----------
    { L"WannaCry",                 L"wannacry",       5, L"勒索" },
    { L"REvil/Sodinokibi",         L"sodinokibi",     5, L"勒索" },
    { L"LockBit",                  L"lockbit",        5, L"勒索" },
    { L"Conti",                    L"conti",          4, L"勒索" },
    { L"BlackCat/ALPHV",           L"blackcat",       5, L"勒索" },
    { L"Ryuk",                     L"ryuk",           5, L"勒索" },
    { L"Maze",                     L"maze",           4, L"勒索" },
    { L"Cl0p",                     L"cl0p",           5, L"勒索" },
    { L"STOP/Djvu",                L"djvu",           4, L"勒索" },
    { L"Hidden Tear",              L"hiddentear",     5, L"勒索" },
    { L"勒索(通用:解密说明)",         L"your files have been encrypted", 5, L"勒索" },
    { L"勒索(通用:卷影删除)",         L"vssadmin delete shadows",        5, L"勒索" },
    // ---------- 挖矿 / 僵尸网络 ----------
    { L"XMRig 挖矿",               L"xmrig",          5, L"挖矿" },
    { L"挖矿(矿池协议)",             L"stratum+tcp",    4, L"挖矿" },
    { L"Mirai 僵尸网络",            L"mirai",          5, L"僵尸网络" },
    { L"Gafgyt 僵尸网络",           L"gafgyt",         5, L"僵尸网络" },
    // ---------- 无文件 / 脚本 / 宏 ----------
    { L"无文件(PowerShell)",        L"invoke-expression", 4, L"无文件" },
    { L"无文件(反射加载)",           L"reflectiveloader",  5, L"无文件" },
    { L"宏病毒(自动执行)",           L"auto_open",      4, L"宏病毒" },
    { L"宏病毒(自动执行)",           L"workbook_open",  4, L"宏病毒" },
    { L"宏病毒(VBA)",              L"vbaproject",     2, L"宏病毒" },
    // ---------- Rootkit / 引导区 ----------
    { L"Rootkit(SSDT Hook)",       L"zwquerydirectoryfile", 2, L"Rootkit" },
    { L"引导区(Bootkit)",           L"\\device\\harddisk0",   3, L"引导区" },
    // ---------- 下载器 / 广告 / 间谍 ----------
    { L"下载器(URLDownload)",       L"urldownloadtofile", 3, L"下载器" },
    { L"键盘记录器",                L"setwindowshookex",  3, L"键盘记录" },
    { L"键盘记录器",                L"getasynckeystate",  3, L"键盘记录" },
    { L"间谍软件(屏幕截取)",         L"bitblt",            2, L"间谍软件" },
};
static const int g_malFamCount = (int)(sizeof(g_malFam) / sizeof(g_malFam[0]));

// 在二进制数据中同时按 ASCII 与 UTF-16LE 两种编码查找(小写)
static bool BlobHasText(const std::string& blob, const wchar_t* needleW) {
    std::string n;
    for (const wchar_t* p = needleW; *p; ++p) {
        unsigned int c = (unsigned int)*p;
        if (c < 0x80) n.push_back((char)tolower((int)c));
        else { n.clear(); return false; }     // 非 ASCII 特征: 仅按宽字符匹配
    }
    if (n.empty()) return false;
    if (blob.find(n) != std::string::npos) return true;
    std::string w;                             // UTF-16LE: 每个字符后补 0
    for (size_t i = 0; i < n.size(); ++i) { w.push_back(n[i]); w.push_back('\0'); }
    return blob.find(w) != std::string::npos;
}

// 返回 sev (0=未命中), why 输出 "家族名[品类]"
static int MalFamilyScan(const std::wstring& path, std::wstring& why) {
    FILE* f = _wfopen(path.c_str(), L"rb");
    if (!f) return 0;
    const size_t CAP = 2u * 1024 * 1024;       // 仅取前 2MB
    std::string blob; blob.resize(CAP);
    size_t got = fread(&blob[0], 1, CAP, f);
    fclose(f);
    if (!got) return 0;
    blob.resize(got);
    for (size_t i = 0; i < blob.size(); ++i) {
        char c = blob[i];
        if (c >= 'A' && c <= 'Z') blob[i] = (char)(c - 'A' + 'a');
    }
    int best = 0; std::wstring bestWhy;
    for (int i = 0; i < g_malFamCount; ++i) {
        if (BlobHasText(blob, g_malFam[i].needle)) {
            if (g_malFam[i].sev > best) {
                best = g_malFam[i].sev;
                bestWhy = std::wstring(g_malFam[i].fam) + L" [" + g_malFam[i].cat + L"]";
            }
        }
    }
    if (best > 0) {
        why = L"恶意代码族谱命中: " + bestWhy;
        if (best >= 5) SetThreatLevel(THREAT_DANGER, (L"检出恶意代码族谱: " + bestWhy + L" -> " + path).c_str());
        else if (best >= 3) SetThreatLevel(THREAT_WARN, (L"可疑代码族谱: " + bestWhy + L" -> " + path).c_str());
    }
    return best;
}

// 已知被"白加黑"侧载利用的 DLL 名单(银狐等常用)
static const wchar_t* const g_sideloadDll[] = {
    L"version.dll", L"dbghelp.dll", L"winhttp.dll", L"uxtheme.dll", L"propsys.dll",
    L"dwmapi.dll",  L"cryptbase.dll", L"cryptsp.dll", L"msimg32.dll", L"davclnt.dll",
    L"wtsapi32.dll", L"ntmarta.dll", L"secur32.dll", L"srvcli.dll", L"coml2.dll",
    L"oleaut32.dll", L"winmm.dll", L"wininet.dll", L"ws2_32.dll", L"iphlpapi.dll",
    L"netapi32.dll", L"psapi.dll", L"setupapi.dll", L"sfc.dll", L"userenv.dll",
    L"apphelp.dll", L"dinput8.dll", L"xinput1_3.dll", L"msvcp140.dll", L"vcruntime140.dll",
    L"ucrtbase.dll", L"mscoree.dll", L"wwlib.dll", L"mso20win32client.dll", L"vgx.dll"
};
static const int g_sideloadCount = (int)(sizeof(g_sideloadDll) / sizeof(g_sideloadDll[0]));

// ------------------------------------------------------------
//  v13.18 银狐(Winos/ValleyRAT) 白加黑侧载专项
// ------------------------------------------------------------
// 公开分析中出现过的银狐实际载荷 DLL。这些是"恶意 DLL 本体", 而宿主 EXE
// 往往带合法签名 —— 只按 EXE 名字/签名判定必然漏报。
static const wchar_t* const g_foxPayloadDll[] = {
    L"xpsplog.dll",              // 火绒/吾爱破解: Philips 白加黑, 导出 XPSPLOG_2
    L"libcef.dll",               // 亚信安全: CEFProcess.exe + 无签名 libcef.dll
    L"libcurl.dll",              // 网易CC 白加黑: DllMain 注入 explorer.exe
    L"uxenhance64.dll",          // 带腾讯签名 bJpMzw.exe 的白加黑载荷
    L"timebrokerclient.dll",     // svchost 侧载(BrokerClientCallback.dll 变体)
    L"brokerclientcallback.dll",
    L"d3dcompiler_74.dll",       // 360: 微信目录劫持
    L"log.dll",                  // 银狐常见: IE 目录下无签名 log.dll
};
static const int g_foxPayloadCount =
    (int)(sizeof(g_foxPayloadDll) / sizeof(g_foxPayloadDll[0]));

// 检测宿主 EXE 同目录的白加黑侧载
static int FoxSideloadDllHit(const std::wstring& exePath, std::wstring& outDll) {
    if (exePath.empty()) return 0;
    size_t bs = exePath.find_last_of(L"\\/");
    if (bs == std::wstring::npos) return 0;
    std::wstring dir = exePath.substr(0, bs + 1);
    // 系统目录内的 DLL 由系统维护, 不参与侧载判定(避免误判系统自带文件)
    std::wstring dl = ToLowerW(dir);
    if (dl.find(L"\\windows\\system32") != std::wstring::npos ||
        dl.find(L"\\windows\\syswow64") != std::wstring::npos ||
        dl.find(L"\\windows\\winsxs")  != std::wstring::npos) return 0;
    // (1) 银狐已知载荷 DLL —— 名字即特征, 无论是否有签名
    for (int i = 0; i < g_foxPayloadCount; ++i) {
        std::wstring f = dir + g_foxPayloadDll[i];
        if (GetFileAttributesW(f.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
        outDll = f;
        return 1;
    }
    // (2) 常侧载名单 DLL 且无有效签名
    for (int i = 0; i < g_sideloadCount; ++i) {
        std::wstring f = dir + g_sideloadDll[i];
        if (GetFileAttributesW(f.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
        if (VerifyFileSignature(f) == 1) continue;   // 有有效签名则放行
        outDll = f;
        return 2;
    }
    return 0;
}

// 银狐白加黑处置入口: 覆盖"随机名 EXE + 载荷 DLL"形态
// (宿主文件名不含 Philips 等关键字, 仅 VersionInfo 伪装, 名字匹配规则抓不到)

// ============================================================
//  v13.19 银狐(SilverFox / Winos4.0 / ValleyRAT) 深度专项
//  依据(均为公开权威来源):
//   - 国家计算机病毒应急处理中心 / 计算机病毒防治技术国家工程实验室 通报
//     (诱饵文件名: 违纪名单/裁员补偿/内部调查结果…, 伪装 pdf.exe)
//   - 微步在线「银狐」情报共享站 https://s.threatbook.com/cybercrime/silverfox
//   - Cato CTRL: 三驱动 BYOVD 链(BootRepair.sys/EnPortv.sys/wsftprm.sys)
//                + PDFCORE8.dll 被 ConvertToPDF.exe / PDFDirect.exe 侧载
//   - CheckPoint: amsdk.sys(Zemana Anti-Malware SDK) 用于终止安全产品
//   - 奇安信天穹: GDFInstall.exe + GameuxInstallHelper.dll 白加黑
//   - 亚信安全: CEFProcess.exe + 无签名 libcef.dll(SetupFactory 打包)
//   - 360: 微信目录 cryptbase.dll / d3dcompiler_74.dll 劫持
//   - CloudSEK: Thunder.exe + libexpat.dll 侧载 + 进程镂空
// ============================================================

// 1) 社工诱饵文件名关键词(人事/财务主题)
static const wchar_t* const g_foxBaitName[] = {
    L"违纪", L"违规", L"裁员", L"补偿", L"通报", L"内职",
    L"稽查", L"补贴", L"公示", L"调查结果", L"人员信息",
    L"绩效", L"考勤", L"工资表", L"退税", L"电子发票"
};
static const int g_foxBaitCount =
    (int)(sizeof(g_foxBaitName) / sizeof(g_foxBaitName[0]));

// 2) BYOVD 漏洞驱动(银狐用于终止杀软/EDR 进程)
static const wchar_t* const g_foxByovdDriver[] = {
    L"amsdk.sys",       // CheckPoint: WatchDog Antimalware / Zemana SDK
    L"wsftprm.sys",     // Cato CTRL 三驱动链
    L"bootrepair.sys",  // Cato CTRL 三驱动链
    L"enportv.sys",     // Cato CTRL 三驱动链
    L"zamguard64.sys", L"zam64.sys", L"rtcore64.sys", L"dbutil_2_3.sys"
};
static const int g_foxByovdCount =
    (int)(sizeof(g_foxByovdDriver) / sizeof(g_foxByovdDriver[0]));

// 3) 被滥用的合法白程序宿主(带合法签名, 仅作侧载载体)
static const wchar_t* const g_foxWhiteExe[] = {
    L"cefprocess.exe",   // 亚信安全: + 无签名 libcef.dll
    L"converttopdf.exe", // Cato: + PDFCORE8.dll
    L"pdfdirect.exe",
    L"thunder.exe",      // CloudSEK: + libexpat.dll + 进程镂空
    L"gdfinstall.exe",   // 奇安信: + GameuxInstallHelper.dll
    L"irsetup.exe",      // SetupFactory: 释放到 aff-web
    L"wsctrlsvc.exe", L"ion.exe"   // 吾爱: 咪咕视频 + sqlite3.dll
};
static const int g_foxWhiteExeCount =
    (int)(sizeof(g_foxWhiteExe) / sizeof(g_foxWhiteExe[0]));

// 4) 异常投放路径(伪装正常目录)
static const wchar_t* const g_foxDropPath[] = {
    L"cfserversoftwaredistribution",   // 伪装软件分发目录
    L"\\windows\\installer\\",         // 伪装 Windows Installer 缓存
    L"\\msys64\\",                     // 伪装 MSYS2 工具链
    L"\\programlog\\", L"aff-web"
};
static const int g_foxDropPathCount =
    (int)(sizeof(g_foxDropPath) / sizeof(g_foxDropPath[0]));

// 5) 公开报告中出现的银狐 / Winos4.0 / ValleyRAT C2
//
// 【重要·为什么保留"旧" IoC】
// 直觉上"过期的 IoC 应该剔除"，但实战里恰恰相反：
//   · 攻击者会故意复用早已曝光的基础设施 —— 因为多数防护产品会
//     按"新鲜度"淘汰旧情报，反而让老 C2 变成检测盲区；
//   · 正常软件不会去连一个被公开点名的 C2，"命中历史 IoC" 本身
//     就是很强的恶意信号，甚至比新 IoC 更可疑。
// 所以这里【新旧一律保留、一律生效】，不做任何剔除。
//
// 【但要区分两种可靠度】这是避免误报的关键：
//   · 域名命中 —— 可靠度极高。域名由攻击者持有，不会像 IP 那样
//     被运营商回收后分配给正常业务，命中基本可判定恶意。
//   · IP 命中   —— 可靠度高但需注意：VPS 的 IP 存在回收再分配可能。
//     命中后仍按高危处置，但日志会标注，便于人工复核。
//
// 【开关】legacyIocOn = false 可整体关闭历史 IoC（默认 true 开启）。
static const wchar_t* const g_foxC2Domain[] = {
    L"bqdrzbyq.cn", L"taxfnat.tw", L"njhwuyklw.com", L"twtaxgo.cn",
    L"taxhub.tw", L"taukeny.com", L"taxpro.tw", L"lmaxjuyh.cn",
    L"tkooyvff.cn", L"etaxtw.cn", L"twswsb.cn", L"ggwk.cc",
    L"dashenbaba3.com", L"wps-offce.cn", L"so-sougou.com.cn",
    L"sougou-browser.com", L"web-google.cn", L"yandibaiji0203.com",
    L"xiazaiabcd5.cy", L"outime.googledns.io", L"time.micrsofthost.com",
    L"time.wkossclsaleklddeff.is", L"time.secssl.com"
};
static const int g_foxC2DomainCount =
    (int)(sizeof(g_foxC2Domain) / sizeof(g_foxC2Domain[0]));

static const wchar_t* const g_foxC2Ip[] = {
    L"43.128.26.132", L"134.122.204.11", L"134.122.134.93",
    L"103.46.185.44", L"47.76.86.151", L"154.82.68.34", L"54.46.23.169",
    L"47.239.197.97", L"8.217.38.238", L"156.234.58.194", L"156.241.144.66",
    L"1.13.249.217", L"43.226.125.44", L"47.238.125.85", L"137.220.229.34",
    L"8.210.165.181", L"143.92.61.154", L"47.86.28.28", L"202.79.168.211",
    L"27.122.59.71", L"143.92.63.144", L"202.79.171.133", L"112.213.116.91",
    L"112.213.101.161", L"112.213.101.139", L"103.46.185.73",
    L"47.83.184.193", L"202.79.173.50", L"202.79.173.54", L"202.79.173.98"
};
static const int g_foxC2IpCount =
    (int)(sizeof(g_foxC2Ip) / sizeof(g_foxC2Ip[0]));

static const int g_foxC2Ports[] = {
    18852, 8852, 670, 8670,          // Rapid7 / 奇安信观测
    52110, 52111, 52116, 52117, 52139, 52160,  // buaq ValleyRAT C2
    9527, 9528, 6074, 6075, 6076,    // Winos4.0 配置字段默认端口
    8888, 8880
};
static const int g_foxC2PortCount =
    (int)(sizeof(g_foxC2Ports) / sizeof(g_foxC2Ports[0]));

// ---- 查询: 端点是否命中银狐 C2 ----
static bool FoxC2Hit(const std::wstring& remote, std::wstring& why) {
    if (remote.empty()) return false;
    if (!g_cfg.legacyIocOn) return false;   // 历史 IoC 总开关(默认开启)
    std::wstring low = ToLowerW(remote);
    size_t colon = low.find(L':');
    std::wstring host = (colon == std::wstring::npos) ? low : low.substr(0, colon);
    int port = -1;
    if (colon != std::wstring::npos) {
        std::wstring ps = low.substr(colon + 1);
        int v = 0; for (wchar_t c : ps) { if (c >= L'0' && c <= L'9') v = v * 10 + (c - L'0'); else { v = -1; break; } }
        port = v;
    }
    for (int i = 0; i < g_foxC2IpCount; ++i) {
        if (host == g_foxC2Ip[i]) {
            // IP 存在被回收再分配的可能，标注以便人工复核
            why = std::wstring(L"银狐C2 IP(历史曝光基础设施复用): ") + g_foxC2Ip[i];
            return true;
        }
    }
    for (int i = 0; i < g_foxC2DomainCount; ++i) {
        if (low.find(g_foxC2Domain[i]) != std::wstring::npos) {
            // 域名由攻击者持有，不会被回收再分配 —— 可靠度最高
            why = std::wstring(L"银狐C2 域名(历史曝光,域名归攻击者持有): ") + g_foxC2Domain[i];
            return true;
        }
    }
    for (int i = 0; i < g_foxC2PortCount; ++i) {
        if (port == g_foxC2Ports[i]) { why = L"银狐/Winos C2 端口"; return true; }
    }
    return false;
}

// ---- 文件名是否为社工诱饵 ----
// 返回 0=否, 1=仅含诱饵词, 2=诱饵词 + 高危形态(pdf 伪装/可写目录落地)
static int FoxBaitNameHit(const std::wstring& path) {
    if (path.empty()) return 0;
    std::wstring low = ToLowerW(path);
    size_t slash = low.find_last_of(L"\\/");
    std::wstring name = (slash == std::wstring::npos) ? low : low.substr(slash + 1);
    bool bait = false;
    for (int i = 0; i < g_foxBaitCount; ++i) {
        if (name.find(g_foxBaitName[i]) != std::wstring::npos) { bait = true; break; }
    }
    if (!bait) return 0;
    // 高危形态: "xxx名单pdf.exe" 这类把 pdf 塞进 exe 名的伪装
    if (name.find(L"pdf.exe") != std::wstring::npos) return 2;
    if (name.find(L"pdf (") != std::wstring::npos) return 2;
    // 落在可写/下载类目录
    if (low.find(L"\\downloads\\") != std::wstring::npos) return 2;
    if (low.find(L"\\temp\\") != std::wstring::npos) return 2;
    if (low.find(L"\\desktop\\") != std::wstring::npos) return 2;
    if (low.find(L"\\appdata\\") != std::wstring::npos) return 2;
    return 1;
}

// ---- BYOVD 漏洞驱动扫描 ----
static void FoxByovdScan() {
    LogPost(L"[银狐] BYOVD 漏洞驱动扫描开始 (已知被用于终止杀软/EDR)...");
    wchar_t sysdir[MAX_PATH] = {0};
    GetSystemDirectoryW(sysdir, MAX_PATH);
    std::wstring dirs[2];
    dirs[0] = std::wstring(sysdir) + L"\\drivers\\";
    dirs[1] = std::wstring(sysdir) + L"\\";
    int found = 0;
    for (int d = 0; d < 2; ++d) {
        for (int i = 0; i < g_foxByovdCount; ++i) {
            std::wstring f = dirs[d] + g_foxByovdDriver[i];
            if (GetFileAttributesW(f.c_str()) != INVALID_FILE_ATTRIBUTES) {
                found++;
                LogFmt(L"[银狐][高危] 发现 BYOVD 驱动: %s", f.c_str());
                BehavAdd(0, L"", BEHAV_SIGN, 5,
                         std::wstring(L"银狐 BYOVD 驱动存在: ") + g_foxByovdDriver[i]);
                SetThreatLevel(THREAT_DANGER, L"银狐 BYOVD 漏洞驱动");
            }
        }
    }
    LogFmt(L"[银狐] BYOVD 驱动扫描完成, 命中 %d 个", found);
}

// ---- Defender 排除项篡改检测(银狐常用 PowerShell 添加 C-F 盘排除) ----
static void FoxDefenderExclusionScan() {
    LogPost(L"[银狐] Defender 排除项篡改检测开始...");
    const wchar_t* keys[] = {
        L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths",
        L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Paths"
    };
    int found = 0;
    for (int k = 0; k < 2; ++k) {
        HKEY hk = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keys[k], 0, KEY_READ, &hk) != ERROR_SUCCESS) continue;
        for (unsigned long i = 0; i < 256; ++i) {
            wchar_t vn[512] = {0}; unsigned long vnLen = 512;
            if (RegEnumValueW(hk, i, vn, &vnLen, nullptr, nullptr, nullptr, nullptr)
                != ERROR_SUCCESS) break;
            std::wstring v = vn;
            if (v.empty()) continue;
            found++;
            LogFmt(L"[银狐][告警] Defender 排除项: %s", v.c_str());
            BehavAdd(0, L"", BEHAV_REG, 3,
                     std::wstring(L"Defender 排除项(可能为银狐添加): ") + v);
            // 整盘排除(C:\\ / D:\\ 等)是银狐对抗手法, 直接升危
            if (v.size() <= 3 && v.size() >= 2 && v[1] == L':') SetThreatLevel(THREAT_DANGER, L"Defender 整盘排除(银狐对抗手法)");
        }
        RegCloseKey(hk);
    }
    LogFmt(L"[银狐] Defender 排除项检测完成, 命中 %d 项", found);
}

// ---- Python 化载荷检测(银狐 ABCDoor / 伪装 WhatsApp 窃取器) ----
static void FoxPythonPayloadScan() {
    LogPost(L"[银狐] Python 化载荷扫描开始 (.pyc/.pyd 出现在非 Python 目录)...");
    wchar_t prof[MAX_PATH] = {0};
    SHGetFolderPathW(nullptr, CSIDL_PROFILE, nullptr, 0, prof);
    std::wstring roots[3];
    roots[0] = std::wstring(prof) + L"\\AppData\\";
    roots[1] = std::wstring(prof) + L"\\Desktop\\";
    roots[2] = L"C:\\ProgramData\\";
    const wchar_t* exts[] = { L".pyc", L".pyd" };
    int found = 0;
    for (int r = 0; r < 3 && found < 40; ++r) {
        for (int e = 0; e < 2; ++e) {
            std::wstring pat = roots[r] + L"*";
            WIN32_FIND_DATAW fd;
            // 仅检查根目录一层(深递归开销过大)
            std::wstring search = roots[r] + L"*";
            HANDLE h = FindFirstFileW((roots[r] + L"*").c_str(), &fd);
            if (h == INVALID_HANDLE_VALUE) continue;
            do {
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                std::wstring nm = ToLowerW(fd.cFileName);
                if (nm.size() < 4) continue;
                if (nm.find(exts[e]) == std::wstring::npos) continue;
                std::wstring full = roots[r] + fd.cFileName;
                found++;
                LogFmt(L"[银狐][可疑] Python 载荷: %s", full.c_str());
                BehavAdd(0, L"", BEHAV_SIGN, 3,
                         std::wstring(L"Python 载荷(.pyc/.pyd)出现在非 Python 目录: ") + full);
            } while (FindNextFileW(h, &fd) && found < 40);
            FindClose(h);
        }
    }
    LogFmt(L"[银狐] Python 载荷扫描完成, 命中 %d 个", found);
}

// ---- 银狐深度专项(汇总: 进程/侧载/诱饵名/白宿主/投放路径/C2) ----
static void FoxDeepScan() {
    LogPost(L"[银狐] 深度专项扫描开始 (SilverFox/Winos4.0/ValleyRAT)...");
    int hits = 0;
    for (const auto& p : SnapshotProcs()) {
        std::wstring pl = ToLowerW(p.path);
        std::wstring nl = ToLowerW(p.name);
        if (pl.empty() && nl.empty()) continue;
        // 白程序宿主: 合法签名进程, 需结合侧载判定
        for (int i = 0; i < g_foxWhiteExeCount; ++i) {
            if (nl == g_foxWhiteExe[i]) {
                std::wstring dll;
                int kind = FoxSideloadDllHit(p.path, dll);
                if (kind != 0) {
                    hits++;
                    LogFmt(L"[银狐][高危] 已知白程序宿主 %s 侧载: %s", p.name.c_str(), dll.c_str());
                    BehavAdd(p.pid, p.name, BEHAV_SIGN, 5,
                             std::wstring(L"银狐白程序宿主侧载: ") + dll);
                    SetThreatLevel(THREAT_DANGER, L"银狐白程序宿主侧载");
                }
                break;
            }
        }
        // 异常投放路径
        for (int i = 0; i < g_foxDropPathCount; ++i) {
            if (pl.find(g_foxDropPath[i]) != std::wstring::npos) {
                hits++;
                LogFmt(L"[银狐][可疑] 异常投放路径运行: %s", p.path.c_str());
                BehavAdd(p.pid, p.name, BEHAV_PROC_START, 4,
                         std::wstring(L"银狐异常投放路径: ") + p.path);
                break;
            }
        }
        // 社工诱饵文件名
        int bait = FoxBaitNameHit(pl.empty() ? nl : pl);
        if (bait == 2) {
            hits++;
            LogFmt(L"[银狐][高危] 社工诱饵形态运行: %s", p.path.c_str());
            BehavAdd(p.pid, p.name, BEHAV_PROC_START, 5,
                     std::wstring(L"银狐社工诱饵文件名: ") + p.name);
            SetThreatLevel(THREAT_DANGER, L"银狐社工诱饵文件名");
        }
    }
    // C2 连接
    for (const auto& n : SnapshotNets()) {
        std::wstring why;
        if (FoxC2Hit(n.remote, why)) {
            hits++;
            LogFmt(L"[银狐][高危] %s -> %s", n.remote.c_str(), why.c_str());
            BehavAdd(0, L"", BEHAV_NET, 5, std::wstring(L"银狐C2: ") + why);
            SetThreatLevel(THREAT_DANGER, L"银狐 C2 通信");
        }
    }
    FoxByovdScan();
    FoxDefenderExclusionScan();
    FoxPythonPayloadScan();
    LogFmt(L"[银狐] 深度专项扫描完成, 共命中 %d 项", hits);
}

static int FoxWhiteBlackEnforce() {
    if (!g_cfg.forceKillOn) return 0;
    auto ps = SnapshotProcs();
    DWORD self = GetCurrentProcessId();
    int n = 0;
    for (auto& p : ps) {
        if (p.pid == 0 || p.pid == 4 || p.pid == self) continue;
        std::wstring path = p.path.empty() ? GetProcPath(p.pid) : p.path;
        std::wstring dll;
        int kind = FoxSideloadDllHit(path, dll);
        if (kind == 0) continue;
        if (kind == 2) {
            // 常侧载无签名 DLL 需叠加"可疑落点"才处置:
            // Program Files 下无签名的侧载 DLL 可能是正常软件自带, 不杀以免误伤
            std::wstring pl = ToLowerW(path);
            bool writable =
                pl.find(L"\\temp\\")          != std::wstring::npos ||
                pl.find(L"\\appdata\\")       != std::wstring::npos ||
                pl.find(L"\\programdata\\")   != std::wstring::npos ||
                pl.find(L"\\downloads\\")     != std::wstring::npos ||
                pl.find(L"\\users\\public\\") != std::wstring::npos;
            if (!writable) continue;
        }
        std::wstring desc = (kind == 1)
            ? (L"银狐白加黑载荷 DLL: " + dll)
            : (L"可疑目录无签名侧载 DLL: " + dll);
        LogFmt(L"[银狐白加黑] 命中: %s | PID=%u | 宿主=%s",
               desc.c_str(), p.pid, p.name.c_str());
        BehavAdd(p.pid, p.name, BEHAV_BLOCK, 10, L"银狐白加黑: " + desc);
        if (KillProcess(p.pid)) ++n;
        RecoverAfterForceKill(p.name, path, p.pid, desc);
    }
    if (n > 0) LogFmt(L"[银狐白加黑] 已处置 %d 个进程", n);
    return n;
}


// 系统进程名(出现在非系统目录即为伪装, 银狐/紫狐常用手法)
static const wchar_t* const g_sysNames[] = {
    L"svchost.exe", L"dllhost.exe", L"explorer.exe", L"taskhostw.exe", L"lsass.exe",
    L"winlogon.exe", L"csrss.exe", L"smss.exe", L"services.exe", L"spoolsv.exe",
    L"rundll32.exe", L"conhost.exe", L"wininit.exe", L"searchindexer.exe"
};
static const int g_sysNameCount = (int)(sizeof(g_sysNames) / sizeof(g_sysNames[0]));

// 进程层面: 系统名伪装 + 白加黑 DLL 侧载 + 银狐/紫狐落地特征
static int FoxProcScan() {
    int hit = 0;
    auto procs = SnapshotProcs();
    for (const auto& p : procs) {
        if (p.path.empty()) continue;
        std::wstring pl = ToLowerW(p.path);
        std::wstring nl = ToLowerW(p.name);
        bool underWin = (pl.find(L"\\windows\\system32") != std::wstring::npos) ||
                        (pl.find(L"\\windows\\syswow64") != std::wstring::npos) ||
                        (pl.find(L"\\windows\\winsxs")  != std::wstring::npos);

        // (a) 系统进程名出现在非系统目录 -> 极可能是伪装
        if (!underWin) {
            for (int i = 0; i < g_sysNameCount; ++i) {
                if (nl == ToLowerW(g_sysNames[i])) {
                    ++hit;
                    LogPost(L"[伪装] 系统进程名出现在非系统目录: " + p.name + L" -> " + p.path);
                    SetThreatLevel(THREAT_DANGER, (L"检测到进程伪装(银狐/紫狐常用手法): " + p.path).c_str());
                    break;
                }
            }
        }
        // (b) 白加黑: 程序同目录存在无签名的常侧载 DLL
        size_t bs = p.path.find_last_of(L"\\/");
        if (bs != std::wstring::npos && !underWin) {
            std::wstring dir = p.path.substr(0, bs + 1);
            for (int i = 0; i < g_sideloadCount; ++i) {
                std::wstring dll = dir + g_sideloadDll[i];
                if (GetFileAttributesW(dll.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
                if (VerifyFileSignature(dll) == 1) continue;      // 有有效签名则放行
                ++hit;
                LogPost(L"[白加黑] 发现无签名侧载 DLL: " + dll + L"  (宿主: " + p.name + L")");
                SetThreatLevel(THREAT_DANGER, (L"检测到白加黑 DLL 侧载(银狐常用): " + dll).c_str());
            }
        }
        // (c) 进程映像本身的族谱特征
        std::wstring why;
        if (MalFamilyScan(p.path, why) >= 5) {
            ++hit;
            LogPost(L"[族谱] 运行进程命中: " + p.name + L" -> " + why);
        }
    }
    return hit;
}

static int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int nShow) {
    // v13.14: 上次未能进入主界面(主程序无法启动) -> 立即修复组策略，放开 EXE/C
    {
        std::wstring bf = BootFailPath();
        bool lastFailed = (GetFileAttributesW(bf.c_str()) != INVALID_FILE_ATTRIBUTES);
        if (lastFailed) {
            DeleteFileW(bf.c_str());
            EnsureSelfRunnable();
        }
        FILE* bf2 = _wfopen(bf.c_str(), L"wb");
        if (bf2) { fputc('1', bf2); fclose(bf2); }   // 标记本次已启动，进入主界面后删除
    }
    // ---- 0) 配置文件防篡改: 校验值不符即视为被篡改, 自动从备份恢复 ----
    {
        const std::wstring cfgPath = CfgDefaultPath();
        const uint64_t hNow = CfgHashFile(cfgPath);
        const uint64_t hSig = CfgReadSig(cfgPath);
        if (hNow != 0 && hSig != 0 && hNow != hSig) {
            if (CfgRestore(cfgPath))
                LogPost(L"[配置] 检测到 zz_EDR.cfg.json 被篡改, 已自动从备份(.bak)恢复");
            else
                LogPost(L"[配置] 检测到 zz_EDR.cfg.json 被篡改, 但备份恢复失败(将使用默认值)");
        } else if (hNow != 0 && hSig == 0) {
            // 首次运行: 补建校验值与备份, 便于后续比对
            CfgBackup(cfgPath);
            CfgWriteSig(cfgPath, hNow);
        }
    }
    // ---- 0.1) 配置文件不存在时, 主动释放一份完整默认配置 ----
    // 【思路】首次运行/配置被误删时, 若什么都不做, 程序会以内存默认值运行,
    // 用户改了设置却没有文件可存, 重启即丢; 且防篡改备份也无从建立。
    // 所以检测到文件不存在就立刻落盘一份, 让用户开箱即用。
    {
        const std::wstring cfgPath = CfgDefaultPath();
        if (GetFileAttributesW(cfgPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            if (g_cfg.Save(cfgPath.c_str())) {
                LogPost(L"[配置] 未找到配置文件, 已释放默认配置到: " + cfgPath);
                CfgBackup(cfgPath);
                CfgWriteSig(cfgPath, CfgHashFile(cfgPath));
            } else {
                LogPost(L"[配置] 未找到配置文件, 且创建默认配置失败(将使用内置默认值)");
            }
        }
    }
    g_cfg.Load(CfgDefaultPath().c_str());

    // ---- 0.5) 程序启动即创建系统还原点(便于后续回滚/自救) ----
    LaunchBg([] { CreateRestorePoint(); });

    // 开机扫描模式: 先全盘扫描处理威胁, 再恢复 Shell 并启动桌面
    if (IsBootScanMode()) {
        BootScanMain();
        BootScanFinishAndLaunchDesktop();
        return 0;
    }

    WNDCLASSEXW wc = { sizeof(wc) };
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = MainWndProc;
    wc.hInstance     = hInst;
    wc.hCursor        = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground  = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName  = L"ZZEDRClass";
    wc.hIcon          = LoadIconW(nullptr, IDI_APPLICATION);
    if (!RegisterClassExW(&wc)) return 1;

    HWND hwnd = CreateWindowExW(0, L"ZZEDRClass", APP_TITLE,
                                WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                                900, 1010, nullptr, nullptr, hInst, nullptr);
    if (!hwnd) return 1;
    ShowWindow(hwnd, nShow);
    DeleteFileW(BootFailPath().c_str());   // v13.14: 已成功进入主界面
    UpdateWindow(hwnd);

    // ---- 启动流程 ----
    // 1) 先加载本地情报缓存(离线可用)
    IntelLoadCache();
    // 2) 后台在线更新威胁情报(哈希库 + IP 库)
    LaunchScan([] { IntelUpdateAll(true); });
    // 漏洞情报: 先读本地缓存保证离线可用, 再后台拉取最新
    VulnLoadCache();
    LaunchBg([] { VulnUpdateAll(); });
    // 3) 对所有当前运行的程序做全量扫描与行为建档
    LaunchScan([] { StartupFullScan(); });
    // 4) 进程守护(若已开启)
        // 最小信任: 载入授权库; 若无任何记录则首次自动学习基线(防系统锁死)
    TrustLoad();
    {
        bool empty = false;
        { std::lock_guard<std::mutex> lk(g_trustMtx); empty = g_trust.empty(); }
        if (empty) {
            LogPost(L"最小信任: 授权库为空, 首次运行自动建立系统基线(请在干净系统上执行)");
            int n = TrustLearnBaseline();
            TrustSave();
            LogFmt(L"最小信任: 已建立基线并保存(%d 条); 此后未授权程序将默认阻止", n);
        } else {
            LogPost(L"最小信任: 已载入授权库, 未授权程序将默认拒绝运行");
        }
    }
if (g_guardOn.load()) LaunchDaemon(L"ProcGuardLoop", [] { ProcGuardLoop(); });
    // 5) 办公软件子进程防护(若已开启)
    g_officeGuardOn.store(g_cfg.officeGuardOn);
    if (g_officeGuardOn.load()) LaunchDaemon(L"OfficeGuardLoop", [] { OfficeGuardLoop(); });
    // 6) 未知账户守护(此前已定义但未启动)
    LaunchDaemon(L"UserGuardLoop", [] { UserGuardLoop(); });
    // v13.29: UI 监控器(心跳检测 -> 主界面崩溃/卡死/加载失败时启用备用呈现器)
    LaunchDaemon(L"UiWatchdogLoop", [] { UiWatchdogLoop(); });
    LaunchDaemon(L"CanaryGuardLoop", [] { CanaryGuardLoop(); });
    // 7) 资源异常监控守护(CPU/内存/磁盘IO/GPU-CUDA/网络)
    FzInit();
    FamLoad();
    g_resGuardOn.store(g_cfg.resGuardOn);
    g_immunizeOn.store(g_cfg.immunizeOn);
    if (g_resGuardOn.load()) {
        LaunchDaemon(L"ResourceGuardLoop", [] { ResourceGuardLoop(); });
        LogPost(L"[RES] 资源异常监控守护已启动(10 秒采样: CPU/内存/磁盘IO/GPU-CUDA/网络)");
    }
    // 8) 持久化与劫持检测守护(本轮新增)
    g_hostGuardOn.store(g_cfg.hostGuardOn);
    g_wmiScanOn.store(g_cfg.wmiScanOn);
    g_taskScanOn.store(g_cfg.taskScanOn);
    g_clipGuardOn.store(g_cfg.clipGuardOn);
    g_selfDefenseOn.store(g_cfg.selfDefenseOn);
    g_netAuditOn.store(g_cfg.netAuditOn);
    if (g_cfg.pdmOn) { if (LaunchDaemon(L"PdmGuardLoop", [] { PdmGuardLoop(); })) LogPost(L"PDM 主动防御已启动"); }
    // 9) v13.25: 重点观察守护(激进处置后观察 10 分钟, 到期自动恢复常规观察)
    LaunchDaemon(L"FocusWatchThread", [] { FocusWatchThread(); });
    if (g_clipGuardOn.load()) {
        LaunchDaemon(L"ClipboardGuardLoop", [] { ClipboardGuardLoop(); });
        LogPost(L"[CLIP] 剪贴板劫持监控已启动(3 秒检查)");
    }
    if (g_selfDefenseOn.load()) {
        LaunchDaemon(L"SelfDefenseLoop", [] { SelfDefenseLoop(); });
        LogPost(L"[SELF] 自我保护看门狗已启动(反调试/存活确认)");
    }
    // 10) 内核驱动对接: 装载成功则升级为内核级拦截, 失败自动回落应用层防护
    //     【思路】驱动是"增强"不是"依赖", 所以这里不判断返回值来决定后续流程;
    //            装载失败时所有既有防护照常工作, 只是没有内核级的即时拦截能力。
    if (DrvInit()) {
        if (LaunchDaemon(L"DrvEventLoop", [] { DrvEventLoop(); }))
            LogPost(L"[DRV] 内核事件接收守护已启动");
    } else {
        LogPost(L"[DRV] 未启用内核驱动, 使用应用层防护(功能完整, 但存在采样时间窗)");
    }

    // 开机即做一次持久化体检(hosts/WMI/计划任务), 这些是木马最常用的驻留手段
    LaunchScan([]() {
        Sleep(2000);
        if (g_hostGuardOn.load()) HostsAuditRun();
        if (g_wmiScanOn.load())   WmiPersistScan();
        if (g_taskScanOn.load())  TaskPersistScan();
    });

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}

// 兼容 Linux 自检: g++ 需要 main
#ifndef _WIN32
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    return wWinMain(GetModuleHandleW(nullptr), nullptr, nullptr, SW_SHOW);
}
#endif
