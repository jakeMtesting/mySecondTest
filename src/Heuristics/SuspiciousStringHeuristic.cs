using AntivirusScanner.Models;
using System.Text;

namespace AntivirusScanner.Heuristics;

/// <summary>
/// Extracts printable ASCII/UTF-16LE strings from the file and matches them
/// against known indicators of compromise (IOCs) grouped into categories.
/// Each category carries its own scoring weight so that a single weak signal
/// does not trigger a false positive, but combinations elevate the verdict.
///
/// Categories examined:
///   - Shell / command execution
///   - Privilege escalation / UAC bypass
///   - Network connectivity
///   - Credential harvesting
///   - Registry persistence
///   - Anti-analysis / anti-debug
///   - Ransomware keywords
///   - Reflective / process injection
/// </summary>
public sealed class SuspiciousStringHeuristic : IHeuristic
{
    public string Name => "Suspicious String Analysis";

    private const int MinStringLength = 5;

    private record StringPattern(string Pattern, string Category, string Description, int Score, ThreatLevel Level);

    private static readonly StringPattern[] Patterns =
    [
        // --- Shell / command execution ---
        new("cmd.exe",            "Shell",   "References cmd.exe",                                   10, ThreatLevel.Suspicious),
        new("powershell",         "Shell",   "References PowerShell",                                10, ThreatLevel.Suspicious),
        new("powershell -enc",    "Shell",   "Base64-encoded PowerShell command",                    25, ThreatLevel.Likely),
        new("powershell -nop",    "Shell",   "PowerShell -NoProfile (script-block evasion)",         20, ThreatLevel.Likely),
        new("wscript.exe",        "Shell",   "References WScript (script host)",                     15, ThreatLevel.Suspicious),
        new("cscript.exe",        "Shell",   "References CScript (script host)",                     15, ThreatLevel.Suspicious),
        new("mshta.exe",          "Shell",   "References MSHTA — common LOLBin",                     20, ThreatLevel.Likely),
        new("rundll32.exe",       "Shell",   "References RunDLL32 — common LOLBin",                  15, ThreatLevel.Suspicious),
        new("regsvr32.exe",       "Shell",   "References Regsvr32 — COM/DLL LOLBin",                 15, ThreatLevel.Suspicious),
        new("certutil",           "Shell",   "References Certutil — download/decode LOLBin",         20, ThreatLevel.Likely),
        new("bitsadmin",          "Shell",   "References BITSAdmin — download LOLBin",               20, ThreatLevel.Likely),

        // --- Privilege escalation / UAC ---
        new("SeDebugPrivilege",   "Privesc", "Requests SeDebugPrivilege",                            25, ThreatLevel.Likely),
        new("AdjustTokenPrivileges", "Privesc", "Adjusts process token privileges",                  20, ThreatLevel.Suspicious),
        new("bypassuac",          "Privesc", "UAC bypass string",                                    40, ThreatLevel.Malicious),
        new("eventvwr.exe",       "Privesc", "eventvwr UAC bypass technique",                        30, ThreatLevel.Likely),

        // --- Network ---
        new("http://",            "Network", "Plain HTTP URL",                                        5, ThreatLevel.Suspicious),
        new("https://",           "Network", "HTTPS URL",                                             5, ThreatLevel.Suspicious),
        new("socket",             "Network", "Raw socket API usage",                                 10, ThreatLevel.Suspicious),
        new("WSAStartup",         "Network", "Winsock initialisation",                               10, ThreatLevel.Suspicious),
        new("connect",            "Network", "Network connect call",                                  8, ThreatLevel.Suspicious),
        new("InternetOpenUrl",    "Network", "WinINet HTTP request",                                 10, ThreatLevel.Suspicious),
        new("URLDownloadToFile",  "Network", "Downloads file via URL (common dropper pattern)",      25, ThreatLevel.Likely),
        new("WinHttpConnect",     "Network", "WinHTTP connectivity",                                 10, ThreatLevel.Suspicious),
        new("ShellExecute",       "Network", "ShellExecute (can launch downloaded payloads)",        10, ThreatLevel.Suspicious),

        // --- Credential harvesting ---
        new("mimikatz",           "Creds",   "Mimikatz credential dumper string",                    50, ThreatLevel.Malicious),
        new("sekurlsa",           "Creds",   "Mimikatz sekurlsa module reference",                   50, ThreatLevel.Malicious),
        new("lsass",              "Creds",   "References LSASS (credential store)",                  20, ThreatLevel.Likely),
        new("SamQueryInformationUser", "Creds", "SAM database query — credential access",            30, ThreatLevel.Likely),
        new("password",           "Creds",   "Generic password string",                               5, ThreatLevel.Suspicious),
        new("NtlmHash",           "Creds",   "NTLM hash reference",                                  25, ThreatLevel.Likely),

        // --- Registry persistence ---
        new("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "Persist",
            "Classic auto-run registry key",                                                          30, ThreatLevel.Likely),
        new("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "Persist",
            "Winlogon hijack registry key",                                                           35, ThreatLevel.Likely),
        new("RegSetValueEx",      "Persist", "Writes a registry value (common for persistence)",     15, ThreatLevel.Suspicious),
        new("schtasks",           "Persist", "Scheduled task creation",                              20, ThreatLevel.Likely),
        new("sc create",          "Persist", "Service creation command",                             20, ThreatLevel.Likely),

        // --- Anti-analysis / anti-debug ---
        new("IsDebuggerPresent",  "AntiDebug", "Debugger detection API",                             20, ThreatLevel.Likely),
        new("CheckRemoteDebuggerPresent", "AntiDebug", "Remote debugger detection API",              20, ThreatLevel.Likely),
        new("NtQueryInformationProcess", "AntiDebug", "Used to detect debugger via NtQueryInfo",     20, ThreatLevel.Likely),
        new("OutputDebugString",  "AntiDebug", "Anti-debug timing trick",                             10, ThreatLevel.Suspicious),
        new("SandboxieControlWndClass", "AntiDebug", "Sandboxie detection string",                   30, ThreatLevel.Likely),
        new("vmware",             "AntiDebug", "VMware detection string",                             15, ThreatLevel.Suspicious),
        new("VBoxGuest",          "AntiDebug", "VirtualBox guest detection",                          15, ThreatLevel.Suspicious),
        new("VBOX",               "AntiDebug", "VirtualBox detection string",                         15, ThreatLevel.Suspicious),
        new("wireshark",          "AntiDebug", "Wireshark detection string",                          15, ThreatLevel.Suspicious),
        new("Sleep",              "AntiDebug", "Sleep call (may be timing-based evasion)",             5, ThreatLevel.Suspicious),

        // --- Ransomware indicators ---
        new("CryptEncrypt",       "Ransomware", "Windows crypto encryption API",                     20, ThreatLevel.Suspicious),
        new("CryptGenKey",        "Ransomware", "Crypto key generation",                             20, ThreatLevel.Suspicious),
        new("Your files have been encrypted", "Ransomware", "Classic ransom note string",            80, ThreatLevel.Malicious),
        new("bitcoin",            "Ransomware", "Bitcoin payment reference",                         20, ThreatLevel.Suspicious),
        new(".onion",             "Ransomware", "Tor hidden service address",                        25, ThreatLevel.Likely),
        new("README_DECRYPT",     "Ransomware", "Ransom note filename",                              60, ThreatLevel.Malicious),
        new("HOW_TO_RECOVER",     "Ransomware", "Ransom note filename variant",                      60, ThreatLevel.Malicious),

        // --- Process / reflective injection ---
        new("VirtualAllocEx",     "Injection", "Allocates memory in remote process",                 30, ThreatLevel.Likely),
        new("WriteProcessMemory", "Injection", "Writes into another process",                        30, ThreatLevel.Likely),
        new("CreateRemoteThread", "Injection", "Creates thread in remote process",                   35, ThreatLevel.Likely),
        new("NtCreateThreadEx",   "Injection", "Low-level remote thread creation",                   35, ThreatLevel.Likely),
        new("QueueUserAPC",       "Injection", "APC injection technique",                            30, ThreatLevel.Likely),
        new("SetWindowsHookEx",   "Injection", "Hook-based injection / keylogging",                  25, ThreatLevel.Likely),
        new("OpenProcess",        "Injection", "Opens handle to another process",                    15, ThreatLevel.Suspicious),
        new("LoadLibrary",        "Injection", "Dynamic library loading",                            10, ThreatLevel.Suspicious),
        new("GetProcAddress",     "Injection", "Dynamic function resolution (common in injectors)",  15, ThreatLevel.Suspicious),
    ];

    public void Analyze(ReadOnlySpan<byte> fileBytes, ScanResult result)
    {
        // Collect all printable ASCII strings
        var asciiStrings  = ExtractStrings(fileBytes, wide: false);
        // Collect UTF-16LE strings (common in .NET / Windows PE resources)
        var wideStrings   = ExtractStrings(fileBytes, wide: true);

        var allStrings = asciiStrings.Concat(wideStrings).ToList();

        // Track which categories have already scored to avoid double-counting
        // identical strings found in both encodings
        var alreadyScored = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var pattern in Patterns)
        {
            foreach (var str in allStrings)
            {
                if (str.Contains(pattern.Pattern, StringComparison.OrdinalIgnoreCase))
                {
                    string dedupeKey = $"{pattern.Pattern}|{pattern.Category}";
                    if (alreadyScored.Add(dedupeKey))
                    {
                        result.AddThreat(new ThreatInfo(
                            pattern.Level, Name,
                            $"[{pattern.Category}] {pattern.Description} (matched: '{pattern.Pattern}')",
                            pattern.Score));
                    }
                    break; // One hit per pattern is enough
                }
            }
        }
    }

    /// <summary>
    /// Extracts runs of printable characters from raw bytes.
    /// When <paramref name="wide"/> is true, treats every other byte as a
    /// null padding byte and extracts UTF-16LE strings.
    /// </summary>
    private static IEnumerable<string> ExtractStrings(ReadOnlySpan<byte> data, bool wide)
    {
        var result = new List<string>();
        var current = new StringBuilder(64);

        int step = wide ? 2 : 1;

        for (int i = 0; i + (wide ? 1 : 0) < data.Length; i += step)
        {
            byte b = data[i];
            byte next = wide && i + 1 < data.Length ? data[i + 1] : (byte)0;

            bool isPrintable = b >= 0x20 && b <= 0x7E && (!wide || next == 0);

            if (isPrintable)
            {
                current.Append((char)b);
            }
            else
            {
                if (current.Length >= MinStringLength)
                    result.Add(current.ToString());
                current.Clear();
            }
        }

        if (current.Length >= MinStringLength)
            result.Add(current.ToString());

        return result;
    }
}
