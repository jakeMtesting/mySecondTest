using AntivirusScanner.Models;
using System;
using System.Collections.Generic;
using System.Text;

namespace AntivirusScanner.Heuristics
{
    /// <summary>
    /// Extracts printable ASCII/UTF-16LE strings from the file and matches them
    /// against known indicators of compromise (IOCs) grouped into categories.
    /// Each category carries its own scoring weight so that a single weak signal
    /// does not trigger a false positive, but combinations elevate the verdict.
    /// </summary>
    public sealed class SuspiciousStringHeuristic : IHeuristic
    {
        public string Name => "Suspicious String Analysis";

        private const int MinStringLength = 5;

        private sealed class StringPattern
        {
            public string Pattern     { get; }
            public string Category    { get; }
            public string Description { get; }
            public int    Score       { get; }
            public ThreatLevel Level  { get; }

            public StringPattern(string pattern, string category, string description, int score, ThreatLevel level)
            {
                Pattern     = pattern;
                Category    = category;
                Description = description;
                Score       = score;
                Level       = level;
            }
        }

        private static readonly StringPattern[] Patterns = new StringPattern[]
        {
            // --- Shell / command execution ---
            new StringPattern("cmd.exe",            "Shell",   "References cmd.exe",                                   10, ThreatLevel.Suspicious),
            new StringPattern("powershell",         "Shell",   "References PowerShell",                                10, ThreatLevel.Suspicious),
            new StringPattern("powershell -enc",    "Shell",   "Base64-encoded PowerShell command",                    25, ThreatLevel.Likely),
            new StringPattern("powershell -nop",    "Shell",   "PowerShell -NoProfile (script-block evasion)",         20, ThreatLevel.Likely),
            new StringPattern("wscript.exe",        "Shell",   "References WScript (script host)",                     15, ThreatLevel.Suspicious),
            new StringPattern("cscript.exe",        "Shell",   "References CScript (script host)",                     15, ThreatLevel.Suspicious),
            new StringPattern("mshta.exe",          "Shell",   "References MSHTA — common LOLBin",                     20, ThreatLevel.Likely),
            new StringPattern("rundll32.exe",       "Shell",   "References RunDLL32 — common LOLBin",                  15, ThreatLevel.Suspicious),
            new StringPattern("regsvr32.exe",       "Shell",   "References Regsvr32 — COM/DLL LOLBin",                 15, ThreatLevel.Suspicious),
            new StringPattern("certutil",           "Shell",   "References Certutil — download/decode LOLBin",         20, ThreatLevel.Likely),
            new StringPattern("bitsadmin",          "Shell",   "References BITSAdmin — download LOLBin",               20, ThreatLevel.Likely),

            // --- Privilege escalation / UAC ---
            new StringPattern("SeDebugPrivilege",      "Privesc", "Requests SeDebugPrivilege",                         25, ThreatLevel.Likely),
            new StringPattern("AdjustTokenPrivileges", "Privesc", "Adjusts process token privileges",                  20, ThreatLevel.Suspicious),
            new StringPattern("bypassuac",             "Privesc", "UAC bypass string",                                 40, ThreatLevel.Malicious),
            new StringPattern("eventvwr.exe",          "Privesc", "eventvwr UAC bypass technique",                     30, ThreatLevel.Likely),

            // --- Network ---
            new StringPattern("http://",            "Network", "Plain HTTP URL",                                        5, ThreatLevel.Suspicious),
            new StringPattern("https://",           "Network", "HTTPS URL",                                             5, ThreatLevel.Suspicious),
            new StringPattern("socket",             "Network", "Raw socket API usage",                                 10, ThreatLevel.Suspicious),
            new StringPattern("WSAStartup",         "Network", "Winsock initialisation",                               10, ThreatLevel.Suspicious),
            new StringPattern("connect",            "Network", "Network connect call",                                  8, ThreatLevel.Suspicious),
            new StringPattern("InternetOpenUrl",    "Network", "WinINet HTTP request",                                 10, ThreatLevel.Suspicious),
            new StringPattern("URLDownloadToFile",  "Network", "Downloads file via URL (common dropper pattern)",      25, ThreatLevel.Likely),
            new StringPattern("WinHttpConnect",     "Network", "WinHTTP connectivity",                                 10, ThreatLevel.Suspicious),
            new StringPattern("ShellExecute",       "Network", "ShellExecute (can launch downloaded payloads)",        10, ThreatLevel.Suspicious),

            // --- Credential harvesting ---
            new StringPattern("mimikatz",                "Creds", "Mimikatz credential dumper string",                 50, ThreatLevel.Malicious),
            new StringPattern("sekurlsa",                "Creds", "Mimikatz sekurlsa module reference",                50, ThreatLevel.Malicious),
            new StringPattern("lsass",                   "Creds", "References LSASS (credential store)",               20, ThreatLevel.Likely),
            new StringPattern("SamQueryInformationUser", "Creds", "SAM database query — credential access",            30, ThreatLevel.Likely),
            new StringPattern("password",                "Creds", "Generic password string",                            5, ThreatLevel.Suspicious),
            new StringPattern("NtlmHash",                "Creds", "NTLM hash reference",                               25, ThreatLevel.Likely),

            // --- Registry persistence ---
            new StringPattern(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Persist",
                "Classic auto-run registry key",                                                                        30, ThreatLevel.Likely),
            new StringPattern(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Persist",
                "Winlogon hijack registry key",                                                                         35, ThreatLevel.Likely),
            new StringPattern("RegSetValueEx", "Persist", "Writes a registry value (common for persistence)",          15, ThreatLevel.Suspicious),
            new StringPattern("schtasks",      "Persist", "Scheduled task creation",                                   20, ThreatLevel.Likely),
            new StringPattern("sc create",     "Persist", "Service creation command",                                  20, ThreatLevel.Likely),

            // --- Anti-analysis / anti-debug ---
            new StringPattern("IsDebuggerPresent",           "AntiDebug", "Debugger detection API",                    20, ThreatLevel.Likely),
            new StringPattern("CheckRemoteDebuggerPresent",  "AntiDebug", "Remote debugger detection API",             20, ThreatLevel.Likely),
            new StringPattern("NtQueryInformationProcess",   "AntiDebug", "Used to detect debugger via NtQueryInfo",   20, ThreatLevel.Likely),
            new StringPattern("OutputDebugString",           "AntiDebug", "Anti-debug timing trick",                   10, ThreatLevel.Suspicious),
            new StringPattern("SandboxieControlWndClass",    "AntiDebug", "Sandboxie detection string",                30, ThreatLevel.Likely),
            new StringPattern("vmware",                      "AntiDebug", "VMware detection string",                   15, ThreatLevel.Suspicious),
            new StringPattern("VBoxGuest",                   "AntiDebug", "VirtualBox guest detection",                15, ThreatLevel.Suspicious),
            new StringPattern("VBOX",                        "AntiDebug", "VirtualBox detection string",               15, ThreatLevel.Suspicious),
            new StringPattern("wireshark",                   "AntiDebug", "Wireshark detection string",                15, ThreatLevel.Suspicious),

            // --- Ransomware indicators ---
            new StringPattern("CryptEncrypt",                  "Ransomware", "Windows crypto encryption API",          20, ThreatLevel.Suspicious),
            new StringPattern("CryptGenKey",                   "Ransomware", "Crypto key generation",                  20, ThreatLevel.Suspicious),
            new StringPattern("Your files have been encrypted","Ransomware", "Classic ransom note string",             80, ThreatLevel.Malicious),
            new StringPattern("bitcoin",                       "Ransomware", "Bitcoin payment reference",              20, ThreatLevel.Suspicious),
            new StringPattern(".onion",                        "Ransomware", "Tor hidden service address",             25, ThreatLevel.Likely),
            new StringPattern("README_DECRYPT",                "Ransomware", "Ransom note filename",                   60, ThreatLevel.Malicious),
            new StringPattern("HOW_TO_RECOVER",                "Ransomware", "Ransom note filename variant",           60, ThreatLevel.Malicious),

            // --- Process / reflective injection ---
            new StringPattern("VirtualAllocEx",     "Injection", "Allocates memory in remote process",                 30, ThreatLevel.Likely),
            new StringPattern("WriteProcessMemory", "Injection", "Writes into another process",                        30, ThreatLevel.Likely),
            new StringPattern("CreateRemoteThread", "Injection", "Creates thread in remote process",                   35, ThreatLevel.Likely),
            new StringPattern("NtCreateThreadEx",   "Injection", "Low-level remote thread creation",                   35, ThreatLevel.Likely),
            new StringPattern("QueueUserAPC",       "Injection", "APC injection technique",                            30, ThreatLevel.Likely),
            new StringPattern("SetWindowsHookEx",   "Injection", "Hook-based injection / keylogging",                  25, ThreatLevel.Likely),
            new StringPattern("OpenProcess",        "Injection", "Opens handle to another process",                    15, ThreatLevel.Suspicious),
            new StringPattern("LoadLibrary",        "Injection", "Dynamic library loading",                            10, ThreatLevel.Suspicious),
            new StringPattern("GetProcAddress",     "Injection", "Dynamic function resolution (common in injectors)",  15, ThreatLevel.Suspicious),
        };

        public void Analyze(ReadOnlySpan<byte> fileBytes, ScanResult result)
        {
            List<string> asciiStrings = ExtractStrings(fileBytes, wide: false);
            List<string> wideStrings  = ExtractStrings(fileBytes, wide: true);

            var allStrings = new List<string>(asciiStrings);
            allStrings.AddRange(wideStrings);

            var alreadyScored = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (StringPattern pattern in Patterns)
            {
                foreach (string str in allStrings)
                {
                    if (str.IndexOf(pattern.Pattern, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        string dedupeKey = $"{pattern.Pattern}|{pattern.Category}";
                        if (alreadyScored.Add(dedupeKey))
                        {
                            result.AddThreat(new ThreatInfo(
                                pattern.Level, Name,
                                $"[{pattern.Category}] {pattern.Description} (matched: '{pattern.Pattern}')",
                                pattern.Score));
                        }
                        break;
                    }
                }
            }
        }

        private static List<string> ExtractStrings(ReadOnlySpan<byte> data, bool wide)
        {
            var result  = new List<string>();
            var current = new StringBuilder(64);

            int step = wide ? 2 : 1;

            for (int i = 0; i + (wide ? 1 : 0) < data.Length; i += step)
            {
                byte b    = data[i];
                byte next = (wide && i + 1 < data.Length) ? data[i + 1] : (byte)0;

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
}
