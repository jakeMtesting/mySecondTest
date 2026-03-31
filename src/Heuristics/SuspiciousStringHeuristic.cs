using AntivirusScanner.Models;
using System;
using System.Collections.Generic;
using System.Text;

namespace AntivirusScanner.Heuristics
{
    /// <summary>
    /// Extracts printable ASCII/UTF-16LE strings from the file and matches them
    /// against known indicators of compromise (IOCs) grouped into categories.
    ///
    /// Patterns are intentionally specific: generic strings that appear in almost
    /// every Windows binary (http://, connect, password, socket) are excluded to
    /// avoid false positives on legitimate software such as installers and browsers.
    /// Only strings that are either unique to malicious tooling or that carry high
    /// contextual significance are included.
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
            // cmd.exe and powershell appear in many tools, but the specific
            // flag-style variants (-enc, -nop) are almost exclusively malicious.
            new StringPattern("cmd.exe",            "Shell", "References cmd.exe",                                    8, ThreatLevel.Suspicious),
            new StringPattern("powershell",         "Shell", "References PowerShell",                                 8, ThreatLevel.Suspicious),
            new StringPattern("powershell -enc",    "Shell", "Base64-encoded PowerShell command",                    30, ThreatLevel.Likely),
            new StringPattern("powershell -nop",    "Shell", "PowerShell -NoProfile bypass",                         25, ThreatLevel.Likely),
            new StringPattern("powershell -w hidden","Shell","PowerShell hidden-window execution",                   25, ThreatLevel.Likely),
            new StringPattern("wscript.exe",        "Shell", "References WScript (script host)",                     12, ThreatLevel.Suspicious),
            new StringPattern("cscript.exe",        "Shell", "References CScript (script host)",                     12, ThreatLevel.Suspicious),
            new StringPattern("mshta.exe",          "Shell", "References MSHTA — common LOLBin",                     25, ThreatLevel.Likely),
            new StringPattern("rundll32.exe",       "Shell", "References RunDLL32 — common LOLBin",                  12, ThreatLevel.Suspicious),
            new StringPattern("regsvr32.exe",       "Shell", "References Regsvr32 — COM/DLL LOLBin",                 12, ThreatLevel.Suspicious),
            new StringPattern("certutil -decode",   "Shell", "Certutil base64 decode — common dropper step",         25, ThreatLevel.Likely),
            new StringPattern("bitsadmin /transfer","Shell", "BITSAdmin download — LOLBin pattern",                  25, ThreatLevel.Likely),

            // --- Privilege escalation / UAC ---
            new StringPattern("SeDebugPrivilege",      "Privesc", "Requests SeDebugPrivilege",                       25, ThreatLevel.Likely),
            new StringPattern("bypassuac",             "Privesc", "UAC bypass string",                               45, ThreatLevel.Malicious),
            new StringPattern("eventvwr.exe",          "Privesc", "eventvwr UAC bypass technique",                   30, ThreatLevel.Likely),

            // --- Network (only high-specificity patterns) ---
            // Generic strings like http://, connect, socket are excluded because
            // they appear in virtually every network-capable legitimate binary.
            new StringPattern("URLDownloadToFile",  "Network", "Downloads file via URL — classic dropper API",       25, ThreatLevel.Likely),
            new StringPattern("InternetOpenUrl",    "Network", "Opens a URL via WinINet",                             8, ThreatLevel.Suspicious),
            new StringPattern("WinHttpConnect",     "Network", "WinHTTP connectivity",                                8, ThreatLevel.Suspicious),
            new StringPattern("WSAStartup",         "Network", "Winsock initialisation",                              5, ThreatLevel.Suspicious),

            // --- Credential harvesting ---
            new StringPattern("mimikatz",                "Creds", "Mimikatz credential dumper string",               55, ThreatLevel.Malicious),
            new StringPattern("sekurlsa",                "Creds", "Mimikatz sekurlsa module reference",              55, ThreatLevel.Malicious),
            new StringPattern("lsass.exe",               "Creds", "References LSASS process by name",               20, ThreatLevel.Likely),
            new StringPattern("SamQueryInformationUser", "Creds", "SAM database query — credential access",          30, ThreatLevel.Likely),
            new StringPattern("NtlmHash",                "Creds", "NTLM hash reference",                             25, ThreatLevel.Likely),
            // "password" alone excluded — too generic; matches any login dialog or docs

            // --- Registry persistence (specific keys only) ---
            new StringPattern(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Persist",
                "Classic auto-run registry key",                                                                      30, ThreatLevel.Likely),
            new StringPattern(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Persist",
                "Winlogon hijack registry key",                                                                       35, ThreatLevel.Likely),
            new StringPattern("schtasks /create",  "Persist", "Scheduled task creation via schtasks",               25, ThreatLevel.Likely),
            new StringPattern("sc create",         "Persist", "Service creation command",                            20, ThreatLevel.Likely),
            // RegSetValueEx alone excluded — any installer or config writer uses it

            // --- Anti-analysis / anti-debug ---
            new StringPattern("IsDebuggerPresent",           "AntiDebug", "Debugger detection API",                  20, ThreatLevel.Likely),
            new StringPattern("CheckRemoteDebuggerPresent",  "AntiDebug", "Remote debugger detection API",           20, ThreatLevel.Likely),
            new StringPattern("NtQueryInformationProcess",   "AntiDebug", "Debugger detection via NtQueryInfo",      20, ThreatLevel.Likely),
            new StringPattern("SandboxieControlWndClass",    "AntiDebug", "Sandboxie sandbox detection string",      30, ThreatLevel.Likely),
            new StringPattern("VBoxGuest",                   "AntiDebug", "VirtualBox guest detection",              15, ThreatLevel.Suspicious),
            new StringPattern("VBOX",                        "AntiDebug", "VirtualBox detection string",             15, ThreatLevel.Suspicious),
            new StringPattern("vmware",                      "AntiDebug", "VMware detection string",                 12, ThreatLevel.Suspicious),
            new StringPattern("wireshark",                   "AntiDebug", "Wireshark detection string",              12, ThreatLevel.Suspicious),
            // OutputDebugString excluded — used legitimately by every debug build

            // --- Ransomware indicators ---
            new StringPattern("Your files have been encrypted", "Ransomware", "Classic ransom note string",          80, ThreatLevel.Malicious),
            new StringPattern("All your files",                 "Ransomware", "Ransomware ransom note opening",      60, ThreatLevel.Malicious),
            new StringPattern("README_DECRYPT",                 "Ransomware", "Ransom note filename",                60, ThreatLevel.Malicious),
            new StringPattern("HOW_TO_RECOVER",                 "Ransomware", "Ransom note filename variant",        60, ThreatLevel.Malicious),
            new StringPattern(".onion",                         "Ransomware", "Tor hidden service address",          20, ThreatLevel.Suspicious),
            // bitcoin excluded alone — too common in legitimate finance/crypto apps
            // CryptEncrypt/CryptGenKey excluded — any TLS/HTTPS implementation uses them

            // --- Process / reflective injection ---
            new StringPattern("VirtualAllocEx",     "Injection", "Allocates memory in remote process",              30, ThreatLevel.Likely),
            new StringPattern("WriteProcessMemory", "Injection", "Writes into another process",                     30, ThreatLevel.Likely),
            new StringPattern("CreateRemoteThread", "Injection", "Creates thread in remote process",                35, ThreatLevel.Likely),
            new StringPattern("NtCreateThreadEx",   "Injection", "Low-level remote thread creation",                35, ThreatLevel.Likely),
            new StringPattern("QueueUserAPC",       "Injection", "APC injection technique",                         30, ThreatLevel.Likely),
            new StringPattern("SetWindowsHookEx",   "Injection", "System-wide hook installation",                   20, ThreatLevel.Suspicious),
            // LoadLibrary / GetProcAddress excluded — used by every plugin system
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
                        string dedupeKey = pattern.Pattern + "|" + pattern.Category;
                        if (alreadyScored.Add(dedupeKey))
                        {
                            result.AddThreat(new ThreatInfo(
                                pattern.Level, Name,
                                "[" + pattern.Category + "] " + pattern.Description +
                                " (matched: '" + pattern.Pattern + "')",
                                pattern.Score));
                        }
                        break;
                    }
                }
            }
        }

        private static List<string> ExtractStrings(ReadOnlySpan<byte> data, bool wide)
        {
            var strings = new List<string>();
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
                        strings.Add(current.ToString());
                    current.Clear();
                }
            }

            if (current.Length >= MinStringLength)
                strings.Add(current.ToString());

            return strings;
        }
    }
}
