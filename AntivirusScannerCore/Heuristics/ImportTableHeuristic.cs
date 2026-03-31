using AntivirusScanner.Models;
using System;
using System.Collections.Generic;
using System.Text;

namespace AntivirusScanner.Heuristics
{
    /// <summary>
    /// Walks the PE Import Directory Table and scores the binary based on which
    /// Win32 APIs it imports.  Dangerous APIs are grouped into functional clusters.
    ///
    /// Scoring philosophy:
    ///   - APIs that are near-universal in legitimate software (LoadLibrary,
    ///     GetProcAddress, RegSetValueEx, send/recv) carry low individual scores.
    ///     They only become meaningful in combination.
    ///   - APIs that are rarely used legitimately (CreateRemoteThread,
    ///     NtUnmapViewOfSection, GetAsyncKeyState) carry higher individual scores.
    ///   - A cluster bonus fires when 4+ functions from the same cluster are
    ///     imported, indicating a deliberate capability rather than incidental use.
    /// </summary>
    public sealed class ImportTableHeuristic : IHeuristic
    {
        public string Name => "Import Table Analysis";

        // Minimum hits in one cluster before adding the combination bonus.
        private const int ClusterBonusThreshold = 4;

        private sealed class ApiEntry
        {
            public string     FunctionName { get; }
            public string     Cluster      { get; }
            public string     Description  { get; }
            public int        Score        { get; }
            public ThreatLevel Level       { get; }

            public ApiEntry(string functionName, string cluster, string description, int score, ThreatLevel level)
            {
                FunctionName = functionName;
                Cluster      = cluster;
                Description  = description;
                Score        = score;
                Level        = level;
            }
        }

        private static readonly ApiEntry[] DangerousApis = new ApiEntry[]
        {
            // --- Process injection ---
            // These are rarely imported by legitimate software; each hit is meaningful.
            new ApiEntry("VirtualAllocEx",          "Injection", "Allocates memory in a remote process",                 25, ThreatLevel.Likely),
            new ApiEntry("WriteProcessMemory",      "Injection", "Writes data into another process",                     25, ThreatLevel.Likely),
            new ApiEntry("CreateRemoteThread",      "Injection", "Creates a thread in another process",                  30, ThreatLevel.Likely),
            new ApiEntry("NtCreateThreadEx",        "Injection", "NT-level remote thread creation",                      30, ThreatLevel.Likely),
            new ApiEntry("RtlCreateUserThread",     "Injection", "User-mode thread injection primitive",                 30, ThreatLevel.Likely),
            new ApiEntry("OpenProcess",             "Injection", "Opens a handle to another process",                     5, ThreatLevel.Suspicious),
            new ApiEntry("QueueUserAPC",            "Injection", "APC-based injection",                                  25, ThreatLevel.Likely),
            new ApiEntry("SetThreadContext",        "Injection", "Thread context manipulation (process hollowing)",      25, ThreatLevel.Likely),
            new ApiEntry("NtUnmapViewOfSection",    "Injection", "Unmaps section (process hollowing)",                   30, ThreatLevel.Likely),
            new ApiEntry("ZwUnmapViewOfSection",    "Injection", "Unmaps section — Zw variant (process hollowing)",     30, ThreatLevel.Likely),

            // --- Hooking / keylogging ---
            new ApiEntry("SetWindowsHookEx",        "Hooking",   "Installs a system-wide hook",                         20, ThreatLevel.Likely),
            new ApiEntry("GetAsyncKeyState",        "Hooking",   "Polls keystroke state — keylogger pattern",            20, ThreatLevel.Likely),
            new ApiEntry("GetKeyState",             "Hooking",   "Reads key state — keylogger pattern",                  10, ThreatLevel.Suspicious),

            // --- Privilege escalation ---
            // AdjustTokenPrivileges is used by legitimate software (backup, defrag),
            // so the score is kept low; only high in combination.
            new ApiEntry("AdjustTokenPrivileges",   "Privesc",   "Adjusts access token privileges",                      8, ThreatLevel.Suspicious),
            new ApiEntry("LookupPrivilegeValue",    "Privesc",   "Looks up privilege LUID",                               5, ThreatLevel.Suspicious),
            new ApiEntry("OpenProcessToken",        "Privesc",   "Opens a process token for manipulation",                5, ThreatLevel.Suspicious),

            // --- Network ---
            // send/recv/WSAStartup/connect are in every network-enabled application.
            // Score is kept low; the cluster bonus makes combinations meaningful.
            new ApiEntry("WSAStartup",              "Network",   "Initialises Winsock",                                   3, ThreatLevel.Suspicious),
            new ApiEntry("connect",                 "Network",   "TCP/UDP connection",                                    5, ThreatLevel.Suspicious),
            new ApiEntry("send",                    "Network",   "Sends data over a socket",                              3, ThreatLevel.Suspicious),
            new ApiEntry("recv",                    "Network",   "Receives data from a socket",                           3, ThreatLevel.Suspicious),
            new ApiEntry("InternetOpenUrl",         "Network",   "Opens a URL (WinINet)",                                 5, ThreatLevel.Suspicious),
            new ApiEntry("URLDownloadToFile",       "Network",   "Downloads file from URL",                              25, ThreatLevel.Likely),
            new ApiEntry("HttpSendRequest",         "Network",   "Sends HTTP request (WinINet)",                          5, ThreatLevel.Suspicious),
            new ApiEntry("WinHttpConnect",          "Network",   "WinHTTP connection",                                    5, ThreatLevel.Suspicious),

            // --- Crypto ---
            // CryptEncrypt et al. appear in any HTTPS client or file-signing code.
            // Only flag at a low score; ransomware is caught by string patterns instead.
            new ApiEntry("CryptEncrypt",               "Crypto", "Encrypts data (CryptoAPI)",                            8, ThreatLevel.Suspicious),
            new ApiEntry("CryptGenKey",                "Crypto", "Generates a cryptographic key",                        8, ThreatLevel.Suspicious),
            new ApiEntry("BCryptEncrypt",              "Crypto", "BCrypt bulk encryption",                               8, ThreatLevel.Suspicious),
            new ApiEntry("BCryptGenerateSymmetricKey", "Crypto", "Generates BCrypt symmetric key",                       8, ThreatLevel.Suspicious),

            // --- Anti-debug ---
            new ApiEntry("IsDebuggerPresent",            "AntiDebug", "Checks for attached debugger",                    20, ThreatLevel.Likely),
            new ApiEntry("CheckRemoteDebuggerPresent",   "AntiDebug", "Checks for remote debugger",                      20, ThreatLevel.Likely),
            new ApiEntry("NtQueryInformationProcess",    "AntiDebug", "Debugger detection via NtQueryInfo",              20, ThreatLevel.Likely),
            new ApiEntry("OutputDebugString",            "AntiDebug", "Timing-based anti-debug trick",                    5, ThreatLevel.Suspicious),
            new ApiEntry("FindWindow",                   "AntiDebug", "May search for analysis tool windows",             3, ThreatLevel.Suspicious),

            // --- Persistence ---
            // RegSetValueEx / RegCreateKeyEx are used by every installer.
            // Only score if combined with other indicators (cluster bonus).
            new ApiEntry("RegSetValueEx",           "Persist",   "Writes a registry value",                              5, ThreatLevel.Suspicious),
            new ApiEntry("RegCreateKeyEx",          "Persist",   "Creates a registry key",                               3, ThreatLevel.Suspicious),
            new ApiEntry("CreateService",           "Persist",   "Creates a Windows service",                           20, ThreatLevel.Likely),

            // --- Dynamic resolution ---
            // GetProcAddress + LoadLibrary appear in virtually every Windows binary.
            // Score is minimal; they are only relevant alongside injection APIs.
            new ApiEntry("GetProcAddress",          "DynResolve", "Resolves API at runtime",                             5, ThreatLevel.Suspicious),
            new ApiEntry("LoadLibrary",             "DynResolve", "Loads DLL at runtime",                                3, ThreatLevel.Suspicious),
            new ApiEntry("LdrLoadDll",              "DynResolve", "NT-level DLL loading",                               20, ThreatLevel.Likely),
        };

        public void Analyze(ReadOnlySpan<byte> fileBytes, ScanResult result)
        {
            if (fileBytes.Length < 64) return;
            if (fileBytes[0] != 0x4D || fileBytes[1] != 0x5A) return;

            int e_lfanew = ReadInt32(fileBytes, 0x3C);
            if (e_lfanew <= 0 || e_lfanew + 24 > fileBytes.Length) return;
            if (fileBytes[e_lfanew] != 0x50 || fileBytes[e_lfanew + 1] != 0x45) return;

            int coffOffset = e_lfanew + 4;
            if (coffOffset + 20 > fileBytes.Length) return;

            ushort sizeOfOptionalHeader = ReadUInt16(fileBytes, coffOffset + 16);
            int optOffset = coffOffset + 20;
            if (optOffset + 2 > fileBytes.Length) return;

            ushort magic = ReadUInt16(fileBytes, optOffset);
            bool is64 = magic == 0x020B;
            bool is32 = magic == 0x010B;
            if (!is32 && !is64) return;

            int importDirOffset = is64 ? optOffset + 120 : optOffset + 104;
            if (importDirOffset + 8 > fileBytes.Length) return;

            uint importRva  = ReadUInt32(fileBytes, importDirOffset);
            uint importSize = ReadUInt32(fileBytes, importDirOffset + 4);
            if (importRva == 0 || importSize == 0) return;

            ushort numberOfSections = ReadUInt16(fileBytes, coffOffset + 2);
            int sectionTableOffset  = optOffset + sizeOfOptionalHeader;
            List<Section> sections  = ParseSections(fileBytes, sectionTableOffset, numberOfSections);

            int importFileOffset = RvaToOffset(importRva, sections);
            if (importFileOffset <= 0 || importFileOffset >= fileBytes.Length) return;

            HashSet<string> importedFunctions = ParseImportTable(fileBytes, importFileOffset, sections);

            var clusterHits = new Dictionary<string, int>(StringComparer.Ordinal);

            foreach (ApiEntry api in DangerousApis)
            {
                if (importedFunctions.Contains(api.FunctionName))
                {
                    result.AddThreat(new ThreatInfo(
                        api.Level, Name,
                        "[" + api.Cluster + "] Imports '" + api.FunctionName + "' — " + api.Description,
                        api.Score));

                    if (!clusterHits.TryGetValue(api.Cluster, out int count))
                        count = 0;
                    clusterHits[api.Cluster] = count + 1;
                }
            }

            foreach (KeyValuePair<string, int> entry in clusterHits)
            {
                if (entry.Value >= ClusterBonusThreshold)
                {
                    result.AddThreat(new ThreatInfo(
                        ThreatLevel.Likely, Name,
                        "Imports " + entry.Value + " functions from the '" + entry.Key +
                        "' cluster — combination strongly indicative of malicious capability.",
                        score: 20));
                }
            }
        }

        // ---- PE parsing helpers ----

        private sealed class Section
        {
            public uint VirtualAddress { get; }
            public uint VirtualSize    { get; }
            public uint RawOffset      { get; }
            public uint RawSize        { get; }

            public Section(uint virtualAddress, uint virtualSize, uint rawOffset, uint rawSize)
            {
                VirtualAddress = virtualAddress;
                VirtualSize    = virtualSize;
                RawOffset      = rawOffset;
                RawSize        = rawSize;
            }
        }

        private static List<Section> ParseSections(ReadOnlySpan<byte> data, int tableOffset, ushort count)
        {
            var list = new List<Section>(count);
            for (int i = 0; i < count; i++)
            {
                int off = tableOffset + i * 40;
                if (off + 40 > data.Length) break;
                list.Add(new Section(
                    virtualAddress: ReadUInt32(data, off + 12),
                    virtualSize:    ReadUInt32(data, off + 8),
                    rawOffset:      ReadUInt32(data, off + 20),
                    rawSize:        ReadUInt32(data, off + 16)));
            }
            return list;
        }

        private static int RvaToOffset(uint rva, List<Section> sections)
        {
            foreach (Section s in sections)
            {
                if (rva >= s.VirtualAddress && rva < s.VirtualAddress + s.VirtualSize)
                    return (int)(s.RawOffset + (rva - s.VirtualAddress));
            }
            return -1;
        }

        private static HashSet<string> ParseImportTable(
            ReadOnlySpan<byte> data, int importOffset, List<Section> sections)
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            int cursor = importOffset;
            while (cursor + 20 <= data.Length)
            {
                uint originalFirstThunk = ReadUInt32(data, cursor);
                uint nameRva            = ReadUInt32(data, cursor + 12);

                if (originalFirstThunk == 0 && nameRva == 0) break;

                if (originalFirstThunk != 0)
                {
                    int intOffset = RvaToOffset(originalFirstThunk, sections);
                    if (intOffset > 0)
                    {
                        int entry = intOffset;
                        while (entry + 4 <= data.Length)
                        {
                            uint thunk = ReadUInt32(data, entry);
                            if (thunk == 0) break;

                            if ((thunk & 0x80000000) == 0)
                            {
                                int hintNameOffset = RvaToOffset(thunk, sections);
                                if (hintNameOffset >= 0 && hintNameOffset + 2 < data.Length)
                                {
                                    string fname = ReadNullTerminatedAscii(data, hintNameOffset + 2);
                                    if (fname.Length > 0)
                                        names.Add(fname);
                                }
                            }
                            entry += 4;
                        }
                    }
                }

                cursor += 20;
            }

            return names;
        }

        private static string ReadNullTerminatedAscii(ReadOnlySpan<byte> data, int offset)
        {
            var sb = new StringBuilder(32);
            for (int i = offset; i < data.Length && data[i] != 0; i++)
                sb.Append((char)data[i]);
            return sb.ToString();
        }

        private static ushort ReadUInt16(ReadOnlySpan<byte> data, int offset) =>
            (ushort)(data[offset] | (data[offset + 1] << 8));

        private static uint ReadUInt32(ReadOnlySpan<byte> data, int offset) =>
            (uint)(data[offset] |
                   (data[offset + 1] << 8) |
                   (data[offset + 2] << 16) |
                   (data[offset + 3] << 24));

        private static int ReadInt32(ReadOnlySpan<byte> data, int offset) =>
            data[offset] |
            (data[offset + 1] << 8) |
            (data[offset + 2] << 16) |
            (data[offset + 3] << 24);
    }
}
