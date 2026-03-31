using AntivirusScanner.Models;
using System.Text;

namespace AntivirusScanner.Heuristics;

/// <summary>
/// Walks the PE Import Directory Table and scores the binary based on which
/// Win32 APIs it imports.  Dangerous APIs are grouped into functional clusters;
/// importing several APIs from the same cluster (or from multiple clusters)
/// provides stronger evidence of malicious intent than a single hit.
///
/// Clusters examined:
///   - Process injection / hollowing
///   - Keylogging / hooking
///   - Privilege escalation
///   - Network connectivity
///   - Crypto (may indicate ransomware)
///   - Anti-debug / sandbox evasion
///   - File / registry persistence
/// </summary>
public sealed class ImportTableHeuristic : IHeuristic
{
    public string Name => "Import Table Analysis";

    private record ApiEntry(string FunctionName, string Cluster, string Description, int Score, ThreatLevel Level);

    private static readonly ApiEntry[] DangerousApis =
    [
        // --- Process injection ---
        new("VirtualAllocEx",          "Injection", "Allocates memory in a remote process",                 25, ThreatLevel.Likely),
        new("WriteProcessMemory",      "Injection", "Writes data into another process",                     25, ThreatLevel.Likely),
        new("CreateRemoteThread",      "Injection", "Creates a thread in another process",                  30, ThreatLevel.Likely),
        new("NtCreateThreadEx",        "Injection", "NT-level remote thread creation",                      30, ThreatLevel.Likely),
        new("RtlCreateUserThread",     "Injection", "User-mode thread injection primitive",                 30, ThreatLevel.Likely),
        new("OpenProcess",             "Injection", "Opens a handle to another process",                    10, ThreatLevel.Suspicious),
        new("QueueUserAPC",            "Injection", "APC-based injection",                                  25, ThreatLevel.Likely),
        new("SetThreadContext",        "Injection", "Thread context manipulation (process hollowing)",      25, ThreatLevel.Likely),
        new("NtUnmapViewOfSection",    "Injection", "Unmaps section (process hollowing)",                   30, ThreatLevel.Likely),
        new("ZwUnmapViewOfSection",    "Injection", "Unmaps section — Zw variant (process hollowing)",     30, ThreatLevel.Likely),

        // --- Hooking / keylogging ---
        new("SetWindowsHookEx",        "Hooking",   "Installs a system-wide hook (keylogging / injection)", 25, ThreatLevel.Likely),
        new("GetAsyncKeyState",        "Hooking",   "Polls keystroke state — keylogger pattern",             20, ThreatLevel.Likely),
        new("GetKeyState",             "Hooking",   "Reads key state — keylogger pattern",                   15, ThreatLevel.Suspicious),

        // --- Privilege escalation ---
        new("AdjustTokenPrivileges",   "Privesc",   "Adjusts access token privileges",                      15, ThreatLevel.Suspicious),
        new("LookupPrivilegeValue",    "Privesc",   "Looks up privilege LUID (precedes AdjustToken)",       10, ThreatLevel.Suspicious),
        new("OpenProcessToken",        "Privesc",   "Opens a process token for manipulation",               10, ThreatLevel.Suspicious),

        // --- Network ---
        new("WSAStartup",              "Network",   "Initialises Winsock",                                   8, ThreatLevel.Suspicious),
        new("connect",                 "Network",   "TCP/UDP connection",                                    10, ThreatLevel.Suspicious),
        new("send",                    "Network",   "Sends data over a socket",                               8, ThreatLevel.Suspicious),
        new("recv",                    "Network",   "Receives data from a socket",                            8, ThreatLevel.Suspicious),
        new("InternetOpenUrl",         "Network",   "Opens a URL (WinINet)",                                 10, ThreatLevel.Suspicious),
        new("URLDownloadToFile",       "Network",   "Downloads file from URL",                              25, ThreatLevel.Likely),
        new("HttpSendRequest",         "Network",   "HTTP request (WinINet)",                               10, ThreatLevel.Suspicious),
        new("WinHttpConnect",          "Network",   "WinHTTP connection",                                   10, ThreatLevel.Suspicious),

        // --- Crypto (ransomware / C2 encryption) ---
        new("CryptEncrypt",            "Crypto",    "Encrypts data (DPAPI/BCrypt)",                         20, ThreatLevel.Suspicious),
        new("CryptGenKey",             "Crypto",    "Generates a cryptographic key",                        20, ThreatLevel.Suspicious),
        new("BCryptEncrypt",           "Crypto",    "BCrypt encryption — bulk data encryption",             20, ThreatLevel.Suspicious),
        new("BCryptGenerateSymmetricKey", "Crypto", "Generates symmetric key (BCrypt)",                    20, ThreatLevel.Suspicious),

        // --- Anti-debug ---
        new("IsDebuggerPresent",       "AntiDebug", "Checks for attached debugger",                         20, ThreatLevel.Likely),
        new("CheckRemoteDebuggerPresent", "AntiDebug", "Checks for remote debugger",                        20, ThreatLevel.Likely),
        new("NtQueryInformationProcess", "AntiDebug", "Queries process info (used to detect debugger)",    20, ThreatLevel.Likely),
        new("OutputDebugString",       "AntiDebug", "Timing-based anti-debug trick",                       10, ThreatLevel.Suspicious),
        new("FindWindow",              "AntiDebug", "May search for analysis tool windows",                  8, ThreatLevel.Suspicious),

        // --- Persistence ---
        new("RegSetValueEx",           "Persist",   "Writes a registry value",                             15, ThreatLevel.Suspicious),
        new("RegCreateKeyEx",          "Persist",   "Creates a registry key",                              10, ThreatLevel.Suspicious),
        new("CreateService",           "Persist",   "Creates a Windows service",                           25, ThreatLevel.Likely),

        // --- Dynamic resolution (common in shellcode / reflective loaders) ---
        new("GetProcAddress",          "DynResolve","Resolves API at runtime (common in injectors)",       15, ThreatLevel.Suspicious),
        new("LoadLibrary",             "DynResolve","Loads DLL at runtime",                                10, ThreatLevel.Suspicious),
        new("LdrLoadDll",              "DynResolve","NT-level DLL loading",                                20, ThreatLevel.Likely),
    ];

    public void Analyze(ReadOnlySpan<byte> fileBytes, ScanResult result)
    {
        if (fileBytes.Length < 64) return;
        if (fileBytes[0] != 0x4D || fileBytes[1] != 0x5A) return; // not MZ

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

        // Import directory entry is at data directory index 1
        // PE32:  optional header is 224 bytes; import dir at offset 104 from opt start
        // PE32+: optional header is 240 bytes; import dir at offset 120 from opt start
        int importDirOffset = is64 ? optOffset + 120 : optOffset + 104;
        if (importDirOffset + 8 > fileBytes.Length) return;

        uint importRva  = ReadUInt32(fileBytes, importDirOffset);
        uint importSize = ReadUInt32(fileBytes, importDirOffset + 4);

        if (importRva == 0 || importSize == 0) return;

        // Build section table for RVA → file offset translation
        ushort numberOfSections     = ReadUInt16(fileBytes, coffOffset + 2);
        int    sectionTableOffset   = optOffset + sizeOfOptionalHeader;
        var    sections             = ParseSections(fileBytes, sectionTableOffset, numberOfSections);

        int importFileOffset = RvaToOffset(importRva, sections);
        if (importFileOffset <= 0 || importFileOffset >= fileBytes.Length) return;

        var importedFunctions = ParseImportTable(fileBytes, importFileOffset, sections);

        // Score against the dangerous API list
        var clusterHits = new Dictionary<string, int>(StringComparer.Ordinal);

        foreach (var api in DangerousApis)
        {
            if (importedFunctions.Contains(api.FunctionName, StringComparer.OrdinalIgnoreCase))
            {
                result.AddThreat(new ThreatInfo(
                    api.Level, Name,
                    $"[{api.Cluster}] Imports '{api.FunctionName}' — {api.Description}",
                    api.Score));

                clusterHits.TryGetValue(api.Cluster, out int count);
                clusterHits[api.Cluster] = count + 1;
            }
        }

        // Bonus score for multiple hits within the same cluster (combination attack)
        foreach (var (cluster, count) in clusterHits)
        {
            if (count >= 3)
            {
                result.AddThreat(new ThreatInfo(
                    ThreatLevel.Likely, Name,
                    $"Imports {count} functions from the '{cluster}' cluster — strongly indicative of malicious capability.",
                    score: 20));
            }
        }
    }

    // ---- PE parsing helpers ----

    private record Section(uint VirtualAddress, uint VirtualSize, uint RawOffset, uint RawSize);

    private static List<Section> ParseSections(ReadOnlySpan<byte> data, int tableOffset, ushort count)
    {
        var list = new List<Section>(count);
        for (int i = 0; i < count; i++)
        {
            int off = tableOffset + i * 40;
            if (off + 40 > data.Length) break;
            list.Add(new Section(
                VirtualAddress: ReadUInt32(data, off + 12),
                VirtualSize:    ReadUInt32(data, off + 8),
                RawOffset:      ReadUInt32(data, off + 20),
                RawSize:        ReadUInt32(data, off + 16)));
        }
        return list;
    }

    private static int RvaToOffset(uint rva, List<Section> sections)
    {
        foreach (var s in sections)
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

        // Walk IMAGE_IMPORT_DESCRIPTOR entries (20 bytes each, null-terminated)
        int cursor = importOffset;
        while (cursor + 20 <= data.Length)
        {
            uint originalFirstThunk = ReadUInt32(data, cursor);
            uint nameRva            = ReadUInt32(data, cursor + 12);

            // End of import directory
            if (originalFirstThunk == 0 && nameRva == 0) break;

            // Walk the import name table (INT)
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

                        // High bit set = ordinal import, no name
                        if ((thunk & 0x80000000) == 0)
                        {
                            int hintNameOffset = RvaToOffset(thunk, sections);
                            if (hintNameOffset >= 0 && hintNameOffset + 2 < data.Length)
                            {
                                // Skip 2-byte hint, read null-terminated name
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
