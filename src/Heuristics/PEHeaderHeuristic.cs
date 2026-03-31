using AntivirusScanner.Models;
using System.Text;

namespace AntivirusScanner.Heuristics;

/// <summary>
/// Parses the Portable Executable (PE) format and flags anomalies that are
/// commonly observed in malicious binaries:
///   - Suspicious / obfuscated section names
///   - Sections with executable + writable flags simultaneously
///   - Raw-size / virtual-size mismatches (common in packers)
///   - TLS callbacks (anti-analysis technique)
///   - Overlay data appended after the last section
///   - Invalid or truncated PE structures
///   - Mismatched file extension vs. actual format
/// </summary>
public sealed class PEHeaderHeuristic : IHeuristic
{
    public string Name => "PE Header Analysis";

    // Known packer / protector section names
    private static readonly HashSet<string> SuspiciousSectionNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "UPX0", "UPX1", "UPX2",
        ".packed", ".pack",
        "ASPack", ".aspack",
        "PESpin", ".spinp",
        "Themida", ".themida",
        "execryptor", ".exc",
        ".vmp0", ".vmp1", ".vmp2",
        "PEBundle", "PECompact",
        ".nsp0", ".nsp1",
        ".MPRESS1", ".MPRESS2",
        ".enigma1", ".enigma2",
    };

    // Characteristics flags (IMAGE_FILE_HEADER.Characteristics)
    private const ushort IMAGE_FILE_DLL           = 0x2000;
    private const ushort IMAGE_FILE_SYSTEM         = 0x1000;

    // Section flags (IMAGE_SECTION_HEADER.Characteristics)
    private const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;
    private const uint IMAGE_SCN_MEM_WRITE   = 0x80000000;
    private const uint IMAGE_SCN_MEM_READ    = 0x40000000;

    public void Analyze(ReadOnlySpan<byte> fileBytes, ScanResult result)
    {
        if (fileBytes.Length < 64)
            return;

        // --- DOS header ---
        if (fileBytes[0] != 0x4D || fileBytes[1] != 0x5A) // 'MZ'
            return; // Not a PE file — skip silently

        int e_lfanew = ReadInt32(fileBytes, 0x3C);
        if (e_lfanew <= 0 || e_lfanew + 24 > fileBytes.Length)
        {
            result.AddThreat(new ThreatInfo(
                ThreatLevel.Suspicious, Name,
                "DOS header e_lfanew points outside file — truncated or mangled PE.", 20));
            return;
        }

        // --- PE signature ---
        if (fileBytes[e_lfanew]     != 0x50 || // 'P'
            fileBytes[e_lfanew + 1] != 0x45 || // 'E'
            fileBytes[e_lfanew + 2] != 0x00 ||
            fileBytes[e_lfanew + 3] != 0x00)
        {
            result.AddThreat(new ThreatInfo(
                ThreatLevel.Suspicious, Name,
                "MZ magic present but PE signature is missing/invalid.", 25));
            return;
        }

        // --- File header (COFF) ---
        int coffOffset = e_lfanew + 4;
        if (coffOffset + 20 > fileBytes.Length) return;

        ushort machine         = ReadUInt16(fileBytes, coffOffset);
        ushort numberOfSections = ReadUInt16(fileBytes, coffOffset + 2);
        ushort characteristics  = ReadUInt16(fileBytes, coffOffset + 18);
        ushort sizeOfOptionalHeader = ReadUInt16(fileBytes, coffOffset + 16);

        CheckFileExtensionMismatch(fileBytes, result, characteristics);

        // --- Optional header ---
        int optOffset = coffOffset + 20;
        if (optOffset + 2 > fileBytes.Length) return;

        ushort magic = ReadUInt16(fileBytes, optOffset);
        bool is64Bit = magic == 0x020B;
        bool is32Bit = magic == 0x010B;

        if (!is32Bit && !is64Bit)
        {
            result.AddThreat(new ThreatInfo(
                ThreatLevel.Suspicious, Name,
                $"Optional header magic 0x{magic:X4} is neither PE32 (0x010B) nor PE32+ (0x020B).", 20));
            return;
        }

        // TLS directory RVA
        int tlsDirectoryOffset = is64Bit
            ? optOffset + 120   // PE32+ TLS is at index 9, offset 120 into optional header
            : optOffset + 104;  // PE32  TLS is at index 9, offset 104

        bool hasTlsCallbacks = false;
        if (tlsDirectoryOffset + 8 <= optOffset + sizeOfOptionalHeader &&
            tlsDirectoryOffset + 8 <= fileBytes.Length)
        {
            uint tlsRva  = ReadUInt32(fileBytes, tlsDirectoryOffset);
            uint tlsSize = ReadUInt32(fileBytes, tlsDirectoryOffset + 4);
            if (tlsRva != 0 && tlsSize != 0)
                hasTlsCallbacks = true;
        }

        if (hasTlsCallbacks)
        {
            result.AddThreat(new ThreatInfo(
                ThreatLevel.Suspicious, Name,
                "TLS directory is present — may contain TLS callbacks used for anti-analysis or early execution.", 15));
        }

        // --- Section table ---
        int sectionTableOffset = optOffset + sizeOfOptionalHeader;
        if (sectionTableOffset < 0 || sectionTableOffset > fileBytes.Length) return;

        int writableExecSections = 0;
        long lastSectionEnd = 0;

        for (int i = 0; i < numberOfSections; i++)
        {
            int secOffset = sectionTableOffset + i * 40;
            if (secOffset + 40 > fileBytes.Length) break;

            string sectionName = ReadSectionName(fileBytes, secOffset);
            uint virtualSize    = ReadUInt32(fileBytes, secOffset + 8);
            uint rawSize        = ReadUInt32(fileBytes, secOffset + 16);
            uint rawDataOffset  = ReadUInt32(fileBytes, secOffset + 20);
            uint sectionFlags   = ReadUInt32(fileBytes, secOffset + 36);

            // Packer section name check
            if (SuspiciousSectionNames.Contains(sectionName))
            {
                result.AddThreat(new ThreatInfo(
                    ThreatLevel.Likely, Name,
                    $"Section '{sectionName}' matches a known packer/protector signature.", 35));
            }

            // Writable + executable section (common in shellcode loaders)
            bool isExec     = (sectionFlags & IMAGE_SCN_MEM_EXECUTE) != 0;
            bool isWritable = (sectionFlags & IMAGE_SCN_MEM_WRITE)   != 0;
            if (isExec && isWritable)
                writableExecSections++;

            // Virtual size >> raw size: typical packer trick (expand at runtime)
            if (rawSize > 0 && virtualSize > rawSize * 10 && virtualSize > 0x1000)
            {
                result.AddThreat(new ThreatInfo(
                    ThreatLevel.Suspicious, Name,
                    $"Section '{sectionName}': VirtualSize ({virtualSize}) >> RawSize ({rawSize}) — possible runtime unpacker.", 20));
            }

            // Raw size >> virtual size: data stuffed into file but not mapped
            if (virtualSize > 0 && rawSize > virtualSize * 10 && rawSize > 0x1000)
            {
                result.AddThreat(new ThreatInfo(
                    ThreatLevel.Suspicious, Name,
                    $"Section '{sectionName}': RawSize ({rawSize}) >> VirtualSize ({virtualSize}) — possible hidden payload in section.", 15));
            }

            // Track where the last section ends (for overlay detection)
            if (rawDataOffset > 0 && rawSize > 0)
            {
                long sectionEnd = rawDataOffset + rawSize;
                if (sectionEnd > lastSectionEnd)
                    lastSectionEnd = sectionEnd;
            }
        }

        if (writableExecSections >= 1)
        {
            result.AddThreat(new ThreatInfo(
                ThreatLevel.Likely, Name,
                $"{writableExecSections} section(s) are both EXECUTABLE and WRITABLE — hallmark of shellcode loaders and injectors.", 30));
        }

        // Overlay detection: data beyond the last mapped section
        if (lastSectionEnd > 0 && fileBytes.Length > lastSectionEnd + 512)
        {
            long overlaySize = fileBytes.Length - lastSectionEnd;
            result.AddThreat(new ThreatInfo(
                ThreatLevel.Suspicious, Name,
                $"Overlay detected: {overlaySize:N0} bytes appended after the last section — common in droppers and binders.", 20));
        }

        // Zero sections is highly unusual for a valid PE
        if (numberOfSections == 0)
        {
            result.AddThreat(new ThreatInfo(
                ThreatLevel.Suspicious, Name,
                "PE has zero sections — this is abnormal and may indicate a hand-crafted or heavily obfuscated binary.", 25));
        }
    }

    private static void CheckFileExtensionMismatch(
        ReadOnlySpan<byte> fileBytes, ScanResult result, ushort characteristics)
    {
        string ext = Path.GetExtension(result.FilePath).ToLowerInvariant();
        bool isDll = (characteristics & IMAGE_FILE_DLL) != 0;

        if (isDll && ext == ".exe")
        {
            result.AddThreat(new ThreatInfo(
                ThreatLevel.Suspicious, "PE Header Analysis",
                "File has .exe extension but PE characteristics mark it as a DLL — possible masquerading.", 20));
        }
        else if (!isDll && ext == ".dll")
        {
            result.AddThreat(new ThreatInfo(
                ThreatLevel.Suspicious, "PE Header Analysis",
                "File has .dll extension but PE characteristics mark it as an EXE — possible masquerading.", 20));
        }
    }

    // ---- Binary helpers ----

    private static string ReadSectionName(ReadOnlySpan<byte> data, int offset)
    {
        Span<char> chars = stackalloc char[8];
        int len = 0;
        for (int i = 0; i < 8; i++)
        {
            byte b = data[offset + i];
            if (b == 0) break;
            chars[len++] = (char)b;
        }
        return new string(chars[..len]);
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
