using AntivirusScanner.Models;

namespace AntivirusScanner.Heuristics;

/// <summary>
/// Computes Shannon entropy across the whole file and, for PE files, across
/// each individual section.  Very high entropy (close to 8.0 bits/byte)
/// indicates encrypted or compressed content — a hallmark of packed malware.
///
/// Thresholds (empirically established):
///   >= 7.2  — high: likely packed / encrypted
///   >= 6.5  — elevated: possibly compressed or obfuscated
///   <= 1.0  — abnormally low: may be a sparse file or intentional padding
/// </summary>
public sealed class EntropyHeuristic : IHeuristic
{
    public string Name => "Entropy Analysis";

    private const double HighEntropyThreshold     = 7.2;
    private const double ElevatedEntropyThreshold = 6.5;
    private const double LowEntropyThreshold      = 1.0;

    // Minimum chunk size worth analysing independently
    private const int MinChunkSize = 256;

    public void Analyze(ReadOnlySpan<byte> fileBytes, ScanResult result)
    {
        if (fileBytes.Length < MinChunkSize)
            return;

        double fileEntropy = ComputeEntropy(fileBytes);

        if (fileEntropy >= HighEntropyThreshold)
        {
            result.AddThreat(new ThreatInfo(
                ThreatLevel.Likely, Name,
                $"Whole-file Shannon entropy is {fileEntropy:F2} bits/byte (threshold: {HighEntropyThreshold}) — strongly suggests packing or encryption.",
                score: 30));
        }
        else if (fileEntropy >= ElevatedEntropyThreshold)
        {
            result.AddThreat(new ThreatInfo(
                ThreatLevel.Suspicious, Name,
                $"Whole-file Shannon entropy is {fileEntropy:F2} bits/byte (threshold: {ElevatedEntropyThreshold}) — may indicate compression or obfuscation.",
                score: 15));
        }
        else if (fileEntropy <= LowEntropyThreshold && fileBytes.Length > 4096)
        {
            result.AddThreat(new ThreatInfo(
                ThreatLevel.Suspicious, Name,
                $"Whole-file Shannon entropy is abnormally low ({fileEntropy:F2} bits/byte) — could be a padding-heavy dropper or a sparse payload.",
                score: 10));
        }

        // Per-section entropy for PE files
        AnalyzePESections(fileBytes, result);
    }

    private void AnalyzePESections(ReadOnlySpan<byte> fileBytes, ScanResult result)
    {
        if (fileBytes.Length < 64) return;
        if (fileBytes[0] != 0x4D || fileBytes[1] != 0x5A) return; // not MZ

        int e_lfanew = ReadInt32(fileBytes, 0x3C);
        if (e_lfanew <= 0 || e_lfanew + 24 > fileBytes.Length) return;
        if (fileBytes[e_lfanew] != 0x50 || fileBytes[e_lfanew + 1] != 0x45) return;

        int coffOffset = e_lfanew + 4;
        if (coffOffset + 20 > fileBytes.Length) return;

        ushort numberOfSections     = ReadUInt16(fileBytes, coffOffset + 2);
        ushort sizeOfOptionalHeader = ReadUInt16(fileBytes, coffOffset + 16);

        int sectionTableOffset = coffOffset + 20 + sizeOfOptionalHeader;

        int highEntropySections = 0;

        for (int i = 0; i < numberOfSections; i++)
        {
            int secOffset = sectionTableOffset + i * 40;
            if (secOffset + 40 > fileBytes.Length) break;

            string sectionName  = ReadSectionName(fileBytes, secOffset);
            uint rawSize        = ReadUInt32(fileBytes, secOffset + 16);
            uint rawDataOffset  = ReadUInt32(fileBytes, secOffset + 20);

            if (rawSize < MinChunkSize || rawDataOffset == 0) continue;
            if (rawDataOffset + rawSize > fileBytes.Length) continue;

            ReadOnlySpan<byte> sectionData = fileBytes.Slice((int)rawDataOffset, (int)rawSize);
            double entropy = ComputeEntropy(sectionData);

            if (entropy >= HighEntropyThreshold)
            {
                highEntropySections++;
                result.AddThreat(new ThreatInfo(
                    ThreatLevel.Suspicious, Name,
                    $"PE section '{sectionName}' entropy = {entropy:F2} — likely packed or encrypted region.",
                    score: 15));
            }
        }
    }

    /// <summary>
    /// Computes the Shannon entropy H = -sum(p * log2(p)) over the byte distribution.
    /// </summary>
    private static double ComputeEntropy(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return 0.0;

        Span<int> freq = stackalloc int[256];
        foreach (byte b in data)
            freq[b]++;

        double entropy = 0.0;
        double len = data.Length;
        for (int i = 0; i < 256; i++)
        {
            if (freq[i] == 0) continue;
            double p = freq[i] / len;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
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
}
