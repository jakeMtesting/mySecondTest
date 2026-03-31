using AntivirusScanner.Heuristics;
using AntivirusScanner.Models;
using System.Security.Cryptography;

namespace AntivirusScanner;

/// <summary>
/// Orchestrates all registered heuristics against a single file.
/// Heuristics are run in declaration order; results accumulate into a
/// <see cref="ScanResult"/> whose overall verdict is derived from the
/// combined score of all <see cref="ThreatInfo"/> entries.
/// </summary>
public sealed class Scanner
{
    private readonly IReadOnlyList<IHeuristic> _heuristics;

    public Scanner()
    {
        _heuristics =
        [
            new PEHeaderHeuristic(),
            new EntropyHeuristic(),
            new ImportTableHeuristic(),
            new SuspiciousStringHeuristic(),
        ];
    }

    /// <summary>
    /// Scans the file at <paramref name="filePath"/> and returns a populated
    /// <see cref="ScanResult"/>.
    /// </summary>
    /// <exception cref="FileNotFoundException">
    /// Thrown when the target file does not exist.
    /// </exception>
    /// <exception cref="IOException">
    /// Thrown when the file cannot be read (permissions, locked, etc.).
    /// </exception>
    public ScanResult Scan(string filePath)
    {
        var info = new FileInfo(filePath);
        if (!info.Exists)
            throw new FileNotFoundException($"File not found: '{filePath}'");

        byte[] fileBytes = File.ReadAllBytes(filePath);
        string sha256    = ComputeSha256(fileBytes);

        var scanResult = new ScanResult(filePath, info.Length, sha256);

        foreach (var heuristic in _heuristics)
        {
            try
            {
                heuristic.Analyze(fileBytes.AsSpan(), scanResult);
            }
            catch (Exception ex)
            {
                // A buggy heuristic must not abort the entire scan
                scanResult.AddThreat(new ThreatInfo(
                    ThreatLevel.Clean,
                    heuristic.Name,
                    $"Heuristic threw an unexpected exception: {ex.Message}",
                    score: 0));
            }
        }

        return scanResult;
    }

    private static string ComputeSha256(byte[] data)
    {
        byte[] hash = SHA256.HashData(data);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
