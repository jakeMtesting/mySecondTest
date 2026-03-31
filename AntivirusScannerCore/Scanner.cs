using AntivirusScanner.Heuristics;
using AntivirusScanner.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace AntivirusScanner
{
    /// <summary>
    /// Orchestrates all registered heuristics against a single file.
    /// Heuristics run in declaration order and accumulate findings into a
    /// <see cref="ScanResult"/>.  Mitigating heuristics (e.g. Authenticode)
    /// can reduce the effective score via <see cref="ScanResult.AddMitigation"/>.
    /// </summary>
    public sealed class Scanner
    {
        private readonly IReadOnlyList<IHeuristic> _heuristics;

        public Scanner()
        {
            _heuristics = new List<IHeuristic>
            {
                new PEHeaderHeuristic(),
                new EntropyHeuristic(),
                new ImportTableHeuristic(),
                new SuspiciousStringHeuristic(),
                new AuthenticodeHeuristic(),   // runs last so it can mitigate the above
            };
        }

        /// <summary>
        /// Scans the file at <paramref name="filePath"/> and returns a populated
        /// <see cref="ScanResult"/>.
        /// </summary>
        public ScanResult Scan(string filePath)
        {
            var info = new FileInfo(filePath);
            if (!info.Exists)
                throw new FileNotFoundException($"File not found: '{filePath}'");

            byte[] fileBytes = File.ReadAllBytes(filePath);
            string sha256    = ComputeSha256(fileBytes);

            var scanResult = new ScanResult(filePath, info.Length, sha256);

            foreach (IHeuristic heuristic in _heuristics)
            {
                try
                {
                    heuristic.Analyze(fileBytes.AsSpan(), scanResult);
                }
                catch (Exception ex)
                {
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
            using (var sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(data);
                return BitConverter.ToString(hash).Replace("-", string.Empty).ToLowerInvariant();
            }
        }
    }
}
