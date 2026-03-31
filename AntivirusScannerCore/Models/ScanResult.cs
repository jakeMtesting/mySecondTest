using System.Collections.Generic;
using System.Linq;

namespace AntivirusScanner.Models
{
    public sealed class ScanResult
    {
        public string FilePath { get; }
        public long FileSize { get; }
        public string FileSha256 { get; }

        /// <summary>Positive-score findings from heuristics.</summary>
        public List<ThreatInfo> Threats { get; } = new List<ThreatInfo>();

        /// <summary>
        /// Mitigating signals (e.g. Authenticode signature present) that reduce
        /// the raw score.  Each entry carries a positive <see cref="ThreatInfo.Score"/>
        /// that is subtracted from the total.
        /// </summary>
        public List<ThreatInfo> Mitigations { get; } = new List<ThreatInfo>();

        public int RawScore      => Threats.Sum(t => t.Score);
        public int MitigatedBy   => Mitigations.Sum(m => m.Score);
        public int TotalScore    => System.Math.Max(0, RawScore - MitigatedBy);

        public ThreatLevel OverallThreatLevel =>
            TotalScore >= 120 ? ThreatLevel.Malicious :
            TotalScore >=  65 ? ThreatLevel.Likely :
            TotalScore >=  25 ? ThreatLevel.Suspicious :
            ThreatLevel.Clean;

        public ScanResult(string filePath, long fileSize, string fileSha256)
        {
            FilePath = filePath;
            FileSize = fileSize;
            FileSha256 = fileSha256;
        }

        public void AddThreat(ThreatInfo threat)     => Threats.Add(threat);
        public void AddMitigation(ThreatInfo signal) => Mitigations.Add(signal);
    }
}
