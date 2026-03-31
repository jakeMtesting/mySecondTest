namespace AntivirusScanner.Models;

public sealed class ScanResult
{
    public string FilePath { get; }
    public long FileSize { get; }
    public string FileSha256 { get; }
    public List<ThreatInfo> Threats { get; } = [];
    public int TotalScore => Threats.Sum(t => t.Score);

    public ThreatLevel OverallThreatLevel =>
        TotalScore >= 80 ? ThreatLevel.Malicious :
        TotalScore >= 40 ? ThreatLevel.Likely :
        TotalScore >= 15 ? ThreatLevel.Suspicious :
        ThreatLevel.Clean;

    public ScanResult(string filePath, long fileSize, string fileSha256)
    {
        FilePath = filePath;
        FileSize = fileSize;
        FileSha256 = fileSha256;
    }

    public void AddThreat(ThreatInfo threat) => Threats.Add(threat);
}
