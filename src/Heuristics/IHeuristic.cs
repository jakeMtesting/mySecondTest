using AntivirusScanner.Models;

namespace AntivirusScanner.Heuristics;

/// <summary>
/// Contract for all heuristic analysers. Each implementation inspects the
/// raw file bytes and appends any discovered <see cref="ThreatInfo"/> entries
/// to the supplied <see cref="ScanResult"/>.
/// </summary>
public interface IHeuristic
{
    string Name { get; }
    void Analyze(ReadOnlySpan<byte> fileBytes, ScanResult result);
}
