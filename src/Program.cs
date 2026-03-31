using AntivirusScanner;
using AntivirusScanner.Models;

// ─── Colour helpers ────────────────────────────────────────────────────────────

static ConsoleColor ColorFor(ThreatLevel level) => level switch
{
    ThreatLevel.Malicious  => ConsoleColor.Red,
    ThreatLevel.Likely     => ConsoleColor.DarkYellow,
    ThreatLevel.Suspicious => ConsoleColor.Yellow,
    _                      => ConsoleColor.Green,
};

static void WriteColored(string text, ConsoleColor color)
{
    Console.ForegroundColor = color;
    Console.Write(text);
    Console.ResetColor();
}

static void WriteColoredLine(string text, ConsoleColor color)
{
    WriteColored(text, color);
    Console.WriteLine();
}

// ─── Banner ───────────────────────────────────────────────────────────────────

static void PrintBanner()
{
    Console.WriteLine();
    WriteColoredLine("╔══════════════════════════════════════════════════╗", ConsoleColor.Cyan);
    WriteColoredLine("║        C# Heuristic Antivirus Scanner  v1.0     ║", ConsoleColor.Cyan);
    WriteColoredLine("╚══════════════════════════════════════════════════╝", ConsoleColor.Cyan);
    Console.WriteLine();
}

// ─── Usage ────────────────────────────────────────────────────────────────────

static void PrintUsage()
{
    Console.Error.WriteLine("Usage: AntivirusScanner <file-path> [--verbose]");
    Console.Error.WriteLine();
    Console.Error.WriteLine("Options:");
    Console.Error.WriteLine("  --verbose   Show every individual finding");
    Console.Error.WriteLine("  --no-color  Disable ANSI colour output");
    Console.Error.WriteLine();
    Console.Error.WriteLine("Exit codes:");
    Console.Error.WriteLine("  0  Clean");
    Console.Error.WriteLine("  1  Suspicious");
    Console.Error.WriteLine("  2  Likely malicious");
    Console.Error.WriteLine("  3  Malicious");
    Console.Error.WriteLine("  9  Error (file not found / unreadable)");
}

// ─── Entry point ──────────────────────────────────────────────────────────────

if (args.Length == 0)
{
    PrintBanner();
    PrintUsage();
    return 9;
}

bool verbose  = args.Contains("--verbose",  StringComparer.OrdinalIgnoreCase);
bool noColor  = args.Contains("--no-color", StringComparer.OrdinalIgnoreCase);

if (noColor)
    Console.OutputEncoding = System.Text.Encoding.ASCII;

string filePath = args.First(a => !a.StartsWith("--"));

PrintBanner();

Console.WriteLine($"  Target : {filePath}");

ScanResult result;
try
{
    var scanner = new Scanner();

    Console.WriteLine("  Status : Scanning...");
    Console.WriteLine();

    result = scanner.Scan(filePath);
}
catch (FileNotFoundException ex)
{
    WriteColoredLine($"[ERROR] {ex.Message}", ConsoleColor.Red);
    return 9;
}
catch (UnauthorizedAccessException)
{
    WriteColoredLine($"[ERROR] Access denied reading '{filePath}'.", ConsoleColor.Red);
    return 9;
}
catch (IOException ex)
{
    WriteColoredLine($"[ERROR] I/O error: {ex.Message}", ConsoleColor.Red);
    return 9;
}

// ─── Results ──────────────────────────────────────────────────────────────────

Console.WriteLine($"  File   : {Path.GetFileName(result.FilePath)}");
Console.WriteLine($"  Size   : {result.FileSize:N0} bytes");
Console.WriteLine($"  SHA256 : {result.FileSha256}");
Console.WriteLine();

if (result.Threats.Count == 0 || result.OverallThreatLevel == ThreatLevel.Clean)
{
    WriteColoredLine("  ✔  No threats detected — file appears clean.", ConsoleColor.Green);
}
else
{
    ConsoleColor verdictColor = ColorFor(result.OverallThreatLevel);
    string verdictLabel = result.OverallThreatLevel switch
    {
        ThreatLevel.Malicious  => "MALICIOUS",
        ThreatLevel.Likely     => "LIKELY MALICIOUS",
        ThreatLevel.Suspicious => "SUSPICIOUS",
        _                      => "CLEAN",
    };

    WriteColored($"  Verdict : ", ConsoleColor.White);
    WriteColoredLine($"[{verdictLabel}]  (total score: {result.TotalScore})", verdictColor);
    Console.WriteLine();

    // Group findings by heuristic
    var groups = result.Threats
        .GroupBy(t => t.HeuristicName)
        .OrderByDescending(g => g.Sum(t => t.Score));

    foreach (var group in groups)
    {
        var groupScore = group.Sum(t => t.Score);
        WriteColoredLine($"  ┌─ {group.Key}  (group score: {groupScore})", ConsoleColor.Cyan);

        // In non-verbose mode show only Likely / Malicious findings
        var toShow = verbose
            ? group.OrderByDescending(t => t.Score)
            : group.Where(t => t.Level >= ThreatLevel.Likely).OrderByDescending(t => t.Score);

        foreach (var threat in toShow)
        {
            ConsoleColor tc = ColorFor(threat.Level);
            Console.Write("  │  ");
            WriteColored($"[{threat.Level,-11}]", tc);
            Console.WriteLine($" {threat.Description}");
        }

        int hiddenCount = group.Count() - toShow.Count();
        if (hiddenCount > 0)
            Console.WriteLine($"  │  ... and {hiddenCount} more Suspicious finding(s) (use --verbose to see all)");

        WriteColoredLine("  └─────────────────────────────────────────────────", ConsoleColor.Cyan);
    }
}

Console.WriteLine();

// ─── Exit code mirrors the threat level ───────────────────────────────────────
return (int)result.OverallThreatLevel;
