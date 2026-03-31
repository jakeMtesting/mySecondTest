using AntivirusScanner;
using AntivirusScanner.Models;
using System;
using System.IO;
using System.Linq;

static ConsoleColor ColorFor(ThreatLevel level)
{
    switch (level)
    {
        case ThreatLevel.Malicious:  return ConsoleColor.Red;
        case ThreatLevel.Likely:     return ConsoleColor.DarkYellow;
        case ThreatLevel.Suspicious: return ConsoleColor.Yellow;
        default:                     return ConsoleColor.Green;
    }
}

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

static void PrintBanner()
{
    Console.WriteLine();
    WriteColoredLine("╔══════════════════════════════════════════════════╗", ConsoleColor.Cyan);
    WriteColoredLine("║        C# Heuristic Antivirus Scanner  v1.0     ║", ConsoleColor.Cyan);
    WriteColoredLine("╚══════════════════════════════════════════════════╝", ConsoleColor.Cyan);
    Console.WriteLine();
}

static void PrintUsage()
{
    Console.Error.WriteLine("Usage: AntivirusScanner <file-path> [--verbose] [--no-color]");
    Console.Error.WriteLine();
    Console.Error.WriteLine("Options:");
    Console.Error.WriteLine("  --verbose   Show every individual finding");
    Console.Error.WriteLine("  --no-color  Disable colour output");
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

bool verbose = Array.Exists(args, a => string.Equals(a, "--verbose",  StringComparison.OrdinalIgnoreCase));
bool noColor = Array.Exists(args, a => string.Equals(a, "--no-color", StringComparison.OrdinalIgnoreCase));

string filePath = null;
foreach (string arg in args)
{
    if (!arg.StartsWith("--"))
    {
        filePath = arg;
        break;
    }
}

if (filePath == null)
{
    Console.Error.WriteLine("[ERROR] No file path provided.");
    PrintUsage();
    return 9;
}

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
    WriteColoredLine("  No threats detected — file appears clean.", ConsoleColor.Green);
}
else
{
    string verdictLabel;
    switch (result.OverallThreatLevel)
    {
        case ThreatLevel.Malicious:  verdictLabel = "MALICIOUS";         break;
        case ThreatLevel.Likely:     verdictLabel = "LIKELY MALICIOUS";  break;
        case ThreatLevel.Suspicious: verdictLabel = "SUSPICIOUS";        break;
        default:                     verdictLabel = "CLEAN";             break;
    }

    ConsoleColor verdictColor = ColorFor(result.OverallThreatLevel);
    WriteColored("  Verdict : ", ConsoleColor.White);
    WriteColoredLine($"[{verdictLabel}]  (total score: {result.TotalScore})", verdictColor);
    Console.WriteLine();

    var groups = result.Threats
        .GroupBy(t => t.HeuristicName)
        .OrderByDescending(g => g.Sum(t => t.Score));

    foreach (var group in groups)
    {
        int groupScore = group.Sum(t => t.Score);
        WriteColoredLine($"  ┌─ {group.Key}  (group score: {groupScore})", ConsoleColor.Cyan);

        var toShow = verbose
            ? group.OrderByDescending(t => t.Score)
            : group.Where(t => t.Level >= ThreatLevel.Likely).OrderByDescending(t => t.Score);

        foreach (ThreatInfo threat in toShow)
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
return (int)result.OverallThreatLevel;
