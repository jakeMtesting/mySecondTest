namespace AntivirusScanner.Models
{
    public enum ThreatLevel
    {
        Clean = 0,
        Suspicious = 1,
        Likely = 2,
        Malicious = 3
    }

    public sealed class ThreatInfo
    {
        public ThreatLevel Level { get; }
        public string HeuristicName { get; }
        public string Description { get; }
        public int Score { get; }

        public ThreatInfo(ThreatLevel level, string heuristicName, string description, int score)
        {
            Level = level;
            HeuristicName = heuristicName;
            Description = description;
            Score = score;
        }

        public override string ToString() =>
            $"[{Level}] ({HeuristicName}) {Description} (score: +{Score})";
    }
}
