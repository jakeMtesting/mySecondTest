using AntivirusScanner;
using AntivirusScanner.Models;
using System;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace AntivirusScannerUI
{
    public partial class MainForm : Form
    {
        // Cascadia Mono may not be installed — fall back to Consolas then Courier New
        private static readonly Font ResultsFont = ResolveMonoFont(9.5f);

        public MainForm()
        {
            InitializeComponent();
            rtbResults.Font = ResultsFont;

            // Wire up drag-and-drop on both the form and the text box
            this.DragEnter        += OnDragEnter;
            this.DragDrop         += OnDragDrop;
            txtFilePath.DragEnter += OnDragEnter;
            txtFilePath.DragDrop  += OnDragDrop;

            // Allow Enter key in the file-path box to trigger scan
            txtFilePath.KeyDown += (s, e) =>
            {
                if (e.KeyCode == Keys.Enter) btnScan.PerformClick();
            };
        }

        // ── Browse ───────────────────────────────────────────────────────────

        private void btnBrowse_Click(object sender, EventArgs e)
        {
            using (var dlg = new OpenFileDialog())
            {
                dlg.Title       = "Select a file to scan";
                dlg.Filter      = "Executables (*.exe;*.dll;*.sys)|*.exe;*.dll;*.sys|All files (*.*)|*.*";
                dlg.FilterIndex = 1;

                if (!string.IsNullOrWhiteSpace(txtFilePath.Text) &&
                    Directory.Exists(Path.GetDirectoryName(txtFilePath.Text)))
                {
                    dlg.InitialDirectory = Path.GetDirectoryName(txtFilePath.Text)!;
                }

                if (dlg.ShowDialog(this) == DialogResult.OK)
                    txtFilePath.Text = dlg.FileName;
            }
        }

        // ── Scan ─────────────────────────────────────────────────────────────

        private async void btnScan_Click(object sender, EventArgs e)
        {
            string path = txtFilePath.Text.Trim();
            if (string.IsNullOrEmpty(path))
            {
                MessageBox.Show("Please select or drag a file onto the window first.",
                    "No file selected", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            SetScanningState(true);
            rtbResults.Clear();

            bool verbose = chkVerbose.Checked;

            ScanResult? result = null;
            Exception? error   = null;

            await Task.Run(() =>
            {
                try
                {
                    result = new Scanner().Scan(path);
                }
                catch (Exception ex)
                {
                    error = ex;
                }
            });

            if (error != null)
            {
                AppendLine("[ERROR] " + error.Message, Color.OrangeRed);
            }
            else if (result != null)
            {
                RenderResults(result, verbose);
            }

            SetScanningState(false);
        }

        // ── Results rendering ─────────────────────────────────────────────────

        private void RenderResults(ScanResult result, bool verbose)
        {
            // ── Header ───────────────────────────────────────────────────────
            AppendLine("File   : " + Path.GetFileName(result.FilePath), Color.White);
            AppendLine($"Size   : {result.FileSize:N0} bytes", Color.White);
            AppendLine("SHA256 : " + result.FileSha256, Color.FromArgb(160, 160, 160));
            AppendLine("", Color.White);

            // ── Mitigations ───────────────────────────────────────────────────
            if (result.Mitigations.Count > 0)
            {
                AppendLine("Mitigating signals:", Color.LimeGreen);
                foreach (ThreatInfo m in result.Mitigations)
                    AppendLine("  + " + m.Description, Color.LimeGreen);

                AppendLine(
                    $"Score  : {result.RawScore} raw  −  {result.MitigatedBy} mitigated" +
                    $"  =  {result.TotalScore} effective",
                    Color.FromArgb(160, 160, 160));
                AppendLine("", Color.White);
            }

            // ── Verdict ───────────────────────────────────────────────────────
            if (result.OverallThreatLevel == ThreatLevel.Clean)
            {
                AppendLine("  ✔  No threats detected — file appears clean.", Color.LimeGreen);
            }
            else
            {
                string verdictLabel;
                Color  verdictColor;

                switch (result.OverallThreatLevel)
                {
                    case ThreatLevel.Malicious:
                        verdictLabel = "MALICIOUS";
                        verdictColor = Color.OrangeRed;
                        break;
                    case ThreatLevel.Likely:
                        verdictLabel = "LIKELY MALICIOUS";
                        verdictColor = Color.Orange;
                        break;
                    case ThreatLevel.Suspicious:
                        verdictLabel = "SUSPICIOUS";
                        verdictColor = Color.Yellow;
                        break;
                    default:
                        verdictLabel = "CLEAN";
                        verdictColor = Color.LimeGreen;
                        break;
                }

                Append("Verdict : ", Color.White);
                AppendLine($"[{verdictLabel}]  (effective score: {result.TotalScore})", verdictColor);
                AppendLine("", Color.White);

                // ── Per-heuristic groups ──────────────────────────────────────
                var groups = result.Threats
                    .GroupBy(t => t.HeuristicName)
                    .OrderByDescending(g => g.Sum(t => t.Score));

                foreach (var group in groups)
                {
                    int groupScore = group.Sum(t => t.Score);
                    AppendLine($"┌─ {group.Key}  (group score: {groupScore})",
                        Color.FromArgb(86, 200, 255));

                    var toShow = verbose
                        ? group.OrderByDescending(t => t.Score)
                        : group.Where(t => t.Level >= ThreatLevel.Likely)
                               .OrderByDescending(t => t.Score);

                    foreach (ThreatInfo threat in toShow)
                    {
                        Append("│  ", Color.FromArgb(86, 200, 255));
                        Append($"[{threat.Level,-11}] ", ThreatColor(threat.Level));
                        AppendLine(threat.Description, Color.FromArgb(220, 220, 220));
                    }

                    int hidden = group.Count() - toShow.Count();
                    if (hidden > 0)
                    {
                        AppendLine(
                            $"│  ... and {hidden} more Suspicious finding(s)" +
                            " — enable Verbose to see all.",
                            Color.FromArgb(130, 130, 130));
                    }

                    AppendLine("└" + new string('─', 60), Color.FromArgb(86, 200, 255));
                }
            }
        }

        // ── RichTextBox helpers ───────────────────────────────────────────────

        private void Append(string text, Color color)
        {
            if (rtbResults.InvokeRequired)
            {
                rtbResults.Invoke(new Action(() => Append(text, color)));
                return;
            }

            rtbResults.SelectionStart  = rtbResults.TextLength;
            rtbResults.SelectionLength = 0;
            rtbResults.SelectionColor  = color;
            rtbResults.AppendText(text);
            rtbResults.SelectionColor  = rtbResults.ForeColor;
            rtbResults.ScrollToCaret();
        }

        private void AppendLine(string text, Color color) => Append(text + "\n", color);

        private static Color ThreatColor(ThreatLevel level)
        {
            switch (level)
            {
                case ThreatLevel.Malicious:  return Color.OrangeRed;
                case ThreatLevel.Likely:     return Color.Orange;
                case ThreatLevel.Suspicious: return Color.Yellow;
                default:                     return Color.LimeGreen;
            }
        }

        // ── UI state helpers ─────────────────────────────────────────────────

        private void SetScanningState(bool scanning)
        {
            btnScan.Enabled      = !scanning;
            btnBrowse.Enabled    = !scanning;
            txtFilePath.Enabled  = !scanning;
            progressBar.Visible  = scanning;
            lblStatus.Text       = scanning ? "Scanning…" : "Ready";
        }

        // ── Drag-and-drop ─────────────────────────────────────────────────────

        private static void OnDragEnter(object? sender, DragEventArgs e)
        {
            if (e.Data != null && e.Data.GetDataPresent(DataFormats.FileDrop))
                e.Effect = DragDropEffects.Copy;
        }

        private void OnDragDrop(object? sender, DragEventArgs e)
        {
            if (e.Data?.GetData(DataFormats.FileDrop) is string[] files && files.Length > 0)
            {
                txtFilePath.Text = files[0];
                // Auto-start scan when file is dropped
                btnScan.PerformClick();
            }
        }

        // ── Font resolution ───────────────────────────────────────────────────

        private static Font ResolveMonoFont(float size)
        {
            foreach (string name in new[] { "Cascadia Mono", "Consolas", "Courier New" })
            {
                try
                {
                    var f = new Font(name, size);
                    if (f.Name == name) return f;
                    f.Dispose();
                }
                catch { /* not installed */ }
            }
            return new Font(FontFamily.GenericMonospace, size);
        }
    }
}
