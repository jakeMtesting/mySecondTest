namespace AntivirusScannerUI
{
    partial class MainForm
    {
        private System.ComponentModel.IContainer components = null;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
                components.Dispose();
            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            this.pnlTop        = new System.Windows.Forms.Panel();
            this.lblFile       = new System.Windows.Forms.Label();
            this.txtFilePath   = new System.Windows.Forms.TextBox();
            this.btnBrowse     = new System.Windows.Forms.Button();
            this.pnlOptions    = new System.Windows.Forms.Panel();
            this.chkVerbose    = new System.Windows.Forms.CheckBox();
            this.btnScan       = new System.Windows.Forms.Button();
            this.lblResults    = new System.Windows.Forms.Label();
            this.rtbResults    = new System.Windows.Forms.RichTextBox();
            this.statusStrip   = new System.Windows.Forms.StatusStrip();
            this.lblStatus     = new System.Windows.Forms.ToolStripStatusLabel();
            this.progressBar   = new System.Windows.Forms.ToolStripProgressBar();

            this.pnlTop.SuspendLayout();
            this.pnlOptions.SuspendLayout();
            this.statusStrip.SuspendLayout();
            this.SuspendLayout();

            // ── Status strip (bottom) ────────────────────────────────────────
            this.lblStatus.Spring = true;
            this.lblStatus.Text = "Ready — drag a file onto the window or use Browse.";
            this.lblStatus.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;

            this.progressBar.Name  = "progressBar";
            this.progressBar.Size  = new System.Drawing.Size(120, 16);
            this.progressBar.Style = System.Windows.Forms.ProgressBarStyle.Marquee;
            this.progressBar.Visible = false;

            this.statusStrip.Items.AddRange(new System.Windows.Forms.ToolStripItem[]
            {
                this.lblStatus,
                this.progressBar
            });
            this.statusStrip.SizingGrip = false;
            this.statusStrip.Dock = System.Windows.Forms.DockStyle.Bottom;

            // ── Top panel — file selection ───────────────────────────────────
            this.lblFile.AutoSize = true;
            this.lblFile.Location = new System.Drawing.Point(12, 14);
            this.lblFile.Text     = "Target file:";
            this.lblFile.Font     = new System.Drawing.Font("Segoe UI", 9.5f,
                                        System.Drawing.FontStyle.Regular);

            this.txtFilePath.Location  = new System.Drawing.Point(12, 34);
            this.txtFilePath.Size      = new System.Drawing.Size(730, 24);
            this.txtFilePath.Font      = new System.Drawing.Font("Segoe UI", 9.5f);
            this.txtFilePath.Anchor    = System.Windows.Forms.AnchorStyles.Top
                                       | System.Windows.Forms.AnchorStyles.Left
                                       | System.Windows.Forms.AnchorStyles.Right;
            this.txtFilePath.AllowDrop = true;

            this.btnBrowse.Text     = "Browse…";
            this.btnBrowse.Size     = new System.Drawing.Size(86, 26);
            this.btnBrowse.Location = new System.Drawing.Point(754, 33);
            this.btnBrowse.Anchor   = System.Windows.Forms.AnchorStyles.Top
                                    | System.Windows.Forms.AnchorStyles.Right;
            this.btnBrowse.Font     = new System.Drawing.Font("Segoe UI", 9.5f);
            this.btnBrowse.Click   += new System.EventHandler(this.btnBrowse_Click);

            this.pnlTop.Controls.AddRange(new System.Windows.Forms.Control[]
            {
                this.lblFile,
                this.txtFilePath,
                this.btnBrowse
            });
            this.pnlTop.Dock   = System.Windows.Forms.DockStyle.Top;
            this.pnlTop.Height = 70;
            this.pnlTop.Padding = new System.Windows.Forms.Padding(0, 4, 0, 0);

            // ── Options panel — verbose + scan button ────────────────────────
            this.chkVerbose.AutoSize = true;
            this.chkVerbose.Location = new System.Drawing.Point(14, 8);
            this.chkVerbose.Text     = "Verbose output  (show all findings, including low-confidence Suspicious signals)";
            this.chkVerbose.Font     = new System.Drawing.Font("Segoe UI", 9.5f);

            this.btnScan.Text      = "Scan File";
            this.btnScan.Size      = new System.Drawing.Size(110, 32);
            this.btnScan.Location  = new System.Drawing.Point(730, 2);
            this.btnScan.Anchor    = System.Windows.Forms.AnchorStyles.Top
                                   | System.Windows.Forms.AnchorStyles.Right;
            this.btnScan.Font      = new System.Drawing.Font("Segoe UI", 9.5f,
                                         System.Drawing.FontStyle.Bold);
            this.btnScan.BackColor = System.Drawing.Color.FromArgb(0, 120, 215);
            this.btnScan.ForeColor = System.Drawing.Color.White;
            this.btnScan.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.btnScan.FlatAppearance.BorderSize = 0;
            this.btnScan.Click    += new System.EventHandler(this.btnScan_Click);

            this.pnlOptions.Controls.AddRange(new System.Windows.Forms.Control[]
            {
                this.chkVerbose,
                this.btnScan
            });
            this.pnlOptions.Dock   = System.Windows.Forms.DockStyle.Top;
            this.pnlOptions.Height = 42;

            // ── Results label ────────────────────────────────────────────────
            this.lblResults.AutoSize = true;
            this.lblResults.Text     = "Results:";
            this.lblResults.Font     = new System.Drawing.Font("Segoe UI", 9.5f,
                                           System.Drawing.FontStyle.Regular);
            this.lblResults.Dock     = System.Windows.Forms.DockStyle.Top;
            this.lblResults.Padding  = new System.Windows.Forms.Padding(12, 4, 0, 2);

            // ── Results RichTextBox (terminal-style) ─────────────────────────
            this.rtbResults.Dock        = System.Windows.Forms.DockStyle.Fill;
            this.rtbResults.BackColor   = System.Drawing.Color.FromArgb(18, 18, 18);
            this.rtbResults.ForeColor   = System.Drawing.Color.FromArgb(220, 220, 220);
            this.rtbResults.Font        = new System.Drawing.Font("Cascadia Mono", 9.5f);
            this.rtbResults.ReadOnly    = true;
            this.rtbResults.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.rtbResults.ScrollBars  = System.Windows.Forms.RichTextBoxScrollBars.Vertical;
            this.rtbResults.WordWrap    = true;

            // ── Form ─────────────────────────────────────────────────────────
            this.AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
            this.AutoScaleMode       = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize          = new System.Drawing.Size(860, 620);
            this.MinimumSize         = new System.Drawing.Size(720, 480);
            this.Text                = "Heuristic Antivirus Scanner";
            this.Font                = new System.Drawing.Font("Segoe UI", 9.5f);
            this.AllowDrop           = true;

            // Add controls in reverse dock order (Fill must be added before Top panels)
            this.Controls.Add(this.rtbResults);
            this.Controls.Add(this.lblResults);
            this.Controls.Add(this.pnlOptions);
            this.Controls.Add(this.pnlTop);
            this.Controls.Add(this.statusStrip);

            this.pnlTop.ResumeLayout(false);
            this.pnlOptions.ResumeLayout(false);
            this.statusStrip.ResumeLayout(false);
            this.statusStrip.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();
        }

        // ── Control declarations ─────────────────────────────────────────────
        private System.Windows.Forms.Panel              pnlTop;
        private System.Windows.Forms.Label              lblFile;
        private System.Windows.Forms.TextBox            txtFilePath;
        private System.Windows.Forms.Button             btnBrowse;
        private System.Windows.Forms.Panel              pnlOptions;
        private System.Windows.Forms.CheckBox           chkVerbose;
        private System.Windows.Forms.Button             btnScan;
        private System.Windows.Forms.Label              lblResults;
        private System.Windows.Forms.RichTextBox        rtbResults;
        private System.Windows.Forms.StatusStrip        statusStrip;
        private System.Windows.Forms.ToolStripStatusLabel   lblStatus;
        private System.Windows.Forms.ToolStripProgressBar   progressBar;
    }
}
