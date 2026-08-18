/*
  OneTimeSecret Share - result dialog.

  Shows the generated one-time link. 
*/

using System;
using System.Drawing;
using System.Windows.Forms;

using KeePass.UI;

namespace OneTimeSecretShare
{
    internal sealed class OtsResultForm : Form
    {
        private readonly string m_url;
        private readonly bool m_autoCopied;
        private readonly string m_ttlLabel;
        private readonly int m_autoCloseSeconds;
        private readonly string m_alternateNote;

        private TextBox m_txtUrl;
        private Button m_btnClose;
        private Timer m_timer;
        private int m_remaining;

        public OtsResultForm(string url, bool autoCopied, string ttlLabel,
            int autoCloseSeconds, string alternateNote)
        {
            m_url = url ?? string.Empty;
            m_autoCopied = autoCopied;
            m_ttlLabel = ttlLabel ?? string.Empty;
            m_autoCloseSeconds = autoCloseSeconds;
            m_alternateNote = alternateNote ?? string.Empty;
            BuildUI();
        }

        private void BuildUI()
        {
            this.Text = OtsInfo.ProductVersioned;
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.StartPosition = FormStartPosition.CenterParent;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.ShowInTaskbar = false;
            this.Font = SystemFonts.MessageBoxFont;
            this.ClientSize = new Size(580, 176);

            const int margin = 16;
            int y = 16;

            Label lblStatus = new Label();
            lblStatus.AutoSize = true;
            lblStatus.Text = "\u2713  One-Time Secret created";
            lblStatus.Font = new Font(this.Font.FontFamily, this.Font.Size + 1.5f, FontStyle.Bold);
            lblStatus.ForeColor = Color.FromArgb(0, 128, 0);
            lblStatus.Location = new Point(margin, y);
            this.Controls.Add(lblStatus);
            y += 34;

            m_txtUrl = new TextBox();
            m_txtUrl.ReadOnly = true;
            m_txtUrl.Text = m_url;
            m_txtUrl.Location = new Point(margin, y);
            m_txtUrl.Width = this.ClientSize.Width - (2 * margin);
            m_txtUrl.Font = new Font(FontFamily.GenericMonospace, this.Font.Size);
            this.Controls.Add(m_txtUrl);
            y += 34;

            Label lblHint = new Label();
            lblHint.AutoSize = false;
            lblHint.Location = new Point(margin, y);
            lblHint.Size = new Size(this.ClientSize.Width - (2 * margin), 36);
            lblHint.ForeColor = SystemColors.GrayText;
            lblHint.Text = "This link reveals the password once, then self-destructs. " +
                           "It also expires after " + m_ttlLabel + ".";
            this.Controls.Add(lblHint);
            y += 38;

            if (m_autoCopied)
            {
                Label lblCopied = new Label();
                lblCopied.AutoSize = true;
                lblCopied.Location = new Point(margin, y);
                lblCopied.ForeColor = SystemColors.GrayText;
                lblCopied.Font = new Font(this.Font, FontStyle.Bold);
                lblCopied.Text = "(Link copied to clipboard.)";
                this.Controls.Add(lblCopied);
                y += 26;
            }
            else y += 6;

            Button btnCopy = new Button();
            btnCopy.Text = "Copy Link (without note)";
            btnCopy.Width = 160;
            btnCopy.Location = new Point(margin, y);
            btnCopy.Click += OnCopy;
            this.Controls.Add(btnCopy);

            Button btnAlt = new Button();
            btnAlt.Text = "Copy Link (with alternative note)";
            btnAlt.Width = 215;
            btnAlt.Location = new Point(margin + 160 + 8, y);
            btnAlt.Enabled = (m_alternateNote.Length > 0);
            btnAlt.Click += OnCopyAlt;
            this.Controls.Add(btnAlt);

            m_btnClose = new Button();
            m_btnClose.Text = "Close";
            m_btnClose.Width = 90;
            m_btnClose.Location = new Point(this.ClientSize.Width - margin - 90, y);
            m_btnClose.DialogResult = DialogResult.OK;
            this.Controls.Add(m_btnClose);

            this.AcceptButton = m_btnClose;
            this.CancelButton = m_btnClose;

            this.ClientSize = new Size(this.ClientSize.Width, y + m_btnClose.Height + margin);

            this.Load += OnFormLoad;
            this.FormClosed += OnFormClosedHandler;
        }

        private void OnFormLoad(object sender, EventArgs e)
        {
            GlobalWindowManager.AddWindow(this);
            m_txtUrl.SelectAll();
            m_txtUrl.Focus();

            if (m_autoCloseSeconds > 0)
            {
                m_remaining = m_autoCloseSeconds;
                UpdateCloseText();
                m_timer = new Timer();
                m_timer.Interval = 1000;
                m_timer.Tick += OnAutoCloseTick;
                m_timer.Start();
            }
        }

        private void OnAutoCloseTick(object sender, EventArgs e)
        {
            m_remaining--;
            if (m_remaining <= 0)
            {
                if (m_timer != null) m_timer.Stop();
                this.Close();
                return;
            }
            UpdateCloseText();
        }

        private void UpdateCloseText()
        {
            if (m_btnClose != null)
                m_btnClose.Text = "Close (" + m_remaining.ToString() + ")";
        }

        private void OnFormClosedHandler(object sender, FormClosedEventArgs e)
        {
            if (m_timer != null)
            {
                m_timer.Stop();
                m_timer.Dispose();
                m_timer = null;
            }
            GlobalWindowManager.RemoveWindow(this);
        }

        private void OnCopy(object sender, EventArgs e)
        {
            // Copies the bare link only, without any configured note.
            bool ok = OtsClipboard.Copy(m_url);
            if (!ok)
                MessageBox.Show(this, "Could not access the clipboard. " +
                    "Please copy the link manually.", OtsInfo.Product,
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }

        private void OnCopyAlt(object sender, EventArgs e)
        {
            // Copies the alternate note (own line) followed by the link.
            string text = (m_alternateNote.Length > 0)
                ? m_alternateNote + "\r\n" + m_url
                : m_url;
            bool ok = OtsClipboard.Copy(text);
            if (!ok)
                MessageBox.Show(this, "Could not access the clipboard. " +
                    "Please copy the link manually.", OtsInfo.Product,
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }
}
