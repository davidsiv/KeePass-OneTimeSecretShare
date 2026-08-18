/*
  OneTimeSecret Share - options dialog.

  Built programmatically (no .Designer.cs / .resx) to keep the .plgx simple.
*/

using System;
using System.Drawing;
using System.Windows.Forms;

using KeePass.Plugins;
using KeePass.UI;

namespace OneTimeSecretShare
{
    internal sealed class OtsOptionsForm : Form
    {
        private readonly IPluginHost m_host;

        private ComboBox m_cmbEndpoint;
        private TextBox m_txtUsername;
        private TextBox m_txtApiKey;
        private TextBox m_txtShareDomain;
        private ComboBox m_cmbTtl;
        private TextBox m_txtNote;
        private TextBox m_txtNoteAlt;
        private CheckBox m_chkAutoCopy;
        private CheckBox m_chkIncludeNote;
        private CheckBox m_chkAutoClose;
        private TextBox m_txtAutoCloseSecs;
        private CheckBox m_chkIncludeUsername;
        private Button m_btnTest;
        private Button m_btnOk;
        private Button m_btnCancel;

        private static readonly string[] EndpointPresets = {
            "https://eu.onetimesecret.com/api/v2/secret/conceal",
            "https://us.onetimesecret.com/api/v2/secret/conceal",
            "https://uk.onetimesecret.com/api/v2/secret/conceal",
            "https://ca.onetimesecret.com/api/v2/secret/conceal",
            "https://nz.onetimesecret.com/api/v2/secret/conceal"
        };

        private static readonly string[] TtlLabels = {
            "5 minutes", "30 minutes", "1 hour", "4 hours", "12 hours",
            "1 day", "3 days", "7 days", "14 days"
        };
        private static readonly long[] TtlValues = {
            300, 1800, 3600, 14400, 43200, 86400, 259200, 604800, 1209600
        };

        public OtsOptionsForm(IPluginHost host)
        {
            m_host = host;
            BuildUI();
        }

        private void BuildUI()
        {
            this.Text = OtsInfo.ProductVersioned + " - Options";
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.StartPosition = FormStartPosition.CenterParent;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.ShowInTaskbar = false;
            this.Font = SystemFonts.MessageBoxFont;
            this.ClientSize = new Size(478, 502);

            const int labelX = 14;
            const int ctrlX = 150;
            const int ctrlW = 314;
            const int rowH = 30;
            int y = 18;

            AddLabel("API Endpoint", labelX, y + 3);
            m_cmbEndpoint = new ComboBox();
            m_cmbEndpoint.DropDownStyle = ComboBoxStyle.DropDown; // editable: pick a region or type a custom/self-hosted URL
            m_cmbEndpoint.Location = new Point(ctrlX, y);
            m_cmbEndpoint.Width = ctrlW;
            m_cmbEndpoint.Items.AddRange(EndpointPresets);
            this.Controls.Add(m_cmbEndpoint);
            y += rowH;

            AddLabel("API Username", labelX, y + 3);
            m_txtUsername = AddText(ctrlX, y, ctrlW);
            y += rowH;

            AddLabel("API Key", labelX, y + 3);
            m_txtApiKey = AddText(ctrlX, y, ctrlW);
            m_txtApiKey.UseSystemPasswordChar = true;
            y += rowH;

            AddLabel("Share domain", labelX, y + 3);
            m_txtShareDomain = AddText(ctrlX, y, ctrlW);
            y += rowH;

            AddLabel("Default TTL", labelX, y + 3);
            m_cmbTtl = new ComboBox();
            m_cmbTtl.DropDownStyle = ComboBoxStyle.DropDownList;
            m_cmbTtl.Location = new Point(ctrlX, y);
            m_cmbTtl.Width = 170;
            m_cmbTtl.Items.AddRange(TtlLabels);
            this.Controls.Add(m_cmbTtl);
            y += rowH;

            AddLabel("Note - Default", labelX, y + 3);
            m_txtNote = AddText(ctrlX, y, ctrlW);
            y += rowH;

            AddLabel("Note - Alternate", labelX, y + 3);
            m_txtNoteAlt = AddText(ctrlX, y, ctrlW);
            y += rowH;

            m_chkAutoCopy = new CheckBox();
            m_chkAutoCopy.Text = "Copy URL to clipboard automatically";
            m_chkAutoCopy.AutoSize = true;
            m_chkAutoCopy.Location = new Point(ctrlX, y + 2);
            this.Controls.Add(m_chkAutoCopy);
            y += rowH;

            m_chkIncludeNote = new CheckBox();
            m_chkIncludeNote.Text = "Include note when copying to clipboard";
            m_chkIncludeNote.AutoSize = true;
            m_chkIncludeNote.Location = new Point(ctrlX, y + 2);
            this.Controls.Add(m_chkIncludeNote);
            y += rowH;

            m_chkAutoClose = new CheckBox();
            m_chkAutoClose.Text = "Auto-close window after";
            m_chkAutoClose.AutoSize = false;
            m_chkAutoClose.Size = new Size(168, 22);
            m_chkAutoClose.Location = new Point(ctrlX, y + 1);
            this.Controls.Add(m_chkAutoClose);

            m_txtAutoCloseSecs = new TextBox();
            m_txtAutoCloseSecs.MaxLength = 2;
            m_txtAutoCloseSecs.Width = 36;
            m_txtAutoCloseSecs.TextAlign = HorizontalAlignment.Center;
            m_txtAutoCloseSecs.Location = new Point(ctrlX + 172, y);
            m_txtAutoCloseSecs.KeyPress += OnSecondsKeyPress;
            this.Controls.Add(m_txtAutoCloseSecs);

            AddLabel("seconds", ctrlX + 172 + 42, y + 3);
            y += rowH;

            m_chkIncludeUsername = new CheckBox();
            m_chkIncludeUsername.Text = "Include username";
            m_chkIncludeUsername.AutoSize = true;
            m_chkIncludeUsername.Location = new Point(ctrlX, y + 2);
            this.Controls.Add(m_chkIncludeUsername);
            y += rowH;

            Label lblWarn = new Label();
            lblWarn.AutoSize = false;
            lblWarn.Location = new Point(labelX, y);
            lblWarn.Size = new Size(ctrlX + ctrlW - labelX, 56);
            lblWarn.ForeColor = Color.Firebrick;
            lblWarn.Text = "Warning: enabling \"Include username\" places both the username and " +
                           "password in a single one-time secret, so one link exposes the full " +
                           "credential. Use only when appropriate and share with discretion.";
            this.Controls.Add(lblWarn);
            y += 62;

            Label lblHint = new Label();
            lblHint.AutoSize = false;
            lblHint.Location = new Point(labelX, y);
            lblHint.Size = new Size(ctrlX + ctrlW - labelX, 30);
            lblHint.ForeColor = SystemColors.GrayText;
            lblHint.Text = "Tip: v1 /share is deprecated. For the current API use " +
                           "https://<region>.onetimesecret.com/api/v2/secret/conceal";
            this.Controls.Add(lblHint);
            y += 42;

            m_btnTest = new Button();
            m_btnTest.Text = "Test...";
            m_btnTest.Width = 96;
            m_btnTest.Location = new Point(labelX, y);
            m_btnTest.Click += OnTest;
            this.Controls.Add(m_btnTest);

            m_btnOk = new Button();
            m_btnOk.Text = "OK";
            m_btnOk.Width = 84;
            m_btnOk.Location = new Point(ctrlX + ctrlW - 174, y);
            m_btnOk.Click += OnOk;
            this.Controls.Add(m_btnOk);

            m_btnCancel = new Button();
            m_btnCancel.Text = "Cancel";
            m_btnCancel.Width = 84;
            m_btnCancel.DialogResult = DialogResult.Cancel;
            m_btnCancel.Location = new Point(ctrlX + ctrlW - 84, y);
            this.Controls.Add(m_btnCancel);

            this.AcceptButton = m_btnOk;
            this.CancelButton = m_btnCancel;

            this.Load += OnFormLoad;
            this.FormClosed += OnFormClosedHandler;
        }

        private Label AddLabel(string text, int x, int y)
        {
            Label l = new Label();
            l.AutoSize = true;
            l.Text = text;
            l.Location = new Point(x, y);
            this.Controls.Add(l);
            return l;
        }

        private TextBox AddText(int x, int y, int w)
        {
            TextBox t = new TextBox();
            t.Location = new Point(x, y);
            t.Width = w;
            this.Controls.Add(t);
            return t;
        }

        private void OnSecondsKeyPress(object sender, KeyPressEventArgs e)
        {
            // Allow digits and control keys (backspace etc.) only.
            if (!char.IsControl(e.KeyChar) && !char.IsDigit(e.KeyChar))
                e.Handled = true;
        }

        private void OnFormLoad(object sender, EventArgs e)
        {
            GlobalWindowManager.AddWindow(this);

            OtsConfig c = OtsConfig.Load(m_host);
            m_cmbEndpoint.Text = c.ApiEndpoint;
            m_txtUsername.Text = c.ApiUsername;
            m_txtApiKey.Text = c.ApiKey;
            m_txtShareDomain.Text = c.ShareDomain;
            m_chkAutoCopy.Checked = c.AutoCopyUrl;
            m_txtNote.Text = c.Note;
            m_txtNoteAlt.Text = c.AlternateNote;
            m_chkIncludeNote.Checked = c.IncludeNoteInClipboard;
            m_chkIncludeUsername.Checked = c.IncludeUsername;
            m_chkAutoClose.Checked = c.AutoCloseEnabled;
            m_txtAutoCloseSecs.Text = c.AutoCloseSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture);

            int idx = Array.IndexOf(TtlValues, c.DefaultTtlSeconds);
            m_cmbTtl.SelectedIndex = (idx >= 0) ? idx : 2; // default: 1 hour
        }

        private void OnFormClosedHandler(object sender, FormClosedEventArgs e)
        {
            GlobalWindowManager.RemoveWindow(this);
        }

        private OtsConfig ReadForm(bool bRequireCreds)
        {
            string ep = m_cmbEndpoint.Text.Trim();
            if (ep.Length == 0) { Warn("Please enter an API endpoint."); return null; }

            Uri u;
            if (!Uri.TryCreate(ep, UriKind.Absolute, out u) ||
                (u.Scheme != Uri.UriSchemeHttps && u.Scheme != Uri.UriSchemeHttp))
            {
                Warn("The API endpoint must be a valid http(s) URL.");
                return null;
            }

            OtsConfig c = new OtsConfig();
            c.ApiEndpoint = ep;
            c.ApiUsername = m_txtUsername.Text.Trim();
            c.ApiKey = m_txtApiKey.Text;
            c.ShareDomain = m_txtShareDomain.Text.Trim();
            c.AutoCopyUrl = m_chkAutoCopy.Checked;
            c.Note = m_txtNote.Text;
            c.AlternateNote = m_txtNoteAlt.Text;
            c.IncludeNoteInClipboard = m_chkIncludeNote.Checked;
            c.IncludeUsername = m_chkIncludeUsername.Checked;

            c.AutoCloseEnabled = m_chkAutoClose.Checked;
            int secs;
            if (!int.TryParse(m_txtAutoCloseSecs.Text.Trim(), out secs)) secs = 0;
            if (secs < 0) secs = 0;
            if (secs > 99) secs = 99;
            if (c.AutoCloseEnabled && secs < 1)
            {
                Warn("Please enter the number of seconds (1-99) for auto-close, or clear the checkbox.");
                return null;
            }
            c.AutoCloseSeconds = secs;

            int i = m_cmbTtl.SelectedIndex;
            c.DefaultTtlSeconds = TtlValues[(i >= 0) ? i : 2];

            if (bRequireCreds && (c.ApiUsername.Length == 0 || c.ApiKey.Length == 0))
            {
                Warn("Please enter both the API Username and API Key.");
                return null;
            }
            return c;
        }

        private void OnOk(object sender, EventArgs e)
        {
            OtsConfig c = ReadForm(false);
            if (c == null) return;
            c.Save(m_host);
            this.DialogResult = DialogResult.OK;
            this.Close();
        }

        private void OnTest(object sender, EventArgs e)
        {
            OtsConfig c = ReadForm(true);
            if (c == null) return;

            Cursor cPrev = this.Cursor;
            this.Cursor = Cursors.WaitCursor;
            try
            {
                // Not a real secret, but Share now takes bytes.
                OtsClient.Result r = OtsClient.Share(c, System.Text.Encoding.UTF8.GetBytes(
                    "KeePass OneTimeSecret Share - connection test. Safe to ignore."));
                MessageBox.Show(this,
                    "Success. A test secret was created:\r\n\r\n" + r.ShareUrl,
                    "Test", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this,
                    "Test failed:\r\n\r\n" + ex.Message,
                    "Test", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                this.Cursor = cPrev;
            }
        }

        private void Warn(string msg)
        {
            MessageBox.Show(this, msg, OtsInfo.Product,
                MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }
}
