/*
  OneTimeSecret Share - KeePass 2.x plugin
  Copyright (C) David S.

  Adds a "Share Password via OneTimeSecret..." item to the entry context
  menu (also on the Entry menu, with a Ctrl+Z shortcut). Selecting it pushes
  the entry's password to a OneTimeSecret instance and shows a one-time,
  self-destructing share link.

  Version: 2.8.26.08

*/

using System;
using System.IO;
using System.Text;
using System.Windows.Forms;

using KeePass.Plugins;
using KeePass.Forms;

using KeePassLib;
using KeePassLib.Security;

namespace OneTimeSecretShare
{
    public sealed class OneTimeSecretShareExt : Plugin
    {
        private IPluginHost m_host = null;

        // No auto-update feed is published for this internal tool.
        public override string UpdateUrl
        {
            get { return string.Empty; }
        }

        public override bool Initialize(IPluginHost host)
        {
            if (host == null) return false;
            m_host = host;
            return true;
        }

        public override void Terminate()
        {
            m_host = null;
        }

        // KeePass calls this for each menu location. We return an item for the
        // entry context menu (right-click an entry) and for the Tools menu
        // (options dialog). KeePass takes ownership of the returned items.
        public override ToolStripMenuItem GetMenuItem(PluginMenuType t)
        {
            if (t == PluginMenuType.Entry)
            {
                ToolStripMenuItem tsmi = new ToolStripMenuItem();
                tsmi.Text = "Share Password via OneTimeSecret...";
                // Ctrl+Z accelerator. KeePass adds this item to the main "Entry"
                // menu (as well as the entry context menu), so the shortcut is
                // processed form-wide by the standard menu accelerator path.
                // Ctrl+Z is free in KeePass's main window (it is not one of the
                // keys handled in HandleMainWindowKeyEvent, unlike Ctrl+D which
                // is bound to "Compare entries").
                tsmi.ShortcutKeys = Keys.Control | Keys.Z;
                tsmi.ShowShortcutKeys = true;
                tsmi.Click += OnShareClicked;
                return tsmi;
            }

            if (t == PluginMenuType.Main)
            {
                ToolStripMenuItem tsmi = new ToolStripMenuItem();
                tsmi.Text = "OneTimeSecret Share Options...";
                tsmi.Click += OnOptionsClicked;
                return tsmi;
            }

            return null;
        }

        private void OnOptionsClicked(object sender, EventArgs e)
        {
            if (m_host == null) return;
            using (OtsOptionsForm f = new OtsOptionsForm(m_host))
            {
                f.ShowDialog(m_host.MainWindow);
            }
        }

        private void OnShareClicked(object sender, EventArgs e)
        {
            if (m_host == null) return;
            MainForm mf = m_host.MainWindow;

            PwEntry[] v = mf.GetSelectedEntries();
            if (v == null || v.Length == 0)
            {
                MessageBox.Show(mf, "Please select an entry first.",
                    OtsInfo.Product, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            PwEntry pe = v[0]; // Share the first selected entry.

            // Validate configuration BEFORE reading the password, so no secret
            // sits in memory while the options dialog is open.
            OtsConfig cfg = OtsConfig.Load(m_host);
            if (string.IsNullOrEmpty(cfg.ApiUsername) || string.IsNullOrEmpty(cfg.ApiKey))
            {
                MessageBox.Show(mf,
                    "OneTimeSecret is not configured yet.\r\n\r\n" +
                    "Open Tools -> \"OneTimeSecret Share Options...\" and enter your " +
                    "API endpoint, username and key.",
                    OtsInfo.Product, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                OnOptionsClicked(sender, e);
                return;
            }

            // Build the secret payload as a UTF-8 byte[] (never a managed string):
            // the password alone, or "Username: ...\r\nPassword: ..." when the
            // Include username option is enabled. Zeroed after use.
            byte[] secretBytes = BuildSecretBytes(pe, cfg);
            if (secretBytes == null || secretBytes.Length == 0)
            {
                if (secretBytes != null) Array.Clear(secretBytes, 0, secretBytes.Length);
                MessageBox.Show(mf, "The selected entry does not contain a password.",
                    OtsInfo.Product, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            OtsClient.Result result = null;
            Exception error = null;
            try
            {
                Cursor cPrev = mf.Cursor;
                mf.Cursor = Cursors.WaitCursor;
                try { result = OtsClient.Share(cfg, secretBytes); }
                catch (Exception ex) { error = ex; }
                finally { mf.Cursor = cPrev; }
            }
            finally
            {
                // Wipe the secret bytes as soon as the request is done,
                // before the result dialog (which only needs the share URL).
                Array.Clear(secretBytes, 0, secretBytes.Length);
            }

            if (error != null)
            {
                MessageBox.Show(mf,
                    "Could not create the one-time secret:\r\n\r\n" + error.Message,
                    OtsInfo.Product, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            string clipText = BuildClipboardText(cfg, result.ShareUrl);

            bool bCopied = false;
            if (cfg.AutoCopyUrl) bCopied = OtsClipboard.Copy(clipText);

            int autoCloseSecs = cfg.AutoCloseEnabled ? (int)cfg.AutoCloseSeconds : 0;
            using (OtsResultForm f = new OtsResultForm(result.ShareUrl, bCopied,
                OtsInfo.HumanTtl(cfg.DefaultTtlSeconds), autoCloseSecs, cfg.AlternateNote))
            {
                f.ShowDialog(mf);
            }
        }

        // Text placed on the clipboard. When enabled and a note is set, the note
        // goes on its own line above the link, so a paste reads e.g.:
        //   the password is in this link for one time view:
        //   https://.../secret/xxxx
        private static string BuildClipboardText(OtsConfig cfg, string url)
        {
            if (cfg.IncludeNoteInClipboard && !string.IsNullOrEmpty(cfg.Note))
                return cfg.Note + "\r\n" + url;
            return url;
        }

        // Builds the secret payload bytes to send. Returns null when the entry
        // has no password. When IncludeUsername is set, the payload is
        // "Username: <user>\r\nPassword: <pw>"; otherwise it is the password
        // alone. Every intermediate buffer is zeroed here; the CALLER must zero
        // the returned array after use.
        private static byte[] BuildSecretBytes(PwEntry pe, OtsConfig cfg)
        {
            ProtectedString psPw = pe.Strings.Get(PwDefs.PasswordField);
            byte[] pw = (psPw != null) ? psPw.ReadUtf8() : null;
            if (pw == null || pw.Length == 0)
            {
                if (pw != null) Array.Clear(pw, 0, pw.Length);
                return null;
            }

            if (!cfg.IncludeUsername)
                return pw; // password only; caller zeros it

            ProtectedString psUser = pe.Strings.Get(PwDefs.UserNameField);
            byte[] user = (psUser != null) ? psUser.ReadUtf8() : new byte[0];

            MemoryStream ms = new MemoryStream();
            try
            {
                WriteAscii(ms, "Username: ");
                ms.Write(user, 0, user.Length);
                WriteAscii(ms, "\r\nPassword: ");
                ms.Write(pw, 0, pw.Length);
                return ms.ToArray();
            }
            finally
            {
                // Wipe every intermediate copy; the returned array is the
                // caller's responsibility.
                Array.Clear(pw, 0, pw.Length);
                if (user.Length > 0) Array.Clear(user, 0, user.Length);
                try
                {
                    int n = (int)ms.Length;
                    if (n > 0)
                    {
                        byte[] zeros = new byte[n];
                        ms.Position = 0;
                        ms.Write(zeros, 0, n);
                    }
                }
                catch { }
                ms.Dispose();
            }
        }

        // Writes a non-secret ASCII literal to the stream.
        private static void WriteAscii(MemoryStream ms, string s)
        {
            byte[] b = Encoding.ASCII.GetBytes(s);
            ms.Write(b, 0, b.Length);
        }
    }

    internal static class OtsInfo
    {
        public const string Product = "OneTimeSecret Share";
        public const string Version = "2.8.26.08";
        public const string ProductVersioned = Product + " " + Version;

        public static string HumanTtl(long secs)
        {
            if (secs <= 0) return "the configured time";
            if (secs % 86400 == 0) { long d = secs / 86400; return d + (d == 1 ? " day" : " days"); }
            if (secs % 3600 == 0) { long h = secs / 3600; return h + (h == 1 ? " hour" : " hours"); }
            if (secs % 60 == 0) { long m = secs / 60; return m + (m == 1 ? " minute" : " minutes"); }
            return secs + " seconds";
        }
    }
}
