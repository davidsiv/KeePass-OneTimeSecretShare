/*
  OneTimeSecret Share - configuration storage.

  Settings are stored in KeePass's own configuration (KeePass.config.xml)
  via IPluginHost.CustomConfig. The API key is additionally protected with
  Windows DPAPI (CurrentUser scope) so it is not written in clear text.
*/

using System;
using System.Reflection;
using System.Text;

using KeePass.Plugins;

namespace OneTimeSecretShare
{
    internal sealed class OtsConfig
    {
        private const string CfgEndpoint = "OtsShare.ApiEndpoint";
        private const string CfgUsername = "OtsShare.ApiUsername";
        private const string CfgApiKey   = "OtsShare.ApiKey";
        private const string CfgTtl      = "OtsShare.DefaultTtlSeconds";
        private const string CfgAutoCopy = "OtsShare.AutoCopyUrl";
        private const string CfgNote     = "OtsShare.Note";
        private const string CfgNoteAlt  = "OtsShare.AlternateNote";
        private const string CfgIncNote  = "OtsShare.IncludeNoteInClipboard";
        private const string CfgIncUser  = "OtsShare.IncludeUsername";
        private const string CfgAutoClose    = "OtsShare.AutoCloseEnabled";
        private const string CfgAutoCloseSec = "OtsShare.AutoCloseSeconds";
        private const string CfgShareDomain  = "OtsShare.ShareDomain";

        private const string DefaultEndpoint = "https://onetimesecret.com/api/v1/share";
        private const string ProtPrefix = "DPAPI:";

        public string ApiEndpoint = DefaultEndpoint;
        public string ApiUsername = string.Empty;
        public string ApiKey = string.Empty;
        public long DefaultTtlSeconds = 3600; // 1 hour
        public bool AutoCopyUrl = true;
        public string Note = string.Empty;
        public string AlternateNote = string.Empty;
        public bool IncludeNoteInClipboard = false;
        public bool IncludeUsername = false;
        public bool AutoCloseEnabled = false;
        public long AutoCloseSeconds = 10;
        public string ShareDomain = string.Empty;

        public static OtsConfig Load(IPluginHost host)
        {
            OtsConfig c = new OtsConfig();
            if (host == null) return c;

            c.ApiEndpoint = host.CustomConfig.GetString(CfgEndpoint, DefaultEndpoint);
            c.ApiUsername = host.CustomConfig.GetString(CfgUsername, string.Empty);
            c.DefaultTtlSeconds = host.CustomConfig.GetLong(CfgTtl, 3600);
            c.AutoCopyUrl = host.CustomConfig.GetBool(CfgAutoCopy, true);
            c.Note = host.CustomConfig.GetString(CfgNote, string.Empty);
            c.AlternateNote = host.CustomConfig.GetString(CfgNoteAlt, string.Empty);
            c.IncludeNoteInClipboard = host.CustomConfig.GetBool(CfgIncNote, false);
            c.IncludeUsername = host.CustomConfig.GetBool(CfgIncUser, false);
            c.AutoCloseEnabled = host.CustomConfig.GetBool(CfgAutoClose, false);
            c.AutoCloseSeconds = host.CustomConfig.GetLong(CfgAutoCloseSec, 10);
            c.ShareDomain = host.CustomConfig.GetString(CfgShareDomain, string.Empty);

            string rawKey = host.CustomConfig.GetString(CfgApiKey, string.Empty);
            if (!string.IsNullOrEmpty(rawKey) && rawKey.StartsWith(ProtPrefix, StringComparison.Ordinal))
                c.ApiKey = Unprotect(rawKey.Substring(ProtPrefix.Length));
            else
                c.ApiKey = rawKey; // Legacy / plain value; will be protected on next save.

            return c;
        }

        public void Save(IPluginHost host)
        {
            if (host == null) return;

            host.CustomConfig.SetString(CfgEndpoint, ApiEndpoint ?? string.Empty);
            host.CustomConfig.SetString(CfgUsername, ApiUsername ?? string.Empty);
            host.CustomConfig.SetLong(CfgTtl, DefaultTtlSeconds);
            host.CustomConfig.SetBool(CfgAutoCopy, AutoCopyUrl);
            host.CustomConfig.SetString(CfgNote, Note ?? string.Empty);
            host.CustomConfig.SetString(CfgNoteAlt, AlternateNote ?? string.Empty);
            host.CustomConfig.SetBool(CfgIncNote, IncludeNoteInClipboard);
            host.CustomConfig.SetBool(CfgIncUser, IncludeUsername);
            host.CustomConfig.SetBool(CfgAutoClose, AutoCloseEnabled);
            host.CustomConfig.SetLong(CfgAutoCloseSec, AutoCloseSeconds);
            host.CustomConfig.SetString(CfgShareDomain, ShareDomain ?? string.Empty);

            string keyToStore = string.IsNullOrEmpty(ApiKey)
                ? string.Empty
                : (ProtPrefix + Protect(ApiKey));
            host.CustomConfig.SetString(CfgApiKey, keyToStore);
        }

        private static string Protect(string plain)
        {
            try
            {
                byte[] data = Encoding.UTF8.GetBytes(plain);
                byte[] prot = Dpapi(data, true);
                if (prot == null) return plain; // DPAPI unavailable: store as-is.
                return Convert.ToBase64String(prot);
            }
            catch { return plain; } // Fall back to storing as-is if DPAPI is unavailable.
        }

        private static string Unprotect(string enc)
        {
            try
            {
                byte[] prot = Convert.FromBase64String(enc);
                byte[] data = Dpapi(prot, false);
                if (data == null) return string.Empty;
                return Encoding.UTF8.GetString(data);
            }
            catch { return string.Empty; }
        }

        // Windows DPAPI (CurrentUser) via late binding.
        //
        // ProtectedData lives in System.Security.dll, which is NOT part of the
        // fixed set of assemblies that KeePass references when it compiles a
        // .plgx on the fly. Referencing it directly (in code or in the .csproj)
        // makes KeePass silently fail to compile the plugin. Invoking it through
        // reflection keeps the encryption while requiring only the default
        // assembly set, so the plugin compiles and loads reliably.
        //
        // Returns null if DPAPI cannot be reached; callers then fall back to
        // storing the value unencrypted (same behaviour as before).
        private static byte[] Dpapi(byte[] input, bool bProtect)
        {
            try
            {
                Assembly asm = LoadSystemSecurity();
                if (asm == null) return null;

                Type tPd = asm.GetType("System.Security.Cryptography.ProtectedData", false);
                Type tScope = asm.GetType("System.Security.Cryptography.DataProtectionScope", false);
                if (tPd == null || tScope == null) return null;

                object scopeCurrentUser = Enum.ToObject(tScope, 0); // CurrentUser = 0
                MethodInfo mi = tPd.GetMethod(bProtect ? "Protect" : "Unprotect",
                    new Type[] { typeof(byte[]), typeof(byte[]), tScope });
                if (mi == null) return null;

                return (byte[])mi.Invoke(null, new object[] { input, null, scopeCurrentUser });
            }
            catch { return null; }
        }

        private static Assembly LoadSystemSecurity()
        {
            // Try the strong name first (robust), then a partial name.
            string[] names = new string[]
            {
                "System.Security, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
                "System.Security"
            };
            foreach (string n in names)
            {
                try { return Assembly.Load(n); }
                catch { }
            }
            return null;
        }
    }
}
