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

        // Set by Load when a stored (DPAPI:) API key could not be decrypted on
        // this machine/user. Not persisted.
        public bool ApiKeyLoadFailed = false;

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
            {
                string dec;
                bool ok = TryUnprotect(rawKey.Substring(ProtPrefix.Length), out dec);
                c.ApiKey = ok ? dec : string.Empty;
                c.ApiKeyLoadFailed = !ok; // stored key present but undecryptable
            }
            else
                c.ApiKey = rawKey; // Legacy / plain value; will be protected on next save.

            return c;
        }

        // Returns true when settings were fully saved. Returns false only when a
        // non-empty API key could not be DPAPI-encrypted: in that case every
        // other setting is still saved, but the stored API key is left unchanged
        // (never overwritten with plaintext).
        public bool Save(IPluginHost host)
        {
            if (host == null) return false;

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

            // API key: clearing is always allowed; otherwise store only if we can
            // encrypt it. On encryption failure, leave the existing stored key
            // untouched so we never write plaintext behind a "DPAPI:" prefix.
            if (string.IsNullOrEmpty(ApiKey))
            {
                host.CustomConfig.SetString(CfgApiKey, string.Empty);
                return true;
            }

            string enc = Protect(ApiKey);
            if (enc == null) return false; // stored key preserved; caller warns

            host.CustomConfig.SetString(CfgApiKey, ProtPrefix + enc);
            return true;
        }

        // Returns Base64 DPAPI ciphertext, or null if encryption is unavailable.
        // It must NEVER return the plaintext: callers only add the "DPAPI:"
        // prefix when this succeeds, so a null result means "do not store".
        private static string Protect(string plain)
        {
            try
            {
                byte[] data = Encoding.UTF8.GetBytes(plain);
                byte[] prot = Dpapi(data, true);
                if (prot == null) return null; // DPAPI unavailable
                return Convert.ToBase64String(prot);
            }
            catch { return null; }
        }

        // Decrypts a Base64 DPAPI value. Returns false (result = "") when the
        // value cannot be decrypted (DPAPI unavailable, or the blob was created
        // by a different Windows user/machine, e.g. a copied config).
        private static bool TryUnprotect(string enc, out string result)
        {
            result = string.Empty;
            try
            {
                byte[] prot = Convert.FromBase64String(enc);
                byte[] data = Dpapi(prot, false);
                if (data == null) return false;
                result = Encoding.UTF8.GetString(data);
                return true;
            }
            catch { return false; }
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
