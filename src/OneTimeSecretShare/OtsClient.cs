/*
  OneTimeSecret Share - HTTP client.

  Supports both OneTimeSecret API versions and auto-selects based on the
  endpoint URL:

    v1 (legacy / maintenance mode):
        POST {endpoint}                       ...e.g. /api/v1/share
        Content-Type: application/x-www-form-urlencoded
        Body: secret=<value>&ttl=<seconds>
        Response (flat JSON): { "secret_key": "...", "metadata_key": "..." }

    v2 (current, recommended):
        POST {endpoint}                       ...e.g. /api/v2/secret/conceal
        Content-Type: application/json
        Body: { "secret": "<value>", "ttl": <seconds> }
        Response (nested JSON): { "record": { "secret": { "identifier": "..." },
                                              "metadata": { "identifier": "..." } } }

  Both versions use HTTP Basic authentication (username:apikey).
  The share link is always {scheme}://{host}/secret/{secret_key}.
*/

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;

namespace OneTimeSecretShare
{
    internal sealed class OtsException : Exception
    {
        public OtsException(string message) : base(message) { }
    }

    internal static class OtsClient
    {
        internal sealed class Result
        {
            public string SecretKey = string.Empty;
            public string MetadataKey = string.Empty;
            public string ShareUrl = string.Empty;
        }

        // The secret is passed as a UTF-8 byte array (never a managed string),
        // so the caller can zero it after use. This method and the buffers it
        // builds are wiped before returning; see BuildAndSend.
        public static Result Share(OtsConfig cfg, byte[] secret)
        {
            if (cfg == null) throw new OtsException("Missing configuration.");
            if (string.IsNullOrEmpty(cfg.ApiEndpoint)) throw new OtsException("No API endpoint configured.");
            if (secret == null || secret.Length == 0) throw new OtsException("The password is empty.");

            EnsureTls();

            bool bV2 =
                cfg.ApiEndpoint.IndexOf("/v2/", StringComparison.OrdinalIgnoreCase) >= 0 ||
                cfg.ApiEndpoint.IndexOf("/conceal", StringComparison.OrdinalIgnoreCase) >= 0 ||
                cfg.ApiEndpoint.IndexOf("/generate", StringComparison.OrdinalIgnoreCase) >= 0;

            return bV2 ? ShareV2(cfg, secret) : ShareV1(cfg, secret);
        }

        private static Result ShareV1(OtsConfig cfg, byte[] secret)
        {
            HttpWebRequest req = NewRequest(cfg, "application/x-www-form-urlencoded");

            // Build "secret=<url-encoded>&ttl=<n>" directly as bytes so the
            // password never becomes a managed string.
            MemoryStream ms = new MemoryStream();
            WriteAscii(ms, "secret=");
            WriteFormEncoded(ms, secret);
            WriteAscii(ms, "&ttl=" + cfg.DefaultTtlSeconds.ToString(CultureInfo.InvariantCulture));

            string json = BuildAndSend(req, ms);
            object root = OtsJson.Parse(json);

            string secretKey = OtsJson.GetString(root, "secret_key");
            if (string.IsNullOrEmpty(secretKey))
                throw new OtsException("Unexpected response (no secret_key):\r\n" + Trim(json));

            Result r = new Result();
            r.SecretKey = secretKey;
            r.MetadataKey = OtsJson.GetString(root, "metadata_key");
            r.ShareUrl = BuildSecretUrl(cfg.ApiEndpoint, secretKey);
            return r;
        }

        private static Result ShareV2(OtsConfig cfg, byte[] secret)
        {
            HttpWebRequest req = NewRequest(cfg, "application/json");

            // Optional branded share domain (host only). Sent in share_domain;
            // OTS uses it for the generated link when it is configured on the
            // account, otherwise it falls back to the canonical host.
            string shareDomain = NormalizeDomain(cfg.ShareDomain);

            // v2 requires the fields wrapped in a "secret" object, with kind and
            // share_domain present. TTL is sent as a numeric string (pattern ^\d+$).
            // Result: {"secret":{"kind":"conceal","secret":"<pw>","ttl":"3600","share_domain":"<host>"}}
            MemoryStream ms = new MemoryStream();
            WriteAscii(ms, "{\"secret\":{\"kind\":\"conceal\",\"secret\":");
            WriteJsonQuoted(ms, secret);
            WriteAscii(ms, ",\"ttl\":\"" + cfg.DefaultTtlSeconds.ToString(CultureInfo.InvariantCulture) + "\"");
            WriteAscii(ms, ",\"share_domain\":");
            WriteJsonQuoted(ms, Encoding.UTF8.GetBytes(shareDomain));
            WriteAscii(ms, "}}");

            string json = BuildAndSend(req, ms);
            object root = OtsJson.Parse(json);

            // v2 success shape: record.secret.key (URL token) + record.receipt.key
            // (metadata). 'identifier' is kept as a fallback.
            string secretKey = string.Empty;
            string metaKey = string.Empty;
            string respDomain = string.Empty;

            object record = OtsJson.Get(root, "record");
            if (record != null)
            {
                object secObj = OtsJson.Get(record, "secret");
                secretKey = OtsJson.GetString(secObj, "key");
                if (string.IsNullOrEmpty(secretKey)) secretKey = OtsJson.GetString(secObj, "identifier");

                object rcpt = OtsJson.Get(record, "receipt");
                metaKey = OtsJson.GetString(rcpt, "key");
                if (string.IsNullOrEmpty(metaKey)) metaKey = OtsJson.GetString(rcpt, "identifier");

                // Domain the server actually associated with the secret.
                respDomain = OtsJson.GetString(record, "share_domain");
                if (string.IsNullOrEmpty(respDomain)) respDomain = OtsJson.GetString(rcpt, "share_domain");

                // Older/alternate shapes.
                if (string.IsNullOrEmpty(secretKey)) secretKey = OtsJson.GetString(OtsJson.Get(record, "secret"), "identifier");
                if (string.IsNullOrEmpty(metaKey)) metaKey = OtsJson.GetString(record, "metadata_key");
            }

            // Fallbacks for other response shapes.
            if (string.IsNullOrEmpty(secretKey)) secretKey = OtsJson.GetString(root, "secret_key");
            if (string.IsNullOrEmpty(secretKey)) secretKey = OtsJson.GetString(root, "key");

            if (string.IsNullOrEmpty(secretKey))
                throw new OtsException("Unexpected v2 response (no secret identifier):\r\n" + Trim(json));

            // Prefer the domain the server returned; then the configured branded
            // domain; then the API host.
            string linkHost = NormalizeDomain(respDomain);
            if (string.IsNullOrEmpty(linkHost)) linkHost = shareDomain;

            Result r = new Result();
            r.SecretKey = secretKey;
            r.MetadataKey = metaKey;
            r.ShareUrl = (linkHost.Length > 0)
                ? "https://" + linkHost + "/secret/" + secretKey
                : BuildSecretUrl(cfg.ApiEndpoint, secretKey);
            return r;
        }

        // Reduces user input (which may include a scheme or trailing path) to a
        // bare host, e.g. "https://secrets.example.com/x" -> "secrets.example.com".
        private static string NormalizeDomain(string d)
        {
            if (string.IsNullOrEmpty(d)) return string.Empty;
            d = d.Trim();
            int s = d.IndexOf("://", StringComparison.Ordinal);
            if (s >= 0) d = d.Substring(s + 3);
            int slash = d.IndexOfAny(new char[] { '/', '?', '#' });
            if (slash >= 0) d = d.Substring(0, slash);
            return d.Trim();
        }

        private static HttpWebRequest NewRequest(OtsConfig cfg, string contentType)
        {
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(cfg.ApiEndpoint);
            req.Method = "POST";
            req.ContentType = contentType;
            req.Accept = "application/json";
            req.UserAgent = "KeePass-OneTimeSecretShare/2.9.26.09 (David S.)";
            req.Timeout = 30000;

            string auth = Convert.ToBase64String(
                Encoding.UTF8.GetBytes(cfg.ApiUsername + ":" + cfg.ApiKey));
            req.Headers[HttpRequestHeader.Authorization] = "Basic " + auth;
            return req;
        }

        // Sends the body built in 'ms', then wipes every buffer this method
        // owns: the byte[] handed to Send and the MemoryStream's backing store.
        // (Copies made inside HttpWebRequest / the TLS stack are outside our
        // control and cannot be zeroed.)
        private static string BuildAndSend(HttpWebRequest req, MemoryStream ms)
        {
            byte[] body = ms.ToArray();
            try
            {
                return Send(req, body);
            }
            finally
            {
                Zero(body);
                try
                {
                    int n = (int)ms.Length;
                    if (n > 0)
                    {
                        // Overwrite the used region of the stream's buffer in
                        // place (capacity already >= n, so no reallocation).
                        byte[] zeros = new byte[n];
                        ms.Position = 0;
                        ms.Write(zeros, 0, n);
                    }
                }
                catch { }
                ms.Dispose();
            }
        }

        private static void Zero(byte[] b)
        {
            if (b != null) Array.Clear(b, 0, b.Length);
        }

        // Writes a non-secret ASCII literal (field names, separators, digits).
        private static void WriteAscii(MemoryStream ms, string s)
        {
            for (int i = 0; i < s.Length; i++) ms.WriteByte((byte)s[i]);
        }

        private static byte HexDigit(int nibble)
        {
            return (byte)(nibble < 10 ? ('0' + nibble) : ('A' + (nibble - 10)));
        }

        // Percent-encodes UTF-8 bytes for application/x-www-form-urlencoded,
        // keeping the RFC 3986 unreserved set (matches Uri.EscapeDataString).
        private static void WriteFormEncoded(MemoryStream ms, byte[] v)
        {
            for (int i = 0; i < v.Length; i++)
            {
                byte b = v[i];
                bool unreserved =
                    (b >= (byte)'A' && b <= (byte)'Z') ||
                    (b >= (byte)'a' && b <= (byte)'z') ||
                    (b >= (byte)'0' && b <= (byte)'9') ||
                    b == (byte)'-' || b == (byte)'_' ||
                    b == (byte)'.' || b == (byte)'~';

                if (unreserved) ms.WriteByte(b);
                else
                {
                    ms.WriteByte((byte)'%');
                    ms.WriteByte(HexDigit((b >> 4) & 0x0F));
                    ms.WriteByte(HexDigit(b & 0x0F));
                }
            }
        }

        // Writes a JSON string (wrapped in quotes) from UTF-8 bytes. Control
        // characters and " \ are escaped; bytes >= 0x20 (including raw UTF-8
        // multibyte sequences) pass through, which is valid in UTF-8 JSON.
        private static void WriteJsonQuoted(MemoryStream ms, byte[] v)
        {
            ms.WriteByte((byte)'"');
            for (int i = 0; i < v.Length; i++)
            {
                byte b = v[i];
                switch (b)
                {
                    case (byte)'"':  ms.WriteByte((byte)'\\'); ms.WriteByte((byte)'"'); break;
                    case (byte)'\\': ms.WriteByte((byte)'\\'); ms.WriteByte((byte)'\\'); break;
                    case 0x08: ms.WriteByte((byte)'\\'); ms.WriteByte((byte)'b'); break;
                    case 0x09: ms.WriteByte((byte)'\\'); ms.WriteByte((byte)'t'); break;
                    case 0x0A: ms.WriteByte((byte)'\\'); ms.WriteByte((byte)'n'); break;
                    case 0x0C: ms.WriteByte((byte)'\\'); ms.WriteByte((byte)'f'); break;
                    case 0x0D: ms.WriteByte((byte)'\\'); ms.WriteByte((byte)'r'); break;
                    default:
                        if (b < 0x20)
                        {
                            ms.WriteByte((byte)'\\'); ms.WriteByte((byte)'u');
                            ms.WriteByte((byte)'0'); ms.WriteByte((byte)'0');
                            ms.WriteByte(HexDigit((b >> 4) & 0x0F));
                            ms.WriteByte(HexDigit(b & 0x0F));
                        }
                        else ms.WriteByte(b);
                        break;
                }
            }
            ms.WriteByte((byte)'"');
        }

        private static string Send(HttpWebRequest req, byte[] body)
        {
            req.ContentLength = body.Length;
            using (Stream rs = req.GetRequestStream())
                rs.Write(body, 0, body.Length);

            try
            {
                using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                using (StreamReader sr = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
                    return sr.ReadToEnd();
            }
            catch (WebException wex)
            {
                HttpWebResponse er = wex.Response as HttpWebResponse;
                if (er != null)
                {
                    string errBody;
                    using (StreamReader sr = new StreamReader(er.GetResponseStream(), Encoding.UTF8))
                        errBody = sr.ReadToEnd();

                    string msg = TryExtractMessage(errBody);
                    string hint = HintForStatus((int)er.StatusCode);

                    throw new OtsException(
                        "API returned " + (int)er.StatusCode + " (" + er.StatusCode + ")." +
                        (string.IsNullOrEmpty(msg) ? string.Empty : "\r\n" + msg) +
                        (string.IsNullOrEmpty(hint) ? string.Empty : "\r\n\r\n" + hint));
                }

                throw new OtsException("Network error: " + wex.Message);
            }
        }

        private static string HintForStatus(int code)
        {
            if (code == 401 || code == 403)
                return "Check the API Username and API Key.";
            if (code == 404)
                return "The endpoint was not found. Note the v1 /share endpoint is " +
                       "deprecated; consider the v2 endpoint /api/v2/secret/conceal " +
                       "(and your regional host, e.g. us./eu./ca.).";
            if (code == 422)
                return "The server rejected the request body. For the v2 endpoint the " +
                       "payload must be wrapped, e.g. {\"secret\":{\"kind\":\"conceal\"," +
                       "\"secret\":\"...\",\"ttl\":\"3600\"}} - this build sends that shape.";
            return string.Empty;
        }

        private static string BuildSecretUrl(string endpoint, string secretKey)
        {
            try
            {
                Uri u = new Uri(endpoint);
                return u.GetLeftPart(UriPartial.Authority) + "/secret/" + secretKey;
            }
            catch
            {
                return "https://onetimesecret.com/secret/" + secretKey;
            }
        }

        private static string TryExtractMessage(string body)
        {
            object o = OtsJson.Parse(body);
            if (o == null) return string.Empty;
            // v2 uses "error" for the user-facing message (ADR-013); v1 uses "message".
            string m = OtsJson.GetString(o, "error");
            if (string.IsNullOrEmpty(m)) m = OtsJson.GetString(o, "message");

            string field = OtsJson.GetString(o, "field");
            if (!string.IsNullOrEmpty(field))
                m = (string.IsNullOrEmpty(m) ? string.Empty : m + " ") + "(field: " + field + ")";

            return m;
        }

        private static string Trim(string s)
        {
            if (s == null) return string.Empty;
            s = s.Trim();
            return (s.Length > 500) ? (s.Substring(0, 500) + "...") : s;
        }

        private static void EnsureTls()
        {
            // TLS 1.2 = 3072, TLS 1.3 = 12288. Enum members may not exist on
            // older target frameworks, so OR the numeric values defensively.
            try { ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072; } catch { }
            try { ServicePointManager.SecurityProtocol |= (SecurityProtocolType)12288; } catch { }
        }
    }
}
