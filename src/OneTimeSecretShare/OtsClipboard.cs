/*
  OneTimeSecret Share - clipboard helper.

  Clipboard.SetText can throw ExternalException when the clipboard is
  momentarily locked by another process, so we retry a few times.
*/

using System.Threading;
using System.Windows.Forms;

namespace OneTimeSecretShare
{
    internal static class OtsClipboard
    {
        public static bool Copy(string text)
        {
            if (string.IsNullOrEmpty(text)) return false;

            for (int attempt = 0; attempt < 6; attempt++)
            {
                try
                {
                    Clipboard.SetText(text);
                    return true;
                }
                catch
                {
                    Thread.Sleep(60);
                }
            }
            return false;
        }
    }
}
