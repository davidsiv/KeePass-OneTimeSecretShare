using System.Reflection;
using System.Runtime.InteropServices;

[assembly: AssemblyTitle("OneTimeSecret Share")]
[assembly: AssemblyDescription("Share KeePass entry passwords as one-time, self-destructing OneTimeSecret links.")]
[assembly: AssemblyConfiguration("")]
[assembly: AssemblyCompany("David S.")]
// KeePass ONLY loads a compiled plugin whose assembly ProductName equals
// "KeePass Plugin" (AppDefs.PluginProductName). Any other value makes KeePass
// silently skip the plugin - no error, not shown in Tools -> Plugins. This is
// the required magic string; do not change it. (The user-visible plugin name
// comes from AssemblyTitle, the author from AssemblyCompany.)
[assembly: AssemblyProduct("KeePass Plugin")]
[assembly: AssemblyCopyright("Copyright (C) David S.")]
[assembly: AssemblyTrademark("")]
[assembly: AssemblyCulture("")]

[assembly: ComVisible(false)]
[assembly: Guid("6f1a2c3d-9b47-4e0a-8c21-7d5f0a1b2c3e")]

[assembly: AssemblyVersion("2.9.26.9")]
[assembly: AssemblyFileVersion("2.9.26.09")]
[assembly: AssemblyInformationalVersion("2.9.26.09")]
