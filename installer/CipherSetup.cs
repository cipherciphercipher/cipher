/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

// Cipher-Setup.exe: installs a prebuilt Vencord + Cipher into the Discord
// desktop app on Windows. Built with the C# compiler that ships with Windows
// (.NET Framework 4.8), see scripts/build-exe.mjs. No third-party code.
//
// What it changes, and nothing else:
//  - %APPDATA%\Vencord\dist: the Vencord + Cipher files (an existing dist is
//    backed up first and restored on uninstall);
//  - Discord's resources\app.asar: only if Discord is unmodified, it's renamed
//    to _app.asar and replaced by a two-file stub that loads the files above
//    (the same thing Vencord's own installer does). A Discord already set up
//    by Vencord is left as it is; a Discord modified by anything else is
//    never touched.
//
// Rules for this file: C# 5 (what the built-in compiler understands), no
// network access, no registry, no admin rights, nothing outside the folders above.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using System.Windows.Forms;

[assembly: AssemblyTitle("Cipher Setup")]
[assembly: AssemblyProduct("Cipher")]
[assembly: AssemblyDescription("Installs Cipher (end-to-end encrypted messages) into the Discord desktop app")]

namespace CipherSetup
{
    enum PatchState { Clean, CipherStub, VencordStub, Foreign, Missing }

    class DiscordInstall
    {
        public string Flavor;      // Discord, DiscordPTB, DiscordCanary, DiscordDevelopment
        public string Resources;   // ...\app-1.0.9200\resources
        public PatchState State;
        public string Label
        {
            get
            {
                string name = Flavor == "Discord" ? "Discord" : Flavor.Replace("Discord", "Discord ");
                switch (State)
                {
                    case PatchState.Clean: return name + " (not modified)";
                    case PatchState.CipherStub: return name + " (Cipher installed)";
                    case PatchState.VencordStub: return name + " (Vencord installed)";
                    case PatchState.Foreign: return name + " (modified by other software: left alone)";
                    default: return name + " (not found properly)";
                }
            }
        }
        public string AppAsar { get { return Path.Combine(Resources, "app.asar"); } }
        public string OriginalAsar { get { return Path.Combine(Resources, "_app.asar"); } }
    }

    /// <summary>Paths are injectable so tests can point everything at a fake folder.</summary>
    class Env
    {
        public string LocalAppData;
        public string AppData;
        public bool Fake;
        public string Dist { get { return Path.Combine(AppData, "Vencord", "dist"); } }
        public string Patcher { get { return Path.Combine(Dist, "patcher.js"); } }

        public static Env Real()
        {
            return new Env
            {
                LocalAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                AppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Fake = false
            };
        }
    }

    /// <summary>Electron's asar archive format, just enough to write and read a two-file stub.</summary>
    static class Asar
    {
        static byte[] U32(uint v) { return BitConverter.GetBytes(v); }

        public static byte[] Build(IList<KeyValuePair<string, byte[]>> files)
        {
            var entries = new Dictionary<string, object>();
            long offset = 0;
            foreach (var f in files)
            {
                entries[f.Key] = new Dictionary<string, object> { { "size", f.Value.Length }, { "offset", offset.ToString() } };
                offset += f.Value.Length;
            }
            string json = new JavaScriptSerializer().Serialize(new Dictionary<string, object> { { "files", entries } });
            byte[] jsonBytes = Encoding.UTF8.GetBytes(json);
            int padded = (jsonBytes.Length + 3) & ~3;
            // Header pickle: [payload size][string length][string, padded to 4 bytes]
            var header = new MemoryStream();
            header.Write(U32((uint)(4 + padded)), 0, 4);
            header.Write(U32((uint)jsonBytes.Length), 0, 4);
            header.Write(jsonBytes, 0, jsonBytes.Length);
            header.Write(new byte[padded - jsonBytes.Length], 0, padded - jsonBytes.Length);
            byte[] headerBytes = header.ToArray();
            var output = new MemoryStream();
            // Size pickle: [payload size = 4][header length]
            output.Write(U32(4), 0, 4);
            output.Write(U32((uint)headerBytes.Length), 0, 4);
            output.Write(headerBytes, 0, headerBytes.Length);
            foreach (var f in files) output.Write(f.Value, 0, f.Value.Length);
            return output.ToArray();
        }

        /// <summary>Reads a small asar's files; null if it isn't one.</summary>
        public static Dictionary<string, byte[]> Read(byte[] data)
        {
            try
            {
                if (data.Length < 16 || BitConverter.ToUInt32(data, 0) != 4) return null;
                uint headerLen = BitConverter.ToUInt32(data, 4);
                uint jsonLen = BitConverter.ToUInt32(data, 12);
                if (16 + (long)jsonLen > data.Length || 8 + (long)headerLen > data.Length) return null;
                string json = Encoding.UTF8.GetString(data, 16, (int)jsonLen);
                var root = new JavaScriptSerializer().DeserializeObject(json) as Dictionary<string, object>;
                if (root == null || !(root.ContainsKey("files"))) return null;
                var files = root["files"] as Dictionary<string, object>;
                if (files == null) return null;
                long baseOffset = 8 + headerLen;
                var result = new Dictionary<string, byte[]>();
                foreach (var kv in files)
                {
                    var e = kv.Value as Dictionary<string, object>;
                    if (e == null || !e.ContainsKey("size") || !e.ContainsKey("offset")) continue;
                    long size = Convert.ToInt64(e["size"]);
                    long off = long.Parse(e["offset"].ToString());
                    if (size < 0 || off < 0 || baseOffset + off + size > data.Length) return null;
                    var bytes = new byte[size];
                    Array.Copy(data, baseOffset + off, bytes, 0, size);
                    result[kv.Key] = bytes;
                }
                return result;
            }
            catch
            {
                return null;
            }
        }
    }

    static class Core
    {
        public const string StubMarker = "// Cipher stub v1";
        public const string BuildMarkerFile = "cipher-build.txt";
        static readonly string[] Flavors = { "Discord", "DiscordPTB", "DiscordCanary", "DiscordDevelopment" };
        /// <summary>The plugin files embedded in this exe (see scripts/build-exe.mjs).</summary>
        public static readonly string[] DistFiles = { "package.json", "patcher.js", "preload.js", "renderer.js", "renderer.css", "patcher.js.LEGAL.txt", "renderer.js.LEGAL.txt" };

        public static string BuildVersion
        {
            get
            {
                var a = (AssemblyInformationalVersionAttribute)Attribute.GetCustomAttribute(Assembly.GetExecutingAssembly(), typeof(AssemblyInformationalVersionAttribute));
                return a != null ? a.InformationalVersion : "dev";
            }
        }

        static System.Version AppVersion(string dirName)
        {
            System.Version v;
            return System.Version.TryParse(dirName.Substring(4), out v) ? v : new System.Version(0, 0);
        }

        public static List<DiscordInstall> Find(Env env)
        {
            var found = new List<DiscordInstall>();
            foreach (var flavor in Flavors)
            {
                string root = Path.Combine(env.LocalAppData, flavor);
                if (!Directory.Exists(root)) continue;
                var latest = Directory.GetDirectories(root, "app-*")
                    .Select(d => Path.GetFileName(d))
                    .Where(n => Regex.IsMatch(n, @"^app-\d+(\.\d+){1,3}$"))
                    .OrderByDescending(n => AppVersion(n))
                    .FirstOrDefault();
                if (latest == null) continue;
                var d1 = new DiscordInstall { Flavor = flavor, Resources = Path.Combine(root, latest, "resources") };
                d1.State = Inspect(d1, env);
                found.Add(d1);
            }
            return found;
        }

        static string Normalize(string s) { return s.Replace("\\\\", "\\").Replace('/', '\\').ToLowerInvariant(); }

        public static PatchState Inspect(DiscordInstall d, Env env)
        {
            // Something that replaces app.asar with a folder: not ours to touch.
            if (Directory.Exists(Path.Combine(d.Resources, "app")) || Directory.Exists(d.AppAsar)) return PatchState.Foreign;
            if (!File.Exists(d.AppAsar)) return PatchState.Missing;
            bool hasOriginal = File.Exists(d.OriginalAsar);
            long size = new FileInfo(d.AppAsar).Length;
            if (!hasOriginal) return size > 512 * 1024 ? PatchState.Clean : PatchState.Foreign;
            if (size > 256 * 1024) return PatchState.Foreign;
            var files = Asar.Read(File.ReadAllBytes(d.AppAsar));
            if (files == null || !files.ContainsKey("index.js")) return PatchState.Foreign;
            string index = Encoding.UTF8.GetString(files["index.js"]);
            if (index.StartsWith(StubMarker)) return PatchState.CipherStub;
            // A stub that loads Vencord from the usual folder (Vencord's own installer, or a custom
            // setup built on it). Cipher only replaces the files it loads, never the stub itself.
            if (Normalize(index).Contains(Normalize(env.Dist))) return PatchState.VencordStub;
            return PatchState.Foreign;
        }

        public static byte[] Stub(Env env)
        {
            string js = StubMarker + "\n// Loads Vencord + Cipher. Uninstall with Cipher-Setup.exe to restore Discord.\nrequire(" + new JavaScriptSerializer().Serialize(env.Patcher) + ");\n";
            var files = new List<KeyValuePair<string, byte[]>>
            {
                new KeyValuePair<string, byte[]>("index.js", Encoding.UTF8.GetBytes(js)),
                new KeyValuePair<string, byte[]>("package.json", Encoding.UTF8.GetBytes("{\"name\":\"discord\",\"main\":\"index.js\"}"))
            };
            return Asar.Build(files);
        }

        public static string[] ProcessNames(DiscordInstall d) { return new[] { d.Flavor }; }

        public static bool IsRunning(DiscordInstall d, Env env)
        {
            // Tests use fake folders: never look at (or close) the real Discord then.
            if (env.Fake) return false;
            return ProcessNames(d).Any(n => Process.GetProcessesByName(n).Length > 0);
        }

        public static void Close(DiscordInstall d, Env env)
        {
            if (env.Fake) return;
            foreach (var n in ProcessNames(d))
                foreach (var p in Process.GetProcessesByName(n))
                {
                    try { p.Kill(); p.WaitForExit(5000); } catch { }
                }
        }

        static byte[] Embedded(string name)
        {
            using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("dist/" + name))
            {
                if (s == null) throw new InvalidOperationException("This Cipher-Setup.exe is incomplete (missing " + name + "). Download it again.");
                var m = new MemoryStream();
                s.CopyTo(m);
                return m.ToArray();
            }
        }

        static bool DistIsCipher(Env env) { return File.Exists(Path.Combine(env.Dist, BuildMarkerFile)); }

        /// <summary>Writes the embedded files to the dist folder, backing up a dist that isn't Cipher's.</summary>
        static void WriteDist(Env env, Action<string> log)
        {
            if (Directory.Exists(env.Dist) && !DistIsCipher(env))
            {
                string backup = env.Dist + ".backup-" + DateTime.Now.ToString("yyyyMMdd-HHmmss");
                Directory.Move(env.Dist, backup);
                log("Backed up the existing Vencord files to " + backup);
            }
            string staging = env.Dist + ".new";
            if (Directory.Exists(staging)) Directory.Delete(staging, true);
            Directory.CreateDirectory(staging);
            foreach (var f in DistFiles) File.WriteAllBytes(Path.Combine(staging, f), Embedded(f));
            File.WriteAllText(Path.Combine(staging, BuildMarkerFile), "Installed by Cipher-Setup.exe " + BuildVersion + "\n");
            if (Directory.Exists(env.Dist)) Directory.Delete(env.Dist, true);
            Directory.Move(staging, env.Dist);
            log("Installed the Vencord + Cipher files into " + env.Dist);
        }

        public static void Install(DiscordInstall d, Env env, Action<string> log)
        {
            if (d.State == PatchState.Foreign || d.State == PatchState.Missing)
                throw new InvalidOperationException(d.Label + ": Cipher won't change this Discord.");
            WriteDist(env, log);
            if (d.State == PatchState.Clean)
            {
                File.Move(d.AppAsar, d.OriginalAsar);
                File.WriteAllBytes(d.AppAsar, Stub(env));
                log("Set up " + d.Flavor + " to load Cipher (the original is kept as _app.asar).");
            }
            else if (d.State == PatchState.CipherStub)
            {
                File.WriteAllBytes(d.AppAsar, Stub(env));
                log(d.Flavor + " already loads Cipher: updated.");
            }
            else
            {
                log(d.Flavor + " already loads Vencord from that folder: left as it is.");
            }
            d.State = Inspect(d, env);
        }

        /// <summary>Removes Cipher from every Discord that has Cipher's stub, and restores the previous files.</summary>
        public static void Uninstall(IEnumerable<DiscordInstall> installs, Env env, Action<string> log)
        {
            foreach (var d in installs)
            {
                if (d.State != PatchState.CipherStub) continue;
                File.Delete(d.AppAsar);
                File.Move(d.OriginalAsar, d.AppAsar);
                d.State = Inspect(d, env);
                log("Restored the original " + d.Flavor + ".");
            }
            if (DistIsCipher(env))
            {
                Directory.Delete(env.Dist, true);
                log("Removed the Vencord + Cipher files.");
                string parent = Path.GetDirectoryName(env.Dist);
                var backup = Directory.Exists(parent)
                    ? Directory.GetDirectories(parent, "dist.backup-*").OrderByDescending(p => p).FirstOrDefault()
                    : null;
                if (backup != null)
                {
                    Directory.Move(backup, env.Dist);
                    log("Put back your previous Vencord files.");
                }
            }
            log("Your Cipher keys and contacts are kept inside Discord; they're only used if Cipher is installed again.");
        }
    }

    /// <summary>Command line, for automated tests only. Always needs explicit (fake) folders.</summary>
    static class Cli
    {
        public static int Run(string[] args)
        {
            string local = null, appData = null, action = null, flavor = null;
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--local-appdata": local = args[++i]; break;
                    case "--appdata": appData = args[++i]; break;
                    case "--install": action = "install"; flavor = args[++i]; break;
                    case "--uninstall": action = "uninstall"; break;
                    case "--list": action = "list"; break;
                }
            }
            if (local == null || appData == null || action == null)
            {
                Console.Error.WriteLine("Test mode needs --local-appdata, --appdata and --list, --install <flavor> or --uninstall.");
                return 2;
            }
            var env = new Env { LocalAppData = local, AppData = appData, Fake = true };
            var installs = Core.Find(env);
            Action<string> log = s => Console.WriteLine(s);
            try
            {
                if (action == "list") foreach (var d in installs) Console.WriteLine(d.Flavor + "\t" + d.State);
                else if (action == "install")
                {
                    var target = installs.FirstOrDefault(d => d.Flavor == flavor);
                    if (target == null) { Console.Error.WriteLine("No " + flavor + " found."); return 3; }
                    Core.Install(target, env, log);
                }
                else Core.Uninstall(installs, env, log);
                return 0;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.Message);
                return 1;
            }
        }
    }

    class SetupForm : Form
    {
        readonly Env env = Env.Real();
        List<DiscordInstall> installs;
        readonly ComboBox picker = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 440 };
        readonly Button installButton = new Button { Text = "Install", Width = 110, Height = 32 };
        readonly Button uninstallButton = new Button { Text = "Uninstall", Width = 110, Height = 32 };
        readonly Button startButton = new Button { Text = "Start Discord", Width = 110, Height = 32, Enabled = false };
        readonly TextBox output = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Width = 440, Height = 130 };

        public SetupForm()
        {
            Text = "Cipher Setup " + Core.BuildVersion;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(480, 330);
            Font = new Font("Segoe UI", 9.5f);

            var title = new Label { Text = "Cipher: end-to-end encrypted messages for Discord", Font = new Font("Segoe UI", 12f, FontStyle.Bold), AutoSize = true, Location = new Point(18, 14) };
            var info = new Label
            {
                Text = "Installs Vencord with the Cipher plugin into the Discord desktop app. Pick your Discord and click Install. Uninstall puts everything back.",
                Location = new Point(20, 46), Size = new Size(440, 40)
            };
            picker.Location = new Point(20, 92);
            installButton.Location = new Point(20, 128);
            uninstallButton.Location = new Point(140, 128);
            startButton.Location = new Point(350, 128);
            output.Location = new Point(20, 172);
            var source = new LinkLabel { Text = "Source code and how to build it yourself", AutoSize = true, Location = new Point(18, 306) };
            source.LinkClicked += (s, e) => Process.Start("https://github.com/cipherciphercipher/cipher");

            Controls.AddRange(new Control[] { title, info, picker, installButton, uninstallButton, startButton, output, source });
            installButton.Click += (s, e) => DoInstall();
            uninstallButton.Click += (s, e) => DoUninstall();
            startButton.Click += (s, e) => StartDiscord();
            Refresh2();
        }

        void Log(string s) { output.AppendText(s + Environment.NewLine); }

        void Refresh2()
        {
            installs = Core.Find(env);
            picker.Items.Clear();
            foreach (var d in installs) picker.Items.Add(d.Label);
            if (installs.Count == 0)
            {
                picker.Items.Add("No Discord desktop app found");
                installButton.Enabled = false;
            }
            int preferred = installs.FindIndex(d => d.State == PatchState.Clean || d.State == PatchState.CipherStub || d.State == PatchState.VencordStub);
            picker.SelectedIndex = Math.Max(0, preferred);
            uninstallButton.Enabled = installs.Any(d => d.State == PatchState.CipherStub) || File.Exists(Path.Combine(env.Dist, Core.BuildMarkerFile));
        }

        DiscordInstall Selected { get { return picker.SelectedIndex >= 0 && picker.SelectedIndex < installs.Count ? installs[picker.SelectedIndex] : null; } }

        bool EnsureClosed(IEnumerable<DiscordInstall> targets)
        {
            var running = targets.Where(d => Core.IsRunning(d, env)).ToList();
            if (running.Count == 0) return true;
            var answer = MessageBox.Show(this, "Discord needs to be closed for this. Close it now?\n\nAnything you're typing in Discord will be lost.", "Cipher Setup", MessageBoxButtons.OKCancel, MessageBoxIcon.Question);
            if (answer != DialogResult.OK) return false;
            foreach (var d in running) Core.Close(d, env);
            return true;
        }

        void DoInstall()
        {
            var d = Selected;
            if (d == null) return;
            if (d.State == PatchState.Foreign || d.State == PatchState.Missing)
            {
                MessageBox.Show(this, "This Discord has been modified by other software, so Cipher won't touch it. Undo that software's changes (or reinstall Discord) and try again.", "Cipher Setup", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            if (!EnsureClosed(new[] { d })) return;
            try
            {
                Core.Install(d, env, Log);
                Log("Done. Start Discord, then turn Cipher on in Settings > Vencord > Plugins.");
                startButton.Enabled = true;
                lastFlavor = d.Flavor;
            }
            catch (Exception e)
            {
                Log("Install failed: " + e.Message);
            }
            Refresh2();
        }

        void DoUninstall()
        {
            var targets = installs.Where(d => d.State == PatchState.CipherStub).ToList();
            if (MessageBox.Show(this, "Remove Cipher from Discord and put back what was there before?", "Cipher Setup", MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK) return;
            if (!EnsureClosed(targets.Count > 0 ? targets : installs)) return;
            try
            {
                Core.Uninstall(installs, env, Log);
                Log("Done.");
            }
            catch (Exception e)
            {
                Log("Uninstall failed: " + e.Message);
            }
            Refresh2();
        }

        string lastFlavor;

        void StartDiscord()
        {
            string updater = Path.Combine(env.LocalAppData, lastFlavor ?? "Discord", "Update.exe");
            string exe = (lastFlavor ?? "Discord") + ".exe";
            try
            {
                if (File.Exists(updater)) Process.Start(updater, "--processStart " + exe);
            }
            catch (Exception e)
            {
                Log("Couldn't start Discord: " + e.Message);
            }
        }
    }

    static class Program
    {
        [STAThread]
        static int Main(string[] args)
        {
            if (args.Length > 0) return Cli.Run(args);
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new SetupForm());
            return 0;
        }
    }
}
