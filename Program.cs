using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Dendrite;

internal static class Program
{
    // ===================================================================
    //  DENDRITE
    //  Ultra lightweight SlimeVR → VMT → PSMSx forwarder
    //  (it do the beep boop)
    // ===================================================================

    // PORTS (HEY FUCKASS — STOP CHANGING THESE):
    //   SlimeVR OSC Out  → 127.0.0.1:29347
    //   Dendrite listens → 0.0.0.0:29347
    //   Dendrite → VMT   → 127.0.0.1:39570

    private const int SlimePort = 29347;
    private const string VmtIp = "127.0.0.1";
    private const int VmtPort = 39570;

    private const string SteamVrAppKey = "dendrite.osc.bridge";
    private const bool DebugLogging = true;

    public static void Main()
    {
        Console.OutputEncoding = Encoding.UTF8;
        DrawHeader();

        TryRegisterWithSteamVrOnce();

        Console.WriteLine($"[Dendrite] Listening for SlimeVR OSC on 0.0.0.0:{SlimePort}");
        Console.WriteLine($"[Dendrite] Forwarding to VMT at {VmtIp}:{VmtPort}");
        Console.WriteLine("[Dendrite] Rotation-only relay. Ctrl+C to stop.\n");
        Console.WriteLine($"[Dendrite] If you see NO 'RX' logs below, SlimeVR is not hitting port {SlimePort}.");
        Console.WriteLine($"[Dendrite] Check SlimeVR OSC settings: IP 127.0.0.1, port {SlimePort}.\n");

        // Try to bind port, but gracefully error if in use
        UdpClient slimeClient;

        try
        {
            slimeClient = new UdpClient(SlimePort);
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AddressAlreadyInUse)
        {
            Console.WriteLine($"\n[Dendrite] ERROR: Could not bind to UDP port {SlimePort}.");
            Console.WriteLine("[Dendrite] Something is already using this port.\n");
            PrintPortUsageInfo(SlimePort);
            Console.Write("\nPress Enter to exit...");
            Console.ReadLine();
            return;
        }
        catch (SocketException ex)
        {
            Console.WriteLine($"\n[Dendrite] ERROR binding UDP port {SlimePort}: {ex.Message}");
            Console.Write("\nPress Enter to exit...");
            Console.ReadLine();
            return;
        }

        using var vmtClient = new UdpClient();
        var vmtEndpoint = new IPEndPoint(IPAddress.Parse(VmtIp), VmtPort);

        while (true)
        {
            IPEndPoint? remote = null;
            byte[] data;

            try
            {
                data = slimeClient.Receive(ref remote!);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Dendrite] Receive error: {ex.Message}");
                continue;
            }

            var msg = OscMessage.Parse(data);
            if (msg == null)
            {
                if (DebugLogging)
                    Console.WriteLine("[Dendrite] RX: Unparseable OSC packet (ignored).");
                continue;
            }

            if (!msg.Address.StartsWith("/tracking/trackers/", StringComparison.Ordinal))
            {
                if (DebugLogging)
                    Console.WriteLine($"[Dendrite] RX: Non-tracker OSC '{msg.Address}'.");
                continue;
            }

            var parts = msg.Address.Split('/', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 4)
            {
                if (DebugLogging)
                    Console.WriteLine($"[Dendrite] RX: Malformed OSC address '{msg.Address}'.");
                continue;
            }

            string trackerIdRaw = parts[2];
            string field = parts[3];

            if (!field.Equals("rotation", StringComparison.OrdinalIgnoreCase))
            {
                if (DebugLogging)
                    Console.WriteLine($"[Dendrite] RX: Field '{field}' ignored.");
                continue;
            }

            if (!int.TryParse(trackerIdRaw, out int trackerId))
            {
                if (DebugLogging)
                    Console.WriteLine($"[Dendrite] RX: Tracker '{trackerIdRaw}' is not numeric.");
                continue;
            }

            if (trackerId < 1 || trackerId > 8)
            {
                if (DebugLogging)
                    Console.WriteLine($"[Dendrite] RX: Tracker ID {trackerId} outside 1–8.");
                continue;
            }

            int vmtIndex = trackerId - 1;

            if (msg.Arguments.Count < 3)
            {
                if (DebugLogging)
                    Console.WriteLine($"[Dendrite] RX: Rotation missing args.");
                continue;
            }

            float rx = msg.GetFloat(0);
            float ry = msg.GetFloat(1);
            float rz = msg.GetFloat(2);

            if (DebugLogging)
                Console.WriteLine($"[Dendrite] RX SlimeVR T{trackerId} → idx {vmtIndex}: ({rx:F3}, {ry:F3}, {rz:F3})");

            var args = new object[]
            {
                vmtIndex,
                1,
                0.0f,
                0.0f, 0.0f, 0.0f,
                rx, ry, rz
            };

            byte[] vmtBytes;
            try
            {
                vmtBytes = OscMessage.Build("/VMT/Room/UEuler", "iiffffffff", args);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Dendrite] Build error: {ex.Message}");
                continue;
            }

            try
            {
                vmtClient.Send(vmtBytes, vmtBytes.Length, vmtEndpoint);
                if (DebugLogging)
                    Console.WriteLine($"[Dendrite] TX VMT idx {vmtIndex}: ({rx:F3}, {ry:F3}, {rz:F3})");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Dendrite] Send error: {ex.Message}");
            }
        }
    }

    // -------------------------------------------------------------------
    // SteamVR auto-registration
    // -------------------------------------------------------------------
    private static void TryRegisterWithSteamVrOnce()
    {
        try
        {
            string baseDir = AppContext.BaseDirectory;
            string flagPath = Path.Combine(baseDir, "dendrite_steamvr_registered.flag");

            if (File.Exists(flagPath))
            {
                Console.WriteLine("[Dendrite] SteamVR registration already attempted.");
                return;
            }

            string exePath = Process.GetCurrentProcess().MainModule?.FileName ?? "";
            string manifestPath = Path.Combine(baseDir, "dendrite.vrmanifest");

            string manifestJson = $@"{{
  ""source"": ""user"",
  ""applications"": [
    {{
      ""app_key"": ""{SteamVrAppKey}"",
      ""launch_type"": ""binary"",
      ""binary_path"": ""{exePath.Replace("\\", "\\\\")}"",
      ""arguments"": """",
      ""is_background"": true
    }}
  ]
}}";

            File.WriteAllText(manifestPath, manifestJson);

            string? vrpathreg = FindVrPathReg();
            if (vrpathreg == null)
            {
                Console.WriteLine("[Dendrite] Could not find vrpathreg.exe – manifest saved, but manual registration may be required.");
            }
            else
            {
                var psi = new ProcessStartInfo
                {
                    FileName = vrpathreg,
                    Arguments = $"addapplication \"{manifestPath}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var proc = Process.Start(psi);
                proc?.WaitForExit(3000);
                Console.WriteLine("[Dendrite] SteamVR registration attempted via vrpathreg.exe.");
            }

            File.WriteAllText(flagPath, "ok");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Dendrite] SteamVR registration failed: {ex.Message}");
        }
    }

    private static string? FindVrPathReg()
    {
        string pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        string[] paths =
        {
            Path.Combine(pf86, "Steam", "steamapps", "common", "SteamVR", "bin", "win64", "vrpathreg.exe"),
            Path.Combine(pf86, "Steam", "steamapps", "common", "SteamVR", "bin", "win32", "vrpathreg.exe")
        };

        foreach (string p in paths)
            if (File.Exists(p))
                return p;

        return null;
    }

    // -------------------------------------------------------------------
    // Port snitching (netstat + tasklist)
    // -------------------------------------------------------------------
    private static void PrintPortUsageInfo(int port)
    {
        try
        {
            Console.WriteLine($"[Dendrite] Checking UDP port {port}…");

            var psi = new ProcessStartInfo
            {
                FileName = "netstat",
                Arguments = "-ano -p udp",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };

            using var proc = Process.Start(psi);
            string output = proc!.StandardOutput.ReadToEnd();
            proc.WaitForExit(2000);

            var lines = output.Split('\n');
            var pids = new HashSet<string>();

            foreach (var line in lines)
            {
                if (line.Contains($":{port}"))
                {
                    var parts = line.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    string pid = parts[^1];
                    if (int.TryParse(pid, out _))
                        pids.Add(pid);
                }
            }

            if (pids.Count == 0)
            {
                Console.WriteLine($"[Dendrite] netstat found nothing using UDP {port}.");
                return;
            }

            Console.WriteLine($"[Dendrite] PIDs using UDP {port}: {string.Join(", ", pids)}");

            foreach (var pid in pids)
            {
                var tasklist = new ProcessStartInfo
                {
                    FileName = "tasklist",
                    Arguments = $"/FI \"PID eq {pid}\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false
                };

                using var tp = Process.Start(tasklist);
                string tOut = tp!.StandardOutput.ReadToEnd();

                foreach (var tl in tOut.Split('\n'))
                {
                    if (tl.Contains(pid))
                        Console.WriteLine($"[Dendrite] PID {pid} -> {tl.Trim()}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Dendrite] Port sniffer error: {ex.Message}");
        }
    }

    // -------------------------------------------------------------------
    // Header (ASCII art)
    // -------------------------------------------------------------------
    private static void DrawHeader()
    {
        Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine("║                           DENDRITE                           ║");
        Console.WriteLine("║       Ultra lightweight SlimeVR → VMT → PSMSx forwarder      ║");
        Console.WriteLine("║                        (it do the beep boop)                 ║");
        Console.WriteLine("╠══════════════════════════════════════════════════════════════╣");
        Console.WriteLine("║  PORTS (HEY FUCKASS — STOP CHANGING THESE):                  ║");
        Console.WriteLine("║      SlimeVR OSC Out  → 127.0.0.1:29347                      ║");
        Console.WriteLine("║      Dendrite listens → 0.0.0.0:29347                        ║");
        Console.WriteLine("║      Dendrite → VMT   → 127.0.0.1:39570                      ║");
        Console.WriteLine("╚══════════════════════════════════════════════════════════════╝\n");
    }

    // ===================================================================
    //  Minimal OSC implementation
    // ===================================================================

    private sealed class OscMessage
    {
        public string Address { get; }
        public string TypeTag { get; }
        public List<object> Arguments { get; } = new();

        private OscMessage(string address, string typeTag)
        {
            Address = address;
            TypeTag = typeTag;
        }

        public static OscMessage? Parse(byte[] data)
        {
            if (data == null || data.Length < 4)
                return null;

            int index = 0;

            try
            {
                string address = ReadString(data, ref index);
                string tags = ReadString(data, ref index);
                if (string.IsNullOrEmpty(tags) || !tags.StartsWith(","))
                    return null;
