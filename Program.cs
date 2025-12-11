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
    //  Rotation-only. It do the beep boop.
    // ===================================================================

    // PORTS (HEY FUCKASS — STOP CHANGING THESE):
    //   SlimeVR OSC Out  -> 127.0.0.1:9002
    //   Dendrite listens -> 0.0.0.0:9002
    //   Dendrite -> VMT  -> 127.0.0.1:39570

    private const int SlimePort = 9002;
    private const string VmtIp = "127.0.0.1";
    private const int VmtPort = 39570;

    // One-time SteamVR registration
    private const string SteamVrAppKey = "dendrite.osc.bridge";

    // Debug logging toggle
    private const bool DebugLogging = true;

    // Map SlimeVR tracker names -> VMT tracker indices
    private static readonly Dictionary<string, int> TrackerIndexMap =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["hip"]         = 0,
            ["chest"]       = 1,
            ["left_foot"]   = 2,
            ["right_foot"]  = 3,
            ["left_knee"]   = 4,
            ["right_knee"]  = 5,
            ["left_elbow"]  = 6,
            ["right_elbow"] = 7,
        };

    public static void Main()
    {
        Console.OutputEncoding = Encoding.UTF8;
        DrawHeader();

        TryRegisterWithSteamVrOnce();

        Console.WriteLine($"[Dendrite] Listening for SlimeVR OSC on 0.0.0.0:{SlimePort}");
        Console.WriteLine($"[Dendrite] Forwarding to VMT at {VmtIp}:{VmtPort}");
        Console.WriteLine("[Dendrite] Rotation-only relay. Ctrl+C to stop.");
        Console.WriteLine();
        Console.WriteLine("[Dendrite] If you see NO 'RX' logs below, SlimeVR is not hitting port 9002.");
        Console.WriteLine("[Dendrite] Check SlimeVR OSC settings: IP 127.0.0.1, port 9002.");
        Console.WriteLine();

        using var slimeClient = new UdpClient(SlimePort);
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
            catch (SocketException ex)
            {
                Console.WriteLine($"[Dendrite] Socket error: {ex.Message}");
                continue;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Dendrite] Unexpected receive error: {ex.Message}");
                continue;
            }

            var msg = OscMessage.Parse(data);
            if (msg == null)
            {
                if (DebugLogging)
                    Console.WriteLine("[Dendrite] RX: Failed to parse OSC message (ignored).");
                continue;
            }

            if (!msg.Address.StartsWith("/tracking/trackers/", StringComparison.Ordinal))
            {
                if (DebugLogging)
                    Console.WriteLine($"[Dendrite] RX: Non-tracker OSC address '{msg.Address}' (ignored).");
                continue;
            }

            var parts = msg.Address.Split('/', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 4)
            {
                if (DebugLogging)
                    Console.WriteLine($"[Dendrite] RX: Malformed address '{msg.Address}' (ignored).");
                continue;
            }

            var trackerName = parts[2];
            var field = parts[3];

            if (!field.Equals("rotation", StringComparison.OrdinalIgnoreCase))
            {
                if (DebugLogging)
                    Console.WriteLine($"[Dendrite] RX: {trackerName} field '{field}' (not rotation, ignored).");
                continue;
            }

            if (msg.Arguments.Count < 3)
            {
                if (DebugLogging)
                    Console.WriteLine($"[Dendrite] RX: {trackerName} rotation has < 3 args (ignored).");
                continue;
            }

            if (!TrackerIndexMap.TryGetValue(trackerName, out int index))
            {
                if (DebugLogging)
                    Console.WriteLine($"[Dendrite] RX: Unknown tracker '{trackerName}' (no VMT index mapped, ignored).");
                continue;
            }

            float rx = msg.GetFloat(0);
            float ry = msg.GetFloat(1);
            float rz = msg.GetFloat(2);

            if (DebugLogging)
            {
                Console.WriteLine(
                    $"[Dendrite] RX SlimeVR: tracker='{trackerName}' idx={index} rot=({rx:0.000}, {ry:0.000}, {rz:0.000})");
            }

            // VMT /VMT/Room/UEuler:
            //   i: index, i: enabled, f: timeoffset,
            //   fff: position, fff: rotation
            var args = new object[]
            {
                index,
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
                Console.WriteLine($"[Dendrite] OSC build error: {ex.Message}");
                continue;
            }

            try
            {
                vmtClient.Send(vmtBytes, vmtBytes.Length, vmtEndpoint);

                if (DebugLogging)
                {
                    Console.WriteLine(
                        $"[Dendrite] TX VMT: idx={index} rot=({rx:0.000}, {ry:0.000}, {rz:0.000}) bytes={vmtBytes.Length}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Dendrite] Failed to send to VMT: {ex.Message}");
            }
        }
    }

    // -------------------------------------------------------------------
    // One-time SteamVR registration helper
    // -------------------------------------------------------------------
    private static void TryRegisterWithSteamVrOnce()
    {
        try
        {
            string baseDir = AppContext.BaseDirectory;
            string flagPath = Path.Combine(baseDir, "dendrite_steamvr_registered.flag");

            if (File.Exists(flagPath))
            {
                Console.WriteLine("[Dendrite] SteamVR registration already attempted (flag file present).");
                return;
            }

            string exePath = Process.GetCurrentProcess().MainModule?.FileName ?? "";
            if (string.IsNullOrEmpty(exePath))
            {
                Console.WriteLine("[Dendrite] Could not determine own exe path for SteamVR registration.");
                return;
            }

            string manifestPath = Path.Combine(baseDir, "dendrite.vrmanifest");

            string manifestJson = $@"{{
  ""source"": ""user"",
  ""applications"": [
    {{
      ""app_key"": ""{SteamVrAppKey}"",
      ""launch_type"": ""binary"",
      ""binary_path"": ""{exePath.Replace("\\", "\\\\")}"",
      ""arguments"": """",
      ""is_dashboard_overlay"": false,
      ""is_background"": true,
      ""last_launch_time"": 0
    }}
  ]
}}";

            File.WriteAllText(manifestPath, manifestJson, Encoding.UTF8);

            string? vrpathregPath = FindVrPathReg();
            if (vrpathregPath == null)
            {
                Console.WriteLine("[Dendrite] Could not find vrpathreg.exe –");
                Console.WriteLine("          SteamVR manifest created as dendrite.vrmanifest,");
                Console.WriteLine("          but you may need to register it manually.");
            }
            else
            {
                var psi = new ProcessStartInfo
                {
                    FileName = vrpathregPath,
                    Arguments = $"addapplication \"{manifestPath}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var proc = Process.Start(psi);
                proc?.WaitForExit(3000);

                Console.WriteLine("[Dendrite] Attempted SteamVR app registration via vrpathreg.exe.");
                Console.WriteLine("          Now go to SteamVR → Settings → Startup / Shutdown");
                Console.WriteLine("          and enable Dendrite in the list (one-time toggle).");
            }

            File.WriteAllText(flagPath, "ok");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Dendrite] SteamVR registration attempt failed: {ex.Message}");
        }
    }

    private static string? FindVrPathReg()
    {
        var candidates = new[]
        {
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                "Steam", "steamapps", "common", "SteamVR", "bin", "win64", "vrpathreg.exe"
            ),
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                "Steam", "steamapps", "common", "SteamVR", "bin", "win32", "vrpathreg.exe"
            )
        };

        foreach (var path in candidates)
        {
            if (File.Exists(path))
                return path;
        }

        return null;
    }

    // -------------------------------------------------------------------
    // Cosmetics
    // -------------------------------------------------------------------
    private static void DrawHeader()
    {
        Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine("║                           DENDRITE                           ║");
        Console.WriteLine("║        Ultra lightweight SlimeVR → VMT → PSMSx forwarder     ║");
        Console.WriteLine("║                      (it do the beep boop)                   ║");
        Console.WriteLine("╠══════════════════════════════════════════════════════════════╣");
        Console.WriteLine("║  PORTS (HEY FUCKASS — STOP CHANGING THESE):                  ║");
        Console.WriteLine("║      SlimeVR OSC Out  → 127.0.0.1:9002                       ║");
        Console.WriteLine("║      Dendrite listens → 0.0.0.0:9002                         ║");
        Console.WriteLine("║      Dendrite → VMT   → 127.0.0.1:39570                      ║");
        Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");
        Console.WriteLine();
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
            if (data == null || data.Length == 0)
                return null;

            int index = 0;
            try
            {
                string address = ReadString(data, ref index);
                if (string.IsNullOrEmpty(address))
                    return null;

                string typeTag = ReadString(data, ref index);
                if (string.IsNullOrEmpty(typeTag) || typeTag[0] != ',')
                    return null;

                var msg = new OscMessage(address, typeTag);

                for (int i = 1; i < typeTag.Length; i++)
                {
                    char t = typeTag[i];
                    switch (t)
                    {
                        case 'i':
                            msg.Arguments.Add(ReadInt(data, ref index));
                            break;
                        case 'f':
                            msg.Arguments.Add(ReadFloat(data, ref index));
                            break;
                        case 's':
                            msg.Arguments.Add(ReadString(data, ref index));
                            break;
                        default:
                            return null;
                    }
                }

                return msg;
            }
            catch
            {
                return null;
            }
        }

        public float GetFloat(int idx)
        {
            if (idx < 0 || idx >= Arguments.Count)
                return 0f;

            return Arguments[idx] switch
            {
                float f => f,
                int i   => i,
                _       => 0f
            };
        }

        public static byte[] Build(string address, string typeTags, object[] args)
        {
            if (address is null) throw new ArgumentNullException(nameof(address));
            if (typeTags is null) throw new ArgumentNullException(nameof(typeTags));
            if (args is null) throw new ArgumentNullException(nameof(args));
            if (typeTags.Length != args.Length)
                throw new ArgumentException("typeTags length must match args length.");

            var buf = new List<byte>(address.Length + typeTags.Length * 4 + 32);

            WriteString(buf, address);
            WriteString(buf, "," + typeTags);

            for (int i = 0; i < typeTags.Length; i++)
            {
                char t = typeTags[i];
                object a = args[i];

                switch (t)
                {
                    case 'i':
                        WriteInt(buf, Convert.ToInt32(a));
                        break;
                    case 'f':
                        WriteFloat(buf, Convert.ToSingle(a));
                        break;
                    case 's':
                        WriteString(buf, Convert.ToString(a) ?? string.Empty);
                        break;
                    default:
                        throw new NotSupportedException($"OSC type '{t}' not supported.");
                }
            }

            return buf.ToArray();
        }

        private static string ReadString(byte[] data, ref int index)
        {
            int len = data.Length;
            if (index >= len)
                return string.Empty;

            int start = index;
            while (index < len && data[index] != 0)
                index++;

            string s = Encoding.ASCII.GetString(data, start, index - start);

            if (index < len && data[index] == 0)
                index++;

            while (index < len && (index & 0x3) != 0)
                index++;

            return s;
        }

        private static int ReadInt(byte[] data, ref int index)
        {
            if (index + 4 > data.Length) throw new IndexOutOfRangeException();

            int b0 = data[index++];
            int b1 = data[index++];
            int b2 = data[index++];
            int b3 = data[index++];

            int value = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
            return value;
        }

        private static float ReadFloat(byte[] data, ref int index)
        {
            int raw = ReadInt(data, ref index);
            return BitConverter.Int32BitsToSingle(raw);
        }

        private static voi
