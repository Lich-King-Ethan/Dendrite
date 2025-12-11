using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Dendrite
{
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
        //   Dendrite → VMT   → 127.0.0.1:39570 (OSC /VMT/Room/UEuler)
        //   Dendrite → PSMSx Remote Devices (binary)
        //       → 192.168.0.243:6969

        private const int SlimePort = 29347;

        private const string VmtIp = "127.0.0.1";
        private const int VmtPort = 39570;

        // PSMSx Remote Devices socket (your static LAN IP + port)
        private const string PsmsIp = "192.168.0.243";
        private const int PsmsPort = 6969;

        private const string SteamVrAppKey = "dendrite.osc.bridge";
        private const bool DebugLogging = true;

        public static void Main()
        {
            Console.OutputEncoding = Encoding.UTF8;
            DrawHeader();

            TryRegisterWithSteamVrOnce();

            // Init PSMSx remote devices (12 fake MACs, 12 sockets)
            PsmsRemote.Initialize();

            Console.WriteLine($"[Dendrite] Listening for SlimeVR OSC on 0.0.0.0:{SlimePort}");
            Console.WriteLine($"[Dendrite] Forwarding to VMT at {VmtIp}:{VmtPort}");
            Console.WriteLine($"[Dendrite] Forwarding to PSMSx Remote Devices at {PsmsIp}:{PsmsPort}");
            Console.WriteLine("[Dendrite] Rotation-only relay. Ctrl+C to stop.\n");
            Console.WriteLine($"[Dendrite] If you see NO 'RX' logs below, SlimeVR is not hitting port {SlimePort}.");
            Console.WriteLine($"[Dendrite] Check SlimeVR OSC settings: IP 127.0.0.1, port {SlimePort}.\n");

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

            using (slimeClient)
            using (var vmtClient = new UdpClient())
            {
                var vmtEndpoint = new IPEndPoint(IPAddress.Parse(VmtIp), VmtPort);

                while (true)
                {
                    IPEndPoint remote = new IPEndPoint(IPAddress.Any, 0);
                    byte[] data;
                    try
                    {
                        data = slimeClient.Receive(ref remote);
                    }
                    catch (ObjectDisposedException)
                    {
                        break;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[Dendrite] Receive error: {ex.Message}");
                        continue;
                    }

                    bool anyMessage = false;
                    foreach (var msg in OscMessage.ParsePacket(data))
                    {
                        anyMessage = true;

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

                        if (field.Equals("position", StringComparison.OrdinalIgnoreCase))
                        {
                            if (DebugLogging)
                                Console.WriteLine("[Dendrite] RX: Field 'position' ignored.");
                            continue;
                        }

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

                        if (trackerId < 1 || trackerId > 12)
                        {
                            if (DebugLogging)
                                Console.WriteLine($"[Dendrite] RX: Tracker ID {trackerId} outside 1–12.");
                            continue;
                        }

                        int idx = trackerId - 1;

                        if (msg.Arguments.Count < 3)
                        {
                            if (DebugLogging)
                                Console.WriteLine("[Dendrite] RX: Rotation missing args.");
                            continue;
                        }

                        float rx = msg.GetFloat(0);
                        float ry = msg.GetFloat(1);
                        float rz = msg.GetFloat(2);

                        if (DebugLogging)
                            Console.WriteLine($"[Dendrite] RX SlimeVR T{trackerId} → idx {idx}: ({rx:F3}, {ry:F3}, {rz:F3})");

                        // ---------- VMT OUTPUT (OSC /VMT/Room/UEuler) ----------
                        var vmtArgs = new object[]
                        {
                            idx,
                            1,
                            0.0f,
                            0.0f, 0.0f, 0.0f,
                            rx, ry, rz
                        };

                        byte[] vmtBytes;
                        try
                        {
                            vmtBytes = OscMessage.Build("/VMT/Room/UEuler", "iiffffffff", vmtArgs);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[Dendrite] Build error (VMT): {ex.Message}");
                            vmtBytes = Array.Empty<byte>();
                        }

                        if (vmtBytes.Length > 0)
                        {
                            try
                            {
                                vmtClient.Send(vmtBytes, vmtBytes.Length, vmtEndpoint);
                                if (DebugLogging)
                                    Console.WriteLine($"[Dendrite] TX VMT idx {idx}: ({rx:F3}, {ry:F3}, {rz:F3})");
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"[Dendrite] Send error (VMT): {ex.Message}");
                            }
                        }

                        // ---------- PSMSx REMOTE DEVICES OUTPUT (binary SlimeVR) ----------
                        PsmsRemote.SendRotation(idx, rx, ry, rz);
                    }

                    if (!anyMessage && DebugLogging)
                    {
                        Console.WriteLine("[Dendrite] RX: Unparseable OSC packet or bundle (no valid messages).");
                        DumpPacketPreview(data);
                    }
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
                if (string.IsNullOrEmpty(exePath))
                    return;

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
                    Console.WriteLine("[Dendrite] Could not find vrpathreg.exe – manifest saved, manual registration may be required.");
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

            foreach (var p in paths)
            {
                if (File.Exists(p))
                    return p;
            }

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
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var proc = Process.Start(psi);
                if (proc == null)
                {
                    Console.WriteLine("[Dendrite] netstat failed to start.");
                    return;
                }

                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(2000);

                var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                var pids = new HashSet<string>();

                foreach (var line in lines)
                {
                    if (!line.Contains($":{port}"))
                        continue;

                    var parts = line.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 5)
                        continue;

                    string pid = parts[^1];
                    if (!string.IsNullOrWhiteSpace(pid))
                        pids.Add(pid);
                }

                if (pids.Count == 0)
                {
                    Console.WriteLine($"[Dendrite] netstat found nothing using UDP {port}.");
                    return;
                }

                Console.WriteLine($"[Dendrite] PIDs using UDP {port}: {string.Join(", ", pids)}");

                foreach (var pid in pids)
                {
                    var tpsi = new ProcessStartInfo
                    {
                        FileName = "tasklist",
                        Arguments = $"/FI \"PID eq {pid}\"",
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };

                    using var tproc = Process.Start(tpsi);
                    if (tproc == null)
                        continue;

                    string tout = tproc.StandardOutput.ReadToEnd();
                    tproc.WaitForExit(2000);

                    foreach (var tl in tout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                    {
                        var trimmed = tl.Trim();
                        if (trimmed.StartsWith("Image Name", StringComparison.OrdinalIgnoreCase))
                            continue;
                        if (trimmed.StartsWith("=", StringComparison.Ordinal))
                            continue;
                        if (trimmed.Length == 0)
                            continue;
                        if (trimmed.Contains(pid))
                        {
                            Console.WriteLine($"[Dendrite] PID {pid} -> {trimmed}");
                            break;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Dendrite] Port sniffer error: {ex.Message}");
            }
        }

        // -------------------------------------------------------------------
        // Packet preview dump (for debugging weird OSC)
        // -------------------------------------------------------------------
        private static void DumpPacketPreview(byte[] data)
        {
            try
            {
                int len = Math.Min(data.Length, 64);
                var sbHex = new StringBuilder();
                for (int i = 0; i < len; i++)
                {
                    sbHex.Append(data[i].ToString("X2")).Append(' ');
                }

                string ascii = Encoding.ASCII.GetString(data, 0, len);
                ascii = ascii.Replace("\0", "·");

                Console.WriteLine($"[Dendrite] Packet length: {data.Length} bytes");
                Console.WriteLine($"[Dendrite] Hex (first {len}): {sbHex}");
                Console.WriteLine($"[Dendrite] ASCII (first {len}): {ascii}");
            }
            catch
            {
                // best effort only
            }
        }

        private static void DrawHeader()
        {
            Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
            Console.WriteLine("║                           DENDRITE                           ║");
            Console.WriteLine("║       Ultra lightweight SlimeVR → VMT → PSMSx forwarder      ║");
            Console.WriteLine("║                        (it do the beep boop)                 ║");
            Console.WriteLine("╠══════════════════════════════════════════════════════════════╣");
            Console.WriteLine("║  PORTS (HEY FUCKASS — STOP CHANGING THESE):                  ║");
            Console.WriteLine($"║      SlimeVR OSC Out  → 127.0.0.1:{SlimePort,-5}                     ║");
            Console.WriteLine($"║      Dendrite listens → 0.0.0.0:{SlimePort,-5}                      ║");
            Console.WriteLine($"║      Dendrite → VMT   → 127.0.0.1:{VmtPort,-5}                     ║");
            Console.WriteLine($"║      Dendrite → PSMSx → {PsmsIp}:{PsmsPort}                   ║");
            Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");
            Console.WriteLine();
        }

        // ===================================================================
        //  PSMSx Remote Devices sender (SlimeVR binary protocol, 12 sockets)
        // ===================================================================
        private static class PsmsRemote
        {
            private sealed class RemoteDevice
            {
                public byte[] Mac = new byte[6];
                public ulong PacketNumber = 1;
                public bool HandshakeSent = false;
                public UdpClient? Client;
                public IPEndPoint? Endpoint;
            }

            private static RemoteDevice[] _devices = Array.Empty<RemoteDevice>();
            private static readonly object _lock = new object();

            public static void Initialize()
            {
                try
                {
                    _devices = new RemoteDevice[12];
                    for (int i = 0; i < _devices.Length; i++)
                    {
                        var dev = new RemoteDevice
                        {
                            Mac = new byte[]
                            {
                                0xDE, 0xAD, 0xBE, 0xEF, 0x00, (byte)(i + 1)
                            },
                            PacketNumber = 1,
                            HandshakeSent = false,
                            Client = new UdpClient(0), // bind to ephemeral local port
                            Endpoint = new IPEndPoint(IPAddress.Parse(PsmsIp), PsmsPort)
                        };

                        _devices[i] = dev;

                        int localPort = ((IPEndPoint)dev.Client.Client.LocalEndPoint!).Port;
                        string macStr = BitConverter.ToString(dev.Mac);
                        Console.WriteLine($"[Dendrite] PSMSx device MAC {macStr} using local UDP port {localPort}.");
                    }

                    // Send initial handshake for all devices
                    foreach (var dev in _devices)
                    {
                        SendHandshake(dev);
                    }

                    Console.WriteLine($"[Dendrite] PSMSx Remote Devices announced {_devices.Length} MACs at {PsmsIp}:{PsmsPort}.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[Dendrite] PSMSx Remote init failed: {ex.Message}");
                    _devices = Array.Empty<RemoteDevice>();
                }
            }

            public static void SendRotation(int trackerIndex, float rxDeg, float ryDeg, float rzDeg)
            {
                if (_devices.Length == 0)
                    return;

                if (trackerIndex < 0 || trackerIndex >= _devices.Length)
                    return;

                var dev = _devices[trackerIndex];
                if (dev.Client == null || dev.Endpoint == null)
                    return;

                if (!dev.HandshakeSent)
                {
                    SendHandshake(dev);
                }

                var q = EulerDegreesToQuaternion(rxDeg, ryDeg, rzDeg);

                byte[] packet;
                lock (_lock)
                {
                    ulong pn = dev.PacketNumber++;
                    packet = BuildRotationPacket(0, pn, q.x, q.y, q.z, q.w, 3);
                }

                try
                {
                    dev.Client.Send(packet, packet.Length, dev.Endpoint);
                    if (DebugLogging)
                    {
                        string macStr = BitConverter.ToString(dev.Mac);
                        Console.WriteLine($"[Dendrite] TX PSMSx MAC {macStr} (tracker {trackerIndex}) q=({q.x:F3},{q.y:F3},{q.z:F3},{q.w:F3})");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[Dendrite] PSMSx send error: {ex.Message}");
                }
            }

            private static void SendHandshake(RemoteDevice dev)
            {
                if (dev.Client == null || dev.Endpoint == null)
                    return;

                byte[] packet = BuildHandshakePacket(0, dev.Mac);
                try
                {
                    dev.Client.Send(packet, packet.Length, dev.Endpoint);
                    dev.HandshakeSent = true;

                    string macStr = BitConverter.ToString(dev.Mac);
                    Console.WriteLine($"[Dendrite] PSMSx handshake sent for MAC {macStr}.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[Dendrite] PSMSx handshake send error: {ex.Message}");
                }
            }

            private static byte[] BuildHandshakePacket(ulong packetNumber, byte[] mac)
            {
                using var ms = new MemoryStream();
                using var bw = new BinaryWriter(ms);

                // Header: 0,0,0,3 (PACKET_HANDSHAKE)
                bw.Write((byte)0);
                bw.Write((byte)0);
                bw.Write((byte)0);
                bw.Write((byte)3);

                WriteUInt64BE(bw, packetNumber);

                // Fake board / imu / mcu identifiers
                WriteInt32BE(bw, 1); // board (pretend ESP32)
                WriteInt32BE(bw, 0); // imu (unused)
                WriteInt32BE(bw, 2); // mcu (fake code)
                WriteInt32BE(bw, 0);
                WriteInt32BE(bw, 0);
                WriteInt32BE(bw, 0);

                // Firmware build + version
                WriteInt32BE(bw, 1); // build number
                string version = "Dendrite-Bridge";
                if (version.Length > 255)
                    version = version.Substring(0, 255);
                bw.Write((byte)version.Length);
                bw.Write(Encoding.ASCII.GetBytes(version));

                // MAC address (6 bytes)
                if (mac.Length != 6)
                {
                    byte[] fallback = { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01 };
                    bw.Write(fallback);
                }
                else
                {
                    bw.Write(mac);
                }

                return ms.ToArray();
            }

            private static byte[] BuildRotationPacket(byte sensorId, ulong packetNumber,
                                                      float qx, float qy, float qz, float qw,
                                                      byte accuracy)
            {
                using var ms = new MemoryStream();
                using var bw = new BinaryWriter(ms);

                // Header: 0,0,0,17 (PACKET_ROTATION_DATA)
                bw.Write((byte)0);
                bw.Write((byte)0);
                bw.Write((byte)0);
                bw.Write((byte)17);

                WriteUInt64BE(bw, packetNumber);

                bw.Write(sensorId);       // sensor ID
                bw.Write((byte)1);        // dataType = normal

                WriteFloatBE(bw, qx);
                WriteFloatBE(bw, qy);
                WriteFloatBE(bw, qz);
                WriteFloatBE(bw, qw);

                bw.Write(accuracy);       // accuracy [0..3]

                return ms.ToArray();
            }

            private static void WriteInt32BE(BinaryWriter bw, int value)
            {
                bw.Write((byte)((value >> 24) & 0xFF));
                bw.Write((byte)((value >> 16) & 0xFF));
                bw.Write((byte)((value >> 8) & 0xFF));
                bw.Write((byte)(value & 0xFF));
            }

            private static void WriteUInt64BE(BinaryWriter bw, ulong value)
            {
                bw.Write((byte)((value >> 56) & 0xFF));
                bw.Write((byte)((value >> 48) & 0xFF));
                bw.Write((byte)((value >> 40) & 0xFF));
                bw.Write((byte)((value >> 32) & 0xFF));
                bw.Write((byte)((value >> 24) & 0xFF));
                bw.Write((byte)((value >> 16) & 0xFF));
                bw.Write((byte)((value >> 8) & 0xFF));
                bw.Write((byte)(value & 0xFF));
            }

            private static void WriteFloatBE(BinaryWriter bw, float value)
            {
                var bytes = BitConverter.GetBytes(value);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(bytes);
                bw.Write(bytes);
            }

            // Euler (deg) → quaternion (x,y,z,w), assuming roll(X), pitch(Y), yaw(Z) order
            private static (float x, float y, float z, float w) EulerDegreesToQuaternion(float rxDeg, float ryDeg, float rzDeg)
            {
                double roll = rxDeg * Math.PI / 180.0;
                double pitch = ryDeg * Math.PI / 180.0;
                double yaw = rzDeg * Math.PI / 180.0;

                double cy = Math.Cos(yaw * 0.5);
                double sy = Math.Sin(yaw * 0.5);
                double cp = Math.Cos(pitch * 0.5);
                double sp = Math.Sin(pitch * 0.5);
                double cr = Math.Cos(roll * 0.5);
                double sr = Math.Sin(roll * 0.5);

                double w = cr * cp * cy + sr * sp * sy;
                double x = sr * cp * cy - cr * sp * sy;
                double y = cr * sp * cy + sr * cp * sy;
                double z = cr * cp * sy - sr * sp * cy;

                return ((float)x, (float)y, (float)z, (float)w);
            }
        }

        // ===================================================================
        //  Minimal OSC implementation (+ bundle support)
        // ===================================================================
        private sealed class OscMessage
        {
            public string Address { get; }
            public string TypeTag { get; }
            public List<object> Arguments { get; } = new List<object>();

            private OscMessage(string address, string typeTag)
            {
                Address = address;
                TypeTag = typeTag;
            }

            public static IEnumerable<OscMessage> ParsePacket(byte[] data)
            {
                if (data == null || data.Length < 4)
                    yield break;

                if (IsBundleHeader(data))
                {
                    int index = 0;
                    string _ = ReadString(data, ref index);
                    if (index + 8 > data.Length)
                        yield break;
                    index += 8;

                    while (index + 4 <= data.Length)
                    {
                        int size = ReadInt(data, ref index);
                        if (size <= 0 || index + size > data.Length)
                            break;

                        var msgBytes = new byte[size];
                        Buffer.BlockCopy(data, index, msgBytes, 0, size);
                        index += size;

                        var msg = Parse(msgBytes);
                        if (msg != null)
                            yield return msg;
                    }
                }
                else
                {
                    var msg = Parse(data);
                    if (msg != null)
                        yield return msg;
                }
            }

            private static bool IsBundleHeader(byte[] data)
            {
                if (data.Length < 8)
                    return false;

                return data[0] == (byte)'#' &&
                       data[1] == (byte)'b' &&
                       data[2] == (byte)'u' &&
                       data[3] == (byte)'n' &&
                       data[4] == (byte)'d' &&
                       data[5] == (byte)'l' &&
                       data[6] == (byte)'e' &&
                       data[7] == 0;
            }

            public static OscMessage? Parse(byte[] data)
            {
                if (data == null || data.Length < 4)
                    return null;

                int index = 0;
                try
                {
                    string address = ReadString(data, ref index);
                    if (string.IsNullOrEmpty(address))
                        return null;

                    string tags = ReadString(data, ref index);
                    if (string.IsNullOrEmpty(tags) || !tags.StartsWith(",", StringComparison.Ordinal))
                        return null;

                    var msg = new OscMessage(address, tags);

                    for (int i = 1; i < tags.Length; i++)
                    {
                        char t = tags[i];
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

            public float GetFloat(int index)
            {
                if (index < 0 || index >= Arguments.Count)
                    return 0f;

                return Arguments[index] switch
                {
                    float f => f,
                    int i => i,
                    _ => 0f
                };
            }

            public static byte[] Build(string address, string tags, object[] args)
            {
                if (address == null) throw new ArgumentNullException(nameof(address));
                if (tags == null) throw new ArgumentNullException(nameof(tags));
                if (args == null) throw new ArgumentNullException(nameof(args));

                int n = Math.Min(tags.Length, args.Length);
                if (n <= 0)
                    throw new ArgumentException("No tags/args to build OSC message.");

                if (tags.Length != n)
                    tags = tags.Substring(0, n);

                if (args.Length != n)
                {
                    var trimmed = new object[n];
                    Array.Copy(args, trimmed, n);
                    args = trimmed;
                }

                var buf = new List<byte>();
                WriteString(buf, address);
                WriteString(buf, "," + tags);

                for (int i = 0; i < n; i++)
                {
                    char t = tags[i];
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
                int start = index;
                while (index < data.Length && data[index] != 0)
                    index++;

                string s = Encoding.ASCII.GetString(data, start, index - start);
                index++; // skip NUL

                while (index % 4 != 0 && index < data.Length)
                    index++;

                return s;
            }

            private static int ReadInt(byte[] data, ref int index)
            {
                if (index + 4 > data.Length)
                    throw new IndexOutOfRangeException();

                int v = (data[index] << 24) |
                        (data[index + 1] << 16) |
                        (data[index + 2] << 8) |
                        data[index + 3];

                index += 4;
                return v;
            }

            private static float ReadFloat(byte[] data, ref int index)
            {
                int v = ReadInt(data, ref index);
                return BitConverter.Int32BitsToSingle(v);
            }

            private static void WriteString(List<byte> buf, string s)
            {
                var bytes = Encoding.ASCII.GetBytes(s);
                buf.AddRange(bytes);
                buf.Add(0);

                while (buf.Count % 4 != 0)
                    buf.Add(0);
            }

            private static void WriteInt(List<byte> buf, int v)
            {
                buf.Add((byte)((v >> 24) & 0xFF));
                buf.Add((byte)((v >> 16) & 0xFF));
                buf.Add((byte)((v >> 8) & 0xFF));
                buf.Add((byte)(v & 0xFF));
            }

            private static void WriteFloat(List<byte> buf, float f)
            {
                WriteInt(buf, BitConverter.SingleToInt32Bits(f));
            }
        }
    }
}
