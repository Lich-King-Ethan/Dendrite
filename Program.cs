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
        //  Ultra lightweight SlimeVR → PSMSx Remote Devices bridge
        //  (it do the beep boop)
        // ===================================================================

        // PORTS (HEY FUCKASS — STOP CHANGING THESE):
        //   SlimeVR OSC Out  → 127.0.0.1:29347
        //   Dendrite listens → 0.0.0.0:29347
        //   Dendrite → PSMSx Remote Devices (binary SlimeVR net protocol)
        //       → 192.168.0.243:6969

        private const int SlimePort = 29347;

        // PSMSx / VDM Remote Devices listener (your static IP)
        private const string PsmsIp = "192.168.0.243";
        private const int PsmsPort = 6969;

        private const string SteamVrAppKey = "dendrite.psmsx.bridge";

        private const bool DebugLogging = true;

        // log throttle: one message per tracker every 3 seconds
        private static readonly TimeSpan TrackerLogInterval = TimeSpan.FromSeconds(3);
        private static readonly DateTime[] LastTrackerLog = new DateTime[12];

        public static void Main()
        {
            Console.OutputEncoding = Encoding.UTF8;
            DrawHeader();

            TryRegisterWithSteamVrOnce();

            // init the 12 PSMSx fake remotes (each with its own source IP + MAC)
            PsmsRemote.Initialize();

            Console.WriteLine($"[Dendrite] Listening for SlimeVR OSC on 0.0.0.0:{SlimePort}");
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
            {
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

                        // Only care about /tracking/trackers/<id>/rotation
                        if (!msg.Address.StartsWith("/tracking/trackers/", StringComparison.Ordinal))
                            continue;

                        var parts = msg.Address.Split('/', StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length < 4)
                            continue;

                        string trackerIdRaw = parts[2];
                        string field = parts[3];

                        if (!field.Equals("rotation", StringComparison.OrdinalIgnoreCase))
                        {
                            // positions & anything else: fully ignored, no spam
                            continue;
                        }

                        if (!int.TryParse(trackerIdRaw, out int trackerId))
                            continue;

                        // T1..T12 only
                        if (trackerId < 1 || trackerId > 12)
                            continue;

                        int idx = trackerId - 1;

                        if (msg.Arguments.Count < 3)
                            continue;

                        float rx = msg.GetFloat(0);
                        float ry = msg.GetFloat(1);
                        float rz = msg.GetFloat(2);

                        bool logThis = DebugLogging && ShouldLogTracker(idx);

                        if (logThis)
                            Console.WriteLine($"[Dendrite] RX SlimeVR T{trackerId} → dev {idx}: ({rx:F3}, {ry:F3}, {rz:F3})");

                        // Send to PSMSx: each tracker gets its own "remote device"
                        // Each remote device has ONE sensor: sensorId = 0
                        PsmsRemote.SendRotation(idx, rx, ry, rz, logThis);
                    }

                    // If we got a packet but it didn’t parse into any OSC messages, dump a tiny preview
                    if (!anyMessage && DebugLogging)
                    {
                        DumpPacketPreview(data);
                    }
                }
            }
        }

        private static bool ShouldLogTracker(int idx)
        {
            if (idx < 0 || idx >= LastTrackerLog.Length)
                return false;

            var now = DateTime.UtcNow;
            var last = LastTrackerLog[idx];

            if (last == default || (now - last) >= TrackerLogInterval)
            {
                LastTrackerLog[idx] = now;
                return true;
            }

            return false;
        }

        // -------------------------------------------------------------------
        // SteamVR auto-registration (kept, harmless)
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

        private static void DumpPacketPreview(byte[] data)
        {
            try
            {
                int len = Math.Min(data.Length, 64);
                var sbHex = new StringBuilder();
                for (int i = 0; i < len; i++)
                    sbHex.Append(data[i].ToString("X2")).Append(' ');

                string ascii = Encoding.ASCII.GetString(data, 0, len).Replace("\0", "·");

                Console.WriteLine($"[Dendrite] Unparseable packet, length {data.Length} bytes");
                Console.WriteLine($"[Dendrite] Hex (first {len}): {sbHex}");
                Console.WriteLine($"[Dendrite] ASCII (first {len}): {ascii}");
            }
            catch { }
        }

        private static void DrawHeader()
        {
            Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
            Console.WriteLine("║                           DENDRITE                           ║");
            Console.WriteLine("║          SlimeVR → PSMSx Remote Devices bridge               ║");
            Console.WriteLine("║                        (it do the beep boop)                 ║");
            Console.WriteLine("╠══════════════════════════════════════════════════════════════╣");
            Console.WriteLine("║  PORTS (HEY FUCKASS — STOP CHANGING THESE):                  ║");
            Console.WriteLine($"║      SlimeVR OSC Out  → 127.0.0.1:{SlimePort,-5}                     ║");
            Console.WriteLine($"║      Dendrite listens → 0.0.0.0:{SlimePort,-5}                      ║");
            Console.WriteLine($"║      Dendrite → PSMSx → {PsmsIp}:{PsmsPort}                   ║");
            Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");
            Console.WriteLine();
        }

        // ===================================================================
        //  PSMSx Remote Devices sender
        //  12 fake boards: each its own local IP + MAC, sensorId=0
        // ===================================================================
        private static class PsmsRemote
        {
            private sealed class RemoteDevice
            {
                public int TrackerIndex;
                public string LocalIp = "";
                public byte[] Mac = new byte[6];
                public UdpClient? Client;
                public IPEndPoint? Endpoint;
                public ulong PacketNumber = 1;
                public bool HandshakeSent = false;
                public bool IsAlive = false;
            }

            // THESE MUST EXIST as IPv4 aliases on your NIC:
            // 192.168.0.201 .. 192.168.0.212
            private static readonly string[] LocalSourceIps =
            {
                "192.168.0.201",
                "192.168.0.202",
                "192.168.0.203",
                "192.168.0.204",
                "192.168.0.205",
                "192.168.0.206",
                "192.168.0.207",
                "192.168.0.208",
                "192.168.0.209",
                "192.168.0.210",
                "192.168.0.211",
                "192.168.0.212"
            };

            private static readonly RemoteDevice[] Devices = new RemoteDevice[12];
            private static readonly object LockObj = new object();

            public static void Initialize()
            {
                for (int i = 0; i < Devices.Length; i++)
                {
                    Devices[i] = new RemoteDevice
                    {
                        TrackerIndex = i,
                        LocalIp = LocalSourceIps[i],
                        Mac = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, (byte)(i + 1) },
                        PacketNumber = 1,
                        HandshakeSent = false,
                        IsAlive = false
                    };
                }

                int alive = 0;

                for (int i = 0; i < Devices.Length; i++)
                {
                    var dev = Devices[i];

                    try
                    {
                        // bind to that exact local IP (requires the alias to exist!)
                        var localEp = new IPEndPoint(IPAddress.Parse(dev.LocalIp), 0);
                        dev.Client = new UdpClient(localEp);
                        dev.Endpoint = new IPEndPoint(IPAddress.Parse(PsmsIp), PsmsPort);

                        int localPort = ((IPEndPoint)dev.Client.Client.LocalEndPoint!).Port;
                        string macStr = BitConverter.ToString(dev.Mac);

                        Console.WriteLine($"[Dendrite] PSMSx dev {i} MAC {macStr} bound {dev.LocalIp}:{localPort} -> {PsmsIp}:{PsmsPort}");
                        dev.IsAlive = true;
                        alive++;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[Dendrite] PSMSx dev {i} FAILED to bind local IP {dev.LocalIp}: {ex.Message}");
                        dev.IsAlive = false;
                    }
                }

                // Handshake all alive devices
                for (int i = 0; i < Devices.Length; i++)
                {
                    if (Devices[i].IsAlive)
                        SendHandshake(Devices[i]);
                }

                Console.WriteLine($"[Dendrite] PSMSx remotes ready: {alive}/12 bound. (Need IPv4 aliases for the missing ones)");
            }

            public static void SendRotation(int trackerIndex, float rxDeg, float ryDeg, float rzDeg, bool logThis)
            {
                if (trackerIndex < 0 || trackerIndex >= Devices.Length)
                    return;

                var dev = Devices[trackerIndex];
                if (!dev.IsAlive || dev.Client == null || dev.Endpoint == null)
                    return;

                if (!dev.HandshakeSent)
                    SendHandshake(dev);

                var q = EulerDegreesToQuaternion(rxDeg, ryDeg, rzDeg);

                byte[] packet;
                lock (LockObj)
                {
                    ulong pn = dev.PacketNumber++;
                    // ONE sensor per fake device: sensorId=0
                    packet = BuildRotationPacket(0, pn, q.x, q.y, q.z, q.w, 3);
                }

                try
                {
                    dev.Client.Send(packet, packet.Length, dev.Endpoint);

                    if (DebugLogging && logThis)
                    {
                        string macStr = BitConverter.ToString(dev.Mac);
                        Console.WriteLine($"[Dendrite] TX PSMSx MAC {macStr} (T{trackerIndex + 1}) q=({q.x:F3},{q.y:F3},{q.z:F3},{q.w:F3})");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[Dendrite] PSMSx send error (T{trackerIndex + 1}): {ex.Message}");
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

                    if (DebugLogging)
                    {
                        string macStr = BitConverter.ToString(dev.Mac);
                        Console.WriteLine($"[Dendrite] PSMSx handshake sent for MAC {macStr} (src {dev.LocalIp}).");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[Dendrite] PSMSx handshake error (src {dev.LocalIp}): {ex.Message}");
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

                // BOARD / IMU / MCU / reserved ints
                WriteInt32BE(bw, 1); // BOARD (pretend ESP32)
                WriteInt32BE(bw, 0); // IMU (unused by PSMSx)
                WriteInt32BE(bw, 2); // MCU (fake id)
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

                // MAC (6 bytes)
                if (mac.Length == 6)
                    bw.Write(mac);
                else
                    bw.Write(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01 });

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

                bw.Write(sensorId);       // sensor ID (always 0 per fake device)
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

            // Euler degrees → Quaternion (x,y,z,w), roll(X), pitch(Y), yaw(Z)
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
        //  Minimal OSC parser (bundle + basic types)
        // ===================================================================
        private sealed class OscMessage
        {
            public string Address { get; }
            public List<object> Arguments { get; } = new List<object>();

            private OscMessage(string address)
            {
                Address = address;
            }

            public static IEnumerable<OscMessage> ParsePacket(byte[] data)
            {
                if (data == null || data.Length < 4)
                    yield break;

                if (IsBundleHeader(data))
                {
                    int index = 0;
                    _ = ReadString(data, ref index); // "#bundle"
                    if (index + 8 > data.Length)
                        yield break;
                    index += 8; // timetag

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
                if (data.Length < 8) return false;
                return data[0] == (byte)'#' &&
                       data[1] == (byte)'b' &&
                       data[2] == (byte)'u' &&
                       data[3] == (byte)'n' &&
                       data[4] == (byte)'d' &&
                       data[5] == (byte)'l' &&
                       data[6] == (byte)'e' &&
                       data[7] == 0;
            }

            private static OscMessage? Parse(byte[] data)
            {
                int index = 0;
                try
                {
                    string address = ReadString(data, ref index);
                    if (string.IsNullOrEmpty(address))
                        return null;

                    string tags = ReadString(data, ref index);
                    if (string.IsNullOrEmpty(tags) || !tags.StartsWith(",", StringComparison.Ordinal))
                        return null;

                    var msg = new OscMessage(address);

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
                                return null; // unsupported type
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
        }
    }
}
