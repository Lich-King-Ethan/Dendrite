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
        // ================================================================
        // DENDRITE
        // SlimeVR OSC -> PSMSx/VDM Remote Devices
        // (it do the beep boop)
        // ================================================================

        // PORTS (HEY FUCKASS — STOP CHANGING THESE):
        private const int SlimeOscListenPort = 29347;      // SlimeVR OSC Out -> 127.0.0.1:29347
        private const string PsmsRemoteIp = "192.168.0.243"; // your static LAN IP
        private const int PsmsRemotePort = 6969;           // VDM Remote Devices port

        private const string SteamVrAppKey = "dendrite.psmsx.bridge";

        private const bool DebugLogging = true;
        private static readonly TimeSpan LogInterval = TimeSpan.FromSeconds(3);
        private static readonly Dictionary<int, DateTime> LastLogUtcByTrackerId = new();

        private static readonly TrackerMacMap MacMap = new TrackerMacMap(Path.Combine(AppContext.BaseDirectory, "dendrite_map.txt"));

        // trackerId (1..N from Slime) -> RemoteDevice
        private static readonly Dictionary<int, RemoteDevice> DevicesByTrackerId = new();

        public static void Main()
        {
            Console.OutputEncoding = Encoding.UTF8;
            DrawHeader();

            TryRegisterWithSteamVrOnce();

            Console.WriteLine($"[Dendrite] Listening for SlimeVR OSC on 0.0.0.0:{SlimeOscListenPort}");
            Console.WriteLine($"[Dendrite] Forwarding to PSMSx Remote Devices at {PsmsRemoteIp}:{PsmsRemotePort}");
            Console.WriteLine("[Dendrite] Dynamic device mode: only creates devices for trackers it actually sees.");
            Console.WriteLine("[Dendrite] Rotation-only relay. Ctrl+C to stop.\n");
            Console.WriteLine($"[Dendrite] If you see NO 'RX' logs below, SlimeVR is not hitting port {SlimeOscListenPort}.");
            Console.WriteLine($"[Dendrite] Check SlimeVR OSC settings: IP 127.0.0.1, port {SlimeOscListenPort}.\n");

            UdpClient oscClient;
            try
            {
                oscClient = new UdpClient(SlimeOscListenPort);
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AddressAlreadyInUse)
            {
                Console.WriteLine($"\n[Dendrite] ERROR: Could not bind to UDP port {SlimeOscListenPort} (already in use).");
                PrintPortUsageInfo(SlimeOscListenPort);
                Console.Write("\nPress Enter to exit...");
                Console.ReadLine();
                return;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n[Dendrite] ERROR binding OSC UDP port: {ex.Message}");
                Console.Write("\nPress Enter to exit...");
                Console.ReadLine();
                return;
            }

            using (oscClient)
            {
                while (true)
                {
                    IPEndPoint sender = new IPEndPoint(IPAddress.Any, 0);
                    byte[] packet;

                    try
                    {
                        packet = oscClient.Receive(ref sender);
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

                    bool parsedAny = false;

                    foreach (var msg in OscMessage.ParsePacket(packet))
                    {
                        parsedAny = true;

                        // Only care about /tracking/trackers/<id>/rotation
                        if (!msg.Address.StartsWith("/tracking/trackers/", StringComparison.Ordinal))
                            continue;

                        var parts = msg.Address.Split('/', StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length < 4)
                            continue;

                        string trackerIdRaw = parts[2];
                        string field = parts[3];

                        if (!field.Equals("rotation", StringComparison.OrdinalIgnoreCase))
                            continue; // ignore everything else silently

                        if (!int.TryParse(trackerIdRaw, out int trackerId))
                            continue;

                        if (msg.Arguments.Count < 3)
                            continue;

                        float rx = msg.GetFloat(0);
                        float ry = msg.GetFloat(1);
                        float rz = msg.GetFloat(2);

                        bool logThis = DebugLogging && ShouldLog(trackerId);

                        if (logThis)
                            Console.WriteLine($"[Dendrite] RX SlimeVR T{trackerId} -> ({rx:F3}, {ry:F3}, {rz:F3})");

                        var dev = GetOrCreateDevice(trackerId);
                        dev.SendRotation(rx, ry, rz, logThis);
                    }

                    if (!parsedAny && DebugLogging)
                    {
                        DumpPacketPreview(packet);
                    }
                }
            }
        }

        private static bool ShouldLog(int trackerId)
        {
            var now = DateTime.UtcNow;
            if (!LastLogUtcByTrackerId.TryGetValue(trackerId, out var last) || (now - last) >= LogInterval)
            {
                LastLogUtcByTrackerId[trackerId] = now;
                return true;
            }
            return false;
        }

        private static RemoteDevice GetOrCreateDevice(int trackerId)
        {
            if (DevicesByTrackerId.TryGetValue(trackerId, out var existing))
                return existing;

            byte[] mac = MacMap.GetOrAssignMac(trackerId);
            var dev = new RemoteDevice(trackerId, mac, PsmsRemoteIp, PsmsRemotePort);

            DevicesByTrackerId[trackerId] = dev;

            string macStr = BitConverter.ToString(mac);
            Console.WriteLine($"[Dendrite] NEW DEVICE: T{trackerId} -> MAC {macStr} (created on first rotation)");
            dev.SendHandshake(); // send immediately

            return dev;
        }

        // ================================================================
        // Remote device (PSMSx/VDM Remote Devices protocol)
        // ================================================================
        private sealed class RemoteDevice
        {
            private readonly int _trackerId;
            private readonly byte[] _mac;
            private readonly IPEndPoint _dest;
            private readonly UdpClient _udp;

            private ulong _packetNumber = 1;
            private bool _handshakeSent = false;
            private DateTime _lastHandshakeUtc = DateTime.MinValue;

            // Resend handshake occasionally so VDM re-discovers if it launched after Dendrite
            private static readonly TimeSpan HandshakeResendInterval = TimeSpan.FromSeconds(2);

            public RemoteDevice(int trackerId, byte[] mac, string destIp, int destPort)
            {
                _trackerId = trackerId;
                _mac = mac;
                _dest = new IPEndPoint(IPAddress.Parse(destIp), destPort);

                // Bind to any local endpoint (no IP alias required)
                _udp = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
            }

            public void SendHandshake()
            {
                byte[] packet = BuildHandshakePacket(0, _mac);
                try
                {
                    _udp.Send(packet, packet.Length, _dest);
                    _handshakeSent = true;
                    _lastHandshakeUtc = DateTime.UtcNow;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[Dendrite] Handshake send error (T{_trackerId}): {ex.Message}");
                }
            }

            public void SendRotation(float rxDeg, float ryDeg, float rzDeg, bool logThis)
            {
                var now = DateTime.UtcNow;

                if (!_handshakeSent || (now - _lastHandshakeUtc) >= HandshakeResendInterval)
                {
                    SendHandshake();
                }

                var q = EulerDegreesToQuaternion(rxDeg, ryDeg, rzDeg);

                ulong pn = _packetNumber++;
                byte[] packet = BuildRotationPacket(sensorId: 0, packetNumber: pn, qx: q.x, qy: q.y, qz: q.z, qw: q.w, accuracy: 3);

                try
                {
                    _udp.Send(packet, packet.Length, _dest);

                    if (DebugLogging && logThis)
                    {
                        string macStr = BitConverter.ToString(_mac);
                        Console.WriteLine($"[Dendrite] TX PSMSx MAC {macStr} (T{_trackerId}) q=({q.x:F3},{q.y:F3},{q.z:F3},{q.w:F3})");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[Dendrite] Send error (T{_trackerId}): {ex.Message}");
                }
            }

            private static byte[] BuildHandshakePacket(ulong packetNumber, byte[] mac)
            {
                using var ms = new MemoryStream();
                using var bw = new BinaryWriter(ms);

                // PACKET_HANDSHAKE = 3
                bw.Write((byte)0);
                bw.Write((byte)0);
                bw.Write((byte)0);
                bw.Write((byte)3);

                WriteUInt64BE(bw, packetNumber);

                // board / imu / mcu / reserved
                WriteInt32BE(bw, 1);
                WriteInt32BE(bw, 0);
                WriteInt32BE(bw, 2);
                WriteInt32BE(bw, 0);
                WriteInt32BE(bw, 0);
                WriteInt32BE(bw, 0);

                // build num
                WriteInt32BE(bw, 1);

                string version = "Dendrite-Bridge";
                if (version.Length > 255) version = version.Substring(0, 255);
                bw.Write((byte)version.Length);
                bw.Write(Encoding.ASCII.GetBytes(version));

                // MAC 6 bytes
                bw.Write(mac, 0, 6);

                return ms.ToArray();
            }

            private static byte[] BuildRotationPacket(byte sensorId, ulong packetNumber, float qx, float qy, float qz, float qw, byte accuracy)
            {
                using var ms = new MemoryStream();
                using var bw = new BinaryWriter(ms);

                // PACKET_ROTATION_DATA = 17
                bw.Write((byte)0);
                bw.Write((byte)0);
                bw.Write((byte)0);
                bw.Write((byte)17);

                WriteUInt64BE(bw, packetNumber);

                bw.Write(sensorId);
                bw.Write((byte)1); // datatype normal

                WriteFloatBE(bw, qx);
                WriteFloatBE(bw, qy);
                WriteFloatBE(bw, qz);
                WriteFloatBE(bw, qw);

                bw.Write(accuracy);

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
                if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
                bw.Write(bytes);
            }

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

        // ================================================================
        // Stable trackerId -> MAC mapping (persisted)
        // ================================================================
        private sealed class TrackerMacMap
        {
            private readonly string _path;
            private readonly Dictionary<int, byte[]> _map = new();
            private int _nextSuffix = 1;

            public TrackerMacMap(string path)
            {
                _path = path;
                Load();
            }

            public byte[] GetOrAssignMac(int trackerId)
            {
                if (_map.TryGetValue(trackerId, out var mac))
                    return mac;

                // assign new
                int suffix = _nextSuffix++;
                mac = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, (byte)(suffix & 0xFF) };
                _map[trackerId] = mac;
                Save();
                return mac;
            }

            private void Load()
            {
                try
                {
                    if (!File.Exists(_path))
                        return;

                    foreach (var raw in File.ReadAllLines(_path))
                    {
                        var line = raw.Trim();
                        if (line.Length == 0 || line.StartsWith("#")) continue;

                        var parts = line.Split('=', 2);
                        if (parts.Length != 2) continue;

                        if (!int.TryParse(parts[0].Trim(), out int trackerId))
                            continue;

                        var macStr = parts[1].Trim();
                        var bytes = ParseMac(macStr);
                        if (bytes == null) continue;

                        _map[trackerId] = bytes;

                        // keep nextSuffix monotonic (based on last byte)
                        int suffix = bytes[5];
                        if (suffix >= _nextSuffix) _nextSuffix = suffix + 1;
                    }
                }
                catch
                {
                    // best effort, no drama
                }
            }

            private void Save()
            {
                try
                {
                    var sb = new StringBuilder();
                    sb.AppendLine("# dendrite_map.txt");
                    sb.AppendLine("# trackerId=MAC (hex with dashes)");
                    foreach (var kv in _map)
                    {
                        sb.Append(kv.Key).Append('=').Append(BitConverter.ToString(kv.Value)).AppendLine();
                    }
                    File.WriteAllText(_path, sb.ToString());
                }
                catch
                {
                    // best effort
                }
            }

            private static byte[]? ParseMac(string s)
            {
                try
                {
                    var parts = s.Split('-', ':');
                    if (parts.Length != 6) return null;

                    var bytes = new byte[6];
                    for (int i = 0; i < 6; i++)
                        bytes[i] = Convert.ToByte(parts[i], 16);

                    return bytes;
                }
                catch
                {
                    return null;
                }
            }
        }

        // ================================================================
        // Minimal OSC parsing (bundle + i/f/s)
        // ================================================================
        private sealed class OscMessage
        {
            public string Address { get; }
            public List<object> Arguments { get; } = new();

            private OscMessage(string address) => Address = address;

            public static IEnumerable<OscMessage> ParsePacket(byte[] data)
            {
                if (data == null || data.Length < 4) yield break;

                if (IsBundleHeader(data))
                {
                    int idx = 0;
                    _ = ReadString(data, ref idx); // "#bundle"
                    if (idx + 8 > data.Length) yield break;
                    idx += 8; // timetag

                    while (idx + 4 <= data.Length)
                    {
                        int size = ReadInt(data, ref idx);
                        if (size <= 0 || idx + size > data.Length) break;

                        var msgBytes = new byte[size];
                        Buffer.BlockCopy(data, idx, msgBytes, 0, size);
                        idx += size;

                        var msg = Parse(msgBytes);
                        if (msg != null) yield return msg;
                    }
                }
                else
                {
                    var msg = Parse(data);
                    if (msg != null) yield return msg;
                }
            }

            private static bool IsBundleHeader(byte[] data)
            {
                if (data.Length < 8) return false;
                return data[0] == (byte)'#' && data[1] == (byte)'b' && data[2] == (byte)'u' && data[3] == (byte)'n' &&
                       data[4] == (byte)'d' && data[5] == (byte)'l' && data[6] == (byte)'e' && data[7] == 0;
            }

            private static OscMessage? Parse(byte[] data)
            {
                int idx = 0;
                try
                {
                    string address = ReadString(data, ref idx);
                    if (string.IsNullOrEmpty(address)) return null;

                    string tags = ReadString(data, ref idx);
                    if (string.IsNullOrEmpty(tags) || !tags.StartsWith(",", StringComparison.Ordinal)) return null;

                    var msg = new OscMessage(address);

                    for (int i = 1; i < tags.Length; i++)
                    {
                        char t = tags[i];
                        switch (t)
                        {
                            case 'i': msg.Arguments.Add(ReadInt(data, ref idx)); break;
                            case 'f': msg.Arguments.Add(ReadFloat(data, ref idx)); break;
                            case 's': msg.Arguments.Add(ReadString(data, ref idx)); break;
                            default: return null;
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
                if (index < 0 || index >= Arguments.Count) return 0f;
                return Arguments[index] switch { float f => f, int i => i, _ => 0f };
            }

            private static string ReadString(byte[] data, ref int idx)
            {
                int start = idx;
                while (idx < data.Length && data[idx] != 0) idx++;
                string s = Encoding.ASCII.GetString(data, start, idx - start);
                idx++; // NUL
                while (idx % 4 != 0 && idx < data.Length) idx++;
                return s;
            }

            private static int ReadInt(byte[] data, ref int idx)
            {
                if (idx + 4 > data.Length) throw new IndexOutOfRangeException();
                int v = (data[idx] << 24) | (data[idx + 1] << 16) | (data[idx + 2] << 8) | data[idx + 3];
                idx += 4;
                return v;
            }

            private static float ReadFloat(byte[] data, ref int idx)
            {
                int v = ReadInt(data, ref idx);
                return BitConverter.Int32BitsToSingle(v);
            }
        }

        // ================================================================
        // SteamVR registration (kept, harmless)
        // ================================================================
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
            foreach (var p in paths) if (File.Exists(p)) return p;
            return null;
        }

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
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var proc = Process.Start(psi);
                if (proc == null) return;

                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(2000);

                var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                var pids = new HashSet<string>();

                foreach (var line in lines)
                {
                    if (!line.Contains($":{port}")) continue;
                    var parts = line.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 5) continue;
                    pids.Add(parts[^1]);
                }

                if (pids.Count == 0)
                {
                    Console.WriteLine($"[Dendrite] netstat found nothing using UDP {port}.");
                    return;
                }

                Console.WriteLine($"[Dendrite] PIDs using UDP {port}: {string.Join(", ", pids)}");
            }
            catch { }
        }

        private static void DumpPacketPreview(byte[] data)
        {
            try
            {
                int len = Math.Min(data.Length, 64);
                var sb = new StringBuilder();
                for (int i = 0; i < len; i++) sb.Append(data[i].ToString("X2")).Append(' ');
                string ascii = Encoding.ASCII.GetString(data, 0, len).Replace("\0", "·");
                Console.WriteLine($"[Dendrite] Unparseable packet, len={data.Length}");
                Console.WriteLine($"[Dendrite] Hex(first {len}): {sb}");
                Console.WriteLine($"[Dendrite] ASCII(first {len}): {ascii}");
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
            Console.WriteLine($"║      SlimeVR OSC Out  → 127.0.0.1:{SlimeOscListenPort,-5}                     ║");
            Console.WriteLine($"║      Dendrite listens → 0.0.0.0:{SlimeOscListenPort,-5}                      ║");
            Console.WriteLine($"║      Dendrite → PSMSx → {PsmsRemoteIp}:{PsmsRemotePort}                   ║");
            Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");
            Console.WriteLine();
        }
    }
}
