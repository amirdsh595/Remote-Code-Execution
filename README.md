Remote Code Execution Tool
A secure, educational tool designed to demonstrate remote command execution, file transfer, screenshot capture, and keylogging over a TCP connection using SSL/TLS encryption. This project is intended for learning purposes, such as understanding network programming, secure communication, and system administration in a controlled environment.
Features

Secure Communication: Establishes an SSL/TLS-encrypted connection between client and server for secure data transfer.
Command Execution: Allows the server to send shell commands to the client for execution (e.g., dir, whoami).
File Transfer: Supports chunked file uploads and downloads between client and server.
Screenshot Capture: Enables the server to request and receive screenshots from the client.
Keylogging: Logs keystrokes on the client with timestamps, optionally sending them to the server in real-time.
Stealth Mode: Client runs without a visible console window for demonstration purposes.
Heartbeat Mechanism: Client sends periodic heartbeats to maintain connection with the server.
Logging: Server logs all commands and results to a file for auditing.

Prerequisites

.NET 8 SDK: Required to build and run both client and server.
Operating System: Windows (client uses System.Windows.Forms for keylogging and screenshots).
SSL Certificate: A server.pfx certificate file for the server (generate using OpenSSL or similar tools).
Dependencies (Client):
System.Drawing.Common NuGet package (dotnet add package System.Drawing.Common --version 8.0.0).
System.Windows.Forms assembly (included in .NET 8 Windows projects).



Setup Instructions

Clone the Repository:
git clone https://github.com/amirdsh595/Remote-Code-Execution.git
cd Remote-Code-Execution


Generate SSL Certificate (for Server):

Create a self-signed certificate using OpenSSL:openssl genrsa -out private.key 2048
openssl req -new -key private.key -out cert.csr
openssl x509 -req -days 365 -in cert.csr -signkey private.key -out server.crt
openssl pkcs12 -export -out server.pfx -inkey private.key -in server.crt


Place server.pfx in the server project directory and update CertPassword in RemoteCodeExecutionServer.cs.


Configure the Client:

Update ServerIP in RemoteCodeExecutionClient.cs to match your server’s IP address.
Ensure the client project references System.Windows.Forms and System.Drawing.Common.


Build and Run:

Build both projects:dotnet build RCE-Server
dotnet build RCE-Client


Run the server first:dotnet run --project RCE-Server


Run the client:dotnet run --project RCE-Client




Usage:

Server: Enter commands like dir, upload <path>, download <path>, screenshot, /keylog, /exit, or /exit -f.
Client: Automatically connects, authenticates, and executes commands from the server.
Keylogs are saved to keylog.txt on the client with timestamps.



Project Structure

RCE-Server/: Server application for sending commands and receiving results.
RCE-Client/: Client application for executing commands and sending data.
LICENSE: MIT License file.
README.md: Project documentation.

Disclaimer
English:This tool is intended for educational and testing purposes only. Any misuse or illegal activities conducted with this tool are the sole responsibility of the user. The creator does not endorse or support any illegal activities and is not liable for any damages or consequences resulting from the use of this tool. Users are advised to seek legal counsel if they are unsure about the legality of using this tool in their jurisdiction. Always obtain explicit permission before running the client on any device.

License
This project is licensed under the MIT License. See the LICENSE file for details.
Contributing
Contributions are welcome! Please read the CONTRIBUTING.md file (if available) for guidelines. Ensure all contributions align with the project’s educational purpose and ethical standards.
Contact
For questions or feedback, please open an issue on GitHub or contact [your email or preferred contact method, if desired].

Note: This project is for educational purposes. Use responsibly and ethically.
