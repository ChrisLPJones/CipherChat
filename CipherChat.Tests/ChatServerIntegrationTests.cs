using System.Net;
using System.Net.Sockets;
using System.Text;
using CipherChatClient;
using CipherChatServer;
using Xunit;

namespace CipherChat.Tests;

public class ChatServerIntegrationTests : IDisposable
{
    private const string Key = "integration-test-key";

    private ChatServer server;

    public void Dispose()
    {
        server?.Stop();
        server?.Dispose();
    }

    [Fact]
    public void Server_BroadcastsMessages_SendsUserList_CleansUpOnDisconnect()
    {
        // Start the server on an ephemeral port and read back the actual port
        server = new ChatServer("localhost", 0);
        server.Start();
        int port = server.Port;

        // A connects and announces its encrypted username
        string aliceUser = AESecureString.EncryptString("alice is Connected", Key);
        using (var a = new TestClient(port))
        {
            a.SendLine(aliceUser);

            // A's initial user list contains only A's own entry
            Assert.Equal(aliceUser, a.ReadLine());

            // B connects and receives the current user list
            string bobUser = AESecureString.EncryptString("bob is Connected", Key);
            using var b = new TestClient(port);
            b.SendLine(bobUser);
            string bFirst = b.ReadLine();
            string bSecond = b.ReadLine();

            // (b) B's initial user list contains A's encrypted username line
            Assert.Contains(aliceUser, new[] { bFirst, bSecond });

            // (a) A broadcast message reaches B and decrypts to the original
            string message = "hello from alice";
            a.SendLine(AESecureString.EncryptString(message, Key));
            string received = b.ReadLine();
            Assert.Equal(message, AESecureString.DecryptCipher(received, Key));

            // (c) Disconnect cleanup: close A, then connect C
            a.Dispose();

            string carolUser = AESecureString.EncryptString("carol is Connected", Key);
            List<string> carolList = null;
            TestClient c = null;
            for (int attempt = 0; attempt < 20; attempt++)
            {
                c?.Dispose();
                c = new TestClient(port);
                c.SendLine(carolUser);

                // Read C's user list (it ends with C's own entry)
                carolList = new List<string>();
                for (int i = 0; i < 5; i++)
                {
                    string line = c.ReadLine();
                    if (line == null) break;
                    carolList.Add(line);
                    if (line == carolUser) break;
                }

                if (!carolList.Contains(aliceUser)) break;
                Thread.Sleep(100); // A's cleanup may not have run yet; retry
            }

            Assert.NotNull(carolList);
            Assert.DoesNotContain(aliceUser, carolList);
            Assert.Contains(bobUser, carolList);
            c?.Dispose();
        }
    }

    // Minimal raw-socket client speaking the newline-delimited Base64 protocol
    private sealed class TestClient : IDisposable
    {
        private readonly TcpClient tcp;
        private readonly StreamReader reader;

        public TestClient(int port)
        {
            tcp = new TcpClient();
            tcp.Connect(IPAddress.Loopback, port);
            tcp.ReceiveTimeout = 5000;
            reader = new StreamReader(tcp.GetStream());
        }

        public void SendLine(string line)
        {
            NetworkStream stream = tcp.GetStream();
            byte[] buffer = Encoding.ASCII.GetBytes(line + "\n");
            stream.Write(buffer, 0, buffer.Length);
            stream.Flush();
        }

        public string ReadLine() => reader.ReadLine();

        public void Dispose()
        {
            reader.Dispose();
            tcp.Close();
        }
    }
}
