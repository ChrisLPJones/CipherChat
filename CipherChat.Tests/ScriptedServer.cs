using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace CipherChat.Tests;

// A scripted TcpListener that speaks just enough v4 to log a ChatSession in, then misbehaves on purpose
// (swapped keys, forged/replayed/reordered lines, fake GONE, floods). It also plays the "peer" using the
// library's own handshake code, so the session under test sees a fully valid counterpart.
public sealed class ScriptedServer : IDisposable
{
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly ConcurrentDictionary<string, byte[]> keys = new();
    private TcpClient client;
    private StreamWriter writer;
    private readonly object writeLock = new();
    public readonly ConcurrentQueue<string> Received = new();
    public string LoginReply = null;    // null = READY <user>; otherwise sent as is (e.g. "ERR nouser x")
    public Func<string, bool> Intercept; // return true if the line was handled
    public byte[] Challenge = RandomNumberGenerator.GetBytes(32);

    public ScriptedServer() { listener.Start(); Port = ((IPEndPoint)listener.LocalEndpoint).Port; Task.Run(Loop); }
    public int Port { get; }
    public void SetKey(string user, byte[] pub) => keys[user] = pub;

    public void Send(string line)
    {
        lock (writeLock) { writer.Write(line + "\n"); writer.Flush(); }
    }

    private async Task Loop()
    {
        try
        {
            client = await listener.AcceptTcpClientAsync();
            var reader = new StreamReader(client.GetStream(), Encoding.ASCII);
            writer = new StreamWriter(client.GetStream(), new ASCIIEncoding()) { NewLine = "\n" };
            while (true)
            {
                string line = await reader.ReadLineAsync();
                if (line == null) return;
                Received.Enqueue(line);
                if (Intercept != null && Intercept(line)) continue;
                string[] t = line.Split(' ');
                switch (t[0])
                {
                    case "HELLO": Send("WELCOME 4 " + Convert.ToBase64String(Challenge)); break;
                    case "LOGIN":
                    case "REGISTER": Send(LoginReply ?? "READY " + t[1]); break;
                    case "KEY":
                        if (keys.TryGetValue(t[1], out byte[] k)) Send($"KEY {t[1]} {Convert.ToBase64String(k)}");
                        else Send($"ERR nouser {t[1]}");
                        break;
                    case "PING": Send("PONG"); break;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or SocketException or NullReferenceException) { }
    }

    public string Wait(Func<string, bool> pred, int ms = 5000)
    {
        DateTime end = DateTime.UtcNow.AddMilliseconds(ms);
        while (DateTime.UtcNow < end)
        {
            string hit = Received.FirstOrDefault(pred);
            if (hit != null) return hit;
            Thread.Sleep(10);
        }
        return null;
    }

    public bool Saw(string prefix) => Received.Any(l => l.StartsWith(prefix));

    public void Dispose() { try { client?.Close(); } catch (Exception) { } listener.Stop(); }
}
