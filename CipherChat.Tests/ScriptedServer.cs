using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace CipherChat.Tests;

// A scripted TcpListener that plays the server side of one v5 connection for the client tests. It records every
// line it receives, answers PING, and otherwise does what the test tells it (Send, Intercept).
public sealed class ScriptedServer : IDisposable
{
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private TcpClient client;
    private StreamWriter writer;
    private readonly object writeLock = new();
    public readonly ConcurrentQueue<string> Received = new();
    public Func<string, bool> Intercept;   // return true if the line was handled

    public ScriptedServer() { listener.Start(); Port = ((IPEndPoint)listener.LocalEndpoint).Port; Task.Run(Loop); }
    public int Port { get; }

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
                if (line == "PING") Send("PONG");
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
