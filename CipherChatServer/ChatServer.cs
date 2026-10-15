using System.Net;
using System.Net.Sockets;
using System.Text;

namespace CipherChatServer;

// Being rebuilt for protocol v5 (paired-code chat). For now: listener, connection caps and a read timeout;
// every connection gets "ERR version" for its first line and is closed. Logs nothing about clients.
public class ChatServer : IDisposable
{
    private const int WriteTimeoutMs = 5000;

    private readonly object sync = new();
    private readonly List<TcpClient> clients = [];
    private readonly Dictionary<string, int> perIp = [];
    private readonly ServerLimits limits;
    private readonly TcpListener listener;
    private readonly TaskCompletionSource<bool> stopped = new();
    private Task acceptTask;
    private int stopRequested;

    // The port the listener is actually bound to (useful when started on port 0)
    public int Port { get; private set; }

    // Completes when Stop() has finished shutting the server down
    public Task Stopped => stopped.Task;

    public ChatServer(string host, int port, ChatServerOptions options = null)
    {
        limits = (options ?? new ChatServerOptions()).Limits;
        IPAddress address = host == "localhost" ? IPAddress.Loopback : IPAddress.Parse(host);
        listener = new(address, port);
    }

    public void Start()
    {
        listener.Start();
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        acceptTask = Task.Run(AcceptLoop);
    }

    public void Stop()
    {
        if (Interlocked.Exchange(ref stopRequested, 1) == 1) return;
        listener.Stop();
        lock (sync)
        {
            foreach (var c in clients) { try { c.Close(); } catch (Exception) { } }
        }
        acceptTask?.Wait();
        stopped.TrySetResult(true);
    }

    public void Dispose() => Stop();

    private void AcceptLoop()
    {
        while (true)
        {
            TcpClient tcp;
            try { tcp = listener.AcceptTcpClient(); }
            catch (Exception) { break; } // listener stopped

            string ip = "?";
            try
            {
                IPAddress a = ((IPEndPoint)tcp.Client.RemoteEndPoint).Address;
                ip = (a.IsIPv4MappedToIPv6 ? a.MapToIPv4() : a).ToString();
            }
            catch (Exception) { }

            bool full;
            lock (sync)
            {
                perIp.TryGetValue(ip, out int n);
                full = clients.Count >= limits.MaxConnections || n >= limits.MaxConnectionsPerIp;
                if (!full) { clients.Add(tcp); perIp[ip] = n + 1; }
            }
            if (full) { _ = Task.Run(() => Reply(tcp, "ERR full")); continue; }
            _ = Task.Factory.StartNew(() => Handle(tcp, ip), TaskCreationOptions.LongRunning);
        }
    }

    private static void Reply(TcpClient tcp, string line)
    {
        try
        {
            tcp.GetStream().WriteTimeout = WriteTimeoutMs;
            byte[] b = Encoding.ASCII.GetBytes(line + "\n");
            tcp.GetStream().Write(b, 0, b.Length);
        }
        catch (Exception) { }
        finally { try { tcp.Close(); } catch (Exception) { } }
    }

    private void Handle(TcpClient tcp, string ip)
    {
        try
        {
            tcp.ReceiveTimeout = limits.ReadTimeoutMs;
            StreamReader reader = new(tcp.GetStream(), Encoding.ASCII);
            try { ProtocolLimits.ReadBoundedLine(reader, ProtocolLimits.MaxLineChars); }
            catch (Exception ex) when (ex is InvalidDataException or IOException or ObjectDisposedException) { }
            Reply(tcp, "ERR version");
        }
        finally
        {
            lock (sync)
            {
                if (clients.Remove(tcp) && perIp.TryGetValue(ip, out int n))
                {
                    if (n <= 1) perIp.Remove(ip); else perIp[ip] = n - 1;
                }
            }
        }
    }
}
