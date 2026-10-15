using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace CipherChatClient;

// Every status except Ok means the message was rejected and the chat should end (strict order, no gaps).
public enum OpenStatus { Ok, Malformed, UnknownSession, Replay, OutOfOrder, AuthFailed, BadPlaintext, Exhausted }
public enum MessageKind : byte { Text = 0x01, EndOfSession = 0x02 }

public sealed class OpenResult
{
    public OpenStatus Status { get; init; }
    public MessageKind Kind { get; init; }
    public string Text { get; init; }
}

// One established 1:1 session (protocol v5). Per direction a symmetric hash chain gives a fresh key per message:
//   mk_n = HMAC(ck_n, 0x01), ck_{n+1} = HMAC(ck_n, 0x02); ck_n and mk_n are zeroed after use.
// MSG bytes: ver(1)=5 | type(1)=0x10 | sid(16) | n(8) | ciphertext(256*k) | gcmTag(16).
// Nonce = 4 zero bytes || n (a key is used for exactly one message). AAD = the 26-byte header.
// Strict order: message n must be exactly the next expected number; anything else is rejected.
// Plaintext = kind(1) || len(2) || UTF-8 text || zero padding to a multiple of 256 bytes.
public sealed class SecureChannel : IDisposable
{
    public const byte Version = 0x05;
    public const byte TypeMsg = 0x10;
    public const int HeaderBytes = 26;
    public const int TagBytes = 16;
    public const int MaxMessages = 100_000;
    private const int MaxBlocks = 24;

    private readonly object gate = new();
    private readonly byte[] sid;
    private byte[] sendCk;
    private byte[] recvCk;
    private ulong sendN;
    private ulong recvN;
    private bool disposed;

    // Ownership of the chain keys passes to the channel (it zeroes them).
    public SecureChannel(byte[] sid, byte[] sendChainKey, byte[] recvChainKey)
    {
        if (sid == null || sid.Length != 16 || sendChainKey.Length != 32 || recvChainKey.Length != 32)
            throw new ArgumentException("Invalid channel parameters.");
        this.sid = (byte[])sid.Clone();
        sendCk = sendChainKey;
        recvCk = recvChainKey;
    }

    public byte[] SessionId => (byte[])sid.Clone();
    public ulong SentCount { get { lock (gate) return sendN; } }
    public ulong ReceivedCount { get { lock (gate) return recvN; } }

    // Test hooks: the live chain key arrays (to prove old keys are zeroed in place).
    internal byte[] SendChainKeyRef { get { lock (gate) return sendCk; } }
    internal byte[] RecvChainKeyRef { get { lock (gate) return recvCk; } }

    internal static byte[] MessageKey(byte[] ck) => HMACSHA256.HashData(ck, new byte[] { 0x01 });
    internal static byte[] NextChainKey(byte[] ck) => HMACSHA256.HashData(ck, new byte[] { 0x02 });

    public static int PaddedLength(int textBytes) => (3 + textBytes + (ProtocolLimits.PadBlock - 1)) / ProtocolLimits.PadBlock * ProtocolLimits.PadBlock;

    public byte[] SealText(string text)
    {
        byte[] utf8 = new UTF8Encoding(false, true).GetBytes(text ?? "");
        if (utf8.Length > ProtocolLimits.MaxTextBytes) throw new ArgumentException("The message is too long.");
        return Seal(MessageKind.Text, utf8);
    }

    public byte[] SealEnd() => Seal(MessageKind.EndOfSession, Array.Empty<byte>());

    private byte[] Seal(MessageKind kind, byte[] utf8)
    {
        lock (gate)
        {
            if (disposed) throw new ObjectDisposedException(nameof(SecureChannel));
            if (sendN >= MaxMessages) throw new InvalidOperationException("The session is exhausted.");
            byte[] pt = new byte[PaddedLength(utf8.Length)];
            pt[0] = (byte)kind;
            BinaryPrimitives.WriteUInt16BigEndian(pt.AsSpan(1, 2), (ushort)utf8.Length);
            utf8.CopyTo(pt, 3);

            byte[] header = Header(sendN);
            byte[] aad = header;
            byte[] mk = MessageKey(sendCk);
            byte[] nextCk = NextChainKey(sendCk);
            byte[] msg = new byte[HeaderBytes + pt.Length + TagBytes];
            try
            {
                header.CopyTo(msg, 0);
                using AesGcm gcm = new(mk, TagBytes);
                gcm.Encrypt(Nonce(sendN), pt, msg.AsSpan(HeaderBytes, pt.Length), msg.AsSpan(HeaderBytes + pt.Length, TagBytes), aad);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(mk);
                CryptographicOperations.ZeroMemory(pt);
                CryptographicOperations.ZeroMemory(sendCk);
            }
            sendCk = nextCk;
            sendN++;
            return msg;
        }
    }

    public OpenResult Open(byte[] msg)
    {
        lock (gate)
        {
            if (disposed) throw new ObjectDisposedException(nameof(SecureChannel));
            if (msg == null || msg.Length < HeaderBytes + ProtocolLimits.PadBlock + TagBytes
                || (msg.Length - HeaderBytes - TagBytes) % ProtocolLimits.PadBlock != 0
                || (msg.Length - HeaderBytes - TagBytes) / ProtocolLimits.PadBlock > MaxBlocks
                || msg[0] != Version || msg[1] != TypeMsg)
                return Fail(OpenStatus.Malformed);
            if (!CryptographicOperations.FixedTimeEquals(msg.AsSpan(2, 16), sid)) return Fail(OpenStatus.UnknownSession);

            ulong n = BinaryPrimitives.ReadUInt64BigEndian(msg.AsSpan(18, 8));
            if (n < recvN) return Fail(OpenStatus.Replay);
            if (n > recvN) return Fail(OpenStatus.OutOfOrder);
            if (n >= MaxMessages) return Fail(OpenStatus.Exhausted);

            // Derive from a copy of the chain; commit only if GCM verifies.
            byte[] ck = (byte[])recvCk.Clone();
            byte[] nextCk = null;
            byte[] mk = null;
            byte[] pt = null;
            try
            {
                mk = MessageKey(ck);
                nextCk = NextChainKey(ck);
                int ctLen = msg.Length - HeaderBytes - TagBytes;
                pt = new byte[ctLen];
                byte[] aad = msg.AsSpan(0, HeaderBytes).ToArray();
                try
                {
                    using AesGcm gcm = new(mk, TagBytes);
                    gcm.Decrypt(Nonce(n), msg.AsSpan(HeaderBytes, ctLen), msg.AsSpan(HeaderBytes + ctLen, TagBytes), pt, aad);
                }
                catch (CryptographicException)
                {
                    CryptographicOperations.ZeroMemory(nextCk);
                    nextCk = null;
                    return Fail(OpenStatus.AuthFailed);
                }

                // Authenticated: consume the message number even if the plaintext is malformed.
                CryptographicOperations.ZeroMemory(recvCk);
                recvCk = nextCk;
                nextCk = null;
                recvN = n + 1;
                return Interpret(pt);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(ck);
                if (mk != null) CryptographicOperations.ZeroMemory(mk);
                if (nextCk != null) CryptographicOperations.ZeroMemory(nextCk);
                if (pt != null) CryptographicOperations.ZeroMemory(pt);
            }
        }
    }

    private static OpenResult Fail(OpenStatus s) => new() { Status = s };

    private static OpenResult Interpret(byte[] pt)
    {
        MessageKind kind = (MessageKind)pt[0];
        int len = BinaryPrimitives.ReadUInt16BigEndian(pt.AsSpan(1, 2));
        if ((kind != MessageKind.Text && kind != MessageKind.EndOfSession) || len > ProtocolLimits.MaxTextBytes
            || 3 + len > pt.Length || (kind == MessageKind.EndOfSession && len != 0)
            || pt.Length != PaddedLength(len))
            return Fail(OpenStatus.BadPlaintext);
        for (int i = 3 + len; i < pt.Length; i++)
            if (pt[i] != 0) return Fail(OpenStatus.BadPlaintext);
        string text = "";
        if (kind == MessageKind.Text)
        {
            try { text = new UTF8Encoding(false, true).GetString(pt, 3, len); }
            catch (ArgumentException) { return Fail(OpenStatus.BadPlaintext); }
        }
        return new OpenResult { Status = OpenStatus.Ok, Kind = kind, Text = text };
    }

    private byte[] Header(ulong n)
    {
        byte[] h = new byte[HeaderBytes];
        h[0] = Version;
        h[1] = TypeMsg;
        sid.CopyTo(h, 2);
        BinaryPrimitives.WriteUInt64BigEndian(h.AsSpan(18, 8), n);
        return h;
    }

    private static byte[] Nonce(ulong n)
    {
        byte[] nonce = new byte[12];
        BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(4, 8), n);
        return nonce;
    }

    public void Dispose()
    {
        lock (gate)
        {
            if (disposed) return;
            disposed = true;
            CryptographicOperations.ZeroMemory(sendCk);
            CryptographicOperations.ZeroMemory(recvCk);
        }
    }
}
