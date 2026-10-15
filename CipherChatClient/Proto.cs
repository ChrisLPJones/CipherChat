using System.Text;

namespace CipherChatClient;

// Byte-building helpers shared by the CPace glue, the key derivation and the session channel.
internal static class Proto
{
    // ASCII label followed by one 0x00 byte (domain separation).
    public static byte[] Label(string s)
    {
        byte[] b = new byte[s.Length + 1];
        Encoding.ASCII.GetBytes(s, 0, s.Length, b, 0);
        return b;
    }

    // 1-byte length followed by the ASCII bytes.
    public static byte[] Lp(string name)
    {
        if (name == null || name.Length == 0 || name.Length > 255) throw new ArgumentException("Invalid name.");
        byte[] b = new byte[1 + name.Length];
        b[0] = (byte)name.Length;
        Encoding.ASCII.GetBytes(name, 0, name.Length, b, 1);
        return b;
    }

    public static byte[] Concat(params byte[][] parts)
    {
        int len = 0;
        foreach (byte[] p in parts) len += p.Length;
        byte[] r = new byte[len];
        int o = 0;
        foreach (byte[] p in parts) { p.CopyTo(r, o); o += p.Length; }
        return r;
    }

    public static byte[] U64(long v)
    {
        byte[] b = new byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(b, v);
        return b;
    }

    public static byte[] U64(ulong v)
    {
        byte[] b = new byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(b, v);
        return b;
    }
}
