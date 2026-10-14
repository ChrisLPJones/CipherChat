namespace CipherChatClient;

public enum ChannelKind { Lobby, Room, Dm }

// Client-side state of one channel (tag + key). Keys stay in memory only.
public sealed class ChannelState
{
    public ChannelState(ChannelKind kind, string name, string displayName, string key, string tag)
    {
        Kind = kind;
        Name = name;
        DisplayName = displayName;
        Key = key;
        Tag = tag;
    }

    public ChannelKind Kind { get; }
    public string Name { get; }          // room name or normalized pair "a|b"
    public string DisplayName { get; }   // what the user sees: "general", "dm:bob"
    public string Key { get; }
    public string Tag { get; }

    public List<string> Messages { get; } = [];
    public Dictionary<int, string> Members { get; } = [];   // mid -> username ("?" if undecryptable)
    public long LastId { get; set; }
    public int Unread { get; set; }
    public bool RosterComplete { get; set; }
    public int WrongKeyCount { get; set; }
}
