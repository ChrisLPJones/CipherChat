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

    // History replay state; touched on the receive thread only (except HistExplicit, set by /history).
    public HashSet<long> SeenIds { get; } = [];                 // message ids already shown (live, own ACKed or replayed)
    public List<ServerEvent> HistBatch { get; } = [];           // HIST records received since the last HISTEND
    public List<ServerEvent> HistLive { get; } = [];            // live MSGs held back while the join replay is outstanding
    public bool HistJoinPending { get; set; }                   // join replay requested, HISTEND not yet seen
    public bool AloneHintPending { get; set; }                  // the "alone" hint waits for the replay result
    public volatile bool HistExplicit;                          // the user typed /history
}
