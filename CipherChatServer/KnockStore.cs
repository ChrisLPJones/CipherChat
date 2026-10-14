namespace CipherChatServer;

public enum KnockResult { Stored, RecipientFull, TotalFull, SenderLimit }

// Offline "knocks": signed blobs the server cannot read or forge, kept in memory only.
// Newest per (sender, recipient); capped per recipient and in total; expire after a TTL;
// delivered after the recipient's next login, then deleted. Thread-safe.
public sealed class KnockStore
{
    private readonly ServerLimits limits;
    private readonly Func<long> clock;
    private readonly object gate = new();
    private readonly Dictionary<string, Dictionary<string, Entry>> byRecipient = new();
    private readonly Dictionary<string, List<long>> senderTimes = new();
    private int total;

    private sealed record Entry(string Blob, long At);

    public KnockStore(ServerLimits limits, Func<long> clock) { this.limits = limits; this.clock = clock; }

    public int Count { get { lock (gate) return total; } }

    public KnockResult Add(string sender, string recipient, string blob)
    {
        lock (gate)
        {
            long now = clock();
            PurgeExpired(now);

            if (!senderTimes.TryGetValue(sender, out List<long> times)) senderTimes[sender] = times = new();
            times.RemoveAll(t => now - t >= 3600_000);
            if (times.Count >= limits.KnockMaxPerSenderPerHour) return KnockResult.SenderLimit;

            if (!byRecipient.TryGetValue(recipient, out Dictionary<string, Entry> box)) byRecipient[recipient] = box = new();
            bool replacing = box.ContainsKey(sender);
            if (!replacing)
            {
                if (box.Count >= limits.KnockMaxPerRecipient) return KnockResult.RecipientFull;
                if (total >= limits.KnockMaxTotal) return KnockResult.TotalFull;
                total++;
            }
            box[sender] = new Entry(blob, now);
            times.Add(now);
            return KnockResult.Stored;
        }
    }

    // Removes and returns the recipient's unexpired knocks, oldest first.
    public List<(string Sender, string Blob)> Take(string recipient)
    {
        lock (gate)
        {
            long now = clock();
            PurgeExpired(now);
            List<(string, string)> result = new();
            if (byRecipient.Remove(recipient, out Dictionary<string, Entry> box))
            {
                total -= box.Count;
                foreach (var kv in box.OrderBy(kv => kv.Value.At)) result.Add((kv.Key, kv.Value.Blob));
            }
            return result;
        }
    }

    private void PurgeExpired(long now)
    {
        foreach (string r in byRecipient.Keys.ToList())
        {
            Dictionary<string, Entry> box = byRecipient[r];
            foreach (string s in box.Where(kv => now - kv.Value.At >= limits.KnockTtlMs).Select(kv => kv.Key).ToList())
            {
                box.Remove(s);
                total--;
            }
            if (box.Count == 0) byRecipient.Remove(r);
        }
        foreach (string s in senderTimes.Where(kv => kv.Value.All(t => now - t >= 3600_000)).Select(kv => kv.Key).ToList())
            senderTimes.Remove(s);
    }
}
