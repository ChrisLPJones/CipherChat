namespace CipherChatServer;

// Token bucket with an injectable clock (unix milliseconds). Thread-safe.
public sealed class RateLimiter
{
    private readonly double capacity;
    private readonly double refillPerMs;
    private readonly Func<long> clock;
    private readonly object gate = new();
    private double tokens;
    private long last;

    public RateLimiter(double capacity, double refillPerSecond, Func<long> clock)
    {
        this.capacity = capacity;
        refillPerMs = refillPerSecond / 1000.0;
        this.clock = clock;
        tokens = capacity;
        last = clock();
    }

    public bool TryTake()
    {
        lock (gate)
        {
            long now = clock();
            long elapsed = Math.Max(0, now - last); // a clock that jumps back never adds tokens
            last = now;
            tokens = Math.Min(capacity, tokens + elapsed * refillPerMs);
            if (tokens < 1) return false;
            tokens -= 1;
            return true;
        }
    }

    // True when the bucket is full again (the entry can be forgotten).
    public bool IsIdle
    {
        get
        {
            lock (gate)
            {
                long now = clock();
                return tokens + Math.Max(0, now - last) * refillPerMs >= capacity;
            }
        }
    }
}
