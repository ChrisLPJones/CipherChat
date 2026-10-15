using Xunit;

namespace CipherChat.Tests;

public static class Wait
{
    public static void For(Func<bool> cond, string what = "condition", int ms = 8000)
    {
        DateTime end = DateTime.UtcNow.AddMilliseconds(ms);
        while (DateTime.UtcNow < end) { if (cond()) return; Thread.Sleep(20); }
        Assert.True(cond(), "Timed out waiting for " + what);
    }

    // Asserts that cond stays false for a short while (negative checks).
    public static void Never(Func<bool> cond, string what, int ms = 400)
    {
        DateTime end = DateTime.UtcNow.AddMilliseconds(ms);
        while (DateTime.UtcNow < end) { Assert.False(cond(), "Unexpected: " + what); Thread.Sleep(20); }
    }

}
