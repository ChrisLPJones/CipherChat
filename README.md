# CipherChat

CipherChat is a small console chat for **two users**. You make up a **secret key** together, give it to each other
in person (or over a channel you trust), and both type it into the client. The server only pairs the two of you and
relays bytes it cannot read. Everything you write is end-to-end encrypted, and the client exits when the chat ends.

There are no accounts, rooms, user lists, history or files on disk. Written in C# (.NET 8).

## Screenshots

| Handle and secret key | Waiting | Connected chat |
|---|---|---|
| ![Handle and secret key prompts](docs/screenshots/login.png) | ![Waiting for the other connection](docs/screenshots/connected.png) | ![Connected, chatting](docs/screenshots/chat.png) |

Two clients in the same conversation:

![Two users chatting](docs/screenshots/two-clients.png)

## Getting started

### Prerequisites

- .NET 8 SDK.
- The client uses the NuGet package `libsodium` 1.0.22 (restored automatically; prebuilt native libraries for Windows,
  Linux, macOS and Android/iOS). The server has no dependencies.

### Build

```bash
git clone https://github.com/ChrisLPJones/CipherChat.git
cd CipherChat
dotnet build
```

### Run the server

```bash
cd CipherChatServer
dotnet run -- [host] [port]        # defaults: localhost 3000; port 0-65535
```

The server prints one line ("Server started (protocol v5).") and logs nothing about clients.

### Run the client

Each of the two users runs, in a real terminal (the client reads single key presses, so it does not work with piped
input; use a terminal or tmux):

```bash
cd CipherChatClient
dotnet run -- [host port]          # defaults: localhost 3000; e.g. dotnet run -- chat.example.com 4000
```

Invalid arguments print a usage message and exit before any prompt.

**Prompts**

```
Enter handle: Anna
Secret key: ****************************
Type it again: ****************************
```

- **Handle**: a display name for this chat, 1-20 characters from `A-Za-z0-9_.-` ("you" is reserved).
- **Secret key**: typed masked, twice (a typo would otherwise only look like "nobody joined"). Both users must type the
  same key; capital letters and extra spaces do not matter. Esc at any prompt exits.

**Secret-key rules** (checked on your computer, with a plain message when one fails). The key is read aloud and typed, so it
must be easy to share but hard to guess. Make up **4 or more random words** together; do not use a quote, a name or a song
line. Anyone who guesses the key can read the chat.
- Printable ASCII only (letters, digits, punctuation, spaces); at most 100 characters.
- At least 12 characters and at least 6 different characters.
- Not one repeated character and not a straight run of keys (`abcdef...`, `123456...`, `qwerty...`).
- A key of only digits needs at least 20 digits (dates and phone numbers are easy to guess).

**Status lines.** The first user sees:

```
* Connecting...
* Connected.
* Waiting for the other connection...
```

When the other user logs in with the same secret key:

```
* Other user found.
* Verifying...
* Secure session established.
* bob is in the chat.
```

The second user sees the same without the waiting line. Then you chat: your lines are `You: ...` and the other user's
lines are `<handle>: ...`. Text from the other side has control and formatting characters removed before it is shown.

**Leaving.** `/quit` or Esc ends the chat (the other user sees "<handle> left the chat."). A line starting with `//` sends a
literal `/`. Any other `/word` shows a hint. When the chat ends for any reason the client shows "Press any key to exit" and
exits (exit code 1 on a failure, 0 after a normal quit or when the other user left). There is no reconnect and nothing is
saved: start the client again for a new chat.

**Waiting has no time limit.** If you are the first to connect you wait until the other user joins, you press Esc, or the
connection dies (the client sends a keepalive ping every 30 seconds, and the server and the client drop dead connections).
The tradeoff is that a waiting client holds one server slot until it leaves; the server limits slots (see Trust model).

**A wrong key looks like nobody joined.** If you and the other user typed different secret keys, you do not connect to each
other at all (the server pairs by an id derived from the key) and both of you simply keep waiting. If you do reach each other
with different keys (a rare id collision) both clients stop with: "Could not connect securely. Someone else may have used your
code, or the connection was tampered with. Make up a NEW code together before trying again." The same message appears when a
third user tries a key that is already in use. A key can pair only once per hour; after any pairing, successful or not, pick a new
secret key.

**Handles are not identities.** A handle is only a name label. It travels inside the encrypted session (never to the server) and
anyone who holds the secret key can choose any handle. Treat it like a nickname, not as proof of who is typing.

## How it works

1. Both users derive a short **rendezvous id** from the secret key with Argon2id (3 passes, 256 MiB, fixed salt), truncated to
   24 bits, and send `HELLO 5 <id> <random nonce>` to the server. The server pairs the first two connections with the same id
   and tells each its role and the other's nonce. It never sees the key.
2. The two clients run **CPace** (password-authenticated key exchange, ristretto255 with SHA-512, exactly as
   `draft-irtf-cfrg-cpace-21`) over the relay: each sends one 32-byte message (`KEY`), computes the shared secret, and then each
   sends a 64-byte key-confirmation tag (`CONFIRM`). A server that does not know the key cannot compute the shared secret, and
   cannot test guesses offline from what it relays.
3. From the CPace output (ISK) the clients derive, with HKDF-SHA256, a send chain key and a receive chain key and a session id.
   **Every message uses a fresh key**: a per-direction hash chain (HMAC-SHA256) gives one AES-256-GCM key per message and the old
   key is deleted, so earlier messages stay safe even if a later key leaks. Messages are padded to multiples of 256 bytes, carry a
   strict increasing number (a replayed, reordered or missing message ends the chat), and authenticate their header. A session ends
   after 100,000 messages per direction.
4. The handle is sent as the first encrypted message of the session. Ending the chat sends an encrypted end-of-session message.

### Cryptography and dependencies

- **CPace** (CPACE-RISTR255-SHA512, draft-irtf-cfrg-cpace-21), **Argon2id** and the ristretto255 group maths come from
  **libsodium** (NuGet package `libsodium` 1.0.22, by the libsodium author, ISC licence). It is referenced by the client only. We
  write only the CPace glue; the draft's test vectors are checked byte for byte in the tests. The draft is not yet an RFC, so the
  revision is pinned.
- Everything else uses the .NET base library: AES-256-GCM, HKDF-SHA256, HMAC-SHA256/SHA-512, SHA-256/512, random numbers.
- Key material is zeroed after use on a best-effort basis (managed memory cannot be fully scrubbed).

## Protocol v5

One ASCII line per command, tokens separated by single spaces, ending in `\n`. The grammar is closed: the server drops the
connection on any line that does not match (or arrives in the wrong order), and over-length lines (max 8300 characters). It
checks Base64 by charset, canonical padding and length and never decodes it.

**Client to server**

| Line | Meaning |
|---|---|
| `HELLO 5 <rid:6 hex> <nonce:32 hex>` | first line only (lowercase hex). Anything else as first line gets `ERR version` |
| `KEY <base64, 32 bytes>` | CPace message, once, after `PAIRED` |
| `CONFIRM <base64, 64 bytes>` | key-confirmation tag, once, after your own `KEY` |
| `MSG <base64, 298..6186 bytes>` | encrypted message: 26-byte header + 256*k bytes (k = 1..24) + 16-byte tag; only after your own `CONFIRM` |
| `PING` | the server answers `PONG` |

**Server to client**

| Line | Meaning |
|---|---|
| `WAIT` | you are first; waiting for the other user (no time limit) |
| `PAIRED <1|2> <peer nonce>` | paired; your role (1 = first) and the other's nonce |
| `KEY` / `CONFIRM` / `MSG <base64>` | relayed byte for byte from the other user, no sender field |
| `GONE` | the other user left (the server then closes your connection) |
| `PONG` | reply to `PING` |
| `ERR <code>` | `version`, `used` (the key's id is taken or burned), `full`, `rate`, `timeout` |

## Trust model (what you are and are not protected from)

**The server and the network cannot read your chat.** A passive observer or an honest-but-curious server learns nothing about
the content, the secret key, the handles or the session keys, and cannot test guesses of your key offline from what it relays.
Past chats stay safe even if the secret key leaks later (forward secrecy per message). Messages cannot be forged, replayed or
reordered without ending the chat.

**What a malicious server (or someone on the network path) can still do**
1. *Online guessing*: in each connection attempt it can pose as the other user with one guessed key, so each attempt allows at
   most one guess per user; every wrong guess shows both of you the failure message. In practice a handful of guesses.
2. *The rendezvous id limits weak keys*: the id is 24 bits derived from your key with an expensive function. A malicious server
   can build a dictionary of likely keys, narrow the candidates by the id, and then try one or two of them in the online guess above.
   **A key that is among the server's top ~16 million guesses can be identified and then used to read the chat silently.** A key it
   cannot narrow to one or two candidates is safe. That is why the client rejects short and patterned keys and why you should
   use 4 or more random words.
3. *Metadata and denial of service*: it sees both IP addresses, the times, the rendezvous id (which links the two IPs), the number,
   timing and padded size (in 256-byte steps) of messages. It (or the network) can drop, delay, end or burn pairings, and lie
   about who left (`GONE`). There is **no TLS**, so a network observer sees the same metadata and can do the same.

**What it cannot do**: read the chat passively; decrypt old chats even if it later learns the key; forge, replay or reorder messages
undetected.

**Not protected**: malware or a keylogger on your computer; someone shoulder-surfing the terminal; the two users being
tricked into sharing the key with the wrong user; a handle used as proof of identity; anonymity from the server; post-quantum
attackers (a recording could be decrypted later by one).

**Server abuse limits** (the server holds no secrets): 200 connections in total, 4 per IP, at most 100 waiting users,
10 new connections per IP per minute, at most 5 pairings per IP per hour that relay no message, one pairing per rendezvous id
(then burned for an hour), `HELLO` within 10 seconds, both `CONFIRM`s within 30 seconds after pairing, 90 seconds without any line
closes a connection (clients ping every 30 seconds), messages 10 per second (burst 30), pings 4 per minute.
A user waiting without a time limit occupies a waiting slot; these limits bound how many one address can hold.

## Tests

```bash
dotnet test CipherChat.sln
```

348 xUnit tests: the draft-21 known-answer vectors, key derivation and the code rules, the secure channel (tampering, replay,
order, padding, handles), the wire grammar on both sides, the server (raw sockets on an ephemeral port: pairing, burns, limits,
deadlines, order enforcement, relay) and the client session end to end, plus a scripted malicious server (wrong keys, bad points,
reflected, replayed, reordered or forged lines, fake `GONE`, silence, garbage). Tests use throwaway ports and never touch disk.
CI (`.github/workflows/ci.yml`) runs `dotnet build CipherChat.sln` and `dotnet test CipherChat.sln` on pushes and pull requests
to `main`.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request.

## License

This project is licensed under the MIT License. See the LICENSE file for details. libsodium is distributed under the ISC licence.
