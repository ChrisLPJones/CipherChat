# CipherChat

CipherChat is a secure and encrypted chat application implemented in C#. 
It consists of a console-based client and server, utilizing AES-256-GCM encryption 
for secure communication between users.

## Features

- End-to-end authenticated encryption using AES-256-GCM.
- Multi-user chat functionality with real-time message broadcasting.
- Password-protected encryption keys.
- All users connect using a shared pre-defined encryption key for secure communication.
- Multiple rooms, each with its own key, plus the default `general` channel.
- Private (direct) messages between two users with their own pair key, invisible to the rest of the chat and unreadable to the server.

## Screenshots

| Login | Connected | Chat |
|---|---|---|
| ![Login](docs/screenshots/login.png) | ![Connected](docs/screenshots/connected.png) | ![Chat](docs/screenshots/chat.png) |

Two clients in the same conversation:

![Two clients](docs/screenshots/two-clients.png)

## Getting Started

Follow these instructions to set up and run CipherChat on your system.

### Prerequisites

- .NET SDK 6.0 or later

### Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/ChrisLPJones/CipherChat.git
   cd CipherChat
   ```

2. Build the project using the .NET CLI:
   ```bash
   dotnet build
   ```

### Running the Server

1. Navigate to the server directory:
   ```bash
   cd CipherChatServer
   ```

2. Run the server:
   ```bash
   dotnet run
   ```

### Running the Client

1. Navigate to the client directory:
   ```bash
   cd CipherChatClient
   ```

2. Run the client (optionally with the server's host and port, default `localhost 3000`; hostnames and IPs work, port 1-65535):
   ```bash
   dotnet run
   dotnet run -- chat.example.com 4000
   ```
   Invalid arguments print a usage message and exit before any prompt.

3. Enter your username and the shared encryption key to connect. You land in the `general` channel.

4. Commands (type them in the message line; start a message with `//` to send a literal `/`):
   - `/join <room>`: join (or create) a room. You are asked for the **room key** (masked); everyone in the room must type the same key. A blank key reuses your login key. Room names are case-insensitive, up to 32 characters of letters, digits, `_`, `.`, `-`. A wrong key opens a different, empty room (you see "You are alone in ..."). You can be in at most 16 channels at once.
   - `/leave [room]`: leave a room or private chat (default: the active one). The lobby `general` cannot be left.
   - `/dm <user>`: open a private chat. You are asked for a **pair key** (masked). You and the other user must type the *same* pair key, which you agree on out of band (e.g. in person or over another secure channel). Nothing is exchanged through the server. A blank key cancels.
   - `/switch <name|n>`, or PgUp/PgDn: change the active channel. The header row lists channels; a number in brackets is the unread count of channels you are not looking at.
   - `/users` (members of the active channel), `/help`, `/quit` (or Esc).
   - `/history` is reserved for a later version.

   A private chat only works if **both** sides ran `/dm <other user>` with the same pair key: the server cannot tell a user to open a chat, and a wrong key silently opens a different, empty channel (the client warns "You are alone in ..." when nobody else is in it).

## How It Works: Secure Communication

CipherChat ensures secure communication between all connected users by employing AES-256-GCM authenticated encryption. 
Below are the detailed steps emphasizing the encryption process:

1. **Pre-defined Encryption Key**:
   - All users must agree on and use the same pre-defined encryption key.
   - This key is required to encrypt and decrypt messages exchanged in the chat.
   - Without the correct key, users cannot participate in the chat or interpret the messages.

2. **Key Derivation**:
   - CipherChat derives a 256-bit AES key from the passphrase (shared encryption key) and a randomly generated salt.
   - This derivation is performed using PBKDF2 (Password-Based Key Derivation Function 2) with 600,000 iterations and SHA256 as the hash algorithm.
   - The 600,000 iterations make guessing the passphrase slower, but a weak passphrase is still weak: use a long random one.

3. **Connecting to the Server**:
   - When a user connects, they must enter their username and the shared encryption key.
   - The client says `HELLO 3`, derives the channel tag from the key and joins the `general` channel with its username encrypted under the key.
   - The server only sees the opaque tag and the encrypted username, and tells the channel's members who joined.

4. **Sending Messages**:
   - Users type their messages in the console input line and press `Enter` to send.
   - Before the message is sent, it is encrypted on the client-side using AES-256-GCM with the derived key and a random per-message salt and nonce.
   - The encrypted message is sent to the server, ensuring that no sensitive information is transmitted in plaintext.

5. **Server Broadcasting**:
   - The server receives the encrypted message and its channel tag from the client.
   - Without decrypting it, the server relays the encrypted message to the other members of that channel.
   - This ensures that the server does not have access to the actual message content, maintaining end-to-end encryption.

6. **Message Decryption**:
   - Each client receives the encrypted message from the server.
   - The client uses the shared encryption key and derived AES key to decrypt the message locally. GCM authenticates every message, so tampered data is detected and reported instead of being dropped silently. Because the channel tag is derived from the key, a wrong key does not decrypt garbage: it opens a different, empty channel, and the client says "You are alone in ..." when nobody else is there.
   - Once decrypted, the message is displayed in the chat interface for the user to read.

By adhering to this process, CipherChat ensures that all communication remains secure, private, and accessible only to users with the correct pre-defined encryption key.

## Protocol v3

Old (v1/v2) and new clients and servers cannot talk to each other: upgrade all of them together. A v3 server answers a v2 client's first line with `ERR version` and closes; a v3 client talking to an older server sees the connection close and reports "protocol mismatch?".

**Framing.** One ASCII line per command, tokens separated by single spaces, terminated by `\n`. The server checks every token against a closed grammar (verbs from a fixed set, tags and Base64 by charset and length) and drops the connection on any violation or over-length line (max 11100 characters). It never decodes or decrypts a payload.

**Channels.** A channel is a `(tag, key)` pair; the lobby (`general`), rooms and private chats are all the same thing. The *tag* is an opaque 22-character id (`A-Za-z0-9_-`) the server routes by. Clients derive it from the key: `Base64Url(PBKDF2-SHA256(key, salt = "cipherchat-channel-v1|room|<name>" or "...|dm|<a>|<b>", 600000, 16 bytes))`. The salt domain differs from the random per-message salts of the message key, so the tag does not give away the message key. Consequences: a wrong key leads to a different, empty channel; only key holders can join a channel; a private chat name is the sorted, case-insensitive user pair, so both sides derive the same tag.

**Client to server**

| Line | Meaning |
|---|---|
| `HELLO 3` | handshake, must be the first line |
| `JOIN <tag> <presence>` | join a channel; `presence` is the username encrypted under the channel key |
| `LEAVE <tag>` | leave a channel |
| `MSG <tag> <payload>` | send an encrypted message to the channel's other members |
| `HIST <tag> <afterId> <max>` | request history (max 50); the server currently answers `ERR unsupported` |
| `PING` | the server answers `PONG` |

**Server to client**

| Line | Meaning |
|---|---|
| `WELCOME 3 <mid>` | handshake reply; `mid` is a per-connection counter, not an identity |
| `MEMBER <tag> <mid> <presence>` | roster entry on join: current members first, the joiner itself last (end of roster) |
| `JOINED <tag> <mid> <presence>` / `LEFT <tag> <mid>` | membership changes; `LEFT` is also sent when a connection drops (even a crash) |
| `MSG <tag> <id> <payload>` | a message; `id` is a per-channel counter assigned by the server |
| `ACK <tag> <id>` | to the sender: the id its message got |
| `HIST <tag> <id> <payload>` ... `HISTEND <tag> <headId>` | reserved for history replay |
| `PONG` | reply to `PING` |
| `ERR <code>` | `version`, `notjoined`, `alreadyjoined`, `limit` (max 16 channels per connection), `unsupported` |

`MSG`/`HIST`/`LEAVE` need membership (`ERR notjoined` otherwise). Payloads and presence blobs are Base64 of `version(0x03) | salt(16) | nonce(12) | ciphertext | tag(16)` (AES-256-GCM, key from PBKDF2-SHA256, 600,000 iterations over a random per-message salt). The additional authenticated data is the version byte followed by the channel tag, so the server cannot move a message to another channel. Limits (`ProtocolLimits`): usernames 1-20 characters of `A-Za-z0-9_.-`, messages up to 2000 characters, payloads 60-10984 characters, presence up to 128 characters. Username rules are enforced by the clients only; the server cannot see usernames (see Trust model).

## Trust model

- Transport is plain TCP: no TLS. Only payloads and presence blobs are encrypted client-side; framing, line lengths, timing, IP addresses and connection times are visible to anyone on the path. TLS is a deliberate, documented-only decision for now.
- The server never holds a key and cannot read messages or usernames (inside the ciphertext). It sees: which opaque channel tag each connection joined, who is in each tag (as opaque per-connection numbers and encrypted presence blobs), message sizes, timing and IP addresses. It can tell that two connections share a channel, and can run an offline guess of a channel key against a tag (no cheaper than guessing against any ciphertext it relays).
- The server does not log payloads, presence blobs, tags or IP addresses; it logs only unexpected errors. Treat the host as sensitive metadata all the same.
- Private chats: the pair key is agreed out of band and is the only secret between the two users. The server is not involved in key agreement, so it cannot substitute keys, but a weak pair key can be guessed offline from any intercepted ciphertext. Use a long random passphrase. Anyone who knows the pair key can read and write the private chat and claim either name.
- Anyone who can reach the port can connect, join tags and relay, inject, drop or replay lines. AES-GCM stops them reading or forging messages without the key, and the tag in the authenticated data stops moving a message to another channel, but not replay, dropping or flooding. Any holder of a channel key can claim any username (no sender authentication). Server-assigned ids are untrusted.
- A leaked or weak key exposes all past and future traffic of its channels (PBKDF2 slows guessing, it does not prevent it). Keys live only in client memory; they are never sent, logged or stored. Run on loopback/LAN or inside a VPN/SSH tunnel.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
