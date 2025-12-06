# Project 2 - Following Idol Posts (TCP) with Project 1 Auth

Components
- `pke_server` (UDP): stores public keys and returns them on request.
- `tfa_server` (UDP): registers TFA clients and issues push challenges when asked by Lodi server.
- `tfa_client` (UDP): registers with TFA server and responds to push challenges.
- `lodi_server` (TCP, per request): handles login (PKE+TFA), follow, unfollow, post, feed, logout; keeps in-memory followers/posts.
- `lodi_client`: UDP to register key with PKE; TCP per request for login/follow/unfollow/post/feed/logout; derives userID/keys from username/password.

Protocol
- Project 1 UDP messages (PKE/TFA) unchanged.
- Project 2 Lodi TCP messages (`include/protocol.h`):
  - `PClientToLodiServer { login, post, feed, follow, unfollow, logout; userID; recipientID; timestamp; digitalSig; char message[100]; }`
  - `LodiServerMessage { ackLogin, ackPost, ackFeed, ackFollow, ackUnfollow, ackLogout; userID; char message[100]; }`

Crypto stub
- `include/util.h` provides RSA-style sign/verify with fixed exponent 65537; `publicKey` is modulus `n`, `privateKey` is exponent `d`.
- Keys are derived deterministically from a password (not secure); use the same username/password on TFA and Lodi clients to match userID/keys.

Build
```sh
gcc -Iinclude -o bin/pke_server src/pke_server.c
gcc -Iinclude -o bin/tfa_server src/tfa_server.c
gcc -Iinclude -o bin/tfa_client src/tfa_client.c
gcc -Iinclude -o bin/lodi_server src/lodi_server.c
gcc -Iinclude -o bin/lodi_client src/lodi_client.c
```

Run (example ports, localhost)
```
bin/pke_server 5000
bin/tfa_server 5001 127.0.0.1 5000
bin/lodi_server 5002 127.0.0.1 5000 127.0.0.1:5001   # TCP port 5002; UDP to PKE/TFA for login auth
bin/tfa_client 127.0.0.1 5001      # prompts for username/password (derives userID/keys)
bin/lodi_client 127.0.0.1 5000 127.0.0.1 5002   # prompts for username/password (derives userID/keys)
```
Notes:
- Use the same username/password for TFA and Lodi clients; userID is derived from username, keys from password.
- Ports can be changed; pass matching values.
- `responseAuth`/`ackLogin` use `userID` to indicate success (echoed) or failure (`0`).
- Lodi client retries PKE register on UDP timeout; TCP requests are blocking per attempt. TFA client blocks waiting for pushes.
- Feed requests: the server streams one `ackFeed` per post (message text includes idol ID) and closes the TCP connection when done; the client prints all items until EOF.

Quick test (single fan/idol on localhost)
- Terminal 1: `bin/pke_server 5000`
- Terminal 2: `bin/tfa_server 5001 127.0.0.1 5000`
- Terminal 3: `bin/lodi_server 5002 127.0.0.1 5000 127.0.0.1:5001`
- Terminal 4: `bin/tfa_client 127.0.0.1 5001` → choose Register, enter username/password.
- Terminal 5: `bin/lodi_client 127.0.0.1 5000 127.0.0.1 5002` → Register key (same username/password), then Login.
- After login in Lodi client: Post a message; Follow an idol userID (e.g., your own or a second user), Request feed.

Quick test (two users)
- Repeat the TFA client + Lodi client steps with a different username/password in new terminals (e.g., ports unchanged).
- In user B’s Lodi client, Follow user A’s ID, then Request feed after user A posts; you should see user A’s posts via ackFeed messages.

Behavior summary
- `pke_server`: registerKey/requestKey (UDP), stores/returns public keys.
- `tfa_server`: on `registerTFA`, fetches public key from PKE, verifies signature over random int (timestamp), stores client address, sends `confirmTFA`, optionally waits for `ackRegTFA`; on `requestAuth`, sends `pushTFA`, waits `ackPushTFA`, replies `responseAuth`.
- `tfa_client`: sends `registerTFA` with random int in timestamp and signature over it, waits `confirmTFA`, sends `ackRegTFA`, then listens for `pushTFA` and sends `ackPushTFA`; username→userID hash, password→keys.
- `lodi_server` (TCP): on `login`, fetches public key from PKE, verifies signature vs timestamp, requests TFA; replies `ackLogin` with userID or 0 and records logged-in address. Handles follow/unfollow/post/feed/logout with in-memory state; per-request TCP connection; feed returns one `ackFeed` per post then closes. Feed payload includes `[userID] text`.
- `lodi_client`: Logged out menu: Register Key (UDP) or Login (TCP). Logged in: Follow, Unfollow, Post, Feed, Logout, Exit. Uses username/password to derive userID/keys; sends `login` with timestamp+signature; other actions use TCP to Lodi server. Feed prints every `ackFeed` until the server closes the connection; shows the idol’s userID (not username).

Logging and robustness
- Processes print sent/received events; errors go to stderr.
- Lodi client retries PKE register; TCP requests are per-attempt blocking. No persistence beyond in-memory state.

Disclaimer
- RSA-style stub and password-derived keys are for assignment purposes only; not secure.
