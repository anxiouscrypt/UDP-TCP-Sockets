# Project 1 - Two-Factor Authentication (UDP)

This repository contains five UDP processes implementing the flow from the provided diagram/spec:

- `pke_server`: stores public keys and returns them on request.
- `tfa_server`: registers TFA clients and issues push challenges when asked by the Lodi server.
- `tfa_client`: registers itself with the TFA server and responds to push challenges.
- `lodi_server`: verifies login digital signatures via the PKE server, then triggers TFA verification.
- `lodi_client`: registers its public key (derived from username/password), then performs login.

## Directory Layout
- `include/` shared headers (`protocol.h`, `util.h`).
- `src/` one source file per process.
- `bin/` suggested output directory for compiled binaries.
- `Sample Socket Code/` original UDP/TCP echo examples provided.

## Message Structures
All structs/enums are defined in `include/protocol.h` exactly as specified in the assignment (registerKey/requestKey, login/ackLogin, registerTFA/confirmTFA/pushTFA/etc.).

## RSA-Style Sign/Verify Stub
`include/util.h` provides a minimal RSA-style sign/verify (modular exponentiation) using a fixed public exponent `RSA_PUBLIC_EXP` (65537). The `publicKey` field is treated as the modulus `n`. The private key argument is treated as the private exponent `d`.
- Sign: `digitalSig = rsa_sign(message, privateKey, modulus)` == `message^d mod n`
- Verify: `rsa_verify(sig, message, RSA_PUBLIC_EXP, modulus)`
Messages are reduced modulo `n` inside the helper to satisfy `m < n`.
Clients derive `(publicKey, privateKey)` deterministically from a password (classroom stub), so enter the same password on both TFA and Lodi clients for the same user.

## Build
From the project root:
```sh
gcc -Iinclude -o bin/pke_server src/pke_server.c
gcc -Iinclude -o bin/tfa_server src/tfa_server.c
gcc -Iinclude -o bin/tfa_client src/tfa_client.c
gcc -Iinclude -o bin/lodi_server src/lodi_server.c
gcc -Iinclude -o bin/lodi_client src/lodi_client.c
```

## Example Run (all localhost, sample ports)
In separate terminals:
```sh
bin/pke_server 5000
bin/tfa_server 5001 127.0.0.1 5000
bin/lodi_server 5002 127.0.0.1 5000 127.0.0.1:5001
bin/tfa_client 127.0.0.1 5001      # prompts for username and password (derives userID/keys)
bin/lodi_client 127.0.0.1 5000 127.0.0.1 5002   # prompts for username and password (derives userID/keys)
```
Notes:
- Use the same username/password for TFA and Lodi clients; a numeric userID is derived from the username and a keypair is derived from the password (not secure, for classroom use).
- Ports can be changed; pass the matching values to each process.
- `responseAuth` and `ackLogin` use `userID` to indicate success (userID echoed) or failure (`userID=0`).
- Lodi client uses simple 2s timeouts and up to 3 retries for register/login steps to avoid hanging on lost packets. TFA client blocks waiting for pushes.

## Behavior Summary
- `pke_server`: accepts `registerKey`, stores `userID -> publicKey`, replies `ackRegisterKey`; on `requestKey` replies `responsePublicKey`.
- `tfa_server`: on `registerTFA`, fetches public key from PKE, verifies signature over a random integer (carried in the timestamp field), stores client address, sends `confirmTFA`, optionally waits for `ackRegTFA`. On `requestAuth`, sends `pushTFA` to the stored client, waits for `ackPushTFA`, then replies `responseAuth` to Lodi server.
- `tfa_client`: sends `registerTFA` with a random integer in timestamp and signature over that value, waits `confirmTFA`, replies `ackRegTFA`, then listens for `pushTFA` and replies `ackPushTFA`. Username is hashed to userID; keys are derived locally from the entered password.
- `lodi_server`: on `login`, fetches public key from PKE, verifies signature vs timestamp, then requests TFA; responds `ackLogin` with `userID` on success or `0` on failure.
- `lodi_client`: interactive menu. When logged out: Register Key (username/password → userID/keys) or Login (username/password → userID/keys); when logged in: Logout or Exit. Sends `login` with timestamp+signature.

## Logging and Robustness
- Each process prints received/sent messages with key fields; errors are reported to stderr.
- Clients use a 2s receive timeout and up to 3 retries on key register/login/confirm to avoid hanging; extend as desired.

## Disclaimer
The RSA-style stub and password-derived keys are only to satisfy the assignment’s verification steps and are not secure. Replace with real RSA if required by your grading environment.
