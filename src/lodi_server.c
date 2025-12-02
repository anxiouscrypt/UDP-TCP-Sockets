/* Lodi Server: verifies login via PKE, triggers TFA via TFA server, and replies with ackLogin. */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>

#include "protocol.h"
#include "util.h"

static void DieWithError(const char *msg) {
    perror(msg);
    exit(1);
}

/* Ask PKE server for a user's public key. */
static unsigned int request_public_key(int sock, const struct sockaddr_in *pkeAddr, unsigned int userID) {
    PClientToPKServer req;
    memset(&req, 0, sizeof(req));
    req.messageType = requestKey;
    req.userID = userID;
    req.publicKey = 0;

    if (sendto(sock, &req, sizeof(req), 0, (const struct sockaddr *)pkeAddr, sizeof(*pkeAddr)) != sizeof(req)) {
        DieWithError("sendto requestKey failed");
    }
    printf("[Lodi Server] Sent requestKey to PKE Server for user %u\n", userID);

    PKServerToPClientOrLodiServer resp;
    struct sockaddr_in from;
    socklen_t fromLen = sizeof(from);
    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ssize_t r = recvfrom(sock, &resp, sizeof(resp), 0, (struct sockaddr *)&from, &fromLen);
    /* Disable timeout for other operations. */
    struct timeval tv0 = { .tv_sec = 0, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv0, sizeof(tv0));
    if (r == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        fprintf(stderr, "Timeout waiting for PKE response for user %u\n", userID);
        return 0;
    }
    if (r != sizeof(resp)) {
        fprintf(stderr, "Unexpected PKE response size: %zd\n", r);
        return 0;
    }
    if (resp.messageType != responsePublicKey || resp.userID != userID) {
        fprintf(stderr, "Invalid PKE response\n");
        return 0;
    }
    printf("[Lodi Server] Received responsePublicKey from PKE Server for user %u (publicKey=%u)\n",
           resp.userID, resp.publicKey);
    return resp.publicKey;
}

/* Ask TFA server to authenticate a user; returns 1 on success, 0 on failure. */
static int request_tfa(int sock, const struct sockaddr_in *tfaAddr, unsigned int userID) {
    TFAClientOrLodiServerToTFAServer req;
    memset(&req, 0, sizeof(req));
    req.messageType = requestAuth;
    req.userID = userID;
    req.timestamp = 0;
    req.digitalSig = 0;

    if (sendto(sock, &req, sizeof(req), 0, (const struct sockaddr *)tfaAddr, sizeof(*tfaAddr)) != sizeof(req)) {
        DieWithError("sendto requestAuth failed");
    }
    printf("[Lodi Server] Sent requestAuth to TFA Server for user %u\n", userID);

    TFAServerToLodiServer resp;
    struct sockaddr_in from;
    socklen_t fromLen = sizeof(from);
    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ssize_t r = recvfrom(sock, &resp, sizeof(resp), 0, (struct sockaddr *)&from, &fromLen);
    struct timeval tv0 = { .tv_sec = 0, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv0, sizeof(tv0));
    if (r == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        fprintf(stderr, "Timeout waiting for responseAuth for user %u\n", userID);
        return 0;
    }
    if (r != sizeof(resp)) {
        fprintf(stderr, "Unexpected responseAuth size: %zd\n", r);
        return 0;
    }
    printf("[Lodi Server] Received responseAuth from TFA Server (userID=%u)\n", resp.userID);
    /* Success if userID echoed; failure if 0 or mismatch. */
    return (resp.userID == userID);
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <LODI_SERVER_PORT> <PKE_IP> <PKE_PORT> <TFA_IP:TFA_PORT>\n", argv[0]);
        fprintf(stderr, "Example: %s 5002 127.0.0.1 5000 127.0.0.1:5001\n", argv[0]);
        exit(1);
    }

    unsigned short myPort = (unsigned short)atoi(argv[1]);
    char *pkeIP = argv[2];
    unsigned short pkePort = (unsigned short)atoi(argv[3]);
    char *tfaSpec = argv[4];

    char *colon = strchr(tfaSpec, ':');
    if (!colon) {
        fprintf(stderr, "TFA spec must be IP:PORT\n");
        exit(1);
    }
    *colon = '\0';
    char *tfaIP = tfaSpec;
    unsigned short tfaPort = (unsigned short)atoi(colon + 1);

    int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) DieWithError("socket() failed");

    struct sockaddr_in servAddr;
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(myPort);

    if (bind(sock, (struct sockaddr *)&servAddr, sizeof(servAddr)) < 0) {
        DieWithError("bind() failed");
    }

    struct sockaddr_in pkeAddr;
    memset(&pkeAddr, 0, sizeof(pkeAddr));
    pkeAddr.sin_family = AF_INET;
    pkeAddr.sin_addr.s_addr = inet_addr(pkeIP);
    pkeAddr.sin_port = htons(pkePort);

    struct sockaddr_in tfaAddr;
    memset(&tfaAddr, 0, sizeof(tfaAddr));
    tfaAddr.sin_family = AF_INET;
    tfaAddr.sin_addr.s_addr = inet_addr(tfaIP);
    tfaAddr.sin_port = htons(tfaPort);

    printf("[Lodi Server] Listening on UDP port %u; PKE %s:%u; TFA %s:%u\n", myPort, pkeIP, pkePort,
           tfaIP, tfaPort);

    for (;;) {  /* main loop */
        struct sockaddr_in from;
        socklen_t fromLen = sizeof(from);
        PClientToLodiServer msg;
        ssize_t n = recvfrom(sock, &msg, sizeof(msg), 0, (struct sockaddr *)&from, &fromLen);
        if (n < 0) DieWithError("recvfrom() failed");
        if ((size_t)n < sizeof(msg)) {
            fprintf(stderr, "[Lodi Server] Ignoring undersized packet (%zd bytes)\n", n);
            continue;
        }

        char addrbuf[64];
        fmt_addr(&from, addrbuf, sizeof(addrbuf));
        printf("[Lodi Server] Received login from %s for user %u\n", addrbuf, msg.userID);

        /* First factor: verify signature using PKE. */
        unsigned int pub = request_public_key(sock, &pkeAddr, msg.userID);
        int authOK = 0;
        if (pub != 0) {
            if (rsa_verify(msg.digitalSig, msg.timestamp, RSA_PUBLIC_EXP, pub)) {
                authOK = 1;
                printf("[Lodi Server] First factor passed for user %u (signature verified)\n", msg.userID);
            } else {
                printf("[Lodi Server] First factor failed: signature mismatch for user %u\n", msg.userID);
            }
        } else {
            printf("[Lodi Server] No public key for user %u\n", msg.userID);
        }

        /* Second factor via TFA server. */
        int tfaOK = 0;
        if (authOK) {
            tfaOK = request_tfa(sock, &tfaAddr, msg.userID);
            printf("[Lodi Server] Second factor %s for user %u\n", tfaOK ? "passed" : "failed",
                   msg.userID);
        }

        LodiServerToLodiClientAcks ack;
        ack.messageType = ackLogin;
        /* userID echoed on success; 0 on failure to signal auth failure to client. */
        ack.userID = (authOK && tfaOK) ? msg.userID : 0;
        ssize_t s = sendto(sock, &ack, sizeof(ack), 0, (struct sockaddr *)&from, fromLen);
        if (s != sizeof(ack)) DieWithError("sendto ackLogin failed");

        if (!(authOK && tfaOK)) {
            /* Additional console error to satisfy "display corresponding error messages" requirement. */
            fprintf(stderr, "[Lodi Server] Login failed for user %u (first=%d, second=%d)\n", msg.userID, authOK, tfaOK);
        } else {
            printf("[Lodi Server] Login succeeded for user %u; sent ackLogin\n", msg.userID);
        }
    }

    close(sock);
    return 0;
}
