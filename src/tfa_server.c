/* TFA Server: registers TFA clients, sends push challenges on requestAuth, and reports responseAuth. */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

#include "protocol.h"
#include "util.h"

#define MAX_USERS 128
#define BUF_SZ 512

typedef struct {
    int inUse;                     /* 0 = empty slot, 1 = occupied */
    unsigned int userID;           /* registered user */
    unsigned int publicKey;        /* cached public key for quick verification */
    struct sockaddr_in clientAddr; /* where to send pushTFA */
} TFAEntry;

static TFAEntry table[MAX_USERS];

static void DieWithError(const char *msg) {
    perror(msg);
    exit(1);
}

static TFAEntry *findEntry(unsigned int userID) {
    for (int i = 0; i < MAX_USERS; ++i) {
        if (table[i].inUse && table[i].userID == userID) return &table[i];
    }
    return NULL;
}

static TFAEntry *allocEntry(void) {
    for (int i = 0; i < MAX_USERS; ++i) {
        if (!table[i].inUse) return &table[i];
    }
    return NULL;
}

/* Request public key from PKE server synchronously over UDP. */
static unsigned int request_public_key(int sock, const struct sockaddr_in *pkeAddr, unsigned int userID) {
    PClientToPKServer req;
    memset(&req, 0, sizeof(req));
    req.messageType = requestKey;
    req.userID = userID;
    req.publicKey = 0;

    if (sendto(sock, &req, sizeof(req), 0, (const struct sockaddr *)pkeAddr, sizeof(*pkeAddr)) != sizeof(req)) {
        DieWithError("sendto() to PKE failed");
    }
    printf("[TFA Server] Sent requestKey to PKE Server for user %u\n", userID);

    PKServerToPClientOrLodiServer resp;
    struct sockaddr_in from;
    socklen_t fromLen = sizeof(from);
    ssize_t r = recvfrom(sock, &resp, sizeof(resp), 0, (struct sockaddr *)&from, &fromLen);
    if (r != sizeof(resp)) {
        fprintf(stderr, "Unexpected response size from PKE: %zd\n", r);
        return 0;
    }
    if (resp.messageType != responsePublicKey || resp.userID != userID) {
        fprintf(stderr, "Invalid response from PKE server\n");
        return 0;
    }
    printf("[TFA Server] Received responsePublicKey from PKE Server for user %u (publicKey=%u)\n",
           resp.userID, resp.publicKey);
    return resp.publicKey;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <TFA_SERVER_PORT> <PKE_SERVER_IP> <PKE_SERVER_PORT>\n", argv[0]);
        exit(1);
    }

    unsigned short myPort = (unsigned short)atoi(argv[1]);
    char *pkeIP = argv[2];
    unsigned short pkePort = (unsigned short)atoi(argv[3]);

    int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) DieWithError("socket() failed");
    /* No global receive timeout; allow blocking main loop. */

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

    printf("TFA server listening on UDP port %u; PKE at %s:%u\n", myPort, pkeIP, pkePort);

    for (;;) {  /* main loop */
        struct sockaddr_in from;
        socklen_t fromLen = sizeof(from);
        TFAClientOrLodiServerToTFAServer msg;
        ssize_t n = recvfrom(sock, &msg, sizeof(msg), 0, (struct sockaddr *)&from, &fromLen);
        if (n < 0) {
            perror("recvfrom() failed");
            continue;
        }
        if ((size_t)n < sizeof(msg)) {
            fprintf(stderr, "Ignoring undersized packet (%zd bytes)\n", n);
            continue;
        }

        char addrbuf[64];
        fmt_addr(&from, addrbuf, sizeof(addrbuf));
        if (msg.messageType == registerTFA) {
            printf("[TFA Server] Received registerTFA from %s for user %u\n", addrbuf, msg.userID);
        } else if (msg.messageType == requestAuth) {
            printf("[TFA Server] Received requestAuth from %s for user %u\n", addrbuf, msg.userID);
        } else if (msg.messageType == ackRegTFA || msg.messageType == ackPushTFA) {
            printf("[TFA Server] Received unexpected ACK type=%u from %s for user %u (ignored)\n",
                   msg.messageType, addrbuf, msg.userID);
        } else {
            printf("[TFA Server] Received unknown messageType=%u from %s for user %u\n",
                   msg.messageType, addrbuf, msg.userID);
        }

        if (msg.messageType == registerTFA) {
            /* Lookup public key from PKE. */
            unsigned int pub = request_public_key(sock, &pkeAddr, msg.userID);
            if (pub == 0) {
                fprintf(stderr, "[TFA Server] No public key for user %u; cannot register\n", msg.userID);
                continue;
            }
            /* Digital signature is over a random integer carried in the timestamp field. */
            unsigned long recovered = powmod(msg.digitalSig, RSA_PUBLIC_EXP, pub);
            if (recovered != msg.timestamp) {
                fprintf(stderr, "[TFA Server] Signature verification failed for user %u\n", msg.userID);
                continue;
            }

            TFAEntry *e = findEntry(msg.userID);
            if (!e) e = allocEntry();
            if (!e) {
                fprintf(stderr, "[TFA Server] TFA table full; cannot register user %u\n", msg.userID);
                continue;
            }
            e->inUse = 1;
            e->userID = msg.userID;
            e->publicKey = pub;
            e->clientAddr = from;
            printf("[TFA Server] Registration verified and stored for user %u\n", msg.userID);

            TFAServerToTFAClient confirm;
            confirm.messageType = confirmTFA;
            confirm.userID = msg.userID;
            ssize_t s = sendto(sock, &confirm, sizeof(confirm), 0, (struct sockaddr *)&from, fromLen);
            if (s != sizeof(confirm)) DieWithError("sendto confirmTFA failed");
            printf("[TFA Server] Sent confirmTFA to %s for user %u\n", addrbuf, msg.userID);

            /* Optional: wait briefly for ackRegTFA; don't block indefinitely. */
            struct timeval tv;
            tv.tv_sec = 2;
            tv.tv_usec = 0;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            TFAClientOrLodiServerToTFAServer ackMsg;
            struct sockaddr_in ackFrom;
            socklen_t ackLen = sizeof(ackFrom);
            ssize_t an = recvfrom(sock, &ackMsg, sizeof(ackMsg), 0, (struct sockaddr *)&ackFrom, &ackLen);
            if (an == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                printf("[TFA Server] No ackRegTFA received (timeout); continuing\n");
            } else if (an == sizeof(ackMsg) && ackMsg.messageType == ackRegTFA && ackMsg.userID == msg.userID) {
                fmt_addr(&ackFrom, addrbuf, sizeof(addrbuf));
                printf("[TFA Server] Received ackRegTFA from %s for user %u (registration complete)\n",
                       addrbuf, ackMsg.userID);
            } else {
                printf("[TFA Server] Did not receive proper ackRegTFA; continuing\n");
            }
        } else if (msg.messageType == requestAuth) {
            TFAEntry *e = findEntry(msg.userID);
            if (!e) {
                fprintf(stderr, "[TFA Server] No TFA client registered for user %u\n", msg.userID);
                TFAServerToLodiServer resp;
                resp.messageType = responseAuth;
                resp.userID = 0; /* signal failure */
                sendto(sock, &resp, sizeof(resp), 0, (struct sockaddr *)&from, fromLen);
                continue;
            }

            /* Preserve Lodi server address before we wait for the client's ackPushTFA. */
            struct sockaddr_in lodiAddr = from;
            socklen_t lodiLen = fromLen;

            /* Send pushTFA to client. */
            TFAServerToTFAClient push;
            push.messageType = pushTFA;
            push.userID = msg.userID;
            ssize_t ps = sendto(sock, &push, sizeof(push), 0, (struct sockaddr *)&e->clientAddr,
                                sizeof(e->clientAddr));
            if (ps != sizeof(push)) DieWithError("sendto pushTFA failed");
            char clientAddrBuf[64];
            fmt_addr(&e->clientAddr, clientAddrBuf, sizeof(clientAddrBuf));
            printf("[TFA Server] Sent pushTFA to %s for user %u\n", clientAddrBuf, msg.userID);

            /* Wait for ackPushTFA. */
            TFAClientOrLodiServerToTFAServer ack;
            struct sockaddr_in fromClient;
            socklen_t fromLen2 = sizeof(fromClient);
            ssize_t ar = recvfrom(sock, &ack, sizeof(ack), 0, (struct sockaddr *)&fromClient, &fromLen2);
            int success = 0;
            if (ar == sizeof(ack) && ack.messageType == ackPushTFA && ack.userID == msg.userID) {
                success = 1;
                fmt_addr(&fromClient, addrbuf, sizeof(addrbuf));
                printf("[TFA Server] Received ackPushTFA from %s for user %u (auth success)\n",
                       addrbuf, ack.userID);
            } else {
                printf("[TFA Server] Did not receive ackPushTFA; marking auth failed for user %u\n",
                       msg.userID);
            }

            TFAServerToLodiServer resp;
            resp.messageType = responseAuth;
            /* userID echoed on success; 0 on failure to signal auth failure to Lodi server. */
            resp.userID = success ? msg.userID : 0;
            ssize_t rs = sendto(sock, &resp, sizeof(resp), 0, (struct sockaddr *)&lodiAddr, lodiLen);
            if (rs != sizeof(resp)) DieWithError("sendto responseAuth failed");
            printf("[TFA Server] Sent responseAuth to Lodi Server at %s (userID=%u)\n",
                   inet_ntoa(lodiAddr.sin_addr), resp.userID);
        } else {
            fprintf(stderr, "Unknown messageType=%u from %s\n", msg.messageType, addrbuf);
        }
    }

    close(sock);
    return 0;
}
