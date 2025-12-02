/* PKE Server: registers and serves public keys over UDP. */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "protocol.h"

#define MAX_USERS 128  /* fixed-size table for simplicity; no dynamic allocation */

typedef struct {
    int inUse;
    unsigned int userID;
    unsigned int publicKey;
    struct sockaddr_in registeredAddr;
} UserEntry;

static UserEntry userTable[MAX_USERS];

/* Crash-fast error helper; suitable for this small assignment. */
static void DieWithError(const char *msg) {
    perror(msg);
    exit(1);
}

/* Find a user entry by ID, or NULL if not present. */
static UserEntry *findUser(unsigned int userID) {
    for (int i = 0; i < MAX_USERS; ++i) {
        if (userTable[i].inUse && userTable[i].userID == userID) {
            return &userTable[i];
        }
    }
    return NULL;
}

/* Allocate a free slot; returns NULL if the table is full. */
static UserEntry *allocUserSlot(void) {
    for (int i = 0; i < MAX_USERS; ++i) {
        if (!userTable[i].inUse) {
            return &userTable[i];
        }
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <PKE_SERVER_PORT>\n", argv[0]);
        exit(1);
    }

    unsigned short port = (unsigned short)atoi(argv[1]);
    int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) DieWithError("socket() failed");

    struct sockaddr_in servAddr;
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(port);

    if (bind(sock, (struct sockaddr *)&servAddr, sizeof(servAddr)) < 0) {
        DieWithError("bind() failed");
    }

    printf("PKE server listening on UDP port %u\n", port);

    for (;;) {  /* main UDP receive loop */
        struct sockaddr_in clntAddr;
        unsigned int cliAddrLen = sizeof(clntAddr);
        PClientToPKServer request;
        ssize_t recvSize =
            recvfrom(sock, &request, sizeof(request), 0, (struct sockaddr *)&clntAddr, &cliAddrLen);
        if (recvSize < 0) DieWithError("recvfrom() failed");
        if ((size_t)recvSize < sizeof(request)) {
            fprintf(stderr, "Received undersized packet (%zd bytes) ignored\n", recvSize);
            continue;
        }

        if (request.messageType == registerKey) {
            printf("[PKE Server] Received registerKey from %s:%u for userID=%u\n",
                   inet_ntoa(clntAddr.sin_addr), ntohs(clntAddr.sin_port), request.userID);
        } else if (request.messageType == requestKey) {
            printf("[PKE Server] Received requestKey from %s:%u for userID=%u\n",
                   inet_ntoa(clntAddr.sin_addr), ntohs(clntAddr.sin_port), request.userID);
        } else {
            printf("[PKE Server] Received unknown messageType=%u from %s:%u\n",
                   request.messageType, inet_ntoa(clntAddr.sin_addr), ntohs(clntAddr.sin_port));
        }

        PKServerToPClientOrLodiServer reply;
        memset(&reply, 0, sizeof(reply));
        reply.userID = request.userID;

        /* Handle the two message types defined for PKE. */
        switch (request.messageType) {
            case registerKey: {
                UserEntry *slot = findUser(request.userID);
                if (!slot) {
                    slot = allocUserSlot();
                    if (!slot) {
                        fprintf(stderr, "User table full; cannot register user %u\n", request.userID);
                        continue;
                    }
                }
                slot->inUse = 1;
                slot->userID = request.userID;
                slot->publicKey = request.publicKey;
                slot->registeredAddr = clntAddr;

                reply.messageType = ackRegisterKey;
                reply.publicKey = request.publicKey;
                printf("[PKE Server] Registered key for user %u (publicKey=%u); sending ackRegisterKey\n",
                       request.userID, request.publicKey);
                break;
            }
            case requestKey: {
                UserEntry *slot = findUser(request.userID);
                reply.messageType = responsePublicKey;
                if (slot) {
                    reply.publicKey = slot->publicKey;
                    printf("[PKE Server] Found public key %u for user %u; sending responsePublicKey\n",
                           reply.publicKey, request.userID);
                } else {
                    reply.publicKey = 0;
                    printf("[PKE Server] No key found for user %u; sending responsePublicKey with publicKey=0\n",
                           request.userID);
                }
                break;
            }
            default:
                fprintf(stderr, "Unknown messageType=%u from %s:%u\n", request.messageType,
                        inet_ntoa(clntAddr.sin_addr), ntohs(clntAddr.sin_port));
                continue;
        }

        ssize_t sent = sendto(sock, &reply, sizeof(reply), 0, (struct sockaddr *)&clntAddr,
                              sizeof(clntAddr));
        if (sent != sizeof(reply)) {
            DieWithError("sendto() sent unexpected byte count");
        }
        printf("[PKE Server] Sent response (type=%u) to %s:%u for userID=%u\n",
               reply.messageType, inet_ntoa(clntAddr.sin_addr), ntohs(clntAddr.sin_port),
               reply.userID);
    }
    /* NOT REACHED */
    close(sock);
    return 0;
}
