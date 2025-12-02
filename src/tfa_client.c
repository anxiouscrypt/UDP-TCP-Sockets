/* TFA Client: registers with the TFA server and responds to push challenges. */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include "protocol.h"
#include "util.h"

static void DieWithError(const char *msg) {
    perror(msg);
    exit(1);
}

/* Prompt for an unsigned int with validation. */
static unsigned int prompt_uint(const char *label) {
    char buf[128];
    for (;;) {
        printf("%s", label);
        fflush(stdout);
        if (!fgets(buf, sizeof(buf), stdin)) {
            fprintf(stderr, "[TFA Client] Input error\n");
            exit(1);
        }
        char *end = NULL;
        unsigned long val = strtoul(buf, &end, 10);
        while (end && *end && (*end == ' ' || *end == '\n' || *end == '\t' || *end == '\r')) {
            end++;
        }
        if (end && *end == '\0' && end != buf) {
            return (unsigned int)val;
        }
        printf("[TFA Client] Please enter a valid number.\n");
    }
}

/* Prompt for a small integer menu choice. */
static int prompt_menu_choice(void) {
    char buf[32];
    if (!fgets(buf, sizeof(buf), stdin)) {
        return 0;
    }
    return (int)strtol(buf, NULL, 10);
}

static void prompt_password(char *out, size_t len) {
    printf("[TFA Client] Enter password: ");
    fflush(stdout);
    if (!fgets(out, len, stdin)) {
        fprintf(stderr, "[TFA Client] Input error\n");
        exit(1);
    }
    size_t l = strlen(out);
    if (l && out[l - 1] == '\n') out[l - 1] = '\0';
}

/* Prompt for username and derive numeric userID (simple hash). */
static void prompt_username(char *out, size_t len, unsigned int *userID) {
    printf("[TFA Client] Enter username: ");
    fflush(stdout);
    if (!fgets(out, len, stdin)) {
        fprintf(stderr, "[TFA Client] Input error\n");
        exit(1);
    }
    size_t l = strlen(out);
    if (l && out[l - 1] == '\n') out[l - 1] = '\0';
    unsigned long h = 5381;
    for (const char *p = out; *p; ++p) {
        h = ((h << 5) + h) + (unsigned long)(unsigned char)(*p);
    }
    *userID = (unsigned int)(h & 0xFFFFFFFFu);
}

static int register_tfa(int sock, const struct sockaddr_in *servAddr, unsigned int userID,
                        unsigned int pubKey, unsigned int privKey) {
    /* Step 1: registerTFA (3-way handshake start) */
    unsigned long randomInt = (unsigned long)(rand() % 1000000u + 1u);
    TFAClientOrLodiServerToTFAServer reg;
    memset(&reg, 0, sizeof(reg));
    reg.messageType = registerTFA;
    reg.userID = userID;
    reg.timestamp = randomInt; /* carry the random integer per spec */
    reg.digitalSig = rsa_sign(randomInt, privKey, pubKey); /* DS over randomInt */

    /* Set a short timeout for confirmTFA wait. */
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int attempts = 0;
    int ok = 0;
    while (attempts < 3 && !ok) {
        attempts++;
        if (sendto(sock, &reg, sizeof(reg), 0, (struct sockaddr *)servAddr, sizeof(*servAddr)) != sizeof(reg)) {
            perror("[TFA Client] sendto registerTFA failed");
            return 0;
        }
        printf("[TFA Client] Sent registerTFA (attempt %d) to TFA Server for user %u\n", attempts, userID);

        /* Wait for confirmTFA from server. */
        TFAServerToTFAClient confirm;
        struct sockaddr_in from;
        socklen_t fromLen = sizeof(from);
        ssize_t r = recvfrom(sock, &confirm, sizeof(confirm), 0, (struct sockaddr *)&from, &fromLen);
        if (r == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            printf("[TFA Client] Timeout waiting for confirmTFA (attempt %d)\n", attempts);
            continue;
        }
        if (r != sizeof(confirm) || confirm.messageType != confirmTFA || confirm.userID != userID) {
            fprintf(stderr, "[TFA Client] Failed to receive valid confirmTFA\n");
            return 0;
        }
        printf("[TFA Client] Received confirmTFA from TFA Server for user %u\n", confirm.userID);

        /* Send ackRegTFA to complete registration. */
        TFAClientOrLodiServerToTFAServer ack;
        memset(&ack, 0, sizeof(ack));
        ack.messageType = ackRegTFA;
        ack.userID = userID;
        ack.timestamp = 0;
        ack.digitalSig = 0;
        if (sendto(sock, &ack, sizeof(ack), 0, (struct sockaddr *)servAddr, sizeof(*servAddr)) != sizeof(ack)) {
            perror("[TFA Client] sendto ackRegTFA failed");
            return 0;
        }
        printf("[TFA Client] Sent ackRegTFA to TFA Server for user %u (registration complete)\n", userID);
        ok = 1;
    }
    return ok;
}

static void listen_for_pushes(int sock, const struct sockaddr_in *servAddr) {
    struct sockaddr_in from;
    socklen_t fromLen = sizeof(from);
    for (;;) {
        TFAServerToTFAClient push;
        ssize_t n = recvfrom(sock, &push, sizeof(push), 0, (struct sockaddr *)&from, &fromLen);
        if (n != sizeof(push) || push.messageType != pushTFA) continue;
        printf("[TFA Client] Received pushTFA for user %u (TFA push event)\n", push.userID);

        TFAClientOrLodiServerToTFAServer ackPush;
        memset(&ackPush, 0, sizeof(ackPush));
        ackPush.messageType = ackPushTFA;
        ackPush.userID = push.userID;
        ackPush.timestamp = 0;
        ackPush.digitalSig = 0;

        if (sendto(sock, &ackPush, sizeof(ackPush), 0, (struct sockaddr *)servAddr, sizeof(*servAddr)) != sizeof(ackPush)) {
            perror("[TFA Client] sendto ackPushTFA failed");
            continue;
        }
        printf("[TFA Client] Sent ackPushTFA for user %u (authentication response)\n", push.userID);
        /* Continue waiting for future pushTFA messages. */
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <TFA_SERVER_IP> <TFA_SERVER_PORT>\n", argv[0]);
        exit(1);
    }
    char *servIP = argv[1];
    unsigned short servPort = (unsigned short)atoi(argv[2]);

    /* Seed RNG for randomInt generation in registerTFA. */
    srand((unsigned int)time(NULL) ^ (unsigned int)getpid());

    unsigned int userID = 0;
    unsigned int pubKey = 0;
    unsigned int privKey = 0;
    char password[128];
    char username[128];
    int registered = 0;
    int logged_in = 0;

    int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) DieWithError("socket() failed");

    struct sockaddr_in servAddr;
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = inet_addr(servIP);
    servAddr.sin_port = htons(servPort);

    /* One-time register-or-exit flow, then wait for pushes if registered. */
    for (;;) {
        printf("\n[TFA Client] Menu:\n");
        printf(" 1) Register TFA\n");
        printf(" 2) Exit\n");
        printf("Select option: ");
        fflush(stdout);

        int choice = prompt_menu_choice();
        if (choice == 0) {
            fprintf(stderr, "[TFA Client] Invalid input; exiting\n");
            break;
        }
        if (choice == 2) {
            printf("[TFA Client] Exiting.\n");
            close(sock);
            return 0;
        }
        if (choice == 1) {
            prompt_username(username, sizeof(username), &userID);
            prompt_password(password, sizeof(password));
            derive_keys_from_password(password, &pubKey, &privKey);
            printf("[TFA Client] Derived keys from password. username=%s userID=%u pubKey=%u privKey=%u\n",
                   username, userID, pubKey, privKey);
            registered = register_tfa(sock, &servAddr, userID, pubKey, privKey);
            if (!registered) {
                printf("[TFA Client] Registration failed; returning to menu.\n");
                continue;
            }
            printf("[TFA Client] Registration succeeded; waiting for pushTFA messages...\n");
            break;
        }
        printf("[TFA Client] Unknown option. Please select 1 or 2.\n");
    }

    if (registered) {
        listen_for_pushes(sock, &servAddr);
    }

    close(sock);
    return 0;
}
