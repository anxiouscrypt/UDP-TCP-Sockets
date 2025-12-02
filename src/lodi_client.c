/* Lodi Client: registers its key with PKE and performs login to the Lodi server. */

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

/* Derive a simple RSA-like keypair deterministically from a password. */
static void DieWithError(const char *msg) {
    perror(msg);
    exit(1);
}

/* Prompt for an unsigned int with basic validation. */
static unsigned int prompt_uint(const char *label) {
    char buf[128];
    for (;;) {
        printf("%s", label);
        fflush(stdout);
        if (!fgets(buf, sizeof(buf), stdin)) {
            fprintf(stderr, "[Lodi Client] Input error\n");
            exit(1);
        }
        char *end = NULL;
        unsigned long val = strtoul(buf, &end, 10);
        /* Skip trailing whitespace */
        while (end && *end && (*end == ' ' || *end == '\n' || *end == '\t' || *end == '\r')) {
            end++;
        }
        if (end && *end == '\0' && end != buf) {
            return (unsigned int)val;
        }
        printf("[Lodi Client] Please enter a valid number.\n");
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
    printf("[Lodi Client] Enter password: ");
    fflush(stdout);
    if (!fgets(out, len, stdin)) {
        fprintf(stderr, "[Lodi Client] Input error\n");
        exit(1);
    }
    size_t l = strlen(out);
    if (l && out[l - 1] == '\n') out[l - 1] = '\0';
}

/* Prompt for username and derive numeric userID from it (simple hash). */
static void prompt_username(char *out, size_t len, unsigned int *userID) {
    printf("[Lodi Client] Enter username: ");
    fflush(stdout);
    if (!fgets(out, len, stdin)) {
        fprintf(stderr, "[Lodi Client] Input error\n");
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

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr,
                "Usage: %s <PKE_IP> <PKE_PORT> <LODI_SERVER_IP> <LODI_SERVER_PORT>\n",
                argv[0]);
        exit(1);
    }
    char *pkeIP = argv[1];
    unsigned short pkePort = (unsigned short)atoi(argv[2]);
    char *lodiIP = argv[3];
    unsigned short lodiPort = (unsigned short)atoi(argv[4]);

    unsigned int userID = 0;
    unsigned int pubKey = 0;
    unsigned int privKey = 0;
    char password[128];
    char username[128];
    int logged_in = 0;

    int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) DieWithError("socket() failed");
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in pkeAddr, lodiAddr;
    memset(&pkeAddr, 0, sizeof(pkeAddr));
    pkeAddr.sin_family = AF_INET;
    pkeAddr.sin_addr.s_addr = inet_addr(pkeIP);
    pkeAddr.sin_port = htons(pkePort);

    memset(&lodiAddr, 0, sizeof(lodiAddr));
    lodiAddr.sin_family = AF_INET;
    lodiAddr.sin_addr.s_addr = inet_addr(lodiIP);
    lodiAddr.sin_port = htons(lodiPort);

    /* Main interactive loop. */
    for (;;) {
        printf("\n[Lodi Client] Menu:\n");
        if (!logged_in) {
            printf(" 1) Register Key with PKE Server\n");
            printf(" 2) Login to Lodi Server\n");
            printf(" 3) Exit\n");
        } else {
            printf(" 1) Logout\n");
            printf(" 2) Exit\n");
        }
        printf("Select option: ");
        fflush(stdout);

        int choice = prompt_menu_choice();
        if (choice == 0) {
            fprintf(stderr, "[Lodi Client] Invalid input; exiting\n");
            continue;
        }

        if (!logged_in) {
            if (choice == 3) {
                printf("[Lodi Client] Exiting.\n");
                break;
            } else if (choice == 1) {
                prompt_username(username, sizeof(username), &userID);
                prompt_password(password, sizeof(password));
                derive_keys_from_password(password, &pubKey, &privKey);
                printf("[Lodi Client] Derived keys from password. username=%s userID=%u pubKey=%u privKey=%u\n",
                       username, userID, pubKey, privKey);
                /* Register key with PKE server (retry on timeout). */
                int attempts = 0;
                int reg_ok = 0;
            while (attempts < 3 && !reg_ok) {
                attempts++;
                PClientToPKServer reg;
                memset(&reg, 0, sizeof(reg));
                reg.messageType = registerKey;
                reg.userID = userID;
                reg.publicKey = pubKey;

                if (sendto(sock, &reg, sizeof(reg), 0, (struct sockaddr *)&pkeAddr, sizeof(pkeAddr)) != sizeof(reg)) {
                    perror("[Lodi Client] sendto registerKey failed");
                    break;
                }
                printf("[Lodi Client] Sent registerKey (attempt %d) to PKE Server for user %u\n", attempts, userID);

                PKServerToPClientOrLodiServer regAck;
                struct sockaddr_in from;
                socklen_t fromLen = sizeof(from);
                ssize_t r = recvfrom(sock, &regAck, sizeof(regAck), 0, (struct sockaddr *)&from, &fromLen);
                if (r == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    printf("[Lodi Client] Timeout waiting for ackRegisterKey (attempt %d)\n", attempts);
                    continue;
                }
                if (r != sizeof(regAck) || regAck.messageType != ackRegisterKey) {
                    fprintf(stderr, "[Lodi Client] Failed to receive ackRegisterKey\n");
                    break;
                }
                printf("[Lodi Client] Received ackRegisterKey from PKE Server for user %u\n", regAck.userID);
                reg_ok = 1;
            }
            if (!reg_ok) {
                fprintf(stderr, "[Lodi Client] RegisterKey failed after retries\n");
            }
            } else if (choice == 2) {
                prompt_username(username, sizeof(username), &userID);
                prompt_password(password, sizeof(password));
                derive_keys_from_password(password, &pubKey, &privKey);
                printf("[Lodi Client] Derived keys from password. username=%s userID=%u pubKey=%u privKey=%u\n",
                       username, userID, pubKey, privKey);
                /* Perform login. */
            PClientToLodiServer loginMsg;
            memset(&loginMsg, 0, sizeof(loginMsg));
            loginMsg.messageType = login;
            loginMsg.userID = userID;
                loginMsg.recipientID = 0;
                loginMsg.timestamp = (unsigned long)time(NULL);
                loginMsg.digitalSig = rsa_sign(loginMsg.timestamp, privKey, pubKey);

            int attempts = 0;
            int login_ok = 0;
            while (attempts < 3 && !login_ok) {
                attempts++;
                if (sendto(sock, &loginMsg, sizeof(loginMsg), 0, (struct sockaddr *)&lodiAddr, sizeof(lodiAddr)) != sizeof(loginMsg)) {
                    perror("[Lodi Client] sendto login failed");
                    break;
                }
                printf("[Lodi Client] Sent login (attempt %d) to Lodi Server for user %u\n", attempts, userID);

            LodiServerMessage ack;
            struct sockaddr_in from;
            socklen_t fromLen = sizeof(from);
            ssize_t r = recvfrom(sock, &ack, sizeof(ack), 0, (struct sockaddr *)&from, &fromLen);
            if (r == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                printf("[Lodi Client] Timeout waiting for ackLogin (attempt %d)\n", attempts);
                continue;
            }
            if (r != sizeof(ack) || ack.messageType != ackLogin) {
                fprintf(stderr, "[Lodi Client] Failed to receive valid ackLogin\n");
                break;
            }
            if (ack.userID == userID) {
                logged_in = 1;
                    login_ok = 1;
                    printf("[Lodi Client] Login succeeded for user %u (now logged in)\n", userID);
                } else {
                    printf("[Lodi Client] Login failed for user %u (ack userID=%u)\n", userID, ack.userID);
                    break;
                }
            }
            if (!login_ok) {
                fprintf(stderr, "[Lodi Client] Login failed after retries\n");
            }
        } else {
            printf("[Lodi Client] Unknown option. Please select 1, 2, or 3.\n");
        }
        } else { /* logged in */
            if (choice == 1) {
                logged_in = 0;
                printf("[Lodi Client] Logged out.\n");
                continue;
            } else if (choice == 2) {
                printf("[Lodi Client] Exiting.\n");
                break;
            } else {
                printf("[Lodi Client] Unknown option. Please select 1 or 2.\n");
                continue;
            }
        }
    }

    close(sock);
    return 0;
}
