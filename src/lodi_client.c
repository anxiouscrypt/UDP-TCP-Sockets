/* Lodi Client (Project 2, COSC 439): UDP to register key with PKE; TCP per-request to Lodi server for login/follow/unfollow/post/feed/logout; keeps Project 1 auth (PKE+TFA). */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "protocol.h"
#include "util.h"

static void DieWithError(const char *msg) {
    perror(msg);
    exit(1);
}

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
        while (end && *end && (*end == ' ' || *end == '\n' || *end == '\t' || *end == '\r')) {
            end++;
        }
        if (end && *end == '\0' && end != buf) {
            return (unsigned int)val;
        }
        printf("[Lodi Client] Please enter a valid number.\n");
    }
}

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

/* Derive userID from an arbitrary username string (same hash as prompt_username). */
static unsigned int user_id_from_name(const char *name) {
    unsigned long h = 5381;
    for (const char *p = name; *p; ++p) {
        h = ((h << 5) + h) + (unsigned long)(unsigned char)(*p);
    }
    return (unsigned int)(h & 0xFFFFFFFFu);
}

/* Prompt for an idol's username and return its hashed userID. */
static unsigned int prompt_idol_user(char *nameBuf, size_t nameLen) {
    printf("[Lodi Client] Enter idol username: ");
    fflush(stdout);
    if (!fgets(nameBuf, nameLen, stdin)) {
        fprintf(stderr, "[Lodi Client] Input error\n");
        return 0;
    }
    size_t l = strlen(nameBuf);
    if (l && nameBuf[l - 1] == '\n') nameBuf[l - 1] = '\0';
    return user_id_from_name(nameBuf);
}

static int send_tcp_request(const char *serverIP, unsigned short serverPort,
                            const PClientToLodiServer *req, LodiServerMessage *resp) {
    int sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        perror("[Lodi Client] socket TCP failed");
        return 0;
    }
    struct sockaddr_in servAddr;
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = inet_addr(serverIP);
    servAddr.sin_port = htons(serverPort);
    if (connect(sock, (struct sockaddr *)&servAddr, sizeof(servAddr)) < 0) {
        perror("[Lodi Client] connect failed");
        close(sock);
        return 0;
    }
    if (send(sock, req, sizeof(*req), 0) != sizeof(*req)) {
        perror("[Lodi Client] send request failed");
        close(sock);
        return 0;
    }
    ssize_t r = recv(sock, resp, sizeof(*resp), 0);
    close(sock);
    if (r != sizeof(*resp)) {
        fprintf(stderr, "[Lodi Client] recv response failed (got %zd bytes)\n", r);
        return 0;
    }
    return 1;
}

/* Specialized feed request: reads all ackFeed messages until server closes the connection. */
static int request_feed(const char *serverIP, unsigned short serverPort, const PClientToLodiServer *req) {
    int sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        perror("[Lodi Client] socket TCP failed");
        return 0;
    }
    struct sockaddr_in servAddr;
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = inet_addr(serverIP);
    servAddr.sin_port = htons(serverPort);
    if (connect(sock, (struct sockaddr *)&servAddr, sizeof(servAddr)) < 0) {
        perror("[Lodi Client] connect failed");
        close(sock);
        return 0;
    }
    if (send(sock, req, sizeof(*req), 0) != sizeof(*req)) {
        perror("[Lodi Client] send request failed");
        close(sock);
        return 0;
    }
    int got = 0;
    for (;;) {
        LodiServerMessage resp;
        ssize_t r = recv(sock, &resp, sizeof(resp), 0);
        if (r == 0) break;          /* server closed connection */
        if (r < 0) {                /* error */
            perror("[Lodi Client] recv feed failed");
            break;
        }
        if (r != sizeof(resp)) {
            fprintf(stderr, "[Lodi Client] Ignoring partial feed message (%zd bytes)\n", r);
            continue;
        }
        if (resp.messageType == ackFeed && resp.userID == req->userID) {
            unsigned int idolID = 0;
            const char *body = resp.message;
            if (resp.message[0] == '[') {
                sscanf(resp.message, "[%u]", &idolID);
                char *closing = strchr(resp.message, ']');
                if (closing) {
                    body = closing + 1;
                    if (*body == ' ') body++;
                }
            }
            if (idolID != 0) {
                printf("[Lodi Client] Idol Post from user%u: %s\n", idolID, body);
            } else {
                printf("[Lodi Client] Idol Post: %s\n", body);
            }
            got = 1;
        }
    }
    close(sock);
    return got;
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

    /* UDP socket for PKE registerKey */
    int udpSock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udpSock < 0) DieWithError("socket() failed");
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(udpSock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in pkeAddr;
    memset(&pkeAddr, 0, sizeof(pkeAddr));
    pkeAddr.sin_family = AF_INET;
    pkeAddr.sin_addr.s_addr = inet_addr(pkeIP);
    pkeAddr.sin_port = htons(pkePort);

    for (;;) {
        printf("\n[Lodi Client] Menu:\n");
        if (!logged_in) {
            printf(" 1) Register for Lodi\n");
            printf(" 2) Login to Lodi\n");
            printf(" 3) Exit\n");
        } else {
            printf(" 1) Follow idol\n");
            printf(" 2) Unfollow idol\n");
            printf(" 3) Post message\n");
            printf(" 4) Request feed\n");
            printf(" 5) Logout\n");
            printf(" 6) Exit\n");
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
                int attempts = 0;
                int reg_ok = 0;
                while (attempts < 3 && !reg_ok) {
                    attempts++;
                    PClientToPKServer reg;
                    memset(&reg, 0, sizeof(reg));
                    reg.messageType = registerKey;
                    reg.userID = userID;
                    reg.publicKey = pubKey;

                    if (sendto(udpSock, &reg, sizeof(reg), 0, (struct sockaddr *)&pkeAddr, sizeof(pkeAddr)) != sizeof(reg)) {
                        perror("[Lodi Client] sendto registerKey failed");
                        break;
                    }
                    printf("[Lodi Client] Sent registerKey (attempt %d) to PKE Server for user %u\n", attempts, userID);

                    PKServerToPClientOrLodiServer regAck;
                    struct sockaddr_in from;
                    socklen_t fromLen = sizeof(from);
                    ssize_t r = recvfrom(udpSock, &regAck, sizeof(regAck), 0, (struct sockaddr *)&from, &fromLen);
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
                    LodiServerMessage ack;
                    if (!send_tcp_request(lodiIP, lodiPort, &loginMsg, &ack)) {
                        fprintf(stderr, "[Lodi Client] Failed to send/recv login (attempt %d)\n", attempts);
                        continue;
                    }
                    if (ack.messageType != ackLogin || ack.userID != userID) {
                        printf("[Lodi Client] Login failed for user %u\n", userID);
                    } else {
                        logged_in = 1;
                        login_ok = 1;
                        printf("[Lodi Client] Login succeeded for user %u (now logged in)\n", userID);
                    }
                }
                if (!login_ok) {
                    fprintf(stderr, "[Lodi Client] Login failed after retries\n");
                }
            } else {
                printf("[Lodi Client] Unknown option. Please select 1, 2, or 3.\n");
            }
        } else {
            if (choice == 1) { /* follow */
                char idolName[128];
                unsigned int idol = prompt_idol_user(idolName, sizeof(idolName));
                PClientToLodiServer req;
                memset(&req, 0, sizeof(req));
                req.messageType = follow;
                req.userID = userID;
                req.recipientID = idol;
                LodiServerMessage resp;
                if (send_tcp_request(lodiIP, lodiPort, &req, &resp) && resp.messageType == ackFollow && resp.userID == userID) {
                    printf("[Lodi Client] Followed idol \"%s\" (user%u)\n", idolName, idol);
                } else {
                    printf("[Lodi Client] Failed to follow idol \"%s\" (user%u)\n", idolName, idol);
                }
            } else if (choice == 2) { /* unfollow */
                char idolName[128];
                unsigned int idol = prompt_idol_user(idolName, sizeof(idolName));
                PClientToLodiServer req;
                memset(&req, 0, sizeof(req));
                req.messageType = unfollow;
                req.userID = userID;
                req.recipientID = idol;
                LodiServerMessage resp;
                if (send_tcp_request(lodiIP, lodiPort, &req, &resp) && resp.messageType == ackUnfollow && resp.userID == userID) {
                    printf("[Lodi Client] Unfollowed idol \"%s\" (user%u)\n", idolName, idol);
                } else {
                    printf("[Lodi Client] Failed to unfollow idol \"%s\" (user%u)\n", idolName, idol);
                }
            } else if (choice == 3) { /* post */
                char text[100];
                printf("[Lodi Client] Enter message (max 99 chars): ");
                fflush(stdout);
                if (!fgets(text, sizeof(text), stdin)) {
                    printf("[Lodi Client] Input error\n");
                    continue;
                }
                size_t l = strlen(text);
                if (l && text[l - 1] == '\n') text[l - 1] = '\0';
                PClientToLodiServer req;
                memset(&req, 0, sizeof(req));
                req.messageType = post;
                req.userID = userID;
                strncpy(req.message, text, sizeof(req.message) - 1);
                LodiServerMessage resp;
                if (send_tcp_request(lodiIP, lodiPort, &req, &resp) && resp.messageType == ackPost && resp.userID == userID) {
                    printf("[Lodi Client] Post acknowledged\n");
                } else {
                    printf("[Lodi Client] Post failed\n");
                }
            } else if (choice == 4) { /* feed */
                PClientToLodiServer req;
                memset(&req, 0, sizeof(req));
                req.messageType = feed;
                req.userID = userID;
                int ok = request_feed(lodiIP, lodiPort, &req);
                if (!ok) printf("[Lodi Client] Feed request failed or no items.\n");
            } else if (choice == 5) { /* logout */
                PClientToLodiServer req;
                memset(&req, 0, sizeof(req));
                req.messageType = logout;
                req.userID = userID;
                LodiServerMessage resp;
                if (send_tcp_request(lodiIP, lodiPort, &req, &resp) && resp.messageType == ackLogout) {
                    printf("[Lodi Client] Logged out.\n");
                    logged_in = 0;
                } else {
                    printf("[Lodi Client] Logout failed.\n");
                }
            } else if (choice == 6) {
                printf("[Lodi Client] Exiting.\n");
                break;
            } else {
                printf("[Lodi Client] Unknown option. Please select 1-6.\n");
                continue;
            }
        }
    }

    close(udpSock);
    return 0;
}
