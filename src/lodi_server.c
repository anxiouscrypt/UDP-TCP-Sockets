/* Lodi Server (Project 2, COSC 439): TCP per-request; login via PKE/TFA; handles follow/unfollow/post/feed/logout. */

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "protocol.h"
#include "util.h"

#define MAX_POSTS 512
#define MAX_FOLLOWS 512
#define MAX_LOGINS 128

typedef struct {
    unsigned int idolID;
    char text[100];
} Post;

typedef struct {
    unsigned int fanID;
    unsigned int idolID;
} FollowEntry;

typedef struct {
    int inUse;
    unsigned int userID;
    struct sockaddr_in addr;
} LoginEntry;

static Post posts[MAX_POSTS];
static int post_count = 0;
static FollowEntry follows[MAX_FOLLOWS];
static int follow_count = 0;
static LoginEntry logins[MAX_LOGINS];

static void DieWithError(const char *msg) {
    perror(msg);
    exit(1);
}

/* UDP: request public key from PKE server. */
static unsigned int request_public_key(int sock, const struct sockaddr_in *pkeAddr, unsigned int userID) {
    PClientToPKServer req;
    memset(&req, 0, sizeof(req));
    req.messageType = requestKey;
    req.userID = userID;
    req.publicKey = 0;

    if (sendto(sock, &req, sizeof(req), 0, (const struct sockaddr *)pkeAddr, sizeof(*pkeAddr)) != sizeof(req)) {
        DieWithError("sendto requestKey failed");
    }
    PKServerToPClientOrLodiServer resp;
    struct sockaddr_in from;
    socklen_t fromLen = sizeof(from);
    ssize_t r = recvfrom(sock, &resp, sizeof(resp), 0, (struct sockaddr *)&from, &fromLen);
    if (r != sizeof(resp)) {
        return 0;
    }
    if (resp.messageType != responsePublicKey || resp.userID != userID) {
        return 0;
    }
    return resp.publicKey;
}

/* UDP: request second factor via TFA server. */
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
    TFAServerToLodiServer resp;
    struct sockaddr_in from;
    socklen_t fromLen = sizeof(from);
    ssize_t r = recvfrom(sock, &resp, sizeof(resp), 0, (struct sockaddr *)&from, &fromLen);
    if (r != sizeof(resp)) {
        return 0;
    }
    return (resp.userID == userID);
}

static void add_follow(unsigned int fan, unsigned int idol) {
    if (follow_count >= MAX_FOLLOWS) return;
    for (int i = 0; i < follow_count; ++i) {
        if (follows[i].fanID == fan && follows[i].idolID == idol) return; /* avoid duplicates */
    }
    follows[follow_count].fanID = fan;
    follows[follow_count].idolID = idol;
    follow_count++;
}

static void remove_follow(unsigned int fan, unsigned int idol) {
    for (int i = 0; i < follow_count; ++i) {
        if (follows[i].fanID == fan && follows[i].idolID == idol) {
            follows[i] = follows[follow_count - 1];
            follow_count--;
            return;
        }
    }
}

static int is_follower(unsigned int fan, unsigned int idol) {
    for (int i = 0; i < follow_count; ++i) {
        if (follows[i].fanID == fan && follows[i].idolID == idol) return 1;
    }
    return 0;
}

static void add_post(unsigned int idol, const char *text) {
    if (post_count >= MAX_POSTS) return;
    posts[post_count].idolID = idol;
    strncpy(posts[post_count].text, text, sizeof(posts[post_count].text) - 1);
    posts[post_count].text[sizeof(posts[post_count].text) - 1] = '\0';
    post_count++;
}

static void add_login(unsigned int userID, const struct sockaddr_in *addr) {
    for (int i = 0; i < MAX_LOGINS; ++i) {
        if (logins[i].inUse && logins[i].userID == userID) {
            logins[i].addr = *addr;
            return;
        }
    }
    for (int i = 0; i < MAX_LOGINS; ++i) {
        if (!logins[i].inUse) {
            logins[i].inUse = 1;
            logins[i].userID = userID;
            logins[i].addr = *addr;
            return;
        }
    }
}

static void remove_login(unsigned int userID) {
    for (int i = 0; i < MAX_LOGINS; ++i) {
        if (logins[i].inUse && logins[i].userID == userID) {
            logins[i].inUse = 0;
            return;
        }
    }
}

/* Send each feed item as its own ackFeed message over the current TCP connection. */
static void send_feed(int clntSock, unsigned int fan) {
    int sent = 0;
    for (int i = 0; i < post_count; ++i) {
        if (is_follower(fan, posts[i].idolID)) {
            LodiServerMessage resp;
            memset(&resp, 0, sizeof(resp));
            resp.messageType = ackFeed;
            resp.userID = fan;
            snprintf(resp.message, sizeof(resp.message), "[%u] %s", posts[i].idolID, posts[i].text);
            send(clntSock, &resp, sizeof(resp), 0);
            printf("[Lodi Server] Sent ackFeed to user %u for idol %u\n", fan, posts[i].idolID);
            sent++;
        }
    }
    if (!sent) {
        LodiServerMessage resp;
        memset(&resp, 0, sizeof(resp));
        resp.messageType = ackFeed;
        resp.userID = fan;
        strncpy(resp.message, "No posts from your idols.", sizeof(resp.message) - 1);
        send(clntSock, &resp, sizeof(resp), 0);
        printf("[Lodi Server] Sent ackFeed (no posts) to user %u\n", fan);
    }
}

static void handle_client(int clntSock, const struct sockaddr_in *clntAddr, int udpSock, const struct sockaddr_in *pkeAddr, const struct sockaddr_in *tfaAddr) {
    PClientToLodiServer req;
    ssize_t n = recv(clntSock, &req, sizeof(req), 0);
    if (n != sizeof(req)) {
        fprintf(stderr, "[Lodi Server] Invalid request size\n");
        return;
    }

    char addrbuf[64];
    fmt_addr(clntAddr, addrbuf, sizeof(addrbuf));
    printf("[Lodi Server] Received messageType=%d from %s for user %u\n", req.messageType, addrbuf, req.userID);

    LodiServerMessage resp;
    memset(&resp, 0, sizeof(resp));

    switch (req.messageType) {
        case login: {
            unsigned int pub = request_public_key(udpSock, pkeAddr, req.userID);
            int authOK = 0;
            if (pub && rsa_verify(req.digitalSig, req.timestamp, RSA_PUBLIC_EXP, pub)) {
                authOK = request_tfa(udpSock, tfaAddr, req.userID);
            }
            resp.messageType = ackLogin;
            resp.userID = authOK ? req.userID : 0;
            if (authOK) {
                add_login(req.userID, clntAddr);
            }
            printf("[Lodi Server] Sent ackLogin to %s for user %u (status=%s)\n",
                   addrbuf, req.userID, authOK ? "success" : "failure");
            break;
        }
        case follow: {
            add_follow(req.userID, req.recipientID);
            resp.messageType = ackFollow;
            resp.userID = req.userID;
            printf("[Lodi Server] Processed follow: fan %u -> idol %u\n", req.userID, req.recipientID);
            break;
        }
        case unfollow: {
            remove_follow(req.userID, req.recipientID);
            resp.messageType = ackUnfollow;
            resp.userID = req.userID;
            printf("[Lodi Server] Processed unfollow: fan %u -> idol %u\n", req.userID, req.recipientID);
            break;
        }
        case post: {
            add_post(req.userID, req.message);
            resp.messageType = ackPost;
            resp.userID = req.userID;
            strncpy(resp.message, "OK", sizeof(resp.message) - 1);
            printf("[Lodi Server] Stored post from user %u: \"%s\"\n", req.userID, req.message);
            break;
        }
        case feed: {
            send_feed(clntSock, req.userID);
            return; /* feed sends all data itself */
        }
        case logout: {
            resp.messageType = ackLogout;
            resp.userID = req.userID;
            remove_login(req.userID);
            printf("[Lodi Server] Logged out user %u\n", req.userID);
            break;
        }
        default:
            fprintf(stderr, "[Lodi Server] Unknown messageType=%d\n", req.messageType);
            return;
    }

    send(clntSock, &resp, sizeof(resp), 0);
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <LODI_TCP_PORT> <PKE_IP> <PKE_PORT> <TFA_IP:TFA_PORT>\n", argv[0]);
        exit(1);
    }

    /* Line-buffer stdout so logs appear immediately. */
    setvbuf(stdout, NULL, _IOLBF, 0);

    unsigned short tcpPort = (unsigned short)atoi(argv[1]);
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

    int udpSock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udpSock < 0) DieWithError("udp socket() failed");

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

    int listenSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock < 0) DieWithError("tcp socket() failed");
    int opt = 1;
    setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in servAddr;
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(tcpPort);

    if (bind(listenSock, (struct sockaddr *)&servAddr, sizeof(servAddr)) < 0) DieWithError("bind() failed");
    if (listen(listenSock, 5) < 0) DieWithError("listen() failed");

    printf("[Lodi Server] Listening on TCP port %u; PKE %s:%u; TFA %s:%u\n", tcpPort, pkeIP, pkePort, tfaIP, tfaPort);

    for (;;) {
        struct sockaddr_in clntAddr;
        socklen_t clntLen = sizeof(clntAddr);
        int clntSock = accept(listenSock, (struct sockaddr *)&clntAddr, &clntLen);
        if (clntSock < 0) {
            perror("accept() failed");
            continue;
        }
        handle_client(clntSock, &clntAddr, udpSock, &pkeAddr, &tfaAddr);
        close(clntSock);
    }

    close(listenSock);
    close(udpSock);
    return 0;
}
