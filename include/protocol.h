#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

/* Message types and structures shared by all components.
 * Keep enums/fields aligned with the assignment spec; they travel directly over UDP.
 */

/* Messages from Lodi client to PKE server. */
typedef struct {
    enum { registerKey = 0, requestKey = 1 } messageType; /* same size as unsigned int */
    unsigned int userID;                                  /* user identifier or requested user identifier */
    unsigned int publicKey;                               /* user's public key or 0 if message_type is requestKey */
} PClientToPKServer;

/* Messages from PKE server to Lodi client or Lodi server. */
typedef struct {
    enum { ackRegisterKey = 0, responsePublicKey = 1 } messageType; /* same size as unsigned int */
    unsigned int userID;                                           /* user identifier or requested user identifier */
    unsigned int publicKey;                                        /* registered public key or requested public key */
} PKServerToPClientOrLodiServer;

/* Messages from Lodi client to Lodi server. */
typedef struct {
    enum { login = 0, post = 1, feed = 2, follow = 3, unfollow = 4, logout = 5 } messageType; /* unsigned int sized */
    unsigned int userID;             /* user identifier */
    unsigned int recipientID;        /* message recipient identifier (idol for follow/unfollow, 0 otherwise) */
    unsigned long timestamp;         /* timestamp or random int for login signature */
    unsigned long digitalSig;        /* encrypted timestamp */
    char message[100];               /* text message payload (post/feed) */
} PClientToLodiServer;

/* Messages from Lodi server to Lodi client. */
typedef struct {
    enum { ackLogin = 0, ackPost = 1, ackFeed = 2, ackFollow = 3, ackUnfollow = 4, ackLogout = 5 } messageType; /* unsigned int sized */
    unsigned int userID;               /* user identifier (or 0 on failure) */
    char message[100];                 /* optional text (feed data or status) */
} LodiServerMessage;

/* Messages from TFA client or Lodi server to TFA server. */
typedef struct {
    enum { registerTFA = 0, ackRegTFA = 1, ackPushTFA = 2, requestAuth = 3 } messageType; /* unsigned int sized */
    unsigned int userID;                                                                    /* user identifier */
    unsigned long timestamp;                                                                /* timestamp */
    unsigned long digitalSig;                                                               /* encrypted timestamp/random int */
} TFAClientOrLodiServerToTFAServer;

/* Messages from TFA server to TFA client. */
typedef struct {
    enum { confirmTFA = 0, pushTFA = 1 } messageType; /* unsigned int sized */
    unsigned int userID;                              /* user identifier */
} TFAServerToTFAClient;

/* Messages from TFA server to Lodi server. */
typedef struct {
    enum { responseAuth = 0 } messageType; /* unsigned int sized */
    unsigned int userID;                   /* user identifier */
} TFAServerToLodiServer;

/* Compile-time checks: enums must match unsigned int size on this platform. */
_Static_assert(sizeof(((PClientToPKServer *)0)->messageType) == sizeof(unsigned int), "enum size mismatch");
_Static_assert(sizeof(((PKServerToPClientOrLodiServer *)0)->messageType) == sizeof(unsigned int), "enum size mismatch");
_Static_assert(sizeof(((PClientToLodiServer *)0)->messageType) == sizeof(unsigned int), "enum size mismatch");
_Static_assert(sizeof(((LodiServerMessage *)0)->messageType) == sizeof(unsigned int), "enum size mismatch");
_Static_assert(sizeof(((TFAClientOrLodiServerToTFAServer *)0)->messageType) == sizeof(unsigned int), "enum size mismatch");
_Static_assert(sizeof(((TFAServerToTFAClient *)0)->messageType) == sizeof(unsigned int), "enum size mismatch");
_Static_assert(sizeof(((TFAServerToLodiServer *)0)->messageType) == sizeof(unsigned int), "enum size mismatch");

#endif /* PROTOCOL_H */
