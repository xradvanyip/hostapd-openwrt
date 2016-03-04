#ifndef _ASLAN_DEFS_H
#define _ASLAN_DEFS_H

#include <stdint.h>
#include <netinet/in.h>

#define ASLAN_PROTOCOL_PORT    0x2016  //decimal: 8214

/* ASLAN message definitions */
#define MSG_ID_HELLO         0
#define MSG_ID_CTX_REQ       1
#define MSG_ID_AUTH_REQ      2
#define MSG_ID_ASSOC_RESP    3
#define MSG_ID_DISASSOC_RESP 4
#define MSG_ID_SIG_RESP      5
#define MSG_ID_INIT_RESP     6
#define MSG_ID_CTX_RESP      7
#define MSG_ID_AUTH_RESP     8
#define MSG_ID_HAND_REQ      9
#define MSG_ID_REL_REQ       10
#define MSG_ID_FLUSH_REQ     11
#define MSG_ID_ACK           12

#define MSG_LENGTH_HELLO         1
#define MSG_LENGTH_CTX_REQ       7
#define MSG_LENGTH_AUTH_REQ
#define MSG_LENGTH_ASSOC_RESP    1007
#define MSG_LENGTH_DISASSOC_RESP 7
#define MSG_LENGTH_SIG_RESP      8
#define MSG_LENGTH_INIT_RESP     17
#define MSG_LENGTH_CTX_RESP      13
#define MSG_LENGTH_AUTH_RESP
#define MSG_LENGTH_HAND_REQ      1013
#define MSG_LENGTH_REL_REQ       7
#define MSG_LENGTH_FLUSH_REQ     1
#define MSG_LENGTH_ACK           2


/* ASLAN Hello Message */
typedef struct aslan_hello_t_ {
} aslan_hello_t;

/* ASLAN abstract message */
typedef struct aslan_msg_t_ {
    in_addr_t sender_ip;
    in_port_t sender_port;
    uint8_t msg_id;
    union {
        aslan_hello_t *hello;
        // ...
    } msg;
} aslan_msg_t;

#endif
