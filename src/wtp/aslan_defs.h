#ifndef _ASLAN_DEFS_H
#define _ASLAN_DEFS_H

#include <stdint.h>
#include <netinet/in.h>

#define ASLAN_PROTOCOL_PORT    0x2016  //decimal: 8214
#define WAIT_FOR_ACK_INTERVAL  2

/* WTP states */
#define WTP_STATE_NONE         0
#define WTP_STATE_INITIALISED  1

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

/* ASLAN Context Request */
typedef struct aslan_ctx_req_t_ {
	unsigned char MAC[6];
} aslan_ctx_req_t;

/* ASLAN Association Response */
typedef struct aslan_assoc_resp_t_ {
	unsigned char MAC[6];
	void* sta_wtp_ctx;
	uint16_t sta_wtp_ctx_length;
} aslan_assoc_resp_t;

/* ASLAN Disassociation Response */
typedef struct aslan_disassoc_resp_t_ {
	unsigned char MAC[6];
} aslan_disassoc_resp_t;

/* ASLAN Signal Response */
typedef struct aslan_sig_resp_t_ {
	unsigned char MAC[6];
	uint8_t RSSI;
} aslan_sig_resp_t;

/* ASLAN Initialisation Response */
typedef struct aslan_init_resp_t_ {
	uint8_t channel_num;
	uint8_t* SSID;
	uint8_t ssid_length;
} aslan_init_resp_t;

/* ASLAN Context Response */
typedef struct aslan_ctx_resp_t_ {
	unsigned char MAC[6];
	unsigned char BSSID[6];
} aslan_ctx_resp_t;

/* ASLAN Handover Request */
typedef struct aslan_hand_req_t_ {
	unsigned char MAC[6];
	unsigned char BSSID[6];
	void* sta_wtp_ctx;
	uint16_t sta_wtp_ctx_length;
} aslan_hand_req_t;

/* ASLAN Release Request */
typedef struct aslan_rel_req_t_ {
	unsigned char MAC[6];
} aslan_rel_req_t;

/* ASLAN Flush Request */
typedef struct aslan_flush_req_t_ {
} aslan_flush_req_t;

/* ASLAN Acknowledgement */
typedef struct aslan_ack_t_ {
	uint8_t flag;
} aslan_ack_t;

/* ASLAN abstract message */
typedef struct aslan_msg_t_ {
    in_addr_t sender_ip;
    in_port_t sender_port;
    uint8_t msg_id;
	uint8_t msg_length;
    union {
        aslan_hello_t *hello;
		aslan_ctx_req_t *ctx_req;
		aslan_assoc_resp_t *assoc_resp;
		aslan_disassoc_resp_t *disassoc_resp;
		aslan_sig_resp_t *sig_resp;
		aslan_init_resp_t *init_resp;
		aslan_ctx_resp_t *ctx_resp;
		aslan_hand_req_t *hand_req;
		aslan_rel_req_t *rel_req;
		aslan_flush_req_t *flush_req;
		aslan_ack_t *ack;
    } msg;
} aslan_msg_t;

#endif
