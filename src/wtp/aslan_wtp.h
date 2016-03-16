#ifndef _ASLAN_WTP
#define _ASLAN_WTP

#include <pthread.h>
#include <net/if.h>
#include <stdbool.h>

#include "aslan_defs.h"
#include "pipe.h"

/*
 * Typedef
 */
 
typedef int (*wtp_aslan_msg_cb)(aslan_msg_t* msg);

typedef struct wtp_handle_t_ {
    char device[IFNAMSIZ];

    pthread_t receive_thread;
    pthread_t process_thread;

    pipe_producer_t* msg_recv_producer;
    pipe_producer_t* msg_send_producer;
    pipe_consumer_t* msg_recv_consumer;
    pipe_consumer_t* msg_send_consumer;

    pthread_mutex_t hello_mutex;
    bool hello_thread_running;
    unsigned int hello_interval_seconds;
    pthread_t hello_thread;

    pthread_mutex_t udp_mutex;
    int udp_socket;
    
    uint32_t local_ip;
    uint16_t local_port;

    unsigned char hds_mac[6];
    uint32_t hds_ip;
    uint16_t hds_port;
    struct sockaddr_in hds_inet_addr;

    wtp_aslan_msg_cb msg_cb;
} wtp_handle_t;


/*
 * Functions
 */
 
wtp_handle_t* wtp_alloc(const char* device, wtp_aslan_msg_cb msg_cb);
int close_wtp(wtp_handle_t* handle);

int wtp_start_hello_thread(wtp_handle_t* handle);
int wtp_stop_hello_thread(wtp_handle_t* handle);

int wtp_send_hello_msg(wtp_handle_t* handle);
int wtp_send_ack(wtp_handle_t* handle, uint8_t flag);

inline int mac_cmp(char mac1[6], char mac2[6]);

#endif
