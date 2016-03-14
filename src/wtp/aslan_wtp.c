#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/udp.h>
#include <net/if_arp.h>
#include <linux/if_ether.h>
#include <linux/sockios.h>
#include <arpa/inet.h>
#include <assert.h>
#include <unistd.h>

#include "includes.h"
#include "common.h"
#include "crc32.h"
#include "aslan_wtp.h"

static void *receive_msg_thread(void *arg);
static void *hello_thread(void *arg);

wtp_handle_t* wtp_alloc(const char* device, wtp_aslan_msg_cb msg_cb)
{
    if ((!device) || (!msg_cb))
	{
        errno = EINVAL;
		return NULL;
    }

    int ret = -1;

    wtp_handle_t *handle = calloc(1, sizeof(wtp_handle_t));
    if (!handle)
	{
        errno = ENOMEM;
		return NULL;
    }

    handle->msg_cb = msg_cb;

    //for testing purposes only
    char hds_ip[] = "192.168.1.10";
    handle->hds_port = ASLAN_PROTOCOL_PORT;
    handle->hello_interval_seconds = 5;

    /* UDP socket */
    int s = -1;
    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
        free(handle);
		return NULL;
    }
    handle->udp_socket = s;

    ret = pthread_mutex_init(&handle->udp_mutex, NULL);
    if (ret != 0)
	{
        close(handle->udp_socket);
        free(handle);
		return NULL;
    }

    /* HDS parameters */
    handle->hds_inet_addr.sin_family = AF_INET;
    if (!inet_aton(hds_ip, (struct in_addr*) &(handle->hds_inet_addr.sin_addr.s_addr)))
	{
        errno = EINVAL;
        pthread_mutex_destroy(&handle->udp_mutex);
        close(handle->udp_socket);
        free(handle);
		return NULL;
    }
    handle->hds_ip = ntohl(handle->hds_inet_addr.sin_addr.s_addr);

    /* interface name */
    strncpy(handle->device, device, IFNAMSIZ - 1);

    /* interface IP */
    struct ifreq ifr;
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, device, IFNAMSIZ - 1);
    if (ioctl(handle->udp_socket, SIOCGIFADDR, &ifr) == -1)
	{
        pthread_mutex_destroy(&handle->udp_mutex);
        close(handle->udp_socket);
        free(handle);
		return NULL;
    }
    handle->local_ip = ntohl(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr);

    /* HDS sockaddr_in structure */
    handle->hds_inet_addr.sin_addr.s_addr = htonl(handle->hds_ip);
    handle->hds_inet_addr.sin_family  = AF_INET;
    handle->hds_inet_addr.sin_port = htons(handle->hds_port);

    /* UDP socket local port */
    struct sockaddr_in address;
    memset((char*) &address, 0, sizeof(address));
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = 0;
    address.sin_family = AF_INET;
    bind(handle->udp_socket, (struct sockaddr*) &address, sizeof(address));

    struct sockaddr_in sin = {0};
    socklen_t len = sizeof(sin);
    if (getsockname(handle->udp_socket, (struct sockaddr*)&sin, &len) == -1)
	{
        pthread_mutex_destroy(&handle->udp_mutex);
        close(handle->udp_socket);
        free(handle);
		return NULL;
    }
    handle->local_port = ntohs(sin.sin_port);
	wpa_printf(MSG_INFO, "INFO: UDP socket for ASLAN messages created, listening on port: %d\n", handle->local_port);

    /* start receiving thread for ASLAN messages */
    ret = pthread_create(&(handle->receive_thread), NULL, receive_msg_thread, (void*)handle);
    if (ret != 0)
	{
        errno = ENOMEM;
        pthread_mutex_destroy(&handle->udp_mutex);
        close(handle->udp_socket);
        free(handle);
		return NULL;
    }
	wpa_printf(MSG_INFO, "DEBUG: receiving thread for ASLAN messages created\n");

    /* obtain HDS MAC address by a Hello message */
    if (wtp_send_hello_msg(handle) == -1)
	{
        pthread_cancel(handle->receive_thread);
        pthread_mutex_destroy(&handle->udp_mutex);
        close(handle->udp_socket);
        free(handle);
		return NULL;
    }

    /* Check ARP cache */
    if (handle->local_ip != handle->hds_ip)
    {
        struct arpreq areq;
        memset(&areq, 0, sizeof(areq));
        struct sockaddr_in* sockaddr = NULL;
        sockaddr = (struct sockaddr_in*) &(areq.arp_pa);
        sockaddr->sin_family = AF_INET;
        sockaddr->sin_addr.s_addr = htonl(handle->hds_ip);
        sockaddr = (struct sockaddr_in*) &(areq.arp_ha);
        sockaddr->sin_family = ARPHRD_ETHER;
        strncpy(areq.arp_dev, device, IFNAMSIZ - 1);

        int i = 0;
        unsigned char mac_loopback[] = {0, 0, 0, 0, 0, 0};

        ioctl(s, SIOCGARP, (caddr_t) &areq);
        while ((i < 5) && (mac_cmp(areq.arp_ha.sa_data, mac_loopback)))
		{
            i++;
            sleep(1);
            ioctl(s, SIOCGARP, (caddr_t) &areq);
        }

        memcpy(handle->hds_mac, areq.arp_ha.sa_data, 6);

        if (mac_cmp(areq.arp_ha.sa_data, mac_loopback)) wpa_printf(MSG_WARNING, "WARNING: HDS MAC address obtaining failed\n");
        else wpa_printf(MSG_INFO, "INFO: HDS MAC address found: "MACSTR"\n", MAC2STR(handle->hds_mac));
    }
    else wpa_printf(MSG_INFO, "INFO: WTP started at loopback\n");

    return handle;
}

int close_wtp(wtp_handle_t* handle) {
    if (!handle)
	{
        errno = EINVAL;
        return -1;
    }

    int ret = -1;

    ret = pthread_mutex_destroy(&handle->udp_mutex);
    if (ret != 0){
        errno = ret;
        pthread_cancel(handle->receive_thread);
        wtp_stop_hello_thread(handle);
        close(handle->udp_socket);
        return -1;
    }

    ret = pthread_cancel(handle->receive_thread);
    if (ret != 0)
	{
        errno = EAGAIN;
        wtp_stop_hello_thread(handle);
        close(handle->udp_socket);
        return -1;
    }

    ret = close(handle->udp_socket);
    if (ret == -1)
	{
        wtp_stop_hello_thread(handle);
        return -1;
    }

    ret = wtp_stop_hello_thread(handle);
    if (ret != 0)
	{
        return -1;
    }

    free(handle);
	return 0;
}

int parse_msg(unsigned char *buf, int length, aslan_msg_t *msg)
{
	msg->msg_id = buf[0];

	switch (msg->msg_id)
	{
		case MSG_ID_INIT_RESP:
			msg->msg.init_resp = calloc(1, sizeof(aslan_init_resp_t));
			if (!msg->msg.init_resp) return -1;
			if (length < MSG_LENGTH_INIT_RESP) return 1;
			msg->msg.init_resp->channel_num = buf[1];
			msg->msg.init_resp->SSID = calloc(15, sizeof(uint8_t));
			if (!msg->msg.init_resp->SSID) return -1;
			strncpy(msg->msg.init_resp->SSID, buf + 2, 15);
			msg->msg.init_resp->ssid_length = strlen(msg->msg.init_resp->SSID);
			if (msg->msg.init_resp->ssid_length > 14) msg->msg.init_resp->ssid_length = 14;
			break;

		case MSG_ID_CTX_RESP:
			msg->msg.ctx_resp = calloc(1, sizeof(aslan_ctx_resp_t));
			if (!msg->msg.ctx_resp) return -1;
			if (length < MSG_LENGTH_CTX_RESP) return 1;
			memcpy(msg->msg.ctx_resp->MAC, buf + 1, 6);
			memcpy(msg->msg.ctx_resp->BSSID, buf + 7, 6);
			break;

		case MSG_ID_HAND_REQ:
			msg->msg.hand_req = calloc(1, sizeof(aslan_hand_req_t));
			if (!msg->msg.hand_req) return -1;
			if (length < MSG_LENGTH_HAND_REQ) return 1;
			memcpy(msg->msg.hand_req->MAC, buf + 1, 6);
			memcpy(msg->msg.hand_req->BSSID, buf + 7, 6);
			msg->msg.hand_req->sta_wtp_ctx_length = ntohs(*((uint16_t*)(buf + 13)));
			msg->msg.hand_req->sta_wtp_ctx = calloc(msg->msg.hand_req->sta_wtp_ctx_length, 1);
			if (!msg->msg.hand_req->sta_wtp_ctx) return -1;
			memcpy(msg->msg.hand_req->sta_wtp_ctx, buf + 15, msg->msg.hand_req->sta_wtp_ctx_length);
			break;

		case MSG_ID_REL_REQ:
			msg->msg.rel_req = calloc(1, sizeof(aslan_rel_req_t));
			if (!msg->msg.rel_req) return -1;
			if (length < MSG_LENGTH_REL_REQ) return 1;
			memcpy(msg->msg.rel_req->MAC, buf + 1, 6);
			break;

		case MSG_ID_FLUSH_REQ:
			msg->msg.flush_req = calloc(1, sizeof(aslan_flush_req_t));
			if (!msg->msg.flush_req) return -1;
			if (length < MSG_LENGTH_FLUSH_REQ) return 1;
			break;

		case MSG_ID_ACK:
			msg->msg.ack = calloc(1, sizeof(aslan_ack_t));
			if (!msg->msg.ack) return -1;
			if (length < MSG_LENGTH_ACK) return 1;
			msg->msg.ack->flag = buf[1];
			break;

		default:
			return 1;
	}

	return 0;
}

void free_msg(aslan_msg_t **msg)
{
	if (!(*msg)) return;

	switch ((*msg)->msg_id)
	{
		case MSG_ID_HELLO:
			free((*msg)->msg.hello);
			break;
		case MSG_ID_CTX_REQ:
			free((*msg)->msg.ctx_req);
			break;
		case MSG_ID_ASSOC_RESP:
			free((*msg)->msg.assoc_resp->sta_wtp_ctx);
			free((*msg)->msg.assoc_resp);
			break;
		case MSG_ID_DISASSOC_RESP:
			free((*msg)->msg.disassoc_resp);
			break;
		case MSG_ID_SIG_RESP:
			free((*msg)->msg.sig_resp);
			break;
		case MSG_ID_INIT_RESP:
			free((*msg)->msg.init_resp->SSID);
			free((*msg)->msg.init_resp);
			break;
		case MSG_ID_CTX_RESP:
			free((*msg)->msg.ctx_resp);
			break;
		case MSG_ID_HAND_REQ:
			free((*msg)->msg.hand_req->sta_wtp_ctx);
			free((*msg)->msg.hand_req);
			break;
		case MSG_ID_REL_REQ:
			free((*msg)->msg.rel_req);
			break;
		case MSG_ID_FLUSH_REQ:
			free((*msg)->msg.flush_req);
			break;
		case MSG_ID_ACK:
			free((*msg)->msg.ack);
			break;
	}
	free(*msg);
	(*msg) = NULL;
}

void *receive_msg_thread(void *arg)
{
	assert(arg);
	wtp_handle_t* handle = (wtp_handle_t *) arg;
	struct sockaddr_in addr_sender = {0};
	addr_sender.sin_family = AF_INET;
	aslan_msg_t *msg = NULL;
	u32 msg_crc, prev_msg_crc = 0;
	unsigned char buf[ETH_DATA_LEN];
	int ret, buf_length, ip_length = sizeof(addr_sender);

	while (1)
	{
		buf_length = recvfrom(handle->udp_socket, buf, ETH_DATA_LEN, 0, (struct sockaddr *) &addr_sender, (socklen_t*) &ip_length);

		if (buf_length == -1)
		{
			perror("Receive ASLAN message error");
			continue;
		}

		msg = calloc(1, sizeof(aslan_msg_t));
		if (!msg)
		{
			errno = ENOMEM;
			perror("ASLAN message parse error");
			continue;
		}

		msg->sender_ip = ntohl(addr_sender.sin_addr.s_addr);
		msg->sender_port = ntohs(addr_sender.sin_port);

		ret = parse_msg(buf,buf_length,msg);
		if (ret == -1)
		{
			errno = ENOMEM;
			perror("ASLAN message parse error");
			free_msg(&msg);
			continue;
		}
		else if (ret == 1)
		{
			wpa_printf(MSG_ERROR, "ERROR: Received unexpected/invalid ASLAN message! Id: %d\n", buf[0]);
			free_msg(&msg);
			continue;
		}

		if (msg->sender_ip != handle->hds_ip)
		{
			wpa_printf(MSG_ERROR, "ERROR: Unexpected HDS IP address: %s\n", inet_ntoa(*(struct in_addr *) &msg->sender_ip));
			free_msg(&msg);
			continue;
		}

		if (msg->sender_port != handle->hds_port)
		{
			wpa_printf(MSG_ERROR, "ERROR: Unexpected HDS port: %u\n", msg->sender_port);
			free_msg(&msg);
			continue;
		}

		msg_crc = crc32((u8*) buf, buf_length);
		if ((prev_msg_crc) && (prev_msg_crc == msg_crc))
		{
			free_msg(&msg);
			continue;
		}
		prev_msg_crc = msg_crc;

		(handle->msg_cb)(msg);
		free_msg(&msg);
	}

	pthread_exit(NULL);
    return NULL;
}

void *hello_thread(void *arg)
{
	assert(arg);
	wtp_handle_t* handle = (wtp_handle_t *) arg;
    int ret = -1;

    while (1)
	{
        sleep(handle->hello_interval_seconds);
        ret = wtp_send_hello_msg(handle);
        if(ret == -1)
        {
            wpa_printf(MSG_ERROR, "ERROR: %s: wtp_send_hello_msg() failed\n", __FUNCTION__);
        }
    }

    pthread_exit(NULL);
    return NULL;
}

int wtp_start_hello_thread(wtp_handle_t* handle)
{
	int ret = -1;
	
	if (!handle)
	{
		errno = EINVAL;
		return -1;
	}
	
	ret = pthread_mutex_lock(&handle->hello_mutex);
    if (ret != 0)
	{
        wpa_printf(MSG_ERROR, "ERROR: %s: mutex lock failed: %s\n", __FUNCTION__, strerror(ret));
        return -1;
    }

    if (!handle->hello_thread_running)
	{
        ret = pthread_create(&handle->hello_thread, NULL, hello_thread, (void *) handle);
        if (ret != 0)
		{
            wpa_printf(MSG_ERROR, "ERROR: %s: thread create failed: %s\n", __FUNCTION__, strerror(ret));
            pthread_mutex_unlock(&handle->hello_mutex);
            return -1;
        }
        handle->hello_thread_running = true;
		wpa_printf(MSG_INFO, "INFO: sending of Hello Messages started\n");
    }

    ret = pthread_mutex_unlock(&handle->hello_mutex);
    if (ret != 0)
	{
        wpa_printf(MSG_ERROR, "ERROR: %s: mutex unlock failed: %s\n", __FUNCTION__, strerror(ret));
        return -1;
    }

    return 0;
}

int wtp_stop_hello_thread(wtp_handle_t* handle)
{
	int ret = -1;
	
	if (!handle)
	{
		errno = EINVAL;
		return -1;
	}
	
	ret = pthread_mutex_lock(&handle->hello_mutex);
    if (ret != 0)
	{
        wpa_printf(MSG_ERROR, "ERROR: %s: mutex lock failed: %s\n", __FUNCTION__, strerror(ret));
        return -1;
    }
	
	if (handle->hello_thread_running)
	{
        handle->hello_thread_running = false;
        ret = pthread_cancel(handle->hello_thread);
        if (ret != 0)
		{
            wpa_printf(MSG_ERROR, "ERROR: %s: thread cancel failed: %s\n", __FUNCTION__, strerror(ret));
            pthread_mutex_unlock(&handle->hello_mutex);
            return -1;
        }
		wpa_printf(MSG_INFO, "INFO: sending of Hello Messages stopped\n");
    }
	
	ret = pthread_mutex_unlock(&handle->hello_mutex);
    if (ret != 0)
	{
        wpa_printf(MSG_ERROR, "ERROR: %s: mutex unlock failed: %s\n", __FUNCTION__, strerror(ret));
        return -1;
    }

    return 0;
}

int udp_lock(wtp_handle_t* handle)
{
	int ret;
	
	if (!handle)
	{
		errno = EINVAL;
		return -1;
	}
	
	ret = pthread_mutex_lock(&handle->udp_mutex);
    if (ret != 0)
	{
		wpa_printf(MSG_ERROR, "ERROR: %s: mutex lock failed: %s\n", __FUNCTION__, strerror(ret));
        return -1;
    }
	
	if (handle->udp_socket < 0)
	{
        errno = EINVAL;
        return -1;
    }
	
	return 0;
}

int udp_unlock(wtp_handle_t* handle)
{
	int ret;
	
	ret = pthread_mutex_unlock(&handle->udp_mutex);
	if (ret != 0)
	{
		wpa_printf(MSG_ERROR, "ERROR: %s: mutex unlock failed: %s\n", __FUNCTION__, strerror(ret));
        return -1;
    }
	
	return 0;
}

int wtp_send_hello_msg(wtp_handle_t* handle)
{	
	int ret;
    uint8_t msg[MSG_LENGTH_HELLO];
			
	if (udp_lock(handle) != 0) return -1;
	
	msg[0] = MSG_ID_HELLO;
    ret = sendto(handle->udp_socket, msg, MSG_LENGTH_HELLO, 0, (struct sockaddr *) &handle->hds_inet_addr, sizeof(handle->hds_inet_addr));
	
	if (udp_unlock(handle) != 0) return -1;
	
	return ret;
}

int wtp_send_ack(wtp_handle_t* handle, uint8_t flag)
{
	int ret;
    uint8_t msg[MSG_LENGTH_ACK];

	if (udp_lock(handle) != 0) return -1;

	msg[0] = MSG_ID_ACK;
	msg[1] = flag;
    ret = sendto(handle->udp_socket, msg, MSG_LENGTH_ACK, 0, (struct sockaddr *) &handle->hds_inet_addr, sizeof(handle->hds_inet_addr));

	if (udp_unlock(handle) != 0) return -1;

	return ret;
}

/* MAC compare function */
inline int mac_cmp(char mac1[6], char mac2[6])
{
    if ((mac1[0] == mac2[0]) && (mac1[1] == mac2[1]) && (mac1[2] == mac2[2]) &&
       (mac1[3] == mac2[3]) && (mac1[4] == mac2[4]) && (mac1[5] == mac2[5]))
    {
        return 1;
    }

    return 0;
}
