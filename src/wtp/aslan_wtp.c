#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/udp.h>
#include <net/if_arp.h>
#include <linux/sockios.h>
#include <arpa/inet.h>
#include <assert.h>
#include <unistd.h>

#include "includes.h"
#include "common.h"
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
    ret = pthread_create(&(handle->receive_thread), NULL,
                         receive_msg_thread, (void*)handle);
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

void *receive_msg_thread(void *arg)
{
	assert(arg);
	wtp_handle_t* handle = (wtp_handle_t *) arg;
	
	// ...
	
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
        ret = wtp_send_hello_msg(handle);
        if(ret == -1){
            wpa_printf(MSG_ERROR, "ERROR: %s: wtp_send_hello_msg() failed\n", __FUNCTION__);
        }
        sleep(handle->hello_interval_seconds);
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
