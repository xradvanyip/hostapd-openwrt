#include <pthread.h>
#include <errno.h>
#include <assert.h>
#include "wtp_core.h"

#include "ap/ap_config.h"
#include "ap/ieee802_11.h"
#include "ap/sta_info.h"
#include "ap/ap_drv_ops.h"
#include "utils/eloop.h"
#include "../hostapd/config_file.h"
#include "../hostapd/ctrl_iface.h"

const char* const chan_freq[] = { "2407", "2412", "2417", "2422", "2427", "2432", "2437", "2442", "2447", "2452", "2457", "2462", "2467", "2472", "2484" };
pthread_mutex_t eloop_lock_mutex = PTHREAD_MUTEX_INITIALIZER;
wtp_handle_t *wtp_handle = NULL;
struct hostapd_iface *wtp_hapdif;
struct mon_node *mon_list = NULL;
int wtp_used_bss[100] = {0};

static void *monitor_thread_cb(void *arg);


void wtp_init(wtp_handle_t *handle, struct hostapd_iface *hapdif)
{
	wtp_handle = handle;
	wtp_hapdif = hapdif;

	handle->wtp_sta_hashmap = hashmapCreate(0);
	wtp_start_hello_thread(handle);

	/* start thread for sending reports of signal level */
    if (pthread_create(&(handle->monitor_thread), NULL, monitor_thread_cb, (void*)handle) != 0)
    {
        errno = ENOMEM;
		close_wtp(handle);
		return;
    }
	wpa_printf(MSG_INFO, "DEBUG: thread for sending RSSI reports created\n");
}

wtp_handle_t* wtp_get_handle()
{
	return wtp_handle;
}

struct wtp_sta* wtp_sta_get(u8* sta_mac)
{
	struct wtp_sta *hash_sta;

	pthread_mutex_lock(&wtp_handle->sta_mutex);
	hash_sta = (struct wtp_sta *) hashmapGet(wtp_handle->wtp_sta_hashmap, *((unsigned long *) sta_mac));
	if (!hash_sta)
	{
		hash_sta = os_calloc(1, sizeof(struct wtp_sta));
		hash_sta->mode = WTP_STA_MODE_NONE;
		hash_sta->rssi_sum = 0;
		hash_sta->rssi_count = 0;
		os_memcpy(hash_sta->wtp_addr, sta_mac, ETH_ALEN);
		os_memset(hash_sta->wtp_bssid, 0, ETH_ALEN);
		wpa_printf(MSG_INFO, "New STA in range: "MACSTR, MAC2STR(hash_sta->wtp_addr));
		hashmapInsert(wtp_handle->wtp_sta_hashmap, hash_sta, *((unsigned long *) sta_mac));
	}
	pthread_mutex_unlock(&wtp_handle->sta_mutex);

	return hash_sta;
}

void wtp_sta_set_reject(u8* sta_mac)
{
	struct wtp_sta *hash_sta;

	pthread_mutex_lock(&wtp_handle->sta_mutex);
	hash_sta = (struct wtp_sta *) hashmapGet(wtp_handle->wtp_sta_hashmap, *((unsigned long *) sta_mac));
	if (hash_sta) hash_sta->mode = WTP_STA_MODE_REJECTED;
	pthread_mutex_unlock(&wtp_handle->sta_mutex);
}

void wtp_sta_set_ctx(u8* sta_mac, u8 *BSSID, int id)
{
	struct wtp_sta *hash_sta;

	pthread_mutex_lock(&wtp_handle->sta_mutex);
	hash_sta = (struct wtp_sta *) hashmapGet(wtp_handle->wtp_sta_hashmap, *((unsigned long *) sta_mac));
	if (hash_sta)
	{
		hash_sta->bss_id = id;
		os_memcpy(hash_sta->wtp_bssid, BSSID, ETH_ALEN);
		hash_sta->mode = WTP_STA_MODE_CTX;
	}
	pthread_mutex_unlock(&wtp_handle->sta_mutex);
}

int wtp_sta_has_ctx(u8* sta_mac)
{
	struct wtp_sta *hash_sta;
	int ret = 0;

	pthread_mutex_lock(&wtp_handle->sta_mutex);
	hash_sta = (struct wtp_sta *) hashmapGet(wtp_handle->wtp_sta_hashmap, *((unsigned long *) sta_mac));
	if (hash_sta)
	{
		if ((hash_sta->mode == WTP_STA_MODE_CTX) || (hash_sta->mode == WTP_STA_MODE_CONNECTED)) ret = 1;
	}
	pthread_mutex_unlock(&wtp_handle->sta_mutex);

	return ret;
}

static int wtp_sta_remove_ctx(u8* sta_mac)
{
	struct wtp_sta *hash_sta;
	int ret = -1;

	pthread_mutex_lock(&wtp_handle->sta_mutex);
	hash_sta = (struct wtp_sta *) hashmapGet(wtp_handle->wtp_sta_hashmap, *((unsigned long *) sta_mac));
	if ((hash_sta) && ((hash_sta->mode == WTP_STA_MODE_CTX) || (hash_sta->mode == WTP_STA_MODE_CONNECTED)))
	{
		if (hash_sta->mode == WTP_STA_MODE_CTX) hash_sta->mode = WTP_STA_MODE_NONE;
		else hash_sta->mode = WTP_STA_MODE_REQ;
		hash_sta->rssi_sum = 0;
		hash_sta->rssi_count = 0;
		os_memset(hash_sta->wtp_bssid, 0, ETH_ALEN);
		ret = hash_sta->bss_id;
	}
	pthread_mutex_unlock(&wtp_handle->sta_mutex);

	return ret;
}

int wtp_sta_get_mode(struct wtp_sta *sta)
{
	int sta_mode;

	pthread_mutex_lock(&wtp_handle->sta_mutex);
	sta_mode = sta->mode;
	pthread_mutex_unlock(&wtp_handle->sta_mutex);

	return sta_mode;
}

void wtp_sta_set_mode(struct wtp_sta *sta, int sta_mode)
{
	pthread_mutex_lock(&wtp_handle->sta_mutex);
	sta->mode = sta_mode;
	pthread_mutex_unlock(&wtp_handle->sta_mutex);
}

static u8 *wtp_sta_get_bssid(u8* sta_mac)
{
	struct wtp_sta *hash_sta;
	u8 *ret = NULL;

	pthread_mutex_lock(&wtp_handle->sta_mutex);
	hash_sta = (struct wtp_sta *) hashmapGet(wtp_handle->wtp_sta_hashmap, *((unsigned long *) sta_mac));
	if ((hash_sta) && ((hash_sta->mode == WTP_STA_MODE_CTX) || (hash_sta->mode == WTP_STA_MODE_CONNECTED)))
	{
		ret = hash_sta->wtp_bssid;
	}
	pthread_mutex_unlock(&wtp_handle->sta_mutex);

	return ret;
}

int wtp_sta_bssid_cmp(struct wtp_sta *sta, u8* mac)
{
	int ret;

	pthread_mutex_lock(&wtp_handle->sta_mutex);
	ret = os_memcmp(mac, sta->wtp_bssid, ETH_ALEN);
	pthread_mutex_unlock(&wtp_handle->sta_mutex);

	return ret;
}

static int wtp_check_bssid_range(const u8 *mac)
{
	if ((mac[0] == 0x02) && (mac[1] == 0x00) && (mac[2] == 0x00) && (mac[3] == 0x00) && (mac[4] == 0x16))
	{
		return 1;
	}

	return 0;
}

void wtp_handle_monitor_frame(u8 *sa, const u8 *bssid, int rssi)
{
	struct wtp_sta *hash_sta;
	struct mon_node *new_node;

	if (!wtp_handle) return;
	if (wtp_get_state(wtp_handle) == WTP_STATE_NONE) return;
	if ((!sa) || (!bssid)) return;
	if (hostapd_mac_comp(sa, bssid) == 0) return;

	hash_sta = wtp_sta_get(sa);
	pthread_mutex_lock(&wtp_handle->monitor_mutex);
	if ((wtp_check_bssid_range(bssid) == 1) || (wtp_sta_get_mode(hash_sta) == WTP_STA_MODE_CONNECTED))
	{
		pthread_mutex_lock(&wtp_handle->sta_mutex);
		if (hash_sta->rssi_count == 0)
		{
			new_node = (struct mon_node *) os_malloc(sizeof(struct mon_node));
			os_memcpy(new_node->sta_mac, sa, ETH_ALEN);
			new_node->next = mon_list;
			mon_list = new_node;
		}
		hash_sta->rssi_sum += rssi;
		hash_sta->rssi_count++;
		pthread_mutex_unlock(&wtp_handle->sta_mutex);
	}
	pthread_mutex_unlock(&wtp_handle->monitor_mutex);
}

void *monitor_thread_cb(void *arg)
{
	assert(arg);
	wtp_handle_t* handle = (wtp_handle_t *) arg;
	struct mon_node *curr_node;
	struct wtp_sta *hash_sta;

	while (1)
	{
		sleep(SIGNAL_RESP_INTERVAL);
		pthread_mutex_lock(&wtp_handle->monitor_mutex);
		while (mon_list)
		{
			curr_node = mon_list;
			mon_list = mon_list->next;

			pthread_mutex_lock(&wtp_handle->sta_mutex);
			hash_sta = (struct wtp_sta *) hashmapGet(wtp_handle->wtp_sta_hashmap, *((unsigned long *) curr_node->sta_mac));
			if ((hash_sta) && (hash_sta->rssi_count))
			{
				wtp_send_sig_resp(handle, (unsigned char *) hash_sta->wtp_addr, hash_sta->rssi_sum / hash_sta->rssi_count);
				hash_sta->rssi_sum = 0;
				hash_sta->rssi_count = 0;
			}
			pthread_mutex_unlock(&wtp_handle->sta_mutex);
			os_free(curr_node);
		}
		pthread_mutex_unlock(&wtp_handle->monitor_mutex);
	}

	pthread_exit(NULL);
    return NULL;
}

static void wtp_ap_init(struct hostapd_data *hapd, u8 channel_num, char *SSID)
{
	char arg_buf[10];

	os_snprintf(arg_buf, 10, "0 %s ht", chan_freq[channel_num]);

	pthread_mutex_lock(&eloop_lock_mutex);
	hostapd_set_iface(hapd->iconf, hapd->conf, "ssid", SSID);
	pthread_mutex_unlock(&eloop_lock_mutex);

	pthread_mutex_lock(&eloop_lock_mutex);
	hostapd_set_iface(hapd->iconf, hapd->conf, "ignore_broadcast_ssid", "0");
	pthread_mutex_unlock(&eloop_lock_mutex);

	pthread_mutex_lock(&eloop_lock_mutex);
	hostapd_reload_iface(hapd->iface);
	pthread_mutex_unlock(&eloop_lock_mutex);
	sleep(1);

	pthread_mutex_lock(&eloop_lock_mutex);
	hostapd_ctrl_iface_chan_switch(hapd->iface, arg_buf);
	pthread_mutex_unlock(&eloop_lock_mutex);
	sleep(1);

	wtp_set_state(wtp_handle, WTP_STATE_INITIALISED);
}

static int wtp_vif_create(u8 *BSSID, u8 *MAC)
{
	struct hostapd_data *hapd_main = wtp_hapdif->bss[0];
	FILE *bss_conf;
	char arg_buf[50];
	int i, j, ret;

	pthread_mutex_lock(&eloop_lock_mutex);
	for (j=0; j < wtp_hapdif->num_bss; j++)
	{
		if (hostapd_mac_comp(wtp_hapdif->bss[j]->conf->bssid, BSSID) == 0)
		{
			pthread_mutex_unlock(&eloop_lock_mutex);
			return -1;
		}
	}

	bss_conf = fopen(BSS_CONF_FILE, "w");
	if (!bss_conf) return -1;

	os_snprintf(arg_buf, 50, "bss_config=%s:%s", wtp_hapdif->phy, BSS_CONF_FILE);
	for (i=1; i < 100; i++) if (wtp_used_bss[i] == 0) break;

	fprintf(bss_conf, "driver=nl80211\n");
	fprintf(bss_conf, "logger_syslog=%d\n", hapd_main->conf->logger_syslog);
	fprintf(bss_conf, "logger_syslog_level=%d\n", hapd_main->conf->logger_syslog_level);
	fprintf(bss_conf, "logger_stdout=%d\n", hapd_main->conf->logger_stdout);
	fprintf(bss_conf, "logger_stdout_level=%d\n", hapd_main->conf->logger_stdout_level);
	fprintf(bss_conf, "country_code=%s\n", hapd_main->iconf->country);
	fprintf(bss_conf, "ieee80211d=%d\n", hapd_main->iconf->ieee80211d);
	fprintf(bss_conf, "hw_mode=g\n");
	fprintf(bss_conf, "channel=%d\n", hapd_main->iconf->channel);
	fprintf(bss_conf, "ieee80211n=%d\n", hapd_main->iconf->ieee80211n);
	fprintf(bss_conf, "interface=%s-%d\n", hapd_main->conf->iface, i);
	fprintf(bss_conf, "ctrl_interface=%s\n", hapd_main->conf->ctrl_interface);
	fprintf(bss_conf, "disassoc_low_ack=%d\n", hapd_main->conf->disassoc_low_ack);
	fprintf(bss_conf, "preamble=%d\n", hapd_main->iconf->preamble);
	fprintf(bss_conf, "wmm_enabled=%d\n", hapd_main->conf->wmm_enabled);
	fprintf(bss_conf, "uapsd_advertisement_enabled=%d\n", hapd_main->conf->wmm_uapsd);
	fprintf(bss_conf, "auth_algs=%d\n", hapd_main->conf->auth_algs);
	fprintf(bss_conf, "wpa=%d\n", hapd_main->conf->wpa);
	fprintf(bss_conf, "ssid=%.*s\n", hapd_main->conf->ssid.ssid_len, hapd_main->conf->ssid.ssid);
	fprintf(bss_conf, "bridge=%s\n", hapd_main->conf->bridge);
	fprintf(bss_conf, "bssid="MACSTR"\n", MAC2STR(BSSID));
	fclose(bss_conf);
	hostapd_add_iface(wtp_hapdif->interfaces, arg_buf);

	wtp_used_bss[i] = 1;
	ret = -1;
	for (j=0; j < wtp_hapdif->num_bss; j++)
	{
		if (hostapd_mac_comp(wtp_hapdif->bss[j]->conf->bssid, BSSID) == 0)
		{
			ret = j;
			break;
		}
	}
	pthread_mutex_unlock(&eloop_lock_mutex);
	wtp_sta_set_ctx(MAC, BSSID, i);

	return ret;
}

static int wtp_vif_remove(int bss_id)
{
	struct hostapd_data *hapd_main = wtp_hapdif->bss[0];
	char arg_buf[10];
	int ret;

	if (!wtp_used_bss[bss_id]) return -1;

	os_snprintf(arg_buf, 10, "%s-%d", hapd_main->conf->iface, bss_id);

	pthread_mutex_lock(&eloop_lock_mutex);
	ret = hostapd_remove_iface(wtp_hapdif->interfaces, arg_buf);
	pthread_mutex_unlock(&eloop_lock_mutex);

	wtp_used_bss[bss_id] = 0;
	return ret;
}

static int wtp_handle_ctx_resp(u8 *BSSID, u8 *MAC)
{
	struct sta_info *sta = NULL;
	int ret;

	if (wtp_sta_has_ctx(MAC)) return -1;

	ret = wtp_vif_create(BSSID, MAC);
	if (ret <= 0) return -1;

	pthread_mutex_lock(&eloop_lock_mutex);
	sta = ap_sta_add(wtp_hapdif->bss[ret], MAC);
	pthread_mutex_unlock(&eloop_lock_mutex);
	if (!sta) return -1;

	wpa_printf(MSG_INFO, "Added STA "MACSTR" with BSS struct id: %d\n", MAC2STR(sta->addr), ret);
	return 0;
}

static int wtp_handle_handover(u8 *BSSID, u8 *MAC, void* ctx, u16 ctx_length)
{
	struct wtp_sta *hash_sta;
	int ret;

	hash_sta = wtp_sta_get(MAC);

	ret = wtp_vif_create(BSSID, MAC);
	if (ret <= 0) return -1;

	pthread_mutex_lock(&eloop_lock_mutex);
	ret = wtp_handle_auth(wtp_hapdif->bss[ret], (const struct ieee80211_mgmt *) ctx, ctx_length);
	pthread_mutex_unlock(&eloop_lock_mutex);
	if (ret < 0) return -1;

	wtp_sta_set_mode(hash_sta, WTP_STA_MODE_CONNECTED);
	return 0;
}

static int wtp_handle_release(u8 *MAC)
{
	u8 *bssid;
	int j, ret;

	bssid = wtp_sta_get_bssid(MAC);
	if (!bssid) return -1;

	pthread_mutex_lock(&eloop_lock_mutex);
	ret = -1;
	for (j=0; j < wtp_hapdif->num_bss; j++)
	{
		if (hostapd_mac_comp(wtp_hapdif->bss[j]->conf->bssid, bssid) == 0)
		{
			ret = j;
			break;
		}
	}
	if (ret > 0) wtp_handle_deauth(wtp_hapdif->bss[ret],MAC);
	pthread_mutex_unlock(&eloop_lock_mutex);

	ret = wtp_sta_remove_ctx(MAC);
	if (ret < 0) return -1;

	ret = wtp_vif_remove(ret);

	return ret;
}

void hapd_eloop_lock_init()
{
	pthread_mutex_lock(&eloop_lock_mutex);
}

void hapd_eloop_lock_cb(void *eloop_data, void *user_data)
{
	pthread_mutex_unlock(&eloop_lock_mutex);
	pthread_mutex_lock(&eloop_lock_mutex);
	eloop_register_timeout(0, 1000, hapd_eloop_lock_cb, NULL, NULL);
}

int aslan_msg_cb(aslan_msg_t* msg)
{
	struct hostapd_data *hapd_main = wtp_hapdif->bss[0];

	switch (msg->msg_id)
	{
		case MSG_ID_INIT_RESP:
			wtp_ap_init(hapd_main, msg->msg.init_resp->channel_num, msg->msg.init_resp->SSID);
			wtp_send_ack(wtp_handle, 0);
			break;

		case MSG_ID_CTX_RESP:
			if (wtp_handle_ctx_resp(msg->msg.ctx_resp->BSSID, msg->msg.ctx_resp->MAC) != -1)
			{
				wtp_send_ack(wtp_handle, 0);
			}
			else wtp_send_ack(wtp_handle, 1);
			break;

		case MSG_ID_HAND_REQ:
			if (wtp_handle_handover(msg->msg.hand_req->BSSID, msg->msg.hand_req->MAC,
						msg->msg.hand_req->sta_wtp_ctx, msg->msg.hand_req->sta_wtp_ctx_length) != -1)
			{
				wtp_send_ack(wtp_handle, 0);
			}
			else wtp_send_ack(wtp_handle, 1);
			break;

		case MSG_ID_REL_REQ:
			if (wtp_handle_release(msg->msg.rel_req->MAC) != -1)
			{
				wtp_send_ack(wtp_handle, 0);
			}
			else wtp_send_ack(wtp_handle, 1);
			break;
	}
}
