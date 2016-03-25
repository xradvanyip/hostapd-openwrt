#include "wtp_core.h"

#include "ap/ap_config.h"
#include "ap/ieee802_11.h"
#include "ap/sta_info.h"
#include "ap/ap_drv_ops.h"
#include "../hostapd/config_file.h"
#include "../hostapd/ctrl_iface.h"

const char* const chan_freq[] = { "2407", "2412", "2417", "2422", "2427", "2432", "2437", "2442", "2447", "2452", "2457", "2462", "2467", "2472", "2484" };
wtp_handle_t *wtp_handle = NULL;
struct hostapd_iface *wtp_hapdif;
int wtp_used_bss[100] = {0};


void wtp_init(wtp_handle_t *handle, struct hostapd_iface *hapdif)
{
	wtp_handle = handle;
	wtp_hapdif = hapdif;

	memset(handle->wtp_hashcount, 0, 256);
	wtp_start_hello_thread(wtp_handle);
}

wtp_handle_t* wtp_get_handle()
{
	return wtp_handle;
}

void wtp_sta_set_reject(int hash_code)
{
	struct wtp_sta *hash_sta;

	pthread_mutex_lock(&wtp_handle->sta_mutex);
	hash_sta = (struct wtp_sta *) wtp_handle->wtp_hashtable[hash_code];
	hash_sta->mode = WTP_STA_MODE_REJECTED;
	pthread_mutex_unlock(&wtp_handle->sta_mutex);
}

void wtp_sta_set_ctx(int hash_code, int id, u8 *BSSID)
{
	struct wtp_sta *hash_sta;

	pthread_mutex_lock(&wtp_handle->sta_mutex);
	hash_sta = (struct wtp_sta *) wtp_handle->wtp_hashtable[hash_code];
	hash_sta->bss_id = id;
	os_memcpy(hash_sta->wtp_bssid, BSSID, ETH_ALEN);
	hash_sta->mode = WTP_STA_MODE_CTX;
	pthread_mutex_unlock(&wtp_handle->sta_mutex);
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

static void wtp_ap_init(struct hostapd_data *hapd, u8 channel_num, char *SSID)
{
	char arg_buf[10];

	os_snprintf(arg_buf, 10, "0 %s ht", chan_freq[channel_num]);

	hostapd_set_iface(hapd->iconf, hapd->conf, "ssid", SSID);
	hostapd_set_iface(hapd->iconf, hapd->conf, "ignore_broadcast_ssid", "0");
	hostapd_reload_iface(hapd->iface);
	sleep(1);
	hostapd_ctrl_iface_chan_switch(hapd->iface, arg_buf);
	sleep(1);

	wtp_set_state(wtp_handle, WTP_STATE_INITIALISED);
}

static int wtp_vif_create(struct hostapd_iface *hapdif, u8 *BSSID, u8 *MAC)
{
	struct hostapd_data *hapd_main = hapdif->bss[0];
	FILE *bss_conf;
	char arg_buf[50];
	struct sta_info *sta = NULL;
	int i, j;

	bss_conf = fopen(BSS_CONF_FILE, "w");
	if (!bss_conf) return -1;

	os_snprintf(arg_buf, 50, "bss_config=%s:%s", hapdif->phy, BSS_CONF_FILE);
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
	hostapd_add_iface(hapdif->interfaces, arg_buf);
	sleep(1);

	wtp_used_bss[i] = 1;
	for (j=0; j < hapdif->num_bss; j++)
	{
		if (hostapd_mac_comp(hapdif->bss[j]->conf->bssid, BSSID) == 0) break;
	}

	if (j != 0)
	{
		sta = ap_sta_add(hapdif->bss[j], MAC);
		if (sta)
		{
			wpa_printf(MSG_INFO, "Added STA "MACSTR" with BSS struct id: %d\n", MAC2STR(sta->addr), j);
			return i;
		}
	}

	return -1;
}

int aslan_msg_cb(aslan_msg_t* msg)
{
	struct hostapd_data *hapd_main = wtp_hapdif->bss[0];
	int ret;

	switch (msg->msg_id)
	{
		case MSG_ID_INIT_RESP:
			wtp_ap_init(hapd_main, msg->msg.init_resp->channel_num, msg->msg.init_resp->SSID);
			wtp_send_ack(wtp_handle, 0);
			break;

		case MSG_ID_CTX_RESP:
			ret = wtp_vif_create(wtp_hapdif, msg->msg.ctx_resp->BSSID, msg->msg.ctx_resp->MAC);
			if (ret != -1)
			{
				wtp_sta_set_ctx(msg->msg.ctx_resp->MAC[5], ret, msg->msg.ctx_resp->BSSID);
				wtp_send_ack(wtp_handle, 0);
			}
			else wtp_send_ack(wtp_handle, 1);
			break;
	}
}
