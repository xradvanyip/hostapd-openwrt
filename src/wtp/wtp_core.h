#ifndef _WTP_CORE
#define _WTP_CORE

#include "includes.h"
#include "common.h"
#include "ap/hostapd.h"
#include "aslan_wtp.h"


struct wtp_sta {
	int mode;
	int bss_id;
	u8 wtp_addr[6];
	u8 wtp_bssid[6];
};


void wtp_init(wtp_handle_t *handle, struct hostapd_iface *hapdif);
wtp_handle_t* wtp_get_handle();

void wtp_sta_set_reject(int hash_code);
void wtp_sta_set_ctx(int hash_code, int id, u8 *BSSID);
int wtp_sta_get_mode(struct wtp_sta *sta);
void wtp_sta_set_mode(struct wtp_sta *sta, int sta_mode);

int aslan_msg_cb(aslan_msg_t* msg);

#endif
