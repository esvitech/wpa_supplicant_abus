
#ifndef ABUS_SERVICE_H
#define ABUS_SERVICE_H

#include "utils/includes.h"
#include "utils/common.h"
#include "utils/eloop.h"
#include "utils/uuid.h"
#include "common/version.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "common/wpa_ctrl.h"
#include "eap_peer/eap.h"
#include "eapol_supp/eapol_supp_sm.h"
#include "rsn_supp/wpa.h"
#include "rsn_supp/preauth.h"
#include "rsn_supp/pmksa_cache.h"
#include "l2_packet/l2_packet.h"
#include "wps/wps.h"
#include "config.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "wps_supplicant.h"
#include "ibss_rsn.h"
#include "ap.h"
#include "p2p_supplicant.h"
#include "p2p/p2p.h"
#include "hs20_supplicant.h"
#include "wifi_display.h"
#include "notify.h"
#include "bss.h"
#include "scan.h"
#include "ctrl_iface.h"
#include "interworking.h"
#include "blacklist.h"
#include "autoscan.h"
#include "wnm_sta.h"
#include "offchannel.h"
#include "abus.h"
#include <abus/json.h>

 int * freq_range_to_channel_list(struct wpa_supplicant *wpa_s, char *val);

 int wpa_supplicant_ctrl_iface_update_network(
	struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid,
	char *name, char *value);

 char * wpa_supplicant_cipher_txt(char *pos, char *end, int cipher);

 char * wpa_supplicant_ie_txt(char *pos, char *end, const char *proto,
                    const u8 *ie, size_t ie_len);
 int wpa_supplicant_ctrl_iface_scan_result(
    struct wpa_supplicant *wpa_s,json_rpc_t *json_rpc,
    const struct wpa_bss *bss, char *buf, size_t buflen);
 int wpa_supplicant_ap_scan(
        struct wpa_supplicant *wpa_s, int ap_scan);

 int wpa_supplicant_scan_results(
        struct wpa_supplicant *wpa_s,json_rpc_t *json_rpc ,char *buf, size_t buflen);

 int wpa_supplicant_add_network(
	struct wpa_supplicant *wpa_s, char *buf, size_t buflen);

 int wpa_supplicant_set_network(
	struct wpa_supplicant *wpa_s, char *cmd);

 int wpa_supplicant_ctrl_iface_select_network(
	struct wpa_supplicant *wpa_s, char *cmd);

 int wpa_supplicant_ctrl_iface_remove_network(
	struct wpa_supplicant *wpa_s, char *cmd);


#endif
