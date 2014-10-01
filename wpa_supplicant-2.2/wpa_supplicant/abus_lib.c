#include "abus_service.h"

 int * freq_range_to_channel_list(struct wpa_supplicant *wpa_s, char *val) {
    struct wpa_freq_range_list ranges;
    int *freqs = NULL;
    struct hostapd_hw_modes *mode;
    u16 i;
    if (wpa_s->hw.modes == NULL)
            return NULL;
    os_memset(&ranges, 0, sizeof(ranges));
    if (freq_range_list_parse(&ranges, val) < 0)
            return NULL;
    for (i = 0; i < wpa_s->hw.num_modes; i++) {
        int j;
        mode = &wpa_s->hw.modes[i];
        for (j = 0; j < mode->num_channels; j++) {
            unsigned int freq;
            if (mode->channels[j].flag & HOSTAPD_CHAN_DISABLED)
                            continue;
            freq = mode->channels[j].freq;
            if (!freq_range_list_includes(&ranges, freq))
                            continue;
            int_array_add_unique(&freqs, freq);
        }
    }
    os_free(ranges.range);
    return freqs;
}

 int wpa_supplicant_ctrl_iface_update_network(
    struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid,
    char *name, char *value) {
    if (wpa_config_set(ssid, name, value, 0) < 0) {
        wpa_printf(MSG_DEBUG, "CTRL_IFACE: Failed to set network "
                       "variable '%s'", name);
        return -1;
    }
    if (os_strcmp(name, "bssid") != 0 &&
            os_strcmp(name, "priority") != 0)
            wpa_sm_pmksa_cache_flush(wpa_s->wpa, ssid);
    if (wpa_s->current_ssid == ssid || wpa_s->current_ssid == NULL) {
        eapol_sm_invalidate_cached_session(wpa_s->eapol);
    }
    if ((os_strcmp(name, "psk") == 0 &&
             value[0] == '"' && ssid->ssid_len) ||
            (os_strcmp(name, "ssid") == 0 && ssid->passphrase))
            wpa_config_update_psk(ssid); 
    else if (os_strcmp(name, "priority") == 0)
            wpa_config_update_prio_list(wpa_s->conf);
    return 0;
}

 char * wpa_supplicant_cipher_txt(char *pos, char *end, int cipher) {
    int ret;
    ret = os_snprintf(pos, end - pos, "-");
    if (ret < 0 || ret >= end - pos)
            return pos;
    pos += ret;
    ret = wpa_write_ciphers(pos, end, cipher, "+");
    if (ret < 0)
            return pos;
    pos += ret;
    return pos;
}

 char * wpa_supplicant_ie_txt(char *pos, char *end, const char *proto,
                    const u8 *ie, size_t ie_len) {
    struct wpa_ie_data data;
    char *start;
    int ret;
    ret = os_snprintf(pos, end - pos, "[%s-", proto);
    if (ret < 0 || ret >= end - pos)
            return pos;
    pos += ret;
    if (wpa_parse_wpa_ie(ie, ie_len, &data) < 0) {
        ret = os_snprintf(pos, end - pos, "?]");
        if (ret < 0 || ret >= end - pos)
                    return pos;
        pos += ret;
        return pos;
    }
    start = pos;
    if (data.key_mgmt & WPA_KEY_MGMT_IEEE8021X) {
        ret = os_snprintf(pos, end - pos, "%sEAP",
                          pos == start ? "" : "+");
        if (ret < 0 || ret >= end - pos)
                    return pos;
        pos += ret;
    }
    if (data.key_mgmt & WPA_KEY_MGMT_PSK) {
        ret = os_snprintf(pos, end - pos, "%sPSK",
                          pos == start ? "" : "+");
        if (ret < 0 || ret >= end - pos)
                    return pos;
        pos += ret;
    }
    if (data.key_mgmt & WPA_KEY_MGMT_WPA_NONE) {
        ret = os_snprintf(pos, end - pos, "%sNone",
                          pos == start ? "" : "+");
        if (ret < 0 || ret >= end - pos)
                    return pos;
        pos += ret;
    }
    #ifdef CONFIG_IEEE80211R
        if (data.key_mgmt & WPA_KEY_MGMT_FT_IEEE8021X) {
        ret = os_snprintf(pos, end - pos, "%sFT/EAP",
                          pos == start ? "" : "+");
        if (ret < 0 || ret >= end - pos)
                    return pos;
        pos += ret;
    }
    if (data.key_mgmt & WPA_KEY_MGMT_FT_PSK) {
        ret = os_snprintf(pos, end - pos, "%sFT/PSK",
                          pos == start ? "" : "+");
        if (ret < 0 || ret >= end - pos)
                    return pos;
        pos += ret;
    }
    #endif 
    /* CONFIG_IEEE80211R */
    #ifdef CONFIG_IEEE80211W
        if (data.key_mgmt & WPA_KEY_MGMT_IEEE8021X_SHA256) {
        ret = os_snprintf(pos, end - pos, "%sEAP-SHA256",
                          pos == start ? "" : "+");
        if (ret < 0 || ret >= end - pos)
                    return pos;
        pos += ret;
    }
    if (data.key_mgmt & WPA_KEY_MGMT_PSK_SHA256) {
        ret = os_snprintf(pos, end - pos, "%sPSK-SHA256",
                          pos == start ? "" : "+");
        if (ret < 0 || ret >= end - pos)
                    return pos;
        pos += ret;
    }
    #endif 
    /* CONFIG_IEEE80211W */
    pos = wpa_supplicant_cipher_txt(pos, end, data.pairwise_cipher);
    if (data.capabilities & WPA_CAPABILITY_PREAUTH) {
        ret = os_snprintf(pos, end - pos, "-preauth");
        if (ret < 0 || ret >= end - pos)
                    return pos;
        pos += ret;
    }
    ret = os_snprintf(pos, end - pos, "]");
    if (ret < 0 || ret >= end - pos)
            return pos;
    pos += ret;
    return pos;
}

 int wpa_supplicant_ctrl_iface_scan_result(
    struct wpa_supplicant *wpa_s,json_rpc_t *json_rpc,
    const struct wpa_bss *bss, char *buf, size_t buflen) {
    char *pos, *end;
    int ret;
    const u8 *ie, *ie2, *p2p;
    p2p = wpa_bss_get_vendor_ie(bss, P2P_IE_VENDOR_TYPE);
    if (!p2p)
            p2p = wpa_bss_get_vendor_ie_beacon(bss, P2P_IE_VENDOR_TYPE);
    if (p2p && bss->ssid_len == P2P_WILDCARD_SSID_LEN &&
            os_memcmp(bss->ssid, P2P_WILDCARD_SSID, P2P_WILDCARD_SSID_LEN) ==
            0)
            return 0;
    pos = buf;
    end = buf + buflen;
    json_rpc_append_int(json_rpc, "frequency : ", bss->freq);
    json_rpc_append_int(json_rpc, "signal_level : ", bss->level);
    ie = wpa_bss_get_vendor_ie(bss, WPA_IE_VENDOR_TYPE);
    if (ie)
            pos = wpa_supplicant_ie_txt(pos, end, "WPA", ie, 2 + ie[1]);
    ie2 = wpa_bss_get_ie(bss, WLAN_EID_RSN);
    if (ie2)
            pos = wpa_supplicant_ie_txt(pos, end, "WPA2", ie2, 2 + ie2[1]);
    //pos = wpa_supplicant_wps_ie_txt(wpa_s, pos, end, bss);
    if (!ie && !ie2 && bss->caps & IEEE80211_CAP_PRIVACY) {
        ret = os_snprintf(pos, end - pos, "[WEP]");
        if (ret < 0 || ret >= end - pos)
                    return -1;
        pos += ret;
    }
    if (bss_is_dmg(bss)) {
        const char *s;
        ret = os_snprintf(pos, end - pos, "[DMG]");
        if (ret < 0 || ret >= end - pos)
                    return -1;
        pos += ret;
        switch (bss->caps & IEEE80211_CAP_DMG_MASK) {
            case IEEE80211_CAP_DMG_IBSS:
                        s = "[IBSS]";
            break;
            case IEEE80211_CAP_DMG_AP:
                        s = "[ESS]";
            break;
            case IEEE80211_CAP_DMG_PBSS:
                        s = "[PBSS]";
            break;
            default:
                        s = "";
            break;
        }
        ret = os_snprintf(pos, end - pos, "%s", s);
        if (ret < 0 || ret >= end - pos)
                    return -1;
        pos += ret;
    } else {
        if (bss->caps & IEEE80211_CAP_IBSS) {
            ret = os_snprintf(pos, end - pos, "[IBSS]");
            if (ret < 0 || ret >= end - pos)
                            return -1;
            pos += ret;
        }
        if (bss->caps & IEEE80211_CAP_ESS) {
            ret = os_snprintf(pos, end - pos, "[ESS]");
            if (ret < 0 || ret >= end - pos)
                            return -1;
            pos += ret;
        }
    }
    if (p2p) {
        ret = os_snprintf(pos, end - pos, "[P2P]");
        if (ret < 0 || ret >= end - pos)
                    return -1;
        pos += ret;
    }
    #ifdef CONFIG_HS20
        if (wpa_bss_get_vendor_ie(bss, HS20_IE_VENDOR_TYPE) && ie2) {
        ret = os_snprintf(pos, end - pos, "[HS20]");
        if (ret < 0 || ret >= end - pos)
                    return -1;
        pos += ret;
    }
    #endif 
    json_rpc_append_str(json_rpc, "ssid : ", wpa_ssid_txt(bss->ssid, bss->ssid_len));
    json_rpc_append_str(json_rpc, "flags : ", buf);
    return pos - buf;
}

 int wpa_supplicant_ap_scan(
        struct wpa_supplicant *wpa_s, int ap_scan) {
    return wpa_supplicant_set_ap_scan(wpa_s, ap_scan);
}

 int wpa_supplicant_scan_results(
        struct wpa_supplicant *wpa_s,json_rpc_t *json_rpc ,char *buf, size_t buflen) {
    char *pos, *end;
    struct wpa_bss *bss;
    pos = buf;
    end = buf + buflen;
    json_rpc_append_args(json_rpc,
            JSON_KEY, "wifi_available_list", -1,
            JSON_ARRAY_BEGIN,
            -1);
    dl_list_for_each(bss, &wpa_s->bss_id, struct wpa_bss, list_id) {
        json_rpc_append_args(json_rpc, JSON_OBJECT_BEGIN, -1);
        wpa_supplicant_ctrl_iface_scan_result(wpa_s,json_rpc,bss, pos,end - pos);
        json_rpc_append_args(json_rpc, JSON_OBJECT_END, -1);
    }
    json_rpc_append_args(json_rpc, JSON_ARRAY_END, -1);
    return pos - buf;
}

 int wpa_supplicant_add_network(
    struct wpa_supplicant *wpa_s, char *buf, size_t buflen) {
    struct wpa_ssid *ssid;
    int ret;
    wpa_printf(MSG_DEBUG, "CTRL_IFACE: ADD_NETWORK");
    ssid = wpa_config_add_network(wpa_s->conf);
    if (ssid == NULL)
            return -1;
    wpas_notify_network_added(wpa_s, ssid);
    ssid->disabled = 1;
    wpa_config_set_network_defaults(ssid);
    ret = os_snprintf(buf, buflen, "%d\n", ssid->id);
    if (ret < 0 || (size_t) ret >= buflen)
            return -1;
    return ret;
}

 int wpa_supplicant_set_network(
    struct wpa_supplicant *wpa_s, char *cmd) {
    int id;
    struct wpa_ssid *ssid;
    char *name, *value;
    /* cmd: "<network id> <variable name> <value>" */
    name = os_strchr(cmd, ' ');
    if (name == NULL)
            return -1;
    *name++ = '\0';
    value = os_strchr(name, ' ');
    if (value == NULL)
            return -1;
    *value++ = '\0';
    id = atoi(cmd);
    wpa_printf(MSG_DEBUG, "CTRL_IFACE: SET_NETWORK id=%d name='%s'",
               id, name);
    wpa_hexdump_ascii_key(MSG_DEBUG, "CTRL_IFACE: value",
                      (u8 *) value, os_strlen(value));
    ssid = wpa_config_get_network(wpa_s->conf, id);
    if (ssid == NULL) {
        wpa_printf(MSG_DEBUG, "CTRL_IFACE: Could not find network "
                       "id=%d", id);
        return -1;
    }
    return wpa_supplicant_ctrl_iface_update_network(wpa_s, ssid, name,
                                value);
}

 int wpa_supplicant_ctrl_iface_select_network(
    struct wpa_supplicant *wpa_s, char *cmd) {
    int id;
    struct wpa_ssid *ssid;
    char *pos;
    /* cmd: "<network id>" or "any" */
    if (os_strncmp(cmd, "any", 3) == 0) {
        wpa_printf(MSG_DEBUG, "CTRL_IFACE: SELECT_NETWORK any");
        ssid = NULL;
    } else {
        id = atoi(cmd);
        wpa_printf(MSG_DEBUG, "CTRL_IFACE: SELECT_NETWORK id=%d", id);
        ssid = wpa_config_get_network(wpa_s->conf, id);
        if (ssid == NULL) {
            wpa_printf(MSG_DEBUG, "CTRL_IFACE: Could not find "
                               "network id=%d", id);
            return -1;
        }
        if (ssid->disabled == 2) {
            wpa_printf(MSG_DEBUG, "CTRL_IFACE: Cannot use "
                               "SELECT_NETWORK with persistent P2P group");
            return -1;
        }
    }
    pos = os_strstr(cmd, " freq=");
    if (pos) {
        int *freqs = freq_range_to_channel_list(wpa_s, pos + 6);
        if (freqs) {
            wpa_s->scan_req = MANUAL_SCAN_REQ;
            os_free(wpa_s->manual_scan_freqs);
            wpa_s->manual_scan_freqs = freqs;
        }
    }
    wpa_supplicant_select_network(wpa_s, ssid);
    return 0;
}

 int wpa_supplicant_ctrl_iface_remove_network(
    struct wpa_supplicant *wpa_s, char *cmd) {
    int id;
    struct wpa_ssid *ssid;
    int was_disabled;
    /* cmd: "<network id>" or "all" */
    if (os_strcmp(cmd, "all") == 0) {
        wpa_printf(MSG_DEBUG, "CTRL_IFACE: REMOVE_NETWORK all");
        if (wpa_s->sched_scanning)
                    wpa_supplicant_cancel_sched_scan(wpa_s);
        eapol_sm_invalidate_cached_session(wpa_s->eapol);
        if (wpa_s->current_ssid) {
            #ifdef CONFIG_SME
                        wpa_s->sme.prev_bssid_set = 0;
            #endif 
            wpa_sm_set_config(wpa_s->wpa, NULL);
            eapol_sm_notify_config(wpa_s->eapol, NULL, NULL);
            wpa_supplicant_deauthenticate(
                            wpa_s, WLAN_REASON_DEAUTH_LEAVING);
        }
        ssid = wpa_s->conf->ssid;
        while (ssid) {
            struct wpa_ssid *remove_ssid = ssid;
            id = ssid->id;
            ssid = ssid->next;
            wpas_notify_network_removed(wpa_s, remove_ssid);
            wpa_config_remove_network(wpa_s->conf, id);
        }
        return 0;
    }
    id = atoi(cmd);
    wpa_printf(MSG_DEBUG, "CTRL_IFACE: REMOVE_NETWORK id=%d", id);
    ssid = wpa_config_get_network(wpa_s->conf, id);
    if (ssid)
            wpas_notify_network_removed(wpa_s, ssid);
    if (ssid == NULL) {
        wpa_printf(MSG_DEBUG, "CTRL_IFACE: Could not find network "
                       "id=%d", id);
        return -1;
    }
    if (ssid == wpa_s->current_ssid || wpa_s->current_ssid == NULL) {
        #ifdef CONFIG_SME
                wpa_s->sme.prev_bssid_set = 0;
        #endif 
        eapol_sm_invalidate_cached_session(wpa_s->eapol);
    }
    if (ssid == wpa_s->current_ssid) {
        wpa_sm_set_config(wpa_s->wpa, NULL);
        eapol_sm_notify_config(wpa_s->eapol, NULL, NULL);
        wpa_supplicant_deauthenticate(wpa_s,
                                  WLAN_REASON_DEAUTH_LEAVING);
    }
    was_disabled = ssid->disabled;
    if (wpa_config_remove_network(wpa_s->conf, id) < 0) {
        wpa_printf(MSG_DEBUG, "CTRL_IFACE: Not able to remove the "
                       "network id=%d", id);
        return -1;
    }
    if (!was_disabled && wpa_s->sched_scanning) {
        wpa_printf(MSG_DEBUG, "Stop ongoing sched_scan to remove "
                       "network from filters");
        wpa_supplicant_cancel_sched_scan(wpa_s);
        wpa_supplicant_req_scan(wpa_s, 0, 0);
    }
    return 0;
}
