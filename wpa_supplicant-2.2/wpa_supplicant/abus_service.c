#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "abus_service.h"
#include "abus.h"
#include <abus/json.h>

static void svc_ap_scan_cb(json_rpc_t *json_rpc, void *arg) {
    int a;
    struct wpa_supplicant *wpa_s=arg;
    json_rpc_get_int(json_rpc, "a", &a);
    if(a==0 || a==1 || a==2)
                wpa_supplicant_ap_scan(wpa_s,a); 
    else
                json_rpc_append_int(json_rpc, "a must be equal to 0 or 1 or 2. you put : ", a);
}

static void svc_scan_results_cb(json_rpc_t *json_rpc, void *arg) {
    struct wpa_supplicant *wpa_s=arg;
    char *reply;
    const int reply_size = 4096;
    reply = os_malloc(reply_size);
    wpa_supplicant_scan_results(wpa_s,json_rpc, reply, reply_size);
}

static void svc_add_network_cb(json_rpc_t *json_rpc, void *arg) {
    struct wpa_supplicant *wpa_s=arg;
    char *reply;
    const int reply_size = 4096;
    reply = os_malloc(reply_size);
    wpa_supplicant_add_network(wpa_s, reply, reply_size);
    json_rpc_append_str(json_rpc, "network added num : ", reply);
}

static void svc_set_network_cb(json_rpc_t *json_rpc, void *arg) {
    char str[1000];
    int res=0;
    struct wpa_supplicant *wpa_s=arg;
    json_rpc_get_str(json_rpc, "str", str, sizeof(str));
    /* str: "<network id> <variable name> <value>" */
    res = wpa_supplicant_set_network(wpa_s, str);
    if(res==-1)
        json_rpc_append_int(json_rpc, "Error ", res);
}

static void svc_select_network_cb(json_rpc_t *json_rpc, void *arg) {
    char str[10];
    int res=0;
    struct wpa_supplicant *wpa_s=arg;
    /* str: "<network id>" or "any" */
    json_rpc_get_str(json_rpc, "str", str, sizeof(str));
    res = wpa_supplicant_ctrl_iface_select_network(wpa_s, str);
    if(res==-1)
        json_rpc_append_int(json_rpc, "Error ", res);
}

static void svc_remove_network_cb(json_rpc_t *json_rpc, void *arg) {
    char str[10];
    int res=0;
    struct wpa_supplicant *wpa_s=arg;
    /* str: "<network id>" or "all" */
    json_rpc_get_str(json_rpc, "str", str, sizeof(str));
    res = wpa_supplicant_ctrl_iface_remove_network(wpa_s, str);
    if(res==-1)
        json_rpc_append_int(json_rpc, "Error ", res);
}

static void wpa_abus_event(int sock, void *eloop_ctx,
					      void *sock_ctx)
{
	abus_t *abus=sock_ctx;
	 abus_process_incoming(abus);
}


int wpa_abus_init(struct wpa_supplicant *wpa) {
    abus_t *abus;
    int ret;
    abus_conf_t abus_conf;
    int fd=0;
    abus = abus_init(NULL);

    abus_get_conf(abus, &abus_conf);
    
    abus_conf.poll_operation = 1;
    abus_set_conf(abus, &abus_conf);
    
    if(ret == -1)
    	return EXIT_FAILURE;
    

    ret = abus_decl_method(abus, "wpa_supp", "ap_scan", &svc_ap_scan_cb,
                                            ABUS_RPC_FLAG_NONE,
                                            wpa,
                                            "Send a notification to begin scanning",
                                            "a:i:type of ap_scan (0,1,2)",
                                            " ");
    if (ret != 0) {
        abus_cleanup(abus);
        return EXIT_FAILURE;
    }
    ret = abus_decl_method(abus, "wpa_supp", "scan_results", &svc_scan_results_cb,
                                            ABUS_RPC_FLAG_NONE,
                                            wpa,
                                            "Read the results of scanning",
                                            "",
                                            "reply:s:Read the results");
    if (ret != 0) {
        abus_cleanup(abus);
        return EXIT_FAILURE;
    }
    ret = abus_decl_method(abus, "wpa_supp", "add_network", &svc_add_network_cb,
                                            ABUS_RPC_FLAG_NONE,
                                            wpa,
                                            "add a network",
                                            "",
                                            "");
    if (ret != 0) {
        abus_cleanup(abus);
        return EXIT_FAILURE;
    }
    ret = abus_decl_method(abus, "wpa_supp", "set_network", &svc_set_network_cb,
                                            ABUS_RPC_FLAG_NONE,
                                            wpa,
                                            "Set a network",
                                            "str:s:write the commande : <network id> <variable name> <value>",
                                            "");
    if (ret != 0) {
        abus_cleanup(abus);
        return EXIT_FAILURE;
    }
    ret = abus_decl_method(abus, "wpa_supp", "select_network", &svc_select_network_cb,
                                            ABUS_RPC_FLAG_NONE,
                                            wpa,
                                            "Select a network",
                                            "str:s:write the id of the network",
                                            "");
    if (ret != 0) {
        abus_cleanup(abus);
        return EXIT_FAILURE;
    }
    ret = abus_decl_method(abus, "wpa_supp", "remove_network", &svc_remove_network_cb,
                                            ABUS_RPC_FLAG_NONE,
                                            wpa,
                                            "remove a network",
                                            "str:s:write the id of the network",
                                            "");
    if (ret != 0) {
        abus_cleanup(abus);
        return EXIT_FAILURE;
    }

    fd = abus_get_fd(abus);
    ret = eloop_register_read_sock(fd, wpa_abus_event,wpa, abus);


    return EXIT_SUCCESS;
}