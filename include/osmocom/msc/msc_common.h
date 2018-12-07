#pragma once

#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/gsm0808.h>

struct msgb;
struct gsm_network;
struct vlr_subscr;

#define MSC_HLR_REMOTE_IP_DEFAULT "127.0.0.1"
#define MSC_HLR_REMOTE_PORT_DEFAULT OSMO_GSUP_PORT

/* TS 48.008 DLCI containing DCCH/ACCH + SAPI */
#define OMSC_LINKID_CB(__msgb)   (__msgb)->cb[3]

enum nsap_addr_enc {
	NSAP_ADDR_ENC_X213,
	NSAP_ADDR_ENC_V4RAW,
};

#define MAX_A5_KEY_LEN	(128/8)

struct geran_encr {
	/*! alg_id is in encoded format:
	 * alg_id == 1 means A5/0 i.e. no encryption, alg_id == 4 means A5/3.
	 * alg_id == 0 means no such IE was present. */
	uint8_t alg_id;
	uint8_t key_len;
	uint8_t key[MAX_A5_KEY_LEN];
};

enum complete_layer3_type {
	COMPLETE_LAYER3_NONE,
	COMPLETE_LAYER3_LU,
	COMPLETE_LAYER3_CM_SERVICE_REQ,
	COMPLETE_LAYER3_PAGING_RESP,
};

extern const struct value_string complete_layer3_type_names[];
static inline const char *complete_layer3_type_name(enum complete_layer3_type val)
{
	return get_value_string(complete_layer3_type_names, val);
}

struct cell_ids_entry {
	struct llist_head entry;
	struct gsm0808_cell_id_list2 cell_ids;
};

typedef int (*mncc_recv_cb_t)(struct gsm_network *, struct msgb *);

struct gsm_network *gsm_network_init(void *ctx, mncc_recv_cb_t mncc_recv);
void gsm_network_set_mncc_sock_path(struct gsm_network *net, const char *mncc_sock_path);

extern const struct vlr_ops msc_vlr_ops;
int msc_vlr_alloc(struct gsm_network *net);
int msc_vlr_start(struct gsm_network *net);
int msc_gsup_client_start(struct gsm_network *net);

uint32_t msc_cc_next_outgoing_callref();
