#pragma once

struct msgb;
struct gsm_network;
struct vlr_subscr;

#define MSC_HLR_REMOTE_IP_DEFAULT "127.0.0.1"
#define MSC_HLR_REMOTE_PORT_DEFAULT OSMO_GSUP_PORT

enum nsap_addr_enc {
	NSAP_ADDR_ENC_X213,
	NSAP_ADDR_ENC_V4RAW,
};

typedef int (*mncc_recv_cb_t)(struct gsm_network *, struct msgb *);

struct gsm_network *gsm_network_init(void *ctx, mncc_recv_cb_t mncc_recv);

int msc_vlr_alloc(struct gsm_network *net);
int msc_vlr_start(struct gsm_network *net);

void msc_stop_paging(struct vlr_subscr *vsub);
