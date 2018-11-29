#pragma once

/* Routines for the MSC handling */

struct gsm_network;
struct vlr_subscr;

#define MSC_HLR_REMOTE_IP_DEFAULT "127.0.0.1"
#define MSC_HLR_REMOTE_PORT_DEFAULT OSMO_GSUP_PORT

int msc_vlr_alloc(struct gsm_network *net);
int msc_vlr_start(struct gsm_network *net);

void msc_stop_paging(struct vlr_subscr *vsub);
