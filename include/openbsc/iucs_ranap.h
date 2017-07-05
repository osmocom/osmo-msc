#pragma once

struct gsm_network;
struct ranap_ue_conn_ctx;

int iucs_rx_ranap_event(struct gsm_network *network,
			struct ranap_ue_conn_ctx *ue_ctx, int type, void *data);
