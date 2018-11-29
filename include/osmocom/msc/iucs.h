#pragma once

#include <osmocom/msc/transaction.h>

struct ranap_ue_conn_ctx;

int gsm0408_rcvmsg_iucs(struct gsm_network *network, struct msgb *msg,
			uint16_t *lac);

struct ran_conn *ran_conn_lookup_iu(struct gsm_network *network,
				    struct ranap_ue_conn_ctx *ue);
int iu_rab_act_cs(struct gsm_trans *trans);

uint32_t iu_get_conn_id(const struct ranap_ue_conn_ctx *ue);
