#pragma once

#include <stdint.h>

struct osmo_gsup_message;
struct vlr_subscr;
struct gsm_trans;
struct msgb;

int gsm411_gsup_mo_ready_for_sm_req(struct gsm_trans *trans, uint8_t sm_rp_mr);
int gsm411_gsup_mo_fwd_sm_req(struct gsm_trans *trans, struct msgb *msg,
	uint8_t sm_rp_mr, uint8_t *sm_rp_da, uint8_t sm_rp_da_len);
int gsm411_gsup_mo_handler(struct vlr_subscr *vsub,
	struct osmo_gsup_message *gsup_msg);
