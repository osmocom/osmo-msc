#pragma once

#include <osmocom/msc/vlr.h>

struct osmo_gsup_message;

int vlr_subscr_req_lu(struct vlr_subscr *vsub) __attribute__((warn_unused_result));
int vlr_subscr_req_sai(struct vlr_subscr *vsub, const uint8_t *auts,
		       const uint8_t *auts_rand) __attribute__((warn_unused_result));
int vlr_subscr_tx_req_check_imei(const struct vlr_subscr *vsub);
void vlr_subscr_update_tuples(struct vlr_subscr *vsub,
			      const struct osmo_gsup_message *gsup);
