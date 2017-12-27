#pragma once

#include <osmocom/msc/vlr.h>

struct osmo_gsup_message;

const char *vlr_subscr_name(struct vlr_subscr *vsub);
int vlr_subscr_req_lu(struct vlr_subscr *vsub, bool is_ps);
int vlr_subscr_req_sai(struct vlr_subscr *vsub, const uint8_t *auts,
		       const uint8_t *auts_rand);
struct vlr_subscr *vlr_subscr_alloc(struct vlr_instance *vlr);
void vlr_subscr_update_tuples(struct vlr_subscr *vsub,
			      const struct osmo_gsup_message *gsup);
