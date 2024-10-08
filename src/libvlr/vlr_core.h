#pragma once

#include <osmocom/vlr/vlr.h>

struct osmo_gsup_message;

int vlr_subscr_req_lu(struct vlr_subscr *vsub) __attribute__((warn_unused_result));
int vlr_subscr_req_sai(struct vlr_subscr *vsub, const uint8_t *auts,
		       const uint8_t *auts_rand) __attribute__((warn_unused_result));
int vlr_subscr_tx_req_check_imei(const struct vlr_subscr *vsub);
void vlr_subscr_update_tuples(struct vlr_subscr *vsub,
			      const struct osmo_gsup_message *gsup);

/* Logging */
extern int g_vlr_log_cat[_OSMO_VLR_LOGC_MAX];

#define LOGVLR(lvl, fmt, args...) LOGP(g_vlr_log_cat[OSMO_VLR_LOGC_VLR], lvl, fmt, ## args)
#define LOGSGS(lvl, fmt, args...) LOGP(g_vlr_log_cat[OSMO_VLR_LOGC_SGS], lvl, fmt, ## args)

#define LOGGSUPP(level, gsup, fmt, args...)				\
	LOGVLR(level, "GSUP(%s) " fmt, (gsup)->imsi, ## args)

#define LOGVSUBP(level, vsub, fmt, args...)				\
	LOGVLR(level, "SUBSCR(%s) " fmt, vlr_subscr_name(vsub), ## args)

