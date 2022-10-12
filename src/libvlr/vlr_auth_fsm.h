#pragma once

#include <osmocom/core/utils.h>

/* Parameters to VLR_AUTH_E_MS_AUTH_RESP */
struct vlr_auth_resp_par {
	bool is_r99;
	bool is_utran;
	const uint8_t *res;
	unsigned int res_len;
	const uint8_t *auts;
};

enum vlr_fsm_auth_event {
	VLR_AUTH_E_START,
	/* TS 23.018 OAS_VLR1(2): SendAuthInfo ACK from HLR */
	VLR_AUTH_E_HLR_SAI_ACK,
	/* TS 23.018 OAS_VLR1(2): SendAuthInfo NACK from HLR */
	VLR_AUTH_E_HLR_SAI_NACK,
	/* FIXME: merge with NACK? */
	VLR_AUTH_E_HLR_SAI_ABORT,
	/* Authentication Response from MS */
	VLR_AUTH_E_MS_AUTH_RESP,
	/* Authentication Failure from MS */
	VLR_AUTH_E_MS_AUTH_FAIL,
	/* Identity Response (IMSI) from MS */
	VLR_AUTH_E_MS_ID_IMSI,
};

extern struct osmo_fsm vlr_auth_fsm;

struct osmo_fsm_inst *auth_fsm_start(struct vlr_subscr *vsub,
				     struct osmo_fsm_inst *parent,
				     uint32_t parent_event_success,
				     uint32_t parent_event_no_auth_info,
				     uint32_t parent_event_failure,
				     bool is_r99,
				     bool is_utran);

bool auth_try_reuse_tuple(struct vlr_subscr *vsub, uint8_t key_seq);
