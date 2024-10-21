/* Osmocom Visitor Location Register (VLR) Authentication FSM */

/* (C) 2016 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */


#include <osmocom/core/fsm.h>
#include <osmocom/core/tdef.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/gsup.h>
#include <osmocom/vlr/vlr.h>

#include "vlr_core.h"
#include "vlr_auth_fsm.h"

#define S(x)	(1 << (x))

static const struct value_string fsm_auth_event_names[] = {
	OSMO_VALUE_STRING(VLR_AUTH_E_START),
	OSMO_VALUE_STRING(VLR_AUTH_E_HLR_SAI_ACK),
	OSMO_VALUE_STRING(VLR_AUTH_E_HLR_SAI_NACK),
	OSMO_VALUE_STRING(VLR_AUTH_E_HLR_SAI_ABORT),
	OSMO_VALUE_STRING(VLR_AUTH_E_MS_AUTH_RESP),
	OSMO_VALUE_STRING(VLR_AUTH_E_MS_AUTH_FAIL),
	OSMO_VALUE_STRING(VLR_AUTH_E_MS_ID_IMSI),
	{ 0, NULL }
};

struct osmo_tdef_state_timeout msc_auth_tdef_states[32] = {
    [VLR_SUB_AS_WAIT_RESP] = { .T = 3260 },
    [VLR_SUB_AS_WAIT_RESP_RESYNC] = { .T = 3260 },
    [VLR_SUB_AS_WAIT_ID_IMSI] = { .T = 3270 },
};

struct osmo_tdef_state_timeout sgsn_auth_tdef_states[32] = {
    [VLR_SUB_AS_WAIT_RESP] = { .T = 3360 },
    [VLR_SUB_AS_WAIT_RESP_RESYNC] = { .T = 3360 },
    [VLR_SUB_AS_WAIT_ID_IMSI] = { .T = 3370 },
};

struct osmo_tdef_state_timeout *auth_fsm_state_tdef;

/* private state of the auth_fsm_instance */
struct auth_fsm_priv {
	struct vlr_subscr *vsub;
	bool by_imsi;
	bool is_r99;
	bool is_utran;
	bool auth_requested;

	int auth_tuple_max_reuse_count; /* see vlr->cfg instead */

	uint32_t parent_event_success;
	uint32_t parent_event_no_auth_info;
	uint32_t parent_event_failure;
};

/***********************************************************************
 * Utility functions
 ***********************************************************************/

/* Always use either vlr_subscr_get_auth_tuple() or vlr_subscr_has_auth_tuple()
 * instead, to ensure proper use count.
 * Return an auth tuple with the lowest use_count among the auth tuples. If
 * max_reuse_count >= 0, return NULL if all available auth tuples have a use
 * count > max_reuse_count. If max_reuse_count is negative, return a currently
 * least used auth tuple without enforcing a maximum use count.  If there are
 * no auth tuples, return NULL.
 */
static struct vlr_auth_tuple *
_vlr_subscr_next_auth_tuple(struct vlr_subscr *vsub, int max_reuse_count)
{
	unsigned int count;
	unsigned int idx;
	struct vlr_auth_tuple *at = NULL;
	unsigned int key_seq = VLR_KEY_SEQ_INVAL;

	if (!vsub)
		return NULL;

	if (vsub->last_tuple)
		key_seq = vsub->last_tuple->key_seq;

	if (key_seq == VLR_KEY_SEQ_INVAL)
		/* Start with 0 after increment modulo array size */
		idx = ARRAY_SIZE(vsub->auth_tuples) - 1;
	else
		idx = key_seq;

	for (count = ARRAY_SIZE(vsub->auth_tuples); count > 0; count--) {
		idx = (idx + 1) % ARRAY_SIZE(vsub->auth_tuples);

		if (vsub->auth_tuples[idx].key_seq == VLR_KEY_SEQ_INVAL)
			continue;

		if (!at || vsub->auth_tuples[idx].use_count < at->use_count)
			at = &vsub->auth_tuples[idx];
	}

	if (!at || (max_reuse_count >= 0 && at->use_count > max_reuse_count))
		return NULL;

	return at;
}

/* Return an auth tuple and increment its use count. */
static struct vlr_auth_tuple *
vlr_subscr_get_auth_tuple(struct vlr_subscr *vsub, int max_reuse_count)
{
	struct vlr_auth_tuple *at = _vlr_subscr_next_auth_tuple(vsub,
							       max_reuse_count);
	if (!at)
		return NULL;
	at->use_count++;
	return at;
}

/* Return whether an auth tuple with a matching use_count is available. */
static bool vlr_subscr_has_auth_tuple(struct vlr_subscr *vsub,
				      int max_reuse_count)
{
	return _vlr_subscr_next_auth_tuple(vsub, max_reuse_count) != NULL;
}

static bool check_auth_resp(struct vlr_subscr *vsub, bool is_r99,
			    bool is_utran, const uint8_t *res,
			    uint8_t res_len)
{
	struct vlr_auth_tuple *at = vsub->last_tuple;
	struct osmo_auth_vector *vec = &at->vec;
	bool check_umts;
	bool res_is_umts_aka;
	OSMO_ASSERT(at);

	LOGVSUBP(LOGL_DEBUG, vsub, "AUTH on %s received %s: %s (%u bytes)\n",
		 is_utran ? "UTRAN" : "GERAN",
		 is_utran ? "RES" : "SRES/RES",
		 osmo_hexdump_nospc(res, res_len), res_len);

	/* RES must be present and at least 32bit */
	if (!res || !res_len) {
		LOGVSUBP(LOGL_NOTICE, vsub, "AUTH SRES/RES missing\n");
		goto out_false;
	}

	/* We're deciding the UMTS AKA-ness of the response by the RES size. So let's make sure we can't
	 * mix them up by size. On UTRAN, we expect full length RES always, no way to mix up there. */
	if (!is_utran && vec->res_len == sizeof(vec->sres))
		LOGVSUBP(LOGL_ERROR, vsub, "Unforeseen situation: UMTS AKA's RES length"
			 " equals the size of SRES: %u -- this code wants to differentiate"
			 " the two by their size, which won't work properly now.\n", vec->res_len);

	/* RES must be either vec->res_len (UMTS AKA) or sizeof(sres) (GSM AKA) */
	if (res_len == vec->res_len)
		res_is_umts_aka = true;
	else if (res_len == sizeof(vec->sres))
		res_is_umts_aka = false;
	else {
		if (is_utran)
			LOGVSUBP(LOGL_NOTICE, vsub, "AUTH RES has invalid length: %u."
				 " Expected %u (UMTS AKA)\n",
				 res_len, vec->res_len);
		else
			LOGVSUBP(LOGL_NOTICE, vsub, "AUTH SRES/RES has invalid length: %u."
				 " Expected either %zu (GSM AKA) or %u (UMTS AKA)\n",
				 res_len, sizeof(vec->sres), vec->res_len);
		goto out_false;
	}

	check_umts = (is_r99
		      && (vec->auth_types & OSMO_AUTH_TYPE_UMTS)
		      && res_is_umts_aka);

	/* Even on an R99 capable MS with a UMTS AKA capable USIM,
	 * the MS may still choose to only perform GSM AKA, as
	 * long as the bearer is GERAN -- never on UTRAN: */
	if (is_utran && !check_umts) {
		LOGVSUBP(LOGL_ERROR, vsub,
			 "AUTH via UTRAN, cannot allow GSM AKA"
			 " (MS is %sR99 capable, vec has %sUMTS AKA tokens, res_len=%u is %s)\n",
			 is_r99 ? "" : "NOT ",
			 (vec->auth_types & OSMO_AUTH_TYPE_UMTS) ? "" : "NO ",
			 res_len, (res_len == vec->res_len)? "valid" : "INVALID on UTRAN");
		goto out_false;
	}

	if (check_umts) {
		if (res_len != vec->res_len
		    || memcmp(res, vec->res, res_len)) {
			LOGVSUBP(LOGL_INFO, vsub, "UMTS AUTH failure:"
				 " mismatching res (expected res=%s)\n",
				 osmo_hexdump(vec->res, vec->res_len));
			goto out_false;
		}

		LOGVSUBP(LOGL_INFO, vsub, "AUTH established UMTS security"
			 " context\n");
		vsub->sec_ctx = VLR_SEC_CTX_UMTS;
		return true;
	} else {
		if (res_len != sizeof(vec->sres)
		    || memcmp(res, vec->sres, sizeof(vec->sres))) {
			LOGVSUBP(LOGL_INFO, vsub, "GSM AUTH failure:"
				 " mismatching sres (expected sres=%s)\n",
				 osmo_hexdump(vec->sres, sizeof(vec->sres)));
			goto out_false;
		}

		LOGVSUBP(LOGL_INFO, vsub, "AUTH established GSM security"
			 " context\n");
		vsub->sec_ctx = VLR_SEC_CTX_GSM;
		return true;
	}

out_false:
	vsub->sec_ctx = VLR_SEC_CTX_NONE;
	return false;
}

static void auth_fsm_onenter_failed(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct auth_fsm_priv *afp = fi->priv;
	struct vlr_subscr *vsub = afp->vsub;

	/* If authentication hasn't even started, e.g. the HLR sent no auth
	 * info, then we also don't need to tell the HLR about an auth failure.
	 */
	if (afp->auth_requested) {
		int rc = vlr_subscr_tx_auth_fail_rep(vsub);
		if (rc < 0)
			LOGVSUBP(LOGL_ERROR, vsub, "Failed to communicate AUTH failure to HLR\n");
	}
}

enum auth_fsm_result {
	/* Authentication verified the subscriber. */
	AUTH_FSM_PASSED = 0,
	/* HLR does not have authentication info for this subscriber. */
	AUTH_FSM_NO_AUTH_INFO,
	/* Authentication was attempted but failed. */
	AUTH_FSM_FAILURE,
};

const char *auth_fsm_result_str[] = {
	[AUTH_FSM_PASSED] = "PASSED",
	[AUTH_FSM_NO_AUTH_INFO] = "NO_AUTH_INFO",
	[AUTH_FSM_FAILURE] = "FAILURE",
};

/* Terminate the Auth FSM Instance and notify parent */
static void auth_fsm_term(struct osmo_fsm_inst *fi, enum auth_fsm_result result, enum gsm48_reject_value cause)
{
	struct auth_fsm_priv *afp = fi->priv;

	LOGPFSM(fi, "Authentication terminating with result %s%s%s\n",
		auth_fsm_result_str[result],
		cause ? ", cause " : "",
		cause ? gsm48_reject_value_name(cause) : "");

	/* Do one final state transition (mostly for logging purpose)
	 * and set the parent_term_event according to result */
	switch (result) {
	case AUTH_FSM_PASSED:
		osmo_fsm_inst_state_chg(fi, VLR_SUB_AS_AUTHENTICATED, 0, 0);
		fi->proc.parent_term_event = afp->parent_event_success;
		break;
	case AUTH_FSM_NO_AUTH_INFO:
		osmo_fsm_inst_state_chg(fi, VLR_SUB_AS_AUTH_FAILED, 0, 0);
		fi->proc.parent_term_event = afp->parent_event_no_auth_info;
		break;
	case AUTH_FSM_FAILURE:
		osmo_fsm_inst_state_chg(fi, VLR_SUB_AS_AUTH_FAILED, 0, 0);
		fi->proc.parent_term_event = afp->parent_event_failure;
		break;
	}

	/* return the result to the parent FSM */
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, &cause);
}

static void auth_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct auth_fsm_priv *afp = fi->priv;
	struct vlr_subscr *vsub = afp->vsub;
	vsub->auth_fsm = NULL;
}

/* back-end function transmitting authentication. Caller ensures we have valid
 * tuple */
static int _vlr_subscr_authenticate(struct osmo_fsm_inst *fi)
{
	struct auth_fsm_priv *afp = fi->priv;
	struct vlr_subscr *vsub = afp->vsub;
	struct vlr_auth_tuple *at;
	bool use_umts_aka;

	/* Caller ensures we have vectors available */
	at = vlr_subscr_get_auth_tuple(vsub, afp->auth_tuple_max_reuse_count);
	if (!at) {
		LOGPFSML(fi, LOGL_ERROR, "A previous check ensured that an"
			 " auth tuple was available, but now there is in fact"
			 " none.\n");
		auth_fsm_term(fi, AUTH_FSM_FAILURE, GSM48_REJECT_NETWORK_FAILURE);
		return -1;
	}

	use_umts_aka = vlr_use_umts_aka(&at->vec, afp->is_r99);
	LOGPFSM(fi, "got auth tuple: use_count=%d key_seq=%d"
		" -- will use %s AKA (is_r99=%s, at->vec.auth_types=0x%x)\n",
		at->use_count, at->key_seq,
		use_umts_aka ? "UMTS" : "GSM", afp->is_r99 ? "yes" : "no", at->vec.auth_types);

	/* Transmit auth req to subscriber */
	afp->auth_requested = true;
	vsub->last_tuple = at;
	vsub->vlr->ops.tx_auth_req(vsub->msc_conn_ref, at, use_umts_aka);
	return 0;
}

/***********************************************************************
 * FSM State Action functions
 ***********************************************************************/

/* Initial State of TS 23.018 AUT_VLR */
static void auth_fsm_needs_auth(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct auth_fsm_priv *afp = fi->priv;
	struct vlr_subscr *vsub = afp->vsub;

	OSMO_ASSERT(event == VLR_AUTH_E_START);

	/* Start off with the default max_reuse_count, possibly change that if we
	 * need to re-use an old tuple. */
	afp->auth_tuple_max_reuse_count = vsub->vlr->cfg.auth_tuple_max_reuse_count;

	/* Check if we have vectors available */
	if (!vlr_subscr_has_auth_tuple(vsub, afp->auth_tuple_max_reuse_count)) {
		/* Obtain_Authentication_Sets_VLR */
		int rc = vlr_subscr_req_sai(vsub, NULL, NULL);
		if (rc < 0)
			LOGPFSM(fi, "Failed to request Authentication Sets from VLR\n");
		osmo_fsm_inst_state_chg(fi, VLR_SUB_AS_NEEDS_AUTH_WAIT_AI,
					GSM_29002_TIMER_M, 0);
	} else {
		/* go straight ahead with sending auth request */
		osmo_tdef_fsm_inst_state_chg(fi, VLR_SUB_AS_WAIT_RESP, auth_fsm_state_tdef, vlr_tdefs, 6);
		_vlr_subscr_authenticate(fi);
	}
}

/* Waiting for Authentication Info from HLR */
static void auth_fsm_wait_ai(struct osmo_fsm_inst *fi, uint32_t event,
			     void *data)
{
	struct auth_fsm_priv *afp = fi->priv;
	struct vlr_subscr *vsub = afp->vsub;
	struct osmo_gsup_message *gsup = data;

	if (event == VLR_AUTH_E_HLR_SAI_NACK)
		LOGPFSM(fi, "GSUP: rx Auth Info Error cause: %d: %s\n",
			gsup->cause,
			get_value_string(gsm48_gmm_cause_names, gsup->cause));

	/* We are in what corresponds to the
	 * Wait_For_Authentication_Sets state of TS 23.018 OAS_VLR */
	if ((event == VLR_AUTH_E_HLR_SAI_ACK && !gsup->num_auth_vectors)
	    || (event == VLR_AUTH_E_HLR_SAI_NACK &&
		gsup->cause != GMM_CAUSE_IMSI_UNKNOWN)
	    || (event == VLR_AUTH_E_HLR_SAI_ABORT)) {
		if (vsub->vlr->cfg.auth_reuse_old_sets_on_error
		    && vlr_subscr_has_auth_tuple(vsub, -1)) {
			/* To re-use an old tuple, disable the max_reuse_count
			 * constraint. */
			afp->auth_tuple_max_reuse_count = -1;
			goto pass;
		}
	}

	switch (event) {
	case VLR_AUTH_E_HLR_SAI_ACK:
		if (!gsup->num_auth_vectors) {
			auth_fsm_term(fi, AUTH_FSM_FAILURE, GSM48_REJECT_NETWORK_FAILURE);
			return;
		}
		vlr_subscr_update_tuples(vsub, gsup);
		goto pass;
	case VLR_AUTH_E_HLR_SAI_NACK:
		/* HLR did not return Auth Info, hence cannot authenticate. (The caller may still decide to permit
		 * attaching without authentication) */
		auth_fsm_term(fi, AUTH_FSM_NO_AUTH_INFO, vlr_gmm_cause_to_reject_cause_domain(gsup->cause, true));
		break;
	case VLR_AUTH_E_HLR_SAI_ABORT:
		auth_fsm_term(fi, AUTH_FSM_FAILURE, vlr_gmm_cause_to_reject_cause_domain(gsup->cause, true));
		break;
	}

	return;
pass:
	osmo_tdef_fsm_inst_state_chg(fi, VLR_SUB_AS_WAIT_RESP, auth_fsm_state_tdef, vlr_tdefs, 0);

	_vlr_subscr_authenticate(fi);
}

/* Waiting for Authentication Response from MS */
static void auth_fsm_wait_auth_resp(struct osmo_fsm_inst *fi, uint32_t event,
				    void *data)
{
	struct auth_fsm_priv *afp = fi->priv;
	struct vlr_subscr *vsub = afp->vsub;
	struct vlr_instance *vlr = vsub->vlr;
	struct vlr_auth_resp_par *par = data;
	int rc;

	switch (event) {
	case VLR_AUTH_E_MS_AUTH_RESP:
		rc = check_auth_resp(vsub, par->is_r99, par->is_utran,
				     par->res, par->res_len);
		if (rc == false) {
			if (!afp->by_imsi) {
				vlr->ops.tx_id_req(vsub->msc_conn_ref,
						   GSM_MI_TYPE_IMSI);
				osmo_tdef_fsm_inst_state_chg(fi, VLR_SUB_AS_WAIT_ID_IMSI, auth_fsm_state_tdef, vlr_tdefs, 0);
			} else {
				auth_fsm_term(fi, AUTH_FSM_FAILURE, GSM48_REJECT_ILLEGAL_MS);
			}
		} else {
			auth_fsm_term(fi, AUTH_FSM_PASSED, 0);
		}
		break;
	case VLR_AUTH_E_MS_AUTH_FAIL:
		if (par->auts) {
			/* First failure, start re-sync attempt */
			rc = vlr_subscr_req_sai(vsub, par->auts,
					   vsub->last_tuple->vec.rand);
			osmo_fsm_inst_state_chg(fi,
					VLR_SUB_AS_NEEDS_AUTH_WAIT_SAI_RESYNC,
					GSM_29002_TIMER_M, 0);
		} else
			auth_fsm_term(fi, AUTH_FSM_FAILURE, GSM48_REJECT_ILLEGAL_MS);
		break;
	}
}

/* Waiting for Authentication Info from HLR (resync case) */
static void auth_fsm_wait_ai_resync(struct osmo_fsm_inst *fi,
				    uint32_t event, void *data)
{
	struct auth_fsm_priv *afp = fi->priv;
	struct vlr_subscr *vsub = afp->vsub;
	struct osmo_gsup_message *gsup = data;

	/* We are in what corresponds to the
	 * Wait_For_Authentication_Sets state of TS 23.018 OAS_VLR */
	if ((event == VLR_AUTH_E_HLR_SAI_ACK && !gsup->num_auth_vectors) ||
	    (event == VLR_AUTH_E_HLR_SAI_NACK &&
	     gsup->cause != GMM_CAUSE_IMSI_UNKNOWN) ||
	    (event == VLR_AUTH_E_HLR_SAI_ABORT)) {
		/* result = procedure error */
		auth_fsm_term(fi, AUTH_FSM_FAILURE, GSM48_REJECT_NETWORK_FAILURE);
	}
	switch (event) {
	case VLR_AUTH_E_HLR_SAI_ACK:
		vlr_subscr_update_tuples(vsub, gsup);
		osmo_tdef_fsm_inst_state_chg(fi, VLR_SUB_AS_WAIT_RESP_RESYNC, auth_fsm_state_tdef, vlr_tdefs, 0);
		_vlr_subscr_authenticate(fi);
		break;
	case VLR_AUTH_E_HLR_SAI_NACK:
		auth_fsm_term(fi,
			      AUTH_FSM_FAILURE,
			      gsup->cause == GMM_CAUSE_IMSI_UNKNOWN ?
				      GSM48_REJECT_IMSI_UNKNOWN_IN_HLR
				      : GSM48_REJECT_NETWORK_FAILURE);
		break;
	}
}

/* Waiting for AUTH RESP from MS (re-sync case) */
static void auth_fsm_wait_auth_resp_resync(struct osmo_fsm_inst *fi,
					   uint32_t event, void *data)
{
	struct auth_fsm_priv *afp = fi->priv;
	struct vlr_subscr *vsub = afp->vsub;
	struct vlr_auth_resp_par *par = data;
	struct vlr_instance *vlr = vsub->vlr;
	int rc;

	switch (event) {
	case VLR_AUTH_E_MS_AUTH_RESP:
		rc = check_auth_resp(vsub, par->is_r99, par->is_utran,
				     par->res, par->res_len);
		if (rc == false) {
			if (!afp->by_imsi) {
				vlr->ops.tx_id_req(vsub->msc_conn_ref,
						   GSM_MI_TYPE_IMSI);
				osmo_tdef_fsm_inst_state_chg(fi, VLR_SUB_AS_WAIT_ID_IMSI, auth_fsm_state_tdef, vlr_tdefs, 0);
			} else {
				/* Result = Aborted */
				auth_fsm_term(fi, AUTH_FSM_FAILURE, GSM48_REJECT_SYNCH_FAILURE);
			}
		} else {
			/* Result = Pass */
			auth_fsm_term(fi, AUTH_FSM_PASSED, 0);
		}
		break;
	case VLR_AUTH_E_MS_AUTH_FAIL:
		/* Second failure: Result = Fail */
		auth_fsm_term(fi, AUTH_FSM_FAILURE, GSM48_REJECT_SYNCH_FAILURE);
		break;
	}
}

/* AUT_VLR waiting for Obtain_IMSI_VLR result */
static void auth_fsm_wait_imsi(struct osmo_fsm_inst *fi, uint32_t event,
				void *data)
{
	struct auth_fsm_priv *afp = fi->priv;
	struct vlr_subscr *vsub = afp->vsub;
	const char *mi_string = data;

	switch (event) {
	case VLR_AUTH_E_MS_ID_IMSI:
		if (vsub->imsi[0]
		    && !vlr_subscr_matches_imsi(vsub, mi_string)) {
			LOGVSUBP(LOGL_ERROR, vsub, "IMSI in ID RESP differs:"
				 " %s\n", mi_string);
		} else {
			strncpy(vsub->imsi, mi_string, sizeof(vsub->imsi));
			vsub->imsi[sizeof(vsub->imsi)-1] = '\0';
		}
		/* retry with identity=IMSI */
		afp->by_imsi = true;
		osmo_fsm_inst_state_chg(fi, VLR_SUB_AS_NEEDS_AUTH, 0, 0);
		osmo_fsm_inst_dispatch(fi, VLR_AUTH_E_START, NULL);
		break;
	}
}

static const struct osmo_fsm_state auth_fsm_states[] = {
	[VLR_SUB_AS_NEEDS_AUTH] = {
		.name = OSMO_STRINGIFY(VLR_SUB_AS_NEEDS_AUTH),
		.in_event_mask = S(VLR_AUTH_E_START),
		.out_state_mask = S(VLR_SUB_AS_NEEDS_AUTH_WAIT_AI) |
				  S(VLR_SUB_AS_WAIT_RESP),
		.action = auth_fsm_needs_auth,
	},
	[VLR_SUB_AS_NEEDS_AUTH_WAIT_AI] = {
		.name = OSMO_STRINGIFY(VLR_SUB_AS_NEEDS_AUTH_WAIT_AI),
		.in_event_mask = S(VLR_AUTH_E_HLR_SAI_ACK) |
				 S(VLR_AUTH_E_HLR_SAI_NACK),
		.out_state_mask = S(VLR_SUB_AS_AUTH_FAILED) |
				  S(VLR_SUB_AS_WAIT_RESP),
		.action = auth_fsm_wait_ai,
	},
	[VLR_SUB_AS_WAIT_RESP] = {
		.name = OSMO_STRINGIFY(VLR_SUB_AS_WAIT_RESP),
		.in_event_mask = S(VLR_AUTH_E_MS_AUTH_RESP) |
				 S(VLR_AUTH_E_MS_AUTH_FAIL),
		.out_state_mask = S(VLR_SUB_AS_WAIT_ID_IMSI) |
				  S(VLR_SUB_AS_AUTH_FAILED) |
				  S(VLR_SUB_AS_AUTHENTICATED) |
				  S(VLR_SUB_AS_NEEDS_AUTH_WAIT_SAI_RESYNC),
		.action = auth_fsm_wait_auth_resp,
	},
	[VLR_SUB_AS_NEEDS_AUTH_WAIT_SAI_RESYNC] = {
		.name = OSMO_STRINGIFY(VLR_SUB_AS_NEEDS_AUTH_WAIT_SAI_RESYNC),
		.in_event_mask = S(VLR_AUTH_E_HLR_SAI_ACK) |
				 S(VLR_AUTH_E_HLR_SAI_NACK),
		.out_state_mask = S(VLR_SUB_AS_AUTH_FAILED) |
				  S(VLR_SUB_AS_WAIT_RESP_RESYNC),
		.action = auth_fsm_wait_ai_resync,
	},
	[VLR_SUB_AS_WAIT_RESP_RESYNC] = {
		.name = OSMO_STRINGIFY(VLR_SUB_AS_WAIT_RESP_RESYNC),
		.in_event_mask = S(VLR_AUTH_E_MS_AUTH_RESP) |
				 S(VLR_AUTH_E_MS_AUTH_FAIL),
		.out_state_mask = S(VLR_SUB_AS_AUTH_FAILED) |
				  S(VLR_SUB_AS_AUTHENTICATED),
		.action = auth_fsm_wait_auth_resp_resync,
	},
	[VLR_SUB_AS_WAIT_ID_IMSI] = {
		.name = OSMO_STRINGIFY(VLR_SUB_AS_WAIT_ID_IMSI),
		.in_event_mask = S(VLR_AUTH_E_MS_ID_IMSI),
		.out_state_mask = S(VLR_SUB_AS_NEEDS_AUTH),
		.action = auth_fsm_wait_imsi,
	},
	[VLR_SUB_AS_AUTHENTICATED] = {
		.name = OSMO_STRINGIFY(VLR_SUB_AS_AUTHENTICATED),
		.in_event_mask = 0,
		.out_state_mask = 0,
	},
	[VLR_SUB_AS_AUTH_FAILED] = {
		.name = OSMO_STRINGIFY(VLR_SUB_AS_AUTH_FAILED),
		.in_event_mask = 0,
		.out_state_mask = 0,
		.onenter = auth_fsm_onenter_failed,
	},
};

static struct osmo_fsm vlr_auth_fsm = {
	.name = "VLR_Authenticate",
	.states = auth_fsm_states,
	.num_states = ARRAY_SIZE(auth_fsm_states),
	.allstate_event_mask = 0,
	.allstate_action = NULL,
	.log_subsys = DLGLOBAL,
	.event_names = fsm_auth_event_names,
	.cleanup = auth_fsm_cleanup,
};

void vlr_auth_fsm_init(bool is_ps)
{
	if (is_ps)
		auth_fsm_state_tdef = sgsn_auth_tdef_states;
	else
		auth_fsm_state_tdef = msc_auth_tdef_states;

	OSMO_ASSERT(osmo_fsm_register(&vlr_auth_fsm) == 0);
}

void vlr_auth_fsm_set_log_subsys(int log_level)
{
		vlr_auth_fsm.log_subsys = log_level;
}

/***********************************************************************
 * User API (for SGSN/MSC code)
 ***********************************************************************/

/* MSC->VLR: Start Procedure Authenticate_VLR (TS 23.012 Ch. 4.1.2.2) */
struct osmo_fsm_inst *auth_fsm_start(struct vlr_subscr *vsub,
				     struct osmo_fsm_inst *parent,
				     uint32_t parent_event_success,
				     uint32_t parent_event_no_auth_info,
				     uint32_t parent_event_failure,
				     bool is_r99,
				     bool is_utran)
{
	struct osmo_fsm_inst *fi;
	struct auth_fsm_priv *afp;

	fi = osmo_fsm_inst_alloc_child(&vlr_auth_fsm, parent, parent_event_failure);
	if (!fi) {
		osmo_fsm_inst_dispatch(parent, parent_event_failure, 0);
		return NULL;
	}

	afp = talloc_zero(fi, struct auth_fsm_priv);
	if (!afp) {
		osmo_fsm_inst_dispatch(parent, parent_event_failure, 0);
		return NULL;
	}

	afp->vsub = vsub;
	if (vsub->imsi[0])
		afp->by_imsi = true;
	afp->is_r99 = is_r99;
	afp->is_utran = is_utran;
	afp->parent_event_success = parent_event_success;
	afp->parent_event_no_auth_info = parent_event_no_auth_info;
	afp->parent_event_failure = parent_event_failure;
	fi->priv = afp;
	vsub->auth_fsm = fi;

	osmo_fsm_inst_dispatch(fi, VLR_AUTH_E_START, NULL);

	return fi;
}

bool auth_try_reuse_tuple(struct vlr_subscr *vsub, uint8_t key_seq)
{
	int max_reuse_count = vsub->vlr->cfg.auth_tuple_max_reuse_count;
	struct vlr_auth_tuple *at = vsub->last_tuple;

	if (!at)
		return false;
	if ((max_reuse_count >= 0) && (at->use_count > max_reuse_count))
		return false;
	if (at->key_seq != key_seq)
		return false;
	at->use_count++;
	return true;
}

