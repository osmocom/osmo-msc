/* Osmocom Visitor Location Register (VLR): Access Request FSMs */

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
#include <osmocom/gsm/gsup.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/vlr/vlr.h>

#include "vlr_core.h"
#include "vlr_auth_fsm.h"
#include "vlr_lu_fsm.h"
#include "vlr_access_req_fsm.h"

#define S(x)	(1 << (x))

/***********************************************************************
 * Process_Access_Request_VLR, TS 29.002 Chapter 25.4.2
 ***********************************************************************/

static const struct value_string proc_arq_vlr_event_names[] = {
	OSMO_VALUE_STRING(PR_ARQ_E_START),
	OSMO_VALUE_STRING(PR_ARQ_E_ID_IMSI),
	OSMO_VALUE_STRING(PR_ARQ_E_AUTH_RES),
	OSMO_VALUE_STRING(PR_ARQ_E_AUTH_NO_INFO),
	OSMO_VALUE_STRING(PR_ARQ_E_AUTH_FAILURE),
	OSMO_VALUE_STRING(PR_ARQ_E_CIPH_RES),
	OSMO_VALUE_STRING(PR_ARQ_E_UPD_LOC_RES),
	OSMO_VALUE_STRING(PR_ARQ_E_TRACE_RES),
	OSMO_VALUE_STRING(PR_ARQ_E_IMEI_RES),
	OSMO_VALUE_STRING(PR_ARQ_E_PRES_RES),
	OSMO_VALUE_STRING(PR_ARQ_E_TMSI_ACK),
	{ 0, NULL }
};

struct osmo_tdef_state_timeout msc_parq_tdef_states[32] = {
	[PR_ARQ_S_WAIT_CHECK_IMEI]	= { .T = 3270 },
	[PR_ARQ_S_WAIT_OBTAIN_IMSI]	= { .T = 3270 },
};

struct osmo_tdef_state_timeout sgsn_parq_tdef_states[32] = {
	[PR_ARQ_S_WAIT_CHECK_IMEI]	= { .T = 3370 },
	[PR_ARQ_S_WAIT_OBTAIN_IMSI]	= { .T = 3370 },
};

struct osmo_tdef_state_timeout *parq_fsm_state_tdef;

struct proc_arq_priv {
	struct vlr_instance *vlr;
	struct vlr_subscr *vsub;
	void *msc_conn_ref;
	struct osmo_fsm_inst *ul_child_fsm;
	struct osmo_fsm_inst *sub_pres_vlr_fsm;
	uint32_t parent_event_success;
	uint32_t parent_event_failure;
	void *parent_event_data;

	enum vlr_parq_type type;
	enum osmo_cm_service_type cm_service_type;
	enum gsm48_reject_value result; /*< 0 on success */
	bool by_tmsi;
	char imsi[16];
	uint32_t tmsi;
	struct osmo_location_area_id lai;
	bool authentication_required;
	/* is_ciphering_to_be_attempted: true when any A5/n > 0 are enabled. Ciphering is allowed, always attempt to get Auth Info from
	 * the HLR. */
	bool is_ciphering_to_be_attempted;
	/* is_ciphering_required: true when A5/0 is disabled. If we cannot get Auth Info from the HLR, reject the
	 * subscriber. */
	bool is_ciphering_required;
	uint8_t key_seq;
	bool is_r99;
	bool is_utran;
	bool implicitly_accepted_parq_by_ciphering_cmd;
};

static int assoc_par_with_subscr(struct osmo_fsm_inst *fi, struct vlr_subscr *vsub)
{
	struct proc_arq_priv *par = fi->priv;
	struct vlr_instance *vlr = par->vlr;

	vsub->msc_conn_ref = par->msc_conn_ref;
	par->vsub = vsub;
	/* Tell MSC to associate this subscriber with the given
	 * connection */
	return vlr->ops.subscr_assoc(par->msc_conn_ref, par->vsub);
}

static const char *vlr_proc_arq_result_name(const struct osmo_fsm_inst *fi)
{
	struct proc_arq_priv *par = fi->priv;
	return par->result? gsm48_reject_value_name(par->result) : "PASSED";
}

#define proc_arq_fsm_done(fi, res) _proc_arq_fsm_done(fi, res, __FILE__, __LINE__)
static void _proc_arq_fsm_done(struct osmo_fsm_inst *fi,
			       enum gsm48_reject_value gsm48_rej,
			       const char *file, int line)
{
	struct proc_arq_priv *par = fi->priv;
	par->result = gsm48_rej;
	LOGPFSMSRC(fi, file, line, "proc_arq_fsm_done(%s)\n", vlr_proc_arq_result_name(fi));
	osmo_fsm_inst_state_chg(fi, PR_ARQ_S_DONE, 0, 0);
}

static void proc_arq_vlr_dispatch_result(struct osmo_fsm_inst *fi,
					 uint32_t prev_state)
{
	struct proc_arq_priv *par = fi->priv;
	bool success;
	int rc;
	LOGPFSM(fi, "Process Access Request result: %s\n", vlr_proc_arq_result_name(fi));

	success = (par->result == 0);

	/* It would be logical to first dispatch the success event to the
	 * parent FSM, but that could start actions that send messages to the
	 * MS. Rather send the CM Service Accept message first and then signal
	 * success. Since messages are handled synchronously, the success event
	 * will be processed before we handle new incoming data from the MS. */

	if (par->type == VLR_PR_ARQ_T_CM_SERV_REQ) {
		if (success
		    && !par->implicitly_accepted_parq_by_ciphering_cmd) {
			rc = par->vlr->ops.tx_cm_serv_acc(par->msc_conn_ref,
							  par->cm_service_type);
			if (rc) {
				LOGPFSML(fi, LOGL_ERROR,
					 "Failed to send CM Service Accept\n");
				success = false;
			}
		}
		if (!success) {
			rc = par->vlr->ops.tx_cm_serv_rej(par->msc_conn_ref,
							  par->cm_service_type,
							  par->result);
			if (rc)
				LOGPFSML(fi, LOGL_ERROR,
					 "Failed to send CM Service Reject\n");
		}
	}

	/* For VLR_PR_ARQ_T_PAGING_RESP, there is nothing to send. The conn_fsm
	 * will start handling pending paging transactions. */

	if (!fi->proc.parent) {
		LOGPFSML(fi, LOGL_ERROR, "No parent FSM\n");
		return;
	}
	osmo_fsm_inst_dispatch(fi->proc.parent,
			       success ? par->parent_event_success
				       : par->parent_event_failure,
			       par->parent_event_data);
}

void proc_arq_vlr_cleanup(struct osmo_fsm_inst *fi,
			  enum osmo_fsm_term_cause cause)
{
	struct proc_arq_priv *par = fi->priv;
	if (par->vsub && par->vsub->proc_arq_fsm == fi)
		par->vsub->proc_arq_fsm = NULL;
}

static void _proc_arq_vlr_post_imei(struct osmo_fsm_inst *fi)
{
	struct proc_arq_priv *par = fi->priv;
	struct vlr_subscr *vsub = par->vsub;

	LOGPFSM(fi, "%s()\n", __func__);

	/* See 3GPP TS 29.002 Proc_Acc_Req_VLR3. */
	/* TODO: Identity := IMSI */
	if (0 /* TODO: TMSI reallocation at access: vlr->cfg.alloc_tmsi_arq */) {
		vlr_subscr_alloc_tmsi(vsub);
		/* TODO: forward TMSI to MS, wait for TMSI
		 * REALLOC COMPLETE */
		/* TODO: Freeze old TMSI */
		osmo_fsm_inst_state_chg(fi, PR_ARQ_S_WAIT_TMSI_ACK, 0, 0);
		return;
	}

	proc_arq_fsm_done(fi, 0);
}

static void _proc_arq_vlr_post_trace(struct osmo_fsm_inst *fi)
{
	struct proc_arq_priv *par = fi->priv;
	struct vlr_subscr *vsub = par->vsub;
	struct vlr_instance *vlr = vsub->vlr;

	LOGPFSM(fi, "%s()\n", __func__);

	/* Node 3 */
	/* See 3GPP TS 29.002 Proc_Acc_Req_VLR3. */
	if (0 /* IMEI check required */) {
		/* Chck_IMEI_VLR */
		vlr->ops.tx_id_req(par->msc_conn_ref, GSM_MI_TYPE_IMEI);
		osmo_tdef_fsm_inst_state_chg(fi, PR_ARQ_S_WAIT_CHECK_IMEI, parq_fsm_state_tdef, vlr_tdefs, -1);
	} else
		_proc_arq_vlr_post_imei(fi);
}

/* After Subscriber_Present_VLR */
static void _proc_arq_vlr_post_pres(struct osmo_fsm_inst *fi)
{
	LOGPFSM(fi, "%s()\n", __func__);
	/* See 3GPP TS 29.002 Proc_Acc_Req_VLR3. */
	if (0 /* TODO: tracing required */) {
		/* TODO: Trace_Subscriber_Activity_VLR */
		osmo_fsm_inst_state_chg(fi, PR_ARQ_S_WAIT_TRACE_SUB, 0, 0);
	}
	_proc_arq_vlr_post_trace(fi);
}

/* After Update_Location_Child_VLR */
static void _proc_arq_vlr_node2_post_vlr(struct osmo_fsm_inst *fi)
{
	struct proc_arq_priv *par = fi->priv;
	struct vlr_subscr *vsub = par->vsub;

	LOGPFSM(fi, "%s()\n", __func__);

	if (!vsub->sub_dataconf_by_hlr_ind) {
		/* Set User Error: Unidentified Subscriber */
		proc_arq_fsm_done(fi, GSM48_REJECT_IMSI_UNKNOWN_IN_HLR);
		return;
	}
	/* We don't feature location area specific blocking (yet). */
	if (0 /* roaming not allowed in LA */) {
		/* Set User Error: Roaming not allowed in this LA */
		proc_arq_fsm_done(fi, GSM48_REJECT_ROAMING_NOT_ALLOWED);
		return;
	}
	vsub->imsi_detached_flag = false;
	if (vsub->ms_not_reachable_flag) {
		/* Start Subscriber_Present_VLR */
		osmo_fsm_inst_state_chg(fi, PR_ARQ_S_WAIT_SUB_PRES, 0, 0);
		sub_pres_vlr_fsm_start(&par->sub_pres_vlr_fsm, fi, vsub, PR_ARQ_E_PRES_RES);
		return;
	}
	_proc_arq_vlr_post_pres(fi);
}

static void _proc_arq_vlr_node2_post_ciph(struct osmo_fsm_inst *fi)
{
	struct proc_arq_priv *par = fi->priv;
	struct vlr_subscr *vsub = par->vsub;
	int rc;

	LOGPFSM(fi, "%s()\n", __func__);

	rc = par->vlr->ops.tx_common_id(par->msc_conn_ref);
	if (rc)
		LOGPFSML(fi, LOGL_ERROR, "Error while sending Common ID (%d)\n", rc);

	vsub->conf_by_radio_contact_ind = true;
	if (vsub->loc_conf_in_hlr_ind == false) {
		/* start Update_Location_Child_VLR.  WE use
		 * Update_HLR_VLR instead, the differences appear
		 * insignificant for now. */
		par->ul_child_fsm = upd_hlr_vlr_proc_start(fi, vsub,
							PR_ARQ_E_UPD_LOC_RES);
		osmo_fsm_inst_state_chg(fi, PR_ARQ_S_WAIT_UPD_LOC_CHILD, 0, 0);
		return;
	}
	_proc_arq_vlr_node2_post_vlr(fi);
}

/* Return true when CipherModeCmd / SecurityModeCmd should be attempted. */
static bool is_cmc_smc_to_be_attempted(struct proc_arq_priv *par)
{
	/* UTRAN: always send SecModeCmd, even if ciphering is not required.
	 * GERAN: avoid sending CiphModeCmd if ciphering is not required. */
	return par->is_utran || par->is_ciphering_to_be_attempted;
}

static void _proc_arq_vlr_node2(struct osmo_fsm_inst *fi)
{
	struct proc_arq_priv *par = fi->priv;
	struct vlr_subscr *vsub = par->vsub;
	bool umts_aka;

	LOGPFSM(fi, "%s()\n", __func__);

	/* Continue with ciphering, if enabled.
	 * If auth/ciph is optional and the HLR returned no auth info, continue without ciphering. */
	if (!is_cmc_smc_to_be_attempted(par)
	    || (vsub->sec_ctx == VLR_SEC_CTX_NONE && !par->is_ciphering_required)) {
		_proc_arq_vlr_node2_post_ciph(fi);
		return;
	}

	switch (vsub->sec_ctx) {
	case VLR_SEC_CTX_GSM:
		umts_aka = false;
		break;
	case VLR_SEC_CTX_UMTS:
		umts_aka = true;
		break;
	default:
		LOGPFSML(fi, LOGL_ERROR, "Cannot start ciphering, security context is not established\n");
		proc_arq_fsm_done(fi, GSM48_REJECT_NETWORK_FAILURE);
		return;
	}

	if (vlr_set_ciph_mode(vsub->vlr, fi, par->msc_conn_ref,
			      umts_aka,
			      vsub->vlr->cfg.retrieve_imeisv_ciphered)) {
		LOGPFSML(fi, LOGL_ERROR,
			 "Failed to send Ciphering Mode Command\n");
		proc_arq_fsm_done(fi, GSM48_REJECT_NETWORK_FAILURE);
		return;
	}

	par->implicitly_accepted_parq_by_ciphering_cmd = true;
	osmo_fsm_inst_state_chg(fi, PR_ARQ_S_WAIT_CIPH, 0, 0);
}

static bool is_auth_to_be_attempted(struct proc_arq_priv *par)
{
	/* The cases where the authentication procedure should be used
	 * are defined in 3GPP TS 33.102 */
	/* For now we use a default value passed in to vlr_lu_fsm(). */
	return par->authentication_required ||
		(par->is_ciphering_to_be_attempted && !auth_try_reuse_tuple(par->vsub, par->key_seq));
}

/* after the IMSI is known */
static void proc_arq_vlr_fn_post_imsi(struct osmo_fsm_inst *fi)
{
	struct proc_arq_priv *par = fi->priv;
	struct vlr_subscr *vsub = par->vsub;

	LOGPFSM(fi, "%s()\n", __func__);

	OSMO_ASSERT(vsub);

	/* TODO: Identity IMEI -> System Failure */
	if (is_auth_to_be_attempted(par)) {
		osmo_fsm_inst_state_chg(fi, PR_ARQ_S_WAIT_AUTH,
					0, 0);
		vsub->auth_fsm = auth_fsm_start(vsub, fi,
						PR_ARQ_E_AUTH_RES,
						PR_ARQ_E_AUTH_NO_INFO,
						PR_ARQ_E_AUTH_FAILURE,
						par->is_r99,
						par->is_utran);
	} else {
		_proc_arq_vlr_node2(fi);
	}
}

static void proc_arq_vlr_fn_init(struct osmo_fsm_inst *fi,
				 uint32_t event, void *data)
{
	struct proc_arq_priv *par = fi->priv;
	struct vlr_instance *vlr = par->vlr;
	struct vlr_subscr *vsub = NULL;

	OSMO_ASSERT(event == PR_ARQ_E_START);

	/* Obtain_Identity_VLR */
	if (!par->by_tmsi) {
		/* IMSI was included */
		vsub = vlr_subscr_find_by_imsi(par->vlr, par->imsi, __func__);
	} else {
		/* TMSI was included */
		vsub = vlr_subscr_find_by_tmsi(par->vlr, par->tmsi, __func__);
	}
	if (vsub) {
		log_set_context(LOG_CTX_VLR_SUBSCR, vsub);
		if (vsub->proc_arq_fsm && fi != vsub->proc_arq_fsm) {
			LOGPFSML(fi, LOGL_ERROR,
				 "Another proc_arq_fsm is already"
				 " associated with subscr %s,"
				 " terminating the other FSM.\n",
				 vlr_subscr_name(vsub));
			proc_arq_fsm_done(vsub->proc_arq_fsm,
					  GSM48_REJECT_NETWORK_FAILURE);
		}
		vsub->proc_arq_fsm = fi;
		if (assoc_par_with_subscr(fi, vsub) != 0)
			proc_arq_fsm_done(fi, GSM48_REJECT_NETWORK_FAILURE);
		else
			proc_arq_vlr_fn_post_imsi(fi);
		vlr_subscr_put(vsub, __func__);
		return;
	}
	/* No VSUB could be resolved. What now? */

	if (!par->by_tmsi) {
		/* We couldn't find a subscriber even by IMSI,
		 * Set User Error: Unidentified Subscriber */
		proc_arq_fsm_done(fi, GSM48_REJECT_IMSI_UNKNOWN_IN_VLR);
		return;
	} else {
		/* TMSI was included, are we permitted to use it? */
		if (vlr->cfg.parq_retrieve_imsi) {
			/* Obtain_IMSI_VLR */
			osmo_tdef_fsm_inst_state_chg(fi, PR_ARQ_S_WAIT_OBTAIN_IMSI, parq_fsm_state_tdef, vlr_tdefs, -1);
			return;
		} else {
			/* Set User Error: Unidentified Subscriber */
			proc_arq_fsm_done(fi, GSM48_REJECT_IMSI_UNKNOWN_IN_VLR);
			return;
		}
	}
}

/* ID REQ(IMSI) has returned */
static void proc_arq_vlr_fn_w_obt_imsi(struct osmo_fsm_inst *fi,
					uint32_t event, void *data)
{
	struct proc_arq_priv *par = fi->priv;
	struct vlr_instance *vlr = par->vlr;
	struct vlr_subscr *vsub;

	OSMO_ASSERT(event == PR_ARQ_E_ID_IMSI);

	vsub = vlr_subscr_find_by_imsi(vlr, par->imsi, __func__);
	if (!vsub) {
		/* Set User Error: Unidentified Subscriber */
		proc_arq_fsm_done(fi, GSM48_REJECT_IMSI_UNKNOWN_IN_VLR);
		return;
	}
	if (assoc_par_with_subscr(fi, vsub))
		proc_arq_fsm_done(fi, GSM48_REJECT_NETWORK_FAILURE);
	else
		proc_arq_vlr_fn_post_imsi(fi);
	vlr_subscr_put(vsub, __func__);
}

/* Authenticate_VLR has completed */
static void proc_arq_vlr_fn_w_auth(struct osmo_fsm_inst *fi,
				   uint32_t event, void *data)
{
	struct proc_arq_priv *par = fi->priv;
	enum gsm48_reject_value *cause = data;

	switch (event) {
	case PR_ARQ_E_AUTH_RES:
		/* Node 2 */
		_proc_arq_vlr_node2(fi);
		return;

	case PR_ARQ_E_AUTH_FAILURE:
		proc_arq_fsm_done(fi, cause ? *cause : GSM48_REJECT_NETWORK_FAILURE);
		return;

	case PR_ARQ_E_AUTH_NO_INFO:
		/* HLR returned no auth info for the subscriber. Continue only if authentication is optional. */
		if (par->authentication_required) {
			proc_arq_fsm_done(fi, cause ? *cause : GSM48_REJECT_NETWORK_FAILURE);
			return;
		}
		LOGPFSML(fi, LOGL_INFO,
			 "Attaching subscriber without auth (auth is optional, and no auth info received from HLR)\n");
		/* Node 2 */
		_proc_arq_vlr_node2(fi);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void proc_arq_vlr_fn_w_ciph(struct osmo_fsm_inst *fi,
				   uint32_t event, void *data)
{
	enum vlr_ciph_result_cause result = VLR_CIPH_REJECT;

	OSMO_ASSERT(event == PR_ARQ_E_CIPH_RES);

	if (!data)
		LOGPFSML(fi, LOGL_ERROR, "invalid ciphering result: NULL\n");
	else
		result = *(enum vlr_ciph_result_cause*)data;

	switch (result) {
	case VLR_CIPH_COMPL:
		_proc_arq_vlr_node2_post_ciph(fi);
		return;
	case VLR_CIPH_REJECT:
		LOGPFSM(fi, "ciphering rejected\n");
		proc_arq_fsm_done(fi, GSM48_REJECT_ILLEGAL_MS);
		return;
	default:
		LOGPFSML(fi, LOGL_ERROR, "invalid ciphering result: %d\n", result);
		proc_arq_fsm_done(fi, GSM48_REJECT_ILLEGAL_MS);
		return;
	}
}

/* Update_Location_Child_VLR has completed */
static void proc_arq_vlr_fn_w_upd_loc(struct osmo_fsm_inst *fi,
					uint32_t event, void *data)
{
	OSMO_ASSERT(event == PR_ARQ_E_UPD_LOC_RES);

	_proc_arq_vlr_node2_post_vlr(fi);
}

/* Subscriber_Present_VLR has completed */
static void proc_arq_vlr_fn_w_pres(struct osmo_fsm_inst *fi,
					uint32_t event, void *data)
{
	OSMO_ASSERT(event == PR_ARQ_E_PRES_RES);

	_proc_arq_vlr_post_pres(fi);
}

static void proc_arq_vlr_fn_w_trace(struct osmo_fsm_inst *fi,
					uint32_t event, void *data)
{
	OSMO_ASSERT(event == PR_ARQ_E_TRACE_RES);

	_proc_arq_vlr_post_trace(fi);
}

/* we have received the ID RESPONSE (IMEI) */
static void proc_arq_vlr_fn_w_imei(struct osmo_fsm_inst *fi,
				uint32_t event, void *data)
{
	OSMO_ASSERT(event == PR_ARQ_E_IMEI_RES);

	_proc_arq_vlr_post_imei(fi);
}

/* MSC tells us that MS has acknowleded TMSI re-allocation */
static void proc_arq_vlr_fn_w_tmsi(struct osmo_fsm_inst *fi,
				uint32_t event, void *data)
{
	OSMO_ASSERT(event == PR_ARQ_E_TMSI_ACK);

	/* FIXME: check confirmation? unfreeze? */
	proc_arq_fsm_done(fi, 0);
}

static const struct osmo_fsm_state proc_arq_vlr_states[] = {
	[PR_ARQ_S_INIT] = {
		.name = OSMO_STRINGIFY(PR_ARQ_S_INIT),
		.in_event_mask = S(PR_ARQ_E_START),
		.out_state_mask = S(PR_ARQ_S_DONE) |
				  S(PR_ARQ_S_WAIT_OBTAIN_IMSI) |
				  S(PR_ARQ_S_WAIT_AUTH) |
				  S(PR_ARQ_S_WAIT_CIPH) |
				  S(PR_ARQ_S_WAIT_UPD_LOC_CHILD) |
				  S(PR_ARQ_S_WAIT_SUB_PRES) |
				  S(PR_ARQ_S_WAIT_TRACE_SUB) |
				  S(PR_ARQ_S_WAIT_CHECK_IMEI) |
				  S(PR_ARQ_S_WAIT_TMSI_ACK),
		.action = proc_arq_vlr_fn_init,
	},
	[PR_ARQ_S_WAIT_OBTAIN_IMSI] = {
		.name = OSMO_STRINGIFY(PR_ARQ_S_WAIT_OBTAIN_IMSI),
		.in_event_mask = S(PR_ARQ_E_ID_IMSI),
		.out_state_mask = S(PR_ARQ_S_DONE) |
				  S(PR_ARQ_S_WAIT_AUTH) |
				  S(PR_ARQ_S_WAIT_CIPH) |
				  S(PR_ARQ_S_WAIT_UPD_LOC_CHILD) |
				  S(PR_ARQ_S_WAIT_SUB_PRES) |
				  S(PR_ARQ_S_WAIT_TRACE_SUB) |
				  S(PR_ARQ_S_WAIT_CHECK_IMEI) |
				  S(PR_ARQ_S_WAIT_TMSI_ACK),
		.action = proc_arq_vlr_fn_w_obt_imsi,
	},
	[PR_ARQ_S_WAIT_AUTH] = {
		.name = OSMO_STRINGIFY(PR_ARQ_S_WAIT_AUTH),
		.in_event_mask = S(PR_ARQ_E_AUTH_RES) |
				 S(PR_ARQ_E_AUTH_NO_INFO) |
				 S(PR_ARQ_E_AUTH_FAILURE),
		.out_state_mask = S(PR_ARQ_S_DONE) |
				  S(PR_ARQ_S_WAIT_CIPH) |
				  S(PR_ARQ_S_WAIT_UPD_LOC_CHILD) |
				  S(PR_ARQ_S_WAIT_SUB_PRES) |
				  S(PR_ARQ_S_WAIT_TRACE_SUB) |
				  S(PR_ARQ_S_WAIT_CHECK_IMEI) |
				  S(PR_ARQ_S_WAIT_TMSI_ACK),
		.action = proc_arq_vlr_fn_w_auth,
	},
	[PR_ARQ_S_WAIT_CIPH] = {
		.name = OSMO_STRINGIFY(PR_ARQ_S_WAIT_CIPH),
		.in_event_mask = S(PR_ARQ_E_CIPH_RES),
		.out_state_mask = S(PR_ARQ_S_DONE) |
				  S(PR_ARQ_S_WAIT_UPD_LOC_CHILD) |
				  S(PR_ARQ_S_WAIT_SUB_PRES) |
				  S(PR_ARQ_S_WAIT_TRACE_SUB) |
				  S(PR_ARQ_S_WAIT_CHECK_IMEI) |
				  S(PR_ARQ_S_WAIT_TMSI_ACK),
		.action = proc_arq_vlr_fn_w_ciph,
	},
	[PR_ARQ_S_WAIT_UPD_LOC_CHILD] = {
		.name = OSMO_STRINGIFY(PR_ARQ_S_WAIT_UPD_LOC_CHILD),
		.in_event_mask = S(PR_ARQ_E_UPD_LOC_RES),
		.out_state_mask = S(PR_ARQ_S_DONE) |
				  S(PR_ARQ_S_WAIT_SUB_PRES) |
				  S(PR_ARQ_S_WAIT_TRACE_SUB) |
				  S(PR_ARQ_S_WAIT_CHECK_IMEI) |
				  S(PR_ARQ_S_WAIT_TMSI_ACK),
		.action = proc_arq_vlr_fn_w_upd_loc,
	},
	[PR_ARQ_S_WAIT_SUB_PRES] = {
		.name = OSMO_STRINGIFY(PR_ARQ_S_WAIT_SUB_PRES),
		.in_event_mask = S(PR_ARQ_E_PRES_RES),
		.out_state_mask = S(PR_ARQ_S_DONE) |
				  S(PR_ARQ_S_WAIT_TRACE_SUB) |
				  S(PR_ARQ_S_WAIT_CHECK_IMEI) |
				  S(PR_ARQ_S_WAIT_TMSI_ACK),
		.action = proc_arq_vlr_fn_w_pres,
	},
	[PR_ARQ_S_WAIT_TRACE_SUB] = {
		.name = OSMO_STRINGIFY(PR_ARQ_S_WAIT_TRACE_SUB),
		.in_event_mask = S(PR_ARQ_E_TRACE_RES),
		.out_state_mask = S(PR_ARQ_S_DONE) |
				  S(PR_ARQ_S_WAIT_CHECK_IMEI) |
				  S(PR_ARQ_S_WAIT_TMSI_ACK),
		.action = proc_arq_vlr_fn_w_trace,
	},
	[PR_ARQ_S_WAIT_CHECK_IMEI] = {
		.name = OSMO_STRINGIFY(PR_ARQ_S_WAIT_CHECK_IMEI),
		.in_event_mask = S(PR_ARQ_E_IMEI_RES),
		.out_state_mask = S(PR_ARQ_S_DONE) |
				  S(PR_ARQ_S_WAIT_TMSI_ACK),
		.action = proc_arq_vlr_fn_w_imei,
	},
	[PR_ARQ_S_WAIT_TMSI_ACK] = {
		.name = OSMO_STRINGIFY(PR_ARQ_S_WAIT_TMSI_ACK),
		.in_event_mask = S(PR_ARQ_E_TMSI_ACK),
		.out_state_mask = S(PR_ARQ_S_DONE),
		.action = proc_arq_vlr_fn_w_tmsi,
	},
	[PR_ARQ_S_DONE] = {
		.name = OSMO_STRINGIFY(PR_ARQ_S_DONE),
		.onenter = proc_arq_vlr_dispatch_result,
	},
};

static struct osmo_fsm proc_arq_vlr_fsm = {
	.name = "Process_Access_Request_VLR",
	.states = proc_arq_vlr_states,
	.num_states = ARRAY_SIZE(proc_arq_vlr_states),
	.allstate_event_mask = 0,
	.allstate_action = NULL,
	.log_subsys = DLGLOBAL,
	.event_names = proc_arq_vlr_event_names,
	.cleanup = proc_arq_vlr_cleanup,
};

void
vlr_proc_acc_req(struct osmo_fsm_inst *parent,
		 uint32_t parent_event_success,
		 uint32_t parent_event_failure,
		 void *parent_event_data,
		 struct vlr_instance *vlr, void *msc_conn_ref,
		 enum vlr_parq_type type, enum osmo_cm_service_type cm_service_type,
		 const struct osmo_mobile_identity *mi,
		 const struct osmo_location_area_id *lai,
		 bool authentication_required,
		 bool is_ciphering_to_be_attempted,
		 bool is_ciphering_required,
		 uint8_t key_seq,
		 bool is_r99, bool is_utran)
{
	struct osmo_fsm_inst *fi;
	struct proc_arq_priv *par;

	if (is_ciphering_required)
		OSMO_ASSERT(is_ciphering_to_be_attempted);

	fi = osmo_fsm_inst_alloc_child(&proc_arq_vlr_fsm, parent,
				       parent_event_failure);
	if (!fi)
		return;

	par = talloc_zero(fi, struct proc_arq_priv);
	fi->priv = par;
	par->vlr = vlr;
	par->msc_conn_ref = msc_conn_ref;
	par->type = type;
	par->cm_service_type = cm_service_type;
	par->lai = *lai;
	par->parent_event_success = parent_event_success;
	par->parent_event_failure = parent_event_failure;
	par->parent_event_data = parent_event_data;
	par->authentication_required = authentication_required;
	par->is_ciphering_to_be_attempted = is_ciphering_to_be_attempted;
	par->is_ciphering_required = is_ciphering_required;
	par->key_seq = key_seq;
	par->is_r99 = is_r99;
	par->is_utran = is_utran;

	LOGPFSM(fi, "rev=%s net=%s%s%s\n",
		is_r99 ? "R99" : "GSM",
		is_utran ? "UTRAN" : "GERAN",
		(authentication_required || is_ciphering_to_be_attempted) ?
		" Auth" : " (no Auth)",
		(authentication_required || is_ciphering_to_be_attempted) ?
			(is_ciphering_to_be_attempted ? "+Ciph" : " (no Ciph)")
			: "");

	if (is_utran && !authentication_required)
		LOGPFSML(fi, LOGL_ERROR,
			 "Authentication off on UTRAN network. Good luck.\n");

	switch (mi->type) {
	case GSM_MI_TYPE_IMSI:
		OSMO_STRLCPY_ARRAY(par->imsi, mi->imsi);
		par->by_tmsi = false;
		break;
	case GSM_MI_TYPE_TMSI:
		par->by_tmsi = true;
		par->tmsi = mi->tmsi;
		break;
	case GSM_MI_TYPE_IMEI:
		/* TODO: IMEI (emergency call) */
	default:
		proc_arq_fsm_done(fi, GSM48_REJECT_INVALID_MANDANTORY_INF);
		return;
	}

	osmo_fsm_inst_dispatch(fi, PR_ARQ_E_START, NULL);
}

/* Gracefully terminate an FSM created by vlr_proc_acc_req() in case of
 * external timeout (i.e. from MSC). */
void vlr_parq_cancel(struct osmo_fsm_inst *fi,
		     enum osmo_fsm_term_cause fsm_cause,
		     enum gsm48_reject_value gsm48_cause)
{
	if (!fi || fi->state == PR_ARQ_S_DONE)
		return;
	LOGPFSM(fi, "Cancel: %s\n", osmo_fsm_term_cause_name(fsm_cause));
	proc_arq_fsm_done(fi, gsm48_cause);
}


#if 0
/***********************************************************************
 * Update_Location_Child_VLR, TS 29.002 Chapter 25.4.4
 ***********************************************************************/

enum upd_loc_child_vlr_state {
	ULC_S_IDLE,
	ULC_S_WAIT_HLR_RESP,
	ULC_S_DONE,
};

enum upd_loc_child_vlr_event {
	ULC_E_START,
};

static const struct value_string upd_loc_child_vlr_event_names[] = {
	{ ULC_E_START, "START" },
	{ 0, NULL }
};

static void upd_loc_child_f_idle(struct osmo_fsm_inst *fi, uint32_t event,
				 void *data)
{
	OSMO_ASSERT(event == ULC_E_START);

	/* send update location */
}

static void upd_loc_child_f_w_hlr(struct osmo_fsm_inst *fi, uint32_t event,
				  void *data)
{
}

static const struct osmo_fsm_state upd_loc_child_vlr_states[] = {
	[ULC_S_IDLE] = {
		.in_event_mask = ,
		.out_state_mask = S(ULC_S_WAIT_HLR_RESP) |
				  S(ULC_S_DONE),
		.name = "IDLE",
		.action = upd_loc_child_f_idle,
	},
	[ULC_S_WAIT_HLR_RESP] = {
		.in_event_mask = ,
		.out_state_mask = S(ULC_S_DONE),
		.name = "WAIT-HLR-RESP",
		.action = upd_loc_child_f_w_hlr,
	},
	[ULC_S_DONE] = {
		.name = "DONE",
	},
};

static struct osmo_fsm upd_loc_child_vlr_fsm = {
	.name = "Update_Location_Child_VLR",
	.states = upd_loc_child_vlr_states,
	.num_states = ARRAY_SIZE(upd_loc_child_vlr_states),
	.log_subsys = DVLR,
	.event_names = upd_loc_child_vlr_event_names,
};
#endif

void vlr_parq_fsm_init(bool is_ps)
{
	if (is_ps)
		parq_fsm_state_tdef = sgsn_parq_tdef_states;
	else
		parq_fsm_state_tdef = msc_parq_tdef_states;

	//OSMO_ASSERT(osmo_fsm_register(&upd_loc_child_vlr_fsm) == 0);
	OSMO_ASSERT(osmo_fsm_register(&proc_arq_vlr_fsm) == 0);
}

void vlr_parq_fsm_set_log_subsys(int log_subsys)
{
	proc_arq_vlr_fsm.log_subsys = log_subsys;
}
