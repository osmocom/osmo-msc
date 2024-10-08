/* (C) 2018-2019 by sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Harald Welte, Philipp Maier
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

#include <osmocom/core/utils.h>
#include <osmocom/core/fsm.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/vlr/vlr.h>
#include <osmocom/vlr/vlr_sgs.h>

#include "vlr_sgs_fsm.h"
#include "vlr_core.h"

#define S(x) (1 << (x))

static const struct value_string sgs_ue_fsm_event_names[] = {
	{SGS_UE_E_VLR_FAILURE, "VLR_FAILURE"},
	{SGS_UE_E_RX_RESET_FROM_MME, "RX_RESET_FROM_MME"},
	{SGS_UE_E_RX_DETACH_IND_FROM_MME, "RX_DETACH_IND_FROM_MME"},
	{SGS_UE_E_RX_DETACH_IND_FROM_UE, "RX_DETACH_IND_FROM_UE"},	/* vlr.c */
	{SGS_UE_E_RX_LU_FROM_A_IU_GS, "RX_LU_FROM_A_Iu_Gs"},	/* vlr_lu_fsm.c */
	{SGS_UE_E_RX_PAGING_FAILURE, "RX_PAGING_FAILURE"},
	{SGS_UE_E_RX_ALERT_FAILURE, "RX_ALERT_FAILURE"},
	{SGS_UE_E_RX_LU_FROM_MME, "RX_LU_FROM_MME"},
	{SGS_UE_E_TX_LU_REJECT, "TX_LU_REJECT"},
	{SGS_UE_E_TX_LU_ACCEPT, "TX_LU_ACCEPT"},
	{SGS_UE_E_TX_PAGING, "TX_PAGING"},
	{SGS_UE_E_RX_SGSAP_UE_UNREACHABLE, "RX_SGSAP_UE_UNREACH"},
	{SGS_UE_E_RX_TMSI_REALLOC, "RX_TMSI_REALLOC"},
	{0, NULL}
};

/* Send the SGs Association to NULL state immediately */
static void to_null(struct osmo_fsm_inst *fi)
{
	struct vlr_subscr *vsub = fi->priv;
	osmo_fsm_inst_state_chg(fi, SGS_UE_ST_NULL, 0, 0);

	/* Note: This is only relevant for cases where we are in the middle
	 * of an TMSI reallocation procedure. Should a failure of some sort
	 * put us to NULL state, we have to free the pending TMSI */
	vsub->tmsi_new = GSM_RESERVED_TMSI;

	/* Make sure we remove recorded Last EUTRAN PLMN Id when UE ceases to be
	 * available over SGs */
	vlr_subscr_set_last_used_eutran_plmn_id(vsub, NULL);

	/* Make sure any ongoing paging is aborted. */
	if (vsub->cs.is_paging && vsub->sgs.paging_cb)
		vsub->sgs.paging_cb(vsub, SGSAP_SERV_IND_PAGING_TIMEOUT);

	/* Ensure that Ts5 (pending paging via SGs) is deleted */
	if (vlr_sgs_pag_pend(vsub))
		osmo_timer_del(&vsub->sgs.Ts5);
}

/* Initiate location update and change to SGS_UE_ST_LA_UPD_PRES state */
static void perform_lu(struct osmo_fsm_inst *fi)
{
	struct vlr_subscr *vsub = fi->priv;
	struct sgs_lu_response sgs_lu_response = {0};
	int rc;

	/* Note: At the moment we allocate a new TMSI on each LU. */
	rc = vlr_subscr_alloc_tmsi(vsub);
	if (rc != 0) {
		LOGPFSML(fi, LOGL_ERROR, "(sub %s) VLR LU tmsi allocation failed\n", vlr_subscr_name(vsub));
		goto error;
	}

	rc = vlr_subscr_req_lu(vsub);
	if (rc != 0) {
		LOGPFSML(fi, LOGL_ERROR, "(sub %s) HLR LU request failed\n", vlr_subscr_name(vsub));
		goto error;
	}

	osmo_fsm_inst_state_chg(fi, SGS_UE_ST_LA_UPD_PRES, 0, 0);
	vsub->ms_not_reachable_flag = false;
	return;

error:
	to_null(fi);
	sgs_lu_response.error = true;
	sgs_lu_response.vsub = vsub;
	vsub->sgs.response_cb(&sgs_lu_response);
}

/* Respawn a pending paging (Timer is reset and a new paging request is sent) */
static void respawn_paging(struct vlr_subscr *vsub)
{
	if (vlr_sgs_pag_pend(vsub)) {

		/* Delete the old paging timer first. */
		osmo_timer_del(&vsub->sgs.Ts5);

		/* Issue a fresh paging request */
		vsub->sgs.paging_cb(vsub, vsub->sgs.paging_serv_ind);
	}
}

/* Figure 4.2.2.1 SGs-NULL */
static void sgs_ue_fsm_null(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case SGS_UE_E_RX_LU_FROM_MME:
		perform_lu(fi);
		break;
	case SGS_UE_E_TX_PAGING:
		/* do nothing */
		break;
	case SGS_UE_E_RX_PAGING_FAILURE:
		/* do nothing */
		break;
	default:
		OSMO_ASSERT(0);
	}
}

/* Figure 4.2.2.1 SGs-LA-UPDATE-PRESENT */
static void sgs_ue_fsm_lau_present(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct vlr_subscr *vsub = fi->priv;
	enum sgsap_sgs_cause *cause = NULL;

	switch (event) {
	case SGS_UE_E_TX_LU_ACCEPT:
		vsub->conf_by_radio_contact_ind = true;
		vsub->sub_dataconf_by_hlr_ind = true;
		vsub->loc_conf_in_hlr_ind = true;
		vsub->la_allowed = true;
		vsub->imsi_detached_flag = false;

		if (!vsub->lu_complete) {
			vsub->lu_complete = true;
			/* Balanced by vlr_subscr_expire() */
			vlr_subscr_get(vsub, VSUB_USE_ATTACHED);
		}

		vlr_sgs_fsm_update_id(vsub);
		vsub->cs.attached_via_ran = OSMO_RAT_EUTRAN_SGS;

		/* Check if we expect a TMSI REALLOCATION COMPLETE message from the MME
		 * by checking the tmsi_new flag. If this flag is not GSM_RESERVED_TMSI
		 * we know that we have a TMSI pending and need to wait for the MME
		 * to acknowledge first */
		if (vsub->tmsi_new != GSM_RESERVED_TMSI) {
			osmo_fsm_inst_state_chg(fi, SGS_UE_ST_ASSOCIATED, vsub->sgs.cfg.timer[SGS_STATE_TS6_2],
						SGS_STATE_TS6_2);
		} else {
			/* Trigger sending of an MM information request */
			vsub->sgs.mminfo_cb(vsub);

			/* In cases where the LU has interrupted the paging, respawn the paging now,
			 * See also: 3GPP TS 29.118, chapter 5.2.3.2 Location update response */
			if (vlr_sgs_pag_pend(vsub))
				respawn_paging(vsub);

			osmo_fsm_inst_state_chg(fi, SGS_UE_ST_ASSOCIATED, 0, 0);
		}

		break;
	case SGS_UE_E_RX_PAGING_FAILURE:
		cause = data;
		if (*cause == SGSAP_SGS_CAUSE_MT_CSFB_REJ_USER)
			break;
		to_null(fi);
		break;
	case SGS_UE_E_TX_LU_REJECT:
	case SGS_UE_E_RX_ALERT_FAILURE:
		to_null(fi);
		break;
	case SGS_UE_E_TX_PAGING:
		/* do nothing */
		break;
	default:
		OSMO_ASSERT(0);
		break;
	}
}

/* Figure 4.2.2.1 SGs-ASSOCIATED */
static void sgs_ue_fsm_associated(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct vlr_subscr *vsub = fi->priv;
	enum sgsap_sgs_cause *cause = NULL;

	switch (event) {
	case SGS_UE_E_TX_PAGING:
		/* do nothing */
		break;
	case SGS_UE_E_RX_TMSI_REALLOC:
		if (vsub->tmsi_new == GSM_RESERVED_TMSI) {
			LOGPFSML(fi, LOGL_ERROR,
				 "(sub %s) TMSI reallocation completed at the MME, but no TMSI reallocation ordered.\n",
				 vlr_subscr_msisdn_or_name(vsub));
		}

		vsub->tmsi = vsub->tmsi_new;
		vsub->tmsi_new = GSM_RESERVED_TMSI;

		/* Trigger sending of MM information */
		vsub->sgs.mminfo_cb(vsub);

		/* In cases where the LU has interrupted the paging, respawn the paging now,
		 * See also: 3GPP TS 29.118, chapter 5.2.3.2 Location update response */
		if (vlr_sgs_pag_pend(vsub))
			respawn_paging(vsub);

		/* Note: We are already in SGS_UE_ST_ASSOCIATED but the
		 * transition that lead us here had is guarded with Ts6-1,
		 * so we change the state now once more without timeout
		 * to ensure the timer is stopped */
		osmo_fsm_inst_state_chg(fi, SGS_UE_ST_ASSOCIATED, 0, 0);
		break;
	case SGS_UE_E_RX_SGSAP_UE_UNREACHABLE:
		/* do nothing */
		break;
	case SGS_UE_E_RX_PAGING_FAILURE:
		cause = data;
		if (*cause == SGSAP_SGS_CAUSE_MT_CSFB_REJ_USER)
			break;
		to_null(fi);
		break;
	case SGS_UE_E_RX_ALERT_FAILURE:
		to_null(fi);
		break;
	case SGS_UE_E_RX_LU_FROM_MME:
		perform_lu(fi);
		break;
	default:
		OSMO_ASSERT(0);
		break;
	}
}

/* Figure 4.2.2.1 From any of the three states (at the VLR) */
static void sgs_ue_fsm_allstate(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct vlr_subscr *vsub = fi->priv;

	switch (event) {
	case SGS_UE_E_RX_DETACH_IND_FROM_MME:
	case SGS_UE_E_RX_DETACH_IND_FROM_UE:
		vsub->imsi_detached_flag = true;
		vsub->expire_lu = VLR_SUBSCRIBER_NO_EXPIRATION;
		/* See 5.4.3 and 5.5.3 */
		to_null(fi);
		break;
	case SGS_UE_E_RX_RESET_FROM_MME:
		/* See also 3GPP TS 29.118, chapter 5.7.2.1 VLR Reset Initiation */
		vsub->conf_by_radio_contact_ind = false;
		to_null(fi);
		break;
	case SGS_UE_E_VLR_FAILURE:
	case SGS_UE_E_RX_LU_FROM_A_IU_GS:
		to_null(fi);
		break;
	default:
		OSMO_ASSERT(0);
		break;
	}
}

static int sgs_ue_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct vlr_subscr *vsub = fi->priv;
	switch (fi->T) {

	case SGS_STATE_TS6_2:
		/* Failed TMSI reallocation procedure, deallocate all TMSI
		 * information, but don't change the SGs association state. */
		vsub->tmsi_new = GSM_RESERVED_TMSI;
		vsub->tmsi = GSM_RESERVED_TMSI;
		break;
	default:
		/* Unhandled timer */
		OSMO_ASSERT(false);
		break;
	}
	return 0;
}

static const struct osmo_fsm_state sgs_ue_fsm_states[] = {
	[SGS_UE_ST_NULL] = {
		.name = "SGs-NULL",
		.action = sgs_ue_fsm_null,
		.in_event_mask = 0
			| S(SGS_UE_E_RX_LU_FROM_MME)
			| S(SGS_UE_E_TX_PAGING)
			| S(SGS_UE_E_RX_PAGING_FAILURE)
			,
		.out_state_mask = 0
			| S(SGS_UE_ST_NULL)
			| S(SGS_UE_ST_LA_UPD_PRES)
			,
	},
	[SGS_UE_ST_LA_UPD_PRES] = {
		.name = "SGs-LA-UPDATE-PRESENT",
		.action = sgs_ue_fsm_lau_present,
		.in_event_mask = 0
			| S(SGS_UE_E_TX_LU_ACCEPT)
			| S(SGS_UE_E_TX_LU_REJECT)
			| S(SGS_UE_E_TX_PAGING)
			| S(SGS_UE_E_RX_PAGING_FAILURE)
			| S(SGS_UE_E_RX_ALERT_FAILURE)
			,
		.out_state_mask = 0
			| S(SGS_UE_ST_NULL)
			| S(SGS_UE_ST_ASSOCIATED)
			| S(SGS_UE_ST_LA_UPD_PRES)
			,
	},
	[SGS_UE_ST_ASSOCIATED] = {
		.name = "SGs-ASSOCIATED",
		.action = sgs_ue_fsm_associated,
		.in_event_mask = 0
			| S(SGS_UE_E_TX_PAGING)
			| S(SGS_UE_E_RX_TMSI_REALLOC)
			| S(SGS_UE_E_RX_SGSAP_UE_UNREACHABLE)
			| S(SGS_UE_E_RX_PAGING_FAILURE)
			| S(SGS_UE_E_RX_ALERT_FAILURE)
			| S(SGS_UE_E_RX_LU_FROM_MME)
			,
		.out_state_mask = 0
			| S(SGS_UE_ST_NULL)
			| S(SGS_UE_ST_ASSOCIATED)
			| S(SGS_UE_ST_LA_UPD_PRES)
			,
	},
};

static struct osmo_fsm sgs_ue_fsm = {
	.name = "SGs-UE",
	.states = sgs_ue_fsm_states,
	.num_states = ARRAY_SIZE(sgs_ue_fsm_states),
	.allstate_event_mask = S(SGS_UE_E_RX_RESET_FROM_MME) |
		S(SGS_UE_E_VLR_FAILURE) | S(SGS_UE_E_RX_DETACH_IND_FROM_MME) | S(SGS_UE_E_RX_DETACH_IND_FROM_UE) |
		S(SGS_UE_E_RX_LU_FROM_A_IU_GS),
	.allstate_action = sgs_ue_fsm_allstate,
	.timer_cb = sgs_ue_fsm_timer_cb,
	.log_subsys = DLGLOBAL,
	.event_names = sgs_ue_fsm_event_names,
};

/*! Initialize/Register SGs FSM in osmo-fsm subsystem */
void vlr_sgs_fsm_init(void)
{
	if (osmo_fsm_find_by_name(sgs_ue_fsm.name) != &sgs_ue_fsm)
		OSMO_ASSERT(osmo_fsm_register(&sgs_ue_fsm) == 0);
}

/*! Set the log level of the fsm */
void vlr_sgs_fsm_set_log_subsys(int log_level)
{
	sgs_ue_fsm.log_subsys = log_level;
}

/*! Crate SGs FSM in struct vlr_subscr.
 *  \param[in] vsub VLR subscriber for which the SGs FSM should be created. */
void vlr_sgs_fsm_create(struct vlr_subscr *vsub)
{
	char interim_fsm_id[256];
	static unsigned int fsm_id_num = 0;

	/* An SGSs FSM must not be created twice! */
	OSMO_ASSERT(!vsub->sgs_fsm);

	snprintf(interim_fsm_id, sizeof(interim_fsm_id), "num:%u", fsm_id_num);

	vsub->sgs_fsm = osmo_fsm_inst_alloc(&sgs_ue_fsm, vsub, vsub, LOGL_INFO, interim_fsm_id);
	OSMO_ASSERT(vsub->sgs_fsm);

	osmo_fsm_inst_state_chg(vsub->sgs_fsm, SGS_UE_ST_NULL, 0, 0);

	fsm_id_num++;
}

/*! Remove SGs FSM from struct vlr_subscr.
 *  \param[in] vsub VLR subscriber from which the SGs FSM should be removed. */
void vlr_sgs_fsm_remove(struct vlr_subscr *vsub)
{
	/* An SGSs FSM must exist! */
	OSMO_ASSERT(vsub->sgs_fsm);

	osmo_fsm_inst_state_chg(vsub->sgs_fsm, SGS_UE_ST_NULL, 0, 0);
	osmo_fsm_inst_term(vsub->sgs_fsm, OSMO_FSM_TERM_REGULAR, NULL);
	vsub->sgs_fsm = NULL;
}

/*! Update the ID of the SGs FSM with the subscriber IMSI
 *  \param[in] vsub VLR subscriber to update. */
void vlr_sgs_fsm_update_id(struct vlr_subscr *vsub)
{
	char fsm_id[256];

	if (strlen(vsub->imsi) > 0) {
		snprintf(fsm_id, sizeof(fsm_id), "imsi:%s", vsub->imsi);
		osmo_fsm_inst_update_id(vsub->sgs_fsm, fsm_id);
	}
}
