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

#include <errno.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/fsm.h>
#include <osmocom/msc/debug.h>
#include <osmocom/msc/vlr.h>
#include <osmocom/msc/vlr_sgs.h>
#include "vlr_sgs_fsm.h"

const struct value_string sgs_state_timer_names[] = {
	{SGS_STATE_TS5, "Ts5"},
	{SGS_STATE_TS6_2, "Ts6-2"},
	{SGS_STATE_TS7, "Ts7"},
	{SGS_STATE_TS11, "Ts11"},
	{SGS_STATE_TS14, "Ts14"},
	{SGS_STATE_TS15, "Ts15"},
	{0, NULL}
};

const struct value_string sgs_state_counter_names[] = {
	{SGS_STATE_NS7, "Ns7"},
	{SGS_STATE_NS11, "Ns11"},
	{0, NULL}
};

/* Reset all SGs-Associations back to zero.
 * \param[in] vlr VLR instace. */
void vlr_sgs_reset(struct vlr_instance *vlr)
{
	struct vlr_subscr *vsub;

	OSMO_ASSERT(vlr);

	LOGP(DVLR, LOGL_INFO, "dropping all SGs associations.\n");

	llist_for_each_entry(vsub, &vlr->subscribers, list) {
		osmo_fsm_inst_dispatch(vsub->sgs_fsm, SGS_UE_E_RX_RESET_FROM_MME, NULL);
	}
}

/*! Perform an SGs location update.
 * \param[in] vlr VLR instace.
 * \param[in] cfg SGs interface configuration parameters.
 * \param[in] response_cb calback function that is called when LU is done.
 * \param[in] paging_cb calback function that is called when LU needs to page.
 * \param[in] mminfo_cb calback function that is called to provide MM info to the UE.
 * \param[in] mme_name fqdn of the requesting MME (mme-name).
 * \param[in] type location update type (normal or IMSI attach).
 * \param[in] imsi mobile identity (IMSI).
 * \param[in] new_lai identifier of the new location area.
 * \returns 0 in case of success, -EINVAL in case of error. */
int vlr_sgs_loc_update(struct vlr_instance *vlr, struct vlr_sgs_cfg *cfg,
		       vlr_sgs_lu_response_cb_t response_cb, vlr_sgs_lu_paging_cb_t paging_cb,
		       vlr_sgs_lu_mminfo_cb_t mminfo_cb, char *mme_name, enum vlr_lu_type type, const char *imsi,
		       struct osmo_location_area_id *new_lai)
{
	struct vlr_subscr *vsub = NULL;

	OSMO_ASSERT(response_cb);
	OSMO_ASSERT(paging_cb);
	OSMO_ASSERT(mminfo_cb);
	OSMO_ASSERT(cfg);
	OSMO_ASSERT(imsi);

	vsub = vlr_subscr_find_or_create_by_imsi(vlr, imsi, VSUB_USE_SGS, NULL);
	if (!vsub) {
		LOGP(DSGS, LOGL_ERROR, "VLR subscriber allocation failed\n");
		return -EINVAL;
	}

	vsub->sgs.cfg = *cfg;
	vsub->sgs.response_cb = response_cb;
	vsub->sgs.paging_cb = paging_cb;
	vsub->sgs.mminfo_cb = mminfo_cb;
	vlr_subscr_set_imsi(vsub, imsi);
	osmo_strlcpy(vsub->sgs.mme_name, mme_name, sizeof(vsub->sgs.mme_name));

	osmo_fsm_inst_dispatch(vsub->sgs_fsm, SGS_UE_E_RX_LU_FROM_MME, NULL);

	/* FIXME: Use the "type" type parameter (for what is it useful?) */

	vsub->sgs.lai = *new_lai;
	vsub->cgi.lai = *new_lai;
	vsub->cs.lac = vsub->sgs.lai.lac;

	/* Subscribers that are created by the SGs location update will not
	 * expire automatically, however a 2G LU or an implicit IMSI detach
	 * from EPS services may change this. */
	vsub->expire_lu = VLR_SUBSCRIBER_NO_EXPIRATION;

	return 0;
}

/*! Notify that the SGs Location Update accept message has been sent to MME.
 *  \param[in] vsub VLR subscriber. */
void vlr_sgs_loc_update_acc_sent(struct vlr_subscr *vsub)
{
	osmo_fsm_inst_dispatch(vsub->sgs_fsm, SGS_UE_E_TX_LU_ACCEPT, NULL);

	/* FIXME: At this point we need to check the status of Ts5 and if
	 * it is still running this means the LU has interrupted the paging,
	 * and we need to start paging again. 3GPP TS 29.118,
	 * chapter 5.2.3.2 */
}

/*! Notify that the SGs Location Update reject message has been sent to MME.
 *  \param[in] vsub VLR subscriber. */
void vlr_sgs_loc_update_rej_sent(struct vlr_subscr *vsub)
{
	osmo_fsm_inst_dispatch(vsub->sgs_fsm, SGS_UE_E_TX_LU_REJECT, NULL);
}

/*! Perform an SGs IMSI detach.
 *  \param[in] vsub VLR subscriber.
 *  \param[in] imsi mobile identity (IMSI).
 *  \param[in] type datach type. */
void vlr_sgs_imsi_detach(struct vlr_instance *vlr, const char *imsi, enum sgsap_imsi_det_noneps_type type)
{
	struct vlr_subscr *vsub;
	enum sgs_ue_fsm_event evt;

	vsub = vlr_subscr_find_by_imsi(vlr, imsi, __func__);
	if (!vsub)
		return;

	/* See also: 3GPP TS 29.118, 5.6.3 Procedures in the VLR: In case of
	 * an implicit detach, we are supposed to check if the state of the
	 * SGs-association, and only when it is not SGs-NULL, we may proceed. */
	if (vsub->sgs_fsm->state == SGS_UE_ST_NULL && type == SGSAP_ID_NONEPS_T_IMPLICIT_UE_EPS_NONEPS)
		return;

	switch (type) {
	case SGSAP_ID_NONEPS_T_EXPLICIT_UE_NONEPS:
		evt = SGS_UE_E_RX_DETACH_IND_FROM_UE;
		break;
	case SGSAP_ID_NONEPS_T_COMBINED_UE_EPS_NONEPS:
	case SGSAP_ID_NONEPS_T_IMPLICIT_UE_EPS_NONEPS:
		/* FIXME: Is that right? */
		evt = SGS_UE_E_RX_DETACH_IND_FROM_MME;
		break;
	default:
		LOGP(DSGS, LOGL_ERROR, "(sub %s) invalid SGS IMSI detach type, detaching anyway...\n",
		     vlr_subscr_msisdn_or_name(vsub));
		evt = SGS_UE_E_RX_DETACH_IND_FROM_MME;
		break;
	}

	osmo_fsm_inst_dispatch(vsub->sgs_fsm, evt, NULL);

	/* Detaching from non EPS services essentially means that the
	 * subscriber is detached from 2G. In any case the VLR will
	 * get rid of the subscriber. */
	vlr_subscr_expire(vsub);
	vlr_subscr_put(vsub, __func__);
}

/*! Perform an SGs EPS detach.
 *  \param[in] vsub VLR subscriber.
 *  \param[in] imsi mobile identity (IMSI).
 *  \param[in] type datach type. */
void vlr_sgs_eps_detach(struct vlr_instance *vlr, const char *imsi, enum sgsap_imsi_det_eps_type type)
{
	struct vlr_subscr *vsub;
	enum sgs_ue_fsm_event evt;
	vsub = vlr_subscr_find_by_imsi(vlr, imsi, __func__);
	if (!vsub)
		return;

	switch (type) {
	case SGSAP_ID_EPS_T_NETWORK_INITIATED:
		evt = SGS_UE_E_RX_DETACH_IND_FROM_MME;
		break;
	case SGSAP_ID_EPS_T_UE_INITIATED:
		evt = SGS_UE_E_RX_DETACH_IND_FROM_UE;
		break;
	case SGSAP_ID_EPS_T_EPS_NOT_ALLOWED:
		evt = SGS_UE_E_RX_DETACH_IND_FROM_MME;
		break;
	default:
		LOGP(DSGS, LOGL_ERROR, "(sub %s) invalid SGS IMSI detach type, detaching anyway...\n",
		     vlr_subscr_msisdn_or_name(vsub));
		evt = SGS_UE_E_RX_DETACH_IND_FROM_MME;
		break;
	}

	osmo_fsm_inst_dispatch(vsub->sgs_fsm, evt, NULL);

	/* See also 3GPP TS 29.118, 5.4.3 Procedures in the VLR. Detaching from
	 * EPS services essentially means that the subscriber leaves the 4G RAN
	 * but continues to live on 2G, this basically turns the subscriber into
	 * a normal 2G subscriber and we need to make sure that the lu-
	 * expiration timer is running. */
	if (vsub->expire_lu == VLR_SUBSCRIBER_NO_EXPIRATION)
		vlr_subscr_enable_expire_lu(vsub);

	vlr_subscr_put(vsub, __func__);
}

/*! Perform an SGs TMSI reallocation complete.
 *  \param[in] vsub VLR subscriber.
 *  \param[in] imsi mobile identity (IMSI). */
void vlr_sgs_tmsi_reall_compl(struct vlr_instance *vlr, const char *imsi)
{
	struct vlr_subscr *vsub;
	vsub = vlr_subscr_find_by_imsi(vlr, imsi, __func__);
	if (!vsub)
		return;

	osmo_fsm_inst_dispatch(vsub->sgs_fsm, SGS_UE_E_RX_TMSI_REALLOC, NULL);
	vlr_subscr_put(vsub, __func__);
}

/*! Notify that an SGs paging has been rejected by the MME.
 *  \param[in] vsub VLR subscriber.
 *  \param[in] imsi mobile identity (IMSI).
 *  \param[in] cause SGs cause code. */
void vlr_sgs_pag_rej(struct vlr_instance *vlr, const char *imsi, enum sgsap_sgs_cause cause)
{
	struct vlr_subscr *vsub;
	vsub = vlr_subscr_find_by_imsi(vlr, imsi, __func__);
	if (!vsub)
		return;

	/* On the reception of a paging rej the VLR is supposed to stop Ts5,
	   also  3GPP TS 29.118, chapter 5.1.2.4 */
	osmo_timer_del(&vsub->sgs.Ts5);
	LOGP(DSGS, LOGL_DEBUG, "(sub %s) Paging via SGs interface rejected by MME, %s stopped, cause: %s!\n",
	     vlr_subscr_msisdn_or_name(vsub), vlr_sgs_state_timer_name(SGS_STATE_TS5), sgsap_sgs_cause_name(cause));

	osmo_fsm_inst_dispatch(vsub->sgs_fsm, SGS_UE_E_RX_PAGING_FAILURE, &cause);
	/* Balance ref count increment from vlr_sgs_pag() */
	vlr_subscr_put(vsub, VSUB_USE_SGS_PAGING_REQ);

	vlr_subscr_put(vsub, __func__);
}

/*! Notify that an SGs paging has been accepted by the MME.
 *  \param[in] vsub VLR subscriber.
 *  \param[in] imsi mobile identity (IMSI). */
void vlr_sgs_pag_ack(struct vlr_instance *vlr, const char *imsi)
{
	struct vlr_subscr *vsub;
	vsub = vlr_subscr_find_by_imsi(vlr, imsi, __func__);
	if (!vsub)
		return;

	/* Stop Ts5 and and consider the paging as successful */
	osmo_timer_del(&vsub->sgs.Ts5);
	/* Balance ref count increment from vlr_sgs_pag() */
	vlr_subscr_put(vsub, VSUB_USE_SGS_PAGING_REQ);

	vlr_subscr_put(vsub, __func__);
}

/*! Notify that the UE has been marked as unreachable by the MME.
 *  \param[in] vsub VLR subscriber.
 *  \param[in] imsi mobile identity (IMSI).
 *  \param[in] cause SGs cause code. */
void vlr_sgs_ue_unr(struct vlr_instance *vlr, const char *imsi, enum sgsap_sgs_cause cause)
{
	struct vlr_subscr *vsub;
	vsub = vlr_subscr_find_by_imsi(vlr, imsi, __func__);
	if (!vsub)
		return;

	/* On the reception of an UE unreachable the VLR is supposed to stop
	 * Ts5, also 3GPP TS 29.118, chapter 5.1.2.5 */
	osmo_timer_del(&vsub->sgs.Ts5);
	LOGP(DSGS, LOGL_DEBUG,
	     "(sub %s) Paging via SGs interface not possible, UE unreachable, %s stopped, cause: %s\n",
	     vlr_subscr_msisdn_or_name(vsub), vlr_sgs_state_timer_name(SGS_STATE_TS5), sgsap_sgs_cause_name(cause));

	osmo_fsm_inst_dispatch(vsub->sgs_fsm, SGS_UE_E_RX_SGSAP_UE_UNREACHABLE, &cause);
	vlr_subscr_put(vsub, __func__);
}

/* Callback function that is called when an SGs paging request times out */
static void Ts5_timeout_cb(void *arg)
{
	struct vlr_subscr *vsub = arg;

	/* 3GPP TS 29.118 does not specify a specif action that has to happen
	 * in case Ts5 times out. The timeout just indicates that the paging
	 * failed. Other actions may check the status of Ts5 to see if a paging
	 * is still ongoing or not. */

	LOGP(DSGS, LOGL_ERROR, "(sub %s) Paging via SGs interface timed out (%s expired)!\n",
	     vlr_subscr_msisdn_or_name(vsub), vlr_sgs_state_timer_name(SGS_STATE_TS5));

	/* Balance ref count increment from vlr_sgs_pag() */
	vlr_subscr_put(vsub, VSUB_USE_SGS_PAGING_REQ);

	return;
}

/*! Notify that a paging message has been sent and a paging is now in progress.
 *  \param[in] vsub VLR subscriber. */
void vlr_sgs_pag(struct vlr_subscr *vsub, enum sgsap_service_ind serv_ind)
{

	/* In cases where we have to respawn a paging after an intermitted LU,
	 * there may e a Ts5 still running. In those cases we have to remove
	 * the old timer first */
	if (osmo_timer_pending(&vsub->sgs.Ts5))
		osmo_timer_del(&vsub->sgs.Ts5);

	/* Note: 3GPP TS 29.118, chapter 4.2.2 mentions paging in the FSM
	 * diagram, but paging never causes a state transition except when
	 * an explicit failure is indicated (MME actively rejects paging).
	 * Apparantly it is also possible that an LU happens while the paging
	 * is still ongoing and Ts5 is running. (chapter 5.1.2.3). This means
	 * that the paging procedure is intended to run in parallel to the
	 * SGs FSM and given that the benaviour around Ts5 must be implemented
	 * also separately, to emphasize this separation Ts5 is implemented
	 * here in and not in vlr_sgs_fsm.c. */
	osmo_timer_setup(&vsub->sgs.Ts5, Ts5_timeout_cb, vsub);
	osmo_timer_schedule(&vsub->sgs.Ts5, vsub->sgs.cfg.timer[SGS_STATE_TS5], 0);

	/* Formally 3GPP TS 29.118 defines the sending of a paging request
	 * as an event, but as far as the VLR is concerned only Ts5 is
	 * started. */
	osmo_fsm_inst_dispatch(vsub->sgs_fsm, SGS_UE_E_TX_PAGING, NULL);

	/* Memorize service type in for the case that the paging must be
	 * respawned after an LU */
	vsub->sgs.paging_serv_ind = serv_ind;

	/* Ensure that the reference count is increased by one while the
	 * paging is happening. We will balance this again in vlr_sgs_pag_rej()
	 * and vlr_sgs_pag_ack(); */
	vlr_subscr_get(vsub, VSUB_USE_SGS_PAGING_REQ);
}

/*! Check if the SGs interface is currently paging
 *  \param[in] vsub VLR subscriber. */
bool vlr_sgs_pag_pend(struct vlr_subscr *vsub)
{
	return osmo_timer_pending(&vsub->sgs.Ts5);
}
