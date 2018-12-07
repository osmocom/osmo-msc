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

#pragma once

#include <osmocom/gsm/gsm29118.h>

enum vlr_lu_type;
struct vlr_subscr;
struct vlr_instance;

#define VSUB_USE_SGS "SGs"
#define VSUB_USE_SGS_PAGING_REQ "SGs-paging-req"

/* See also 3GPP TS 29.118, chapter 4.2.2 States at the VLR */
enum sgs_ue_fsm_state {
	SGS_UE_ST_NULL,
	SGS_UE_ST_ASSOCIATED,
	SGS_UE_ST_LA_UPD_PRES,
};

enum vlr_sgs_state_tmr {
	/* Started when sending the SGsAP-PAGING-REQUEST, implemented in vlr_sgs.c */
	SGS_STATE_TS5,
	/* TMSI reallocation, 5.2.3.5, implemented by fsm in vlr_sgs_fsm.c */
	SGS_STATE_TS6_2,
	/* Started when SGsAP-ALERT-REQUEST is sent 5.3.2.1, not implemented yet */
	SGS_STATE_TS7,
	/* Reset ack timeout, implemnted in sgs_iface.c */
	SGS_STATE_TS11,
	/* Started when SGsAP-SERVICE-REQUEST is received 5.15.1, not implemented yet */
	SGS_STATE_TS14,
	/* Started when SGsAP-MO-CSFB-INDICATION is received 5.16.3 (UE fallback, not implemented yet) */
	SGS_STATE_TS15,
	_NUM_SGS_STATE_TIMERS
};

enum vlr_sgs_state_ctr {
	/* Alert request retransmit count */
	SGS_STATE_NS7,
	/* Reset repeat count */
	SGS_STATE_NS11,
	_NUM_SGS_STATE_COUNTERS
};

extern const struct value_string sgs_state_timer_names[];
static inline const char *vlr_sgs_state_timer_name(enum vlr_sgs_state_tmr Ts)
{
	return get_value_string(sgs_state_timer_names, Ts);
}

extern const struct value_string sgs_state_counter_names[];
static inline const char *vlr_sgs_state_counter_name(enum vlr_sgs_state_ctr Ns)
{
	return get_value_string(sgs_state_timer_names, Ns);
}

/* This callback function is called when an SGs location update is complete */
struct sgs_lu_response {
	bool accepted;
	struct vlr_subscr *vsub;
};
typedef void (*vlr_sgs_lu_response_cb_t) (struct sgs_lu_response *response);

/* This callback function is called in cases where a paging request is required
 * after the LU is completed */
typedef int (*vlr_sgs_lu_paging_cb_t) (struct vlr_subscr *vsub, enum sgsap_service_ind serv_ind);

/* This callback function is called to send the MM info to the UE. */
typedef void (*vlr_sgs_lu_mminfo_cb_t) (struct vlr_subscr *vsub);

/* Configuration parameters for the SGs FSM */
struct vlr_sgs_cfg {
	unsigned int timer[_NUM_SGS_STATE_TIMERS];
	unsigned int counter[_NUM_SGS_STATE_COUNTERS];
};

void vlr_sgs_reset(struct vlr_instance *vlr);
int vlr_sgs_loc_update(struct vlr_instance *vlr, struct vlr_sgs_cfg *cfg,
		       vlr_sgs_lu_response_cb_t response_cb, vlr_sgs_lu_paging_cb_t paging_cb,
		       vlr_sgs_lu_mminfo_cb_t mminfo_cb, char *mme_name, enum vlr_lu_type type, const char *imsi,
		       struct osmo_location_area_id *new_lai);
void vlr_sgs_loc_update_acc_sent(struct vlr_subscr *vsub);
void vlr_sgs_loc_update_rej_sent(struct vlr_subscr *vsub);
void vlr_sgs_detach(struct vlr_instance *vlr, const char *imsi, bool eps);
void vlr_sgs_imsi_detach(struct vlr_instance *vlr, const char *imsi, enum sgsap_imsi_det_noneps_type type);
void vlr_sgs_eps_detach(struct vlr_instance *vlr, const char *imsi, enum sgsap_imsi_det_eps_type type);
void vlr_sgs_tmsi_reall_compl(struct vlr_instance *vlr, const char *imsi);
void vlr_sgs_pag_rej(struct vlr_instance *vlr, const char *imsi, enum sgsap_sgs_cause cause);
void vlr_sgs_pag_ack(struct vlr_instance *vlr, const char *imsi);
void vlr_sgs_ue_unr(struct vlr_instance *vlr, const char *imsi, enum sgsap_sgs_cause cause);
void vlr_sgs_pag(struct vlr_subscr *vsub, enum sgsap_service_ind serv_ind);
bool vlr_sgs_pag_pend(struct vlr_subscr *vsub);
