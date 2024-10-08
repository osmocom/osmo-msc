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

struct vlr_subscr;

enum sgs_ue_fsm_event {
	SGS_UE_E_VLR_FAILURE,
	SGS_UE_E_RX_RESET_FROM_MME,
	SGS_UE_E_RX_DETACH_IND_FROM_MME,
	SGS_UE_E_RX_DETACH_IND_FROM_UE,
	SGS_UE_E_RX_LU_FROM_A_IU_GS,
	SGS_UE_E_RX_PAGING_FAILURE,
	SGS_UE_E_RX_ALERT_FAILURE,
	SGS_UE_E_RX_LU_FROM_MME,
	SGS_UE_E_TX_LU_REJECT,
	SGS_UE_E_TX_LU_ACCEPT,
	SGS_UE_E_TX_PAGING,
	SGS_UE_E_RX_SGSAP_UE_UNREACHABLE,
	SGS_UE_E_RX_TMSI_REALLOC,
};

void vlr_sgs_fsm_init(void);
void vlr_sgs_fsm_set_log_subsys(int log_subsys);
void vlr_sgs_fsm_create(struct vlr_subscr *vsub);
void vlr_sgs_fsm_remove(struct vlr_subscr *vsub);
void vlr_sgs_fsm_update_id(struct vlr_subscr *vsub);
