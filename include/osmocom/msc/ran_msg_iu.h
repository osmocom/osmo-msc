/* Abstraction of RANAP decoding into NAS events, to be handled by MSC-A or MSC-I, and encoding of RANAP messages
 * towards the RAN. */
/*
 * (C) 2019 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 *
 * Author: Neels Hofmeyr <neels@hofmeyr.de>
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
 */
#pragma once

#include <osmocom/msc/ran_msg.h>
#include <osmocom/msc/paging.h>
#include <osmocom/msc/sccp_ran.h>

int ran_iu_decode_l2(struct ran_dec *ran_dec_iu, struct msgb *ranap);
struct msgb *ran_iu_encode(struct osmo_fsm_inst *caller_fi, const struct ran_msg *ran_enc_msg);

enum reset_msg_type ranap_is_reset_msg(const struct sccp_ran_inst *sri, struct osmo_fsm_inst *log_fi,
				       struct msgb *l2, int *supports_osmux);
struct msgb *ranap_make_reset_msg(const struct sccp_ran_inst *sri, enum reset_msg_type type);
struct msgb *ranap_make_paging_msg(const struct sccp_ran_inst *sri, const struct gsm0808_cell_id *page_cell_id,
				   const char *imsi, uint32_t tmsi, enum paging_cause cause);
const char *ranap_msg_name(const struct sccp_ran_inst *sri, const struct msgb *l2);

extern const int g_ranap_rab_modes_default;
extern int g_ranap_rab_modes;
