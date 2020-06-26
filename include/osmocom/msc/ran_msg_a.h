/* Abstraction of BSSAP decoding into NAS events, to be handled by MSC-A or MSC-I, and encoding of BSSAP messages
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

#include <stdint.h>

#include <osmocom/msc/ran_msg.h>
#include <osmocom/msc/paging.h>

struct msgb;
struct sccp_ran_inst;
struct msub;
struct gsm_mncc_bearer_cap;

int ran_a_decode_l2(struct ran_dec *ran_a, struct msgb *bssap);
struct msgb *ran_a_encode(struct osmo_fsm_inst *caller_fi, const struct ran_msg *ran_enc_msg);

enum reset_msg_type bssmap_is_reset_msg(const struct sccp_ran_inst *sri, struct osmo_fsm_inst *log_fi,
					struct msgb *l2, int *supports_osmux);
struct msgb *bssmap_make_reset_msg(const struct sccp_ran_inst *sri, enum reset_msg_type type);
struct msgb *bssmap_make_paging_msg(const struct sccp_ran_inst *sri, const struct gsm0808_cell_id *page_cell_id,
				    const char *imsi, uint32_t tmsi, enum paging_cause cause);
const char *bssmap_msg_name(const struct sccp_ran_inst *sri, const struct msgb *l2);

enum mgcp_codecs ran_a_mgcp_codec_from_sc(const struct gsm0808_speech_codec *sc);
int ran_a_bearer_cap_to_channel_type(struct gsm0808_channel_type *ct, const struct gsm_mncc_bearer_cap *bc);
