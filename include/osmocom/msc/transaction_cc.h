/* Filter/overlay codec and CSD bearer service selections for voice calls/CSD,
 * across MS, RAN and CN limitations
 *
 * (C) 2023 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Oliver Smith
 *
 * SPDX-License-Identifier: AGPL-3.0+
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

#include <osmocom/gsm/mncc.h>

#include <osmocom/msc/codec_mapping.h>
#include <osmocom/msc/transaction.h>
#include <osmocom/msc/vlr.h>

void trans_cc_filter_init(struct gsm_trans *trans);
void trans_cc_filter_set_ran(struct gsm_trans *trans, enum osmo_rat_type ran_type);
void trans_cc_filter_set_bss(struct gsm_trans *trans, struct msc_a *msc_a);
void trans_cc_filter_run(struct gsm_trans *trans);
void trans_cc_filter_set_ms_from_bc(struct gsm_trans *trans, const struct gsm_mncc_bearer_cap *bcap);
void trans_cc_set_remote_from_bc(struct gsm_trans *trans, const struct gsm_mncc_bearer_cap *bcap);
