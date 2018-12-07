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

#include <osmocom/gsm/protocol/gsm_23_003.h>
#include <osmocom/gsm/protocol/gsm_29_118.h>
#include <osmocom/msc/vlr.h>
#include <osmocom/msc/vlr_sgs.h>
#include <osmocom/msc/paging.h>
#include <osmocom/core/socket.h>

struct msc_a;

static const unsigned int sgs_state_timer_defaults[_NUM_SGS_STATE_TIMERS] = {
	[SGS_STATE_TS5] = SGS_TS5_DEFAULT,
	[SGS_STATE_TS6_2] = SGS_TS6_2_DEFAULT,
	[SGS_STATE_TS7] = SGS_TS7_DEFAULT,
	[SGS_STATE_TS11] = SGS_TS11_DEFAULT,
	[SGS_STATE_TS14] = SGS_TS14_DEFAULT,
	[SGS_STATE_TS15] = SGS_TS15_DEFAULT,
};

static const unsigned int sgs_state_counter_defaults[_NUM_SGS_STATE_COUNTERS] = {
	[SGS_STATE_NS7] = SGS_NS7_DEFAULT,
	[SGS_STATE_NS11] = SGS_NS11_DEFAULT,
};

struct sgs_connection {
	/* global list of SGs connections */
	struct llist_head entry;

	/* back-pointer */
	struct sgs_state *sgs;

	/* Socket name from osmo_sock_get_name() */
	char sockname[OSMO_SOCK_NAME_MAXLEN];

	/* MME for this connection, if any.  This field is NULL until we
	 * receive the first "MME name" IE from the MME, which could be part
	 * of the RESET procedure, but also just a normal LU request. */
	struct sgs_mme_ctx *mme;

	/* represents the SCTP connection we accept()ed from this MME */
	struct osmo_stream_srv *srv;
};

struct sgs_mme_ctx {
	/* global list of MME contexts */
	struct llist_head entry;

	/* back-pointer */
	struct sgs_state *sgs;

	/* MME name as string representation */
	char fqdn[GSM23003_MME_DOMAIN_LEN + 1];

	/* current connection for this MME, if any. Can be NULL if the SCTP
	 * connection to the MME was lost and hasn't been re-established yet */
	struct sgs_connection *conn;

	/* FSM for the "VLR reset" procedure" */
	struct osmo_fsm_inst *fi;
	unsigned int ns11_remaining;
};

extern struct sgs_state *g_sgs;

struct sgs_state *sgs_iface_init(void *ctx, struct gsm_network *network);
int sgs_iface_rx(struct sgs_connection *sgc, struct msgb *msg);
enum sgsap_service_ind sgs_serv_ind_from_paging_cause(enum paging_cause);
int sgs_iface_tx_paging(struct vlr_subscr *vsub, enum sgsap_service_ind serv_ind);
int sgs_iface_tx_dtap_ud(struct msc_a *msc_a, struct msgb *msg);
void sgs_iface_tx_release(struct vlr_subscr *vsub);

