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

#include <arpa/inet.h>
#include <osmocom/gsm/protocol/gsm_29_118.h>

#define DEFAULT_SGS_SERVER_IP "0.0.0.0"
#define DEFAULT_SGS_SERVER_VLR_NAME "vlr.example.net"

/* global SGs state */
struct sgs_state {
	/* list of MMEs (sgs_mme_ctx) */
	struct llist_head mme_list;

	/* list of SCTP client connections */
	struct llist_head conn_list;

	/* SCTP server for inbound SGs connections */
	struct osmo_stream_srv_link *srv_link;

	struct {
		char local_addr[INET6_ADDRSTRLEN];
		uint16_t local_port;
		/* user-configured VLR name (FQDN) */
		char vlr_name[SGS_VLR_NAME_MAXLEN];
		/* timers on VLR side */
		unsigned int timer[_NUM_SGS_STATE_TIMERS];
		/* counters on VLR side */
		unsigned int counter[_NUM_SGS_STATE_COUNTERS];
	} cfg;
};

struct sgs_state *sgs_server_alloc(void *ctx);
int sgs_server_open(struct sgs_state *sgs);
