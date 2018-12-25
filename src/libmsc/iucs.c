/* Code to manage MSC RAN connections over IuCS interface */

/*
 * (C) 2016,2017 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 *
 * Author: Neels Hofmeyr <nhofmeyr@sysmocom.de>
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

#include <inttypes.h>

#include <osmocom/core/logging.h>
#include <osmocom/ranap/iu_client.h>
#include <osmocom/msc/debug.h>

#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/gsm_subscriber.h>
#include <osmocom/msc/transaction.h>
#include <osmocom/msc/vlr.h>
#include <osmocom/core/byteswap.h>

#include "../../bscconfig.h"

#ifdef BUILD_IU
#include <osmocom/ranap/iu_client.h>
extern struct msgb *ranap_new_msg_rab_assign_voice(uint8_t rab_id,
						   uint32_t rtp_ip,
						   uint16_t rtp_port,
						   bool use_x213_nsap);
#else
#include <osmocom/msc/iu_dummy.h>
#endif /* BUILD_IU */

/* For A-interface see libbsc/bsc_api.c subscr_con_allocate() */
static struct ran_conn *ran_conn_allocate_iu(struct gsm_network *network,
								 struct ranap_ue_conn_ctx *ue,
								 uint16_t lac)
{
	struct ran_conn *conn;

	DEBUGP(DIUCS, "Allocating IuCS RAN conn: lac %d, conn_id %" PRIx32 "\n",
	       lac, ue->conn_id);

	conn = ran_conn_alloc(network, OSMO_RAT_UTRAN_IU, lac);
	if (!conn)
		return NULL;

	conn->iu.ue_ctx = ue;
	conn->iu.ue_ctx->rab_assign_addr_enc = network->iu.rab_assign_addr_enc;
	return conn;
}

static int same_ue_conn(struct ranap_ue_conn_ctx *a, struct ranap_ue_conn_ctx *b)
{
	if (a == b)
		return 1;
	return (a->conn_id == b->conn_id);
}

static inline void log_subscribers(struct gsm_network *network)
{
	if (!log_check_level(DIUCS, LOGL_DEBUG))
		return;

	struct ran_conn *conn;
	int i = 0;
	llist_for_each_entry(conn, &network->ran_conns, entry) {
		DEBUGP(DIUCS, "%3d: %s", i, vlr_subscr_name(conn->vsub));
		switch (conn->via_ran) {
		case OSMO_RAT_UTRAN_IU:
			DEBUGPC(DIUCS, " Iu");
			if (conn->iu.ue_ctx) {
				DEBUGPC(DIUCS, " conn_id %d",
					conn->iu.ue_ctx->conn_id
				       );
			}
			break;
		case OSMO_RAT_GERAN_A:
			DEBUGPC(DIUCS, " A");
			/* TODO log A-interface connection details */
			break;
		case OSMO_RAT_UNKNOWN:
			DEBUGPC(DIUCS, " ?");
			break;
		default:
			DEBUGPC(DIUCS, " invalid");
			break;
		}
		DEBUGPC(DIUCS, "\n");
		i++;
	}
	DEBUGP(DIUCS, "subscribers registered: %d\n", i);
}

/* Return an existing IuCS RAN connection record for the given
 * connection IDs, or return NULL if not found. */
struct ran_conn *ran_conn_lookup_iu(
						struct gsm_network *network,
						struct ranap_ue_conn_ctx *ue)
{
	struct ran_conn *conn;

	DEBUGP(DIUCS, "Looking for IuCS subscriber: conn_id %" PRIx32 "\n",
	       ue->conn_id);
	log_subscribers(network);

	llist_for_each_entry(conn, &network->ran_conns, entry) {
		if (conn->via_ran != OSMO_RAT_UTRAN_IU)
			continue;
		if (!same_ue_conn(conn->iu.ue_ctx, ue))
			continue;
		DEBUGP(DIUCS, "Found IuCS subscriber for conn_id %" PRIx32 "\n",
		       ue->conn_id);
		return conn;
	}
	DEBUGP(DIUCS, "No IuCS subscriber found for conn_id %" PRIx32 "\n",
	       ue->conn_id);
	return NULL;
}

/* Receive MM/CC/... message from IuCS (SCCP user SAP).
 * msg->dst must reference a struct ranap_ue_conn_ctx, which identifies the peer that
 * sent the msg.
 *
 * For A-interface see libbsc/bsc_api.c gsm0408_rcvmsg(). */
int gsm0408_rcvmsg_iucs(struct gsm_network *network, struct msgb *msg,
			uint16_t *lac)
{
	struct ranap_ue_conn_ctx *ue_ctx;
	struct ran_conn *conn;

	ue_ctx = (struct ranap_ue_conn_ctx*)msg->dst;

	/* TODO: are there message types that could allow us to skip this
	 * search? */
	conn = ran_conn_lookup_iu(network, ue_ctx);

	if (conn && lac && (conn->lac != *lac)) {
		LOGP(DIUCS, LOGL_ERROR, "IuCS subscriber has changed LAC"
		     " within the same connection, discarding connection:"
		     " %s from LAC %d to %d\n",
		     vlr_subscr_name(conn->vsub), conn->lac, *lac);
		/* Deallocate conn with previous LAC */
		ran_conn_close(conn, GSM_CAUSE_INV_MAND_INFO);
		/* At this point we could be tolerant and allocate a new
		 * connection, but changing the LAC within the same connection
		 * is shifty. Rather cancel everything. */
		return -1;
	}

	if (conn) {
		/* Make sure we don't receive RR over IuCS; otherwise all
		 * messages handled by gsm0408_dispatch() are of interest (CC,
		 * MM, SMS, NS_SS, maybe even MM_GPRS and SM_GPRS). */
		struct gsm48_hdr *gh = msgb_l3(msg);
		uint8_t pdisc = gh->proto_discr & 0x0f;
		OSMO_ASSERT(pdisc != GSM48_PDISC_RR);

		ran_conn_dtap(conn, msg);
	} else {
		/* allocate a new connection */

		if (!lac) {
			LOGP(DIUCS, LOGL_ERROR, "New IuCS subscriber"
			     " but no LAC available. Expecting an InitialUE"
			     " message containing a LAI IE."
			     " Dropping connection.\n");
			return -1;
		}

		conn = ran_conn_allocate_iu(network, ue_ctx, *lac);
		if (!conn)
			abort();

		/* ownership of conn hereby goes to the MSC: */
		ran_conn_compl_l3(conn, msg, 0);
	}

	return 0;
}

int iu_rab_act_cs(struct gsm_trans *trans)
{
	struct ran_conn *conn;
	struct msgb *msg;
	bool use_x213_nsap;
	uint32_t conn_id;
	struct ranap_ue_conn_ctx *uectx;
	uint8_t rab_id;
	uint32_t rtp_ip;
	uint16_t rtp_port;

	conn = trans->conn;
	uectx = conn->iu.ue_ctx;
	rab_id = conn->iu.rab_id;
	rtp_ip = osmo_htonl(inet_addr(conn->rtp.local_addr_ran));
	rtp_port = conn->rtp.local_port_ran;
	conn_id = uectx->conn_id;

	if (rtp_ip == INADDR_NONE) {
		LOGP(DIUCS, LOGL_DEBUG,
		     "Assigning RAB: conn_id=%u, rab_id=%d, invalid RTP IP-Address\n",
		     conn_id, rab_id);
		return -EINVAL;
	}
	if (rtp_port == 0) {
		LOGP(DIUCS, LOGL_DEBUG,
		     "Assigning RAB: conn_id=%u, rab_id=%d, invalid RTP Port\n",
		     conn_id, rab_id);
		return -EINVAL;
	}

	use_x213_nsap =
	    (uectx->rab_assign_addr_enc == RANAP_NSAP_ADDR_ENC_X213);

	LOGP(DIUCS, LOGL_DEBUG,
	     "Assigning RAB: conn_id=%u, rab_id=%d, rtp=%x:%u, use_x213_nsap=%d\n",
	     conn_id, rab_id, rtp_ip, rtp_port, use_x213_nsap);

	msg = ranap_new_msg_rab_assign_voice(rab_id, rtp_ip, rtp_port,
					     use_x213_nsap);
	msg->l2h = msg->data;

	if (ranap_iu_rab_act(uectx, msg))
		LOGP(DIUCS, LOGL_ERROR,
		     "Failed to send RAB Assignment: conn_id=%d rab_id=%d rtp=%x:%u\n",
		     conn_id, rab_id, rtp_ip, rtp_port);
	return 0;
}

uint32_t iu_get_conn_id(const struct ranap_ue_conn_ctx *ue)
{
	return ue->conn_id;
}
