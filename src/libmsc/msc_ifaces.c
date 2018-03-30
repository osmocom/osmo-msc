/* Implementation for MSC decisions which interface to send messages out on. */

/* (C) 2016 by sysmocom s.m.f.c GmbH <info@sysmocom.de>
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

#include <osmocom/core/logging.h>

#include <osmocom/msc/debug.h>
#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/msc_ifaces.h>
#include <osmocom/msc/gsm_subscriber.h>
#include <osmocom/msc/transaction.h>
#include <osmocom/mgcp_client/mgcp_client.h>
#include <osmocom/msc/vlr.h>
#include <osmocom/msc/a_iface.h>
#include <osmocom/msc/gsm_04_08.h>
#include <osmocom/msc/msc_mgcp.h>

#include "../../bscconfig.h"

#ifdef BUILD_IU
#include <osmocom/ranap/iu_client.h>
#else
#include <osmocom/msc/iu_dummy.h>
#endif /* BUILD_IU */

const struct value_string ran_type_names[] = {
	OSMO_VALUE_STRING(RAN_UNKNOWN),
	OSMO_VALUE_STRING(RAN_GERAN_A),
	OSMO_VALUE_STRING(RAN_UTRAN_IU),
	{ 0, NULL }
};

static int msc_tx(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	if (!msg)
		return -EINVAL;
	if (!conn) {
		msgb_free(msg);
		return -EINVAL;
	}

	DEBUGP(DMSC, "msc_tx %u bytes to %s via %s\n",
	       msg->len, vlr_subscr_name(conn->vsub),
	       ran_type_name(conn->via_ran));
	switch (conn->via_ran) {
	case RAN_GERAN_A:
		msg->dst = conn;
		return a_iface_tx_dtap(msg);

	case RAN_UTRAN_IU:
		msg->dst = conn->iu.ue_ctx;
		return ranap_iu_tx(msg, 0);

	default:
		LOGP(DMSC, LOGL_ERROR,
		     "msc_tx(): conn->via_ran invalid (%d)\n",
		     conn->via_ran);
		msgb_free(msg);
		return -1;
	}
}


int msc_tx_dtap(struct gsm_subscriber_connection *conn,
		struct msgb *msg)
{
	return msc_tx(conn, msg);
}


/* 9.2.5 CM service accept */
int msc_gsm48_tx_mm_serv_ack(struct gsm_subscriber_connection *conn)
{
	struct msgb *msg;
	struct gsm48_hdr *gh;

	if (!conn)
		return -EINVAL;

	msg = gsm48_msgb_alloc_name("GSM 04.08 SERV ACC");

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_CM_SERV_ACC;

	DEBUGP(DMM, "-> CM SERVICE ACCEPT %s\n",
	       vlr_subscr_name(conn->vsub));

	return msc_tx_dtap(conn, msg);
}

/* 9.2.6 CM service reject */
int msc_gsm48_tx_mm_serv_rej(struct gsm_subscriber_connection *conn,
			     enum gsm48_reject_value value)
{
	struct msgb *msg;

	if (!conn)
		return -EINVAL;

	msg = gsm48_create_mm_serv_rej(value);
	if (!msg) {
		LOGP(DMM, LOGL_ERROR, "Failed to allocate CM Service Reject.\n");
		return -1;
	}

	DEBUGP(DMM, "-> CM SERVICE Reject cause: %d\n", value);

	return msc_tx_dtap(conn, msg);
}

int msc_tx_common_id(struct gsm_subscriber_connection *conn)
{
	if (!conn)
		return -EINVAL;

	/* Common ID is only sent over IuCS */
	if (conn->via_ran != RAN_UTRAN_IU) {
		LOGP(DMM, LOGL_INFO,
		     "%s: Asked to transmit Common ID, but skipping"
		     " because this is not on UTRAN\n",
		     vlr_subscr_name(conn->vsub));
		return 0;
	}

	DEBUGP(DIUCS, "%s: tx CommonID %s\n",
	       vlr_subscr_name(conn->vsub), conn->vsub->imsi);
	return ranap_iu_tx_common_id(conn->iu.ue_ctx, conn->vsub->imsi);
}
