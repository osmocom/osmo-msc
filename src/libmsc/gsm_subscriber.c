/* The concept of a subscriber for the MSC, roughly HLR/VLR functionality */

/* (C) 2008 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009,2013 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include "../../bscconfig.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdbool.h>

#include <osmocom/core/talloc.h>

#include <osmocom/vty/vty.h>

#ifdef BUILD_IU
#include <osmocom/ranap/iu_client.h>
#else
#include <osmocom/msc/iu_dummy.h>
#endif

#include <osmocom/msc/gsm_subscriber.h>
#include <osmocom/msc/gsm_04_08.h>
#include <osmocom/msc/debug.h>
#include <osmocom/msc/signal.h>
#include <osmocom/msc/db.h>
#include <osmocom/msc/vlr.h>
#include <osmocom/msc/msc_ifaces.h>
#include <osmocom/msc/a_iface.h>
#include <osmocom/msc/sgs_iface.h>

#define VSUB_USE_PAGING "Paging"

void subscr_paging_cancel(struct vlr_subscr *vsub, enum gsm_paging_event event)
{
	subscr_paging_dispatch(GSM_HOOK_RR_PAGING, event, NULL, NULL, vsub);
}

int subscr_paging_dispatch(unsigned int hooknum, unsigned int event,
			   struct msgb *msg, void *data, void *param)
{
	struct subscr_request *request, *tmp;
	struct ran_conn *conn = data;
	struct vlr_subscr *vsub = param;
	struct paging_signal_data sig_data;

	OSMO_ASSERT(vsub);
	OSMO_ASSERT(hooknum == GSM_HOOK_RR_PAGING);
	OSMO_ASSERT(!(conn && (conn->vsub != vsub)));
	OSMO_ASSERT(!((event == GSM_PAGING_SUCCEEDED) && !conn));

	LOGP(DPAG, LOGL_DEBUG, "Paging %s for %s (event=%d)\n",
	     event == GSM_PAGING_SUCCEEDED ? "success" : "failure",
	     vlr_subscr_name(vsub), event);

	if (!vsub->cs.is_paging) {
		LOGP(DPAG, LOGL_ERROR,
		     "Paging Response received for subscriber"
		     " that is not paging.\n");
		return -EINVAL;
	}

	osmo_timer_del(&vsub->cs.paging_response_timer);

	if (event == GSM_PAGING_SUCCEEDED
	    || event == GSM_PAGING_EXPIRED)
		msc_stop_paging(vsub);

	/* Inform parts of the system we don't know */
	sig_data.vsub = vsub;
	sig_data.conn = conn;
	sig_data.paging_result = event;
	osmo_signal_dispatch(SS_PAGING,
			     event == GSM_PAGING_SUCCEEDED ?
				S_PAGING_SUCCEEDED : S_PAGING_EXPIRED,
			     &sig_data);

	llist_for_each_entry_safe(request, tmp, &vsub->cs.requests, entry) {
		llist_del(&request->entry);
		if (request->cbfn) {
			LOGP(DPAG, LOGL_DEBUG, "Calling paging cbfn.\n");
			request->cbfn(hooknum, event, msg, data, request->param);
		} else
			LOGP(DPAG, LOGL_DEBUG, "Paging without action.\n");
		talloc_free(request);
	}

	/* balanced with the moment we start paging */
	vsub->cs.is_paging = false;
	vlr_subscr_put(vsub, VSUB_USE_PAGING);
	return 0;
}

/* Execute a paging on the currently active RAN. Returns the number of
 * delivered paging requests or -EINVAL in case of failure. */
static int msc_paging_request(struct vlr_subscr *vsub, enum sgsap_service_ind serv_ind)
{
	/* The subscriber was last seen in subscr->lac. Find out which
	 * BSCs/RNCs are responsible and send them a paging request via open
	 * SCCP connections (if any). */
	switch (vsub->cs.attached_via_ran) {
	case OSMO_RAT_GERAN_A:
		return a_iface_tx_paging(vsub->imsi, vsub->tmsi, vsub->cgi.lai.lac);
	case OSMO_RAT_UTRAN_IU:
		return ranap_iu_page_cs(vsub->imsi,
					vsub->tmsi == GSM_RESERVED_TMSI?
					NULL : &vsub->tmsi,
					vsub->cgi.lai.lac);
	case OSMO_RAT_EUTRAN_SGS:
		return sgs_iface_tx_paging(vsub, serv_ind);
	default:
		break;
	}

	LOGP(DPAG, LOGL_ERROR, "%s: Cannot page, subscriber not attached\n",
	     vlr_subscr_name(vsub));
	return -EINVAL;
}

static void paging_response_timer_cb(void *data)
{
	struct vlr_subscr *vsub = data;
	subscr_paging_cancel(vsub, GSM_PAGING_EXPIRED);
}

/*! \brief Start a paging request for vsub, call cbfn(param) when done.
 * \param vsub  subscriber to page.
 * \param cbfn  function to call when the conn is established.
 * \param param  caller defined param to pass to cbfn().
 * \param label  human readable label of the request kind used for logging.
 * \param serv_ind  sgsap service indicator (in case SGs interface is used to page).
 */
struct subscr_request *subscr_request_conn(struct vlr_subscr *vsub,
					   gsm_cbfn *cbfn, void *param,
					   const char *label, enum sgsap_service_ind serv_ind)
{
	int rc;
	struct subscr_request *request;
	struct gsm_network *net = vsub->vlr->user_ctx;

	/* Start paging.. we know it is async so we can do it before */
	if (!vsub->cs.is_paging) {
		LOGP(DMM, LOGL_DEBUG, "Subscriber %s not paged yet, start paging.\n",
		     vlr_subscr_name(vsub));
		rc = msc_paging_request(vsub, serv_ind);
		if (rc <= 0) {
			LOGP(DMM, LOGL_ERROR, "Subscriber %s paging failed: %d\n",
			     vlr_subscr_name(vsub), rc);
			return NULL;
		}
		/* reduced on the first paging callback */
		vlr_subscr_get(vsub, VSUB_USE_PAGING);
		vsub->cs.is_paging = true;
		osmo_timer_setup(&vsub->cs.paging_response_timer, paging_response_timer_cb, vsub);
		osmo_timer_schedule(&vsub->cs.paging_response_timer, net->paging_response_timer, 0);
	} else {
		LOGP(DMM, LOGL_DEBUG, "Subscriber %s already paged.\n",
			vlr_subscr_name(vsub));
	}

	/* TODO: Stop paging in case of memory allocation failure */
	request = talloc_zero(vsub, struct subscr_request);
	if (!request)
		return NULL;

	request->cbfn = cbfn;
	request->param = param;
	llist_add_tail(&request->entry, &vsub->cs.requests);
	return request;
}

void subscr_remove_request(struct subscr_request *request)
{
	llist_del(&request->entry);
	talloc_free(request);
}

struct ran_conn *connection_for_subscr(struct vlr_subscr *vsub)
{
	struct gsm_network *net = vsub->vlr->user_ctx;
	struct ran_conn *conn;

	llist_for_each_entry(conn, &net->ran_conns, entry) {
		if (conn->vsub != vsub)
			continue;
		/* Found a conn, but is it in a usable state? Must not add transactions to a conn that is in release,
		 * and must not start transactions for an unauthenticated subscriber. There will obviously be only one
		 * conn for this vsub, so return NULL right away. */
		if (!ran_conn_is_accepted(conn))
			return NULL;
		return conn;
	}

	return NULL;
}
