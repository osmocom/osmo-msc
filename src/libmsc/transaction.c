/* GSM 04.07 Transaction handling */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
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

#include <osmocom/msc/transaction.h>
#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/mncc.h>
#include <osmocom/msc/debug.h>
#include <osmocom/core/talloc.h>
#include <osmocom/msc/gsm_04_08.h>
#include <osmocom/msc/vlr.h>

void *tall_trans_ctx;

void _gsm48_cc_trans_free(struct gsm_trans *trans);
void _gsm411_sms_trans_free(struct gsm_trans *trans);
void _gsm911_nc_ss_trans_free(struct gsm_trans *trans);

/*! Find a transaction in connection for given protocol + transaction ID
 * \param[in] conn Connection in which we want to find transaction
 * \param[in] proto Protocol of transaction
 * \param[in] trans_id Transaction ID of transaction
 * \returns Matching transaction, if any
 */
struct gsm_trans *trans_find_by_id(const struct ran_conn *conn,
				   uint8_t proto, uint8_t trans_id)
{
	struct gsm_trans *trans;
	struct gsm_network *net = conn->network;
	struct vlr_subscr *vsub = conn->vsub;

	llist_for_each_entry(trans, &net->trans_list, entry) {
		if (trans->vsub == vsub &&
		    trans->protocol == proto &&
		    trans->transaction_id == trans_id)
			return trans;
	}
	return NULL;
}

/*! Find a transaction by call reference
 * \param[in] net Network in which we should search
 * \param[in] callref Call Reference of transaction
 * \returns Matching transaction, if any
 */
struct gsm_trans *trans_find_by_callref(const struct gsm_network *net,
					uint32_t callref)
{
	struct gsm_trans *trans;

	llist_for_each_entry(trans, &net->trans_list, entry) {
		if (trans->callref == callref)
			return trans;
	}
	return NULL;
}

/*! Find a transaction by SM-RP-MR (RP Message Reference)
 * \param[in] net Network in which we should search
 * \param[in] vsub Subscriber for which we should search
 * \param[in] sm_rp_mr RP Message Reference (see GSM TS 04.11, section 8.2.3)
 * \returns Matching transaction, NULL otherwise
 */
struct gsm_trans *trans_find_by_sm_rp_mr(const struct gsm_network *net,
					 const struct vlr_subscr *vsub,
					 uint8_t sm_rp_mr)
{
	struct gsm_trans *trans;

	llist_for_each_entry(trans, &net->trans_list, entry) {
		if (trans->vsub == vsub &&
		    trans->protocol == GSM48_PDISC_SMS &&
		    trans->sms.sm_rp_mr == sm_rp_mr)
			return trans;
	}

	return NULL;
}

static const char *trans_vsub_use(uint8_t proto)
{
	return get_value_string_or_null(gsm48_pdisc_names, proto) ? : "trans-proto-unknown";
}

/*! Allocate a new transaction and add it to network list
 *  \param[in] net Netwokr in which we allocate transaction
 *  \param[in] subscr Subscriber for which we allocate transaction
 *  \param[in] protocol Protocol (CC/SMS/...)
 *  \param[in] callref Call Reference
 *  \returns Transaction
 */
struct gsm_trans *trans_alloc(struct gsm_network *net,
			      struct vlr_subscr *vsub,
			      uint8_t protocol, uint8_t trans_id,
			      uint32_t callref)
{
	struct gsm_trans *trans;

	/* a valid subscriber is indispensable */
	if (vsub == NULL) {
		LOGP(DVLR, LOGL_ERROR,
		     "unable to alloc transaction, invalid subscriber (NULL)\n");
		return NULL;
	}

	DEBUGP(DCC, "(ti %02x sub %s callref %x) New transaction\n",
	       trans_id, vlr_subscr_name(vsub), callref);

	trans = talloc_zero(tall_trans_ctx, struct gsm_trans);
	if (!trans)
		return NULL;

	vlr_subscr_get(vsub, trans_vsub_use(protocol));
	trans->vsub = vsub;
	trans->protocol = protocol;
	trans->transaction_id = trans_id;
	trans->callref = callref;

	trans->net = net;
	llist_add_tail(&trans->entry, &net->trans_list);

	return trans;
}

/*! Release a transaction
 * \param[in] trans Transaction to be released
 */
void trans_free(struct gsm_trans *trans)
{
	enum ran_conn_use conn_usage_token;
	struct ran_conn *conn;

	switch (trans->protocol) {
	case GSM48_PDISC_CC:
		_gsm48_cc_trans_free(trans);
		conn_usage_token = RAN_CONN_USE_TRANS_CC;
		break;
	case GSM48_PDISC_SMS:
		_gsm411_sms_trans_free(trans);
		conn_usage_token = RAN_CONN_USE_TRANS_SMS;
		break;
	case GSM48_PDISC_NC_SS:
		_gsm911_nc_ss_trans_free(trans);
		conn_usage_token = RAN_CONN_USE_TRANS_NC_SS;
		break;
	default:
		conn_usage_token = RAN_CONN_USE_UNTRACKED;
		break;
	}

	if (trans->paging_request) {
		subscr_remove_request(trans->paging_request);
		trans->paging_request = NULL;
	}

	if (trans->vsub) {
		vlr_subscr_put(trans->vsub, trans_vsub_use(trans->protocol));
		trans->vsub = NULL;
	}

	conn = trans->conn;
	trans->conn = NULL;
	llist_del(&trans->entry);
	talloc_free(trans);

	if (conn)
		ran_conn_put(conn, conn_usage_token);
}

/*! allocate an unused transaction ID for the given subscriber
 * in the given protocol using TI flag = 0 (allocated by us).
 * See GSM 04.07, section 11.2.3.1.3 "Transaction identifier".
 * \param[in] net GSM network
 * \param[in] subscr Subscriber for which to assign a new TID
 * \param[in] protocol Protocol of to be assigned TID
 */
int trans_assign_trans_id(const struct gsm_network *net, const struct vlr_subscr *vsub,
			  uint8_t protocol)
{
	struct gsm_trans *trans;
	unsigned int used_tid_bitmask = 0;
	int i, j, h;

	/* generate bitmask of already-used TIDs for this (subscr,proto) */
	llist_for_each_entry(trans, &net->trans_list, entry) {
		if (trans->vsub != vsub ||
		    trans->protocol != protocol ||
		    trans->transaction_id == TRANS_ID_UNASSIGNED)
			continue;
		used_tid_bitmask |= (1 << trans->transaction_id);
	}

	/* find a new one, trying to go in a 'circular' pattern */
	for (h = 6; h > 0; h--)
		if (used_tid_bitmask & (1 << h))
			break;
	for (i = 0; i < 7; i++) {
		j = (h + i) % 7;
		if ((used_tid_bitmask & (1 << j)) == 0)
			return j;
	}

	return -1;
}

/*! Check if we have any transaction for given connection
 * \param[in] conn Connection to check
 * \returns transaction pointer if found, NULL otherwise
 */
struct gsm_trans *trans_has_conn(const struct ran_conn *conn)
{
	struct gsm_trans *trans;

	llist_for_each_entry(trans, &conn->network->trans_list, entry)
		if (trans->conn == conn)
			return trans;

	return NULL;
}

/*! Free all transactions associated with a connection, presumably when the
 * conn is being closed. The transaction code will inform the CC or SMS
 * facilities, which will then send the necessary release indications.
 * \param[in] conn Connection that is going to be closed.
 */
void trans_conn_closed(const struct ran_conn *conn)
{
	struct gsm_trans *trans;

	/* As part of the CC REL_IND the remote leg might be released and this
	 * will trigger another call to trans_free. This is something the llist
	 * macro can not handle and we need to re-iterate the list every time.
	 */
restart:
	llist_for_each_entry(trans, &conn->network->trans_list, entry) {
		if (trans->conn == conn) {
			trans_free(trans);
			goto restart;
		}
	}
}
