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
#include <osmocom/msc/msc_a.h>
#include <osmocom/msc/msub.h>
#include <osmocom/msc/paging.h>
#include <osmocom/msc/silent_call.h>
#include <osmocom/msc/msc_vgcs.h>

void *tall_trans_ctx;

void _gsm48_cc_trans_free(struct gsm_trans *trans);
void _gsm411_sms_trans_free(struct gsm_trans *trans);
void _gsm911_nc_ss_trans_free(struct gsm_trans *trans);

struct gsm_trans *trans_find_by_type(const struct msc_a *msc_a, enum trans_type type)
{
	struct gsm_trans *trans;
	struct gsm_network *net = msc_a_net(msc_a);
	struct vlr_subscr *vsub = msc_a_vsub(msc_a);

	llist_for_each_entry(trans, &net->trans_list, entry) {
		if (trans->vsub == vsub && trans->type == type)
			return trans;
	}
	return NULL;
}

/*! Find a transaction in connection for given protocol + transaction ID
 * \param[in] conn Connection in which we want to find transaction
 * \param[in] proto Protocol of transaction
 * \param[in] trans_id Transaction ID of transaction
 * \returns Matching transaction, if any
 */
struct gsm_trans *trans_find_by_id(const struct msc_a *msc_a,
				   enum trans_type type, uint8_t trans_id)
{
	struct gsm_trans *trans;
	struct gsm_network *net = msc_a_net(msc_a);
	struct vlr_subscr *vsub = msc_a_vsub(msc_a);

	llist_for_each_entry(trans, &net->trans_list, entry) {
		if (trans->vsub == vsub &&
		    trans->type == type &&
		    trans->transaction_id == trans_id)
			return trans;
	}
	return NULL;
}

/*! Find a transaction by call reference
 * \param[in] net Network in which we should search
 * \param[in] type Transaction type (e.g. TRANS_CC)
 * \param[in] callref Call Reference of transaction
 * \returns Matching transaction, if any
 */
struct gsm_trans *trans_find_by_callref(const struct gsm_network *net, enum trans_type type,
					uint32_t callref)
{
	struct gsm_trans *trans;

	llist_for_each_entry(trans, &net->trans_list, entry) {
		if (trans->callref == callref && trans->type == type)
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
		    trans->type == TRANS_SMS &&
		    trans->sms.sm_rp_mr == sm_rp_mr)
			return trans;
	}

	return NULL;
}

struct osmo_lcls *trans_lcls_compose(const struct gsm_trans *trans, bool use_lac)
{
	if (!trans) {
		LOGP(DCC, LOGL_ERROR, "LCLS: unable to fill parameters for unallocated transaction\n");
		return NULL;
	}

	if (!trans->net->a.sri->sccp)
		return NULL;

	struct osmo_ss7_instance *ss7 = osmo_sccp_get_ss7(trans->net->a.sri->sccp);
	struct osmo_lcls *lcls;
	uint8_t w = osmo_ss7_pc_width(&ss7->cfg.pc_fmt);

	if (!trans->net->lcls_permitted) {
		LOGP(DCC, LOGL_NOTICE, "LCLS disabled globally\n");
		return NULL;
	}

	if (!trans->msc_a) {
		LOGP(DCC, LOGL_ERROR, "LCLS: unable to fill parameters for transaction without connection\n");
		return NULL;
	}

	if (trans->msc_a->c.ran->type != OSMO_RAT_GERAN_A) {
		LOGP(DCC, LOGL_ERROR, "LCLS: only A interface is supported at the moment\n");
		return NULL;
	}

	lcls = talloc_zero(trans, struct osmo_lcls);
	if (!lcls) {
		LOGP(DCC, LOGL_ERROR, "LCLS: failed to allocate osmo_lcls\n");
		return NULL;
	}

	LOGP(DCC, LOGL_INFO, "LCLS: using %u bits (%u bytes) for node ID\n", w, w / 8);

	lcls->gcr.net_len = 3;
	lcls->gcr.node = ss7->cfg.primary_pc;

	/* net id from Q.1902.3 3-5 bytes, this function gives 3 bytes exactly */
	osmo_plmn_to_bcd(lcls->gcr.net, &trans->msc_a->via_cell.lai.plmn);


	/* TS 29.205 Table B.2.1.9.2 Call Reference ID
	 * 3 octets Call ID + 2 octets BSS ID
	 */
	lcls->gcr.cr[2] = (trans->callref >>  0) & 0xff;
	lcls->gcr.cr[1] = (trans->callref >>  8) & 0xff;
	lcls->gcr.cr[0] = (trans->callref >> 16) & 0xff;
	osmo_store16be(use_lac ? trans->msc_a->via_cell.lai.lac : trans->msc_a->via_cell.cell_identity, &lcls->gcr.cr[3]);

	LOGP(DCC, LOGL_INFO, "LCLS: allocated %s-based CR-ID %sfor callref 0x%04x\n", use_lac ? "LAC" : "CI",
	     osmo_hexdump(lcls->gcr.cr, 5), trans->callref);

	lcls->config = GSM0808_LCLS_CFG_BOTH_WAY;
	lcls->control = GSM0808_LCLS_CSC_CONNECT;
	lcls->corr_needed = true;
	lcls->gcr_available = true;

	LOGP(DCC, LOGL_DEBUG, "Filled %s\n", osmo_lcls_dump(lcls));
	LOGP(DCC, LOGL_DEBUG, "Filled %s\n", osmo_gcr_dump(lcls));

	return lcls;
}

static const char *trans_vsub_use(enum trans_type type)
{
	return get_value_string_or_null(trans_type_names, type) ? : "trans-type-unknown";
}

static uint32_t new_call_id = 1;

/*! Allocate a new transaction and add it to network list
 *  \param[in] net Network in which we allocate transaction
 *  \param[in] subscr Subscriber for which we allocate transaction
 *  \param[in] protocol Protocol (CC/SMS/...)
 *  \param[in] callref Call Reference
 *  \returns Transaction
 */
struct gsm_trans *trans_alloc(struct gsm_network *net,
			      struct vlr_subscr *vsub,
			      enum trans_type type, uint8_t trans_id,
			      uint32_t callref)
{
	int subsys = trans_log_subsys(type);
	struct gsm_trans *trans;

	/* A valid subscriber is indispensable, except for voice group/broadcast calls. */
	if (vsub == NULL && type != TRANS_GCC && type != TRANS_BCC) {
		LOGP(subsys, LOGL_ERROR, "unable to alloc transaction, invalid subscriber (NULL)\n");
		return NULL;
	}

	trans = talloc(tall_trans_ctx, struct gsm_trans);
	if (!trans)
		return NULL;

	*trans = (struct gsm_trans){
		.vsub = vsub,
		.type = type,
		.log_subsys = subsys,
		.transaction_id = trans_id,
		.callref = callref,
		.call_id = new_call_id++,
		.net = net,
		/* empty bearer_cap: make sure the speech_ver array is empty */
		.bearer_cap = {
			.speech_ver = { -1 },
		},
	};
	if (vsub)
		vlr_subscr_get(vsub, trans_vsub_use(type));
	llist_add_tail(&trans->entry, &net->trans_list);

	LOG_TRANS(trans, LOGL_DEBUG, "New transaction\n");
	return trans;
}

/*! Release a transaction
 * \param[in] trans Transaction to be released
 */
void trans_free(struct gsm_trans *trans)
{
	const char *usage_token;
	struct msc_a *msc_a;

	LOG_TRANS(trans, LOGL_DEBUG, "Freeing transaction\n");

	switch (trans->type) {
	case TRANS_GCC:
		gsm44068_bcc_gcc_trans_free(trans);
		usage_token = MSC_A_USE_GCC;
		break;
	case TRANS_BCC:
		gsm44068_bcc_gcc_trans_free(trans);
		usage_token = MSC_A_USE_BCC;
		break;
	case TRANS_CC:
		_gsm48_cc_trans_free(trans);
		usage_token = MSC_A_USE_CC;
		break;
	case TRANS_SMS:
		_gsm411_sms_trans_free(trans);
		usage_token = MSC_A_USE_SMS;
		break;
	case TRANS_USSD:
		_gsm911_nc_ss_trans_free(trans);
		usage_token = MSC_A_USE_NC_SS;
		break;
	case TRANS_SILENT_CALL:
		trans_silent_call_free(trans);
		usage_token = MSC_A_USE_SILENT_CALL;
		break;
	default:
		usage_token = NULL;
		break;
	}

	if (trans->paging_request) {
		paging_request_remove(trans->paging_request);
		trans->paging_request = NULL;
	}

	if (trans->vsub) {
		vlr_subscr_put(trans->vsub, trans_vsub_use(trans->type));
		trans->vsub = NULL;
	}

	msc_a = trans->msc_a;
	trans->msc_a = NULL;

	llist_del(&trans->entry);
	talloc_free(trans);

	if (msc_a && usage_token)
		msc_a_put(msc_a, usage_token);
}

/*! allocate an unused transaction ID for the given subscriber
 * in the given protocol using TI flag = 0 (allocated by us).
 * See GSM 04.07, section 11.2.3.1.3 "Transaction identifier".
 * \param[in] net GSM network
 * \param[in] subscr Subscriber for which to assign a new TID
 * \param[in] protocol Protocol of to be assigned TID
 */
int trans_assign_trans_id(const struct gsm_network *net, const struct vlr_subscr *vsub,
			  enum trans_type type)
{
	struct gsm_trans *trans;
	unsigned int used_tid_bitmask = 0;
	int i, j, h;
	uint8_t proto = trans_type_to_gsm48_proto(type);

	/* generate bitmask of already-used TIDs for this (subscr,proto) */
	llist_for_each_entry(trans, &net->trans_list, entry) {
		if (trans->vsub != vsub ||
		    proto != trans_type_to_gsm48_proto(trans->type) ||
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
struct gsm_trans *trans_has_conn(const struct msc_a *msc_a)
{
	struct gsm_trans *trans;
	struct gsm_network *net = msc_a_net(msc_a);

	llist_for_each_entry(trans, &net->trans_list, entry)
		if (trans->msc_a == msc_a)
			return trans;

	return NULL;
}

/*! Free all transactions associated with a connection, presumably when the
 * conn is being closed. The transaction code will inform the CC or SMS
 * facilities, which will then send the necessary release indications.
 * \param[in] conn Connection that is going to be closed.
 */
void trans_conn_closed(const struct msc_a *msc_a)
{
	/* As part of the CC REL_IND the remote leg might be released and this
	 * will trigger another call to trans_free. This is something the llist
	 * macro can not handle and we need to re-iterate the list every time.
	 */
	struct gsm_trans *trans;
	while ((trans = trans_has_conn(msc_a)))
		trans_free(trans);
}

const struct value_string trans_type_names[] = {
	{ TRANS_GCC, "GCC" },
	{ TRANS_BCC, "BCC" },
	{ TRANS_CC, "CC" },
	{ TRANS_SMS, "SMS" },
	{ TRANS_USSD, "NCSS" },
	{ TRANS_SILENT_CALL, "silent-call" },
	{}
};

uint8_t trans_type_to_gsm48_proto(enum trans_type type)
{
	switch (type) {
	case TRANS_GCC:
		return GSM48_PDISC_GROUP_CC;
	case TRANS_BCC:
		return GSM48_PDISC_BCAST_CC;
	case TRANS_CC:
	case TRANS_SILENT_CALL:
		return GSM48_PDISC_CC;
	case TRANS_SMS:
		return GSM48_PDISC_SMS;
	case TRANS_USSD:
		return GSM48_PDISC_NC_SS;
	default:
		return GSM48_PDISC_TEST;
	}

}

const char *trans_name(const struct gsm_trans *trans)
{
	static char namebuf[32];
	if (!trans)
		return "NULL";
	switch (trans->type) {
	case TRANS_CC:
		snprintf(namebuf, sizeof(namebuf), "%s:%s",
			 trans_type_name(trans->type), gsm48_cc_state_name(trans->cc.state));
		return namebuf;

	case TRANS_GCC:
	case TRANS_BCC:
		snprintf(namebuf, sizeof(namebuf), "%s:%s",
			 trans_type_name(trans->type), gsm44068_group_id_string(trans->callref));
		return namebuf;

	default:
		return trans_type_name(trans->type);
	}
}
