/* main MSC management code... */

/*
 * (C) 2010,2013 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
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

#include <osmocom/msc/osmo_msc.h>
#include <osmocom/msc/debug.h>
#include <osmocom/msc/transaction.h>
#include <osmocom/msc/db.h>
#include <osmocom/msc/vlr.h>
#include <osmocom/msc/osmo_msc.h>
#include <osmocom/msc/a_iface.h>
#include <osmocom/msc/gsm_04_08.h>
#include <osmocom/msc/gsm_04_11.h>

#include "../../bscconfig.h"
#ifdef BUILD_IU
#include <osmocom/ranap/iu_client.h>
#else
#include <osmocom/msc/iu_dummy.h>
#endif

struct gsm_network *gsm_network_init(void *ctx, mncc_recv_cb_t mncc_recv)
{
	struct gsm_network *net;

	net = talloc_zero(ctx, struct gsm_network);
	if (!net)
		return NULL;

	net->plmn = (struct osmo_plmn_id){ .mcc=1, .mnc=1 };

	/* Permit a compile-time default of A5/3 and A5/1 */
	net->a5_encryption_mask = (1 << 3) | (1 << 1);

	/* Use 30 min periodic update interval as sane default */
	net->t3212 = 5;

	net->paging_response_timer = MSC_PAGING_RESPONSE_TIMER_DEFAULT;

	INIT_LLIST_HEAD(&net->trans_list);
	INIT_LLIST_HEAD(&net->upqueue);
	INIT_LLIST_HEAD(&net->subscr_conns);

	/* init statistics */
	net->msc_ctrs = rate_ctr_group_alloc(net, &msc_ctrg_desc, 0);
	if (!net->msc_ctrs) {
		talloc_free(net);
		return NULL;
	}
	net->active_calls = osmo_counter_alloc("msc.active_calls");
	net->active_nc_ss = osmo_counter_alloc("msc.active_nc_ss");

	net->mncc_recv = mncc_recv;

	INIT_LLIST_HEAD(&net->a.bscs);

	return net;
}

/* Receive a SAPI-N-REJECT from BSC */
void msc_sapi_n_reject(struct gsm_subscriber_connection *conn, int dlci)
{
	int sapi = dlci & 0x7;

	if (sapi == UM_SAPI_SMS)
		gsm411_sapi_n_reject(conn);
}

/* receive a Level 3 Complete message and return MSC_CONN_ACCEPT or
 * MSC_CONN_REJECT */
int msc_compl_l3(struct gsm_subscriber_connection *conn,
		 struct msgb *msg, uint16_t chosen_channel)
{
	msc_subscr_conn_get(conn, MSC_CONN_USE_COMPL_L3);
	gsm0408_dispatch(conn, msg);

	msc_subscr_conn_put(conn, MSC_CONN_USE_COMPL_L3);

	/* Always return acceptance, because even if the conn was not accepted,
	 * we assumed ownership of it and the caller shall not interfere with
	 * that. We may even already have discarded the conn. */
	return MSC_CONN_ACCEPT;

#if 0
	/*
	 * If this is a silent call we want the channel to remain open as long as
	 * possible and this is why we accept this connection regardless of any
	 * pending transaction or ongoing operation.
	 */
	if (conn->silent_call)
		return MSC_CONN_ACCEPT;
	if (conn->loc_operation || conn->sec_operation || conn->anch_operation)
		return MSC_CONN_ACCEPT;
	if (trans_has_conn(conn))
		return MSC_CONN_ACCEPT;

	LOGP(DRR, LOGL_INFO, "MSC Complete L3: Rejecting connection.\n");
	return MSC_CONN_REJECT;
#endif
}

/* Receive a DTAP message from BSC */
void msc_dtap(struct gsm_subscriber_connection *conn, uint8_t link_id, struct msgb *msg)
{
	msc_subscr_conn_get(conn, MSC_CONN_USE_DTAP);
	gsm0408_dispatch(conn, msg);

	msc_subscr_conn_put(conn, MSC_CONN_USE_DTAP);
}

/* Receive an ASSIGNMENT COMPLETE from BSC */
void msc_assign_compl(struct gsm_subscriber_connection *conn,
		      uint8_t rr_cause, uint8_t chosen_channel,
		      uint8_t encr_alg_id, uint8_t speec)
{
	LOGP(DRR, LOGL_DEBUG, "MSC assign complete (do nothing).\n");
}

/* Receive an ASSIGNMENT FAILURE from BSC */
void msc_assign_fail(struct gsm_subscriber_connection *conn,
		     uint8_t cause, uint8_t *rr_cause)
{
	LOGP(DRR, LOGL_DEBUG, "MSC assign failure (do nothing).\n");
}

/* Receive a CLASSMARK CHANGE from BSC */
void msc_classmark_chg(struct gsm_subscriber_connection *conn,
		       const uint8_t *cm2, uint8_t cm2_len,
		       const uint8_t *cm3, uint8_t cm3_len)
{
	if (cm2 && cm2_len) {
		if (cm2_len > sizeof(conn->classmark.classmark2)) {
			LOGP(DRR, LOGL_NOTICE, "%s: classmark2 is %u bytes, truncating at %zu bytes\n",
			     vlr_subscr_name(conn->vsub), cm2_len, sizeof(conn->classmark.classmark2));
			cm2_len = sizeof(conn->classmark.classmark2);
		}
		conn->classmark.classmark2_len = cm2_len;
		memcpy(conn->classmark.classmark2, cm2, cm2_len);
	}
	if (cm3 && cm3_len) {
		if (cm3_len > sizeof(conn->classmark.classmark3)) {
			LOGP(DRR, LOGL_NOTICE, "%s: classmark3 is %u bytes, truncating at %zu bytes\n",
			     vlr_subscr_name(conn->vsub), cm3_len, sizeof(conn->classmark.classmark3));
			cm3_len = sizeof(conn->classmark.classmark3);
		}
		conn->classmark.classmark3_len = cm3_len;
		memcpy(conn->classmark.classmark3, cm3, cm3_len);
	}
}

/* Receive a CIPHERING MODE COMPLETE from BSC */
void msc_cipher_mode_compl(struct gsm_subscriber_connection *conn,
			   struct msgb *msg, uint8_t alg_id)
{
	struct vlr_ciph_result ciph_res = { .cause = VLR_CIPH_REJECT };

	if (!conn) {
		LOGP(DRR, LOGL_ERROR, "invalid: rx Ciphering Mode Complete on NULL conn\n");
		return;
	}
	if (!conn->vsub) {
		LOGP(DRR, LOGL_ERROR, "invalid: rx Ciphering Mode Complete for NULL subscr\n");
		return;
	}

	DEBUGP(DRR, "%s: CIPHERING MODE COMPLETE\n", vlr_subscr_name(conn->vsub));

	if (msg) {
		struct gsm48_hdr *gh = msgb_l3(msg);
		unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
		struct tlv_parsed tp;
		uint8_t mi_type;

		if (!gh) {
			LOGP(DRR, LOGL_ERROR, "invalid: msgb without l3 header\n");
			return;
		}

		tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len, 0, 0);

		/* bearer capability */
		if (TLVP_PRESENT(&tp, GSM48_IE_MOBILE_ID)) {
			mi_type = TLVP_VAL(&tp, GSM48_IE_MOBILE_ID)[0] & GSM_MI_TYPE_MASK;
			if (mi_type == GSM_MI_TYPE_IMEISV
			    && TLVP_LEN(&tp, GSM48_IE_MOBILE_ID) > 0) {
				gsm48_mi_to_string(ciph_res.imeisv, sizeof(ciph_res.imeisv),
						   TLVP_VAL(&tp, GSM48_IE_MOBILE_ID),
						   TLVP_LEN(&tp, GSM48_IE_MOBILE_ID));
			}
		}
	}

	ciph_res.cause = VLR_CIPH_COMPL;
	vlr_subscr_rx_ciph_res(conn->vsub, &ciph_res);
}

/* Receive a CLEAR REQUEST from BSC */
int msc_clear_request(struct gsm_subscriber_connection *conn, uint32_t cause)
{
	msc_subscr_conn_close(conn, cause);
	return 1;
}

static const char *used_ref_counts_str(struct gsm_subscriber_connection *conn)
{
	static char buf[256];
	int bit_nr;
	char *pos = buf;
	*pos = '\0';

	if (conn->use_tokens < 0)
		return "invalid";

#define APPEND_STR(fmt, args...) do { \
		int remain = sizeof(buf) - (pos - buf) - 1; \
		int l = -1; \
		if (remain > 0) \
		    l = snprintf(pos, remain, "%s" fmt, (pos == buf? "" : ","), ##args); \
		if (l < 0 || l > remain) { \
			buf[sizeof(buf) - 1] = '\0'; \
			return buf; \
		} \
		pos += l; \
	} while(0)

	for (bit_nr = 0; (1 << bit_nr) <= conn->use_tokens; bit_nr++) {
		if (conn->use_tokens & (1 << bit_nr)) {
			APPEND_STR("%s", get_value_string(msc_subscr_conn_use_names, bit_nr));
		}
	}
	return buf;
#undef APPEND_STR
}

/* increment the ref-count. Needs to be called by every user */
struct gsm_subscriber_connection *
_msc_subscr_conn_get(struct gsm_subscriber_connection *conn,
		     enum msc_subscr_conn_use balance_token,
		     const char *file, int line)
{
	OSMO_ASSERT(conn);

	if (balance_token != MSC_CONN_USE_UNTRACKED) {
		uint32_t flag = 1 << balance_token;
		OSMO_ASSERT(balance_token < 32);
		if (conn->use_tokens & flag)
			LOGPSRC(DREF, LOGL_ERROR, file, line,
				"%s: MSC conn use error: using an already used token: %s\n",
				vlr_subscr_name(conn->vsub),
				msc_subscr_conn_use_name(balance_token));
		conn->use_tokens |= flag;
	}

	conn->use_count++;
	LOGPSRC(DREF, LOGL_DEBUG, file, line,
		"%s: MSC conn use + %s == %u (0x%x: %s)\n",
		vlr_subscr_name(conn->vsub), msc_subscr_conn_use_name(balance_token),
		conn->use_count, conn->use_tokens, used_ref_counts_str(conn));

	return conn;
}

/* decrement the ref-count. Once it reaches zero, we release */
void _msc_subscr_conn_put(struct gsm_subscriber_connection *conn,
			  enum msc_subscr_conn_use balance_token,
			  const char *file, int line)
{
	OSMO_ASSERT(conn);

	if (balance_token != MSC_CONN_USE_UNTRACKED) {
		uint32_t flag = 1 << balance_token;
		OSMO_ASSERT(balance_token < 32);
		if (!(conn->use_tokens & flag))
			LOGPSRC(DREF, LOGL_ERROR, file, line,
				"%s: MSC conn use error: freeing an unused token: %s\n",
				vlr_subscr_name(conn->vsub),
				msc_subscr_conn_use_name(balance_token));
		conn->use_tokens &= ~flag;
	}

	if (conn->use_count == 0) {
		LOGPSRC(DREF, LOGL_ERROR, file, line,
			"%s: MSC conn use - %s failed: is already 0\n",
			vlr_subscr_name(conn->vsub),
			msc_subscr_conn_use_name(balance_token));
		return;
	}

	conn->use_count--;
	LOGPSRC(DREF, LOGL_DEBUG, file, line,
		"%s: MSC conn use - %s == %u (0x%x: %s)\n",
		vlr_subscr_name(conn->vsub), msc_subscr_conn_use_name(balance_token),
		conn->use_count, conn->use_tokens, used_ref_counts_str(conn));

	if (conn->use_count == 0)
		osmo_fsm_inst_dispatch(conn->fi, SUBSCR_CONN_E_UNUSED, NULL);
}

bool msc_subscr_conn_used_by(struct gsm_subscriber_connection *conn, enum msc_subscr_conn_use token)
{
	return conn && (conn->use_tokens & (1 << token));
}

const struct value_string msc_subscr_conn_use_names[] = {
	{MSC_CONN_USE_UNTRACKED,	"UNTRACKED"},
	{MSC_CONN_USE_COMPL_L3,		"compl_l3"},
	{MSC_CONN_USE_DTAP,		"dtap"},
	{MSC_CONN_USE_AUTH_CIPH,	"auth+ciph"},
	{MSC_CONN_USE_CM_SERVICE,	"cm_service"},
	{MSC_CONN_USE_TRANS_CC,		"trans_cc"},
	{MSC_CONN_USE_TRANS_SMS,	"trans_sms"},
	{MSC_CONN_USE_TRANS_NC_SS,	"trans_nc_ss"},
	{MSC_CONN_USE_SILENT_CALL,	"silent_call"},
	{MSC_CONN_USE_RELEASE,		"release"},
	{0, NULL},
};

void msc_stop_paging(struct vlr_subscr *vsub)
{
	DEBUGP(DPAG, "Paging can stop for %s\n", vlr_subscr_name(vsub));
	/* tell BSCs and RNCs to stop paging? How? */
}
