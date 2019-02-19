/* GSM Mobile Radio Interface Layer 3 messages on the A-bis interface
 * 3GPP TS 04.08 version 7.21.0 Release 1998 / ETSI TS 100 940 V7.21.0 */

/* (C) 2008-2016 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008-2012 by Holger Hans Peter Freyther <zecke@selfish.org>
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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>
#include <regex.h>
#include <sys/types.h>

#include "bscconfig.h"

#include <osmocom/msc/db.h>
#include <osmocom/msc/debug.h>
#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/gsm_subscriber.h>
#include <osmocom/msc/gsm_04_11.h>
#include <osmocom/msc/gsm_04_08.h>
#include <osmocom/msc/gsm_04_80.h>
#include <osmocom/msc/gsm_04_14.h>
#include <osmocom/msc/gsm_09_11.h>
#include <osmocom/msc/signal.h>
#include <osmocom/msc/transaction.h>
#include <osmocom/msc/silent_call.h>
#include <osmocom/msc/mncc_int.h>
#include <osmocom/abis/e1_input.h>
#include <osmocom/core/bitvec.h>
#include <osmocom/msc/vlr.h>
#include <osmocom/msc/msc_ifaces.h>

#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/gsm0480.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/byteswap.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/crypt/auth.h>
#ifdef BUILD_IU
#include <osmocom/ranap/iu_client.h>
#endif

#include <osmocom/msc/msc_ifaces.h>
#include <osmocom/msc/a_iface.h>
#include <osmocom/msc/msc_mgcp.h>

#include <assert.h>


void *tall_locop_ctx;
void *tall_authciphop_ctx;

static int gsm0408_loc_upd_acc(struct ran_conn *conn,
			       uint32_t send_tmsi);

/*! Send a simple GSM 04.08 message without any payload
 * \param      conn      Active RAN connection
 * \param[in]  pdisc     Protocol discriminator
 * \param[in]  msg_type  Message type
 * \return     result of \ref gsm48_conn_sendmsg
 */
int gsm48_tx_simple(struct ran_conn *conn,
		    uint8_t pdisc, uint8_t msg_type)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 TX SIMPLE");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->proto_discr = pdisc;
	gh->msg_type = msg_type;

	return gsm48_conn_sendmsg(msg, conn, NULL);
}

static bool classmark1_is_r99(const struct gsm48_classmark1 *cm1)
{
	return cm1->rev_lev >= 2;
}

static bool classmark2_is_r99(const uint8_t *cm2, uint8_t cm2_len)
{
	uint8_t rev_lev;
	if (!cm2_len)
		return false;
	rev_lev = (cm2[0] >> 5) & 0x3;
	return rev_lev >= 2;
}

static bool classmark_is_r99(struct gsm_classmark *cm)
{
	if (cm->classmark1_set)
		return classmark1_is_r99(&cm->classmark1);
	return classmark2_is_r99(cm->classmark2, cm->classmark2_len);
}

static const char *classmark_a5_name(const struct gsm_classmark *cm)
{
	static char buf[128];
	char cm1[42];
	char cm2[42];
	char cm3[42];

	if (cm->classmark1_set)
		snprintf(cm1, sizeof(cm1), "cm1{a5/1=%s}",
		     cm->classmark1.a5_1 ? "not-supported":"supported" /* inverted logic */);
	else
		snprintf(cm1, sizeof(cm1), "no-cm1");

	if (cm->classmark2_len >= 3)
		snprintf(cm2, sizeof(cm2), " cm2{0x%x=%s%s}",
			 cm->classmark2[2],
			 cm->classmark2[2] & 0x1 ? " A5/2" : "",
			 cm->classmark2[2] & 0x2 ? " A5/3" : "");
	else
		snprintf(cm2, sizeof(cm2), " no-cm2");

	if (cm->classmark3_len >= 1)
		snprintf(cm3, sizeof(cm3), " cm3{0x%x=%s%s%s%s}",
			 cm->classmark3[0],
			 cm->classmark3[0] & (1 << 0) ? " A5/4" : "",
			 cm->classmark3[0] & (1 << 1) ? " A5/5" : "",
			 cm->classmark3[0] & (1 << 2) ? " A5/6" : "",
			 cm->classmark3[0] & (1 << 3) ? " A5/7" : "");
	else
		snprintf(cm3, sizeof(cm3), " no-cm3");

	snprintf(buf, sizeof(buf), "%s%s%s", cm1, cm2, cm3);
	return buf;
}

/* Determine if the given CLASSMARK (1/2/3) value permits a given A5/n cipher.
 * Return 1 when the given A5/n is permitted, 0 when not, and negative if the respective MS CLASSMARK is
 * not known, where the negative number indicates the classmark type: -2 means Classmark 2 is not
 * available. */
static int classmark_supports_a5(const struct gsm_classmark *cm, uint8_t a5)
{
	switch (a5) {
	case 0:
		/* all phones must implement A5/0, see 3GPP TS 43.020 4.9 */
		return 1;
	case 1:
		/* 3GPP TS 43.020 4.9 requires A5/1 to be suppored by all phones and actually states:
		 * "The network shall not provide service to an MS which indicates that it does not
		 *  support the ciphering algorithm A5/1.".  However, let's be more tolerant based
		 * on policy here */
		/* See 3GPP TS 24.008 10.5.1.7 */
		if (!cm->classmark1_set) {
			DEBUGP(DMSC, "CLASSMARK 1 unknown, assuming MS supports A5/1\n");
			return -1;
		} else {
			if (cm->classmark1.a5_1)
				return 0;	/* Inverted logic for this bit! */
			else
				return 1;
		}
		break;
	case 2:
	case 3:
		/* See 3GPP TS 24.008 10.5.1.6 */
		if (cm->classmark2_len < 3) {
			return -2;
		} else {
			if (cm->classmark2[2] & (1 << (a5-2)))
				return 1;
			else
				return 0;
		}
		break;
	case 4:
	case 5:
	case 6:
	case 7:
		/* See 3GPP TS 24.008 10.5.1.7 */
		if (cm->classmark3_len < 1) {
			return -3;
		} else {
			if (cm->classmark3[0] & (1 << (a5-4)))
				return 1;
			else
				return 0;
		}
		break;
	default:
		return false;
	}
}

int gsm48_conn_sendmsg(struct msgb *msg, struct ran_conn *conn, struct gsm_trans *trans)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msg->data;

	/* if we get passed a transaction reference, do some common
	 * work that the caller no longer has to do */
	if (trans) {
		gh->proto_discr = trans->protocol | (trans->transaction_id << 4);
		OMSC_LINKID_CB(msg) = trans->dlci;
	}

	return msc_tx_dtap(conn, msg);
}

/* clear all transactions globally; used in case of MNCC socket disconnect */
void gsm0408_clear_all_trans(struct gsm_network *net, int protocol)
{
	struct gsm_trans *trans, *temp;

	LOGP(DCC, LOGL_NOTICE, "Clearing all currently active transactions!!!\n");

	llist_for_each_entry_safe(trans, temp, &net->trans_list, entry) {
		if (trans->protocol == protocol) {
			trans->callref = 0;
			trans_free(trans);
		}
	}
}

/* Chapter 9.2.14 : Send LOCATION UPDATING REJECT */
static int gsm0408_loc_upd_rej(struct ran_conn *conn, uint8_t cause)
{
	struct msgb *msg;

	msg = gsm48_create_loc_upd_rej(cause);
	if (!msg) {
		LOGP(DMM, LOGL_ERROR, "Failed to create msg for LOCATION UPDATING REJECT.\n");
		return -1;
	}

	LOGP(DMM, LOGL_INFO, "Subscriber %s: LOCATION UPDATING REJECT\n",
	     vlr_subscr_name(conn->vsub));

	return gsm48_conn_sendmsg(msg, conn, NULL);
}

/* Chapter 9.2.13 : Send LOCATION UPDATE ACCEPT */
static int gsm0408_loc_upd_acc(struct ran_conn *conn,
			       uint32_t send_tmsi)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 LOC UPD ACC");
	struct gsm48_hdr *gh;
	struct gsm48_loc_area_id *lai;
	uint8_t *mid;
	struct osmo_location_area_id laid = {
		.plmn = conn->network->plmn,
		.lac = conn->lac,
	};

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_LOC_UPD_ACCEPT;

	lai = (struct gsm48_loc_area_id *) msgb_put(msg, sizeof(*lai));
	gsm48_generate_lai2(lai, &laid);

	if (send_tmsi == GSM_RESERVED_TMSI) {
		/* we did not allocate a TMSI to the MS, so we need to
		 * include the IMSI in order for the MS to delete any
		 * old TMSI that might still be allocated */
		uint8_t mi[10];
		int len;
		len = gsm48_generate_mid_from_imsi(mi, conn->vsub->imsi);
		mid = msgb_put(msg, len);
		memcpy(mid, mi, len);
		DEBUGP(DMM, "-> %s LOCATION UPDATE ACCEPT\n",
		       vlr_subscr_name(conn->vsub));
	} else {
		/* Include the TMSI, which means that the MS will send a
		 * TMSI REALLOCATION COMPLETE, and we should wait for
		 * that until T3250 expiration */
		mid = msgb_put(msg, GSM48_MID_TMSI_LEN);
		gsm48_generate_mid_from_tmsi(mid, send_tmsi);
		DEBUGP(DMM, "-> %s LOCATION UPDATE ACCEPT (TMSI = 0x%08x)\n",
		       vlr_subscr_name(conn->vsub),
		       send_tmsi);
	}
	/* TODO: Follow-on proceed */
	/* TODO: CTS permission */
	/* TODO: Equivalent PLMNs */
	/* TODO: Emergency Number List */
	/* TODO: Per-MS T3312 */


	return gsm48_conn_sendmsg(msg, conn, NULL);
}

/* Transmit Chapter 9.2.10 Identity Request */
static int mm_tx_identity_req(struct ran_conn *conn, uint8_t id_type)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 ID REQ");
	struct gsm48_hdr *gh;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_ID_REQ;
	gh->data[0] = id_type;

	return gsm48_conn_sendmsg(msg, conn, NULL);
}

/* Parse Chapter 9.2.11 Identity Response */
static int mm_rx_id_resp(struct ran_conn *conn, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	uint8_t *mi = gh->data+1;
	uint8_t mi_len = gh->data[0];

	if (!conn->vsub) {
		LOGP(DMM, LOGL_ERROR,
		     "Rx MM Identity Response: invalid: no subscriber\n");
		return -EINVAL;
	}

	DEBUGP(DMM, "IDENTITY RESPONSE: MI=%s\n", osmo_mi_name(mi, mi_len));

	osmo_signal_dispatch(SS_SUBSCR, S_SUBSCR_IDENTITY, gh->data);

	return vlr_subscr_rx_id_resp(conn->vsub, mi, mi_len);
}

/* Chapter 9.2.15: Receive Location Updating Request.
 * Keep this function non-static for direct invocation by unit tests. */
int mm_rx_loc_upd_req(struct ran_conn *conn, struct msgb *msg)
{
	struct gsm_network *net = conn->network;
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm48_loc_upd_req *lu;
	uint8_t mi_type;
	char mi_string[GSM48_MI_SIZE];
	enum vlr_lu_type vlr_lu_type = VLR_LU_TYPE_REGULAR;
	uint32_t tmsi;
	char *imsi;
	struct osmo_location_area_id old_lai, new_lai;
	struct osmo_fsm_inst *lu_fsm;
	bool is_utran;

 	lu = (struct gsm48_loc_upd_req *) gh->data;

	if (ran_conn_is_establishing_auth_ciph(conn)) {
		LOG_RAN_CONN_CAT(conn, DMM, LOGL_ERROR,
				 "Cannot accept another LU, conn already busy establishing authenticity;"
				 " extraneous LOCATION UPDATING REQUEST: MI=%s LU-type=%s\n",
				 osmo_mi_name(lu->mi, lu->mi_len), osmo_lu_type_name(lu->type));
		return -EINVAL;
	}

	if (ran_conn_is_accepted(conn)) {
		LOG_RAN_CONN_CAT(conn, DMM, LOGL_ERROR,
				 "Cannot accept another LU, conn already established;"
				 " extraneous LOCATION UPDATING REQUEST: MI=%s LU-type=%s\n",
				 osmo_mi_name(lu->mi, lu->mi_len), osmo_lu_type_name(lu->type));
		return -EINVAL;
	}

	conn->complete_layer3_type = COMPLETE_LAYER3_LU;
	ran_conn_update_id_from_mi(conn, lu->mi, lu->mi_len);

	LOG_RAN_CONN_CAT(conn, DMM, LOGL_DEBUG, "LOCATION UPDATING REQUEST: MI=%s LU-type=%s\n",
			 osmo_mi_name(lu->mi, lu->mi_len), osmo_lu_type_name(lu->type));

	osmo_signal_dispatch(SS_SUBSCR, S_SUBSCR_IDENTITY, &lu->mi_len);

	switch (lu->type) {
	case GSM48_LUPD_NORMAL:
		rate_ctr_inc(&conn->network->msc_ctrs->ctr[MSC_CTR_LOC_UPDATE_TYPE_NORMAL]);
		vlr_lu_type = VLR_LU_TYPE_REGULAR;
		break;
	case GSM48_LUPD_IMSI_ATT:
		rate_ctr_inc(&conn->network->msc_ctrs->ctr[MSC_CTR_LOC_UPDATE_TYPE_ATTACH]);
		vlr_lu_type = VLR_LU_TYPE_IMSI_ATTACH;
		break;
	case GSM48_LUPD_PERIODIC:
		rate_ctr_inc(&conn->network->msc_ctrs->ctr[MSC_CTR_LOC_UPDATE_TYPE_PERIODIC]);
		vlr_lu_type = VLR_LU_TYPE_PERIODIC;
		break;
	}

	/* TODO: 10.5.1.6 MS Classmark for UMTS / Classmark 2 */
	/* TODO: 10.5.3.14 Aditional update parameters (CS fallback calls) */
	/* TODO: 10.5.7.8 Device properties */
	/* TODO: 10.5.1.15 MS network feature support */

	mi_type = lu->mi[0] & GSM_MI_TYPE_MASK;
	gsm48_mi_to_string(mi_string, sizeof(mi_string), lu->mi, lu->mi_len);
	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
		tmsi = GSM_RESERVED_TMSI;
		imsi = mi_string;
		break;
	case GSM_MI_TYPE_TMSI:
		tmsi = tmsi_from_string(mi_string);
		imsi = NULL;
		break;
	default:
		LOG_RAN_CONN_CAT(conn, DMM, LOGL_ERROR, "unknown mobile identity type\n");
		tmsi = GSM_RESERVED_TMSI;
		imsi = NULL;
		break;
	}

	gsm48_decode_lai2(&lu->lai, &old_lai);
	new_lai.plmn = conn->network->plmn;
	new_lai.lac = conn->lac;
	LOG_RAN_CONN_CAT(conn, DMM, LOGL_DEBUG, "LU/new-LAC: %u/%u\n", old_lai.lac, new_lai.lac);

	is_utran = (conn->via_ran == OSMO_RAT_UTRAN_IU);
	lu_fsm = vlr_loc_update(conn->fi,
				RAN_CONN_E_ACCEPTED, RAN_CONN_E_CN_CLOSE, NULL,
				net->vlr, conn, vlr_lu_type, tmsi, imsi,
				&old_lai, &new_lai,
				is_utran || conn->network->authentication_required,
				is_utran || conn->network->a5_encryption_mask > 0x01,
				lu->key_seq,
				classmark1_is_r99(&lu->classmark1),
				is_utran,
				net->vlr->cfg.assign_tmsi);
	if (!lu_fsm) {
		LOG_RAN_CONN(conn, LOGL_ERROR, "Can't start LU FSM\n");
		return 0;
	}

	/* From vlr_loc_update() we expect an implicit dispatch of
	 * VLR_ULA_E_UPDATE_LA, and thus we expect msc_vlr_subscr_assoc() to
	 * already have been called and completed. Has an error occured? */

	if (!conn->vsub || conn->vsub->lu_fsm != lu_fsm) {
		LOG_RAN_CONN(conn, LOGL_ERROR, "internal error during Location Updating attempt\n");
		return -EIO;
	}

	conn->vsub->classmark.classmark1 = lu->classmark1;
	conn->vsub->classmark.classmark1_set = true;

	ran_conn_complete_layer_3(conn);
	return 0;
}

/* Turn int into semi-octet representation: 98 => 0x89 */
/* FIXME: libosmocore/libosmogsm */
static uint8_t bcdify(uint8_t value)
{
        uint8_t ret;

        ret = value / 10;
        ret |= (value % 10) << 4;

        return ret;
}

/* Generate a message buffer that contains a valid MM info message,
 * See also 3GPP TS 24.008, chapter 9.2.15a */
struct msgb *gsm48_create_mm_info(struct gsm_network *net)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 MM INF");
	struct gsm48_hdr *gh;
	uint8_t *ptr8;
	int name_len, name_pad;

	time_t cur_t;
	struct tm* gmt_time;
	struct tm* local_time;
	int tzunits;
	int dst = 0;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_INFO;

	if (net->name_long) {
#if 0
		name_len = strlen(net->name_long);
		/* 10.5.3.5a */
		ptr8 = msgb_put(msg, 3);
		ptr8[0] = GSM48_IE_NAME_LONG;
		ptr8[1] = name_len*2 +1;
		ptr8[2] = 0x90; /* UCS2, no spare bits, no CI */

		ptr16 = (uint16_t *) msgb_put(msg, name_len*2);
		for (i = 0; i < name_len; i++)
			ptr16[i] = htons(net->name_long[i]);

		/* FIXME: Use Cell Broadcast, not UCS-2, since
		 * UCS-2 is only supported by later revisions of the spec */
#endif
		name_len = (strlen(net->name_long)*7)/8;
		name_pad = (8 - strlen(net->name_long)*7)%8;
		if (name_pad > 0)
			name_len++;
		/* 10.5.3.5a */
		ptr8 = msgb_put(msg, 3);
		ptr8[0] = GSM48_IE_NAME_LONG;
		ptr8[1] = name_len +1;
		ptr8[2] = 0x80 | name_pad; /* Cell Broadcast DCS, no CI */

		ptr8 = msgb_put(msg, name_len);
		gsm_7bit_encode_n(ptr8, name_len, net->name_long, NULL);

	}

	if (net->name_short) {
#if 0
		name_len = strlen(net->name_short);
		/* 10.5.3.5a */
		ptr8 = (uint8_t *) msgb_put(msg, 3);
		ptr8[0] = GSM48_IE_NAME_SHORT;
		ptr8[1] = name_len*2 + 1;
		ptr8[2] = 0x90; /* UCS2, no spare bits, no CI */

		ptr16 = (uint16_t *) msgb_put(msg, name_len*2);
		for (i = 0; i < name_len; i++)
			ptr16[i] = htons(net->name_short[i]);
#endif
		name_len = (strlen(net->name_short)*7)/8;
		name_pad = (8 - strlen(net->name_short)*7)%8;
		if (name_pad > 0)
			name_len++;
		/* 10.5.3.5a */
		ptr8 = (uint8_t *) msgb_put(msg, 3);
		ptr8[0] = GSM48_IE_NAME_SHORT;
		ptr8[1] = name_len +1;
		ptr8[2] = 0x80 | name_pad; /* Cell Broadcast DCS, no CI */

		ptr8 = msgb_put(msg, name_len);
		gsm_7bit_encode_n(ptr8, name_len, net->name_short, NULL);

	}

	/* Section 10.5.3.9 */
	cur_t = time(NULL);
	gmt_time = gmtime(&cur_t);

	ptr8 = msgb_put(msg, 8);
	ptr8[0] = GSM48_IE_NET_TIME_TZ;
	ptr8[1] = bcdify(gmt_time->tm_year % 100);
	ptr8[2] = bcdify(gmt_time->tm_mon + 1);
	ptr8[3] = bcdify(gmt_time->tm_mday);
	ptr8[4] = bcdify(gmt_time->tm_hour);
	ptr8[5] = bcdify(gmt_time->tm_min);
	ptr8[6] = bcdify(gmt_time->tm_sec);

	if (net->tz.override) {
		/* Convert tz.hr and tz.mn to units */
		if (net->tz.hr < 0) {
			tzunits = ((net->tz.hr/-1)*4);
			tzunits = tzunits + (net->tz.mn/15);
			ptr8[7] = bcdify(tzunits);
			/* Set negative time */
			ptr8[7] |= 0x08;
		}
		else {
			tzunits = net->tz.hr*4;
			tzunits = tzunits + (net->tz.mn/15);
			ptr8[7] = bcdify(tzunits);
		}
		/* Convert DST value */
		if (net->tz.dst >= 0 && net->tz.dst <= 2)
			dst = net->tz.dst;
	}
	else {
		/* Need to get GSM offset and convert into 15 min units */
		/* This probably breaks if gmtoff returns a value not evenly divisible by 15? */
#ifdef HAVE_TM_GMTOFF_IN_TM
		local_time = localtime(&cur_t);
		tzunits = (local_time->tm_gmtoff/60)/15;
#else
		/* find timezone offset */
		time_t utc;
		double offsetFromUTC;
		utc = mktime(gmt_time);
		local_time = localtime(&cur_t);
		offsetFromUTC = difftime(cur_t, utc);
		if (local_time->tm_isdst)
			offsetFromUTC += 3600.0;
		tzunits = ((int)offsetFromUTC) / 60 / 15;
#endif
		if (tzunits < 0) {
			tzunits = tzunits/-1;
			ptr8[7] = bcdify(tzunits);
			/* Flip it to negative */
			ptr8[7] |= 0x08;
		}
		else
			ptr8[7] = bcdify(tzunits);

		/* Does not support DST +2 */
		if (local_time->tm_isdst)
			dst = 1;
	}

	if (dst) {
		ptr8 = msgb_put(msg, 3);
		ptr8[0] = GSM48_IE_NET_DST;
		ptr8[1] = 1;
		ptr8[2] = dst;
	}

	return msg;
}

/* Section 9.2.15a */
int gsm48_tx_mm_info(struct ran_conn *conn)
{
	struct gsm_network *net = conn->network;
	struct msgb *msg;

        msg = gsm48_create_mm_info(net);

	LOG_RAN_CONN(conn, LOGL_DEBUG, "Tx MM INFO\n");
	return gsm48_conn_sendmsg(msg, conn, NULL);
}

/*! Send an Authentication Request to MS on the given RAN connection
 * according to 3GPP/ETSI TS 24.008, Section 9.2.2.
 * \param[in] conn  Subscriber connection to send on.
 * \param[in] rand  Random challenge token to send, must be 16 bytes long.
 * \param[in] autn  r99: In case of UMTS mutual authentication, AUTN token to
 * 	send; must be 16 bytes long, or pass NULL for plain GSM auth.
 * \param[in] key_seq  auth tuple's sequence number.
 */
int gsm48_tx_mm_auth_req(struct ran_conn *conn, uint8_t *rand,
			 uint8_t *autn, int key_seq)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 AUTH REQ");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	struct gsm48_auth_req *ar = (struct gsm48_auth_req *) msgb_put(msg, sizeof(*ar));

	DEBUGP(DMM, "Tx AUTH REQ (rand = %s)\n", osmo_hexdump_nospc(rand, 16));
	if (autn)
		DEBUGP(DMM, "   AUTH REQ (autn = %s)\n", osmo_hexdump_nospc(autn, 16));

	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_AUTH_REQ;

	ar->key_seq = key_seq;

	/* 16 bytes RAND parameters */
	osmo_static_assert(sizeof(ar->rand) == 16, sizeof_auth_req_r99_rand);
	if (rand)
		memcpy(ar->rand, rand, 16);


	/* 16 bytes AUTN */
	if (autn)
		msgb_tlv_put(msg, GSM48_IE_AUTN, 16, autn);

	return gsm48_conn_sendmsg(msg, conn, NULL);
}

/* Section 9.2.1 */
int gsm48_tx_mm_auth_rej(struct ran_conn *conn)
{
	DEBUGP(DMM, "-> AUTH REJECT\n");
	return gsm48_tx_simple(conn, GSM48_PDISC_MM, GSM48_MT_MM_AUTH_REJ);
}

static int msc_vlr_tx_cm_serv_acc(void *msc_conn_ref);
static int msc_vlr_tx_cm_serv_rej(void *msc_conn_ref, enum gsm48_reject_value result);

static int cm_serv_reuse_conn(struct ran_conn *conn, const uint8_t *mi_lv)
{
	uint8_t mi_type;
	char mi_string[GSM48_MI_SIZE];
	uint32_t tmsi;

	gsm48_mi_to_string(mi_string, sizeof(mi_string), mi_lv+1, mi_lv[0]);
	mi_type = mi_lv[1] & GSM_MI_TYPE_MASK;

	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
		if (vlr_subscr_matches_imsi(conn->vsub, mi_string))
			goto accept_reuse;
		break;
	case GSM_MI_TYPE_TMSI:
		tmsi = osmo_load32be(mi_lv+2);
		if (vlr_subscr_matches_tmsi(conn->vsub, tmsi))
			goto accept_reuse;
		break;
	case GSM_MI_TYPE_IMEI:
		if (vlr_subscr_matches_imei(conn->vsub, mi_string))
			goto accept_reuse;
		break;
	default:
		break;
	}

	LOGP(DMM, LOGL_ERROR, "%s: CM Service Request with mismatching mobile identity: %s %s\n",
	     vlr_subscr_name(conn->vsub), gsm48_mi_type_name(mi_type), mi_string);
	msc_vlr_tx_cm_serv_rej(conn, GSM48_REJECT_ILLEGAL_MS);
	return -EINVAL;

accept_reuse:
	DEBUGP(DMM, "%s: re-using already accepted connection\n",
	       vlr_subscr_name(conn->vsub));

	if (!conn->received_cm_service_request) {
		conn->received_cm_service_request = true;
		ran_conn_get(conn, RAN_CONN_USE_CM_SERVICE);
	}
	ran_conn_update_id(conn);
	return conn->network->vlr->ops.tx_cm_serv_acc(conn);
}

/*
 * Handle CM Service Requests
 * a) Verify that the packet is long enough to contain the information
 *    we require otherwsie reject with INCORRECT_MESSAGE
 * b) Try to parse the TMSI. If we do not have one reject
 * c) Check that we know the subscriber with the TMSI otherwise reject
 *    with a HLR cause
 * d) Set the subscriber on the conn and accept
 *
 * Keep this function non-static for direct invocation by unit tests.
 */
int gsm48_rx_mm_serv_req(struct ran_conn *conn, struct msgb *msg)
{
	struct gsm_network *net = conn->network;
	uint8_t mi_type;
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm48_service_request *req =
			(struct gsm48_service_request *)gh->data;
	/* unfortunately in Phase1 the classmark2 length is variable */
	uint8_t classmark2_len = gh->data[1];
	uint8_t *classmark2 = gh->data+2;
	uint8_t *mi_p = classmark2 + classmark2_len;
	uint8_t mi_len = *mi_p;
	uint8_t *mi = mi_p + 1;
	struct osmo_location_area_id lai;
	bool is_utran;

	lai.plmn = conn->network->plmn;
	lai.lac = conn->lac;

	if (msg->data_len < sizeof(struct gsm48_service_request*)) {
		LOG_RAN_CONN(conn, LOGL_ERROR, "Rx CM SERVICE REQUEST: wrong message size (%u < %zu)\n",
			     msg->data_len, sizeof(struct gsm48_service_request*));
		return msc_gsm48_tx_mm_serv_rej(conn,
						GSM48_REJECT_INCORRECT_MESSAGE);
	}

	if (msg->data_len < req->mi_len + 6) {
		LOG_RAN_CONN(conn, LOGL_ERROR, "Rx CM SERVICE REQUEST: message does not fit in packet\n");
		return msc_gsm48_tx_mm_serv_rej(conn,
						GSM48_REJECT_INCORRECT_MESSAGE);
	}

	if (ran_conn_is_establishing_auth_ciph(conn)) {
		LOG_RAN_CONN(conn, LOGL_ERROR,
		     "Cannot accept CM Service Request, conn already busy establishing authenticity\n");
		msc_vlr_tx_cm_serv_rej(conn, GSM48_REJECT_CONGESTION);
		return -EINVAL;
		/* or should we accept and note down the service request anyway? */
	}

	conn->complete_layer3_type = COMPLETE_LAYER3_CM_SERVICE_REQ;
	ran_conn_update_id_from_mi(conn, mi, mi_len);
	LOG_RAN_CONN_CAT(conn, DMM, LOGL_DEBUG, "Rx CM SERVICE REQUEST cm_service_type=0x%02x\n",
			 req->cm_service_type);

	mi_type = (mi && mi_len) ? (mi[0] & GSM_MI_TYPE_MASK) : GSM_MI_TYPE_NONE;
	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
	case GSM_MI_TYPE_TMSI:
		/* continue below */
		break;
	case GSM_MI_TYPE_IMEI:
		if (req->cm_service_type == GSM48_CMSERV_EMERGENCY) {
			/* We don't do emergency calls by IMEI */
			LOG_RAN_CONN(conn, LOGL_NOTICE, "Tx CM SERVICE REQUEST REJECT\n");
			return msc_gsm48_tx_mm_serv_rej(conn, GSM48_REJECT_IMEI_NOT_ACCEPTED);
		}
		/* fall-through for non-emergency setup */
	default:
		LOG_RAN_CONN(conn, LOGL_ERROR, "MI type is not expected: %s\n", gsm48_mi_type_name(mi_type));
		return msc_gsm48_tx_mm_serv_rej(conn,
						GSM48_REJECT_INCORRECT_MESSAGE);
	}

	switch (req->cm_service_type) {
	case GSM48_CMSERV_MO_CALL_PACKET:
	case GSM48_CMSERV_EMERGENCY:
	case GSM48_CMSERV_SMS:
	case GSM48_CMSERV_SUP_SERV:
		/* continue below */
		break;
	default:
		return msc_gsm48_tx_mm_serv_rej(conn, GSM48_REJECT_SRV_OPT_NOT_SUPPORTED);
	}

	if (ran_conn_is_accepted(conn))
		return cm_serv_reuse_conn(conn, mi_p);

	osmo_signal_dispatch(SS_SUBSCR, S_SUBSCR_IDENTITY, mi_p);

	is_utran = (conn->via_ran == OSMO_RAT_UTRAN_IU);
	vlr_proc_acc_req(conn->fi,
			 RAN_CONN_E_ACCEPTED, RAN_CONN_E_CN_CLOSE, NULL,
			 net->vlr, conn,
			 VLR_PR_ARQ_T_CM_SERV_REQ, mi-1, &lai,
			 is_utran || conn->network->authentication_required,
			 is_utran || conn->network->a5_encryption_mask > 0x01,
			 req->cipher_key_seq,
			 classmark2_is_r99(classmark2, classmark2_len),
			 is_utran);

	/* From vlr_proc_acc_req() we expect an implicit dispatch of PR_ARQ_E_START we expect
	 * msc_vlr_subscr_assoc() to already have been called and completed. Has an error occured? */
	if (!conn->vsub) {
		LOG_RAN_CONN(conn, LOGL_ERROR, "subscriber not allowed to do a CM Service Request\n");
		return -EIO;
	}

	memcpy(conn->vsub->classmark.classmark2, classmark2, classmark2_len);
	conn->vsub->classmark.classmark2_len = classmark2_len;

	ran_conn_complete_layer_3(conn);
	return 0;
}

/* Receive a CM Re-establish Request */
static int gsm48_rx_cm_reest_req(struct ran_conn *conn, struct msgb *msg)
{
	uint8_t mi_type;
	char mi_string[GSM48_MI_SIZE];
	struct gsm48_hdr *gh = msgb_l3(msg);

	uint8_t classmark2_len = gh->data[1];
	uint8_t *classmark2 = gh->data+2;
	uint8_t mi_len = *(classmark2 + classmark2_len);
	uint8_t *mi = (classmark2 + classmark2_len + 1);

	gsm48_mi_to_string(mi_string, sizeof(mi_string), mi, mi_len);
	mi_type = mi[0] & GSM_MI_TYPE_MASK;
	DEBUGP(DMM, "<- CM RE-ESTABLISH REQUEST MI(%s)=%s\n", gsm48_mi_type_name(mi_type), mi_string);

	/* we don't support CM call re-establishment */
	return msc_gsm48_tx_mm_serv_rej(conn, GSM48_REJECT_SRV_OPT_NOT_SUPPORTED);
}

static int gsm48_rx_mm_imsi_detach_ind(struct ran_conn *conn, struct msgb *msg)
{
	struct gsm_network *network = conn->network;
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm48_imsi_detach_ind *idi =
				(struct gsm48_imsi_detach_ind *) gh->data;
	uint8_t mi_type = idi->mi[0] & GSM_MI_TYPE_MASK;
	char mi_string[GSM48_MI_SIZE];
	struct vlr_subscr *vsub = NULL;

	gsm48_mi_to_string(mi_string, sizeof(mi_string), idi->mi, idi->mi_len);
	DEBUGP(DMM, "IMSI DETACH INDICATION: MI(%s)=%s\n",
	       gsm48_mi_type_name(mi_type), mi_string);

	rate_ctr_inc(&network->msc_ctrs->ctr[MSC_CTR_LOC_UPDATE_TYPE_DETACH]);

	switch (mi_type) {
	case GSM_MI_TYPE_TMSI:
		vsub = vlr_subscr_find_by_tmsi(network->vlr,
					       tmsi_from_string(mi_string), __func__);
		break;
	case GSM_MI_TYPE_IMSI:
		vsub = vlr_subscr_find_by_imsi(network->vlr, mi_string, __func__);
		break;
	case GSM_MI_TYPE_IMEI:
	case GSM_MI_TYPE_IMEISV:
		/* no sim card... FIXME: what to do ? */
		LOGP(DMM, LOGL_ERROR, "MI(%s)=%s: unimplemented mobile identity type\n",
		     gsm48_mi_type_name(mi_type), mi_string);
		break;
	default:
		LOGP(DMM, LOGL_ERROR, "MI(%s)=%s: unknown mobile identity type\n",
		     gsm48_mi_type_name(mi_type), mi_string);
		break;
	}

	if (!vsub) {
		LOGP(DMM, LOGL_ERROR, "IMSI DETACH for unknown subscriber MI(%s)=%s\n",
		     gsm48_mi_type_name(mi_type), mi_string);
	} else {
		LOGP(DMM, LOGL_INFO, "IMSI DETACH for %s\n", vlr_subscr_name(vsub));

		if (vsub->cs.is_paging)
			subscr_paging_cancel(vsub, GSM_PAGING_EXPIRED);

		/* We already got Classmark 1 during Location Updating ... but well, ok */
		vsub->classmark.classmark1 = idi->classmark1;

		vlr_subscr_rx_imsi_detach(vsub);
		osmo_signal_dispatch(SS_SUBSCR, S_SUBSCR_DETACHED, vsub);
		vlr_subscr_put(vsub, __func__);
	}

	ran_conn_close(conn, 0);
	return 0;
}

static int gsm48_rx_mm_status(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);

	DEBUGP(DMM, "MM STATUS (reject cause 0x%02x)\n", gh->data[0]);

	return 0;
}

static int parse_gsm_auth_resp(uint8_t *res, uint8_t *res_len,
			       struct ran_conn *conn,
			       struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm48_auth_resp *ar = (struct gsm48_auth_resp*) gh->data;

	if (msgb_l3len(msg) < sizeof(*gh) + sizeof(*ar)) {
		LOGP(DMM, LOGL_ERROR,
		     "%s: MM AUTHENTICATION RESPONSE:"
		     " l3 length invalid: %u\n",
		     vlr_subscr_name(conn->vsub), msgb_l3len(msg));
		return -EINVAL;
	}

	*res_len = sizeof(ar->sres);
	memcpy(res, ar->sres, sizeof(ar->sres));
	return 0;
}

static int parse_umts_auth_resp(uint8_t *res, uint8_t *res_len,
				struct ran_conn *conn,
				struct msgb *msg)
{
	struct gsm48_hdr *gh;
	uint8_t *data;
	uint8_t iei;
	uint8_t ie_len;
	unsigned int data_len;

	/* First parse the GSM part */
	if (parse_gsm_auth_resp(res, res_len, conn, msg))
		return -EINVAL;
	OSMO_ASSERT(*res_len == 4);

	/* Then add the extended res part */
	gh = msgb_l3(msg);
	data = gh->data + sizeof(struct gsm48_auth_resp);
	data_len = msgb_l3len(msg) - (data - (uint8_t*)msgb_l3(msg));

	if (data_len < 3) {
		LOGP(DMM, LOGL_ERROR,
		     "%s: MM AUTHENTICATION RESPONSE:"
		     " l3 length invalid: %u\n",
		     vlr_subscr_name(conn->vsub), msgb_l3len(msg));
		return -EINVAL;
	}

	iei = data[0];
	ie_len = data[1];
	if (iei != GSM48_IE_AUTH_RES_EXT) {
		LOGP(DMM, LOGL_ERROR,
		     "%s: MM R99 AUTHENTICATION RESPONSE:"
		     " expected IEI 0x%02x, got 0x%02x\n",
		     vlr_subscr_name(conn->vsub),
		     GSM48_IE_AUTH_RES_EXT, iei);
		return -EINVAL;
	}

	if (ie_len > 12) {
		LOGP(DMM, LOGL_ERROR,
		     "%s: MM R99 AUTHENTICATION RESPONSE:"
		     " extended Auth Resp IE 0x%02x is too large: %u bytes\n",
		     vlr_subscr_name(conn->vsub), GSM48_IE_AUTH_RES_EXT, ie_len);
		return -EINVAL;
	}

	*res_len += ie_len;
	memcpy(res + 4, &data[2], ie_len);
	return 0;
}

/* Chapter 9.2.3: Authentication Response */
static int gsm48_rx_mm_auth_resp(struct ran_conn *conn, struct msgb *msg)
{
	uint8_t res[16];
	uint8_t res_len;
	int rc;
	bool is_umts;

	if (!conn->vsub) {
		LOGP(DMM, LOGL_ERROR,
		     "MM AUTHENTICATION RESPONSE: invalid: no subscriber\n");
		ran_conn_close(conn, GSM_CAUSE_AUTH_FAILED);
		return -EINVAL;
	}

	is_umts = (msgb_l3len(msg) > sizeof(struct gsm48_hdr) + sizeof(struct gsm48_auth_resp));

	if (is_umts)
		rc = parse_umts_auth_resp(res, &res_len, conn, msg);
	else
		rc = parse_gsm_auth_resp(res, &res_len, conn, msg);

	if (rc) {
		LOGP(DMM, LOGL_ERROR,
		     "%s: MM AUTHENTICATION RESPONSE: invalid: parsing %s AKA Auth Response"
		     " failed with rc=%d; dispatching zero length SRES/RES to trigger failure\n",
		     vlr_subscr_name(conn->vsub), is_umts ? "UMTS" : "GSM", rc);
		memset(res, 0, sizeof(res));
		res_len = 0;
	}

	DEBUGP(DMM, "%s: MM %s AUTHENTICATION RESPONSE (%s = %s)\n",
	       vlr_subscr_name(conn->vsub),
	       is_umts ? "UMTS" : "GSM", is_umts ? "res" : "sres",
	       osmo_hexdump_nospc(res, res_len));

	return vlr_subscr_rx_auth_resp(conn->vsub, classmark_is_r99(&conn->vsub->classmark),
				       conn->via_ran == OSMO_RAT_UTRAN_IU,
				       res, res_len);
}

static int gsm48_rx_mm_auth_fail(struct ran_conn *conn, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	uint8_t cause;
	uint8_t auts_tag;
	uint8_t auts_len;
	uint8_t *auts;

	if (!conn->vsub) {
		LOGP(DMM, LOGL_ERROR,
		     "MM R99 AUTHENTICATION FAILURE: invalid: no subscriber\n");
		ran_conn_close(conn, GSM_CAUSE_AUTH_FAILED);
		return -EINVAL;
	}

	if (msgb_l3len(msg) < sizeof(*gh) + 1) {
		LOGP(DMM, LOGL_ERROR,
		     "%s: MM R99 AUTHENTICATION FAILURE:"
		     " l3 length invalid: %u\n",
		     vlr_subscr_name(conn->vsub), msgb_l3len(msg));
		ran_conn_close(conn, GSM_CAUSE_AUTH_FAILED);
		return -EINVAL;
	}

	cause = gh->data[0];

	if (cause != GSM48_REJECT_SYNCH_FAILURE) {
		LOGP(DMM, LOGL_INFO,
		     "%s: MM R99 AUTHENTICATION FAILURE: cause 0x%0x\n",
		     vlr_subscr_name(conn->vsub), cause);
		vlr_subscr_rx_auth_fail(conn->vsub, NULL);
		return 0;
	}

	/* This is a Synch Failure procedure, which should pass an AUTS to
	 * resynchronize the sequence nr with the HLR. Expecting exactly one
	 * TLV with 14 bytes of AUTS. */

	if (msgb_l3len(msg) < sizeof(*gh) + 1 + 2) {
		LOGP(DMM, LOGL_INFO,
		     "%s: MM R99 AUTHENTICATION FAILURE:"
		     " invalid Synch Failure: missing AUTS IE\n",
		     vlr_subscr_name(conn->vsub));
		ran_conn_close(conn, GSM_CAUSE_AUTH_FAILED);
		return -EINVAL;
	}

	auts_tag = gh->data[1];
	auts_len = gh->data[2];
	auts = &gh->data[3];

	if (auts_tag != GSM48_IE_AUTS
	    || auts_len != 14) {
		LOGP(DMM, LOGL_INFO,
		     "%s: MM R99 AUTHENTICATION FAILURE:"
		     " invalid Synch Failure:"
		     " expected AUTS IE 0x%02x of 14 bytes,"
		     " got IE 0x%02x of %u bytes\n",
		     vlr_subscr_name(conn->vsub),
		     GSM48_IE_AUTS, auts_tag, auts_len);
		ran_conn_close(conn, GSM_CAUSE_AUTH_FAILED);
		return -EINVAL;
	}

	if (msgb_l3len(msg) < sizeof(*gh) + 1 + 2 + auts_len) {
		LOGP(DMM, LOGL_INFO,
		     "%s: MM R99 AUTHENTICATION FAILURE:"
		     " invalid Synch Failure msg: message truncated (%u)\n",
		     vlr_subscr_name(conn->vsub), msgb_l3len(msg));
		ran_conn_close(conn, GSM_CAUSE_AUTH_FAILED);
		return -EINVAL;
	}

	/* We have an AUTS IE with exactly 14 bytes of AUTS and the msgb is
	 * large enough. */

	DEBUGP(DMM, "%s: MM R99 AUTHENTICATION SYNCH (AUTS = %s)\n",
	       vlr_subscr_name(conn->vsub), osmo_hexdump_nospc(auts, 14));

	return vlr_subscr_rx_auth_fail(conn->vsub, auts);
}

static int gsm48_rx_mm_tmsi_reall_compl(struct ran_conn *conn)
{
	DEBUGP(DMM, "TMSI Reallocation Completed. Subscriber: %s\n",
	       vlr_subscr_name(conn->vsub));
	if (!conn->vsub) {
		LOGP(DMM, LOGL_ERROR,
		     "Rx MM TMSI Reallocation Complete: invalid: no subscriber\n");
		return -EINVAL;
	}
	return vlr_subscr_rx_tmsi_reall_compl(conn->vsub);
}

/* Receive a GSM 04.08 Mobility Management (MM) message */
static int gsm0408_rcv_mm(struct ran_conn *conn, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	int rc = 0;

	switch (gsm48_hdr_msg_type(gh)) {
	case GSM48_MT_MM_LOC_UPD_REQUEST:
		rc = mm_rx_loc_upd_req(conn, msg);
		break;
	case GSM48_MT_MM_ID_RESP:
		rc = mm_rx_id_resp(conn, msg);
		break;
	case GSM48_MT_MM_CM_SERV_REQ:
		rc = gsm48_rx_mm_serv_req(conn, msg);
		break;
	case GSM48_MT_MM_STATUS:
		rc = gsm48_rx_mm_status(msg);
		break;
	case GSM48_MT_MM_TMSI_REALL_COMPL:
		rc = gsm48_rx_mm_tmsi_reall_compl(conn);
		break;
	case GSM48_MT_MM_IMSI_DETACH_IND:
		rc = gsm48_rx_mm_imsi_detach_ind(conn, msg);
		break;
	case GSM48_MT_MM_CM_REEST_REQ:
		rc = gsm48_rx_cm_reest_req(conn, msg);
		break;
	case GSM48_MT_MM_AUTH_RESP:
		rc = gsm48_rx_mm_auth_resp(conn, msg);
		break;
	case GSM48_MT_MM_AUTH_FAIL:
		rc = gsm48_rx_mm_auth_fail(conn, msg);
		break;
	default:
		LOGP(DMM, LOGL_NOTICE, "Unknown GSM 04.08 MM msg type 0x%02x\n",
			gh->msg_type);
		break;
	}

	return rc;
}

/* Receive a PAGING RESPONSE message from the MS */
static int gsm48_rx_rr_pag_resp(struct ran_conn *conn, struct msgb *msg)
{
	struct gsm_network *net = conn->network;
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm48_pag_resp *pr =
			(struct gsm48_pag_resp *)gh->data;
	uint8_t classmark2_len = gh->data[1];
	uint8_t *classmark2 = gh->data+2;
	uint8_t *mi_lv = classmark2 + classmark2_len;
	struct osmo_location_area_id lai;
	bool is_utran;

	lai.plmn = conn->network->plmn;
	lai.lac = conn->lac;

	if (ran_conn_is_establishing_auth_ciph(conn)) {
		LOGP(DMM, LOGL_ERROR,
		     "Ignoring Paging Response, conn already busy establishing authenticity\n");
		return 0;
	}

	if (ran_conn_is_accepted(conn)) {
		LOGP(DMM, LOGL_ERROR, "Ignoring Paging Response, conn already established\n");
		return 0;
	}

	conn->complete_layer3_type = COMPLETE_LAYER3_PAGING_RESP;
	ran_conn_update_id_from_mi(conn, mi_lv + 1, *mi_lv);
	LOG_RAN_CONN_CAT(conn, DRR, LOGL_DEBUG, "PAGING RESPONSE\n");

	is_utran = (conn->via_ran == OSMO_RAT_UTRAN_IU);
	vlr_proc_acc_req(conn->fi,
			 RAN_CONN_E_ACCEPTED, RAN_CONN_E_CN_CLOSE, NULL,
			 net->vlr, conn,
			 VLR_PR_ARQ_T_PAGING_RESP, mi_lv, &lai,
			 is_utran || conn->network->authentication_required,
			 is_utran || conn->network->a5_encryption_mask > 0x01,
			 pr->key_seq,
			 classmark2_is_r99(classmark2, classmark2_len),
			 is_utran);

	/* From vlr_proc_acc_req() we expect an implicit dispatch of PR_ARQ_E_START we expect
	 * msc_vlr_subscr_assoc() to already have been called and completed. Has an error occured? */
	if (!conn->vsub) {
		LOG_RAN_CONN(conn, LOGL_ERROR, "subscriber not allowed to do a Paging Response\n");
		return -EIO;
	}

	memcpy(conn->vsub->classmark.classmark2, classmark2, classmark2_len);
	conn->vsub->classmark.classmark2_len = classmark2_len;

	ran_conn_complete_layer_3(conn);
	return 0;
}

static int gsm48_rx_rr_app_info(struct ran_conn *conn, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	uint8_t apdu_id_flags;
	uint8_t apdu_len;
	uint8_t *apdu_data;

	apdu_id_flags = gh->data[0];
	apdu_len = gh->data[1];
	apdu_data = gh->data+2;

	DEBUGP(DRR, "RX APPLICATION INFO id/flags=0x%02x apdu_len=%u apdu=%s\n",
		apdu_id_flags, apdu_len, osmo_hexdump(apdu_data, apdu_len));

	/* we're not using the app info blob anywhere, so ignore. */
#if 0
	return db_apdu_blob_store(conn->subscr, apdu_id_flags, apdu_len, apdu_data);
#else
	return 0;
#endif
}

/* Receive a GSM 04.08 Radio Resource (RR) message */
static int gsm0408_rcv_rr(struct ran_conn *conn, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	int rc = 0;

	switch (gh->msg_type) {
	case GSM48_MT_RR_PAG_RESP:
		rc = gsm48_rx_rr_pag_resp(conn, msg);
		break;
	case GSM48_MT_RR_APP_INFO:
		rc = gsm48_rx_rr_app_info(conn, msg);
		break;
	default:
		LOGP(DRR, LOGL_NOTICE, "MSC: Unimplemented %s GSM 04.08 RR "
		     "message\n", gsm48_rr_msg_name(gh->msg_type));
		break;
	}

	return rc;
}

int gsm48_send_rr_app_info(struct ran_conn *conn, uint8_t apdu_id,
			   uint8_t apdu_len, const uint8_t *apdu)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 APP INF");
	struct gsm48_hdr *gh;

	DEBUGP(DRR, "TX APPLICATION INFO id=0x%02x, len=%u\n",
		apdu_id, apdu_len);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 2 + apdu_len);
	gh->proto_discr = GSM48_PDISC_RR;
	gh->msg_type = GSM48_MT_RR_APP_INFO;
	gh->data[0] = apdu_id;
	gh->data[1] = apdu_len;
	memcpy(gh->data+2, apdu, apdu_len);

	return gsm48_conn_sendmsg(msg, conn, NULL);
}

static bool msg_is_initially_permitted(const struct gsm48_hdr *hdr)
{
	uint8_t pdisc = gsm48_hdr_pdisc(hdr);
	uint8_t msg_type = gsm48_hdr_msg_type(hdr);

	switch (pdisc) {
	case GSM48_PDISC_MM:
		switch (msg_type) {
		case GSM48_MT_MM_LOC_UPD_REQUEST:
		case GSM48_MT_MM_CM_SERV_REQ:
		case GSM48_MT_MM_CM_REEST_REQ:
		case GSM48_MT_MM_AUTH_RESP:
		case GSM48_MT_MM_AUTH_FAIL:
		case GSM48_MT_MM_ID_RESP:
		case GSM48_MT_MM_TMSI_REALL_COMPL:
		case GSM48_MT_MM_IMSI_DETACH_IND:
			return true;
		default:
			break;
		}
		break;
	case GSM48_PDISC_RR:
		switch (msg_type) {
		/* GSM48_MT_RR_CIPH_M_COMPL is actually handled in bssmap_rx_ciph_compl() and gets redirected in the
		 * BSSAP layer to ran_conn_cipher_mode_compl() (before this here is reached) */
		case GSM48_MT_RR_PAG_RESP:
			return true;
		default:
			break;
		}
		break;
	default:
		break;
	}

	return false;
}

void cm_service_request_concludes(struct ran_conn *conn,
				  struct msgb *msg)
{

	/* If a CM Service Request was received before, this is the request the
	 * conn was opened for. No need to wait for further messages. */

	if (!conn->received_cm_service_request)
		return;

	if (log_check_level(DMM, LOGL_DEBUG)) {
		struct gsm48_hdr *gh = msgb_l3(msg);
		uint8_t pdisc = gsm48_hdr_pdisc(gh);
		uint8_t msg_type = gsm48_hdr_msg_type(gh);

		DEBUGP(DMM, "%s: rx msg %s:"
		       " received_cm_service_request changes to false\n",
		       vlr_subscr_name(conn->vsub),
		       gsm48_pdisc_msgtype_name(pdisc, msg_type));
	}
	conn->received_cm_service_request = false;
	ran_conn_put(conn, RAN_CONN_USE_CM_SERVICE);
}

/* TS 24.007 11.2.3.2.3 Message Type Octet / Duplicate Detection */
int gsm0407_pdisc_ctr_bin(uint8_t pdisc)
{
	switch (pdisc) {
	case GSM48_PDISC_MM:
	case GSM48_PDISC_CC:
	case GSM48_PDISC_NC_SS:
		return 0;
	case GSM48_PDISC_GROUP_CC:
		return 1;
	case GSM48_PDISC_BCAST_CC:
		return 2;
	case GSM48_PDISC_LOC:
		return 3;
	default:
		return -1;
	}
}

/* extract the N(SD) and return the modulo value for a R98 message */
static uint8_t gsm0407_determine_nsd_ret_modulo_r99(uint8_t pdisc, uint8_t msg_type, uint8_t *n_sd)
{
	switch (pdisc) {
	case GSM48_PDISC_MM:
	case GSM48_PDISC_CC:
	case GSM48_PDISC_NC_SS:
		*n_sd = (msg_type >> 6) & 0x3;
		return 4;
	case GSM48_PDISC_GROUP_CC:
	case GSM48_PDISC_BCAST_CC:
	case GSM48_PDISC_LOC:
		*n_sd = (msg_type >> 6) & 0x1;
		return 2;
	default:
		/* no sequence number, we cannot detect dups */
		return 0;
	}
}

/* extract the N(SD) and return the modulo value for a R99 message */
static uint8_t gsm0407_determine_nsd_ret_modulo_r98(uint8_t pdisc, uint8_t msg_type, uint8_t *n_sd)
{
	switch (pdisc) {
	case GSM48_PDISC_MM:
	case GSM48_PDISC_CC:
	case GSM48_PDISC_NC_SS:
	case GSM48_PDISC_GROUP_CC:
	case GSM48_PDISC_BCAST_CC:
	case GSM48_PDISC_LOC:
		*n_sd = (msg_type >> 6) & 0x1;
		return 2;
	default:
		/* no sequence number, we cannot detect dups */
		return 0;
	}
}

/* TS 24.007 11.2.3.2 Message Type Octet / Duplicate Detection */
static bool gsm0407_is_duplicate(struct ran_conn *conn, struct msgb *msg)
{
	struct gsm48_hdr *gh;
	uint8_t pdisc;
	uint8_t n_sd, modulo;
	int bin;

	gh = msgb_l3(msg);
	pdisc = gsm48_hdr_pdisc(gh);

	if (conn->vsub && classmark_is_r99(&conn->vsub->classmark)) {
		modulo = gsm0407_determine_nsd_ret_modulo_r99(pdisc, gh->msg_type, &n_sd);
	} else { /* pre R99 */
		modulo = gsm0407_determine_nsd_ret_modulo_r98(pdisc, gh->msg_type, &n_sd);
	}
	if (modulo == 0)
		return false;
	bin = gsm0407_pdisc_ctr_bin(pdisc);
	if (bin < 0)
		return false;

	OSMO_ASSERT(bin < ARRAY_SIZE(conn->n_sd_next));
	if (n_sd != conn->n_sd_next[bin]) {
		/* not what we expected: duplicate */
		return true;
	} else {
		/* as expected: no dup; update expected counter for next message */
		conn->n_sd_next[bin] = (n_sd + 1) % modulo;
		return false;
	}
}

extern int gsm0408_rcv_cc(struct ran_conn *conn, struct msgb *msg);

/* Main entry point for GSM 04.08/44.008 Layer 3 data (e.g. from the BSC). */
int gsm0408_dispatch(struct ran_conn *conn, struct msgb *msg)
{
	struct gsm48_hdr *gh;
	uint8_t pdisc;
	int rc = 0;

	OSMO_ASSERT(msg->l3h);
	OSMO_ASSERT(conn);
	OSMO_ASSERT(msg);

	gh = msgb_l3(msg);
	pdisc = gsm48_hdr_pdisc(gh);

	if (gsm0407_is_duplicate(conn, msg)) {
		LOGP(DRLL, LOGL_NOTICE, "%s: Discarding duplicate L3 message\n",
			(conn && conn->vsub) ? vlr_subscr_name(conn->vsub) : "UNKNOWN");
		return 0;
	}

	LOGP(DRLL, LOGL_DEBUG, "Dispatching 04.08 message %s (0x%x:0x%x)\n",
	     gsm48_pdisc_msgtype_name(pdisc, gsm48_hdr_msg_type(gh)),
	     pdisc, gsm48_hdr_msg_type(gh));

	if (!ran_conn_is_accepted(conn)
	    && !msg_is_initially_permitted(gh)) {
		LOGP(DRLL, LOGL_ERROR,
		     "subscr %s: Message not permitted for initial conn: %s\n",
		     vlr_subscr_name(conn->vsub),
		     gsm48_pdisc_msgtype_name(pdisc, gsm48_hdr_msg_type(gh)));
		return -EACCES;
	}

	if (conn->vsub && conn->vsub->cs.attached_via_ran != conn->via_ran) {
		LOGP(DMM, LOGL_ERROR,
		     "%s: Illegal situation: RAN type mismatch:"
		     " attached via %s, received message via %s\n",
		     vlr_subscr_name(conn->vsub),
		     osmo_rat_type_name(conn->vsub->cs.attached_via_ran),
		     osmo_rat_type_name(conn->via_ran));
		return -EACCES;
	}

#if 0
	if (silent_call_reroute(conn, msg))
		return silent_call_rx(conn, msg);
#endif

	switch (pdisc) {
	case GSM48_PDISC_CC:
		rc = gsm0408_rcv_cc(conn, msg);
		break;
	case GSM48_PDISC_MM:
		rc = gsm0408_rcv_mm(conn, msg);
		break;
	case GSM48_PDISC_RR:
		rc = gsm0408_rcv_rr(conn, msg);
		break;
	case GSM48_PDISC_SMS:
		rc = gsm0411_rcv_sms(conn, msg);
		break;
	case GSM48_PDISC_MM_GPRS:
	case GSM48_PDISC_SM_GPRS:
		LOGP(DRLL, LOGL_NOTICE, "Unimplemented "
			"GSM 04.08 discriminator 0x%02x\n", pdisc);
		rc = -ENOTSUP;
		break;
	case GSM48_PDISC_NC_SS:
		rc = gsm0911_rcv_nc_ss(conn, msg);
		break;
	case GSM48_PDISC_TEST:
		rc = gsm0414_rcv_test(conn, msg);
		break;
	default:
		LOGP(DRLL, LOGL_NOTICE, "Unknown "
			"GSM 04.08 discriminator 0x%02x\n", pdisc);
		rc = -EINVAL;
		break;
	}

	return rc;
}

/***********************************************************************
 * VLR integration
 ***********************************************************************/

/* VLR asks us to send an authentication request */
static int msc_vlr_tx_auth_req(void *msc_conn_ref, struct vlr_auth_tuple *at,
			       bool send_autn)
{
	struct ran_conn *conn = msc_conn_ref;
	return gsm48_tx_mm_auth_req(conn, at->vec.rand,
				    send_autn? at->vec.autn : NULL,
				    at->key_seq);
}

/* VLR asks us to send an authentication reject */
static int msc_vlr_tx_auth_rej(void *msc_conn_ref)
{
	struct ran_conn *conn = msc_conn_ref;
	return gsm48_tx_mm_auth_rej(conn);
}

/* VLR asks us to transmit an Identity Request of given type */
static int msc_vlr_tx_id_req(void *msc_conn_ref, uint8_t mi_type)
{
	struct ran_conn *conn = msc_conn_ref;
	return mm_tx_identity_req(conn, mi_type);
}

/* VLR asks us to transmit a Location Update Accept */
static int msc_vlr_tx_lu_acc(void *msc_conn_ref, uint32_t send_tmsi)
{
	struct ran_conn *conn = msc_conn_ref;
	return gsm0408_loc_upd_acc(conn, send_tmsi);
}

/* VLR asks us to transmit a Location Update Reject */
static int msc_vlr_tx_lu_rej(void *msc_conn_ref, enum gsm48_reject_value cause)
{
	struct ran_conn *conn = msc_conn_ref;
	return gsm0408_loc_upd_rej(conn, cause);
}

/* VLR asks us to transmit a CM Service Accept */
static int msc_vlr_tx_cm_serv_acc(void *msc_conn_ref)
{
	struct ran_conn *conn = msc_conn_ref;
	return msc_gsm48_tx_mm_serv_ack(conn);
}

static int msc_vlr_tx_common_id(void *msc_conn_ref)
{
	struct ran_conn *conn = msc_conn_ref;
	return msc_tx_common_id(conn);
}

/* VLR asks us to transmit MM info. */
static int msc_vlr_tx_mm_info(void *msc_conn_ref)
{
	struct ran_conn *conn = msc_conn_ref;
	if (!conn->network->send_mm_info)
		return 0;
	return gsm48_tx_mm_info(conn);
}

/* VLR asks us to transmit a CM Service Reject */
static int msc_vlr_tx_cm_serv_rej(void *msc_conn_ref, enum gsm48_reject_value cause)
{
	struct ran_conn *conn = msc_conn_ref;
	int rc;

	rc = msc_gsm48_tx_mm_serv_rej(conn, cause);

	if (conn->received_cm_service_request) {
		conn->received_cm_service_request = false;
		ran_conn_put(conn, RAN_CONN_USE_CM_SERVICE);
	}

	return rc;
}

/* For msc_vlr_set_ciph_mode() */
osmo_static_assert(sizeof(((struct gsm0808_encrypt_info*)0)->key) >= sizeof(((struct osmo_auth_vector*)0)->kc),
		   gsm0808_encrypt_info_key_fits_osmo_auth_vec_kc);

int ran_conn_geran_set_cipher_mode(struct ran_conn *conn, bool umts_aka, bool retrieve_imeisv)
{
	struct gsm_network *net;
	struct gsm0808_encrypt_info ei;
	int i, j = 0;
	int request_classmark = 0;
	int request_classmark_for_a5_n = 0;
	struct vlr_auth_tuple *tuple;

	if (!conn || !conn->vsub || !conn->vsub->last_tuple) {
		/* This should really never happen, because we checked this in msc_vlr_set_ciph_mode()
		 * already. */
		LOGP(DMM, LOGL_ERROR, "Internal error: missing state during Ciphering Mode Command\n");
		return -EINVAL;
	}

	net = conn->network;
        tuple = conn->vsub->last_tuple;

	for (i = 0; i < 8; i++) {
		int supported;

		/* A5/n permitted by osmo-msc.cfg? */
		if (!(net->a5_encryption_mask & (1 << i)))
			continue;

		/* A5/n supported by MS? */
		supported = classmark_supports_a5(&conn->vsub->classmark, i);
		if (supported == 1) {
			ei.perm_algo[j++] = vlr_ciph_to_gsm0808_alg_id(i);
			/* A higher A5/n is supported, so no need to request a Classmark
			 * for support of a lesser A5/n. */
			request_classmark = 0;
		} else if (supported < 0) {
			request_classmark = -supported;
			request_classmark_for_a5_n = i;
		}
	}
	ei.perm_algo_len = j;

	if (request_classmark) {
		/* The highest A5/n as from osmo-msc.cfg might be available, but we are
		 * still missing the Classmark information for that from the MS. First
		 * ask for that. */
		LOGP(DMM, LOGL_DEBUG, "%s: to determine whether A5/%d is supported,"
		     " first ask for a Classmark Update to obtain Classmark %d\n",
		     vlr_subscr_name(conn->vsub), request_classmark_for_a5_n,
		     request_classmark);

		return ran_conn_classmark_request_then_cipher_mode_cmd(conn, umts_aka, retrieve_imeisv);
	}

	if (ei.perm_algo_len == 0) {
		LOGP(DMM, LOGL_ERROR, "%s: cannot start ciphering, no intersection "
		     "between MSC-configured and MS-supported A5 algorithms. MSC: %x  MS: %s\n",
		     vlr_subscr_name(conn->vsub), net->a5_encryption_mask,
		     classmark_a5_name(&conn->vsub->classmark));
		return -ENOTSUP;
	}

	DEBUGP(DMM, "-> CIPHER MODE COMMAND %s\n", vlr_subscr_name(conn->vsub));

	tuple = conn->vsub->last_tuple;

	/* In case of UMTS AKA, the Kc for ciphering must be derived from the 3G auth
	 * tokens.  tuple->vec.kc was calculated from the GSM algorithm and is not
	 * necessarily a match for the UMTS AKA tokens. */
	if (umts_aka)
		osmo_auth_c3(ei.key, tuple->vec.ck, tuple->vec.ik);
	else
		memcpy(ei.key, tuple->vec.kc, sizeof(tuple->vec.kc));
	ei.key_len = sizeof(tuple->vec.kc);

	conn->geran_encr = (struct geran_encr){};
	if (ei.key_len <= sizeof(conn->geran_encr.key)) {
		memcpy(conn->geran_encr.key, ei.key, ei.key_len);
		conn->geran_encr.key_len = ei.key_len;
	}
	/* conn->geran_encr.alg_id remains unknown until we receive a Cipher Mode Complete from the BSC */

	return a_iface_tx_cipher_mode(conn, &ei, retrieve_imeisv);
}

/* VLR asks us to start using ciphering.
 * (Keep non-static to allow regression testing on this function.) */
int msc_vlr_set_ciph_mode(void *msc_conn_ref,
			  bool umts_aka,
			  bool retrieve_imeisv)
{
	struct ran_conn *conn = msc_conn_ref;
	struct vlr_subscr *vsub;
	struct vlr_auth_tuple *tuple;

	if (!conn || !conn->vsub) {
		LOGP(DMM, LOGL_ERROR, "Cannot send Ciphering Mode Command to"
		     " NULL conn/subscriber");
		return -EINVAL;
	}

	vsub = conn->vsub;
	tuple = vsub->last_tuple;

	if (!tuple) {
		LOGP(DMM, LOGL_ERROR, "subscr %s: Cannot send Ciphering Mode"
		     " Command: no auth tuple available\n",
		     vlr_subscr_name(vsub));
		return -EINVAL;
	}

	switch (conn->via_ran) {
	case OSMO_RAT_GERAN_A:
		return ran_conn_geran_set_cipher_mode(conn, umts_aka, retrieve_imeisv);

	case OSMO_RAT_UTRAN_IU:
#ifdef BUILD_IU
		DEBUGP(DMM, "-> SECURITY MODE CONTROL %s\n",
		       vlr_subscr_name(conn->vsub));
		return ranap_iu_tx_sec_mode_cmd(conn->iu.ue_ctx, &tuple->vec, 0, 1);
#else
		LOGP(DMM, LOGL_ERROR, "Cannot send Security Mode Control over OSMO_RAT_UTRAN_IU,"
		     " built without Iu support\n");
		return -ENOTSUP;
#endif

	default:
		break;
	}
	LOGP(DMM, LOGL_ERROR,
	     "%s: cannot start ciphering, unknown RAN type %d\n",
	     vlr_subscr_name(conn->vsub), conn->via_ran);
	return -ENOTSUP;
}

void ran_conn_rx_sec_mode_compl(struct ran_conn *conn)
{
	struct vlr_ciph_result vlr_res = {};

	if (!conn || !conn->vsub) {
		LOGP(DMM, LOGL_ERROR,
		     "Rx Security Mode Complete for invalid conn\n");
		return;
	}

	DEBUGP(DMM, "<- SECURITY MODE COMPLETE %s\n",
	       vlr_subscr_name(conn->vsub));

	vlr_res.cause = VLR_CIPH_COMPL;
	vlr_subscr_rx_ciph_res(conn->vsub, &vlr_res);
}

/* VLR informs us that the subscriber data has somehow been modified */
static void msc_vlr_subscr_update(struct vlr_subscr *subscr)
{
	LOGVSUBP(LOGL_NOTICE, subscr, "VLR: update for IMSI=%s (MSISDN=%s)\n",
		 subscr->imsi, subscr->msisdn);
	ran_conn_update_id_for_vsub(subscr);
}

static void update_classmark(const struct gsm_classmark *src, struct gsm_classmark *dst)
{
	if (src->classmark1_set) {
		dst->classmark1 = src->classmark1;
		dst->classmark1_set = true;
	}
	if (src->classmark2_len) {
		dst->classmark2_len = src->classmark2_len;
		memcpy(dst->classmark2, src->classmark2, sizeof(dst->classmark2));
	}
	if (src->classmark3_len) {
		dst->classmark3_len = src->classmark3_len;
		memcpy(dst->classmark3, src->classmark3, sizeof(dst->classmark3));
	}
}

/* VLR informs us that the subscriber has been associated with a conn */
static int msc_vlr_subscr_assoc(void *msc_conn_ref,
				 struct vlr_subscr *vsub)
{
	struct ran_conn *conn = msc_conn_ref;
	OSMO_ASSERT(vsub);
	if (conn->vsub) {
		if (conn->vsub == vsub)
			LOG_RAN_CONN(conn, LOGL_NOTICE, "msc_vlr_subscr_assoc(): conn already associated with %s\n",
				     vlr_subscr_name(vsub));
		else {
			LOG_RAN_CONN(conn, LOGL_ERROR, "msc_vlr_subscr_assoc(): conn already associated with a subscriber,"
				     " cannot associate with %s\n", vlr_subscr_name(vsub));
			return -EINVAL;
		}
	}

	vlr_subscr_get(vsub, VSUB_USE_CONN);
	conn->vsub = vsub;
	OSMO_ASSERT(conn->vsub);
	conn->vsub->cs.attached_via_ran = conn->via_ran;

	/* In case we have already received Classmark Information before the VLR Subscriber was
	 * associated with the conn: merge the new Classmark into vsub->classmark. Don't overwrite valid
	 * vsub->classmark with unset classmark, though. */
	update_classmark(&conn->temporary_classmark, &conn->vsub->classmark);
	ran_conn_update_id(conn);
	return 0;
}

static int msc_vlr_route_gsup_msg(struct vlr_subscr *vsub,
				  struct osmo_gsup_message *gsup_msg)
{
	switch (gsup_msg->message_type) {
	/* GSM 09.11 code implementing SS/USSD */
	case OSMO_GSUP_MSGT_PROC_SS_REQUEST:
	case OSMO_GSUP_MSGT_PROC_SS_RESULT:
	case OSMO_GSUP_MSGT_PROC_SS_ERROR:
		DEBUGP(DMSC, "Routed to GSM 09.11 SS/USSD handler\n");
		return gsm0911_gsup_handler(vsub, gsup_msg);

	/* GSM 04.11 code implementing MO SMS */
	case OSMO_GSUP_MSGT_MO_FORWARD_SM_ERROR:
	case OSMO_GSUP_MSGT_MO_FORWARD_SM_RESULT:
	case OSMO_GSUP_MSGT_READY_FOR_SM_ERROR:
	case OSMO_GSUP_MSGT_READY_FOR_SM_RESULT:
		DEBUGP(DMSC, "Routed to GSM 04.11 MO handler\n");
		return gsm411_gsup_mo_handler(vsub, gsup_msg);

	/* GSM 04.11 code implementing MT SMS */
	case OSMO_GSUP_MSGT_MT_FORWARD_SM_REQUEST:
		DEBUGP(DMSC, "Routed to GSM 04.11 MT handler\n");
		return gsm411_gsup_mt_handler(vsub, gsup_msg);

	default:
		LOGP(DMM, LOGL_ERROR, "No handler found for %s, dropping message...\n",
			osmo_gsup_message_type_name(gsup_msg->message_type));
		return -GMM_CAUSE_MSGT_NOTEXIST_NOTIMPL;
	}
}

/* operations that we need to implement for libvlr */
static const struct vlr_ops msc_vlr_ops = {
	.tx_auth_req = msc_vlr_tx_auth_req,
	.tx_auth_rej = msc_vlr_tx_auth_rej,
	.tx_id_req = msc_vlr_tx_id_req,
	.tx_lu_acc = msc_vlr_tx_lu_acc,
	.tx_lu_rej = msc_vlr_tx_lu_rej,
	.tx_cm_serv_acc = msc_vlr_tx_cm_serv_acc,
	.tx_cm_serv_rej = msc_vlr_tx_cm_serv_rej,
	.set_ciph_mode = msc_vlr_set_ciph_mode,
	.tx_common_id = msc_vlr_tx_common_id,
	.tx_mm_info = msc_vlr_tx_mm_info,
	.subscr_update = msc_vlr_subscr_update,
	.subscr_assoc = msc_vlr_subscr_assoc,
	.forward_gsup_msg = msc_vlr_route_gsup_msg,
};

/* Allocate net->vlr so that the VTY may configure the VLR's data structures */
int msc_vlr_alloc(struct gsm_network *net)
{
	net->vlr = vlr_alloc(net, &msc_vlr_ops);
	if (!net->vlr)
		return -ENOMEM;
	net->vlr->user_ctx = net;
	return 0;
}

/* Launch the VLR, i.e. its GSUP connection */
int msc_vlr_start(struct gsm_network *net)
{
	struct ipaccess_unit *ipa_dev;

	OSMO_ASSERT(net->vlr);

	ipa_dev = talloc_zero(net->vlr, struct ipaccess_unit);
	ipa_dev->unit_name = "MSC";
	ipa_dev->serno = net->msc_ipa_name; /* NULL unless configured via VTY */
	ipa_dev->swversion = PACKAGE_NAME "-" PACKAGE_VERSION;

	return vlr_start(ipa_dev, net->vlr, net->gsup_server_addr_str, net->gsup_server_port);
}

struct msgb *gsm48_create_mm_serv_rej(enum gsm48_reject_value value)
{
	struct msgb *msg;
	struct gsm48_hdr *gh;

	msg = gsm48_msgb_alloc_name("GSM 04.08 SERV REJ");
	if (!msg)
		return NULL;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_CM_SERV_REJ;
	gh->data[0] = value;

	return msg;
}

struct msgb *gsm48_create_loc_upd_rej(uint8_t cause)
{
	struct gsm48_hdr *gh;
	struct msgb *msg;

	msg = gsm48_msgb_alloc_name("GSM 04.08 LOC UPD REJ");
	if (!msg)
		return NULL;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_LOC_UPD_REJECT;
	gh->data[0] = cause;
	return msg;
}

int gsm48_extract_mi(uint8_t *classmark2_lv, int length, char *mi_string, uint8_t *mi_type)
{
	/* Check the size for the classmark */
	if (length < 1 + *classmark2_lv)
		return -1;

	uint8_t *mi_lv = classmark2_lv + *classmark2_lv + 1;
	if (length < 2 + *classmark2_lv + mi_lv[0])
		return -2;

	*mi_type = mi_lv[1] & GSM_MI_TYPE_MASK;
	return gsm48_mi_to_string(mi_string, GSM48_MI_SIZE, mi_lv+1, *mi_lv);
}

int gsm48_paging_extract_mi(struct gsm48_pag_resp *resp, int length,
			    char *mi_string, uint8_t *mi_type)
{
	static const uint32_t classmark_offset =
		offsetof(struct gsm48_pag_resp, classmark2);
	uint8_t *classmark2_lv = (uint8_t *) &resp->classmark2;
	return gsm48_extract_mi(classmark2_lv, length - classmark_offset,
				mi_string, mi_type);
}
