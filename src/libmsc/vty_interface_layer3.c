/* OpenBSC interface to quagga VTY */
/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009-2011 by Holger Hans Peter Freyther
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

#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>
#include <inttypes.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/buffer.h>
#include <osmocom/vty/vty.h>

#include <arpa/inet.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/gsm_subscriber.h>
#include <osmocom/msc/silent_call.h>
#include <osmocom/msc/gsm_04_11.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/core/utils.h>
#include <osmocom/msc/db.h>
#include <osmocom/core/talloc.h>
#include <osmocom/msc/signal.h>
#include <osmocom/msc/debug.h>
#include <osmocom/msc/vty.h>
#include <osmocom/msc/gsm_04_80.h>
#include <osmocom/msc/gsm_04_14.h>
#include <osmocom/gsm/protocol/gsm_08_58.h>
#include <osmocom/msc/sms_queue.h>
#include <osmocom/msc/mncc_int.h>
#include <osmocom/msc/vlr.h>
#include <osmocom/msc/transaction.h>

#include <osmocom/vty/logging.h>

#include <osmocom/msc/osmo_msc.h>

extern struct gsm_network *gsmnet_from_vty(struct vty *v);

static void vty_conn_hdr(struct vty *vty)
{
	vty_out(vty, "--ConnId ------------Subscriber RAN --LAC Use --Tokens C A5 State%s",
		VTY_NEWLINE);
}

static void vty_dump_one_conn(struct vty *vty, const struct gsm_subscriber_connection *conn)
{
	vty_out(vty, "%08x %22s %3s %5u %3u %08x %c /%1u %27s %s",
		conn->a.conn_id,
		conn->vsub ? vlr_subscr_name(conn->vsub) : "-",
		conn->via_ran == RAN_UTRAN_IU ? "Iu" : "A",
		conn->lac,
		conn->use_count,
		conn->use_tokens,
		conn->received_cm_service_request ? 'C' : '-',
		conn->encr.alg_id,
		conn->conn_fsm ? osmo_fsm_inst_state_name(conn->conn_fsm) : "-",
		VTY_NEWLINE);
}

DEFUN(show_msc_conn, show_msc_conn_cmd,
	"show connection", SHOW_STR "Subscriber Connections\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct gsm_subscriber_connection *conn;

	vty_conn_hdr(vty);
	llist_for_each_entry(conn, &gsmnet->subscr_conns, entry)
		vty_dump_one_conn(vty, conn);

	return CMD_SUCCESS;
}

static void vty_trans_hdr(struct vty *vty)
{
	vty_out(vty, "------------Subscriber --ConnId -P TI -CallRef Proto%s",
		VTY_NEWLINE);
}

static const char *get_trans_proto_str(const struct gsm_trans *trans)
{
	static char buf[256];

	switch (trans->protocol) {
	case GSM48_PDISC_CC:
		snprintf(buf, sizeof(buf), "%s %4u %4u",
			 gsm48_cc_state_name(trans->cc.state),
			 trans->cc.Tcurrent,
			 trans->cc.T308_second);
		break;
	case GSM48_PDISC_SMS:
		snprintf(buf, sizeof(buf), "%s %s",
			gsm411_cp_state_name(trans->sms.smc_inst.cp_state),
			gsm411_rp_state_name(trans->sms.smr_inst.rp_state));
		break;
	default:
		buf[0] = '\0';
		break;
	}

	return buf;
}

static void vty_dump_one_trans(struct vty *vty, const struct gsm_trans *trans)
{
	vty_out(vty, "%22s %08x %s %02u %08x %s%s",
		trans->vsub ? vlr_subscr_name(trans->vsub) : "-",
		trans->conn ? trans->conn->a.conn_id : 0,
		gsm48_pdisc_name(trans->protocol),
		trans->transaction_id,
		trans->callref,
		get_trans_proto_str(trans), VTY_NEWLINE);
}

DEFUN(show_msc_transaction, show_msc_transaction_cmd,
	"show transaction", SHOW_STR "Transactions\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct gsm_trans *trans;

	vty_trans_hdr(vty);
	llist_for_each_entry(trans, &gsmnet->trans_list, entry)
		vty_dump_one_trans(vty, trans);

	return CMD_SUCCESS;
}



static void subscr_dump_full_vty(struct vty *vty, struct vlr_subscr *vsub)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct gsm_trans *trans;
	int reqs;
	struct llist_head *entry;

	if (strlen(vsub->name))
		vty_out(vty, "    Name: '%s'%s", vsub->name, VTY_NEWLINE);
	if (strlen(vsub->msisdn))
		vty_out(vty, "    Extension: %s%s", vsub->msisdn,
			VTY_NEWLINE);
	vty_out(vty, "    LAC: %d/0x%x%s",
		vsub->lac, vsub->lac, VTY_NEWLINE);
	vty_out(vty, "    IMSI: %s%s", vsub->imsi, VTY_NEWLINE);
	if (vsub->tmsi != GSM_RESERVED_TMSI)
		vty_out(vty, "    TMSI: %08X%s", vsub->tmsi,
			VTY_NEWLINE);
	if (vsub->tmsi_new != GSM_RESERVED_TMSI)
		vty_out(vty, "    new TMSI: %08X%s", vsub->tmsi_new,
			VTY_NEWLINE);

#if 0
	/* TODO: add this to vlr_subscr? */
	if (vsub->auth_info.auth_algo != AUTH_ALGO_NONE) {
		struct gsm_auth_info *i = &vsub->auth_info;
		vty_out(vty, "    A3A8 algorithm id: %d%s",
			i->auth_algo, VTY_NEWLINE);
		vty_out(vty, "    A3A8 Ki: %s%s",
			osmo_hexdump(i->a3a8_ki, i->a3a8_ki_len),
			VTY_NEWLINE);
	}
#endif

	if (vsub->last_tuple) {
		struct gsm_auth_tuple *t = vsub->last_tuple;
		vty_out(vty, "    A3A8 last tuple (used %d times):%s",
			t->use_count, VTY_NEWLINE);
		vty_out(vty, "     seq # : %d%s",
			t->key_seq, VTY_NEWLINE);
		vty_out(vty, "     RAND  : %s%s",
			osmo_hexdump(t->vec.rand, sizeof(t->vec.rand)),
			VTY_NEWLINE);
		vty_out(vty, "     SRES  : %s%s",
			osmo_hexdump(t->vec.sres, sizeof(t->vec.sres)),
			VTY_NEWLINE);
		vty_out(vty, "     Kc    : %s%s",
			osmo_hexdump(t->vec.kc, sizeof(t->vec.kc)),
			VTY_NEWLINE);
	}

	reqs = 0;
	llist_for_each(entry, &vsub->cs.requests)
		reqs += 1;
	vty_out(vty, "    Paging: %s paging for %d requests%s",
		vsub->cs.is_paging ? "is" : "not", reqs, VTY_NEWLINE);
	vty_out(vty, "    Use count: %u%s", vsub->use_count, VTY_NEWLINE);

	/* Connection */
	if (vsub->msc_conn_ref) {
		struct gsm_subscriber_connection *conn = vsub->msc_conn_ref;
		vty_conn_hdr(vty);
		vty_dump_one_conn(vty, conn);
	}

	/* Transactions */
	vty_trans_hdr(vty);
	llist_for_each_entry(trans, &gsmnet->trans_list, entry) {
		if (trans->vsub != vsub)
			continue;
		vty_dump_one_trans(vty, trans);
	}
}


/* Subscriber */
DEFUN(show_subscr_cache,
      show_subscr_cache_cmd,
      "show subscriber cache",
	SHOW_STR "Show information about subscribers\n"
	"Display contents of subscriber cache\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct vlr_subscr *vsub;
	int count = 0;

	llist_for_each_entry(vsub, &gsmnet->vlr->subscribers, list) {
		if (++count > 100) {
			vty_out(vty, "%% More than %d subscribers in cache,"
				" stopping here.%s", count-1, VTY_NEWLINE);
			break;
		}
		vty_out(vty, "  Subscriber:%s", VTY_NEWLINE);
		subscr_dump_full_vty(vty, vsub);
	}

	return CMD_SUCCESS;
}

DEFUN(sms_send_pend,
      sms_send_pend_cmd,
      "sms send pending",
      "SMS related commands\n" "SMS Sending related commands\n"
      "Send all pending SMS")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct gsm_sms *sms;
	unsigned long long sms_id = 0;

	while (1) {
		sms = db_sms_get_next_unsent(gsmnet, sms_id, UINT_MAX);
		if (!sms)
			break;

		if (sms->receiver)
			gsm411_send_sms_subscr(sms->receiver, sms);

		sms_id = sms->id + 1;
	}

	return CMD_SUCCESS;
}


DEFUN(sms_delete_expired,
      sms_delete_expired_cmd,
      "sms delete expired",
      "SMS related commands\n" "SMS Database related commands\n"
      "Delete all expired SMS")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct gsm_sms *sms;
	unsigned long long sms_id = 0;
	long long num_deleted = 0;

	while (1) {
		sms = db_sms_get_next_unsent(gsmnet, sms_id, UINT_MAX);
		if (!sms)
			break;

		/* Skip SMS which are currently queued for sending. */
		if (sms_queue_sms_is_pending(gsmnet->sms_queue, sms->id))
			continue;

		/* Expiration check is performed by the DB layer. */
		if (db_sms_delete_expired_message_by_id(sms->id) == 0)
			num_deleted++;

		sms_id = sms->id + 1;
	}

	if (num_deleted == 0) {
		vty_out(vty, "No expired SMS in database%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty_out(vty, "Deleted %llu expired SMS from database%s", num_deleted, VTY_NEWLINE);
	return CMD_SUCCESS;
}


static int _send_sms_str(struct vlr_subscr *receiver,
			 struct vlr_subscr *sender,
			 char *str, uint8_t tp_pid)
{
	struct gsm_network *net = receiver->vlr->user_ctx;
	struct gsm_sms *sms;

	sms = sms_from_text(receiver, sender, 0, str);
	sms->protocol_id = tp_pid;

	/* store in database for the queue */
	if (db_sms_store(sms) != 0) {
		LOGP(DLSMS, LOGL_ERROR, "Failed to store SMS in Database\n");
		sms_free(sms);
		return CMD_WARNING;
	}
	LOGP(DLSMS, LOGL_DEBUG, "SMS stored in DB\n");

	sms_free(sms);
	sms_queue_trigger(net->sms_queue);
	return CMD_SUCCESS;
}

static struct vlr_subscr *get_vsub_by_argv(struct gsm_network *gsmnet,
					       const char *type,
					       const char *id)
{
	if (!strcmp(type, "extension") || !strcmp(type, "msisdn"))
		return vlr_subscr_find_by_msisdn(gsmnet->vlr, id);
	else if (!strcmp(type, "imsi") || !strcmp(type, "id"))
		return vlr_subscr_find_by_imsi(gsmnet->vlr, id);
	else if (!strcmp(type, "tmsi"))
		return vlr_subscr_find_by_tmsi(gsmnet->vlr, atoi(id));

	return NULL;
}
#define SUBSCR_TYPES "(msisdn|extension|imsi|tmsi|id)"
#define SUBSCR_HELP "Operations on a Subscriber\n"			\
	"Identify subscriber by MSISDN (phone number)\n"		\
	"Legacy alias for 'msisdn'\n"		\
	"Identify subscriber by IMSI\n"					\
	"Identify subscriber by TMSI\n"					\
	"Identify subscriber by database ID\n"				\
	"Identifier for the subscriber\n"

DEFUN(show_subscr,
      show_subscr_cmd,
      "show subscriber " SUBSCR_TYPES " ID",
	SHOW_STR SUBSCR_HELP)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct vlr_subscr *vsub = get_vsub_by_argv(gsmnet, argv[0],
						       argv[1]);

	if (!vsub) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	subscr_dump_full_vty(vty, vsub);

	vlr_subscr_put(vsub);

	return CMD_SUCCESS;
}

DEFUN(subscriber_create,
      subscriber_create_cmd,
      "subscriber create imsi ID",
	"Operations on a Subscriber\n" \
	"Create new subscriber\n" \
	"Identify the subscriber by his IMSI\n" \
	"Identifier for the subscriber\n")
{
	vty_out(vty, "%% 'subscriber create' now needs to be done at osmo-hlr%s",
		VTY_NEWLINE);
	return CMD_WARNING;
}

DEFUN(subscriber_send_pending_sms,
      subscriber_send_pending_sms_cmd,
      "subscriber " SUBSCR_TYPES " ID sms pending-send",
	SUBSCR_HELP "SMS Operations\n" "Send pending SMS\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct vlr_subscr *vsub;
	struct gsm_sms *sms;

	vsub = get_vsub_by_argv(gsmnet, argv[0], argv[1]);
	if (!vsub) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	sms = db_sms_get_unsent_for_subscr(vsub, UINT_MAX);
	if (sms)
		gsm411_send_sms_subscr(sms->receiver, sms);

	vlr_subscr_put(vsub);

	return CMD_SUCCESS;
}

DEFUN(subscriber_send_sms,
      subscriber_send_sms_cmd,
      "subscriber " SUBSCR_TYPES " ID sms sender " SUBSCR_TYPES " SENDER_ID send .LINE",
	SUBSCR_HELP "SMS Operations\n" SUBSCR_HELP "Send SMS\n" "Actual SMS Text\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct vlr_subscr *vsub = get_vsub_by_argv(gsmnet, argv[0], argv[1]);
	struct vlr_subscr *sender = get_vsub_by_argv(gsmnet, argv[2], argv[3]);
	char *str;
	int rc;

	if (!vsub) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		rc = CMD_WARNING;
		goto err;
	}

	if (!sender) {
		vty_out(vty, "%% No sender found for %s %s%s",
			argv[2], argv[3], VTY_NEWLINE);
		rc = CMD_WARNING;
		goto err;
	}

	str = argv_concat(argv, argc, 4);
	rc = _send_sms_str(vsub, sender, str, 0);
	talloc_free(str);

err:
	if (sender)
		vlr_subscr_put(sender);

	if (vsub)
		vlr_subscr_put(vsub);

	return rc;
}

DEFUN(subscriber_silent_sms,
      subscriber_silent_sms_cmd,

      "subscriber " SUBSCR_TYPES " ID silent-sms sender " SUBSCR_TYPES " SENDER_ID send .LINE",
	SUBSCR_HELP "Silent SMS Operations\n" SUBSCR_HELP "Send SMS\n" "Actual SMS Text\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct vlr_subscr *vsub = get_vsub_by_argv(gsmnet, argv[0], argv[1]);
	struct vlr_subscr *sender = get_vsub_by_argv(gsmnet, argv[2], argv[3]);
	char *str;
	int rc;

	if (!vsub) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		rc = CMD_WARNING;
		goto err;
	}

	if (!sender) {
		vty_out(vty, "%% No sender found for %s %s%s",
			argv[2], argv[3], VTY_NEWLINE);
		rc = CMD_WARNING;
		goto err;
	}

	str = argv_concat(argv, argc, 4);
	rc = _send_sms_str(vsub, sender, str, 64);
	talloc_free(str);

err:
	if (sender)
		vlr_subscr_put(sender);

	if (vsub)
		vlr_subscr_put(vsub);

	return rc;
}

#define CHAN_TYPES "(any|tch/f|tch/any|sdcch)"
#define CHAN_TYPE_HELP 			\
		"Any channel\n"		\
		"TCH/F channel\n"	\
		"Any TCH channel\n"	\
		"SDCCH channel\n"

DEFUN(subscriber_silent_call_start,
      subscriber_silent_call_start_cmd,
      "subscriber " SUBSCR_TYPES " ID silent-call start (any|tch/f|tch/any|sdcch)",
	SUBSCR_HELP "Silent call operation\n" "Start silent call\n"
	CHAN_TYPE_HELP)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct vlr_subscr *vsub = get_vsub_by_argv(gsmnet, argv[0], argv[1]);
	int rc, type;

	if (!vsub) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!strcmp(argv[2], "tch/f"))
		type = RSL_CHANNEED_TCH_F;
	else if (!strcmp(argv[2], "tch/any"))
		type = RSL_CHANNEED_TCH_ForH;
	else if (!strcmp(argv[2], "sdcch"))
		type = RSL_CHANNEED_SDCCH;
	else
		type = RSL_CHANNEED_ANY;	/* Defaults to ANY */

	rc = gsm_silent_call_start(vsub, vty, type);
	if (rc <= 0) {
		vty_out(vty, "%% Subscriber not attached%s",
			VTY_NEWLINE);
		vlr_subscr_put(vsub);
		return CMD_WARNING;
	}

	vlr_subscr_put(vsub);

	return CMD_SUCCESS;
}

DEFUN(subscriber_silent_call_stop,
      subscriber_silent_call_stop_cmd,
      "subscriber " SUBSCR_TYPES " ID silent-call stop",
	SUBSCR_HELP "Silent call operation\n" "Stop silent call\n"
	CHAN_TYPE_HELP)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct vlr_subscr *vsub = get_vsub_by_argv(gsmnet, argv[0], argv[1]);
	int rc;

	if (!vsub) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	rc = gsm_silent_call_stop(vsub);
	if (rc < 0) {
		vlr_subscr_put(vsub);
		return CMD_WARNING;
	}

	vlr_subscr_put(vsub);

	return CMD_SUCCESS;
}

DEFUN(subscriber_ussd_notify,
      subscriber_ussd_notify_cmd,
      "subscriber " SUBSCR_TYPES " ID ussd-notify (0|1|2) .TEXT",
      SUBSCR_HELP "Send a USSD notify to the subscriber\n"
      "Alerting Level 0\n"
      "Alerting Level 1\n"
      "Alerting Level 2\n"
      "Text of USSD message to send\n")
{
	char *text;
	struct gsm_subscriber_connection *conn;
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct vlr_subscr *vsub = get_vsub_by_argv(gsmnet, argv[0], argv[1]);
	int level;

	if (!vsub) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	level = atoi(argv[2]);
	text = argv_concat(argv, argc, 3);
	if (!text) {
		vlr_subscr_put(vsub);
		return CMD_WARNING;
	}

	conn = connection_for_subscr(vsub);
	if (!conn) {
		vty_out(vty, "%% An active connection is required for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		vlr_subscr_put(vsub);
		talloc_free(text);
		return CMD_WARNING;
	}

	msc_send_ussd_notify(conn, level, text);
	msc_send_ussd_release_complete(conn);

	vlr_subscr_put(vsub);
	talloc_free(text);
	return CMD_SUCCESS;
}

static int loop_by_char(uint8_t ch)
{
	switch (ch) {
	case 'a':
		return GSM414_LOOP_A;
	case 'b':
		return GSM414_LOOP_B;
	case 'c':
		return GSM414_LOOP_C;
	case 'd':
		return GSM414_LOOP_D;
	case 'e':
		return GSM414_LOOP_E;
	case 'f':
		return GSM414_LOOP_F;
	case 'i':
		return GSM414_LOOP_I;
	}
	return -1;
}

DEFUN(subscriber_mstest_close,
      subscriber_mstest_close_cmd,
      "subscriber " SUBSCR_TYPES " ID ms-test close-loop (a|b|c|d|e|f|i)",
      SUBSCR_HELP "Send a TS 04.14 MS Test Command to subscriber\n"
      "Close a TCH Loop inside the MS\n"
      "Loop Type A\n"
      "Loop Type B\n"
      "Loop Type C\n"
      "Loop Type D\n"
      "Loop Type E\n"
      "Loop Type F\n"
      "Loop Type I\n")
{
	struct gsm_subscriber_connection *conn;
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct vlr_subscr *vsub = get_vsub_by_argv(gsmnet, argv[0], argv[1]);
	const char *loop_str;
	int loop_mode;

	if (!vsub) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	loop_str = argv[2];
	loop_mode = loop_by_char(loop_str[0]);

	conn = connection_for_subscr(vsub);
	if (!conn) {
		vty_out(vty, "%% An active connection is required for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		vlr_subscr_put(vsub);
		return CMD_WARNING;
	}

	gsm0414_tx_close_tch_loop_cmd(conn, loop_mode);

	return CMD_SUCCESS;
}

DEFUN(subscriber_mstest_open,
      subscriber_mstest_open_cmd,
      "subscriber " SUBSCR_TYPES " ID ms-test open-loop",
      SUBSCR_HELP "Send a TS 04.14 MS Test Command to subscriber\n"
      "Open a TCH Loop inside the MS\n")
{
	struct gsm_subscriber_connection *conn;
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct vlr_subscr *vsub = get_vsub_by_argv(gsmnet, argv[0], argv[1]);

	if (!vsub) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	conn = connection_for_subscr(vsub);
	if (!conn) {
		vty_out(vty, "%% An active connection is required for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		vlr_subscr_put(vsub);
		return CMD_WARNING;
	}

	gsm0414_tx_open_loop_cmd(conn);

	return CMD_SUCCESS;
}

DEFUN(ena_subscr_expire,
      ena_subscr_expire_cmd,
      "subscriber " SUBSCR_TYPES " ID expire",
	SUBSCR_HELP "Expire the subscriber Now\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct vlr_subscr *vsub = get_vsub_by_argv(gsmnet, argv[0],
						       argv[1]);

	if (!vsub) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (vlr_subscr_expire(vsub))
		vty_out(vty, "%% VLR released subscriber %s%s",
			vlr_subscr_name(vsub), VTY_NEWLINE);

	if (vsub->use_count > 1)
		vty_out(vty, "%% Subscriber %s is still in use,"
			" should be released soon%s",
			vlr_subscr_name(vsub), VTY_NEWLINE);

	vlr_subscr_put(vsub);
	return CMD_SUCCESS;
}

static int scall_cbfn(unsigned int subsys, unsigned int signal,
			void *handler_data, void *signal_data)
{
	struct scall_signal_data *sigdata = signal_data;
	struct vty *vty = sigdata->data;

	switch (signal) {
	case S_SCALL_SUCCESS:
		vty_out(vty, "%% silent call success%s", VTY_NEWLINE);
		break;
	case S_SCALL_EXPIRED:
		vty_out(vty, "%% silent call expired paging%s", VTY_NEWLINE);
		break;
	}
	return 0;
}

DEFUN(show_stats,
      show_stats_cmd,
      "show statistics",
	SHOW_STR "Display network statistics\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);

	vty_out(vty, "Location Update         : %lu attach, %lu normal, %lu periodic%s",
		net->msc_ctrs->ctr[MSC_CTR_LOC_UPDATE_TYPE_ATTACH].current,
		net->msc_ctrs->ctr[MSC_CTR_LOC_UPDATE_TYPE_NORMAL].current,
		net->msc_ctrs->ctr[MSC_CTR_LOC_UPDATE_TYPE_PERIODIC].current,
		VTY_NEWLINE);
	vty_out(vty, "IMSI Detach Indications : %lu%s",
		net->msc_ctrs->ctr[MSC_CTR_LOC_UPDATE_TYPE_DETACH].current,
		VTY_NEWLINE);
	vty_out(vty, "Location Updating Results: %lu completed, %lu failed%s",
		net->msc_ctrs->ctr[MSC_CTR_LOC_UPDATE_COMPLETED].current,
		net->msc_ctrs->ctr[MSC_CTR_LOC_UPDATE_FAILED].current,
		VTY_NEWLINE);
	vty_out(vty, "SMS MO                  : %lu submitted, %lu no receiver%s",
		net->msc_ctrs->ctr[MSC_CTR_SMS_SUBMITTED].current,
		net->msc_ctrs->ctr[MSC_CTR_SMS_NO_RECEIVER].current,
		VTY_NEWLINE);
	vty_out(vty, "SMS MT                  : %lu delivered, %lu no memory, %lu other error%s",
		net->msc_ctrs->ctr[MSC_CTR_SMS_DELIVERED].current,
		net->msc_ctrs->ctr[MSC_CTR_SMS_RP_ERR_MEM].current,
		net->msc_ctrs->ctr[MSC_CTR_SMS_RP_ERR_OTHER].current,
		VTY_NEWLINE);
	vty_out(vty, "MO Calls                : %lu setup, %lu connect ack%s",
		net->msc_ctrs->ctr[MSC_CTR_CALL_MO_SETUP].current,
		net->msc_ctrs->ctr[MSC_CTR_CALL_MO_CONNECT_ACK].current,
		VTY_NEWLINE);
	vty_out(vty, "MT Calls                : %lu setup, %lu connect%s",
		net->msc_ctrs->ctr[MSC_CTR_CALL_MT_SETUP].current,
		net->msc_ctrs->ctr[MSC_CTR_CALL_MT_CONNECT].current,
		VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN(show_smsqueue,
      show_smsqueue_cmd,
      "show sms-queue",
      SHOW_STR "Display SMSqueue statistics\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);

	sms_queue_stats(net->sms_queue, vty);
	return CMD_SUCCESS;
}

DEFUN(smsqueue_trigger,
      smsqueue_trigger_cmd,
      "sms-queue trigger",
      "SMS Queue\n" "Trigger sending messages\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);

	sms_queue_trigger(net->sms_queue);
	return CMD_SUCCESS;
}

DEFUN(smsqueue_max,
      smsqueue_max_cmd,
      "sms-queue max-pending <1-500>",
      "SMS Queue\n" "SMS to deliver in parallel\n" "Amount\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);

	sms_queue_set_max_pending(net->sms_queue, atoi(argv[0]));
	return CMD_SUCCESS;
}

DEFUN(smsqueue_clear,
      smsqueue_clear_cmd,
      "sms-queue clear",
      "SMS Queue\n" "Clear the queue of pending SMS\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);

	sms_queue_clear(net->sms_queue);
	return CMD_SUCCESS;
}

DEFUN(smsqueue_fail,
      smsqueue_fail_cmd,
      "sms-queue max-failure <1-500>",
      "SMS Queue\n" "Maximum amount of delivery failures\n" "Amount\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);

	sms_queue_set_max_failure(net->sms_queue, atoi(argv[0]));
	return CMD_SUCCESS;
}


DEFUN(cfg_mncc_int, cfg_mncc_int_cmd,
      "mncc-int", "Configure internal MNCC handler")
{
	vty->node = MNCC_INT_NODE;

	return CMD_SUCCESS;
}

static struct cmd_node mncc_int_node = {
	MNCC_INT_NODE,
	"%s(config-mncc-int)# ",
	1,
};

static const struct value_string tchf_codec_names[] = {
	{ GSM48_CMODE_SPEECH_V1,	"fr" },
	{ GSM48_CMODE_SPEECH_EFR,	"efr" },
	{ GSM48_CMODE_SPEECH_AMR,	"amr" },
	{ 0, NULL }
};

static const struct value_string tchh_codec_names[] = {
	{ GSM48_CMODE_SPEECH_V1,	"hr" },
	{ GSM48_CMODE_SPEECH_AMR,	"amr" },
	{ 0, NULL }
};

static int config_write_mncc_int(struct vty *vty)
{
	vty_out(vty, "mncc-int%s", VTY_NEWLINE);
	vty_out(vty, " default-codec tch-f %s%s",
		get_value_string(tchf_codec_names, mncc_int.def_codec[0]),
		VTY_NEWLINE);
	vty_out(vty, " default-codec tch-h %s%s",
		get_value_string(tchh_codec_names, mncc_int.def_codec[1]),
		VTY_NEWLINE);

	return CMD_SUCCESS;
}

DEFUN(mnccint_def_codec_f,
      mnccint_def_codec_f_cmd,
      "default-codec tch-f (fr|efr|amr)",
      "Set default codec\n" "Codec for TCH/F\n"
      "Full-Rate\n" "Enhanced Full-Rate\n" "Adaptive Multi-Rate\n")
{
	mncc_int.def_codec[0] = get_string_value(tchf_codec_names, argv[0]);

	return CMD_SUCCESS;
}

DEFUN(mnccint_def_codec_h,
      mnccint_def_codec_h_cmd,
      "default-codec tch-h (hr|amr)",
      "Set default codec\n" "Codec for TCH/H\n"
      "Half-Rate\n" "Adaptive Multi-Rate\n")
{
	mncc_int.def_codec[1] = get_string_value(tchh_codec_names, argv[0]);

	return CMD_SUCCESS;
}


DEFUN(logging_fltr_imsi,
      logging_fltr_imsi_cmd,
      "logging filter imsi IMSI",
	LOGGING_STR FILTER_STR
      "Filter log messages by IMSI\n" "IMSI to be used as filter\n")
{
	struct vlr_subscr *vlr_subscr;
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct log_target *tgt = osmo_log_vty2tgt(vty);
	const char *imsi = argv[0];

	if (!tgt)
		return CMD_WARNING;

	vlr_subscr = vlr_subscr_find_by_imsi(gsmnet->vlr, imsi);

	if (!vlr_subscr) {
		vty_out(vty, "%%no subscriber with IMSI(%s)%s",
			argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	log_set_filter_vlr_subscr(tgt, vlr_subscr);
	return CMD_SUCCESS;
}

static struct cmd_node hlr_node = {
	HLR_NODE,
	"%s(config-hlr)# ",
	1,
};

DEFUN(cfg_hlr, cfg_hlr_cmd,
      "hlr", "Configure connection to the HLR")
{
	vty->node = HLR_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_hlr_remote_ip, cfg_hlr_remote_ip_cmd, "remote-ip A.B.C.D",
      "Remote GSUP address of the HLR\n"
      "Remote GSUP address (default: " MSC_HLR_REMOTE_IP_DEFAULT ")")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	talloc_free((void*)gsmnet->gsup_server_addr_str);
	gsmnet->gsup_server_addr_str = talloc_strdup(gsmnet, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_hlr_remote_port, cfg_hlr_remote_port_cmd, "remote-port <1-65535>",
      "Remote GSUP port of the HLR\n"
      "Remote GSUP port (default: " OSMO_STRINGIFY(MSC_HLR_REMOTE_PORT_DEFAULT) ")")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->gsup_server_port = atoi(argv[0]);
	return CMD_SUCCESS;
}

static int config_write_hlr(struct vty *vty)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	vty_out(vty, "hlr%s", VTY_NEWLINE);
	vty_out(vty, " remote-ip %s%s",
		gsmnet->gsup_server_addr_str, VTY_NEWLINE);
	vty_out(vty, " remote-port %u%s",
		gsmnet->gsup_server_port, VTY_NEWLINE);
	return CMD_SUCCESS;
}

int bsc_vty_init_extra(void)
{
	osmo_signal_register_handler(SS_SCALL, scall_cbfn, NULL);

	install_element_ve(&show_subscr_cmd);
	install_element_ve(&show_subscr_cache_cmd);
	install_element_ve(&show_msc_conn_cmd);
	install_element_ve(&show_msc_transaction_cmd);

	install_element_ve(&sms_send_pend_cmd);
	install_element_ve(&sms_delete_expired_cmd);

	install_element_ve(&subscriber_create_cmd);
	install_element_ve(&subscriber_send_sms_cmd);
	install_element_ve(&subscriber_silent_sms_cmd);
	install_element_ve(&subscriber_silent_call_start_cmd);
	install_element_ve(&subscriber_silent_call_stop_cmd);
	install_element_ve(&subscriber_ussd_notify_cmd);
	install_element_ve(&subscriber_mstest_close_cmd);
	install_element_ve(&subscriber_mstest_open_cmd);
	install_element_ve(&show_stats_cmd);
	install_element_ve(&show_smsqueue_cmd);
	install_element_ve(&logging_fltr_imsi_cmd);

	install_element(ENABLE_NODE, &ena_subscr_expire_cmd);
	install_element(ENABLE_NODE, &smsqueue_trigger_cmd);
	install_element(ENABLE_NODE, &smsqueue_max_cmd);
	install_element(ENABLE_NODE, &smsqueue_clear_cmd);
	install_element(ENABLE_NODE, &smsqueue_fail_cmd);
	install_element(ENABLE_NODE, &subscriber_send_pending_sms_cmd);

	install_element(CONFIG_NODE, &cfg_mncc_int_cmd);
	install_node(&mncc_int_node, config_write_mncc_int);
	install_element(MNCC_INT_NODE, &mnccint_def_codec_f_cmd);
	install_element(MNCC_INT_NODE, &mnccint_def_codec_h_cmd);

	install_element(CFG_LOG_NODE, &logging_fltr_imsi_cmd);

	install_element(CONFIG_NODE, &cfg_hlr_cmd);
	install_node(&hlr_node, config_write_hlr);
	install_element(HLR_NODE, &cfg_hlr_remote_ip_cmd);
	install_element(HLR_NODE, &cfg_hlr_remote_port_cmd);

	return 0;
}
