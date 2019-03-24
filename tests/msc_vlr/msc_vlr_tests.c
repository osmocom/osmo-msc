/* Osmocom MSC+VLR end-to-end tests */

/* (C) 2017 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 *
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <nhofmeyr@sysmocom.de>
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

#include <getopt.h>
#include <stdlib.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/application.h>
#include <osmocom/gsm/protocol/gsm_04_11.h>
#include <osmocom/gsm/gsup.h>
#include <osmocom/gsupclient/gsup_client.h>
#include <osmocom/msc/gsm_04_11.h>
#include <osmocom/msc/debug.h>
#include <osmocom/msc/gsm_04_08.h>
#include <osmocom/msc/transaction.h>
#include <osmocom/msc/a_iface_bssap.h>

#if BUILD_IU
#include <osmocom/msc/iucs_ranap.h>
#include <osmocom/ranap/iu_client.h>
#else
#include <osmocom/msc/iu_dummy.h>
#endif

#include "msc_vlr_tests.h"

void *msc_vlr_tests_ctx = NULL;

bool _log_lines = false;

struct gsm_network *net = NULL;

const char *gsup_tx_expected = NULL;
bool gsup_tx_confirmed;

struct msgb *dtap_tx_expected = NULL;
bool dtap_tx_confirmed;

enum result_sent lu_result_sent;
enum result_sent cm_service_result_sent;
bool auth_request_sent;
const char *auth_request_expect_rand;
const char *auth_request_expect_autn;
bool cipher_mode_cmd_sent;
bool cipher_mode_cmd_sent_with_imeisv;
const char *cipher_mode_expect_kc;
bool security_mode_ctrl_sent;
const char *security_mode_expect_ck;
const char *security_mode_expect_ik;

bool iu_release_expected = false;
bool iu_release_sent = false;
bool bssap_clear_expected = false;
bool bssap_clear_sent = false;

uint32_t cc_to_mncc_tx_expected_msg_type = 0;
const char *cc_to_mncc_tx_expected_imsi = NULL;
bool cc_to_mncc_tx_confirmed = false;
uint32_t cc_to_mncc_tx_got_callref = 0;

extern int gsm0407_pdisc_ctr_bin(uint8_t pdisc);

/* static state variables for the L3 send sequence numbers */
static uint8_t n_sd[4];

/* patch a correct send sequence number into the given message */
static void patch_l3_seq_nr(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	uint8_t pdisc = gsm48_hdr_pdisc(gh);
	uint8_t *msg_type_oct = &msg->l3h[1];
	int bin = gsm0407_pdisc_ctr_bin(pdisc);

	if (bin >= 0 && bin < ARRAY_SIZE(n_sd)) {
		/* patch in n_sd into the msg_type octet */
		*msg_type_oct = (*msg_type_oct & 0x3f) | ((n_sd[bin] & 0x3) << 6);
		//fprintf(stderr, "pdisc=0x%02x bin=%d, patched n_sd=%u\n\n", pdisc, bin, n_sd[bin] & 3);
		/* increment N(SD) */
		n_sd[bin] = (n_sd[bin] + 1) % 4;
	} else {
		//fprintf(stderr, "pdisc=0x%02x NO SEQ\n\n", pdisc);
	}
}

/* reset L3 sequence numbers (e.g. new RR connection) */
static void reset_l3_seq_nr()
{
	memset(n_sd, 0, sizeof(n_sd));
}

struct msgb *msgb_from_hex(const char *label, uint16_t size, const char *hex)
{
	struct msgb *msg = msgb_alloc_headroom(size, 4, label);
	unsigned char *rc;
	msg->l2h = msg->data;
	rc = msgb_put(msg, osmo_hexparse(hex, msg->data, msgb_tailroom(msg)));
	OSMO_ASSERT(rc == msg->l2h);
	return msg;
}

static const char *gh_type_name(struct gsm48_hdr *gh)
{
	return gsm48_pdisc_msgtype_name(gsm48_hdr_pdisc(gh),
					gsm48_hdr_msg_type(gh));
}

void dtap_expect_tx(const char *hex)
{
	/* Has the previously expected dtap been received? */
	OSMO_ASSERT(!dtap_tx_expected);
	if (!hex)
		return;
	dtap_tx_expected = msgb_from_hex("dtap_tx_expected", 1024, hex);
	/* Mask the sequence number out */
	if (msgb_length(dtap_tx_expected) >= 2)
		dtap_tx_expected->data[1] &= 0x3f;
	dtap_tx_confirmed = false;
}

int vlr_gsupc_read_cb(struct osmo_gsup_client *gsupc, struct msgb *msg);

void gsup_rx(const char *rx_hex, const char *expect_tx_hex)
{
	int rc;
	struct msgb *msg;
	const char *label;

	gsup_expect_tx(expect_tx_hex);

	msg = msgb_from_hex("gsup", 1024, rx_hex);
	label = osmo_gsup_message_type_name(msg->l2h[0]);
	fprintf(stderr, "<-- GSUP rx %s: %s\n", label,
		osmo_hexdump_nospc(msgb_l2(msg), msgb_l2len(msg)));
	/* GSUP read cb takes ownership of msgb */
	rc = vlr_gsupc_read_cb(net->vlr->gsup_client, msg);
	fprintf(stderr, "<-- GSUP rx %s: vlr_gsupc_read_cb() returns %d\n",
		label, rc);
	if (expect_tx_hex)
		OSMO_ASSERT(gsup_tx_confirmed);
}

bool conn_exists(const struct ran_conn *conn)
{
	struct ran_conn *c;

	if (!conn)
		return false;

	llist_for_each_entry(c, &net->ran_conns, entry) {
		if (c == conn)
			return true;
	}

	return false;
}

/* Simplified version of the cm_service_request_concludes() */
void conn_conclude_cm_service_req(struct ran_conn *conn,
				  enum osmo_rat_type via_ran)
{
	btw("Concluding CM Service Request");

	OSMO_ASSERT(conn);
	OSMO_ASSERT(conn->received_cm_service_request);

	conn->received_cm_service_request = false;
	ran_conn_put(conn, RAN_CONN_USE_CM_SERVICE);

	ASSERT_RELEASE_CLEAR(via_ran);
}

enum osmo_rat_type rx_from_ran = OSMO_RAT_GERAN_A;

/* SCCP user stub to make a_iface_tx_bssap() happy during test case execution */
struct osmo_sccp_user {
	uint8_t foo;
};
static struct osmo_sccp_user g_scu;

struct ran_conn *conn_new(void)
{
	struct ran_conn *conn;
	conn = ran_conn_alloc(net, rx_from_ran, 23);
	if (conn->via_ran == OSMO_RAT_UTRAN_IU) {
		struct ranap_ue_conn_ctx *ue_ctx = talloc_zero(conn, struct ranap_ue_conn_ctx);
		*ue_ctx = (struct ranap_ue_conn_ctx){
			.conn_id = 42,
		};
		conn->iu.ue_ctx = ue_ctx;
	} else {
		conn->a.scu = &g_scu;
	}
	return conn;
}

struct ran_conn *g_conn = NULL;

void rx_from_ms(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);

	log("MSC <--%s-- MS: %s",
	    osmo_rat_type_name(rx_from_ran),
	    gh_type_name(gh));

	if (!conn_exists(g_conn))
		g_conn = NULL;

	if (!g_conn) {
		log("new conn");
		g_conn = conn_new();
		reset_l3_seq_nr();
		patch_l3_seq_nr(msg);
		ran_conn_compl_l3(g_conn, msg, 23);
	} else {
		patch_l3_seq_nr(msg);
		if ((gsm48_hdr_pdisc(gh) == GSM48_PDISC_RR)
		    && (gsm48_hdr_msg_type(gh) == GSM48_MT_RR_CIPH_M_COMPL))
			ran_conn_cipher_mode_compl(g_conn, msg, 0);
		else
			ran_conn_dtap(g_conn, msg);
	}

	if (!conn_exists(g_conn))
		g_conn = NULL;
}

void ms_sends_msg(const char *hex)
{
	struct msgb *msg;

	msg = msgb_from_hex("ms_sends_msg", 1024, hex);
	msg->l1h = msg->l2h = msg->l3h = msg->data;
	rx_from_ms(msg);
	msgb_free(msg);
}

void bss_sends_bssap_mgmt(const char *hex)
{
	struct msgb *msg;
	struct bssmap_header *bh;
	struct a_conn_info a_conn_info;

	msg = msgb_from_hex("bss_sends_bssap_mgmt", 1024, hex);
	msg->l3h = msg->data;

	msg->l2h = msgb_push(msg, sizeof(*bh));
	bh = (void*)msg->l2h;
	bh->type = BSSAP_MSG_BSS_MANAGEMENT;
	bh->length = msgb_l3len(msg);

	if (!conn_exists(g_conn))
		g_conn = NULL;

	OSMO_ASSERT(g_conn);
	a_conn_info.network = net;
	a_conn_info.conn_id = g_conn->a.conn_id;

	a_sccp_rx_dt((struct osmo_sccp_user*)0x1, &a_conn_info, msg);
	msgb_free(msg);
}

static int ms_sends_msg_fake(uint8_t pdisc, uint8_t msg_type)
{
	int rc;
	struct msgb *msg;
	struct gsm48_hdr *gh;

	msg = msgb_alloc(1024, "ms_sends_msg_fake");
	msg->l1h = msg->l2h = msg->l3h = msg->data;

	gh = (struct gsm48_hdr*)msgb_put(msg, sizeof(*gh));
	gh->proto_discr = pdisc;
	gh->msg_type = msg_type;
	/* some amount of data, whatever */
	msgb_put(msg, 123);

	patch_l3_seq_nr(msg);
	rc = gsm0408_dispatch(g_conn, msg);

	talloc_free(msg);
	return rc;
}

static inline void ms_msg_log_err(uint8_t val, uint8_t msgtype)
{
	int rc = ms_sends_msg_fake(val, msgtype);
	if (rc != -EACCES)
		log("Unexpected return value %u != %u for %s/%s",
		    -rc, -EACCES, gsm48_pdisc_name(val), gsm48_cc_msg_name(msgtype));
}

void thwart_rx_non_initial_requests()
{
	log("requests shall be thwarted");

	ms_msg_log_err(GSM48_PDISC_CC, GSM48_MT_CC_SETUP);
	ms_msg_log_err(GSM48_PDISC_MM, 0x33); /* nonexistent */
	ms_msg_log_err(GSM48_PDISC_RR, GSM48_MT_RR_SYSINFO_1);
	ms_msg_log_err(GSM48_PDISC_SMS, GSM411_MT_CP_DATA);
}

void send_sms(struct vlr_subscr *receiver,
	      struct vlr_subscr *sender,
	      char *str)
{
	struct gsm_sms *sms = sms_from_text(receiver, sender->msisdn, 0, str);
	gsm411_send_sms(net, receiver, sms);
}

unsigned char next_rand_byte = 0;
/* override, requires '-Wl,--wrap=osmo_get_rand_id' */
int __real_osmo_get_rand_id(uint8_t *buf, size_t num);
int __wrap_osmo_get_rand_id(uint8_t *buf, size_t num)
{
	size_t i;
	for (i = 0; i < num; i++)
		buf[i] = next_rand_byte++;
	return 1;
}

/* override, requires '-Wl,--wrap=gsm340_gen_scts' */
void __real_gsm340_gen_scts(uint8_t *scts, time_t time);
void __wrap_gsm340_gen_scts(uint8_t *scts, time_t time)
{
	/* Write fixed time bytes for deterministic test results */
	osmo_hexparse("07101000000000", scts, 7);
}

const char *paging_expecting_imsi = NULL;
uint32_t paging_expecting_tmsi;
bool paging_sent;
bool paging_stopped;

void paging_expect_imsi(const char *imsi)
{
	paging_expecting_imsi = imsi;
	paging_expecting_tmsi = GSM_RESERVED_TMSI;
}

void paging_expect_tmsi(uint32_t tmsi)
{
	paging_expecting_tmsi = tmsi;
	paging_expecting_imsi = NULL;
}

static int _paging_sent(enum osmo_rat_type via_ran, const char *imsi, uint32_t tmsi, uint32_t lac)
{
	log("%s sends out paging request to IMSI %s, TMSI 0x%08x, LAC %u",
	    osmo_rat_type_name(via_ran), imsi, tmsi, lac);
	OSMO_ASSERT(paging_expecting_imsi || (paging_expecting_tmsi != GSM_RESERVED_TMSI));
	if (paging_expecting_imsi)
		VERBOSE_ASSERT(strcmp(paging_expecting_imsi, imsi), == 0, "%d");
	if (paging_expecting_tmsi != GSM_RESERVED_TMSI) {
		VERBOSE_ASSERT(paging_expecting_tmsi, == tmsi, "0x%08x");
	}
	paging_sent = true;
	paging_stopped = false;
	return 1;
}

/* override, requires '-Wl,--wrap=ranap_iu_page_cs' */
int __real_ranap_iu_page_cs(const char *imsi, const uint32_t *tmsi, uint16_t lac);
int __wrap_ranap_iu_page_cs(const char *imsi, const uint32_t *tmsi, uint16_t lac)
{
	return _paging_sent(OSMO_RAT_UTRAN_IU, imsi, tmsi ? *tmsi : GSM_RESERVED_TMSI, lac);
}

/* override, requires '-Wl,--wrap=a_iface_tx_paging' */
int __real_a_iface_tx_paging(const char *imsi, uint32_t tmsi, uint16_t lac);
int __wrap_a_iface_tx_paging(const char *imsi, uint32_t tmsi, uint16_t lac)
{
	return _paging_sent(OSMO_RAT_GERAN_A, imsi, tmsi, lac);
}

/* override, requires '-Wl,--wrap=msc_stop_paging' */
void __real_msc_stop_paging(struct vlr_subscr *vsub);
void __wrap_msc_stop_paging(struct vlr_subscr *vsub)
{
	paging_stopped = true;
}


/* override, requires '-Wl,--wrap=osmo_sccp_tx_data_msg' */
int __real_osmo_sccp_tx_data_msg(struct osmo_sccp_user *scu, uint32_t conn_id,
				 struct msgb *msg);
int __wrap_osmo_sccp_tx_data_msg(struct osmo_sccp_user *scu, uint32_t conn_id,
				 struct msgb *msg)
{
	const char *proto_str;
	const char *msg_str = gsm0808_bssmap_name(msg->l3h[2]);
	switch (*msg->l3h) {
	case BSSAP_MSG_BSS_MANAGEMENT:
		proto_str = "BSSAP-BSS-MANAGEMENT";
		break;
	case BSSAP_MSG_DTAP:
		proto_str = "BSSAP-DTAP";
		break;
	default:
		proto_str = "";
		msg_str = "";
		break;
	}

	log("BSC <--%s-- MSC: %s %s", proto_str, msg_str, msgb_hexdump(msg));
	msgb_free(msg);
	return 0;
}

void clear_vlr()
{
	struct vlr_subscr *vsub, *n;
	llist_for_each_entry_safe(vsub, n, &net->vlr->subscribers, list) {
		vlr_subscr_free(vsub);
	}

	net->authentication_required = false;
	net->a5_encryption_mask = (1 << 0);
	net->vlr->cfg.check_imei_rqd = false;
	net->vlr->cfg.assign_tmsi = false;
	net->vlr->cfg.retrieve_imeisv_early = false;
	net->vlr->cfg.retrieve_imeisv_ciphered = false;
	net->vlr->cfg.auth_tuple_max_reuse_count = 0;
	net->vlr->cfg.auth_reuse_old_sets_on_error = false;

	rx_from_ran = OSMO_RAT_GERAN_A;
	auth_request_sent = false;
	auth_request_expect_rand = NULL;
	auth_request_expect_autn = NULL;

	cipher_mode_cmd_sent = false;
	cipher_mode_cmd_sent_with_imeisv = false;
	cipher_mode_expect_kc = NULL;

	security_mode_ctrl_sent = false;
	security_mode_expect_ck = NULL;
	security_mode_expect_ik = NULL;

	next_rand_byte = 0;

	iu_release_expected = false;
	iu_release_sent = false;
	bssap_clear_expected = false;
	bssap_clear_sent = false;

	osmo_gettimeofday_override = false;
}

static struct log_info_cat test_categories[] = {
	[DMSC] = {
		.name = "DMSC",
		.description = "Mobile Switching Center",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DRLL] = {
		.name = "DRLL",
		.description = "A-bis Radio Link Layer (RLL)",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DMM] = {
		.name = "DMM",
		.description = "Layer3 Mobility Management (MM)",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DRR] = {
		.name = "DRR",
		.description = "Layer3 Radio Resource (RR)",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DCC] = {
		.name = "DCC",
		.description = "Layer3 Call Control (CC)",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DVLR] = {
		.name = "DVLR",
		.description = "Visitor Location Register",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DREF] = {
		.name = "DREF",
		.description = "Reference Counting",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DPAG]	= {
		.name = "DPAG",
		.description = "Paging Subsystem",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DIUCS] = {
		.name = "DIUCS",
		.description = "Iu-CS Protocol",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DMNCC] = {
		.name = "DMNCC",
		.description = "MNCC API for Call Control application",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DBSSAP] = {
		.name = "DBSSAP",
		.description = "BSSAP Protocol (A Interface)",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

static struct log_info info = {
	.cat = test_categories,
	.num_cat = ARRAY_SIZE(test_categories),
};

int mncc_recv(struct gsm_network *net, struct msgb *msg)
{
	struct gsm_mncc *mncc = (void*)msg->data;
	log("MSC --> MNCC: callref 0x%x: %s", mncc->callref,
	    get_mncc_name(mncc->msg_type));

	OSMO_ASSERT(cc_to_mncc_tx_expected_msg_type);
	if (cc_to_mncc_tx_expected_msg_type != mncc->msg_type) {
		log("Mismatch! Expected MNCC msg type: %s",
		    get_mncc_name(cc_to_mncc_tx_expected_msg_type));
		abort();
	}

	if (strcmp(cc_to_mncc_tx_expected_imsi, mncc->imsi)) {
		log("Mismatch! Expected MNCC msg IMSI: '%s', got '%s'",
		    cc_to_mncc_tx_expected_imsi,
		    mncc->imsi);
		abort();
	}

	cc_to_mncc_tx_confirmed = true;
	cc_to_mncc_tx_got_callref = mncc->callref;
	cc_to_mncc_tx_expected_imsi = NULL;
	cc_to_mncc_tx_expected_msg_type = 0;
	talloc_free(msg);
	return 0;
}

struct osmo_gsup_client *
__real_osmo_gsup_client_create2(struct ipaccess_unit *ipa_dev, const char *ip_addr,
				unsigned int tcp_port, osmo_gsup_client_read_cb_t read_cb,
				struct osmo_oap_client_config *oap_config);
struct osmo_gsup_client *
__wrap_osmo_gsup_client_create2(struct ipaccess_unit *ipa_dev, const char *ip_addr,
				unsigned int tcp_port, osmo_gsup_client_read_cb_t read_cb,
				struct osmo_oap_client_config *oap_config)
{
	struct osmo_gsup_client *gsupc;
	gsupc = talloc_zero(msc_vlr_tests_ctx, struct osmo_gsup_client);
	OSMO_ASSERT(gsupc);
	return gsupc;
}

/* override, requires '-Wl,--wrap=gsup_client_send' */
int __real_osmo_gsup_client_send(struct osmo_gsup_client *gsupc, struct msgb *msg);
int __wrap_osmo_gsup_client_send(struct osmo_gsup_client *gsupc, struct msgb *msg)
{
	uint8_t buf[512];
	int len;

	fprintf(stderr, "GSUP --> HLR: %s: %s\n",
		osmo_gsup_message_type_name(msg->data[0]), osmo_hexdump_nospc(msg->data, msg->len));

	OSMO_ASSERT(gsup_tx_expected);
	OSMO_ASSERT(strlen(gsup_tx_expected) <= (sizeof(buf) * 2));

	len = osmo_hexparse(gsup_tx_expected, buf, sizeof(buf));
	if (len < 1)
		abort();

	if (!msgb_eq_data_print(msg, buf, len))
		abort();

	talloc_free(msg);
	gsup_tx_confirmed = true;
	gsup_tx_expected = NULL;
	return 0;
}

static int _validate_dtap(struct msgb *msg, enum osmo_rat_type to_ran)
{
	btw("DTAP --%s--> MS: %s: %s",
	    osmo_rat_type_name(to_ran), gh_type_name((void*)msg->data),
	    osmo_hexdump_nospc(msg->data, msg->len));

	OSMO_ASSERT(dtap_tx_expected);

	/* Mask the sequence number out before comparing */
	msg->data[1] &= 0x3f;
	if (!msgb_eq_data_print(msg, dtap_tx_expected->data, dtap_tx_expected->len))
		abort();

	btw("DTAP matches expected message");

	talloc_free(msg);
	dtap_tx_confirmed = true;
	talloc_free(dtap_tx_expected);
	dtap_tx_expected = NULL;
	return 0;
}

/* override, requires '-Wl,--wrap=ranap_iu_tx' */
int __real_ranap_iu_tx(struct msgb *msg, uint8_t sapi);
int __wrap_ranap_iu_tx(struct msgb *msg, uint8_t sapi)
{
	return _validate_dtap(msg, OSMO_RAT_UTRAN_IU);
}

/* override, requires '-Wl,--wrap=ranap_iu_tx_release' */
int __real_ranap_iu_tx_release(struct ranap_ue_conn_ctx *ctx, const struct RANAP_Cause *cause);
int __wrap_ranap_iu_tx_release(struct ranap_ue_conn_ctx *ctx, const struct RANAP_Cause *cause)
{
	btw("Iu Release --%s--> MS", osmo_rat_type_name(OSMO_RAT_UTRAN_IU));
	OSMO_ASSERT(iu_release_expected);
	iu_release_expected = false;
	iu_release_sent = true;
	return 0;
}

/* override, requires '-Wl,--wrap=iu_tx_common_id' */
int __real_ranap_iu_tx_common_id(struct ranap_ue_conn_ctx *ue_ctx, const char *imsi);
int __wrap_ranap_iu_tx_common_id(struct ranap_ue_conn_ctx *ue_ctx, const char *imsi)
{
	btw("Iu Common ID --%s--> MS (IMSI=%s)", osmo_rat_type_name(OSMO_RAT_UTRAN_IU), imsi);
	return 0;
}

/* override, requires '-Wl,--wrap=a_iface_tx_dtap' */
int __real_a_iface_tx_dtap(struct msgb *msg);
int __wrap_a_iface_tx_dtap(struct msgb *msg)
{
	return _validate_dtap(msg, OSMO_RAT_GERAN_A);
}

/* override, requires '-Wl,--wrap=a_iface_tx_clear_cmd' */
int __real_a_iface_tx_clear_cmd(struct ran_conn *conn);
int __wrap_a_iface_tx_clear_cmd(struct ran_conn *conn)
{
	btw("BSSAP Clear --%s--> MS", osmo_rat_type_name(OSMO_RAT_GERAN_A));
	OSMO_ASSERT(bssap_clear_expected);
	bssap_clear_expected = false;
	bssap_clear_sent = true;
	return 0;
}

/* override, requires '-Wl,--wrap=msc_mgcp_try_call_assignment' */
int __real_msc_mgcp_try_call_assignment(struct gsm_trans *trans);
int __wrap_msc_mgcp_try_call_assignment(struct gsm_trans *trans)
{
	log("MS <--Call Assignment-- MSC: subscr=%s callref=0x%x",
	    vlr_subscr_name(trans->vsub), trans->callref);
	return 0;
}

struct gsm_mncc *on_call_release_mncc_sends_to_cc_data = NULL;

/* override, requires '-Wl,--wrap=msc_mgcp_call_release' */
void __real_msc_mgcp_call_release(struct gsm_trans *trans);
void __wrap_msc_mgcp_call_release(struct gsm_trans *trans)
{
	log("MS <--Call Release-- MSC: subscr=%s callref=0x%x",
	    vlr_subscr_name(trans->vsub), trans->callref);
	if (on_call_release_mncc_sends_to_cc_data) {
		mncc_tx_to_cc(trans->net, on_call_release_mncc_sends_to_cc_data->msg_type,
			      on_call_release_mncc_sends_to_cc_data);
		on_call_release_mncc_sends_to_cc_data = NULL;
	}
}

static int fake_vlr_tx_lu_acc(void *msc_conn_ref, uint32_t send_tmsi)
{
	struct ran_conn *conn = msc_conn_ref;
	if (send_tmsi == GSM_RESERVED_TMSI)
		btw("sending LU Accept for %s", vlr_subscr_name(conn->vsub));
	else
		btw("sending LU Accept for %s, with TMSI 0x%08x",
		    vlr_subscr_name(conn->vsub), send_tmsi);
	lu_result_sent |= RES_ACCEPT;
	return 0;
}

static int fake_vlr_tx_lu_rej(void *msc_conn_ref, enum gsm48_reject_value cause)
{
	struct ran_conn *conn = msc_conn_ref;
	btw("sending LU Reject for %s, cause %u", vlr_subscr_name(conn->vsub), cause);
	lu_result_sent |= RES_REJECT;
	return 0;
}

static int fake_vlr_tx_cm_serv_acc(void *msc_conn_ref)
{
	struct ran_conn *conn = msc_conn_ref;
	btw("sending CM Service Accept for %s", vlr_subscr_name(conn->vsub));
	cm_service_result_sent |= RES_ACCEPT;
	return 0;
}

static int fake_vlr_tx_cm_serv_rej(void *msc_conn_ref, enum gsm48_reject_value cause)
{
	struct ran_conn *conn = msc_conn_ref;
	btw("sending CM Service Reject for %s, cause: %s",
	    vlr_subscr_name(conn->vsub), gsm48_reject_value_name(cause));
	cm_service_result_sent |= RES_REJECT;
	return 0;
}

static int fake_vlr_tx_auth_req(void *msc_conn_ref, struct vlr_auth_tuple *at,
				bool send_autn)
{
	struct ran_conn *conn = msc_conn_ref;
	char *hex;
	bool ok = true;
	btw("sending %s Auth Request for %s: tuple use_count=%d key_seq=%d auth_types=0x%x and...",
	    send_autn? "UMTS" : "GSM", vlr_subscr_name(conn->vsub),
	    at->use_count, at->key_seq, at->vec.auth_types);

	hex = osmo_hexdump_nospc((void*)&at->vec.rand, sizeof(at->vec.rand));
	btw("...rand=%s", hex);
	if (!auth_request_expect_rand
	    || strcmp(hex, auth_request_expect_rand) != 0) {
		ok = false;
		log("FAILURE: expected rand=%s",
		    auth_request_expect_rand ? auth_request_expect_rand : "-");
	}

	if (send_autn) {
		hex = osmo_hexdump_nospc((void*)&at->vec.autn, sizeof(at->vec.autn));
		btw("...autn=%s", hex);
		if (!auth_request_expect_autn
		    || strcmp(hex, auth_request_expect_autn) != 0) {
			ok = false;
			log("FAILURE: expected autn=%s",
			    auth_request_expect_autn ? auth_request_expect_autn : "-");
		}
	} else if (auth_request_expect_autn) {
		ok = false;
		log("FAILURE: no AUTN sent, expected AUTN = %s",
		    auth_request_expect_autn);
	}

	if (send_autn)
		btw("...expecting res=%s",
		    osmo_hexdump_nospc((void*)&at->vec.res, at->vec.res_len));
	else
		btw("...expecting sres=%s",
		    osmo_hexdump_nospc((void*)&at->vec.sres, sizeof(at->vec.sres)));

	auth_request_sent = ok;
	return 0;
}

static int fake_vlr_tx_auth_rej(void *msc_conn_ref)
{
	struct ran_conn *conn = msc_conn_ref;
	btw("sending Auth Reject for %s", vlr_subscr_name(conn->vsub));
	return 0;
}

/* override, requires '-Wl,--wrap=a_iface_tx_cipher_mode' */
int __real_a_iface_tx_cipher_mode(const struct ran_conn *conn,
				  struct gsm0808_encrypt_info *ei, int include_imeisv);
int __wrap_a_iface_tx_cipher_mode(const struct ran_conn *conn,
				  struct gsm0808_encrypt_info *ei, int include_imeisv)
{
	int i;
	btw("sending Ciphering Mode Command for %s: include_imeisv=%d",
	    vlr_subscr_name(conn->vsub), include_imeisv);
	for (i = 0; i < ei->perm_algo_len; i++)
		btw("...perm algo: A5/%u", ei->perm_algo[i] - 1);
	OSMO_ASSERT(ei->key_len <= sizeof(ei->key));
	btw("...key: %s", osmo_hexdump_nospc(ei->key, ei->key_len));
	cipher_mode_cmd_sent = true;
	cipher_mode_cmd_sent_with_imeisv = include_imeisv;

	if (!cipher_mode_expect_kc
	    || strcmp(cipher_mode_expect_kc, osmo_hexdump_nospc(ei->key, ei->key_len))) {
		log("FAILURE: expected kc=%s", cipher_mode_expect_kc ? : "NULL");
		OSMO_ASSERT(false);
	}
	return 0;
}

/* override, requires '-Wl,--wrap=ranap_iu_tx_sec_mode_cmd' */
int __real_ranap_iu_tx_sec_mode_cmd(struct ranap_ue_conn_ctx *uectx, struct osmo_auth_vector *vec,
				    int send_ck, int new_key);
int __wrap_ranap_iu_tx_sec_mode_cmd(struct ranap_ue_conn_ctx *uectx, struct osmo_auth_vector *vec,
				    int send_ck, int new_key)
{
	btw("sending SecurityModeControl for UE ctx %u send_ck=%d new_key=%d",
	    uectx->conn_id, send_ck, new_key);
	btw("...ik=%s", osmo_hexdump_nospc(vec->ik, sizeof(vec->ik)));
	if (send_ck)
		btw("...ck=%s", osmo_hexdump_nospc(vec->ck, sizeof(vec->ck)));
	security_mode_ctrl_sent = true;
	if (!security_mode_expect_ik
	    || strcmp(security_mode_expect_ik, osmo_hexdump_nospc(vec->ik, sizeof(vec->ik)))) {
		log("FAILURE: expected ik=%s", security_mode_expect_ik ? : "NULL");
		OSMO_ASSERT(false);
	}
	if (((!!send_ck) != (!!security_mode_expect_ck))
	    || (security_mode_expect_ck
		&& strcmp(security_mode_expect_ck, osmo_hexdump_nospc(vec->ck, sizeof(vec->ck))))) {
		log("FAILURE: expected ck=%s", security_mode_expect_ck ? : "NULL");
		OSMO_ASSERT(false);
	}
	return 0;
}

extern int msc_vlr_set_ciph_mode(void *msc_conn_ref, bool umts_aka, bool retrieve_imeisv);

static int fake_vlr_tx_ciph_mode_cmd(void *msc_conn_ref, bool umts_aka, bool retrieve_imeisv)
{
	int rc;
#ifndef BUILD_IU
	/* If we built without support for IU, fake the IU part here. The root cause is that we don't
	 * have differing sets of expected outputs for --enable-iu and --disable-iu. */
	struct ran_conn *conn = msc_conn_ref;
	if (conn->via_ran == OSMO_RAT_UTRAN_IU) {
		DEBUGP(DMM, "-> SECURITY MODE CONTROL %s\n", vlr_subscr_name(conn->vsub));
		rc = __wrap_ranap_iu_tx_sec_mode_cmd(conn->iu.ue_ctx, &conn->vsub->last_tuple->vec,
						     0, 1);
	} else
#endif
	rc = msc_vlr_set_ciph_mode(msc_conn_ref, umts_aka, retrieve_imeisv);
	if (rc)
		btw("ERROR sending ciphering mode command: rc=%d", rc);
	return rc;
}

void ms_sends_security_mode_complete()
{
	OSMO_ASSERT(g_conn);
	OSMO_ASSERT(g_conn->via_ran == OSMO_RAT_UTRAN_IU);
	OSMO_ASSERT(g_conn->iu.ue_ctx);
	ran_conn_rx_sec_mode_compl(g_conn);
}

void bss_sends_clear_complete()
{
	btw("BSS sends BSSMAP Clear Complete");
	OSMO_ASSERT(g_conn);
	OSMO_ASSERT(g_conn->via_ran == OSMO_RAT_GERAN_A);
	ran_conn_rx_bssmap_clear_complete(g_conn);
}

void rnc_sends_release_complete()
{
	btw("RNC sends Iu Release Complete");
	OSMO_ASSERT(g_conn);
	OSMO_ASSERT(g_conn->via_ran == OSMO_RAT_UTRAN_IU);
	ran_conn_rx_iu_release_complete(g_conn);
}

const struct timeval fake_time_start_time = { 123, 456 };

void fake_time_start()
{
	struct timespec *clock_override;

	osmo_gettimeofday_override_time = fake_time_start_time;
	osmo_gettimeofday_override = true;
	clock_override = osmo_clock_override_gettimespec(CLOCK_MONOTONIC);
	OSMO_ASSERT(clock_override);
	clock_override->tv_sec = fake_time_start_time.tv_sec;
	clock_override->tv_nsec = fake_time_start_time.tv_usec * 1000;
	osmo_clock_override_enable(CLOCK_MONOTONIC, true);
	fake_time_passes(0, 0);
}

static void check_talloc(void *msgb_ctx, void *msc_vlr_tests_ctx)
{
	/* Verifying that the msgb context is empty */
	talloc_report_full(msgb_ctx, stderr);
	/* Expecting these to stick around in msc_vlr_tests_ctx:
	 * talloc_total_blocks(tall_bsc_ctx) == 13
	 * full talloc report on 'msc_vlr_tests_ctx' (total   4638 bytes in  13 blocks)
	 *     struct osmo_gsup_client        contains    256 bytes in   1 blocks (ref 0) 0x61300000dd20
	 *     struct gsm_network             contains   2983 bytes in   5 blocks (ref 0) 0x61400000fea0
	 *         struct vlr_instance            contains    320 bytes in   2 blocks (ref 0) 0x61300000dee0
	 *             struct ipaccess_unit           contains     64 bytes in   1 blocks (ref 0) 0x60e0000244c0
	 *         no_gsup_server                 contains     15 bytes in   1 blocks (ref 0) 0x60b00000af40
	 *         rate_ctr.c:234                 contains   2352 bytes in   1 blocks (ref 0) 0x61e00000f0e0
	 *     logging                        contains   1399 bytes in   5 blocks (ref 0) 0x60b00000aff0
	 *         struct log_target              contains    238 bytes in   2 blocks (ref 0) 0x61200000bf20
	 *             struct log_category            contains     70 bytes in   1 blocks (ref 0) 0x60f00000efb0
	 *         struct log_info                contains   1160 bytes in   2 blocks (ref 0) 0x60d00000cfd0
	 *             struct log_info_cat            contains   1120 bytes in   1 blocks (ref 0) 0x61a00001f2e0
	 *     msgb                           contains      0 bytes in   1 blocks (ref 0) 0x60800000bf80
	 * (That's 13 counting the root ctx)
	 */
	fprintf(stderr, "talloc_total_blocks(tall_bsc_ctx) == %zu\n",
		talloc_total_blocks(msc_vlr_tests_ctx));
	if (talloc_total_blocks(msc_vlr_tests_ctx) != 13)
		talloc_report_full(msc_vlr_tests_ctx, stderr);
	fprintf(stderr, "\n");
}

static struct {
	bool verbose;
	int run_test_nr;
} cmdline_opts = {
	.verbose = false,
	.run_test_nr = -1,
};

static void print_help(const char *program)
{
	printf("Usage:\n"
	       "  %s [-v] [N [N...]]\n"
	       "Options:\n"
	       "  -h --help      show this text.\n"
	       "  -v --verbose   print source file and line numbers\n"
	       "  N              run only the Nth test (first test is N=1)\n",
	       program
	       );
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"verbose", 1, 0, 'v'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hv",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_help(argv[0]);
			exit(0);
		case 'v':
			cmdline_opts.verbose = true;
			break;
		default:
			/* catch unknown options *as well as* missing arguments. */
			fprintf(stderr, "Error in command line options. Exiting.\n");
			exit(-1);
			break;
		}
	}
}

void *msgb_ctx = NULL;

static void run_tests(int nr)
{
	int test_nr;

	check_talloc(msgb_ctx, msc_vlr_tests_ctx);

	nr--; /* arg's first test is 1, in here it's 0 */
	for (test_nr = 0; msc_vlr_tests[test_nr]; test_nr++) {
		if (nr >= 0 && test_nr != nr)
			continue;

		if (cmdline_opts.verbose)
			fprintf(stderr, "(test nr %d)\n", test_nr + 1);

		msc_vlr_tests[test_nr]();

		if (cmdline_opts.verbose)
			fprintf(stderr, "(test nr %d)\n", test_nr + 1);

		check_talloc(msgb_ctx, msc_vlr_tests_ctx);
	}
}

struct gsm_network *test_net(void *ctx)
{
	struct gsm_network *net = gsm_network_init(ctx, mncc_recv);

	net->gsup_server_addr_str = talloc_strdup(net, "no_gsup_server");
	net->gsup_server_port = 0;

	OSMO_ASSERT(msc_vlr_alloc(net) == 0);
	OSMO_ASSERT(msc_vlr_start(net) == 0);
	OSMO_ASSERT(net->vlr);
	OSMO_ASSERT(net->vlr->gsup_client);

	net->vlr->ops.tx_lu_acc = fake_vlr_tx_lu_acc;
	net->vlr->ops.tx_lu_rej = fake_vlr_tx_lu_rej;
	net->vlr->ops.tx_cm_serv_acc = fake_vlr_tx_cm_serv_acc;
	net->vlr->ops.tx_cm_serv_rej = fake_vlr_tx_cm_serv_rej;
	net->vlr->ops.tx_auth_req = fake_vlr_tx_auth_req;
	net->vlr->ops.tx_auth_rej = fake_vlr_tx_auth_rej;
	net->vlr->ops.set_ciph_mode = fake_vlr_tx_ciph_mode_cmd;

	return net;
}

int main(int argc, char **argv)
{
	handle_options(argc, argv);

	osmo_fsm_term_safely(true);

	msc_vlr_tests_ctx = talloc_named_const(NULL, 0, "msc_vlr_tests_ctx");
	msgb_ctx = msgb_talloc_ctx_init(msc_vlr_tests_ctx, 0);
	osmo_init_logging2(msc_vlr_tests_ctx, &info);

	_log_lines = cmdline_opts.verbose;

	OSMO_ASSERT(osmo_stderr_target);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_timestamp(osmo_stderr_target, 0);
	log_set_print_filename(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 1);
	log_set_category_filter(osmo_stderr_target, DLSMS, 1, LOGL_DEBUG);

	if (cmdline_opts.verbose) {
		log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_BASENAME);
		log_set_print_filename_pos(osmo_stderr_target, LOG_FILENAME_POS_LINE_END);
		log_set_use_color(osmo_stderr_target, 1);
		log_set_print_level(osmo_stderr_target, 1);
	}

	net = test_net(msc_vlr_tests_ctx);

	osmo_fsm_log_addr(false);

	ran_conn_init();

	clear_vlr();

	if (optind >= argc)
		run_tests(-1);
	else {
		int arg;
		long int nr;
		for (arg = optind; arg < argc; arg++) {
			errno = 0;
			nr = strtol(argv[arg], NULL, 10);
			if (errno) {
				fprintf(stderr, "Invalid argument: %s\n",
					argv[arg]);
				exit(1);
			}

			run_tests(nr);
		}
	}

	printf("Done\n");

	check_talloc(msgb_ctx, msc_vlr_tests_ctx);
	return 0;
}
