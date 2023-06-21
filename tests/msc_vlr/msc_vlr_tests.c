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
#include <osmocom/msc/gsup_client_mux.h>
#include <osmocom/msc/gsm_04_11.h>
#include <osmocom/msc/debug.h>
#include <osmocom/msc/gsm_04_08.h>
#include <osmocom/msc/transaction.h>
#include <osmocom/msc/ran_msg.h>
#include <osmocom/msc/msc_a.h>
#include <osmocom/msc/msc_i.h>
#include <osmocom/msc/msc_t.h>
#include <osmocom/msc/call_leg.h>
#include <osmocom/msc/rtp_stream.h>
#include <osmocom/msc/codec_mapping.h>

#include "msc_vlr_tests.h"

void *msc_vlr_tests_ctx = NULL;
void *msgb_ctx = NULL;

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

bool bssap_assignment_expected = false;
bool bssap_assignment_sent = false;
struct gsm0808_channel_type bssap_assignment_command_last_channel_type;
bool iu_rab_assignment_expected = false;
bool iu_rab_assignment_sent = false;

uint32_t cc_to_mncc_tx_expected_msg_type = 0;
const char *cc_to_mncc_tx_expected_imsi = NULL;
bool cc_to_mncc_tx_confirmed = false;
uint32_t cc_to_mncc_tx_got_callref = 0;
char cc_to_mncc_tx_last_sdp[1024] = {};

bool expecting_crcx[2] = {};
bool got_crcx[2] = {};

extern int ran_dec_dtap_undup_pdisc_ctr_bin(uint8_t pdisc);

/* static state variables for the L3 send sequence numbers */
static uint8_t n_sd[4];

/* patch a correct send sequence number into the given message */
static void patch_l3_seq_nr(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	uint8_t pdisc = gsm48_hdr_pdisc(gh);
	uint8_t *msg_type_oct = &msg->l3h[1];
	int bin = ran_dec_dtap_undup_pdisc_ctr_bin(pdisc);

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
	rc = gsup_client_mux_rx(net->gcm->gsup_client, msg);
	fprintf(stderr, "<-- GSUP rx %s: vlr_gsupc_read_cb() returns %d\n",
		label, rc);
	if (expect_tx_hex)
		OSMO_ASSERT(gsup_tx_confirmed);
}

bool conn_exists(const struct msub *msub)
{
	struct msub *i;

	if (!msub)
		return false;

	llist_for_each_entry(i, &msub_list, entry) {
		if (i == msub)
			return true;
	}

	btw("msub gone");
	return false;
}

/* Simplified version of the cm_service_request_concludes() */
void conn_conclude_cm_service_req(struct msub *msub, const char *cm_service_use)
{
	int32_t count;
	struct msc_a *msc_a = msub_msc_a(msub);
	btw("Concluding CM Service Request");

	OSMO_ASSERT(conn_exists(msub));
	count = osmo_use_count_by(&msc_a->use_count, cm_service_use);
	OSMO_ASSERT(count > 0);

	OSMO_ASSERT(osmo_use_count_get_put(&msc_a->use_count, cm_service_use, -count) == 0);

	ASSERT_RELEASE_CLEAR(msc_a->c.ran->type);
}

void dummy_msc_i_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
}

static const struct osmo_fsm_state dummy_msc_i_states[] = {
	{
		.name = "0",
		.in_event_mask = 0xffffffff,
		.action = dummy_msc_i_action,
	},
};

struct osmo_fsm dummy_msc_i_fsm = {
	.name = "dummy_msc_i",
	.states = dummy_msc_i_states,
	.num_states = ARRAY_SIZE(dummy_msc_i_states),
	.log_subsys = DMSC,
	.event_names = msc_i_fsm_event_names,
};

struct msc_i *dummy_msc_i_alloc(struct msub *msub, struct ran_infra *ran)
{
	return msub_role_alloc(g_msub, MSC_ROLE_I, &dummy_msc_i_fsm, struct msc_i, ran);
}

enum osmo_rat_type rx_from_ran = OSMO_RAT_GERAN_A;

struct msub *g_msub = NULL;

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

static int _validate_dtap(struct msgb *msg, enum osmo_rat_type to_ran)
{
	struct gsm48_hdr *gh = (void*)msg->data;
	uint8_t pdisc = gsm48_hdr_pdisc(gh);
	uint8_t msgt = gsm48_hdr_msg_type(gh);

	btw("DTAP --%s--> MS: %s: %s",
	    osmo_rat_type_name(to_ran), gh_type_name((void*)msg->data),
	    osmo_hexdump_nospc(msg->data, msg->len));

	if (pdisc == GSM48_PDISC_MM
	    && msgt == GSM48_MT_MM_CM_SERV_ACC) {
		cm_service_result_sent |= RES_ACCEPT;
		talloc_free(msg);
		return 0;
	}

	if (pdisc == GSM48_PDISC_MM
	    && msgt == GSM48_MT_MM_CM_SERV_REJ) {
		cm_service_result_sent |= RES_REJECT;
		talloc_free(msg);
		return 0;
	}

	OSMO_ASSERT(dtap_tx_expected);

	/* Mask the sequence number out before comparing */
	msg->data[1] &= 0x3f;
	if (!msgb_eq_data_print(msg, dtap_tx_expected->data, dtap_tx_expected->len)) {
		btw("Expected %s", osmo_hexdump(dtap_tx_expected->data, dtap_tx_expected->len));
		abort();
	}

	btw("DTAP matches expected message");

	talloc_free(msg);
	dtap_tx_confirmed = true;
	talloc_free(dtap_tx_expected);
	dtap_tx_expected = NULL;

	return 0;
}

static void bssap_validate_clear_cmd()
{
	OSMO_ASSERT(bssap_clear_expected);
	bssap_clear_expected = false;
	bssap_clear_sent = true;
}

static void iucs_validate_clear_cmd()
{
	OSMO_ASSERT(iu_release_expected);
	iu_release_expected = false;
	iu_release_sent = true;
}

static int bssap_validate_cipher_mode_cmd(const struct ran_cipher_mode_command *cmd)
{
	int i;
	const char *got_key;
	cipher_mode_cmd_sent = true;
	cipher_mode_cmd_sent_with_imeisv = cmd->geran.retrieve_imeisv;
	btw("sending Ciphering Mode Command: retrieve_imeisv=%d", cipher_mode_cmd_sent_with_imeisv);
	for (i = 0; i < 7; i++) {
		if (!(cmd->geran.a5_encryption_mask & (1 << i)))
			continue;
		btw("...perm algo: A5/%d", i);
	}
	got_key = osmo_hexdump_nospc(cmd->vec->kc, sizeof(cmd->vec->kc));
	btw("...key: %s", got_key);

	if (!cipher_mode_expect_kc
	    || strcmp(cipher_mode_expect_kc, got_key)) {
		log("FAILURE: expected kc=%s", cipher_mode_expect_kc ? : "NULL");
		OSMO_ASSERT(false);
	}
	return 0;
}

static void bssap_validate_assignment_cmd(const struct ran_assignment_command *assignment_command)
{
	OSMO_ASSERT(bssap_assignment_expected);
	bssap_assignment_expected = false;
	bssap_assignment_sent = true;
	if (assignment_command->channel_type)
		bssap_assignment_command_last_channel_type = *assignment_command->channel_type;
	else
		bssap_assignment_command_last_channel_type = (struct gsm0808_channel_type){};
}

static void iucs_validate_assignment_cmd(const struct ran_assignment_command *assignment_command)
{
	OSMO_ASSERT(iu_rab_assignment_expected);
	iu_rab_assignment_expected = false;
	iu_rab_assignment_sent = true;
}

static int iucs_validate_security_mode_ctrl(const struct ran_cipher_mode_command *cmd)
{
	const char *got_ik;
	got_ik = osmo_hexdump_nospc(cmd->vec->ik, sizeof(cmd->vec->ik));
	btw("sending SecurityModeControl: ik=%s", got_ik);
	security_mode_ctrl_sent = true;
	if (!security_mode_expect_ik
	    || strcmp(security_mode_expect_ik, got_ik)) {
		log("FAILURE: expected ik=%s", security_mode_expect_ik ? : "NULL");
		OSMO_ASSERT(false);
	}
	return 0;
}

struct msgb *dont_ran_encode(struct osmo_fsm_inst *caller_fi, const struct ran_msg *ran_enc_msg)
{
	struct msc_role_common *c = caller_fi->priv;
	enum osmo_rat_type ran_type = c->ran->type;
	const char *ran_name = osmo_rat_type_name(ran_type);
	LOG_RAN_ENC(caller_fi, DMSC, LOGL_INFO, "%s on %s\n", ran_msg_type_name(ran_enc_msg->msg_type),
		     ran_name);

	switch (ran_enc_msg->msg_type) {
	case RAN_MSG_DTAP:
		_validate_dtap(ran_enc_msg->dtap, ran_type);
		break;
	case RAN_MSG_CLEAR_COMMAND:
		switch (ran_type) {
		case OSMO_RAT_GERAN_A:
			bssap_validate_clear_cmd();
			break;
		case OSMO_RAT_UTRAN_IU:
			iucs_validate_clear_cmd();
			break;
		default:
			OSMO_ASSERT(false);
		}
		break;
	case RAN_MSG_CIPHER_MODE_COMMAND:
		switch (ran_type) {
		case OSMO_RAT_GERAN_A:
			bssap_validate_cipher_mode_cmd(&ran_enc_msg->cipher_mode_command);
			break;
		case OSMO_RAT_UTRAN_IU:
			iucs_validate_security_mode_ctrl(&ran_enc_msg->cipher_mode_command);
			break;
		default:
			OSMO_ASSERT(false);
		}
		break;
	case RAN_MSG_ASSIGNMENT_COMMAND:
		switch (ran_type) {
		case OSMO_RAT_GERAN_A:
			bssap_validate_assignment_cmd(&ran_enc_msg->assignment_command);
			break;
		case OSMO_RAT_UTRAN_IU:
			iucs_validate_assignment_cmd(&ran_enc_msg->assignment_command);
			break;
		default:
			OSMO_ASSERT(false);
		}
		break;
	default:
		break;
	}

	/* We're testing MSC and VLR interaction, not message encoding.
	 * Return whatever. The test msc_i instance is a dummy and drops these.
	 * But it must be msg_free()-able.
	 */
	return msgb_alloc(1, "unused dummy msg");
}

struct ran_infra test_ran_infra[] = {
	[OSMO_RAT_GERAN_A] = {
		.type = OSMO_RAT_GERAN_A,
		.an_proto = OSMO_GSUP_ACCESS_NETWORK_PROTOCOL_TS3G_48006,
		.log_subsys = DBSSAP,
		.tdefs = msc_tdefs_geran,
		.ran_encode = dont_ran_encode,
	},
	[OSMO_RAT_UTRAN_IU] = {
		.type = OSMO_RAT_UTRAN_IU,
		.an_proto = OSMO_GSUP_ACCESS_NETWORK_PROTOCOL_TS3G_25413,
		.log_subsys = DIUCS,
		.tdefs = msc_tdefs_utran,
		.ran_encode = dont_ran_encode,
		.force_mgw_codecs_to_ran = {
			.count = 1,
			.codec = {
				{
					.payload_type = 96,
					.subtype_name = "VND.3GPP.IUFP",
					.rate = 16000,
				},
			},
		},
	},
};

static int fake_msc_a_ran_dec(const struct ran_msg *ran_dec_msg)
{
	struct msc_a_ran_dec_data d = {
		.from_role = MSC_ROLE_I,
	};
	return msc_a_ran_decode_cb(g_msub->role[MSC_ROLE_A], &d, ran_dec_msg);
}

void rx_from_ms(struct msgb *msg, const struct gsm0808_speech_codec_list *codec_list_bss_supported)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct ran_msg ran_dec_msg;
	struct gsm0808_cell_id cell_id = {
		.id_discr = CELL_IDENT_LAI_AND_LAC,
		.id.lai_and_lac = {
			.plmn = {
				.mcc = 1,
				.mnc = 2,
			},
			.lac = 23,
		},
	};
	struct msc_a *msc_a;

	log("MSC <--%s-- MS: %s", osmo_rat_type_name(rx_from_ran), gh_type_name(gh));

	if (!conn_exists(g_msub))
		g_msub = NULL;

	if (!g_msub) {
		log("new conn");
		g_msub = msub_alloc(net);
		msc_a_alloc(g_msub, &test_ran_infra[rx_from_ran]);
		dummy_msc_i_alloc(g_msub, &test_ran_infra[rx_from_ran]);

		reset_l3_seq_nr();
		ran_dec_msg = (struct ran_msg){
			.msg_type = RAN_MSG_COMPL_L3,
			.compl_l3 = {
				.cell_id = &cell_id,
				.msg = msg,
				.codec_list_bss_supported = codec_list_bss_supported,
			},
		};
	} else {
		ran_dec_msg = (struct ran_msg){
			.msg_type = RAN_MSG_DTAP,
			.dtap = msg,
		};
	}

	msc_a = msub_msc_a(g_msub);
	msc_a_get(msc_a, __func__);

	patch_l3_seq_nr(msg);
	fake_msc_a_ran_dec(&ran_dec_msg);

	msc_a_put(msc_a, __func__);

	if (!conn_exists(g_msub))
		g_msub = NULL;
}

void ms_sends_msg(const char *hex)
{
	struct msgb *msg;

	msg = msgb_from_hex("ms_sends_msg", 1024, hex);
	msg->l1h = msg->l2h = msg->l3h = msg->data;
	rx_from_ms(msg, NULL);
	msgb_free(msg);
}

void ms_sends_msgf(const char *fmt, ...)
{
	va_list ap;
	char *hex;

	va_start(ap, fmt);
	hex = talloc_vasprintf(msc_vlr_tests_ctx, fmt, ap);
	va_end(ap);

	ms_sends_msg(hex);
	talloc_free(hex);
}

void ms_sends_compl_l3(const char *hex, const struct gsm0808_speech_codec_list *codec_list_bss_supported)
{
	struct msgb *msg;

	msg = msgb_from_hex("ms_sends_msg", 1024, hex);
	msg->l1h = msg->l2h = msg->l3h = msg->data;
	rx_from_ms(msg, codec_list_bss_supported);
	msgb_free(msg);
}

void ms_sends_classmark_update(const struct osmo_gsm48_classmark *classmark)
{
	struct ran_msg ran_dec = {
		.msg_type = RAN_MSG_CLASSMARK_UPDATE,
		.classmark_update = {
			.classmark = classmark,
		},
	};
	fake_msc_a_ran_dec(&ran_dec);
}

static int ms_sends_msg_fake(uint8_t pdisc, uint8_t msg_type)
{
	int rc;
	struct ran_msg ran_dec;
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

	ran_dec = (struct ran_msg){
		.msg_type = RAN_MSG_DTAP,
		.dtap = msg,
	};
	rc = fake_msc_a_ran_dec(&ran_dec);

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

/* override, requires '-Wl,--wrap=ran_peers_down_paging' */
int __real_ran_peers_down_paging(struct sccp_ran_inst *sri, enum CELL_IDENT page_where, struct vlr_subscr *vsub,
				 enum paging_cause cause);
int __wrap_ran_peers_down_paging(struct sccp_ran_inst *sri, enum CELL_IDENT page_where, struct vlr_subscr *vsub,
				 enum paging_cause cause)
{
	log("paging request (%s) to %s on %s", paging_cause_name(cause), vlr_subscr_name(vsub),
	    osmo_rat_type_name(sri->ran->type));

	OSMO_ASSERT(paging_expecting_imsi || (paging_expecting_tmsi != GSM_RESERVED_TMSI));
	if (paging_expecting_imsi)
		VERBOSE_ASSERT(strcmp(paging_expecting_imsi, vsub->imsi), == 0, "%d");
	if (paging_expecting_tmsi != GSM_RESERVED_TMSI) {
		VERBOSE_ASSERT(paging_expecting_tmsi, == vsub->tmsi, "0x%08x");
	}
	paging_sent = true;
	return 1;
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

	memset(expecting_crcx, 0, sizeof(expecting_crcx));
	memset(got_crcx, 0, sizeof(got_crcx));

	bssap_assignment_expected = false;
	bssap_assignment_sent = false;
	iu_rab_assignment_expected = false;
	iu_rab_assignment_sent = false;
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
	[DSS] = {
		.name = "DSS",
		.description = "Supplementary Services",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

static struct log_info info = {
	.cat = test_categories,
	.num_cat = ARRAY_SIZE(test_categories),
};

struct gsm_mncc *on_call_release_mncc_sends_to_cc_data = NULL;

int mncc_recv(struct gsm_network *net, struct msgb *msg)
{
	struct gsm_mncc *mncc = (void*)msg->data;
	if (mncc->msg_type == MNCC_RTP_CREATE) {
		struct gsm_mncc_rtp *rtp = (void *)msg->data;
		log("MSC --> MNCC: callref 0x%x: %s\n%s", rtp->callref,
		    get_mncc_name(rtp->msg_type),
		    rtp->sdp);
		OSMO_STRLCPY_ARRAY(cc_to_mncc_tx_last_sdp, rtp->sdp);
	} else {
		log("MSC --> MNCC: callref 0x%x: %s\n%s", mncc->callref,
		    get_mncc_name(mncc->msg_type),
		    mncc->sdp);
		OSMO_STRLCPY_ARRAY(cc_to_mncc_tx_last_sdp, mncc->sdp);
	}

	if (mncc->msg_type == MNCC_REL_IND && on_call_release_mncc_sends_to_cc_data) {

		log("MNCC: callref 0x%x: Call Release triggering %s", mncc->callref,
		    get_mncc_name(on_call_release_mncc_sends_to_cc_data->msg_type));

		mncc_tx_to_cc(net,
			      on_call_release_mncc_sends_to_cc_data);

		on_call_release_mncc_sends_to_cc_data = NULL;
		return 0;
	}

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

	/* Compare only the length expected. Extra data is fine, to not care about new GSUP IEs invented later. */
	if (msg->len < len) {
		fprintf(stderr, "ERROR: GSUP message too short, expected '%s'\n", gsup_tx_expected);
		abort();
	}

	if (memcmp(msg->data, buf, len)) {
		fprintf(stderr, "ERROR: GSUP message mismatch, expected it to start with '%s'\n", gsup_tx_expected);
		abort();
	}

	talloc_free(msg);
	gsup_tx_confirmed = true;
	gsup_tx_expected = NULL;
	return 0;
}

struct rtp_stream fake_rtp[2] = {
	{
		.dir = RTP_TO_RAN,
		.local = {
			.ip = "10.23.42.1",
			.port = 99,
		},
		.remote = {
			.ip = "10.23.42.2",
			.port = 100,
		},
	},
	{
		.dir = RTP_TO_CN,
		.local = {
			.ip = "10.23.42.1",
			.port = 23,
		},
		.remote = {
			.ip = "10.23.42.2",
			.port = 42,
		},
	},
};

void expect_crcx(enum rtp_direction towards)
{
	OSMO_ASSERT(!expecting_crcx[towards]);
	expecting_crcx[towards] = true;
	got_crcx[towards] = false;
}

bool crcx_scheduled(enum rtp_direction towards)
{
	return got_crcx[towards];
}

/* override, requires '-Wl,--wrap=call_leg_ensure_ci' */
int __real_call_leg_ensure_ci(struct call_leg *cl, enum rtp_direction dir, uint32_t call_id, struct gsm_trans *for_trans,
			      const struct sdp_audio_codecs *codecs_if_known,
			      const struct osmo_sockaddr_str *remote_addr_if_known);
int __wrap_call_leg_ensure_ci(struct call_leg *cl, enum rtp_direction dir, uint32_t call_id, struct gsm_trans *for_trans,
			      const struct sdp_audio_codecs *codecs_if_known,
			      const struct osmo_sockaddr_str *remote_addr_if_known)
{
	if (!cl->rtp[dir]) {
		log("MGW <--CRCX to %s-- MSC: call_id=0x%x codecs=%s", rtp_direction_name(dir), call_id,
		    codecs_if_known ? sdp_audio_codecs_to_str(codecs_if_known) : "unset");

		OSMO_ASSERT(expecting_crcx[dir]);
		expecting_crcx[dir] = false;
		got_crcx[dir] = true;

		call_leg_ensure_rtp_alloc(cl, dir, call_id, for_trans);
		if (codecs_if_known)
			rtp_stream_set_codecs(cl->rtp[dir], codecs_if_known);
		if (remote_addr_if_known && osmo_sockaddr_str_is_nonzero(remote_addr_if_known))
			rtp_stream_set_remote_addr(cl->rtp[dir], remote_addr_if_known);
	}

	return 0;
}

void crcx_ok(enum rtp_direction dir)
{
	struct msc_a *msc_a = msub_msc_a(g_msub);
	struct call_leg *cl = msc_a->cc.call_leg;
	OSMO_ASSERT(cl);
	OSMO_ASSERT(cl->rtp[dir]);
	osmo_sockaddr_str_from_str(&cl->rtp[dir]->local, "10.23.23.1", 23);
	//osmo_sockaddr_str_from_str(&cl->rtp[dir].remote, "10.42.42.1", 42);
	log("MGW --CRCX OK to %s--> MSC", rtp_direction_name(dir));
	osmo_fsm_inst_dispatch(cl->fi, CALL_LEG_EV_RTP_STREAM_ADDR_AVAILABLE, cl->rtp[dir]);
}

static int fake_vlr_tx_lu_acc(void *msc_conn_ref, uint32_t send_tmsi)
{
	struct msc_a *msc_a = msc_conn_ref;
	if (send_tmsi == GSM_RESERVED_TMSI)
		btw("sending LU Accept for %s", msc_a->c.fi->id);
	else
		btw("sending LU Accept for %s, with TMSI 0x%08x",
		    msc_a->c.fi->id, send_tmsi);
	lu_result_sent |= RES_ACCEPT;
	return 0;
}

static int fake_vlr_tx_lu_rej(void *msc_conn_ref, enum gsm48_reject_value cause)
{
	struct msc_a *msc_a = msc_conn_ref;
	btw("sending LU Reject for %s, cause %u", msc_a->c.fi->id, cause);
	lu_result_sent |= RES_REJECT;
	return 0;
}

static int fake_vlr_tx_cm_serv_rej(void *msc_conn_ref, enum osmo_cm_service_type cm_service_type,
				   enum gsm48_reject_value cause)
{
	struct msc_a *msc_a = msc_conn_ref;
	btw("sending CM Service Reject (%s) for %s, cause: %s",
	    osmo_cm_service_type_name(cm_service_type), msc_a->c.fi->id, gsm48_reject_value_name(cause));
	cm_service_result_sent |= RES_REJECT;
	return 0;
}

static int fake_vlr_tx_auth_req(void *msc_conn_ref, struct vlr_auth_tuple *at,
				bool send_autn)
{
	struct msc_a *msc_a = msc_conn_ref;
	char *hex;
	bool ok = true;
	btw("sending %s Auth Request for %s: tuple use_count=%d key_seq=%d auth_types=0x%x and...",
	    send_autn? "UMTS" : "GSM", msc_a->c.fi->id,
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
	struct msc_a *msc_a = msc_conn_ref;
	btw("sending Auth Reject for %s", msc_a->c.fi->id);
	return 0;
}

void ms_sends_ciphering_mode_complete(const char *inner_ran_msg)
{
	struct ran_msg ran_dec;

	msc_a_get(msub_msc_a(g_msub), __func__);

	ran_dec = (struct ran_msg){
		.msg_type = RAN_MSG_CIPHER_MODE_COMPLETE,
	};
	fake_msc_a_ran_dec(&ran_dec);

	if (inner_ran_msg) {
		struct msgb *msg = msgb_from_hex("cipher_mode_complete_ran", 1024, inner_ran_msg);
		msg->l1h = msg->l2h = msg->l3h = msg->data;
		ran_dec = (struct ran_msg){
			.msg_type = RAN_MSG_DTAP,
			.dtap = msg,
		};
		patch_l3_seq_nr(msg);
		fake_msc_a_ran_dec(&ran_dec);
		msgb_free(msg);
	}

	msc_a_put(msub_msc_a(g_msub), __func__);

	if (!conn_exists(g_msub))
		g_msub = NULL;
}

void ms_sends_security_mode_complete(uint8_t utran_encryption)
{
	struct ran_msg ran_dec;

	ran_dec = (struct ran_msg){
		.msg_type = RAN_MSG_CIPHER_MODE_COMPLETE,
		.cipher_mode_complete.utran_encryption = utran_encryption,
	};
	fake_msc_a_ran_dec(&ran_dec);

	if (!conn_exists(g_msub))
		g_msub = NULL;
}

void ms_sends_assignment_complete(const char *sdp_codec_name)
{
	struct ran_msg ran_dec;
	const struct codec_mapping *m = codec_mapping_by_subtype_name(sdp_codec_name);
	OSMO_ASSERT(m);
	OSMO_ASSERT(m->has_gsm0808_speech_codec);

	ran_dec = (struct ran_msg){
		.msg_type = RAN_MSG_ASSIGNMENT_COMPLETE,
		.assignment_complete = {
			.codec_present = true,
			.codec = m->gsm0808_speech_codec,
			.codec_with_iuup = (rx_from_ran == OSMO_RAT_UTRAN_IU),
		},
	};
	osmo_sockaddr_str_from_str(&ran_dec.assignment_complete.remote_rtp, "1.2.3.4", 1234);
	fake_msc_a_ran_dec(&ran_dec);

	if (!conn_exists(g_msub))
		g_msub = NULL;
}

void ran_sends_clear_complete()
{
	struct ran_msg ran_dec;

	ran_dec = (struct ran_msg){
		.msg_type = RAN_MSG_CLEAR_COMPLETE,
	};
	fake_msc_a_ran_dec(&ran_dec);

	if (!conn_exists(g_msub))
		g_msub = NULL;
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

static void run_tests(int nr)
{
	int test_nr;

	nr--; /* arg's first test is 1, in here it's 0 */
	for (test_nr = 0; msc_vlr_tests[test_nr]; test_nr++) {
		size_t talloc_blocks_before_test;

		if (nr >= 0 && test_nr != nr)
			continue;

		if (cmdline_opts.verbose)
			fprintf(stderr, "(test nr %d)\n", test_nr + 1);

		talloc_blocks_before_test = talloc_total_blocks(msc_vlr_tests_ctx);

		msc_vlr_tests[test_nr]();

		if (talloc_total_blocks(msc_vlr_tests_ctx) != talloc_blocks_before_test) {
			fprintf(stderr, "ERROR: talloc leak: %zu blocks\n",
				talloc_total_blocks(msc_vlr_tests_ctx) - talloc_blocks_before_test);
			talloc_report_full(msc_vlr_tests_ctx, stderr);
			fprintf(stderr, "\n");
		}

		if (talloc_total_blocks(msgb_ctx) > 1) {
			fprintf(stderr, "ERROR: msgb leak:\n");
			talloc_report_full(msgb_ctx, stderr);
			fprintf(stderr, "\n");
		}

		if (cmdline_opts.verbose)
			fprintf(stderr, "(test nr %d)\n", test_nr + 1);
	}
}

struct gsm_network *test_net(void *ctx)
{
	struct gsm_network *net = gsm_network_init(ctx, mncc_recv);
	struct mgcp_client *client;

	net->gsup_server_addr_str = talloc_strdup(net, "no_gsup_server");
	net->gsup_server_port = 0;

	OSMO_ASSERT(msc_vlr_alloc(net) == 0);
	OSMO_ASSERT(net->vlr);
	OSMO_ASSERT(msc_gsup_client_start(net) == 0);
	OSMO_ASSERT(net->gcm);
	OSMO_ASSERT(msc_vlr_start(net) == 0);

	net->vlr->ops.tx_lu_acc = fake_vlr_tx_lu_acc;
	net->vlr->ops.tx_lu_rej = fake_vlr_tx_lu_rej;
	net->vlr->ops.tx_cm_serv_acc = msc_vlr_tx_cm_serv_acc;
	net->vlr->ops.tx_cm_serv_rej = fake_vlr_tx_cm_serv_rej;
	net->vlr->ops.tx_auth_req = fake_vlr_tx_auth_req;
	net->vlr->ops.tx_auth_rej = fake_vlr_tx_auth_rej;
	net->vlr->ops.set_ciph_mode = msc_a_vlr_set_cipher_mode;

	/* Allocate fake SCCP Ran Instances */
	net->a.sri = talloc_zero(net, struct sccp_ran_inst);
	*net->a.sri = (struct sccp_ran_inst){
		.ran = &test_ran_infra[OSMO_RAT_GERAN_A],
	};
	INIT_LLIST_HEAD(&net->a.sri->ran_peers);
	INIT_LLIST_HEAD(&net->a.sri->ran_conns);

	net->iu.sri = talloc_zero(net, struct sccp_ran_inst);
	*net->iu.sri = (struct sccp_ran_inst){
		.ran = &test_ran_infra[OSMO_RAT_UTRAN_IU],
	};
	INIT_LLIST_HEAD(&net->iu.sri->ran_peers);
	INIT_LLIST_HEAD(&net->iu.sri->ran_conns);

	net->mgw.tdefs = g_mgw_tdefs;
	net->mgw.tdefs = g_mgw_tdefs;
	net->mgw.conf = mgcp_client_conf_alloc(net);
	net->mgw.mgw_pool = mgcp_client_pool_alloc(net);
	client = mgcp_client_init(net, net->mgw.conf);
	mgcp_client_pool_register_single(net->mgw.mgw_pool, client);
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
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_print_category(osmo_stderr_target, 1);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_category_filter(osmo_stderr_target, DLSMS, 1, LOGL_DEBUG);
	log_set_category_filter(osmo_stderr_target, DLMGCP, 0, LOGL_NOTICE);

	if (cmdline_opts.verbose) {
		log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_BASENAME);
		log_set_print_filename_pos(osmo_stderr_target, LOG_FILENAME_POS_LINE_END);
		log_set_use_color(osmo_stderr_target, 1);
		log_set_print_level(osmo_stderr_target, 1);
	}

	net = test_net(msc_vlr_tests_ctx);

	osmo_fsm_log_addr(false);
	osmo_fsm_log_timeouts(cmdline_opts.verbose);

	call_leg_init(net);

	OSMO_ASSERT(osmo_fsm_register(&dummy_msc_i_fsm) == 0);

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

	return 0;
}
