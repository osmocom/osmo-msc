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

#pragma once

#include <stdbool.h>
#include <stdio.h>

#include <osmocom/crypt/utran_cipher.h>
#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/vlr.h>
#include <osmocom/msc/msub.h>
#include <osmocom/msc/msc_a.h>
#include <osmocom/msc/mncc.h>
#include <osmocom/msc/call_leg.h>
#include <osmocom/msc/rtp_stream.h>

extern bool _log_lines;
#define LOG_COLOR "\033[1;33m"
#define LOG_COLOR_OFF "\033[0;m"

#define _log(fmt, args...) do { \
		if (_log_lines) \
			fprintf(stderr, LOG_COLOR " %4d:%s: " fmt LOG_COLOR_OFF "\n", \
				__LINE__, __FILE__, ## args ); \
		else \
			fprintf(stderr, fmt "\n", ## args ); \
	} while (false)

/* btw means "by the way", the test tells the log what's happening.
 * BTW() marks a larger section, btw() is the usual logging. */
#define BTW(fmt, args...) _log("\n\n- " fmt, ## args )
#define btw(fmt, args...) _log("- " fmt, ## args )
#define log(fmt, args...) _log("  " fmt, ## args )

#define comment_start() fprintf(stderr, "===== %s\n", __func__);
#define comment_end() fprintf(stderr, "===== %s: SUCCESS\n\n", __func__);

extern void *msc_vlr_tests_ctx;

extern struct msub *g_msub;
extern struct gsm_network *net;
extern void *msgb_ctx;

extern enum osmo_rat_type rx_from_ran;

extern const char *gsup_tx_expected;
extern bool gsup_tx_confirmed;

extern struct msgb *dtap_tx_expected;
extern bool dtap_tx_confirmed;

enum result_sent {
	RES_NONE = 0,
	RES_ACCEPT = 1,
	RES_REJECT = 2,
};
extern enum result_sent lu_result_sent;
extern enum result_sent cm_service_result_sent;

extern bool auth_request_sent;
extern const char *auth_request_expect_rand;
extern const char *auth_request_expect_autn;

extern bool cipher_mode_cmd_sent;
extern bool cipher_mode_cmd_sent_with_imeisv;
extern const char *cipher_mode_expect_kc;

extern bool security_mode_ctrl_sent;
extern const char *security_mode_expect_ck;
extern const char *security_mode_expect_ik;

static inline void expect_cipher_mode_cmd(const char *kc)
{
	cipher_mode_cmd_sent = false;
	cipher_mode_expect_kc = kc;
	/* make sure we don't mix up the two */
	security_mode_ctrl_sent = false;
}

static inline void expect_security_mode_ctrl(const char *ck, const char *ik)
{
	security_mode_ctrl_sent = false;
	security_mode_expect_ck = ck;
	security_mode_expect_ik = ik;
	/* make sure we don't mix up the two */
	cipher_mode_cmd_sent = false;
}

extern bool paging_sent;

extern bool iu_release_expected;
extern bool iu_release_sent;
extern bool bssap_clear_expected;
extern bool bssap_clear_sent;

extern uint32_t cc_to_mncc_tx_expected_msg_type;
extern const char *cc_to_mncc_tx_expected_imsi;
extern bool cc_to_mncc_tx_confirmed;
extern uint32_t cc_to_mncc_tx_got_callref;
extern char cc_to_mncc_tx_last_sdp[1024];

extern struct gsm_mncc *on_call_release_mncc_sends_to_cc_data;

static inline void expect_iu_release()
{
	iu_release_expected = true;
	iu_release_sent = false;
}

static inline void expect_bssap_clear()
{
	bssap_clear_expected = true;
	bssap_clear_sent = false;
}

static inline void expect_release_clear(enum osmo_rat_type via_ran)
{
	switch (via_ran) {
	case OSMO_RAT_GERAN_A:
		expect_bssap_clear();
		return;
	case OSMO_RAT_UTRAN_IU:
		expect_iu_release();
		return;
	default:
		OSMO_ASSERT(false);
		break;
	}
}

extern bool bssap_assignment_expected;
extern bool bssap_assignment_sent;
extern struct gsm0808_channel_type bssap_assignment_command_last_channel_type;
extern bool iu_rab_assignment_expected;
extern bool iu_rab_assignment_sent;

static inline void expect_bssap_assignment()
{
	bssap_assignment_expected = true;
	bssap_assignment_sent = false;
}

static inline void expect_iu_rab_assignment()
{
	iu_rab_assignment_expected = true;
	iu_rab_assignment_sent = false;
}

struct msc_vlr_test_cmdline_opts {
	bool verbose;
	int run_test_nr;
};

typedef void (* msc_vlr_test_func_t )(void);
extern msc_vlr_test_func_t msc_vlr_tests[];

struct msgb *msgb_from_hex(const char *label, uint16_t size, const char *hex);

void clear_vlr();
bool conn_exists(const struct msub *msub);
void conn_conclude_cm_service_req(struct msub *msub, const char *cm_service_use);

void dtap_expect_tx(const char *hex);
void dtap_expect_tx_ussd(char *ussd_text);
void paging_expect_imsi(const char *imsi);
void paging_expect_tmsi(uint32_t tmsi);

void ms_sends_msg(const char *hex);
void ms_sends_msgf(const char *fmt, ...);
void ms_sends_compl_l3(const char *hex, const struct gsm0808_speech_codec_list *codec_list_bss_supported);
void ms_sends_classmark_update(const struct osmo_gsm48_classmark *classmark);
void ms_sends_ciphering_mode_complete(const char *inner_nas_msg);
void ms_sends_security_mode_complete(uint8_t utran_encryption);
void ms_sends_assignment_complete(const char *sdp_codec_name);
void gsup_rx(const char *rx_hex, const char *expect_tx_hex);
void send_sms(struct vlr_subscr *receiver,
	      struct vlr_subscr *sender,
	      char *str);
void crcx_ok(enum rtp_direction dir);

void ran_sends_clear_complete();

void thwart_rx_non_initial_requests();

#define EXPECT_ACCEPTED(expect_accepted) do { \
		if (g_msub) \
			OSMO_ASSERT(conn_exists(g_msub)); \
		bool accepted = msc_a_is_accepted(msub_msc_a(g_msub)); \
		fprintf(stderr, "msc_a_is_accepted() == %s\n", \
			accepted ? "true" : "false"); \
		OSMO_ASSERT(accepted == expect_accepted); \
	} while (false)

#define VAL_ASSERT(desc, val, expect_op, fmt)	\
	do { \
		log(desc " == " fmt, (val)); \
		OSMO_ASSERT((val) expect_op); \
	} while (0)

#define VERBOSE_ASSERT(val, expect_op, fmt) VAL_ASSERT(#val, val, expect_op, fmt)

#define EXPECT_CONN_COUNT(N) VERBOSE_ASSERT(llist_count(&msub_list), == N, "%d")

#define gsup_expect_tx(hex) do \
{ \
	if (gsup_tx_expected) { \
		log("Previous expected GSUP tx was not confirmed!"); \
		OSMO_ASSERT(!gsup_tx_expected); \
	} \
	if (!hex) \
		break; \
	gsup_tx_expected = hex; \
	gsup_tx_confirmed = false; \
} while (0)

#define cc_to_mncc_expect_tx(imsi, msg_type) do \
{ \
	if (cc_to_mncc_tx_expected_msg_type) { \
		log("Previous expected MNCC tx was not confirmed!"); \
		OSMO_ASSERT(!cc_to_mncc_tx_expected_msg_type); \
	} \
	cc_to_mncc_tx_expected_imsi = imsi; \
	cc_to_mncc_tx_expected_msg_type = msg_type; \
	cc_to_mncc_tx_confirmed = false; \
} while (0)

void fake_time_start();

/* as macro to get the test file's source line number */
#define fake_time_passes(secs, usecs) do \
{ \
	struct timeval diff; \
	osmo_gettimeofday_override_add(secs, usecs); \
	osmo_clock_override_add(CLOCK_MONOTONIC, secs, usecs * 1000); \
	timersub(&osmo_gettimeofday_override_time, &fake_time_start_time, &diff); \
	btw("Total time passed: %d.%06d s", \
	    (int)diff.tv_sec, (int)diff.tv_usec); \
	osmo_timers_prepare(); \
	osmo_timers_update(); \
} while (0)

extern const struct timeval fake_time_start_time;

#define ASSERT_RELEASE_CLEAR(via_ran) \
	switch (via_ran) { \
	case OSMO_RAT_GERAN_A: \
		VERBOSE_ASSERT(bssap_clear_sent, == true, "%d"); \
		break; \
	case OSMO_RAT_UTRAN_IU: \
		VERBOSE_ASSERT(iu_release_sent, == true, "%d"); \
		break; \
	default: \
		OSMO_ASSERT(false); \
		break; \
	}

#define HLR_TO_VLR "0a0101"
#define VLR_TO_HLR "0a0101"
#define CN_DOMAIN "280102"
#define EUSE_TO_MSC_USSD "0a0103"
#define MSC_USSD_TO_EUSE "0a0103"

void expect_crcx(enum rtp_direction towards);
bool crcx_scheduled(enum rtp_direction towards);
