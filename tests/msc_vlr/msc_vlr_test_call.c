/* Osmocom MSC+VLR end-to-end tests */

/* (C) 2017 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#include "msc_vlr_tests.h"

#include <osmocom/msc/gsm_04_08.h>
#include <osmocom/msc/codec_mapping.h>

#define mncc_sends_to_cc(MSG_TYPE, MNCC) do { \
		(MNCC)->msg_type = MSG_TYPE; \
		log("MSC <-- MNCC: callref 0x%x: %s\n%s", (MNCC)->callref, \
		    get_mncc_name((MNCC)->msg_type), \
		    (MNCC)->sdp); \
		mncc_tx_to_cc(net, MNCC); \
	} while(0)

/*
static void on_call_release_mncc_sends_to_cc(uint32_t msg_type, struct gsm_mncc *mncc)
{
	mncc->msg_type = msg_type;
	on_call_release_mncc_sends_to_cc_data = mncc;
}
*/

#define IMSI "901700000010650"

static void lu_utran_tmsi()
{
	struct vlr_subscr *vsub;

	net->authentication_required = true;
	net->vlr->cfg.assign_tmsi = true;
	rx_from_ran = OSMO_RAT_UTRAN_IU;

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("080108" "09710000000156f0" CN_DOMAIN VLR_TO_HLR);
	ms_sends_msg("0508" /* MM LU */
		     "7" /* ciph key seq: no key available */
		     "0" /* LU type: normal */
		     "09f107" "0017" /* LAI, LAC */
		     "57" /* classmark 1: R99, early classmark, no power lvl */
		     "089910070000106005" /* IMSI */
		     "3303575886" /* classmark 2 */
		     );
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("from HLR, rx _SEND_AUTH_INFO_RESULT; VLR sends Auth Req to MS");
	/* based on auc_3g:
	 * K = 'EB215756028D60E3275E613320AEC880',
	 * OPC = 'FB2A3D1B360F599ABAB99DB8669F8308'
	 * SQN = 0
	 */
	auth_request_sent = false;
	auth_request_expect_rand = "39fa2f4e3d523d8619a73b4f65c3e14d";
	auth_request_expect_autn = "8704f5ba55f30000d2ee44b22c8ea919";
	gsup_rx("0a"
		/* imsi */
		"0108" "09710000000156f0"
		/* 5 auth vectors... */
		/* TL    TL     rand */
		"0362"  "2010" "39fa2f4e3d523d8619a73b4f65c3e14d"
		/*       TL     sres       TL     kc */
			"2104" "9b36efdf" "2208" "059a4f668f6fbe39"
		/*       TL     3G IK */
			"2310" "27497388b6cb044648f396aa155b95ef"
		/*       TL     3G CK */
			"2410" "f64735036e5871319c679f4742a75ea1"
		/*       TL     AUTN */
			"2510" "8704f5ba55f30000d2ee44b22c8ea919"
		/*       TL     RES */
			"2708" "e229c19e791f2e41"
		/* TL    TL     rand */
		"0362"  "2010" "c187a53a5e6b9d573cac7c74451fd46d"
			"2104" "85aa3130" "2208" "d3d50a000bf04f6e"
			"2310" "1159ec926a50e98c034a6b7d7c9f418d"
			"2410" "df3a03d9ca5335641efc8e36d76cd20b"
			"2510" "1843a645b98d00005b2d666af46c45d9"
			"2708" "7db47cf7f81e4dc7"
		"0362"  "2010" "efa9c29a9742148d5c9070348716e1bb"
			"2104" "69d5f9fb" "2208" "3df176f0c29f1a3d"
			"2310" "eb50e770ddcc3060101d2f43b6c2b884"
			"2410" "76542abce5ff9345b0e8947f4c6e019c"
			"2510" "f9375e6d41e1000096e7fe4ff1c27e39"
			"2708" "706f996719ba609c"
		"0362"  "2010" "f023d5a3b24726e0631b64b3840f8253"
			"2104" "d570c03f" "2208" "ec011be8919883d6"
			"2310" "c4e58af4ba43f3bcd904e16984f086d7"
			"2410" "0593f65e752e5cb7f473862bda05aa0a"
			"2510" "541ff1f077270000c5ea00d658bc7e9a"
			"2708" "3fd26072eaa2a04d"
		"0362"  "2010" "2f8f90c780d6a9c0c53da7ac57b6707e"
			"2104" "b072446f220823f39f9f425ad6e6"
			"2310" "65af0527fda95b0dc5ae4aa515cdf32f"
			"2410" "537c3b35a3b13b08d08eeb28098f45cc"
			"2510" "4bf4e564f75300009bc796706bc65744"
			"2708" "0edb0eadbea94ac2"
		HLR_TO_VLR,
		NULL);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Authen Response, VLR accepts and sends SecurityModeControl");
	expect_security_mode_ctrl(NULL, "27497388b6cb044648f396aa155b95ef");
	ms_sends_msg("0554" "e229c19e" "2104" "791f2e41");
	VERBOSE_ASSERT(security_mode_ctrl_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends SecurityModeControl acceptance, VLR accepts and sends GSUP LU Req to HLR");
	gsup_expect_tx("04010809710000000156f0" CN_DOMAIN VLR_TO_HLR);
	ms_sends_security_mode_complete(1);
	VERBOSE_ASSERT(gsup_tx_confirmed, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000000156f00804032443f2" HLR_TO_VLR,
		"12010809710000000156f0" VLR_TO_HLR);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT");
	gsup_rx("06010809710000000156f0" HLR_TO_VLR, NULL);

	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");

	btw("a LU Accept with a new TMSI was sent, waiting for TMSI Realloc Compl");
	EXPECT_CONN_COUNT(1);
	EXPECT_ACCEPTED(false);

	btw("MS sends TMSI Realloc Complete");
	iu_release_expected = true;
	iu_release_sent = false;
	ms_sends_msg("055b");
	VERBOSE_ASSERT(iu_release_sent, == true, "%d"); \

	btw("LU was successful, and the conn has already been closed");
	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	vsub = vlr_subscr_find_by_imsi(net->vlr, IMSI, __func__);
	VERBOSE_ASSERT(vsub != NULL, == true, "%d");
	VERBOSE_ASSERT(strcmp(vsub->imsi, IMSI), == 0, "%d");
	VAL_ASSERT("LAC", vsub->cgi.lai.lac, == 23, "%u");
	vlr_subscr_put(vsub, __func__);
}

static void lu_geran_noauth(void)
{
	rx_from_ran = OSMO_RAT_GERAN_A;
	net->authentication_required = false;
	net->vlr->cfg.assign_tmsi = false;

	btw("Location Update request causes a GSUP LU request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("04010809710000000156f0280102" VLR_TO_HLR);
	ms_sends_msg("0508" /* MM LU */
		     "7" /* ciph key seq: no key available */
		     "0" /* LU type: normal */
		     "09f107" "0017" /* LAI, LAC */
		     "57" /* classmark 1: R99, early classmark, no power lvl */
		     "089910070000106005" /* IMSI */
		     "3303575886" /* classmark 2 */
		     );
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000000156f00804036470f1" HLR_TO_VLR,
		"12010809710000000156f0" VLR_TO_HLR);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT");
	expect_bssap_clear();
	gsup_rx("06010809710000000156f0" HLR_TO_VLR, NULL);

	btw("LU was successful, and the conn has already been closed");
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);
}


static void test_call_mo()
{
	struct gsm_mncc mncc = {
		.imsi = IMSI,
	};
	struct gsm_mncc_rtp mncc_rtp = {};

	comment_start();

	fake_time_start();

	lu_utran_tmsi();

	BTW("after a while, a new conn sends a CM Service Request. VLR responds with Auth Req, 2nd auth vector");
	auth_request_sent = false;
	auth_request_expect_rand = "c187a53a5e6b9d573cac7c74451fd46d";
	auth_request_expect_autn = "1843a645b98d00005b2d666af46c45d9";
	cm_service_result_sent = RES_NONE;
	ms_sends_msg("052471"
		     "03575886" /* classmark 2 */
		     "089910070000106005" /* IMSI */);
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");

	btw("needs auth, not yet accepted");
	EXPECT_ACCEPTED(false);

	/* On UTRAN */
	btw("MS sends Authen Response, VLR accepts and sends SecurityModeControl");
	expect_security_mode_ctrl(NULL, "1159ec926a50e98c034a6b7d7c9f418d");
	ms_sends_msg("0554" "7db47cf7" "2104" "f81e4dc7"); /* 2nd vector's res, s.a. */
	VERBOSE_ASSERT(security_mode_ctrl_sent, == true, "%d");
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");

	btw("MS sends SecurityModeControl acceptance, VLR accepts; above Ciphering is an implicit CM Service Accept");
	ms_sends_security_mode_complete(1);
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");

	BTW("a call is initiated");

	btw("CC SETUP causes CRCX towards CN and RAN");
	expect_crcx(RTP_TO_CN);
	expect_crcx(RTP_TO_RAN);
	ms_sends_msg("0385" /* CC, seq = 2 -> 0x80 | CC Setup = 0x5 */
		     "0406600402000581" /* Bearer Capability */
		     "5e038121f3" /* Called Number BCD */
		     "15020100" /* CC Capabilities */
		     "4008" /* Supported Codec List */
		       "04026000" /* UMTS: AMR 2 | AMR */
		       "00021f00" /* GSM: HR AMR | FR AMR | GSM EFR | GSM HR | GSM FR */
		    );
	OSMO_ASSERT(crcx_scheduled(RTP_TO_CN));
	OSMO_ASSERT(crcx_scheduled(RTP_TO_RAN));

	btw("As soon as the MGW port towards CN is created, MNCC_SETUP_IND is triggered");
	cc_to_mncc_expect_tx(IMSI, MNCC_SETUP_IND);
	crcx_ok(RTP_TO_CN);
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);
	mncc.callref = mncc_rtp.callref = cc_to_mncc_tx_got_callref;

	btw("MNCC replies with MNCC_RTP_CREATE");
	mncc_sends_to_cc(MNCC_RTP_CREATE, &mncc_rtp);

	btw("MGW acknowledges the CRCX, triggering Assignment");
	expect_iu_rab_assignment();
	crcx_ok(RTP_TO_RAN);
	OSMO_ASSERT(iu_rab_assignment_sent);

	btw("Assignment succeeds, triggering MNCC_RTP_CREATE ack to MNCC");
	cc_to_mncc_expect_tx("", MNCC_RTP_CREATE);
	ms_sends_assignment_complete(true, "AMR:octet-align=1");
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);

	btw("MNCC says that's fine");
	dtap_expect_tx("8302" /* CC: Call Proceeding */);
	mncc_sends_to_cc(MNCC_CALL_PROC_REQ, &mncc);
	OSMO_ASSERT(dtap_tx_confirmed);

	fake_time_passes(1, 23);

	btw("The other call leg got established (not shown here), MNCC tells us so");
	dtap_expect_tx("8301" /* CC: Call Alerting */);
	mncc_sends_to_cc(MNCC_ALERT_REQ, &mncc);
	OSMO_ASSERT(dtap_tx_confirmed);

	dtap_expect_tx("8307" /* CC: Connect */);
	mncc_sends_to_cc(MNCC_SETUP_RSP, &mncc);
	OSMO_ASSERT(dtap_tx_confirmed);

	fake_time_passes(1, 23);

	cc_to_mncc_expect_tx("", MNCC_SETUP_COMPL_IND);
	ms_sends_msg("03cf" /* CC: Connect Acknowledge */);
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);

	BTW("RTP stream goes ahead, not shown here.");
	fake_time_passes(123, 45);

	BTW("Call ends");
	cc_to_mncc_expect_tx("", MNCC_DISC_IND);
	ms_sends_msg("032502e090" /* CC: Disconnect, cause: Normal Call Clearing */);
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);

	dtap_expect_tx("832d" /* CC: Release */);
	mncc_sends_to_cc(MNCC_REL_REQ, &mncc);
	OSMO_ASSERT(dtap_tx_confirmed);

	cc_to_mncc_expect_tx("", MNCC_REL_CNF);
	expect_iu_release();
	ms_sends_msg("036a" /* CC: Release Complete */);
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);
	OSMO_ASSERT(iu_release_sent);

	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

static void test_call_mt()
{
	struct gsm_mncc mncc = {
		.imsi = IMSI,
		.callref = 0x423,
		.fields = MNCC_F_BEARER_CAP,
		.bearer_cap = {
			.speech_ver = {
				GSM48_BCAP_SV_AMR_F,
				GSM48_BCAP_SV_EFR,
				GSM48_BCAP_SV_FR,
				GSM48_BCAP_SV_AMR_H,
				GSM48_BCAP_SV_HR,
				-1 },
		},
		/* NOTE: below SDP includes only AMR, above bearer_cap includes more codecs. Ideally, these would match,
		 * but in reality the bearer cap in MNCC was never implemented properly. This test shows that above
		 * bearer_cap is ignored when SDP is present: In the CC Setup below, the Bearer Capability is only
		 * "04 03 60 04 85" with speech versions '04' == GSM48_BCAP_SV_AMR_F and '05' == GSM48_BCAP_SV_AMR_H.
		 */
		.sdp = "v=0\r\n"
		       "o=OsmoMSC 0 0 IN IP4 10.23.23.1\r\n"
		       "s=GSM Call\r\n"
		       "c=IN IP4 10.23.23.1\r\n"
		       "t=0 0\r\n"
		       "m=audio 23 RTP/AVP 112\r\n"
		       "a=rtpmap:112 AMR/8000\r\n"
		       "a=fmtp:112 octet-align=1\r\n"
		       "a=ptime:20\r\n",
	};

	struct gsm_mncc_rtp mncc_rtp = {
		.callref = 0x423,
	};

	comment_start();

	fake_time_start();

	lu_utran_tmsi();

	BTW("after a while, MNCC asks us to setup a call, causing Paging");

	paging_expect_imsi(IMSI);
	paging_sent = false;
	mncc_sends_to_cc(MNCC_SETUP_REQ, &mncc);
	mncc.sdp[0] = '\0';

	VERBOSE_ASSERT(paging_sent, == true, "%d");

	btw("MS replies with Paging Response, and VLR sends Auth Request");
	auth_request_sent = false;
	auth_request_expect_rand = "c187a53a5e6b9d573cac7c74451fd46d";
	auth_request_expect_autn = "1843a645b98d00005b2d666af46c45d9";
	ms_sends_msg("062707"
		     "03575886" /* classmark 2 */
		     "089910070000106005" /* IMSI */);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");

	btw("MS sends Authen Response, VLR accepts and sends SecurityModeControl");
	expect_security_mode_ctrl(NULL, "1159ec926a50e98c034a6b7d7c9f418d");
	ms_sends_msg("0554" "7db47cf7" "2104" "f81e4dc7"); /* 2nd vector's res, s.a. */
	VERBOSE_ASSERT(security_mode_ctrl_sent, == true, "%d");

	btw("MS sends SecurityModeControl acceptance, VLR accepts, sends CC Setup");
	dtap_expect_tx("0305" /* CC: Setup */ "04 03 60 04 85" /* Bearer Cap, speech ver of AMR-FR and AMR-HR */);
	ms_sends_security_mode_complete(1);

	btw("MS confirms call, we create a RAN-side RTP and forward MNCC_CALL_CONF_IND");
	expect_crcx(RTP_TO_CN);
	expect_crcx(RTP_TO_RAN);
	cc_to_mncc_expect_tx(IMSI, MNCC_CALL_CONF_IND);
	ms_sends_msg("8348" /* CC: Call Confirmed */
		     "0406600402000581" /* Bearer Capability */
		     "15020100" /* Call Control Capabilities */
		     "40080402600400021f00" /* Supported Codec List */);
	OSMO_ASSERT(crcx_scheduled(RTP_TO_CN));
	OSMO_ASSERT(crcx_scheduled(RTP_TO_RAN));
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);

	btw("MGW acknowledges the CRCX to RAN, triggering Assignment");
	expect_iu_rab_assignment();
	crcx_ok(RTP_TO_RAN);
	OSMO_ASSERT(iu_rab_assignment_sent);

	btw("Assignment completes, triggering CRCX to CN");
	expect_crcx(RTP_TO_CN);
	ms_sends_assignment_complete(true, "AMR:octet-align=1");

	btw("MNCC sends MNCC_RTP_CREATE, which first waits for the CN side RTP");
	mncc_sends_to_cc(MNCC_RTP_CREATE, &mncc_rtp);

	btw("When the CN side RTP address is known, ack MNCC_RTP_CREATE with full SDP");
	cc_to_mncc_expect_tx("", MNCC_RTP_CREATE);
	crcx_ok(RTP_TO_CN);
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);

	fake_time_passes(1, 23);

	cc_to_mncc_expect_tx("", MNCC_ALERT_IND);
	ms_sends_msg("8381" /* CC: Alerting */);
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);

	fake_time_passes(1, 23);

	cc_to_mncc_expect_tx(IMSI, MNCC_SETUP_CNF);
	ms_sends_msg("83c7" /* CC: Connect */);
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);

	dtap_expect_tx("030f" /* CC: Connect Acknowledge */);
	mncc_sends_to_cc(MNCC_SETUP_COMPL_REQ, &mncc);

	BTW("RTP stream goes ahead, not shown here.");
	fake_time_passes(123, 45);

	BTW("Call ends");
	cc_to_mncc_expect_tx("", MNCC_DISC_IND);
	ms_sends_msg("832502e090" /* CC: Disconnect, cause: Normal Call Clearing */);
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);

	dtap_expect_tx("032d" /* CC: Release */);
	mncc_sends_to_cc(MNCC_REL_REQ, &mncc);
	OSMO_ASSERT(dtap_tx_confirmed);

	cc_to_mncc_expect_tx("", MNCC_REL_CNF);
	expect_iu_release();
	ms_sends_msg("836a" /* CC: Release Complete */);
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);
	OSMO_ASSERT(iu_release_sent);

	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

static void test_call_mt2()
{
	struct gsm_mncc mncc = {
		.imsi = IMSI,
		.callref = 0x423,
		.fields = MNCC_F_BEARER_CAP,
		.bearer_cap = {
			.speech_ver = { GSM48_BCAP_SV_FR, -1, },
		},
		/* NOTE: below SDP includes only AMR, above bearer_cap includes only GSM-FR. Ideally, these would match,
		 * but in reality the bearer cap in MNCC was never implemented properly. This test shows that above
		 * bearer_cap is ignored when SDP is present: In the CC Setup below, the Bearer Capability is only
		 * "04 03 60 04 85" with speech versions '04' == GSM48_BCAP_SV_AMR_F and '05' == GSM48_BCAP_SV_AMR_H.
		 */
		.sdp = "v=0\r\n"
		       "o=OsmoMSC 0 0 IN IP4 10.23.23.1\r\n"
		       "s=GSM Call\r\n"
		       "c=IN IP4 10.23.23.1\r\n"
		       "t=0 0\r\n"
		       "m=audio 23 RTP/AVP 112\r\n"
		       "a=rtpmap:112 AMR/8000\r\n"
		       "a=fmtp:112 octet-align=1\r\n"
		       "a=ptime:20\r\n",
	};

	struct gsm_mncc_rtp mncc_rtp = {
		.callref = 0x423,
		.sdp = "v=0\r\n"
		       "o=OsmoMSC 0 0 IN IP4 10.23.23.1\r\n"
		       "s=GSM Call\r\n"
		       "c=IN IP4 10.23.23.1\r\n"
		       "t=0 0\r\n"
		       "m=audio 23 RTP/AVP 112\r\n"
		       "a=rtpmap:112 AMR/8000\r\n"
		       "a=fmtp:112 octet-align=1\r\n"
		       "a=ptime:20\r\n",
	};

	comment_start();

	fake_time_start();

	lu_utran_tmsi();

	BTW("after a while, MNCC asks us to setup a call, causing Paging");

	paging_expect_imsi(IMSI);
	paging_sent = false;
	mncc_sends_to_cc(MNCC_SETUP_REQ, &mncc);

	VERBOSE_ASSERT(paging_sent, == true, "%d");

	btw("MS replies with Paging Response, and VLR sends Auth Request");
	auth_request_sent = false;
	auth_request_expect_rand = "c187a53a5e6b9d573cac7c74451fd46d";
	auth_request_expect_autn = "1843a645b98d00005b2d666af46c45d9";
	ms_sends_msg("062707"
		     "03575886" /* classmark 2 */
		     "089910070000106005" /* IMSI */);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");

	btw("MS sends Authen Response, VLR accepts and sends SecurityModeControl");
	expect_security_mode_ctrl(NULL, "1159ec926a50e98c034a6b7d7c9f418d");
	ms_sends_msg("0554" "7db47cf7" "2104" "f81e4dc7"); /* 2nd vector's res, s.a. */
	VERBOSE_ASSERT(security_mode_ctrl_sent, == true, "%d");

	btw("MS sends SecurityModeControl acceptance, VLR accepts, sends CC Setup");
	dtap_expect_tx("0305" /* CC: Setup */ "04 03 60 04 85" /* Bearer Cap, speech ver of AMR-FR and AMR-HR */);
	ms_sends_security_mode_complete(1);

	btw("MS confirms call, we create a RAN-side RTP and forward MNCC_CALL_CONF_IND");
	expect_crcx(RTP_TO_CN);
	expect_crcx(RTP_TO_RAN);
	cc_to_mncc_expect_tx(IMSI, MNCC_CALL_CONF_IND);
	ms_sends_msg("8348" /* CC: Call Confirmed */
		     "0406600402000581" /* Bearer Capability */
		     "15020100" /* Call Control Capabilities */
		     "40080402600400021f00" /* Supported Codec List */);
	OSMO_ASSERT(crcx_scheduled(RTP_TO_CN));
	OSMO_ASSERT(crcx_scheduled(RTP_TO_RAN));
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);

	btw("MNCC sends MNCC_RTP_CREATE, which first waits for the CN side RTP");
	mncc_sends_to_cc(MNCC_RTP_CREATE, &mncc_rtp);

	btw("MGW acknowledges the CRCX to RAN, triggering Assignment");
	expect_iu_rab_assignment();
	crcx_ok(RTP_TO_RAN);
	OSMO_ASSERT(iu_rab_assignment_sent);

	btw("Assignment completes, triggering CRCX to CN");
	ms_sends_assignment_complete(true, "AMR:octet-align=1");

	btw("When the CN side RTP address is known, ack MNCC_RTP_CREATE with full SDP");
	cc_to_mncc_expect_tx("", MNCC_RTP_CREATE);
	crcx_ok(RTP_TO_CN);
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);

	fake_time_passes(1, 23);

	cc_to_mncc_expect_tx("", MNCC_ALERT_IND);
	ms_sends_msg("8381" /* CC: Alerting */);
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);

	fake_time_passes(15, 23);

	btw("The call failed, the BSC sends a BSSMAP Clear Request");
	cc_to_mncc_expect_tx("", MNCC_REL_IND);
	dtap_expect_tx("032d0802e1af"); /* CC: Release */
	expect_iu_release();
	msc_a_release_cn(msub_msc_a(g_msub));
	OSMO_ASSERT(dtap_tx_confirmed);
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);
	OSMO_ASSERT(iu_release_sent);

	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	/* Make sure a pending release timer doesn't fire later to access freed data */
	fake_time_passes(15, 23);

	clear_vlr();
	comment_end();
}

static void test_call_mo_to_unknown()
{
	struct gsm_mncc mncc = {
		.imsi = IMSI,
	};

	struct gsm_mncc_rtp mncc_rtp = {};

	comment_start();

	fake_time_start();

	lu_utran_tmsi();

	BTW("after a while, a new conn sends a CM Service Request. VLR responds with Auth Req, 2nd auth vector");
	auth_request_sent = false;
	auth_request_expect_rand = "c187a53a5e6b9d573cac7c74451fd46d";
	auth_request_expect_autn = "1843a645b98d00005b2d666af46c45d9";
	cm_service_result_sent = RES_NONE;
	ms_sends_msg("052471"
		     "03575886" /* classmark 2 */
		     "089910070000106005" /* IMSI */);
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");

	btw("needs auth, not yet accepted");
	EXPECT_ACCEPTED(false);

	/* On UTRAN */
	btw("MS sends Authen Response, VLR accepts and sends SecurityModeControl");
	expect_security_mode_ctrl(NULL, "1159ec926a50e98c034a6b7d7c9f418d");
	ms_sends_msg("0554" "7db47cf7" "2104" "f81e4dc7"); /* 2nd vector's res, s.a. */
	VERBOSE_ASSERT(security_mode_ctrl_sent, == true, "%d");
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");

	btw("MS sends SecurityModeControl acceptance, VLR accepts; above Ciphering is an implicit CM Service Accept");
	ms_sends_security_mode_complete(1);
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");

	BTW("a call is initiated");

	btw("CC SETUP causes CRCX towards CN and RAN");
	expect_crcx(RTP_TO_CN);
	expect_crcx(RTP_TO_RAN);
	ms_sends_msg("0385" /* CC, seq = 2 -> 0x80 | CC Setup = 0x5 */
		     "0406600402000581" /* Bearer Capability */
		     "5e038121f3" /* Called Number BCD */
		     "15020100" /* CC Capabilities */
		     "4008" /* Supported Codec List */
		       "04026000" /* UMTS: AMR 2 | AMR */
		       "00021f00" /* GSM: HR AMR | FR AMR | GSM EFR | GSM HR | GSM FR */
		    );
	OSMO_ASSERT(crcx_scheduled(RTP_TO_CN));
	OSMO_ASSERT(crcx_scheduled(RTP_TO_RAN));

	btw("As soon as the MGW port towards CN is created, MNCC_SETUP_IND is triggered");
	cc_to_mncc_expect_tx(IMSI, MNCC_SETUP_IND);
	crcx_ok(RTP_TO_CN);
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);
	mncc.callref = mncc_rtp.callref = cc_to_mncc_tx_got_callref;

	btw("MNCC replies with MNCC_RTP_CREATE");
	mncc_sends_to_cc(MNCC_RTP_CREATE, &mncc_rtp);

	btw("MGW acknowledges the CRCX, triggering Assignment");
	expect_iu_rab_assignment();
	crcx_ok(RTP_TO_RAN);
	OSMO_ASSERT(iu_rab_assignment_sent);

	btw("Assignment succeeds, triggering MNCC_RTP_CREATE ack to MNCC");
	cc_to_mncc_expect_tx("", MNCC_RTP_CREATE);
	ms_sends_assignment_complete(true, "AMR:octet-align=1");
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);

	btw("MNCC says that's fine");
	dtap_expect_tx("8302" /* CC: Call Proceeding */);
	mncc_sends_to_cc(MNCC_CALL_PROC_REQ, &mncc);
	OSMO_ASSERT(dtap_tx_confirmed);

	btw("But the other side's MSISDN could not be resolved, MNCC tells us to cancel");
	dtap_expect_tx("832d" /* CC: Release Request */);
	mncc_sends_to_cc(MNCC_REL_REQ, &mncc);

	dtap_expect_tx("832d" /* CC: Release Request */);
	fake_time_passes(10, 23);

	expect_iu_release();
	cc_to_mncc_expect_tx("", MNCC_REL_CNF);
	ms_sends_msg("036a" /* CC: Release Complete */);
	OSMO_ASSERT(iu_release_sent);
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);

	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

static void test_call_mo_to_unknown_timeout()
{
	struct gsm_mncc mncc = {
		.imsi = IMSI,
	};
	struct gsm_mncc_rtp mncc_rtp = {};

	comment_start();

	fake_time_start();

	lu_utran_tmsi();

	BTW("after a while, a new conn sends a CM Service Request. VLR responds with Auth Req, 2nd auth vector");
	auth_request_sent = false;
	auth_request_expect_rand = "c187a53a5e6b9d573cac7c74451fd46d";
	auth_request_expect_autn = "1843a645b98d00005b2d666af46c45d9";
	cm_service_result_sent = RES_NONE;
	ms_sends_msg("052471"
		     "03575886" /* classmark 2 */
		     "089910070000106005" /* IMSI */);
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");

	btw("needs auth, not yet accepted");
	EXPECT_ACCEPTED(false);

	/* On UTRAN */
	btw("MS sends Authen Response, VLR accepts and sends SecurityModeControl");
	expect_security_mode_ctrl(NULL, "1159ec926a50e98c034a6b7d7c9f418d");
	ms_sends_msg("0554" "7db47cf7" "2104" "f81e4dc7"); /* 2nd vector's res, s.a. */
	VERBOSE_ASSERT(security_mode_ctrl_sent, == true, "%d");
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");

	btw("MS sends SecurityModeControl acceptance, VLR accepts; above Ciphering is an implicit CM Service Accept");
	ms_sends_security_mode_complete(1);
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");

	BTW("a call is initiated");

	btw("CC SETUP causes CRCX towards CN and RAN");
	expect_crcx(RTP_TO_CN);
	expect_crcx(RTP_TO_RAN);
	ms_sends_msg("0385" /* CC, seq = 2 -> 0x80 | CC Setup = 0x5 */
		     "0406600402000581" /* Bearer Capability */
		     "5e038121f3" /* Called Number BCD */
		     "15020100" /* CC Capabilities */
		     "4008" /* Supported Codec List */
		       "04026000" /* UMTS: AMR 2 | AMR */
		       "00021f00" /* GSM: HR AMR | FR AMR | GSM EFR | GSM HR | GSM FR */
		    );
	OSMO_ASSERT(crcx_scheduled(RTP_TO_CN));
	OSMO_ASSERT(crcx_scheduled(RTP_TO_RAN));

	btw("As soon as the MGW port towards CN is created, MNCC_SETUP_IND is triggered");
	cc_to_mncc_expect_tx(IMSI, MNCC_SETUP_IND);
	crcx_ok(RTP_TO_CN);
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);
	mncc.callref = mncc_rtp.callref = cc_to_mncc_tx_got_callref;

	btw("MNCC replies with MNCC_RTP_CREATE");
	mncc_sends_to_cc(MNCC_RTP_CREATE, &mncc_rtp);

	btw("MGW acknowledges the CRCX, triggering Assignment");
	expect_iu_rab_assignment();
	crcx_ok(RTP_TO_RAN);
	OSMO_ASSERT(iu_rab_assignment_sent);

	btw("Assignment succeeds, triggering MNCC_RTP_CREATE ack to MNCC");
	cc_to_mncc_expect_tx("", MNCC_RTP_CREATE);
	ms_sends_assignment_complete(true, "AMR:octet-align=1");
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);

	btw("MNCC says that's fine");
	dtap_expect_tx("8302" /* CC: Call Proceeding */);
	mncc_sends_to_cc(MNCC_CALL_PROC_REQ, &mncc);
	OSMO_ASSERT(dtap_tx_confirmed);

	btw("But the other side's MSISDN could not be resolved, MNCC tells us to cancel");
	dtap_expect_tx("832d" /* CC: Release Request */);
	mncc_sends_to_cc(MNCC_REL_REQ, &mncc);

	btw("Despite our repeated CC Release Requests, the MS does not respond anymore");
	dtap_expect_tx("832d" /* CC: Release Request */);
	fake_time_passes(10, 23);

	btw("The CC Release times out and we still properly clear the conn");
	cc_to_mncc_expect_tx("", MNCC_REL_CNF);
	expect_iu_release();
	fake_time_passes(10, 23);
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);
	OSMO_ASSERT(iu_release_sent);

	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

#define LIST_END 0xffff

struct codec_test {
	const char *desc;

	/* What to send during Complete Layer 3 as Codec List (BSS Supported). List ends with a LIST_END entry */
	struct gsm0808_speech_codec mo_rx_compl_l3_codec_list_bss_supported[8];

	/* What to send during CC Setup as MS Bearer Capability. List ends with a LIST_END entry */
	enum gsm48_bcap_speech_ver mo_rx_ms_bcap[8];

	/* What codecs should osmo-msc send in the MNCC_SETUP_IND message.
	 * Just the SDP subtype names like "GSM", "GSM-EFR", "AMR", ..., list ends with NULL entry */
	const char *mo_tx_sdp_mncc_setup_ind[16];

	/* What codecs the remote call leg should send as SDP via MNCC during MNCC_RTP_CREATE (if any). */
	const char *mo_rx_sdp_mncc_rtp_create[16];

	/* What the MSC should send as Channel Type IE in the Assignment Command to the BSS. List ends with a
	 * LIST_END entry */
	enum gsm0808_permitted_speech mo_tx_assignment_perm_speech[8];

	/* What codec to assign in the Assignment Complete's Codec (Chosen) IE. Just a subtype name. */
	bool mo_rx_assigned_codec_fr;
	const char *mo_rx_assigned_codec;

	/* MO acks the MNCC_RTP_CREATE with these codecs (if any). */
	const char *mo_tx_sdp_mncc_rtp_create[16];
	bool mo_tx__ignore_pt_nrs;

	/* mt_rx_sdp_mncc_setup_req == mo_tx_sdp_mncc_rtp_create */
#define mt_rx_sdp_mncc_setup_req  mo_tx_sdp_mncc_rtp_create

	struct gsm0808_speech_codec mt_rx_compl_l3_codec_list_bss_supported[8];
	bool expect_codec_mismatch_on_paging_response;
	enum gsm48_bcap_speech_ver mt_tx_cc_setup_bcap[8];
	enum gsm48_bcap_speech_ver mt_rx_ms_bcap[8];
	bool expect_codec_mismatch_on_cc_call_conf;
	const char *mt_tx_sdp_mncc_call_conf_ind[16];

	enum gsm0808_permitted_speech mt_tx_assignment_perm_speech[8];
	bool mt_rx_assigned_codec_fr;
	const char *mt_rx_assigned_codec;

	const char *mt_rx_sdp_mncc_rtp_create[16];

	const char *mt_tx_sdp_mncc_rtp_create[16];
	const char *mt_tx_sdp_mncc_alert_ind[16];
	bool mt_tx__ignore_pt_nrs;

	bool mo_expect_reassignment;
	enum gsm0808_permitted_speech mo_tx_reassignment_perm_speech[8];
	bool mo_rx_reassigned_codec_fr;
	const char *mo_rx_reassigned_codec;

	const char *mt_tx_sdp_mncc_setup_cnf[16];
	const char *mt_rx_sdp_mncc_setup_compl_req[16];

	/* mo_rx_sdp_mncc_alert_req == mt_tx_sdp_mncc_alert_ind */
#define mo_rx_sdp_mncc_alert_req  mt_tx_sdp_mncc_alert_ind
#define mo_rx_sdp_mncc_setup_rsp  mt_tx_sdp_mncc_alert_ind

	const char *mo_tx_sdp_mncc_setup_compl_ind[16];
};

/* define a struct gsm0808_speech_codec */
#define SC(TYPE, CFG) { .fi = true, .type = TYPE, .cfg = CFG }

/* define a struct gsm0808_speech_codec list[] */
#define CODEC_LIST_ALL_GSM { \
			SC(GSM0808_SCT_FR1, 0), \
			SC(GSM0808_SCT_FR2, 0), \
			SC(GSM0808_SCT_FR3, GSM0808_SC_CFG_DEFAULT_FR_AMR), \
			SC(GSM0808_SCT_HR1, 0), \
			SC(GSM0808_SCT_HR3, GSM0808_SC_CFG_DEFAULT_HR_AMR), \
		}

#define BCAP_ALL_GSM { \
			GSM48_BCAP_SV_AMR_F, \
			GSM48_BCAP_SV_AMR_H, \
			GSM48_BCAP_SV_EFR, \
			GSM48_BCAP_SV_FR, \
			GSM48_BCAP_SV_HR, \
			LIST_END \
		}

#define BCAP_ALL_GSM_AMR_HR_FIRST { \
			GSM48_BCAP_SV_AMR_H, \
			GSM48_BCAP_SV_AMR_F, \
			GSM48_BCAP_SV_EFR, \
			GSM48_BCAP_SV_FR, \
			GSM48_BCAP_SV_HR, \
			LIST_END \
		}

#define PERM_SPEECH_ALL_GSM { \
			GSM0808_PERM_FR3, \
			GSM0808_PERM_HR3, \
			GSM0808_PERM_FR2, \
			GSM0808_PERM_FR1, \
			GSM0808_PERM_HR1, \
			LIST_END \
		}

#define PERM_SPEECH_ALL_GSM_HR3_FIRST { \
			GSM0808_PERM_HR3, \
			GSM0808_PERM_FR3, \
			GSM0808_PERM_FR2, \
			GSM0808_PERM_FR1, \
			GSM0808_PERM_HR1, \
			LIST_END \
		}

#define SDP_CODECS_ALL_GSM \
	{ \
		"AMR:octet-align=1;mode-set=0,2,4,7#112", \
		"AMR:octet-align=1;mode-set=0,2,4#114", \
		"AMR:mode-set=0,2,4,7#115", \
		"AMR:mode-set=0,2,4#116", \
		"GSM-EFR#110", \
		"GSM#3", \
		"GSM-HR-08#111", \
	}

#define SDP_CODECS_ALL_GSM_WITH_ODD_PT_NRS \
	{ \
		"AMR:octet-align=1;mode-set=0,2,4,7#127", \
		"AMR:octet-align=1;mode-set=0,2,4#126", \
		"AMR:mode-set=0,2,4,7#125", \
		"AMR:mode-set=0,2,4#124", \
		"GSM-EFR#110", \
		"GSM#3", \
		"GSM-HR-08#111", \
	}

/* same as SDP_CODECS_ALL_GSM, but AMR-HR octet-align=1 listed as first entry */
#define SDP_CODECS_ALL_GSM_AMR_HR_FIRST \
	{ \
		"AMR:octet-align=1;mode-set=0,2,4#114", \
		"AMR:octet-align=1;mode-set=0,2,4,7#112", \
		"AMR:mode-set=0,2,4,7#115", \
		"AMR:mode-set=0,2,4#116", \
		"GSM-EFR#110", \
		"GSM#3", \
		"GSM-HR-08#111", \
	}

static const struct codec_test codec_tests[] = {
	{
		.desc = "AMR picked by both MO and MT",
		.mo_rx_compl_l3_codec_list_bss_supported = CODEC_LIST_ALL_GSM,
		.mo_rx_ms_bcap = BCAP_ALL_GSM,
		.mo_tx_sdp_mncc_setup_ind = SDP_CODECS_ALL_GSM,
		.mo_rx_sdp_mncc_rtp_create = {},
		.mo_tx_assignment_perm_speech = PERM_SPEECH_ALL_GSM,
		.mo_rx_assigned_codec_fr = true,
		.mo_rx_assigned_codec = "AMR",
		.mo_tx_sdp_mncc_rtp_create = SDP_CODECS_ALL_GSM,
		/* mt_rx_sdp_mncc_setup_req == mo_tx_sdp_mncc_rtp_create */
		.mt_rx_compl_l3_codec_list_bss_supported = CODEC_LIST_ALL_GSM,
		.mt_tx_cc_setup_bcap = {
			GSM48_BCAP_SV_AMR_F,
			GSM48_BCAP_SV_AMR_H,
			GSM48_BCAP_SV_EFR,
			GSM48_BCAP_SV_FR,
			GSM48_BCAP_SV_HR,
			LIST_END
		},
		.mt_rx_ms_bcap = BCAP_ALL_GSM,
		.mt_tx_sdp_mncc_call_conf_ind = {},
		.mt_rx_sdp_mncc_rtp_create = {},
		.mt_tx_assignment_perm_speech = PERM_SPEECH_ALL_GSM,
		.mt_rx_assigned_codec_fr = true,
		.mt_rx_assigned_codec = "AMR",
		.mt_tx_sdp_mncc_rtp_create = SDP_CODECS_ALL_GSM,
		.mt_tx_sdp_mncc_alert_ind = SDP_CODECS_ALL_GSM,
		.mt_tx_sdp_mncc_setup_cnf = SDP_CODECS_ALL_GSM,
		.mo_tx_sdp_mncc_setup_compl_ind = {},
	},

	{
		.desc = "FR1 picked by MO from Codec List (BSS Supported), MT hence also picks FR1",
		.mo_rx_compl_l3_codec_list_bss_supported = { SC(GSM0808_SCT_FR1, 0) },
		.mo_rx_ms_bcap = BCAP_ALL_GSM,
		.mo_tx_sdp_mncc_setup_ind = { "GSM#3" },
		.mo_rx_sdp_mncc_rtp_create = {},
		.mo_tx_assignment_perm_speech = { GSM0808_PERM_FR1, LIST_END },
		.mo_rx_assigned_codec_fr = true,
		.mo_rx_assigned_codec = "GSM",
		.mo_tx_sdp_mncc_rtp_create = { "GSM#3" },
		/* mt_rx_sdp_mncc_setup_req == mo_tx_sdp_mncc_rtp_create */
		.mt_rx_compl_l3_codec_list_bss_supported = CODEC_LIST_ALL_GSM,
		.mt_tx_cc_setup_bcap = { GSM48_BCAP_SV_FR, LIST_END },
		.mt_rx_ms_bcap = BCAP_ALL_GSM,
		.mt_tx_sdp_mncc_call_conf_ind = {},
		.mt_rx_sdp_mncc_rtp_create = {},
		.mt_tx_assignment_perm_speech = { GSM0808_PERM_FR1, LIST_END },
		.mt_rx_assigned_codec_fr = true,
		.mt_rx_assigned_codec = "GSM",
		.mt_tx_sdp_mncc_rtp_create = { "GSM#3" },
		.mt_tx_sdp_mncc_alert_ind = { "GSM#3" },
		.mt_tx_sdp_mncc_setup_cnf = { "GSM#3" },
		.mo_tx_sdp_mncc_setup_compl_ind = {},
	},

	{
		.desc = "FR1 picked by MO from Bearer Cap, MT hence also picks FR1",
		.mo_rx_compl_l3_codec_list_bss_supported = CODEC_LIST_ALL_GSM,
		.mo_rx_ms_bcap = { GSM48_BCAP_SV_FR, LIST_END },
		.mo_tx_sdp_mncc_setup_ind = { "GSM#3" },
		.mo_rx_sdp_mncc_rtp_create = {},
		.mo_tx_assignment_perm_speech = { GSM0808_PERM_FR1, LIST_END },
		.mo_rx_assigned_codec_fr = true,
		.mo_rx_assigned_codec = "GSM",
		.mo_tx_sdp_mncc_rtp_create = { "GSM#3" },
		/* mt_rx_sdp_mncc_setup_req == mo_tx_sdp_mncc_rtp_create */
		.mt_rx_compl_l3_codec_list_bss_supported = CODEC_LIST_ALL_GSM,
		.mt_tx_cc_setup_bcap = { GSM48_BCAP_SV_FR, LIST_END },
		.mt_rx_ms_bcap = BCAP_ALL_GSM,
		.mt_tx_sdp_mncc_call_conf_ind = {},
		.mt_rx_sdp_mncc_rtp_create = {},
		.mt_tx_assignment_perm_speech = { GSM0808_PERM_FR1, LIST_END },
		.mt_rx_assigned_codec_fr = true,
		.mt_rx_assigned_codec = "GSM",
		.mt_tx_sdp_mncc_rtp_create = { "GSM#3" },
		.mt_tx_sdp_mncc_alert_ind = { "GSM#3" },
		.mt_tx_sdp_mncc_setup_cnf = { "GSM#3" },
		.mo_tx_sdp_mncc_setup_compl_ind = {},
	},

	{
		.desc = "FR1 picked by MT's Codec List (BSS Supported), hence MO re-assigns to FR1",
		.mo_rx_compl_l3_codec_list_bss_supported = CODEC_LIST_ALL_GSM,
		.mo_rx_ms_bcap = BCAP_ALL_GSM,
		.mo_tx_sdp_mncc_setup_ind = SDP_CODECS_ALL_GSM,
		.mo_rx_sdp_mncc_rtp_create = {},
		.mo_tx_assignment_perm_speech = PERM_SPEECH_ALL_GSM,
		.mo_rx_assigned_codec_fr = true,
		.mo_rx_assigned_codec = "AMR", /* <- Early Assignment first picks a mismatching codec */
		.mo_tx_sdp_mncc_rtp_create = SDP_CODECS_ALL_GSM,

		/* This is the codec limitation this test verifies, Codec List (BSS Supported): */
		.mt_rx_compl_l3_codec_list_bss_supported = { SC(GSM0808_SCT_FR1, 0) },

		/* from above codec list, MSC derives the limited bcap sent in CC Setup to MS */
		.mt_tx_cc_setup_bcap = {
			GSM48_BCAP_SV_FR,
			LIST_END
		},
		/* MS could do more, but it doesn't affect the choice of FR1 */
		.mt_rx_ms_bcap = BCAP_ALL_GSM,
		.mt_tx_sdp_mncc_call_conf_ind = {},
		.mt_rx_sdp_mncc_rtp_create = {},
		.mt_tx_assignment_perm_speech = {
			GSM0808_PERM_FR1,
			LIST_END
		},
		.mt_rx_assigned_codec_fr = true,
		.mt_rx_assigned_codec = "GSM",
		.mt_tx_sdp_mncc_rtp_create = { "GSM#3" },
		.mt_tx_sdp_mncc_alert_ind = { "GSM#3" },

		.mo_expect_reassignment = true,
		.mo_tx_reassignment_perm_speech = {
			GSM0808_PERM_FR1,
			LIST_END
		},
		.mo_rx_reassigned_codec_fr = true,
		.mo_rx_reassigned_codec = "GSM",

		.mt_tx_sdp_mncc_setup_cnf = { "GSM#3" },
		.mo_tx_sdp_mncc_setup_compl_ind = {},
	},

	{
		.desc = "FR1 picked by MT's MS Bearer Capability, hence MO re-assigns to FR1",
		.mo_rx_compl_l3_codec_list_bss_supported = CODEC_LIST_ALL_GSM,
		.mo_rx_ms_bcap = BCAP_ALL_GSM,
		.mo_tx_sdp_mncc_setup_ind = SDP_CODECS_ALL_GSM,
		.mo_rx_sdp_mncc_rtp_create = {},
		.mo_tx_assignment_perm_speech = PERM_SPEECH_ALL_GSM,
		.mo_rx_assigned_codec_fr = true,
		.mo_rx_assigned_codec = "AMR", /* <- Early Assignment first picks a mismatching codec */
		.mo_tx_sdp_mncc_rtp_create = SDP_CODECS_ALL_GSM,

		.mt_rx_compl_l3_codec_list_bss_supported = CODEC_LIST_ALL_GSM,
		.mt_tx_cc_setup_bcap = BCAP_ALL_GSM,

		/* This is the codec limitation this test verifies: */
		.mt_rx_ms_bcap = {
			GSM48_BCAP_SV_FR,
			LIST_END
		},
		.mt_tx_sdp_mncc_call_conf_ind = {},
		.mt_rx_sdp_mncc_rtp_create = {},
		.mt_tx_assignment_perm_speech = {
			GSM0808_PERM_FR1,
			LIST_END
		},
		.mt_rx_assigned_codec_fr = true,
		.mt_rx_assigned_codec = "GSM",
		.mt_tx_sdp_mncc_rtp_create = { "GSM#3" },
		.mt_tx_sdp_mncc_alert_ind = { "GSM#3" },

		.mo_expect_reassignment = true,
		.mo_tx_reassignment_perm_speech = {
			GSM0808_PERM_FR1,
			LIST_END
		},
		.mo_rx_reassigned_codec_fr = true,
		.mo_rx_reassigned_codec = "GSM",

		.mt_tx_sdp_mncc_setup_cnf = { "GSM#3" },
		.mo_tx_sdp_mncc_setup_compl_ind = {},
	},

	{
		.desc = "AMR picked by both MO and MT, but MT assigns a different payload type number",
		.mo_rx_compl_l3_codec_list_bss_supported = CODEC_LIST_ALL_GSM,
		.mo_rx_ms_bcap = BCAP_ALL_GSM,
		.mo_tx_sdp_mncc_setup_ind = SDP_CODECS_ALL_GSM,
		.mo_rx_sdp_mncc_rtp_create = {},
		.mo_tx_assignment_perm_speech = PERM_SPEECH_ALL_GSM,
		.mo_rx_assigned_codec_fr = true,
		.mo_rx_assigned_codec = "AMR",
		.mo_tx_sdp_mncc_rtp_create = SDP_CODECS_ALL_GSM,
		/* mt_rx_sdp_mncc_setup_req == mo_tx_sdp_mncc_rtp_create */
		.mt_rx_compl_l3_codec_list_bss_supported = CODEC_LIST_ALL_GSM,
		.mt_tx_cc_setup_bcap = BCAP_ALL_GSM,
		.mt_rx_ms_bcap = BCAP_ALL_GSM,
		.mt_tx_sdp_mncc_call_conf_ind = {},
		.mt_rx_sdp_mncc_rtp_create = {},
		.mt_tx_assignment_perm_speech = PERM_SPEECH_ALL_GSM,
		.mt_rx_assigned_codec_fr = true,
		.mt_rx_assigned_codec = "AMR",

		/* We want to test how osmo-msc reacts to a peer using different payload type nrs. So below SDP string
		 * features odd numbers that osmo-msc would never pick.
		 * But, the below SDP string serves two purposes:
		 * - feed this to osmo-msc when it is MO.
		 * - *validate* what osmo-msc sends when it is MT.
		 * The validation step will fail on the MT side, but we still want to feed this SDP to MO.
		 * By the flag ...__ignore_pt_nrs = true, we skip validation of the payload type numbers and can pass
		 * this SDP without the test failing.
		 */
		.mt_tx_sdp_mncc_rtp_create = SDP_CODECS_ALL_GSM_WITH_ODD_PT_NRS,
		.mt_tx__ignore_pt_nrs = true,

		.mt_tx_sdp_mncc_alert_ind = SDP_CODECS_ALL_GSM_WITH_ODD_PT_NRS,
		.mt_tx_sdp_mncc_setup_cnf = SDP_CODECS_ALL_GSM_WITH_ODD_PT_NRS,
		.mo_tx_sdp_mncc_setup_compl_ind = {},
	},

	{
		.desc = "AMR picked by both MO and MT, but MO assigns a different payload type number",
		.mo_rx_compl_l3_codec_list_bss_supported = CODEC_LIST_ALL_GSM,
		.mo_rx_ms_bcap = BCAP_ALL_GSM,
		.mo_tx_sdp_mncc_setup_ind = SDP_CODECS_ALL_GSM,
		.mo_rx_sdp_mncc_rtp_create = {},
		.mo_tx_assignment_perm_speech = PERM_SPEECH_ALL_GSM,
		.mo_rx_assigned_codec_fr = true,
		.mo_rx_assigned_codec = "AMR",
		/* We want to test how osmo-msc reacts to a peer using different payload type nrs. So below SDP string
		 * features odd numbers that osmo-msc would never pick.
		 * But, the below SDP string serves two purposes:
		 * - feed this to osmo-msc when it is MO.
		 * - *validate* what osmo-msc sends when it is MT.
		 * The validation step will fail on the MT side, but we still want to feed this SDP to MO.
		 * By the flag ...__ignore_pt_nrs = true, we skip validation of the payload type numbers and can pass
		 * this SDP without the test failing.
		 */
		.mo_tx_sdp_mncc_rtp_create = SDP_CODECS_ALL_GSM_WITH_ODD_PT_NRS,
		.mo_tx__ignore_pt_nrs = true,
		/* mt_rx_sdp_mncc_setup_req == mo_tx_sdp_mncc_rtp_create */
		.mt_rx_compl_l3_codec_list_bss_supported = CODEC_LIST_ALL_GSM,
		.mt_tx_cc_setup_bcap = BCAP_ALL_GSM,
		.mt_rx_ms_bcap = BCAP_ALL_GSM,
		.mt_tx_sdp_mncc_call_conf_ind = {},
		.mt_rx_sdp_mncc_rtp_create = {},
		.mt_tx_assignment_perm_speech = PERM_SPEECH_ALL_GSM,
		.mt_rx_assigned_codec_fr = true,
		.mt_rx_assigned_codec = "AMR",
		.mt_tx_sdp_mncc_rtp_create = SDP_CODECS_ALL_GSM_WITH_ODD_PT_NRS,
		.mt_tx_sdp_mncc_alert_ind = SDP_CODECS_ALL_GSM_WITH_ODD_PT_NRS,
		.mt_tx_sdp_mncc_setup_cnf = SDP_CODECS_ALL_GSM_WITH_ODD_PT_NRS,
		.mo_tx_sdp_mncc_setup_compl_ind = {},
	},

	{
		.desc = "AMR with rate limitations",
		.mo_rx_compl_l3_codec_list_bss_supported = CODEC_LIST_ALL_GSM,
		.mo_rx_ms_bcap = BCAP_ALL_GSM,
		.mo_tx_sdp_mncc_setup_ind = SDP_CODECS_ALL_GSM,
		.mo_rx_sdp_mncc_rtp_create = {},
		.mo_tx_assignment_perm_speech = PERM_SPEECH_ALL_GSM,
		.mo_rx_assigned_codec_fr = true,
		.mo_rx_assigned_codec = "AMR",
		.mo_tx_sdp_mncc_rtp_create = SDP_CODECS_ALL_GSM,
		/* mt_rx_sdp_mncc_setup_req == mo_tx_sdp_mncc_rtp_create */
		.mt_rx_compl_l3_codec_list_bss_supported = CODEC_LIST_ALL_GSM,
		.mt_tx_cc_setup_bcap = BCAP_ALL_GSM,
		.mt_rx_ms_bcap = BCAP_ALL_GSM,
		.mt_tx_sdp_mncc_call_conf_ind = {},
		.mt_rx_sdp_mncc_rtp_create = {},
		.mt_tx_assignment_perm_speech = PERM_SPEECH_ALL_GSM,
		.mt_rx_assigned_codec_fr = true,
		.mt_rx_assigned_codec = "AMR",
		.mt_tx_sdp_mncc_rtp_create = SDP_CODECS_ALL_GSM,
		.mt_tx_sdp_mncc_alert_ind = SDP_CODECS_ALL_GSM,
		.mt_tx_sdp_mncc_setup_cnf = SDP_CODECS_ALL_GSM,
		.mo_tx_sdp_mncc_setup_compl_ind = {},
	},

	{
		.desc = "MO on AMR-HR, MT on AMR-FR. See that the AMR modes are selected to match AMR-HR",
		.mo_rx_compl_l3_codec_list_bss_supported = CODEC_LIST_ALL_GSM,
		.mo_rx_ms_bcap = BCAP_ALL_GSM,
		.mo_tx_sdp_mncc_setup_ind = SDP_CODECS_ALL_GSM,
		.mo_rx_sdp_mncc_rtp_create = {},
		.mo_tx_assignment_perm_speech = PERM_SPEECH_ALL_GSM,
		.mo_rx_assigned_codec_fr = false,
		.mo_rx_assigned_codec = "AMR:octet-align=1;mode-set=0,2,4",
		.mo_tx_sdp_mncc_rtp_create = SDP_CODECS_ALL_GSM_AMR_HR_FIRST,
		/* mt_rx_sdp_mncc_setup_req == mo_tx_sdp_mncc_rtp_create */
		.mt_rx_compl_l3_codec_list_bss_supported = CODEC_LIST_ALL_GSM,
		/* HR is sent first in the CC Setup Bearer Capabilities */
		.mt_tx_cc_setup_bcap = BCAP_ALL_GSM_AMR_HR_FIRST,
		.mt_rx_ms_bcap = BCAP_ALL_GSM,
		.mt_tx_sdp_mncc_call_conf_ind = {},
		.mt_rx_sdp_mncc_rtp_create = {},
		.mt_tx_assignment_perm_speech = PERM_SPEECH_ALL_GSM_HR3_FIRST,
		.mt_rx_assigned_codec_fr = false,
		.mt_rx_assigned_codec = "AMR:octet-align=1;mode-set=0,2,4",
		.mt_tx_sdp_mncc_rtp_create = SDP_CODECS_ALL_GSM_AMR_HR_FIRST,
		.mt_tx_sdp_mncc_alert_ind = SDP_CODECS_ALL_GSM_AMR_HR_FIRST,
		/* mo_rx_sdp_mncc_alert_req == mt_tx_sdp_mncc_alert_ind */
		.mt_tx_sdp_mncc_setup_cnf = SDP_CODECS_ALL_GSM_AMR_HR_FIRST,
		.mo_tx_sdp_mncc_setup_compl_ind = {},
	},
	{
		.desc = "MO on AMR-FR, MT on AMR-HR. See that the AMR modes are selected to match AMR-HR",
		.mo_rx_compl_l3_codec_list_bss_supported = CODEC_LIST_ALL_GSM,
		.mo_rx_ms_bcap = BCAP_ALL_GSM,
		.mo_tx_sdp_mncc_setup_ind = SDP_CODECS_ALL_GSM,
		.mo_rx_sdp_mncc_rtp_create = {},
		.mo_tx_assignment_perm_speech = PERM_SPEECH_ALL_GSM,
		.mo_rx_assigned_codec_fr = true,
		.mo_rx_assigned_codec = "AMR:octet-align=1;mode-set=0,2,4,7",
		.mo_tx_sdp_mncc_rtp_create = SDP_CODECS_ALL_GSM,
		/* mt_rx_sdp_mncc_setup_req == mo_tx_sdp_mncc_rtp_create */
		.mt_rx_compl_l3_codec_list_bss_supported = CODEC_LIST_ALL_GSM,
		.mt_tx_cc_setup_bcap = BCAP_ALL_GSM,
		.mt_rx_ms_bcap = BCAP_ALL_GSM,
		.mt_tx_sdp_mncc_call_conf_ind = {},
		.mt_rx_sdp_mncc_rtp_create = {},
		.mt_tx_assignment_perm_speech = PERM_SPEECH_ALL_GSM,
		.mt_rx_assigned_codec_fr = false,
		.mt_rx_assigned_codec = "AMR:octet-align=1;mode-set=0,2,4",
		.mt_tx_sdp_mncc_rtp_create = SDP_CODECS_ALL_GSM_AMR_HR_FIRST,
		.mt_tx_sdp_mncc_alert_ind = SDP_CODECS_ALL_GSM_AMR_HR_FIRST,
		/* mo_rx_sdp_mncc_alert_req == mt_tx_sdp_mncc_alert_ind */

		/*
		.mo_expect_reassignment = true,
		.mo_tx_reassignment_perm_speech = PERM_SPEECH_ALL_GSM_HR3_FIRST,
		.mo_rx_reassigned_codec_fr = false,
		.mo_rx_reassigned_codec = "AMR:octet-align=1;mode-set=0,2,4",
		*/

		.mt_tx_sdp_mncc_setup_cnf = SDP_CODECS_ALL_GSM_AMR_HR_FIRST,
		.mo_tx_sdp_mncc_setup_compl_ind = {},
	},
};

static char namebuf[4][1024];
static int use_namebuf = 0;

static const char *codec_list_name(const struct gsm0808_speech_codec compl_l3_codec_list_bss_supported[])
{
	struct osmo_strbuf sb = { .buf = namebuf[use_namebuf], .len = sizeof(namebuf[0]) };
	use_namebuf = (use_namebuf + 1) % ARRAY_SIZE(namebuf);

	const struct gsm0808_speech_codec *pos;
	sb.buf[0] = '\0';
	for (pos = compl_l3_codec_list_bss_supported; pos->fi; pos++) {
		OSMO_STRBUF_PRINTF(sb, " %s", gsm0808_speech_codec_type_name(pos->type));
		if (pos->cfg)
			OSMO_STRBUF_PRINTF(sb, ":%x", pos->cfg);
	}
	return sb.buf;
}

static const struct gsm0808_speech_codec_list *codec_list(const struct gsm0808_speech_codec compl_l3_codec_list_bss_supported[])
{
	static struct gsm0808_speech_codec_list scl;
	scl = (struct gsm0808_speech_codec_list){};
	const struct gsm0808_speech_codec *pos;
	for (pos = compl_l3_codec_list_bss_supported; pos->fi; pos++) {
		scl.codec[scl.len] = *pos;
		scl.len++;
	}
	return &scl;
}

static const char *bcap_name(const enum gsm48_bcap_speech_ver ms_bcap[])
{
	struct osmo_strbuf sb = { .buf = namebuf[use_namebuf], .len = sizeof(namebuf[0]) };
	use_namebuf = (use_namebuf + 1) % ARRAY_SIZE(namebuf);

	const enum gsm48_bcap_speech_ver *pos;
	sb.buf[0] = '\0';
	for (pos = ms_bcap; *pos != LIST_END; pos++) {
		const struct codec_mapping *m = codec_mapping_by_speech_ver(*pos);
		OSMO_STRBUF_PRINTF(sb, " %s", m ? m->sdp.subtype_name : "NULL");
	}
	return sb.buf;
}

static const char *perm_speech_name(const enum gsm0808_permitted_speech perm_speech[])
{
	struct osmo_strbuf sb = { .buf = namebuf[use_namebuf], .len = sizeof(namebuf[0]) };
	use_namebuf = (use_namebuf + 1) % ARRAY_SIZE(namebuf);

	const enum gsm0808_permitted_speech *pos;
	sb.buf[0] = '\0';
	for (pos = perm_speech; *pos != LIST_END; pos++)
		OSMO_STRBUF_PRINTF(sb, " %s", gsm0808_permitted_speech_name(*pos));
	return sb.buf;
}

static const char *strlist_name(const char *const*strs)
{
	struct osmo_strbuf sb = { .buf = namebuf[use_namebuf], .len = sizeof(namebuf[0]) };
	use_namebuf = (use_namebuf + 1) % ARRAY_SIZE(namebuf);

	const char * const *pos;
	sb.buf[0] = '\0';
	for (pos = strs; *pos != NULL; pos++)
		OSMO_STRBUF_PRINTF(sb, " %s", *pos);
	return sb.buf;
}

/* Validate that the codecs in sdp_str appear in the order as expected by the list of subtype names in expected_codecs.
 * Ignore any payload type numbers ("#96") in expected_codecs.
 */
static bool validate_sdp(const char *func, const char *desc,
			 const char *sdp_str, const char * const expected_codecs[], bool cmp_payload_type)
{
	const char * const *expect_pos;
	struct sdp_audio_codec *codec;
	struct sdp_msg sdp;
	if (sdp_msg_from_sdp_str(&sdp, sdp_str)) {
		BTW("%s: %s: ERROR: failed to parse SDP\n%s", func, desc, sdp_str);
		return false;
	}

	expect_pos = expected_codecs;
	sdp_audio_codecs_foreach(codec, &sdp.audio_codecs) {
		struct sdp_audio_codec xc;

		if (!*expect_pos) {
			BTW("%s: %s: ERROR: did not expect %s", func, desc, codec->subtype_name);
			return false;
		}

		if (sdp_audio_codec_from_str(&xc, *expect_pos)) {
			BTW("%s: %s: ERROR: cannot parse %s", func, desc, codec->subtype_name);
			return false;
		}

		if (sdp_audio_codec_cmp(&xc, codec, true, cmp_payload_type)) {
			BTW("%s: %s: ERROR: mismatch: in idx %d, expect %s, got %s", func, desc,
			    (int)(expect_pos - expected_codecs), sdp_audio_codec_to_str(&xc),
			    sdp_audio_codec_to_str(codec));
			return false;
		}
		expect_pos++;
	}
	if (*expect_pos) {
		BTW("%s: %s: ERROR: mismatch: expected %s to be listed, but not found", func, desc, *expect_pos);
		return false;
	}
	return true;
}

#define VALIDATE_SDP(GOT_SDP_STR, EXPECT_SDP_STR, CMP_PAYLOAD_TYPE) do { \
		if (validate_sdp(__func__, t->desc, GOT_SDP_STR, EXPECT_SDP_STR, CMP_PAYLOAD_TYPE)) { \
			btw("VALIDATE_SDP OK: " #GOT_SDP_STR " == " #EXPECT_SDP_STR " ==%s", strlist_name(EXPECT_SDP_STR)); \
		} else { \
			btw("Failed to validate SDP:\nexpected%s\ngot\n%s", \
			    strlist_name(EXPECT_SDP_STR), GOT_SDP_STR); \
			OSMO_ASSERT(false); \
		} \
	} while (0)

static bool validate_perm_speech(const char *func, const char *desc,
				 const struct gsm0808_channel_type *ct,
				 const enum gsm0808_permitted_speech perm_speech[])
{
	const enum gsm0808_permitted_speech *pos;
	const uint8_t *pos2;

	btw("validate_perm_speech(): expect:");
	for (pos = perm_speech; *pos != LIST_END; pos++)
		btw("  %s", gsm0808_permitted_speech_name(*pos));
	btw("got:");
	for (pos2 = ct->perm_spch; (pos2 - ct->perm_spch) < ct->perm_spch_len; pos2++)
		btw("  %s", gsm0808_permitted_speech_name(*pos2));

	pos2 = ct->perm_spch;
	for (pos = perm_speech; *pos != LIST_END; pos++, pos2++) {
		if (pos2 - ct->perm_spch >= ct->perm_spch_len) {
			BTW("%s: %s: ERROR: mismatch: expected %s to be listed, but not found", func, desc,
			    gsm0808_permitted_speech_name(*pos));
			return false;
		}
		if (*pos2 != *pos) {
			BTW("%s: %s: ERROR: mismatch: in idx %d, expect %s", func, desc,
			    (int)(pos - perm_speech), gsm0808_permitted_speech_name(*pos));
			btw("in idx %d, got %s", (int)(pos - perm_speech), gsm0808_permitted_speech_name(*pos2));
			return false;
		}
	}
	if (pos2 - ct->perm_spch < ct->perm_spch_len) {
		BTW("%s: %s: ERROR: did not expect %s", func, desc, gsm0808_permitted_speech_name(*pos2));
		return false;
	}
	return true;
}

#define VALIDATE_PERM_SPEECH(GOT_PERM_SPEECH, EXPECT_PERM_SPEECH) do { \
		if (validate_perm_speech(__func__, t->desc, GOT_PERM_SPEECH, EXPECT_PERM_SPEECH)) { \
			btw("VALIDATE_PERM_SPEECH OK: " #GOT_PERM_SPEECH " == " #EXPECT_PERM_SPEECH " ==%s", \
			    perm_speech_name(EXPECT_PERM_SPEECH)); \
		} else { \
			btw("Failed to validate Permitted Speech:\nexpected%s", \
			    perm_speech_name(EXPECT_PERM_SPEECH)); \
			btw("got:"); \
			int i; \
			for (i = 0; i < (GOT_PERM_SPEECH)->perm_spch_len; i++) { \
				btw("%s", gsm0808_permitted_speech_name((GOT_PERM_SPEECH)->perm_spch[i])); \
			} \
			OSMO_ASSERT(false); \
		} \
	} while (0)

/* Compose a valid SDP string from the list of codec subtype names given. If a subtype name includes a payload type
 * number ("AMR#96") then use that PT number in the SDP instead of the default from codec_mapping.c. */
static struct sdp_msg *sdp_from_codec_strs(const char *const *codec_strs)
{
	static struct sdp_msg sdp;
	sdp = (struct sdp_msg){};
	const char *const *codec_str;
	osmo_sockaddr_str_from_str(&sdp.rtp, "1.2.3.4", 56);
	for (codec_str = codec_strs; *codec_str; codec_str++) {
		struct sdp_audio_codec c;
		if (sdp_audio_codec_from_str(&c, *codec_str)) {
			BTW("ERROR: unknown codec_str: %s", *codec_str);
			abort();
		}
		if (!sdp_audio_codecs_add_copy(&sdp.audio_codecs, &c, false, false)) {
			BTW("ERROR: list full, cannot add %s", *codec_str);
			abort();
		}
	}
	return &sdp;
}

static int sdp_str_from_codec_strs(char *buf, size_t buflen, const char *const *codec_strs)
{
	if (!codec_strs[0]) {
		buf[0] = '\0';
		return 0;
	}
	return sdp_msg_to_sdp_str_buf(buf, buflen, sdp_from_codec_strs(codec_strs));
}

static const char *bcap_hexstr(const enum gsm48_bcap_speech_ver ms_bcap[])
{
	struct gsm_mncc_bearer_cap bcap = {
		.transfer = GSM_MNCC_BCAP_SPEECH,
		.speech_ver = { -1 },
	};
	LOGP(DLGLOBAL, LOGL_ERROR, "bcap_hexstr():\n");
	const enum gsm48_bcap_speech_ver *pos;
	for (pos = ms_bcap; *pos != LIST_END; pos++) {
		LOGP(DLGLOBAL, LOGL_ERROR, " - %d\n", *pos);
		bearer_cap_add_speech_ver(&bcap, *pos);
	}
	bearer_cap_set_radio(&bcap);
	struct msgb *msg = msgb_alloc(128, "bcap");
	gsm48_encode_bearer_cap(msg, 0, &bcap);
	char *ret = osmo_hexdump_nospc(msg->data, msg->len);
	msgb_free(msg);

	LOGP(DLGLOBAL, LOGL_ERROR, " --> %s\n", ret);
	return ret;
}

static void test_codecs_mo(const struct codec_test *t)
{
	struct gsm_mncc mncc = {
		.imsi = IMSI,
	};

	struct gsm_mncc_rtp mncc_rtp = {};

	BTW("======================== MO call: %s", t->desc);
	btw("CM Service Request with Codec List (BSS Supported) =%s",
	    codec_list_name(t->mo_rx_compl_l3_codec_list_bss_supported));

	cm_service_result_sent = RES_NONE;
	ms_sends_compl_l3("052471"
			  "03575886" /* classmark 2 */
			  "089910070000106005" /* IMSI */,
			  codec_list(t->mo_rx_compl_l3_codec_list_bss_supported));
	VERBOSE_ASSERT(cm_service_result_sent, == RES_ACCEPT, "%d");
	EXPECT_ACCEPTED(true);

	btw("MS sends CC SETUP with Bearer Capability = %s",
	    bcap_name(t->mo_rx_ms_bcap));
	expect_crcx(RTP_TO_CN);
	expect_crcx(RTP_TO_RAN);
	ms_sends_msgf("0385" /* CC, seq = 2 -> 0x80 | CC Setup = 0x5 */
		      "%s" /* Bearer Capability */
		      "5e038121f3" /* Called Number BCD */
		      "15020100" /* CC Capabilities */
		      "4008" /* Supported Codec List */
		      "04026000" /* UMTS: AMR 2 | AMR */
		      "00021f00" /* GSM: HR AMR | FR AMR | GSM EFR | GSM HR | GSM FR */,
		      bcap_hexstr(t->mo_rx_ms_bcap)
		     );
	OSMO_ASSERT(crcx_scheduled(RTP_TO_CN));
	OSMO_ASSERT(crcx_scheduled(RTP_TO_RAN));

	btw("As soon as the MGW port towards CN is created, MNCC_SETUP_IND is triggered");
	cc_to_mncc_expect_tx(IMSI, MNCC_SETUP_IND);
	crcx_ok(RTP_TO_CN);
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);
	mncc.callref = mncc_rtp.callref = cc_to_mncc_tx_got_callref;
	VALIDATE_SDP(cc_to_mncc_tx_last_sdp, t->mo_tx_sdp_mncc_setup_ind, true);

	btw("MNCC replies with MNCC_RTP_CREATE");
	sdp_str_from_codec_strs(mncc_rtp.sdp, sizeof(mncc_rtp.sdp), t->mo_rx_sdp_mncc_rtp_create);
	mncc_sends_to_cc(MNCC_RTP_CREATE, &mncc_rtp);

	btw("MGW acknowledges the CRCX, triggering Assignment with%s", perm_speech_name(t->mo_tx_assignment_perm_speech));
	expect_bssap_assignment();
	crcx_ok(RTP_TO_RAN);
	OSMO_ASSERT(bssap_assignment_sent);
	VALIDATE_PERM_SPEECH(&bssap_assignment_command_last_channel_type, t->mo_tx_assignment_perm_speech);

	btw("Assignment succeeds with %s %s, triggering MNCC_RTP_CREATE ack to MNCC with %s",
	    t->mo_rx_assigned_codec_fr ? "FR" : "HR", t->mo_rx_assigned_codec,
	    strlist_name(t->mo_tx_sdp_mncc_rtp_create));
	cc_to_mncc_expect_tx("", MNCC_RTP_CREATE);
	ms_sends_assignment_complete(t->mo_rx_assigned_codec_fr, t->mo_rx_assigned_codec);
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);
	VALIDATE_SDP(cc_to_mncc_tx_last_sdp, t->mo_tx_sdp_mncc_rtp_create,
		     !t->mo_tx__ignore_pt_nrs);

	btw("MNCC says that's fine");
	dtap_expect_tx("8302" /* CC: Call Proceeding */);
	mncc_sends_to_cc(MNCC_CALL_PROC_REQ, &mncc);
	OSMO_ASSERT(dtap_tx_confirmed);

	fake_time_passes(1, 23);

	btw("The other call leg got established (not shown here), MNCC tells us so, with codecs {%s }",
	    strlist_name(t->mo_rx_sdp_mncc_alert_req));
	dtap_expect_tx("8301" /* CC: Call Alerting */);

	if (t->mo_expect_reassignment) {
		btw("Expecting re-assignment");
		expect_bssap_assignment();
	}

	sdp_str_from_codec_strs(mncc.sdp, sizeof(mncc.sdp), t->mo_rx_sdp_mncc_alert_req);
	mncc_sends_to_cc(MNCC_ALERT_REQ, &mncc);
	OSMO_ASSERT(dtap_tx_confirmed);

	if (t->mo_expect_reassignment) {
		btw("Validating re-assignment");
		OSMO_ASSERT(bssap_assignment_sent);
		VALIDATE_PERM_SPEECH(&bssap_assignment_command_last_channel_type, t->mo_tx_reassignment_perm_speech);
		ms_sends_assignment_complete(t->mo_rx_reassigned_codec_fr, t->mo_rx_reassigned_codec);
	}

	dtap_expect_tx("8307" /* CC: Connect */);
	sdp_str_from_codec_strs(mncc.sdp, sizeof(mncc.sdp), t->mo_rx_sdp_mncc_setup_rsp);
	mncc_sends_to_cc(MNCC_SETUP_RSP, &mncc);
	OSMO_ASSERT(dtap_tx_confirmed);

	fake_time_passes(1, 23);

	cc_to_mncc_expect_tx("", MNCC_SETUP_COMPL_IND);
	ms_sends_msg("03cf" /* CC: Connect Acknowledge */);
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);
	VALIDATE_SDP(cc_to_mncc_tx_last_sdp, t->mo_tx_sdp_mncc_setup_compl_ind, true);

	BTW("RTP stream goes ahead, not shown here.");
	fake_time_passes(123, 45);

	BTW("Call ends");
	cc_to_mncc_expect_tx("", MNCC_DISC_IND);
	ms_sends_msg("032502e090" /* CC: Disconnect, cause: Normal Call Clearing */);
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);

	dtap_expect_tx("832d" /* CC: Release */);
	mncc_sends_to_cc(MNCC_REL_REQ, &mncc);
	OSMO_ASSERT(dtap_tx_confirmed);

	cc_to_mncc_expect_tx("", MNCC_REL_CNF);
	expect_bssap_clear();
	ms_sends_msg("036a" /* CC: Release Complete */);
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);
	OSMO_ASSERT(bssap_clear_sent);

	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);
	BTW("======================== SUCCESS: MO call: %s", t->desc);
}

static void test_codecs_mt(const struct codec_test *t)
{
	struct gsm_mncc mncc = {
		.imsi = IMSI,
		.callref = 0x423,
		.fields = MNCC_F_BEARER_CAP,
		.bearer_cap = {
			.speech_ver = { GSM48_BCAP_SV_FR, -1, },
		},
	};
	struct gsm_mncc_rtp mncc_rtp = {
		.callref = 0x423,
	};

	BTW("======================== MT call: %s", t->desc);

	BTW("MNCC asks us to setup a call, causing Paging");

	paging_expect_imsi(IMSI);
	paging_sent = false;
	sdp_str_from_codec_strs(mncc.sdp, sizeof(mncc.sdp), t->mt_rx_sdp_mncc_setup_req);
	mncc_sends_to_cc(MNCC_SETUP_REQ, &mncc);
	mncc.sdp[0] = '\0';

	VERBOSE_ASSERT(paging_sent, == true, "%d");

	btw("MS replies with Paging Response, with Codec List (BSS Supported) =%s",
	    codec_list_name(t->mt_rx_compl_l3_codec_list_bss_supported));

	if (t->expect_codec_mismatch_on_paging_response) {
		btw("VLR accepts, but MSC notices a codec mismatch and aborts");
		cc_to_mncc_expect_tx("", MNCC_REL_IND);
		expect_bssap_clear();
		ms_sends_compl_l3("062707"
				  "03575886" /* classmark 2 */
				  "089910070000106005" /* IMSI */,
				  codec_list(t->mt_rx_compl_l3_codec_list_bss_supported));
		OSMO_ASSERT(cc_to_mncc_tx_confirmed);
		OSMO_ASSERT(bssap_clear_sent);

		ran_sends_clear_complete();
		EXPECT_CONN_COUNT(0);

		BTW("======================== SUCCESS: MT call: %s", t->desc);
		return;
	}

	btw("VLR accepts, MSC sends CC Setup with Bearer Capability = %s %s",
	    bcap_name(t->mt_tx_cc_setup_bcap), bcap_hexstr(t->mt_tx_cc_setup_bcap));
	char *cc_setup_bcap = talloc_asprintf(msc_vlr_tests_ctx, "0305%s",
					      bcap_hexstr(t->mt_tx_cc_setup_bcap));
	dtap_expect_tx(cc_setup_bcap);
	ms_sends_compl_l3("062707"
			  "03575886" /* classmark 2 */
			  "089910070000106005" /* IMSI */,
			  codec_list(t->mt_rx_compl_l3_codec_list_bss_supported));
	OSMO_ASSERT(dtap_tx_confirmed);
	talloc_free(cc_setup_bcap);

	btw("MS confirms call, we create a RAN-side RTP and forward MNCC_CALL_CONF_IND");
	expect_crcx(RTP_TO_CN);
	expect_crcx(RTP_TO_RAN);
	cc_to_mncc_expect_tx(IMSI, MNCC_CALL_CONF_IND);
	ms_sends_msgf("8348" /* CC: Call Confirmed */
		      "%s" /* Bearer Capability */
		      "15020100" /* Call Control Capabilities */
		      "40080402600400021f00" /* Supported Codec List */,
		      bcap_hexstr(t->mt_rx_ms_bcap)
		     );
	OSMO_ASSERT(crcx_scheduled(RTP_TO_CN));
	OSMO_ASSERT(crcx_scheduled(RTP_TO_RAN));
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);
	VALIDATE_SDP(cc_to_mncc_tx_last_sdp, t->mt_tx_sdp_mncc_call_conf_ind, true);

	btw("MGW acknowledges the CRCX to RAN, triggering Assignment with%s", perm_speech_name(t->mt_tx_assignment_perm_speech));

	if (t->expect_codec_mismatch_on_cc_call_conf) {
		btw("MS Bearer Capability leads to a codec mismatch, Assignment aborts");

		dtap_expect_tx("032d0802e1af" /* CC Release */);
		cc_to_mncc_expect_tx("", MNCC_REL_IND);
		expect_bssap_clear();
		crcx_ok(RTP_TO_RAN);

		OSMO_ASSERT(cc_to_mncc_tx_confirmed);
		OSMO_ASSERT(bssap_clear_sent);

		ran_sends_clear_complete();
		EXPECT_CONN_COUNT(0);
		BTW("======================== SUCCESS: MT call: %s", t->desc);
		return;
	}

	expect_bssap_assignment();
	crcx_ok(RTP_TO_RAN);
	OSMO_ASSERT(bssap_assignment_sent);
	VALIDATE_PERM_SPEECH(&bssap_assignment_command_last_channel_type, t->mt_tx_assignment_perm_speech);

	btw("Assignment completes, triggering CRCX to CN");
	ms_sends_assignment_complete(t->mt_rx_assigned_codec_fr, t->mt_rx_assigned_codec);

	btw("MNCC sends MNCC_RTP_CREATE, which first waits for the CN side RTP");
	sdp_str_from_codec_strs(mncc_rtp.sdp, sizeof(mncc_rtp.sdp), t->mt_rx_sdp_mncc_rtp_create);
	mncc_sends_to_cc(MNCC_RTP_CREATE, &mncc_rtp);

	btw("When the CN side RTP address is known, ack MNCC_RTP_CREATE");
	cc_to_mncc_expect_tx("", MNCC_RTP_CREATE);
	crcx_ok(RTP_TO_CN);
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);
	VALIDATE_SDP(cc_to_mncc_tx_last_sdp, t->mt_tx_sdp_mncc_rtp_create,
		     !t->mt_tx__ignore_pt_nrs);

	fake_time_passes(1, 23);

	cc_to_mncc_expect_tx("", MNCC_ALERT_IND);
	ms_sends_msg("8381" /* CC: Alerting */);
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);
	VALIDATE_SDP(cc_to_mncc_tx_last_sdp, t->mt_tx_sdp_mncc_alert_ind,
		     !t->mt_tx__ignore_pt_nrs);

	fake_time_passes(1, 23);

	cc_to_mncc_expect_tx(IMSI, MNCC_SETUP_CNF);
	ms_sends_msg("83c7" /* CC: Connect */);
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);
	VALIDATE_SDP(cc_to_mncc_tx_last_sdp, t->mt_tx_sdp_mncc_setup_cnf,
		     !t->mt_tx__ignore_pt_nrs);

	dtap_expect_tx("030f" /* CC: Connect Acknowledge */);
	sdp_str_from_codec_strs(mncc.sdp, sizeof(mncc.sdp), t->mt_rx_sdp_mncc_setup_compl_req);
	mncc_sends_to_cc(MNCC_SETUP_COMPL_REQ, &mncc);

	BTW("RTP stream goes ahead, not shown here.");
	fake_time_passes(123, 45);

	BTW("Call ends");
	cc_to_mncc_expect_tx("", MNCC_DISC_IND);
	ms_sends_msg("832502e090" /* CC: Disconnect, cause: Normal Call Clearing */);
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);

	dtap_expect_tx("032d" /* CC: Release */);
	mncc_sends_to_cc(MNCC_REL_REQ, &mncc);
	OSMO_ASSERT(dtap_tx_confirmed);

	cc_to_mncc_expect_tx("", MNCC_REL_CNF);
	expect_bssap_clear();
	ms_sends_msg("836a" /* CC: Release Complete */);
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);
	OSMO_ASSERT(bssap_clear_sent);

	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);
	BTW("======================== SUCCESS: MT call: %s", t->desc);
}

static void test_codecs(void)
{
	const struct codec_test *t;
	clear_vlr();

	comment_start();

	fake_time_start();

	lu_geran_noauth();

	for (t = codec_tests; t - codec_tests < ARRAY_SIZE(codec_tests); t++) {
		test_codecs_mo(t);
		test_codecs_mt(t);
	}

	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

msc_vlr_test_func_t msc_vlr_tests[] = {
	test_call_mo,
	test_call_mt,
	test_call_mt2,
	test_call_mo_to_unknown,
	test_call_mo_to_unknown_timeout,
	test_codecs,
	NULL
};
