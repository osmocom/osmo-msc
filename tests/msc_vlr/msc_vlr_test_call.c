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
#include "stubs.h"

#include <osmocom/msc/gsm_04_08.h>

static void mncc_sends_to_cc(uint32_t msg_type, struct gsm_mncc *mncc)
{
	mncc->msg_type = msg_type;
	mncc_tx_to_cc(net, msg_type, mncc);
}

static void on_call_release_mncc_sends_to_cc(uint32_t msg_type, struct gsm_mncc *mncc)
{
	mncc->msg_type = msg_type;
	on_call_release_mncc_sends_to_cc_data = mncc;
}

#define IMSI "901700000010650"

static void standard_lu()
{
	struct vlr_subscr *vsub;

	net->authentication_required = true;
	net->vlr->cfg.assign_tmsi = true;
	rx_from_ran = OSMO_RAT_UTRAN_IU;

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("080108" "09710000000156f0");
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
			"2708" "0edb0eadbea94ac2",
		NULL);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Authen Response, VLR accepts and sends SecurityModeControl");
	expect_security_mode_ctrl(NULL, "27497388b6cb044648f396aa155b95ef");
	ms_sends_msg("0554" "e229c19e" "2104" "791f2e41");
	VERBOSE_ASSERT(security_mode_ctrl_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends SecurityModeControl acceptance, VLR accepts and sends GSUP LU Req to HLR");
	gsup_expect_tx("04010809710000000156f0280102");
	ms_sends_security_mode_complete();
	VERBOSE_ASSERT(gsup_tx_confirmed, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000000156f00804032443f2",
		"12010809710000000156f0");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT");
	gsup_rx("06010809710000000156f0", NULL);

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
	rnc_sends_release_complete();
	EXPECT_CONN_COUNT(0);

	vsub = vlr_subscr_find_by_imsi(net->vlr, IMSI, __func__);
	VERBOSE_ASSERT(vsub != NULL, == true, "%d");
	VERBOSE_ASSERT(strcmp(vsub->imsi, IMSI), == 0, "%d");
	VAL_ASSERT("LAC", vsub->cgi.lai.lac, == 23, "%u");
	vlr_subscr_put(vsub, __func__);
}

static void test_call_mo()
{
	struct gsm_mncc mncc = {
		.imsi = IMSI,
	};

	comment_start();

	fake_time_start();

	standard_lu();

	BTW("after a while, a new conn sends a CM Service Request. VLR responds with Auth Req, 2nd auth vector");
	auth_request_sent = false;
	auth_request_expect_rand = "c187a53a5e6b9d573cac7c74451fd46d";
	auth_request_expect_autn = "1843a645b98d00005b2d666af46c45d9";
	cm_service_result_sent = RES_NONE;
	ms_sends_msg("052478"
		     "03575886" /* classmark 2 */
		     "089910070000106005" /* IMSI */);
	OSMO_ASSERT(g_conn);
	OSMO_ASSERT(g_conn->fi);
	OSMO_ASSERT(g_conn->vsub);
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
	ms_sends_security_mode_complete();
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");

	BTW("a call is initiated");

	btw("SETUP gets forwarded to MNCC");
	cc_to_mncc_expect_tx(IMSI, MNCC_SETUP_IND);
	ms_sends_msg("0385" /* CC, seq = 2 -> 0x80 | CC Setup = 0x5 */
		     "0406600402000581" /* Bearer Capability */
		     "5e038121f3" /* Called Number BCD */
		     "15020100" /* CC Capabilities */
		     "4008" /* Supported Codec List */
		       "04026000" /* UMTS: AMR 2 | AMR */
		       "00021f00" /* GSM: HR AMR | FR AMR | GSM EFR | GSM HR | GSM FR */
		    );
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);
	mncc.callref = cc_to_mncc_tx_got_callref;

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

	rnc_sends_release_complete();
	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

static void test_call_mt()
{
	struct gsm_mncc mncc = {
		.imsi = IMSI,
		.callref = 0x423,
	};

	comment_start();

	fake_time_start();

	standard_lu();

	BTW("after a while, MNCC asks us to setup a call, causing Paging");
	
	paging_expect_imsi(IMSI);
	paging_sent = false;
	mncc_sends_to_cc(MNCC_SETUP_REQ, &mncc);

	VERBOSE_ASSERT(paging_sent, == true, "%d");
	VERBOSE_ASSERT(paging_stopped, == false, "%d");

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
	dtap_expect_tx("0305" /* CC: Setup */);
	ms_sends_security_mode_complete();
	VERBOSE_ASSERT(paging_stopped, == true, "%d");

	cc_to_mncc_expect_tx(IMSI, MNCC_CALL_CONF_IND);
	ms_sends_msg("8348" /* CC: Call Confirmed */
		     "0406600402000581" /* Bearer Capability */
		     "15020100" /* Call Control Capabilities */
		     "40080402600400021f00" /* Supported Codec List */);

	fake_time_passes(1, 23);

	cc_to_mncc_expect_tx("", MNCC_ALERT_IND);
	ms_sends_msg("8381" /* CC: Alerting */);

	fake_time_passes(1, 23);

	cc_to_mncc_expect_tx(IMSI, MNCC_SETUP_CNF);
	ms_sends_msg("83c7" /* CC: Connect */);

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

	rnc_sends_release_complete();
	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

static void test_call_mt2()
{
	struct gsm_mncc mncc = {
		.imsi = IMSI,
		.callref = 0x423,
	};

	comment_start();

	fake_time_start();

	standard_lu();

	BTW("after a while, MNCC asks us to setup a call, causing Paging");
	
	paging_expect_imsi(IMSI);
	paging_sent = false;
	mncc_sends_to_cc(MNCC_SETUP_REQ, &mncc);

	VERBOSE_ASSERT(paging_sent, == true, "%d");
	VERBOSE_ASSERT(paging_stopped, == false, "%d");

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
	dtap_expect_tx("0305" /* CC: Setup */);
	ms_sends_security_mode_complete();
	VERBOSE_ASSERT(paging_stopped, == true, "%d");

	cc_to_mncc_expect_tx(IMSI, MNCC_CALL_CONF_IND);
	ms_sends_msg("8348" /* CC: Call Confirmed */
		     "0406600402000581" /* Bearer Capability */
		     "15020100" /* Call Control Capabilities */
		     "40080402600400021f00" /* Supported Codec List */);
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);

	fake_time_passes(1, 23);

	cc_to_mncc_expect_tx("", MNCC_ALERT_IND);
	ms_sends_msg("8381" /* CC: Alerting */);
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);

	fake_time_passes(15, 23);

	btw("The call failed, the BSC sends a BSSMAP Clear Request");
	on_call_release_mncc_sends_to_cc(MNCC_REL_REQ, &mncc);
	cc_to_mncc_expect_tx("", MNCC_REL_CNF);
	dtap_expect_tx("032d"); /* CC: Release */
	expect_iu_release();
	ran_conn_clear_request(g_conn, 0);
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);
	OSMO_ASSERT(iu_release_sent);

	rnc_sends_release_complete();
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

	comment_start();

	fake_time_start();

	standard_lu();

	BTW("after a while, a new conn sends a CM Service Request. VLR responds with Auth Req, 2nd auth vector");
	auth_request_sent = false;
	auth_request_expect_rand = "c187a53a5e6b9d573cac7c74451fd46d";
	auth_request_expect_autn = "1843a645b98d00005b2d666af46c45d9";
	cm_service_result_sent = RES_NONE;
	ms_sends_msg("052478"
		     "03575886" /* classmark 2 */
		     "089910070000106005" /* IMSI */);
	OSMO_ASSERT(g_conn);
	OSMO_ASSERT(g_conn->fi);
	OSMO_ASSERT(g_conn->vsub);
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
	ms_sends_security_mode_complete();
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");

	BTW("a call is initiated");

	btw("SETUP gets forwarded to MNCC");
	cc_to_mncc_expect_tx(IMSI, MNCC_SETUP_IND);
	ms_sends_msg("0385" /* CC, seq = 2 -> 0x80 | CC Setup = 0x5 */
		     "0406600402000581" /* Bearer Capability */
		     "5e038121f3" /* Called Number BCD */
		     "15020100" /* CC Capabilities */
		     "4008" /* Supported Codec List */
		       "04026000" /* UMTS: AMR 2 | AMR */
		       "00021f00" /* GSM: HR AMR | FR AMR | GSM EFR | GSM HR | GSM FR */
		    );
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);
	mncc.callref = cc_to_mncc_tx_got_callref;

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
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);
	OSMO_ASSERT(iu_release_sent);
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);

	rnc_sends_release_complete();
	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

static void test_call_mo_to_unknown_timeout()
{
	struct gsm_mncc mncc = {
		.imsi = IMSI,
	};

	comment_start();

	fake_time_start();

	standard_lu();

	BTW("after a while, a new conn sends a CM Service Request. VLR responds with Auth Req, 2nd auth vector");
	auth_request_sent = false;
	auth_request_expect_rand = "c187a53a5e6b9d573cac7c74451fd46d";
	auth_request_expect_autn = "1843a645b98d00005b2d666af46c45d9";
	cm_service_result_sent = RES_NONE;
	ms_sends_msg("052478"
		     "03575886" /* classmark 2 */
		     "089910070000106005" /* IMSI */);
	OSMO_ASSERT(g_conn);
	OSMO_ASSERT(g_conn->fi);
	OSMO_ASSERT(g_conn->vsub);
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
	ms_sends_security_mode_complete();
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");

	BTW("a call is initiated");

	btw("SETUP gets forwarded to MNCC");
	cc_to_mncc_expect_tx(IMSI, MNCC_SETUP_IND);
	ms_sends_msg("0385" /* CC, seq = 2 -> 0x80 | CC Setup = 0x5 */
		     "0406600402000581" /* Bearer Capability */
		     "5e038121f3" /* Called Number BCD */
		     "15020100" /* CC Capabilities */
		     "4008" /* Supported Codec List */
		       "04026000" /* UMTS: AMR 2 | AMR */
		       "00021f00" /* GSM: HR AMR | FR AMR | GSM EFR | GSM HR | GSM FR */
		    );
	OSMO_ASSERT(cc_to_mncc_tx_confirmed);
	mncc.callref = cc_to_mncc_tx_got_callref;

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

	rnc_sends_release_complete();
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
	NULL
};
