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

#include "msc_vlr_tests.h"
#include "stubs.h"

static void test_ciph()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000004620";

	comment_start();

	/* implicit: net->authentication_required = true; */
	net->a5_encryption_mask = (1 << 1);

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("08010809710000004026f0");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("from HLR, rx _SEND_AUTH_INFO_RESULT; VLR sends Auth Req to MS");
	/* Based on a Ki of 000102030405060708090a0b0c0d0e0f */
	auth_request_sent = false;
	auth_request_expect_rand = "585df1ae287f6e273dce07090d61320b";
	auth_request_expect_autn = NULL;
	gsup_rx("0a"
		/* imsi */
		"0108" "09710000004026f0"
		/* 5 auth vectors... */
		/* TL    TL     rand */
		"0322"  "2010" "585df1ae287f6e273dce07090d61320b"
		/*       TL     sres       TL     kc */
			"2104" "2d8b2c3e" "2208" "61855fb81fc2a800"
		"0322"  "2010" "12aca96fb4ffdea5c985cbafa9b6e18b"
			"2104" "20bde240" "2208" "07fa7502e07e1c00"
		"0322"  "2010" "e7c03ba7cf0e2fde82b2dc4d63077d42"
			"2104" "a29514ae" "2208" "e2b234f807886400"
		"0322"  "2010" "fa8f20b781b5881329d4fea26b1a3c51"
			"2104" "5afc8d72" "2208" "2392f14f709ae000"
		"0322"  "2010" "0fd4cc8dbe8715d1f439e304edfd68dc"
			"2104" "bc8d1c5b" "2208" "da7cdd6bfe2d7000",
		NULL);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");

	btw("MS sends Authen Response, VLR accepts and sends Ciphering Mode Command to MS");
	expect_cipher_mode_cmd("61855fb81fc2a800");
	ms_sends_msg("05542d8b2c3e");
	OSMO_ASSERT(cipher_mode_cmd_sent);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("needs ciph, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Ciphering Mode Complete, VLR accepts and sends GSUP LU Req to HLR");
	gsup_expect_tx("04010809710000004026f0280102");
	ms_sends_msg("0632");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000004026f00804036470f1",
		"12010809710000004026f0");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT");
	expect_bssap_clear();
	gsup_rx("06010809710000004026f0", NULL);
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	btw("LU was successful, and the conn has already been closed");
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	BTW("after a while, a new conn sends a CM Service Request. VLR responds with Auth Req, 2nd auth vector");
	cm_service_result_sent = RES_NONE;
	auth_request_sent = false;
	auth_request_expect_rand = "12aca96fb4ffdea5c985cbafa9b6e18b";
	ms_sends_msg("05247803305886089910070000006402");
	OSMO_ASSERT(g_conn);
	OSMO_ASSERT(g_conn->fi);
	OSMO_ASSERT(g_conn->vsub);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");

	btw("needs auth, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS sends Authen Response, VLR accepts and requests Ciphering");
	expect_cipher_mode_cmd("07fa7502e07e1c00");
	ms_sends_msg("0554" "20bde240" /* 2nd vector's sres, s.a. */);
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");
	VERBOSE_ASSERT(cipher_mode_cmd_sent, == true, "%d");

	btw("needs ciph, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS sends Ciphering Mode Complete, VLR accepts; above Ciphering is an implicit CM Service Accept");
	ms_sends_msg("0632");
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");

	/* Release connection */
	expect_bssap_clear(OSMO_RAT_GERAN_A);
	conn_conclude_cm_service_req(g_conn, OSMO_RAT_GERAN_A);

	btw("all requests serviced, conn has been released");
	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	BTW("an SMS is sent, MS is paged");
	paging_expect_imsi(imsi);
	paging_sent = false;
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 0, "%d");

	send_sms(vsub, vsub,
		 "Privacy in residential applications is a desirable"
		 " marketing option.");

	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 1, "%d");
	vlr_subscr_put(vsub, __func__);
	vsub = NULL;
	VERBOSE_ASSERT(paging_sent, == true, "%d");
	VERBOSE_ASSERT(paging_stopped, == false, "%d");

	btw("the subscriber and its pending request should remain");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 1, "%d");
	vlr_subscr_put(vsub, __func__);

	btw("MS replies with Paging Response, and VLR sends Auth Request with third key");
	auth_request_sent = false;
	auth_request_expect_rand = "e7c03ba7cf0e2fde82b2dc4d63077d42";
	ms_sends_msg("06270703305882089910070000006402");
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");

	btw("needs auth, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS sends Authen Response, VLR accepts and requests Ciphering");
	expect_cipher_mode_cmd("e2b234f807886400");
	ms_sends_msg("0554" "a29514ae" /* 3rd vector's sres, s.a. */);
	VERBOSE_ASSERT(cipher_mode_cmd_sent, == true, "%d");

	btw("needs ciph, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS sends Ciphering Mode Complete, VLR accepts and sends pending SMS");
	dtap_expect_tx("09" /* SMS messages */
		       "01" /* CP-DATA */
		       "58" /* length */
		       "01" /* Network to MS */
		       "00" /* reference */
		       /* originator (gsm411_send_sms() hardcodes this weird nr) */
		       "0791" "447758100650" /* 447785016005 */
		       "00" /* dest */
		       /* SMS TPDU */
		       "4c" /* len */
		       "00" /* SMS deliver */
		       "05806470f1" /* originating address 46071 */
		       "00" /* TP-PID */
		       "00" /* GSM default alphabet */
		       "071010" /* Y-M-D (from wrapped gsm340_gen_scts())*/
		       "000000" /* H-M-S */
		       "00" /* GMT+0 */
		       "44" /* data length */
		       "5079da1e1ee7416937485e9ea7c965373d1d6683c270383b3d0e"
		       "d3d36ff71c949e83c22072799e9687c5ec32a81d96afcbf4b4fb"
		       "0c7ac3e9e9b7db05");
	ms_sends_msg("0632");
	VERBOSE_ASSERT(dtap_tx_confirmed, == true, "%d");
	VERBOSE_ASSERT(paging_stopped, == true, "%d");

	btw("SMS was delivered, no requests pending for subscr");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 0, "%d");
	vlr_subscr_put(vsub, __func__);

	btw("conn is still open to wait for SMS ack dance");
	EXPECT_CONN_COUNT(1);

	btw("MS replies with CP-ACK for received SMS");
	ms_sends_msg("8904");
	EXPECT_CONN_COUNT(1);

	btw("MS also sends RP-ACK, MSC in turn sends CP-ACK for that");
	dtap_expect_tx("0904");
	expect_bssap_clear();
	ms_sends_msg("890106020041020000");
	VERBOSE_ASSERT(dtap_tx_confirmed, == true, "%d");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	btw("SMS is done, conn is gone");
	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	BTW("subscriber detaches");
	expect_bssap_clear();
	ms_sends_msg("050130089910070000006402");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

static void test_ciph_tmsi()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000004620";

	comment_start();

	/* implicit: net->authentication_required = true; */
	net->a5_encryption_mask = (1 << 1);
	net->vlr->cfg.assign_tmsi = true;

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("08010809710000004026f0");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("from HLR, rx _SEND_AUTH_INFO_RESULT; VLR sends Auth Req to MS");
	/* Based on a Ki of 000102030405060708090a0b0c0d0e0f */
	auth_request_sent = false;
	auth_request_expect_rand = "585df1ae287f6e273dce07090d61320b";
	auth_request_expect_autn = NULL;
	gsup_rx("0a"
		/* imsi */
		"0108" "09710000004026f0"
		/* 5 auth vectors... */
		/* TL    TL     rand */
		"0322"  "2010" "585df1ae287f6e273dce07090d61320b"
		/*       TL     sres       TL     kc */
			"2104" "2d8b2c3e" "2208" "61855fb81fc2a800"
		"0322"  "2010" "12aca96fb4ffdea5c985cbafa9b6e18b"
			"2104" "20bde240" "2208" "07fa7502e07e1c00"
		"0322"  "2010" "e7c03ba7cf0e2fde82b2dc4d63077d42"
			"2104" "a29514ae" "2208" "e2b234f807886400"
		"0322"  "2010" "fa8f20b781b5881329d4fea26b1a3c51"
			"2104" "5afc8d72" "2208" "2392f14f709ae000"
		"0322"  "2010" "0fd4cc8dbe8715d1f439e304edfd68dc"
			"2104" "bc8d1c5b" "2208" "da7cdd6bfe2d7000",
		NULL);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Authen Response, VLR accepts and sends Ciphering Mode Command to MS");
	expect_cipher_mode_cmd("61855fb81fc2a800");
	ms_sends_msg("05542d8b2c3e");
	OSMO_ASSERT(cipher_mode_cmd_sent);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");

	btw("needs ciph, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Ciphering Mode Complete, VLR accepts and sends GSUP LU Req to HLR");
	gsup_expect_tx("04010809710000004026f0280102");
	ms_sends_msg("0632");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000004026f00804036470f1",
		"12010809710000004026f0");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT");
	gsup_rx("06010809710000004026f0", NULL);

	btw("a LU Accept with a new TMSI was sent, waiting for TMSI Realloc Compl");
	EXPECT_CONN_COUNT(1);
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("even though the TMSI is not acked, we can already find the subscr with it");
	vsub = vlr_subscr_find_by_tmsi(net->vlr, 0x03020100, __func__);
	VERBOSE_ASSERT(vsub != NULL, == true, "%d");
	VERBOSE_ASSERT(strcmp(vsub->imsi, imsi), == 0, "%d");
	VERBOSE_ASSERT(vsub->tmsi_new, == 0x03020100, "0x%08x");
	VERBOSE_ASSERT(vsub->tmsi, == GSM_RESERVED_TMSI, "0x%08x");
	vlr_subscr_put(vsub, __func__);

	btw("MS sends TMSI Realloc Complete");
	expect_bssap_clear();
	ms_sends_msg("055b");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	btw("LU was successful, and the conn has already been closed");
	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	btw("Subscriber has the new TMSI");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	VERBOSE_ASSERT(vsub != NULL, == true, "%d");
	VERBOSE_ASSERT(strcmp(vsub->imsi, imsi), == 0, "%d");
	VERBOSE_ASSERT(vsub->tmsi_new, == GSM_RESERVED_TMSI, "0x%08x");
	VERBOSE_ASSERT(vsub->tmsi, == 0x03020100, "0x%08x");
	vlr_subscr_put(vsub, __func__);

	BTW("after a while, a new conn sends a CM Service Request using above TMSI. VLR responds with Auth Req, 2nd auth vector");
	cm_service_result_sent = RES_NONE;
	auth_request_sent = false;
	auth_request_expect_rand = "12aca96fb4ffdea5c985cbafa9b6e18b";
	auth_request_expect_autn = NULL;
	ms_sends_msg("05247803305886" "05f4" "03020100");
	OSMO_ASSERT(g_conn);
	OSMO_ASSERT(g_conn->fi);
	OSMO_ASSERT(g_conn->vsub);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");

	btw("needs auth, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS sends Authen Response, VLR accepts and requests Ciphering");
	expect_cipher_mode_cmd("07fa7502e07e1c00");
	ms_sends_msg("0554" "20bde240" /* 2nd vector's sres, s.a. */);
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");
	VERBOSE_ASSERT(cipher_mode_cmd_sent, == true, "%d");

	btw("needs ciph, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS sends Ciphering Mode Complete, VLR accepts; above Ciphering is an implicit CM Service Accept");
	ms_sends_msg("0632");
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");

	/* Release connection */
	expect_bssap_clear(OSMO_RAT_GERAN_A);
	conn_conclude_cm_service_req(g_conn, OSMO_RAT_GERAN_A);

	btw("all requests serviced, conn has been released");
	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	BTW("an SMS is sent, MS is paged");
	paging_expect_tmsi(0x03020100);
	paging_sent = false;
	vsub = vlr_subscr_find_by_tmsi(net->vlr, 0x03020100, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 0, "%d");

	send_sms(vsub, vsub,
		 "Privacy in residential applications is a desirable"
		 " marketing option.");

	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 1, "%d");
	vlr_subscr_put(vsub, __func__);
	vsub = NULL;
	VERBOSE_ASSERT(paging_sent, == true, "%d");
	VERBOSE_ASSERT(paging_stopped, == false, "%d");

	btw("the subscriber and its pending request should remain");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 1, "%d");
	vlr_subscr_put(vsub, __func__);

	btw("MS replies with Paging Response using TMSI, and VLR sends Auth Request with third key");
	auth_request_sent = false;
	auth_request_expect_rand = "e7c03ba7cf0e2fde82b2dc4d63077d42";
	ms_sends_msg("06270703305882" "05f4" "03020100");
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");

	btw("needs auth, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS sends Authen Response, VLR accepts and requests Ciphering");
	expect_cipher_mode_cmd("e2b234f807886400");
	ms_sends_msg("0554" "a29514ae" /* 3rd vector's sres, s.a. */);
	VERBOSE_ASSERT(cipher_mode_cmd_sent, == true, "%d");

	btw("needs ciph, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS sends Ciphering Mode Complete, VLR accepts and sends pending SMS");
	dtap_expect_tx("09" /* SMS messages */
		       "01" /* CP-DATA */
		       "58" /* length */
		       "01" /* Network to MS */
		       "00" /* reference */
		       /* originator (gsm411_send_sms() hardcodes this weird nr) */
		       "0791" "447758100650" /* 447785016005 */
		       "00" /* dest */
		       /* SMS TPDU */
		       "4c" /* len */
		       "00" /* SMS deliver */
		       "05806470f1" /* originating address 46071 */
		       "00" /* TP-PID */
		       "00" /* GSM default alphabet */
		       "071010" /* Y-M-D (from wrapped gsm340_gen_scts())*/
		       "000000" /* H-M-S */
		       "00" /* GMT+0 */
		       "44" /* data length */
		       "5079da1e1ee7416937485e9ea7c965373d1d6683c270383b3d0e"
		       "d3d36ff71c949e83c22072799e9687c5ec32a81d96afcbf4b4fb"
		       "0c7ac3e9e9b7db05");
	ms_sends_msg("0632");
	VERBOSE_ASSERT(dtap_tx_confirmed, == true, "%d");
	VERBOSE_ASSERT(paging_stopped, == true, "%d");

	btw("SMS was delivered, no requests pending for subscr");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 0, "%d");
	vlr_subscr_put(vsub, __func__);

	btw("conn is still open to wait for SMS ack dance");
	EXPECT_CONN_COUNT(1);

	btw("MS replies with CP-ACK for received SMS");
	ms_sends_msg("8904");
	EXPECT_CONN_COUNT(1);

	btw("MS also sends RP-ACK, MSC in turn sends CP-ACK for that");
	dtap_expect_tx("0904");
	expect_bssap_clear();
	ms_sends_msg("890106020041020000");
	VERBOSE_ASSERT(dtap_tx_confirmed, == true, "%d");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	btw("SMS is done, conn is gone");
	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	BTW("subscriber detaches, using TMSI");
	expect_bssap_clear();
	ms_sends_msg("050130" "05f4" "03020100");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

static void test_ciph_imei()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000004620";

	comment_start();

	/* implicit: net->authentication_required = true; */
	net->a5_encryption_mask = (1 << 1);
	net->vlr->cfg.check_imei_rqd = true;

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("08010809710000004026f0");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("from HLR, rx _SEND_AUTH_INFO_RESULT; VLR sends Auth Req to MS");
	/* Based on a Ki of 000102030405060708090a0b0c0d0e0f */
	auth_request_sent = false;
	auth_request_expect_rand = "585df1ae287f6e273dce07090d61320b";
	auth_request_expect_autn = NULL;
	gsup_rx("0a"
		/* imsi */
		"0108" "09710000004026f0"
		/* 5 auth vectors... */
		/* TL    TL     rand */
		"0322"  "2010" "585df1ae287f6e273dce07090d61320b"
		/*       TL     sres       TL     kc */
			"2104" "2d8b2c3e" "2208" "61855fb81fc2a800"
		"0322"  "2010" "12aca96fb4ffdea5c985cbafa9b6e18b"
			"2104" "20bde240" "2208" "07fa7502e07e1c00"
		"0322"  "2010" "e7c03ba7cf0e2fde82b2dc4d63077d42"
			"2104" "a29514ae" "2208" "e2b234f807886400"
		"0322"  "2010" "fa8f20b781b5881329d4fea26b1a3c51"
			"2104" "5afc8d72" "2208" "2392f14f709ae000"
		"0322"  "2010" "0fd4cc8dbe8715d1f439e304edfd68dc"
			"2104" "bc8d1c5b" "2208" "da7cdd6bfe2d7000",
		NULL);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Authen Response, VLR accepts and sends Ciphering Mode Command to MS");
	expect_cipher_mode_cmd("61855fb81fc2a800");
	ms_sends_msg("05542d8b2c3e");
	OSMO_ASSERT(cipher_mode_cmd_sent);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("needs ciph, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Ciphering Mode Complete, VLR accepts and sends GSUP LU Req to HLR");
	gsup_expect_tx("04010809710000004026f0280102");
	ms_sends_msg("0632");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000004026f00804036470f1",
		"12010809710000004026f0");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT, and we send an ID Request for the IMEI to the MS");
	dtap_expect_tx("051802");
	gsup_rx("06010809710000004026f0", NULL);

	btw("We will only do business when the IMEI is known");
	EXPECT_CONN_COUNT(1);
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(vsub->imei[0], == 0, "%d");
	vlr_subscr_put(vsub, __func__);
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS replies with an Identity Response, VLR sends the IMEI to HLR");
	gsup_expect_tx("30010809710000004026f050090824433224433224f0");
	ms_sends_msg("0559084a32244332244302");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("HLR accepts the IMEI");
	expect_bssap_clear();
	gsup_rx("32010809710000004026f0510100", NULL);
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	btw("LU was successful, and the conn has already been closed");
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	btw("Subscriber has the IMEI");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(strcmp(vsub->imei, "423423423423420"), == 0, "%d");
	vlr_subscr_put(vsub, __func__);

	BTW("subscriber detaches");
	expect_bssap_clear();
	ms_sends_msg("050130089910070000006402");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

static void test_ciph_imeisv()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000004620";

	comment_start();

	/* implicit: net->authentication_required = true; */
	net->a5_encryption_mask = (1 << 1);
	net->vlr->cfg.retrieve_imeisv_ciphered = true;

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("08010809710000004026f0");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("from HLR, rx _SEND_AUTH_INFO_RESULT; VLR sends Auth Req to MS");
	/* Based on a Ki of 000102030405060708090a0b0c0d0e0f */
	auth_request_sent = false;
	auth_request_expect_rand = "585df1ae287f6e273dce07090d61320b";
	auth_request_expect_autn = NULL;
	gsup_rx("0a"
		/* imsi */
		"0108" "09710000004026f0"
		/* 5 auth vectors... */
		/* TL    TL     rand */
		"0322"  "2010" "585df1ae287f6e273dce07090d61320b"
		/*       TL     sres       TL     kc */
			"2104" "2d8b2c3e" "2208" "61855fb81fc2a800"
		"0322"  "2010" "12aca96fb4ffdea5c985cbafa9b6e18b"
			"2104" "20bde240" "2208" "07fa7502e07e1c00"
		"0322"  "2010" "e7c03ba7cf0e2fde82b2dc4d63077d42"
			"2104" "a29514ae" "2208" "e2b234f807886400"
		"0322"  "2010" "fa8f20b781b5881329d4fea26b1a3c51"
			"2104" "5afc8d72" "2208" "2392f14f709ae000"
		"0322"  "2010" "0fd4cc8dbe8715d1f439e304edfd68dc"
			"2104" "bc8d1c5b" "2208" "da7cdd6bfe2d7000",
		NULL);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Authen Response, VLR accepts and sends Ciphering Mode Command to MS");
	expect_cipher_mode_cmd("61855fb81fc2a800");
	ms_sends_msg("05542d8b2c3e");
	VERBOSE_ASSERT(cipher_mode_cmd_sent, == true, "%d");
	VERBOSE_ASSERT(cipher_mode_cmd_sent_with_imeisv, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("needs ciph, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(vsub->imeisv[0], == 0, "%d");
	vlr_subscr_put(vsub, __func__);

	btw("MS sends Ciphering Mode Complete with IMEISV, VLR accepts and sends GSUP LU Req to HLR");
	gsup_expect_tx("04010809710000004026f0280102");
	ms_sends_msg("063217094b32244332244372f5");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("Subscriber has the IMEISV");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(strcmp(vsub->imeisv, "4234234234234275"), == 0, "%d");
	vlr_subscr_put(vsub, __func__);

	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000004026f00804036470f1",
		"12010809710000004026f0");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT");
	expect_bssap_clear();
	gsup_rx("06010809710000004026f0", NULL);
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	btw("LU was successful, and the conn has already been closed");
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	BTW("subscriber detaches");
	expect_bssap_clear();
	ms_sends_msg("050130089910070000006402");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

static void test_ciph_tmsi_imei()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000004620";

	comment_start();

	/* implicit: net->authentication_required = true; */
	net->a5_encryption_mask = (1 << 1);
	net->vlr->cfg.assign_tmsi = true;
	net->vlr->cfg.check_imei_rqd = true;

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("08010809710000004026f0");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("from HLR, rx _SEND_AUTH_INFO_RESULT; VLR sends Auth Req to MS");
	/* Based on a Ki of 000102030405060708090a0b0c0d0e0f */
	auth_request_sent = false;
	auth_request_expect_rand = "585df1ae287f6e273dce07090d61320b";
	auth_request_expect_autn = NULL;
	gsup_rx("0a"
		/* imsi */
		"0108" "09710000004026f0"
		/* 5 auth vectors... */
		/* TL    TL     rand */
		"0322"  "2010" "585df1ae287f6e273dce07090d61320b"
		/*       TL     sres       TL     kc */
			"2104" "2d8b2c3e" "2208" "61855fb81fc2a800"
		"0322"  "2010" "12aca96fb4ffdea5c985cbafa9b6e18b"
			"2104" "20bde240" "2208" "07fa7502e07e1c00"
		"0322"  "2010" "e7c03ba7cf0e2fde82b2dc4d63077d42"
			"2104" "a29514ae" "2208" "e2b234f807886400"
		"0322"  "2010" "fa8f20b781b5881329d4fea26b1a3c51"
			"2104" "5afc8d72" "2208" "2392f14f709ae000"
		"0322"  "2010" "0fd4cc8dbe8715d1f439e304edfd68dc"
			"2104" "bc8d1c5b" "2208" "da7cdd6bfe2d7000",
		NULL);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Authen Response, VLR accepts and sends Ciphering Mode Command to MS");
	expect_cipher_mode_cmd("61855fb81fc2a800");
	ms_sends_msg("05542d8b2c3e");
	OSMO_ASSERT(cipher_mode_cmd_sent);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("needs ciph, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Ciphering Mode Complete, VLR accepts and sends GSUP LU Req to HLR");
	gsup_expect_tx("04010809710000004026f0280102");
	ms_sends_msg("0632");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000004026f00804036470f1",
		"12010809710000004026f0");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT, and we send an ID Request for the IMEI to the MS");
	dtap_expect_tx("051802");
	gsup_rx("06010809710000004026f0", NULL);

	btw("We will only do business when the IMEI is known");
	EXPECT_CONN_COUNT(1);
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(vsub->imei[0], == 0, "%d");
	vlr_subscr_put(vsub, __func__);
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS replies with an Identity Response, VLR sends the IMEI to HLR");
	gsup_expect_tx("30010809710000004026f050090824433224433224f0");
	ms_sends_msg("0559084a32244332244302");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("HLR accepts the IMEI");
	gsup_rx("32010809710000004026f0510100", NULL);

	btw("a LU Accept with a new TMSI was sent, waiting for TMSI Realloc Compl");
	EXPECT_CONN_COUNT(1);
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("even though the TMSI is not acked, we can already find the subscr with it");
	vsub = vlr_subscr_find_by_tmsi(net->vlr, 0x03020100, __func__);
	VERBOSE_ASSERT(vsub != NULL, == true, "%d");
	VERBOSE_ASSERT(strcmp(vsub->imsi, imsi), == 0, "%d");
	VERBOSE_ASSERT(vsub->tmsi_new, == 0x03020100, "0x%08x");
	VERBOSE_ASSERT(vsub->tmsi, == GSM_RESERVED_TMSI, "0x%08x");
	vlr_subscr_put(vsub, __func__);

	btw("MS sends TMSI Realloc Complete");
	expect_bssap_clear();
	ms_sends_msg("055b");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	btw("LU was successful, and the conn has already been closed");
	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	btw("Subscriber has the IMEI and TMSI");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(strcmp(vsub->imei, "423423423423420"), == 0, "%d");
	VERBOSE_ASSERT(vsub->tmsi, == 0x03020100, "0x%08x");
	vlr_subscr_put(vsub, __func__);

	BTW("subscriber detaches, using TMSI");
	expect_bssap_clear();
	ms_sends_msg("050130" "05f4" "03020100");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

static void test_gsm_ciph_in_umts_env()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000010650";
	const char *sms =
		"09" /* SMS messages */
		"01" /* CP-DATA */
		"58" /* length */
		"01" /* Network to MS */
		"00" /* reference */
		/* originator (gsm411_send_sms() hardcodes this weird nr) */
		"0791" "447758100650" /* 447785016005 */
		"00" /* dest */
		/* SMS TPDU */
		"4c" /* len */
		"00" /* SMS deliver */
		"05802443f2" /* originating address 42342 */
		"00" /* TP-PID */
		"00" /* GSM default alphabet */
		"071010" /* Y-M-D (from wrapped gsm340_gen_scts())*/
		"000000" /* H-M-S */
		"00" /* GMT+0 */
		"44" /* data length */
		"5079da1e1ee7416937485e9ea7c965373d1d6683c270383b3d0e"
		"d3d36ff71c949e83c22072799e9687c5ec32a81d96afcbf4b4fb"
		"0c7ac3e9e9b7db05";

	comment_start();

	/* implicit: net->authentication_required = true; */
	net->a5_encryption_mask = (1 << 1);
	rx_from_ran = OSMO_RAT_GERAN_A;

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("080108" "09710000000156f0");
	ms_sends_msg("0508" /* MM LU */
		     "7" /* ciph key seq: no key available */
		     "0" /* LU type: normal */
		     "ffffff" "0000" /* LAI, LAC */
		     "57" /* classmark 1: R99, early classmark, no power lvl */
		     "089910070000106005" /* IMSI */
		     "3303575886" /* classmark 2 */
		     );
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("from HLR, rx _SEND_AUTH_INFO_RESULT; VLR sends *UMTS AKA* Auth Req to MS");
	/* based on
	 * 2G auth: COMP128v1
	 *          KI=7bcd108be4c3d551ee6c67faaf52bd68
	 * 3G auth: MILENAGE
	 *          K=7bcd108be4c3d551ee6c67faaf52bd68
	 *          OPC=6e23f641ce724679b73d933515a8589d
	 *          IND-bitlen=5 last-SQN=641
	 * Note that the SRES will be calculated by COMP128v1, separately from 3G tokens;
	 * the resulting Kc to use for ciphering returned by the HLR is also calculated from COMP128v1.
	 */
	auth_request_sent = false;
	auth_request_expect_rand = "4ac8d1cd1a51937597ca1016fe69a0fa";
	auth_request_expect_autn = "2d837d2b0d6f00004b282d5acf23428d";
	gsup_rx("0a"
		/* imsi */
		"0108" "09710000000156f0"
		/* 5 auth vectors... */
		/* TL    TL     rand */
		"0362" "2010" "4ac8d1cd1a51937597ca1016fe69a0fa"
		/*       TL     sres       TL     kc */
		       "2104" "dacc4b26" "2208" "7a75f0ac9b844400"
		/*       TL     3G IK */
		       "2310" "3747da4e31545baa2db59e500bdae047"
		/*       TL     3G CK */
		       "2410" "8544d35b945ccba01a7f1293575291c3"
		/*       TL     AUTN */
		       "2510" "2d837d2b0d6f00004b282d5acf23428d"
		/*       TL     RES */
		       "2708" "37527064741f8ddb"
		/* TL    TL     rand */
		"0362" "2010" "b2661531b97b12c5a2edc21a0ed16fc5"
		       "2104" "2fb4cfad" "2208" "da149b11d473f400"
		       "2310" "3fe013b1a428ea737c37f8f0288c8edf"
		       "2410" "f275438c02b97e4d6f639dddda3d10b9"
		       "2510" "78cdd96c60840000322f421b3bb778b1"
		       "2708" "ed3ebf9cb6ea48ed"
		"0362" "2010" "54d8f19778056666b41c8c25e52eb60c"
		       "2104" "0ff61e0f" "2208" "26ec67fad3073000"
		       "2310" "2868b0922c652616f1c975e3eaf7943a"
		       "2410" "6a84a20b1bc13ec9840466406d2dd91e"
		       "2510" "53f3e5632b3d00008865dd54d49663f2"
		       "2708" "86e848a9e7ad8cd5"
		"0362" "2010" "1f05607ff9c8984f46ad97f8c9a94982"
		       "2104" "91a36e3d" "2208" "5d84421884fdcc00"
		       "2310" "2171fef54b81e30c83a598a5e44f634c"
		       "2410" "f02d088697509827565b46938fece211"
		       "2510" "1b43bbf9815e00001cb9b2a9f6b8a77c"
		       "2708" "373e67d62e719c51"
		"0362" "2010" "80d89a58a2a41050918caf68a4e93c64"
		       "2104" "a319f5f1" "2208" "883df2b867293000"
		       "2310" "fa5d70f929ff298efb160413698dc107"
		       "2410" "ae9a3d8ce70ce13bac297bdb91cd6c68"
		       "2510" "5c0dc2eeaefa0000396882a1fe2cf80b"
		       "2708" "65ab1cad216bfe87",
		NULL);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends *GSM AKA* Authen Response, VLR accepts and sends Ciphering Mode Command to MS");
	expect_cipher_mode_cmd("7a75f0ac9b844400");
	ms_sends_msg("0554" "dacc4b26");
	OSMO_ASSERT(cipher_mode_cmd_sent);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Ciphering Mode Complete, VLR accepts and sends GSUP LU Req to HLR");
	gsup_expect_tx("04010809710000000156f0280102");
	ms_sends_msg("0632");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000000156f00804032443f2",
		"12010809710000000156f0");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT");
	expect_bssap_clear();
	gsup_rx("06010809710000000156f0", NULL);
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	btw("LU was successful, and the conn has already been closed");
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	BTW("after a while, a new conn sends a CM Service Request. VLR responds with *UMTS AKA* Auth Req, 2nd auth vector");
	auth_request_sent = false;
	auth_request_expect_rand = "b2661531b97b12c5a2edc21a0ed16fc5";
	auth_request_expect_autn = "78cdd96c60840000322f421b3bb778b1";
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
	thwart_rx_non_initial_requests();

	btw("MS sends *GSM AKA* Authen Response, VLR accepts and requests Ciphering");
	expect_cipher_mode_cmd("da149b11d473f400");
	ms_sends_msg("0554" "2fb4cfad");
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");
	VERBOSE_ASSERT(cipher_mode_cmd_sent, == true, "%d");

	btw("MS sends Ciphering Mode Complete, VLR accepts; above Ciphering is an implicit CM Service Accept");
	ms_sends_msg("0632");
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");

	/* Release connection */
	expect_bssap_clear(OSMO_RAT_GERAN_A);
	conn_conclude_cm_service_req(g_conn, OSMO_RAT_GERAN_A);

	btw("all requests serviced, conn has been released");
	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	BTW("an SMS is sent, MS is paged");
	paging_expect_imsi(imsi);
	paging_sent = false;
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 0, "%d");

	send_sms(vsub, vsub,
		 "Privacy in residential applications is a desirable"
		 " marketing option.");

	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 1, "%d");
	vlr_subscr_put(vsub, __func__);
	vsub = NULL;
	VERBOSE_ASSERT(paging_sent, == true, "%d");
	VERBOSE_ASSERT(paging_stopped, == false, "%d");

	btw("the subscriber and its pending request should remain");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 1, "%d");
	vlr_subscr_put(vsub, __func__);

	btw("MS replies with Paging Response, and VLR sends *UMTS AKA* Auth Request with third key");
	auth_request_sent = false;
	auth_request_expect_rand = "54d8f19778056666b41c8c25e52eb60c";
	auth_request_expect_autn = "53f3e5632b3d00008865dd54d49663f2";
	ms_sends_msg("062707"
		     "03575886" /* classmark 2 */
		     "089910070000106005" /* IMSI */);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");

	btw("needs auth, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS sends *GSM AKA* Authen Response, VLR accepts and requests Ciphering");
	expect_cipher_mode_cmd("26ec67fad3073000");
	ms_sends_msg("0554" "0ff61e0f");
	VERBOSE_ASSERT(cipher_mode_cmd_sent, == true, "%d");

	btw("MS sends Ciphering Mode Complete, VLR accepts and sends pending SMS");
	dtap_expect_tx(sms);
	ms_sends_msg("0632");
	VERBOSE_ASSERT(dtap_tx_confirmed, == true, "%d");
	VERBOSE_ASSERT(paging_stopped, == true, "%d");

	btw("SMS was delivered, no requests pending for subscr");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 0, "%d");
	vlr_subscr_put(vsub, __func__);

	btw("conn is still open to wait for SMS ack dance");
	EXPECT_CONN_COUNT(1);

	btw("MS replies with CP-ACK for received SMS");
	ms_sends_msg("8904");
	EXPECT_CONN_COUNT(1);

	btw("MS also sends RP-ACK, MSC in turn sends CP-ACK for that");
	dtap_expect_tx("0904");
	expect_bssap_clear();
	ms_sends_msg("890106020041020000");
	VERBOSE_ASSERT(dtap_tx_confirmed, == true, "%d");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	btw("SMS is done, conn is gone");
	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	BTW("subscriber detaches");
	expect_bssap_clear();
	ms_sends_msg("050130"
		     "089910070000106005" /* IMSI */);
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

static void test_a5_3_supported()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000004620";

	comment_start();

	/* implicit: net->authentication_required = true; */
	net->a5_encryption_mask = (1 << 3); /* A5/3 */

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("08010809710000004026f0");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("from HLR, rx _SEND_AUTH_INFO_RESULT; VLR sends Auth Req to MS");
	/* Based on a Ki of 000102030405060708090a0b0c0d0e0f */
	auth_request_sent = false;
	auth_request_expect_rand = "585df1ae287f6e273dce07090d61320b";
	auth_request_expect_autn = NULL;
	gsup_rx("0a"
		/* imsi */
		"0108" "09710000004026f0"
		/* 5 auth vectors... */
		/* TL    TL     rand */
		"0322"  "2010" "585df1ae287f6e273dce07090d61320b"
		/*       TL     sres       TL     kc */
			"2104" "2d8b2c3e" "2208" "61855fb81fc2a800"
		"0322"  "2010" "12aca96fb4ffdea5c985cbafa9b6e18b"
			"2104" "20bde240" "2208" "07fa7502e07e1c00"
		"0322"  "2010" "e7c03ba7cf0e2fde82b2dc4d63077d42"
			"2104" "a29514ae" "2208" "e2b234f807886400"
		"0322"  "2010" "fa8f20b781b5881329d4fea26b1a3c51"
			"2104" "5afc8d72" "2208" "2392f14f709ae000"
		"0322"  "2010" "0fd4cc8dbe8715d1f439e304edfd68dc"
			"2104" "bc8d1c5b" "2208" "da7cdd6bfe2d7000",
		NULL);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");

	BTW("MS sends Authen Response, VLR accepts and wants to send Ciphering Mode Command to MS"
	    " -- but needs Classmark 2 to determine whether A5/3 is supported");
	cipher_mode_cmd_sent = false;
	ms_sends_msg("05542d8b2c3e");
	OSMO_ASSERT(!cipher_mode_cmd_sent);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("BSC sends back a BSSMAP Classmark Update, that triggers the Ciphering Mode Command in A5/3");
	expect_cipher_mode_cmd("61855fb81fc2a800");
	bss_sends_bssap_mgmt("541203505886130b6014042f6503b8800d2100");
	OSMO_ASSERT(cipher_mode_cmd_sent);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Ciphering Mode Complete, VLR accepts and sends GSUP LU Req to HLR");
	gsup_expect_tx("04010809710000004026f0280102");
	ms_sends_msg("0632");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000004026f00804032443f2",
		"12010809710000004026f0");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT");
	expect_bssap_clear();
	gsup_rx("06010809710000004026f0", NULL);
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	btw("LU was successful, and the conn has already been closed");
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	BTW("after a while, a new conn sends a CM Service Request. VLR responds with Auth Req, 2nd auth vector");
	cm_service_result_sent = RES_NONE;
	auth_request_sent = false;
	auth_request_expect_rand = "12aca96fb4ffdea5c985cbafa9b6e18b";
	ms_sends_msg("05247803305886089910070000006402");
	OSMO_ASSERT(g_conn);
	OSMO_ASSERT(g_conn->fi);
	OSMO_ASSERT(g_conn->vsub);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");

	btw("needs auth, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS sends Authen Response, VLR accepts and requests Ciphering. We already know Classmark 3,"
	    " so no need to request Classmark Update.");
	expect_cipher_mode_cmd("07fa7502e07e1c00");
	ms_sends_msg("0554" "20bde240" /* 2nd vector's sres, s.a. */);
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");
	VERBOSE_ASSERT(cipher_mode_cmd_sent, == true, "%d");

	btw("needs ciph, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS sends Ciphering Mode Complete, VLR accepts; above Ciphering is an implicit CM Service Accept");
	ms_sends_msg("0632");
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");

	/* Release connection */
	expect_bssap_clear(OSMO_RAT_GERAN_A);
	conn_conclude_cm_service_req(g_conn, OSMO_RAT_GERAN_A);

	btw("all requests serviced, conn has been released");
	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	BTW("an SMS is sent, MS is paged");
	paging_expect_imsi(imsi);
	paging_sent = false;
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 0, "%d");

	send_sms(vsub, vsub,
		 "Privacy in residential applications is a desirable"
		 " marketing option.");

	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 1, "%d");
	vlr_subscr_put(vsub, __func__);
	vsub = NULL;
	VERBOSE_ASSERT(paging_sent, == true, "%d");
	VERBOSE_ASSERT(paging_stopped, == false, "%d");

	btw("the subscriber and its pending request should remain");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 1, "%d");
	vlr_subscr_put(vsub, __func__);

	btw("MS replies with Paging Response, and VLR sends Auth Request with third key");
	auth_request_sent = false;
	auth_request_expect_rand = "e7c03ba7cf0e2fde82b2dc4d63077d42";
	ms_sends_msg("06270703305882089910070000006402");
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");

	btw("needs auth, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS sends Authen Response, VLR accepts and requests Ciphering");
	expect_cipher_mode_cmd("e2b234f807886400");
	ms_sends_msg("0554" "a29514ae" /* 3rd vector's sres, s.a. */);
	VERBOSE_ASSERT(cipher_mode_cmd_sent, == true, "%d");

	btw("needs ciph, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS sends Ciphering Mode Complete, VLR accepts and sends pending SMS");
	dtap_expect_tx("09" /* SMS messages */
		       "01" /* CP-DATA */
		       "58" /* length */
		       "01" /* Network to MS */
		       "00" /* reference */
		       /* originator (gsm411_send_sms() hardcodes this weird nr) */
		       "0791" "447758100650" /* 447785016005 */
		       "00" /* dest */
		       /* SMS TPDU */
		       "4c" /* len */
		       "00" /* SMS deliver */
		       "05802443f2" /* originating address 42342 */
		       "00" /* TP-PID */
		       "00" /* GSM default alphabet */
		       "071010" /* Y-M-D (from wrapped gsm340_gen_scts())*/
		       "000000" /* H-M-S */
		       "00" /* GMT+0 */
		       "44" /* data length */
		       "5079da1e1ee7416937485e9ea7c965373d1d6683c270383b3d0e"
		       "d3d36ff71c949e83c22072799e9687c5ec32a81d96afcbf4b4fb"
		       "0c7ac3e9e9b7db05");
	ms_sends_msg("0632");
	VERBOSE_ASSERT(dtap_tx_confirmed, == true, "%d");
	VERBOSE_ASSERT(paging_stopped, == true, "%d");

	btw("SMS was delivered, no requests pending for subscr");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 0, "%d");
	vlr_subscr_put(vsub, __func__);

	btw("conn is still open to wait for SMS ack dance");
	EXPECT_CONN_COUNT(1);

	btw("MS replies with CP-ACK for received SMS");
	ms_sends_msg("8904");
	EXPECT_CONN_COUNT(1);

	btw("MS also sends RP-ACK, MSC in turn sends CP-ACK for that");
	dtap_expect_tx("0904");
	expect_bssap_clear();
	ms_sends_msg("890106020041020000");
	VERBOSE_ASSERT(dtap_tx_confirmed, == true, "%d");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	btw("SMS is done, conn is gone");
	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	BTW("subscriber detaches");
	expect_bssap_clear();
	ms_sends_msg("050130089910070000006402");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

/* During CM Service Request or Paging Response we already have Classmark 2 that indicates A5/3
 * availablity. Here, in a hacky way remove the knowledge of Classmark 2 to tickle a code path where
 * proc_arq_fsm needs a Classmark Update during Ciphering. Shouldn't happen in reality though. */
static void test_cm_service_needs_classmark_update()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000004620";

	comment_start();

	/* A5/3 support is indicated in Classmark 3. By configuring A5/3, trigger the code paths that
	 * send a Classmark Request. */
	net->a5_encryption_mask = (1 << 3); /* A5/3 */
        /* implicit: net->authentication_required = true; */

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("08010809710000004026f0");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("from HLR, rx _SEND_AUTH_INFO_RESULT; VLR sends Auth Req to MS");
	/* Based on a Ki of 000102030405060708090a0b0c0d0e0f */
	auth_request_sent = false;
	auth_request_expect_rand = "585df1ae287f6e273dce07090d61320b";
	auth_request_expect_autn = NULL;
	gsup_rx("0a"
		/* imsi */
		"0108" "09710000004026f0"
		/* 5 auth vectors... */
		/* TL    TL     rand */
		"0322"  "2010" "585df1ae287f6e273dce07090d61320b"
		/*       TL     sres       TL     kc */
			"2104" "2d8b2c3e" "2208" "61855fb81fc2a800"
		"0322"  "2010" "12aca96fb4ffdea5c985cbafa9b6e18b"
			"2104" "20bde240" "2208" "07fa7502e07e1c00"
		"0322"  "2010" "e7c03ba7cf0e2fde82b2dc4d63077d42"
			"2104" "a29514ae" "2208" "e2b234f807886400"
		"0322"  "2010" "fa8f20b781b5881329d4fea26b1a3c51"
			"2104" "5afc8d72" "2208" "2392f14f709ae000"
		"0322"  "2010" "0fd4cc8dbe8715d1f439e304edfd68dc"
			"2104" "bc8d1c5b" "2208" "da7cdd6bfe2d7000",
		NULL);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");

	BTW("MS sends Authen Response, VLR accepts and wants to send Ciphering Mode Command to MS"
	    " -- but needs Classmark 2 to determine whether A5/3 is supported");
	cipher_mode_cmd_sent = false;
	ms_sends_msg("05542d8b2c3e");
	OSMO_ASSERT(!cipher_mode_cmd_sent);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("BSC sends back a BSSMAP Classmark Update, that triggers the Ciphering Mode Command in A5/3");
	expect_cipher_mode_cmd("61855fb81fc2a800");
	bss_sends_bssap_mgmt("541203505886130b6014042f6503b8800d2100");
	OSMO_ASSERT(cipher_mode_cmd_sent);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Ciphering Mode Complete, VLR accepts and sends GSUP LU Req to HLR");
	gsup_expect_tx("04010809710000004026f0280102");
	ms_sends_msg("0632");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000004026f00804032443f2",
		"12010809710000004026f0");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT");
	expect_bssap_clear();
	gsup_rx("06010809710000004026f0", NULL);
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	btw("LU was successful, and the conn has already been closed");
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);


	BTW("after a while, a new conn sends a CM Service Request. VLR responds with Auth Req, 2nd auth vector");
	cm_service_result_sent = RES_NONE;
	auth_request_sent = false;
	auth_request_expect_rand = "12aca96fb4ffdea5c985cbafa9b6e18b";
	ms_sends_msg("05247803305886089910070000006402");
	OSMO_ASSERT(g_conn);
	OSMO_ASSERT(g_conn->fi);
	OSMO_ASSERT(g_conn->vsub);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");

	btw("needs auth, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS sends Authen Response, VLR accepts and requests Ciphering. We already know Classmark 3,"
	    " so no need to request Classmark Update.");
	expect_cipher_mode_cmd("07fa7502e07e1c00");
	ms_sends_msg("0554" "20bde240" /* 2nd vector's sres, s.a. */);
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");
	VERBOSE_ASSERT(cipher_mode_cmd_sent, == true, "%d");

	btw("needs ciph, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS sends Ciphering Mode Complete, VLR accepts; above Ciphering is an implicit CM Service Accept");
	ms_sends_msg("0632");
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");

	/* Release connection */
	expect_bssap_clear(OSMO_RAT_GERAN_A);
	conn_conclude_cm_service_req(g_conn, OSMO_RAT_GERAN_A);

	btw("all requests serviced, conn has been released");
	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	BTW("an SMS is sent, MS is paged");
	paging_expect_imsi(imsi);
	paging_sent = false;
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 0, "%d");

	send_sms(vsub, vsub, "Privacy in residential applications is a desirable marketing option.");

	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 1, "%d");
	vlr_subscr_put(vsub, __func__);
	vsub = NULL;
	VERBOSE_ASSERT(paging_sent, == true, "%d");
	VERBOSE_ASSERT(paging_stopped, == false, "%d");

	btw("the subscriber and its pending request should remain");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 1, "%d");
	vlr_subscr_put(vsub, __func__);

	btw("MS replies with Paging Response, and VLR sends Auth Request with third key");
	auth_request_sent = false;
	auth_request_expect_rand = "e7c03ba7cf0e2fde82b2dc4d63077d42";
	ms_sends_msg("06270703305882089910070000006402");
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");

	BTW("Fake a situation where Classmark 2 is unknown during proc_arq_fsm");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	vsub->classmark.classmark2_len = 0;
	vsub->classmark.classmark3_len = 0;
	vlr_subscr_put(vsub, __func__);
	

	btw("MS sends Authen Response, VLR accepts and requests Ciphering");
	btw("MS sends Authen Response, VLR accepts and requests Ciphering."
	    " Normally, we'd know Classmark 3, but this test removed it."
	    " Hence a Classmark Request is generated.");
	cipher_mode_cmd_sent = false;
	ms_sends_msg("0554" "a29514ae" /* 3rd vector's sres, s.a. */);
	OSMO_ASSERT(!cipher_mode_cmd_sent);

	btw("BSC sends back a BSSMAP Classmark Update, that triggers the Ciphering Mode Command in A5/3");
	expect_cipher_mode_cmd("e2b234f807886400");
	bss_sends_bssap_mgmt("541203505886130b6014042f6503b8800d2100");
	OSMO_ASSERT(cipher_mode_cmd_sent);

	btw("needs ciph, not yet accepted");
	EXPECT_ACCEPTED(false);

	btw("MS sends Ciphering Mode Complete, VLR accepts and sends pending SMS");
	dtap_expect_tx("09" /* SMS messages */
		       "01" /* CP-DATA */
		       "58" /* length */
		       "01" /* Network to MS */
		       "00" /* reference */
		       /* originator (gsm411_send_sms() hardcodes this weird nr) */
		       "0791" "447758100650" /* 447785016005 */
		       "00" /* dest */
		       /* SMS TPDU */
		       "4c" /* len */
		       "00" /* SMS deliver */
		       "05802443f2" /* originating address 42342 */
		       "00" /* TP-PID */
		       "00" /* GSM default alphabet */
		       "071010" /* Y-M-D (from wrapped gsm340_gen_scts())*/
		       "000000" /* H-M-S */
		       "00" /* GMT+0 */
		       "44" /* data length */
		       "5079da1e1ee7416937485e9ea7c965373d1d6683c270383b3d0e"
		       "d3d36ff71c949e83c22072799e9687c5ec32a81d96afcbf4b4fb"
		       "0c7ac3e9e9b7db05");
	ms_sends_msg("0632");
	VERBOSE_ASSERT(dtap_tx_confirmed, == true, "%d");
	VERBOSE_ASSERT(paging_stopped, == true, "%d");

	btw("SMS was delivered, no requests pending for subscr");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 0, "%d");
	vlr_subscr_put(vsub, __func__);

	btw("conn is still open to wait for SMS ack dance");
	EXPECT_CONN_COUNT(1);

	btw("MS replies with CP-ACK for received SMS");
	ms_sends_msg("8904");
	EXPECT_CONN_COUNT(1);

	btw("MS also sends RP-ACK, MSC in turn sends CP-ACK for that");
	dtap_expect_tx("0904");
	expect_bssap_clear();
	ms_sends_msg("890106020041020000");
	VERBOSE_ASSERT(dtap_tx_confirmed, == true, "%d");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	btw("SMS is done, conn is gone");
	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	BTW("subscriber detaches");
	expect_bssap_clear();
	ms_sends_msg("050130089910070000006402");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}


msc_vlr_test_func_t msc_vlr_tests[] = {
	test_ciph,
	test_ciph_tmsi,
	test_ciph_imei,
	test_ciph_imeisv,
	test_ciph_tmsi_imei,
	test_gsm_ciph_in_umts_env,
	test_a5_3_supported,
	test_cm_service_needs_classmark_update,
	NULL
};
