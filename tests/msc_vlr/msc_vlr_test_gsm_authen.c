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

static void test_gsm_authen()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000004620";

	comment_start();

	net->authentication_required = true;

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("08010809710000004026f0" CN_DOMAIN VLR_TO_HLR);
	ms_sends_msg("0508020081680001"
		     "30" /* <-- Revision Level == 1, i.e. is_r99 == false */
		     "089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("from HLR, rx _SEND_AUTH_INFO_RESULT; VLR sends Auth Req to MS");
	auth_request_sent = false;
	auth_request_expect_rand = "585df1ae287f6e273dce07090d61320b";
	auth_request_expect_autn = NULL;
	/* Based on a Ki of 000102030405060708090a0b0c0d0e0f */
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
			"2104" "bc8d1c5b" "2208" "da7cdd6bfe2d7000"
		HLR_TO_VLR,
		NULL);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("If the HLR were to send a GSUP _UPDATE_LOCATION_RESULT we'd still reject");
	gsup_rx("06010809710000004026f0" HLR_TO_VLR, NULL);
	EXPECT_ACCEPTED(false);

	thwart_rx_non_initial_requests();

	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Authen Response, VLR accepts and sends GSUP LU Req to HLR");
	gsup_expect_tx("04010809710000004026f0" CN_DOMAIN VLR_TO_HLR);
	ms_sends_msg("05542d8b2c3e");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000004026f00804036470f1" HLR_TO_VLR,
		"12010809710000004026f0" VLR_TO_HLR);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT");
	expect_bssap_clear();
	gsup_rx("06010809710000004026f0" HLR_TO_VLR, NULL);
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	btw("LU was successful, and the conn has already been closed");
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	BTW("after a while, a new conn sends a CM Service Request. VLR responds with Auth Req, 2nd auth vector");
	auth_request_sent = false;
	auth_request_expect_rand = "12aca96fb4ffdea5c985cbafa9b6e18b";
	cm_service_result_sent = RES_NONE;
	ms_sends_msg("05247403305886089910070000006402");
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");

	btw("needs auth, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS sends Authen Response, VLR accepts with a CM Service Accept");
	gsup_expect_tx(NULL);
	ms_sends_msg("0554" "20bde240" /* 2nd vector's sres, s.a. */);
	VERBOSE_ASSERT(cm_service_result_sent, == RES_ACCEPT, "%d");

	/* Release connection */
	expect_bssap_clear();
	conn_conclude_cm_service_req(g_msub, MSC_A_USE_CM_SERVICE_SMS);

	btw("all requests serviced, conn has been released");
	ran_sends_clear_complete();
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

	btw("MS sends Authen Response, VLR accepts and sends pending SMS");
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
	ms_sends_msg("0554" "a29514ae" /* 3rd vector's sres, s.a. */);
	VERBOSE_ASSERT(dtap_tx_confirmed, == true, "%d");

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
	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	BTW("subscriber detaches");
	expect_bssap_clear();
	ms_sends_msg("050130089910070000006402");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

static void test_gsm_authen_tmsi()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000004620";

	comment_start();

	net->authentication_required = true;
	net->vlr->cfg.assign_tmsi = true;

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("08010809710000004026f0" CN_DOMAIN VLR_TO_HLR);
	ms_sends_msg("0508020081680001"
		     "30" /* <-- Revision Level == 1, i.e. is_r99 == false */
		     "089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("from HLR, rx _SEND_AUTH_INFO_RESULT; VLR sends Auth Req to MS");
	auth_request_sent = false;
	auth_request_expect_rand = "585df1ae287f6e273dce07090d61320b";
	auth_request_expect_autn = NULL;
	/* Based on a Ki of 000102030405060708090a0b0c0d0e0f */
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
			"2104" "bc8d1c5b" "2208" "da7cdd6bfe2d7000"
		HLR_TO_VLR,
		NULL);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("If the HLR were to send a GSUP _UPDATE_LOCATION_RESULT we'd still reject");
	gsup_rx("06010809710000004026f0" HLR_TO_VLR, NULL);
	EXPECT_ACCEPTED(false);

	thwart_rx_non_initial_requests();

	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Authen Response, VLR accepts and sends GSUP LU Req to HLR");
	gsup_expect_tx("04010809710000004026f0" CN_DOMAIN VLR_TO_HLR);
	ms_sends_msg("05542d8b2c3e");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000004026f00804036470f1" HLR_TO_VLR,
		"12010809710000004026f0" VLR_TO_HLR);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT");
	gsup_rx("06010809710000004026f0" HLR_TO_VLR, NULL);

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
	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	btw("Subscriber has the new TMSI");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	VERBOSE_ASSERT(vsub != NULL, == true, "%d");
	VERBOSE_ASSERT(strcmp(vsub->imsi, imsi), == 0, "%d");
	VERBOSE_ASSERT(vsub->tmsi_new, == GSM_RESERVED_TMSI, "0x%08x");
	VERBOSE_ASSERT(vsub->tmsi, == 0x03020100, "0x%08x");
	vlr_subscr_put(vsub, __func__);

	BTW("after a while, a new conn sends a CM Service Request using above TMSI. VLR responds with Auth Req, 2nd auth vector");
	auth_request_sent = false;
	auth_request_expect_rand = "12aca96fb4ffdea5c985cbafa9b6e18b";
	cm_service_result_sent = RES_NONE;
	ms_sends_msg("05247403305886" "05f4" "03020100");
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");

	btw("needs auth, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS sends Authen Response, VLR accepts with a CM Service Accept");
	gsup_expect_tx(NULL);
	ms_sends_msg("0554" "20bde240" /* 2nd vector's sres, s.a. */);
	VERBOSE_ASSERT(cm_service_result_sent, == RES_ACCEPT, "%d");

	/* Release connection */
	expect_bssap_clear();
	conn_conclude_cm_service_req(g_msub, MSC_A_USE_CM_SERVICE_SMS);

	btw("all requests serviced, conn has been released");
	ran_sends_clear_complete();
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

	btw("MS sends Authen Response, VLR accepts and sends pending SMS");
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
	ms_sends_msg("0554" "a29514ae" /* 3rd vector's sres, s.a. */);
	VERBOSE_ASSERT(dtap_tx_confirmed, == true, "%d");

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
	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	/* TODO: when the subscriber detaches, the vlr_subscr gets
	 * deallocated and we no longer know the TMSI. This case is covered by
	 * test_lu_unknown_tmsi(), so here I'd like to still have the TMSI.
	BTW("subscriber detaches, using TMSI");
	expect_bssap_clear();
	ms_sends_msg("050130" "05f4" "03020100");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");
	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);
	 */

	BTW("subscriber sends LU Request, this time with the TMSI");
	btw("Location Update request causes an Auth Req to MS");
	lu_result_sent = RES_NONE;
	auth_request_sent = false;
	auth_request_expect_rand = "fa8f20b781b5881329d4fea26b1a3c51";
	ms_sends_msg("0508020081680001"
		     "30" /* <-- Revision Level == 1, i.e. is_r99 == false */
		     "05f4" "03020100");
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Authen Response, VLR accepts and sends GSUP LU Req to HLR");
	gsup_expect_tx("04010809710000004026f0" CN_DOMAIN VLR_TO_HLR);
	ms_sends_msg("05545afc8d72");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000004026f00804036470f1" HLR_TO_VLR,
		"12010809710000004026f0" VLR_TO_HLR);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT");
	gsup_rx("06010809710000004026f0" HLR_TO_VLR, NULL);

	btw("a LU Accept with a new TMSI was sent, waiting for TMSI Realloc Compl");
	EXPECT_CONN_COUNT(1);
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("even though the TMSI is not acked, we can already find the subscr with it");
	vsub = vlr_subscr_find_by_tmsi(net->vlr, 0x07060504, __func__);
	VERBOSE_ASSERT(vsub != NULL, == true, "%d");
	VERBOSE_ASSERT(strcmp(vsub->imsi, imsi), == 0, "%d");
	VERBOSE_ASSERT(vsub->tmsi_new, == 0x07060504, "0x%08x");
	VERBOSE_ASSERT(vsub->tmsi, == 0x03020100, "0x%08x");
	vlr_subscr_put(vsub, __func__);

	btw("MS sends TMSI Realloc Complete");
	expect_bssap_clear();
	ms_sends_msg("055b");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	btw("LU was successful, and the conn has already been closed");
	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	btw("subscriber has the new TMSI");
	vsub = vlr_subscr_find_by_tmsi(net->vlr, 0x07060504, __func__);
	VERBOSE_ASSERT(vsub != NULL, == true, "%d");
	VERBOSE_ASSERT(strcmp(vsub->imsi, imsi), == 0, "%d");
	VERBOSE_ASSERT(vsub->tmsi_new, == GSM_RESERVED_TMSI, "0x%08x");
	VERBOSE_ASSERT(vsub->tmsi, == 0x07060504, "0x%08x");
	vlr_subscr_put(vsub, __func__);

	BTW("subscriber detaches, using new TMSI");
	expect_bssap_clear();
	ms_sends_msg("050130" "05f4" "07060504");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

static void test_gsm_authen_imei()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000004620";

	comment_start();

	net->authentication_required = true;
	net->vlr->cfg.check_imei_rqd = true;

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("08010809710000004026f0" CN_DOMAIN VLR_TO_HLR);
	ms_sends_msg("0508020081680001"
		     "30" /* <-- Revision Level == 1, i.e. is_r99 == false */
		     "089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("from HLR, rx _SEND_AUTH_INFO_RESULT; VLR sends Auth Req to MS");
	auth_request_sent = false;
	auth_request_expect_rand = "585df1ae287f6e273dce07090d61320b";
	auth_request_expect_autn = NULL;
	/* Based on a Ki of 000102030405060708090a0b0c0d0e0f */
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
			"2104" "bc8d1c5b" "2208" "da7cdd6bfe2d7000"
		HLR_TO_VLR,
		NULL);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("If the HLR were to send a GSUP _UPDATE_LOCATION_RESULT we'd still reject");
	gsup_rx("06010809710000004026f0" HLR_TO_VLR, NULL);
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Authen Response, VLR accepts and sends GSUP LU Req to HLR");
	gsup_expect_tx("04010809710000004026f0" CN_DOMAIN VLR_TO_HLR);
	ms_sends_msg("05542d8b2c3e");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000004026f00804036470f1" HLR_TO_VLR,
		"12010809710000004026f0" VLR_TO_HLR);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT, and we send an ID Request for the IMEI to the MS");
	dtap_expect_tx("051802");
	gsup_rx("06010809710000004026f0" HLR_TO_VLR, NULL);

	btw("We will only do business when the IMEI is known");
	EXPECT_CONN_COUNT(1);
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(vsub->imei[0], == 0, "%d");
	vlr_subscr_put(vsub, __func__);
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS replies with an Identity Response, VLR sends the IMEI to HLR");
	gsup_expect_tx("30010809710000004026f050080724433224433224" VLR_TO_HLR);
	ms_sends_msg("0559084a32244332244302");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("HLR accepts the IMEI");
	expect_bssap_clear();
	gsup_rx("32010809710000004026f0510100" HLR_TO_VLR, NULL);
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	btw("LU was successful, and the conn has already been closed");
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	btw("Subscriber has the IMEI");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(strcmp(vsub->imei, "42342342342342"), == 0, "%d");
	vlr_subscr_put(vsub, __func__);

	BTW("subscriber detaches");
	expect_bssap_clear();
	ms_sends_msg("050130089910070000006402");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

static void test_gsm_authen_imei_nack()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000004620";

	comment_start();

	net->authentication_required = true;
	net->vlr->cfg.check_imei_rqd = true;

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("08010809710000004026f0" CN_DOMAIN VLR_TO_HLR);
	ms_sends_msg("0508020081680001"
		     "30" /* <-- Revision Level == 1, i.e. is_r99 == false */
		     "089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("from HLR, rx _SEND_AUTH_INFO_RESULT; VLR sends Auth Req to MS");
	auth_request_sent = false;
	auth_request_expect_rand = "585df1ae287f6e273dce07090d61320b";
	auth_request_expect_autn = NULL;
	/* Based on a Ki of 000102030405060708090a0b0c0d0e0f */
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
			"2104" "bc8d1c5b" "2208" "da7cdd6bfe2d7000"
		HLR_TO_VLR,
		NULL);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("If the HLR were to send a GSUP _UPDATE_LOCATION_RESULT we'd still reject");
	gsup_rx("06010809710000004026f0" HLR_TO_VLR, NULL);
	EXPECT_ACCEPTED(false);

	thwart_rx_non_initial_requests();

	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Authen Response, VLR accepts and sends GSUP LU Req to HLR");
	gsup_expect_tx("04010809710000004026f0" CN_DOMAIN VLR_TO_HLR);
	ms_sends_msg("05542d8b2c3e");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000004026f00804036470f1" HLR_TO_VLR,
		"12010809710000004026f0" VLR_TO_HLR);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT, and we send an ID Request for the IMEI to the MS");
	dtap_expect_tx("051802");
	gsup_rx("06010809710000004026f0" HLR_TO_VLR, NULL);

	btw("We will only do business when the IMEI is known");
	EXPECT_CONN_COUNT(1);
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(vsub->imei[0], == 0, "%d");
	vlr_subscr_put(vsub, __func__);
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS replies with an Identity Response, VLR sends the IMEI to HLR");
	gsup_expect_tx("30010809710000004026f050080724433224433224" VLR_TO_HLR);
	ms_sends_msg("0559084a32244332244302");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	expect_bssap_clear();
	btw("HLR does not like the IMEI and sends NACK");
	gsup_rx("32010809710000004026f0510101" HLR_TO_VLR, NULL);
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

static void test_gsm_authen_imei_err()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000004620";

	comment_start();

	net->authentication_required = true;
	net->vlr->cfg.check_imei_rqd = true;

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("08010809710000004026f0" CN_DOMAIN VLR_TO_HLR);
	ms_sends_msg("0508020081680001"
		     "30" /* <-- Revision Level == 1, i.e. is_r99 == false */
		     "089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("from HLR, rx _SEND_AUTH_INFO_RESULT; VLR sends Auth Req to MS");
	auth_request_sent = false;
	auth_request_expect_rand = "585df1ae287f6e273dce07090d61320b";
	auth_request_expect_autn = NULL;
	/* Based on a Ki of 000102030405060708090a0b0c0d0e0f */
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
			"2104" "bc8d1c5b" "2208" "da7cdd6bfe2d7000" HLR_TO_VLR,
		NULL);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("If the HLR were to send a GSUP _UPDATE_LOCATION_RESULT we'd still reject");
	gsup_rx("06010809710000004026f0" HLR_TO_VLR, NULL);
	EXPECT_ACCEPTED(false);

	thwart_rx_non_initial_requests();

	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Authen Response, VLR accepts and sends GSUP LU Req to HLR");
	gsup_expect_tx("04010809710000004026f0" CN_DOMAIN VLR_TO_HLR);
	ms_sends_msg("05542d8b2c3e");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000004026f00804036470f1" HLR_TO_VLR,
		"12010809710000004026f0" VLR_TO_HLR);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT, and we send an ID Request for the IMEI to the MS");
	dtap_expect_tx("051802");
	gsup_rx("06010809710000004026f0" HLR_TO_VLR, NULL);

	btw("We will only do business when the IMEI is known");
	EXPECT_CONN_COUNT(1);
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(vsub->imei[0], == 0, "%d");
	vlr_subscr_put(vsub, __func__);
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS replies with an Identity Response, VLR sends the IMEI to HLR");
	gsup_expect_tx("30010809710000004026f050080724433224433224" VLR_TO_HLR);
	ms_sends_msg("0559084a32244332244302");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	expect_bssap_clear();
	btw("HLR can't parse the message and returns ERR");
	gsup_rx("31010809710000004026f0020160" HLR_TO_VLR, NULL);
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

static void test_gsm_authen_tmsi_imei()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000004620";

	comment_start();

	net->authentication_required = true;
	net->vlr->cfg.assign_tmsi = true;
	net->vlr->cfg.check_imei_rqd = true;

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("08010809710000004026f0" CN_DOMAIN VLR_TO_HLR);
	ms_sends_msg("0508020081680001"
		     "30" /* <-- Revision Level == 1, i.e. is_r99 == false */
		     "089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("from HLR, rx _SEND_AUTH_INFO_RESULT; VLR sends Auth Req to MS");
	auth_request_sent = false;
	auth_request_expect_rand = "585df1ae287f6e273dce07090d61320b";
	auth_request_expect_autn = NULL;
	/* Based on a Ki of 000102030405060708090a0b0c0d0e0f */
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
			"2104" "bc8d1c5b" "2208" "da7cdd6bfe2d7000" HLR_TO_VLR,
		NULL);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("If the HLR were to send a GSUP _UPDATE_LOCATION_RESULT we'd still reject");
	gsup_rx("06010809710000004026f0" HLR_TO_VLR, NULL);
	EXPECT_ACCEPTED(false);

	thwart_rx_non_initial_requests();

	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Authen Response, VLR accepts and sends GSUP LU Req to HLR");
	gsup_expect_tx("04010809710000004026f0" CN_DOMAIN VLR_TO_HLR);
	ms_sends_msg("05542d8b2c3e");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000004026f00804036470f1" HLR_TO_VLR,
		"12010809710000004026f0" VLR_TO_HLR);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT, and we send an ID Request for the IMEI to the MS");
	dtap_expect_tx("051802");
	gsup_rx("06010809710000004026f0" HLR_TO_VLR, NULL);

	btw("We will only do business when the IMEI is known");
	EXPECT_CONN_COUNT(1);
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(vsub->imei[0], == 0, "%d");
	vlr_subscr_put(vsub, __func__);
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS replies with an Identity Response, VLR sends the IMEI to HLR");
	gsup_expect_tx("30010809710000004026f050080724433224433224" VLR_TO_HLR);
	ms_sends_msg("0559084a32244332244302");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("HLR accepts the IMEI");
	gsup_rx("32010809710000004026f0510100" HLR_TO_VLR, NULL);

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
	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	btw("Subscriber has the IMEI and TMSI");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(strcmp(vsub->imei, "42342342342342"), == 0, "%d");
	VERBOSE_ASSERT(vsub->tmsi, == 0x03020100, "0x%08x");
	vlr_subscr_put(vsub, __func__);

	BTW("subscriber detaches, using TMSI");
	expect_bssap_clear();
	ms_sends_msg("050130" "05f4" "03020100");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

static void test_gsm_milenage_authen()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000010650";

	comment_start();

	net->authentication_required = true;
	rx_from_ran = OSMO_RAT_GERAN_A;

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("080108" "09710000000156f0" CN_DOMAIN VLR_TO_HLR);
	ms_sends_msg("0508" /* MM LU */
		     "7" /* ciph key seq: no key available */
		     "0" /* LU type: normal */
		     "ffffff" "0000" /* LAI, LAC */
		     "30" /* classmark 1: GSM phase 2 */
		     "089910070000106005" /* IMSI */
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
	auth_request_expect_autn = NULL;
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
			"2708" "706f996719ba609c" HLR_TO_VLR,
		NULL);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Authen Response, VLR accepts and sends GSUP LU Req to HLR");
	gsup_expect_tx("04010809710000000156f0" CN_DOMAIN VLR_TO_HLR);
	ms_sends_msg("0554" "9b36efdf");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000000156f00804032443f2" HLR_TO_VLR,
		"12010809710000000156f0" VLR_TO_HLR);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT");
	expect_bssap_clear();
	gsup_rx("06010809710000000156f0" HLR_TO_VLR, NULL);
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	btw("LU was successful, and the conn has already been closed");
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	BTW("after a while, a new conn sends a CM Service Request. VLR responds with Auth Req, 2nd auth vector");
	auth_request_sent = false;
	auth_request_expect_rand = "c187a53a5e6b9d573cac7c74451fd46d";
	auth_request_expect_autn = NULL;
	cm_service_result_sent = RES_NONE;
	ms_sends_msg("052474"
		     "03305886" /* classmark 2: GSM phase 2 */
		     "089910070000106005" /* IMSI */);
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");

	btw("needs auth, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS sends Authen Response, VLR accepts with a CM Service Accept");
	gsup_expect_tx(NULL);
	ms_sends_msg("0554" "85aa3130"); /* 2nd vector's sres, s.a. */
	VERBOSE_ASSERT(cm_service_result_sent, == RES_ACCEPT, "%d");

	/* Release connection */
	expect_bssap_clear();
	conn_conclude_cm_service_req(g_msub, MSC_A_USE_CM_SERVICE_SMS);

	btw("all requests serviced, conn has been released");
	ran_sends_clear_complete();
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

	btw("the subscriber and its pending request should remain");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 1, "%d");
	vlr_subscr_put(vsub, __func__);

	btw("MS replies with Paging Response, and VLR sends Auth Request with third key");
	auth_request_sent = false;
	auth_request_expect_rand = "efa9c29a9742148d5c9070348716e1bb";
	auth_request_expect_autn = NULL;
	ms_sends_msg("062707"
		     "03305886" /* classmark 2 */
		     "089910070000106005" /* IMSI */);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");

	btw("needs auth, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS sends Authen Response, VLR accepts and sends pending SMS");
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
	ms_sends_msg("0554" "69d5f9fb"); /* 3nd vector's sres, s.a. */
	VERBOSE_ASSERT(dtap_tx_confirmed, == true, "%d");

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
	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	BTW("subscriber detaches");
	expect_bssap_clear();
	ms_sends_msg("050130"
		     "089910070000106005" /* IMSI */);
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

static void test_wrong_sres_length()
{
	comment_start();
	fake_time_start();

	net->authentication_required = true;

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("08010809710000004026f0" CN_DOMAIN VLR_TO_HLR);
	ms_sends_msg("0508020081680001"
		     "30" /* <-- Revision Level == 1, i.e. is_r99 == false */
		     "089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("from HLR, rx _SEND_AUTH_INFO_RESULT; VLR sends Auth Req to MS");
	auth_request_sent = false;
	auth_request_expect_rand = "585df1ae287f6e273dce07090d61320b";
	auth_request_expect_autn = NULL;
	/* Based on a Ki of 000102030405060708090a0b0c0d0e0f */
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
			"2104" "bc8d1c5b" "2208" "da7cdd6bfe2d7000" HLR_TO_VLR,
		NULL);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("If the HLR were to send a GSUP _UPDATE_LOCATION_RESULT we'd still reject");
	gsup_rx("06010809710000004026f0" HLR_TO_VLR, NULL);
	EXPECT_ACCEPTED(false);

	thwart_rx_non_initial_requests();

	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Authen Response with too short SRES data, auth is thwarted.");
	gsup_expect_tx("0b010809710000004026f0280102" VLR_TO_HLR); /* OSMO_GSUP_MSGT_AUTH_FAIL_REPORT */
	expect_bssap_clear();
	ms_sends_msg("05542d8b2c");
	VERBOSE_ASSERT(lu_result_sent, == RES_REJECT, "%d");

	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

msc_vlr_test_func_t msc_vlr_tests[] = {
	test_gsm_authen,
	test_gsm_authen_tmsi,
	test_gsm_authen_imei,
	test_gsm_authen_imei_nack,
	test_gsm_authen_imei_err,
	test_gsm_authen_tmsi_imei,
	test_gsm_milenage_authen,
	test_wrong_sres_length,
	NULL
};
