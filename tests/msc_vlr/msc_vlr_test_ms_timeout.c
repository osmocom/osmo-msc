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

static void test_ms_timeout_lu_auth_resp()
{
	comment_start();

	net->authentication_required = true;

	fake_time_start();

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("08010809710000004026f0");
	ms_sends_msg("050802008168000130089910070000006402");
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
		/* auth vectors... */
		/* TL    TL     rand */
		"0322"  "2010" "585df1ae287f6e273dce07090d61320b"
		/*       TL     sres       TL     kc */
			"2104" "2d8b2c3e" "2208" "61855fb81fc2a800"
		,NULL);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	BTW("MS fails to send an Authentication Response");

	btw("At first, we're still waiting");
	fake_time_passes(0, 423);
	EXPECT_CONN_COUNT(1);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");
	fake_time_passes(1, 235);
	EXPECT_CONN_COUNT(1);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");
	fake_time_passes(1, 235);
	EXPECT_CONN_COUNT(1);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");
	fake_time_passes(1, 235);
	EXPECT_CONN_COUNT(1);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");
	fake_time_passes(1, 235);
	EXPECT_CONN_COUNT(1);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");
	expect_bssap_clear();
	fake_time_passes(1, 235);
	btw("RAN_CONN_TIMEOUT has passed, conn is gone.");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");
	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);
	VERBOSE_ASSERT(lu_result_sent, == RES_REJECT, "%d");

	comment_end();
}

static void test_ms_timeout_cm_auth_resp()
{
	comment_start();

	net->authentication_required = true;

	fake_time_start();

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("08010809710000004026f0");
	ms_sends_msg("050802008168000130089910070000006402");
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
			"2104" "bc8d1c5b" "2208" "da7cdd6bfe2d7000",
		NULL);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Authen Response, VLR accepts and sends GSUP LU Req to HLR");
	gsup_expect_tx("04010809710000004026f0280102");
	ms_sends_msg("05542d8b2c3e");
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
	auth_request_sent = false;
	auth_request_expect_rand = "12aca96fb4ffdea5c985cbafa9b6e18b";
	cm_service_result_sent = RES_NONE;
	ms_sends_msg("05247803305886089910070000006402");
	OSMO_ASSERT(g_conn);
	OSMO_ASSERT(g_conn->fi);
	OSMO_ASSERT(g_conn->vsub);
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");

	BTW("MS fails to send an Authentication Response");

	btw("At first, we're still waiting");
	fake_time_passes(0, 423);
	EXPECT_CONN_COUNT(1);
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");
	fake_time_passes(1, 235);
	EXPECT_CONN_COUNT(1);
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");
	fake_time_passes(1, 235);
	EXPECT_CONN_COUNT(1);
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");
	fake_time_passes(1, 235);
	EXPECT_CONN_COUNT(1);
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");
	fake_time_passes(1, 235);
	EXPECT_CONN_COUNT(1);
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");
	expect_bssap_clear();
	fake_time_passes(1, 235);
	btw("RAN_CONN_TIMEOUT has passed, conn is gone.");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");
	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);
	VERBOSE_ASSERT(cm_service_result_sent, == RES_REJECT, "%d");

	clear_vlr();
	comment_end();
}

static void test_ms_timeout_paging()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000004620";

	rx_from_ran = OSMO_RAT_GERAN_A;

	comment_start();

	fake_time_start();

	btw("Location Update request causes a GSUP LU request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("04010809710000004026f0280102");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000004026f00804036470f1",
		"12010809710000004026f0");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT");
	expect_bssap_clear();
	gsup_rx("06010809710000004026f0", NULL);

	btw("LU was successful, and the conn has already been closed");
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");
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

	btw("time passes and no paging result is received");

	fake_time_passes(MSC_PAGING_RESPONSE_TIMER_DEFAULT - 1, 0);

	btw("the paging timeout has not yet expired");
	VERBOSE_ASSERT(paging_stopped, == false, "%d");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(vsub->cs.is_paging, == true, "%d");
	btw("another request is added to the list but does not cause another paging");
	paging_sent = false;
	paging_expect_imsi(NULL);
	send_sms(vsub, vsub,
		 "One paging ought to be enough for anyone.");
	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 2, "%d");
	vlr_subscr_put(vsub, __func__);
	vsub = NULL;
	VERBOSE_ASSERT(paging_sent, == false, "%d");

	btw("the paging timeout expires, the paging as well as the requests are canceled");
	fake_time_passes(2, 0);
	VERBOSE_ASSERT(paging_stopped, == true, "%d");

	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(vsub->cs.is_paging, == false, "%d");
	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 0, "%d");

	BTW("Now that the timeout has expired, another Paging is sent on request");
	paging_expect_imsi(imsi);
	paging_sent = false;

	send_sms(vsub, vsub,
		 "Privacy in residential applications is a desirable"
		 " marketing option.");

	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 1, "%d");
	vlr_subscr_put(vsub, __func__);
	vsub = NULL;
	VERBOSE_ASSERT(paging_sent, == true, "%d");
	VERBOSE_ASSERT(paging_stopped, == false, "%d");

	BTW("subscriber detaches, pagings are canceled");
	expect_bssap_clear();
	ms_sends_msg("050130089910070000006402");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");
	VERBOSE_ASSERT(paging_stopped, == true, "%d");

	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(!vsub);

	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

static void test_classmark_update_timeout()
{
	comment_start();

	fake_time_start();

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
		/* TL    TL     rand */
		"0322"  "2010" "585df1ae287f6e273dce07090d61320b"
		/*       TL     sres       TL     kc */
			"2104" "2d8b2c3e" "2208" "61855fb81fc2a800"
		,
		NULL);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");

	BTW("MS sends Authen Response, VLR accepts and wants to send Ciphering Mode Command to MS"
	    " -- but needs Classmark 2 to determine whether A5/3 is supported");
	cipher_mode_cmd_sent = false;
	ms_sends_msg("05542d8b2c3e");
	OSMO_ASSERT(!cipher_mode_cmd_sent);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	BTW("But the BSSMAP Classmark Update never arrives");
	btw("At first, we're still waiting");
	fake_time_passes(0, 423);
	EXPECT_CONN_COUNT(1);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");
	fake_time_passes(1, 235);
	EXPECT_CONN_COUNT(1);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");
	fake_time_passes(1, 235);
	EXPECT_CONN_COUNT(1);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");
	fake_time_passes(1, 235);
	EXPECT_CONN_COUNT(1);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");
	fake_time_passes(1, 235);
	EXPECT_CONN_COUNT(1);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");
	expect_bssap_clear();
	fake_time_passes(1, 235);
	btw("RAN_CONN_TIMEOUT has passed, conn is gone.");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");
	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);
	VERBOSE_ASSERT(lu_result_sent, == RES_REJECT, "%d");

	comment_end();
}


msc_vlr_test_func_t msc_vlr_tests[] = {
	test_ms_timeout_lu_auth_resp,
	test_ms_timeout_cm_auth_resp,
	test_ms_timeout_paging,
	test_classmark_update_timeout,
	NULL
};
