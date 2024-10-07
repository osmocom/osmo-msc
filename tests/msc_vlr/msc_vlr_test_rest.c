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

#include <osmocom/vlr/vlr.h>

#if 0
static void test_early_stage()
{
	comment_start();

	btw("NULL conn");
	EXPECT_ACCEPTED(false);

	btw("freshly allocated conn");
	g_conn = ran_conn_alloc(net, OSMO_RAT_GERAN_A, 123);
	EXPECT_ACCEPTED(false);

	btw("conn_fsm present, in state NEW");
	OSMO_ASSERT(g_conn->fi);
	OSMO_ASSERT(g_conn->fi->state == RAN_CONN_S_NEW);
	EXPECT_ACCEPTED(false);

	thwart_rx_non_initial_requests();

	btw("fake: acceptance");
	g_conn->vsub = vlr_subscr_find_or_create_by_imsi(net->vlr, "135111", VSUB_USE_CONN, NULL);
	g_conn->via_ran = OSMO_RAT_GERAN_A;
	OSMO_ASSERT(g_conn->vsub);
	/* mark as silent call so it sticks around */
	g_conn->silent_call = 1;
	osmo_fsm_inst_state_chg(g_conn->fi, RAN_CONN_S_ACCEPTED, 0, 0);
	EXPECT_CONN_COUNT(1);
	EXPECT_ACCEPTED(true);

	btw("CLOSE event marks conn_fsm as released and frees the conn");
	expect_bssap_clear();
	osmo_fsm_inst_dispatch(g_conn->fi, RAN_CONN_E_CN_CLOSE, NULL);
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");
	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	clear_vlr();
	comment_end();
}
#endif

static void test_cm_service_without_lu()
{
	comment_start();

	btw("CM Service Request without a prior Location Updating");
	expect_bssap_clear();
	ms_sends_msg("05247403305886089910070000006402");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	btw("conn was released");
	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	clear_vlr();
	comment_end();
}

static void test_two_lu()
{
	comment_start();

	btw("Location Update request causes a GSUP LU request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("04010809710000004026f0" CN_DOMAIN VLR_TO_HLR);
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000004026f00804036470f1" HLR_TO_VLR,
		"12010809710000004026f0" VLR_TO_HLR);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("having received subscriber data does not mean acceptance");
	EXPECT_ACCEPTED(false);

	thwart_rx_non_initial_requests();

	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT");
	expect_bssap_clear();
	gsup_rx("06010809710000004026f0" HLR_TO_VLR, NULL);
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	btw("LU was successful, and the conn has already been closed");
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);


	BTW("verify that the MS can send another LU request");
	btw("Location Update request causes a GSUP LU request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("04010809710000004026f0" CN_DOMAIN VLR_TO_HLR);
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000004026f00804036470f1" HLR_TO_VLR,
		"12010809710000004026f0" VLR_TO_HLR);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("having received subscriber data does not mean acceptance");
	EXPECT_ACCEPTED(false);

	thwart_rx_non_initial_requests();

	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT");
	expect_bssap_clear();
	gsup_rx("06010809710000004026f0" HLR_TO_VLR, NULL);
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	btw("LU was successful, and the conn has already been closed");
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
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

static void test_lu_unknown_tmsi()
{
	comment_start();

	btw("Location Update request with unknown TMSI sends ID Request for IMSI");
	lu_result_sent = RES_NONE;
	dtap_expect_tx("051801");
	ms_sends_msg("050802008168000130" "05f4" "23422342");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS tells us the IMSI, causes a GSUP LU request to HLR");
	gsup_expect_tx("04010809710000004026f0" CN_DOMAIN VLR_TO_HLR);
	ms_sends_msg("0559089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000004026f00804036470f1" HLR_TO_VLR,
		"12010809710000004026f0" VLR_TO_HLR);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("having received subscriber data does not mean acceptance");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT");
	expect_bssap_clear();
	gsup_rx("06010809710000004026f0" HLR_TO_VLR, NULL);
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	btw("LU was successful, and the conn has already been closed");
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

msc_vlr_test_func_t msc_vlr_tests[] = {
	//test_early_stage,
	test_cm_service_without_lu,
	test_two_lu,
	test_lu_unknown_tmsi,
	NULL
};
