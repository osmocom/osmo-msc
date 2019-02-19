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

/* NOTE that further auth re-use tests exist in msc_vlr_test_hlr_reject.c */

#include "msc_vlr_tests.h"
#include "stubs.h"

static void _test_auth_reuse(enum osmo_rat_type via_ran,
			     int set_max_reuse_count,
			     int loop_requests_without_hlr,
			     bool final_request_with_hlr)
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000010650";
	int expected_use_count;
	int i;

	net->authentication_required = true;
	net->vlr->cfg.assign_tmsi = true;
	net->vlr->cfg.auth_tuple_max_reuse_count = set_max_reuse_count;
	net->vlr->cfg.auth_reuse_old_sets_on_error = false;
	rx_from_ran = via_ran;

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

	btw("from HLR, rx _SEND_AUTH_INFO_RESULT, only one tuple; VLR sends Auth Req to MS");
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
			"2708" "e229c19e791f2e41",
		NULL);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	if (via_ran == OSMO_RAT_GERAN_A) {
		btw("MS sends Authen Response, VLR accepts and sends GSUP LU Req to HLR");
		gsup_expect_tx("04010809710000000156f0280102");
		ms_sends_msg("0554" "e229c19e" "2104" "791f2e41");
		VERBOSE_ASSERT(gsup_tx_confirmed, == true, "%d");
		VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");
	} else {
		/* On UTRAN */
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
	}

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
	thwart_rx_non_initial_requests();

	btw("even though the TMSI is not acked, we can already find the subscr with it");
	vsub = vlr_subscr_find_by_tmsi(net->vlr, 0x03020100, __func__);
	VERBOSE_ASSERT(vsub != NULL, == true, "%d");
	VERBOSE_ASSERT(strcmp(vsub->imsi, imsi), == 0, "%d");
	VERBOSE_ASSERT(vsub->tmsi_new, == 0x03020100, "0x%08x");
	VERBOSE_ASSERT(vsub->tmsi, == GSM_RESERVED_TMSI, "0x%08x");
	vlr_subscr_put(vsub, __func__);

	btw("MS sends TMSI Realloc Complete");
	expect_release_clear(via_ran);
	ms_sends_msg("055b");
	ASSERT_RELEASE_CLEAR(via_ran);
	bss_rnc_sends_release_clear_complete(via_ran);

	btw("LU was successful, and the conn has already been closed");
	EXPECT_CONN_COUNT(0);

	expected_use_count = 1;

	for (i = 0; i < loop_requests_without_hlr; i++, expected_use_count++) {
		BTW("Now the auth tuple has use_count == %d", expected_use_count);
		vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
		OSMO_ASSERT(vsub);
		OSMO_ASSERT(vsub->last_tuple);
		VERBOSE_ASSERT(vsub->last_tuple->use_count, == expected_use_count, "%d");
		vlr_subscr_put(vsub, __func__);

		BTW("after a while, a new conn sends a CM Service Request. VLR responds with Auth Req,"
		    " and reuses old auth vector");
		auth_request_sent = true;
		cm_service_result_sent = RES_NONE;
		ms_sends_msg("052478"
			     "03575886" /* classmark 2 */
			     "089910070000106005" /* IMSI */);
		OSMO_ASSERT(g_conn);
		OSMO_ASSERT(g_conn->fi);
		OSMO_ASSERT(g_conn->vsub);
		VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");
		VERBOSE_ASSERT(auth_request_sent, == true, "%d");

		if (via_ran == OSMO_RAT_GERAN_A) {
			btw("MS sends Authen Response, VLR accepts with a CM Service Accept");
			gsup_expect_tx(NULL);
			ms_sends_msg("0554" "e229c19e" "2104" "791f2e41");
			VERBOSE_ASSERT(cm_service_result_sent, == RES_ACCEPT, "%d");
		} else {
			/* On UTRAN */
			btw("MS sends Authen Response, VLR accepts and sends SecurityModeControl");
			expect_security_mode_ctrl(NULL, "27497388b6cb044648f396aa155b95ef");
			ms_sends_msg("0554" "e229c19e" "2104" "791f2e41");
			VERBOSE_ASSERT(security_mode_ctrl_sent, == true, "%d");
			VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");

			btw("MS sends SecurityModeControl acceptance, VLR accepts; above Ciphering is an implicit CM Service Accept");
			ms_sends_security_mode_complete();
			VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");
		}

		/* Release connection */
		expect_release_clear(via_ran);
		conn_conclude_cm_service_req(g_conn, via_ran);
		bss_rnc_sends_release_clear_complete(via_ran);

		btw("all requests serviced, conn has been released");
		EXPECT_CONN_COUNT(0);
	}

	if (final_request_with_hlr) {
		BTW("Now the auth tuple has use_count == %d, as much as is allowed.", expected_use_count);
		vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
		OSMO_ASSERT(vsub);
		OSMO_ASSERT(vsub->last_tuple);
		VERBOSE_ASSERT(vsub->last_tuple->use_count, == expected_use_count, "%d");
		vlr_subscr_put(vsub, __func__);

		BTW("after a while, a new conn sends a CM Service Request. VLR responds with Auth Req,"
		    " and needs to request a second auth vector from HLR");
		auth_request_sent = false;
		cm_service_result_sent = RES_NONE;
		gsup_expect_tx("080108" "09710000000156f0");
		ms_sends_msg("052478"
			     "03575886" /* classmark 2 */
			     "089910070000106005" /* IMSI */);
		OSMO_ASSERT(g_conn);
		OSMO_ASSERT(g_conn->fi);
		OSMO_ASSERT(g_conn->vsub);
		VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");
		VERBOSE_ASSERT(auth_request_sent, == false, "%d");
		VERBOSE_ASSERT(gsup_tx_confirmed, == true, "%d");

		btw("from HLR, rx _SEND_AUTH_INFO_RESULT, second tuple; VLR sends Auth Req to MS");
		auth_request_expect_rand = "c187a53a5e6b9d573cac7c74451fd46d";
		auth_request_expect_autn = "1843a645b98d00005b2d666af46c45d9";
		gsup_rx("0a"
			/* imsi */
			"0108" "09710000000156f0"
			/* TL    TL     rand */
			/*       TL     sres       TL     kc */
			/*       TL     3G IK */
			/*       TL     3G CK */
			/*       TL     AUTN */
			/*       TL     RES */
			"0362"  "2010" "c187a53a5e6b9d573cac7c74451fd46d"
				"2104" "85aa3130" "2208" "d3d50a000bf04f6e"
				"2310" "1159ec926a50e98c034a6b7d7c9f418d"
				"2410" "df3a03d9ca5335641efc8e36d76cd20b"
				"2510" "1843a645b98d00005b2d666af46c45d9"
				"2708" "7db47cf7f81e4dc7",
			NULL);
		VERBOSE_ASSERT(auth_request_sent, == true, "%d");
		VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");

		if (via_ran == OSMO_RAT_GERAN_A) {
			btw("MS sends Authen Response, VLR accepts with a CM Service Accept");
			gsup_expect_tx(NULL);
			ms_sends_msg("0554" "7db47cf7" "2104" "f81e4dc7"); /* 2nd vector's res, s.a. */
			VERBOSE_ASSERT(cm_service_result_sent, == RES_ACCEPT, "%d");
		} else {
			/* On UTRAN */
			btw("MS sends Authen Response, VLR accepts and sends SecurityModeControl");
			expect_security_mode_ctrl(NULL, "1159ec926a50e98c034a6b7d7c9f418d");
			ms_sends_msg("0554" "7db47cf7" "2104" "f81e4dc7"); /* 2nd vector's res, s.a. */
			VERBOSE_ASSERT(security_mode_ctrl_sent, == true, "%d");
			VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");

			btw("MS sends SecurityModeControl acceptance, VLR accepts; above Ciphering is an implicit CM Service Accept");
			ms_sends_security_mode_complete();
			VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");
		}

		/* Release connection */
		expect_release_clear(via_ran);
		conn_conclude_cm_service_req(g_conn, via_ran);
		bss_rnc_sends_release_clear_complete(via_ran);

		btw("all requests serviced, conn has been released");
		EXPECT_CONN_COUNT(0);
	}

	BTW("subscriber detaches");
	expect_release_clear(via_ran);
	ms_sends_msg("050130"
		     "089910070000106005" /* IMSI */);
	ASSERT_RELEASE_CLEAR(via_ran);
	bss_rnc_sends_release_clear_complete(via_ran);

	EXPECT_CONN_COUNT(0);
	clear_vlr();
}

static void test_auth_use_twice_geran()
{
	comment_start();
	_test_auth_reuse(OSMO_RAT_GERAN_A, 1, 1, true);
	comment_end();
}

static void test_auth_use_twice_utran()
{
	comment_start();
	_test_auth_reuse(OSMO_RAT_UTRAN_IU, 1, 1, true);
	comment_end();
}

static void test_auth_use_infinitely_geran()
{
	comment_start();
	_test_auth_reuse(OSMO_RAT_GERAN_A, -1, 3, false);
	comment_end();
}

static void test_auth_use_infinitely_utran()
{
	comment_start();
	_test_auth_reuse(OSMO_RAT_UTRAN_IU, -1, 3, false);
	comment_end();
}

static void test_no_auth_reuse_geran()
{
	comment_start();
	_test_auth_reuse(OSMO_RAT_GERAN_A, 0, 0, true);
	comment_end();
}

static void test_no_auth_reuse_utran()
{
	comment_start();
	_test_auth_reuse(OSMO_RAT_UTRAN_IU, 0, 0, true);
	comment_end();
}

msc_vlr_test_func_t msc_vlr_tests[] = {
	test_auth_use_twice_geran,
	test_auth_use_twice_utran,
	test_auth_use_infinitely_geran,
	test_auth_use_infinitely_utran,
	test_no_auth_reuse_geran,
	test_no_auth_reuse_utran,
	NULL
};
