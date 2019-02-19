/*
 * Osmocom MSC+VLR end-to-end tests
 *
 * (C) 2018 by Vadim Yanitskiy <axilirator@gmail.com>
 *
 * All Rights Reserved
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

#define IMSI "901700000004620"

#define FACILITY_IE_REQ \
	"a113"    /* Invoke component, len=19 */ \
	"020101"  /* InvokeID=1 */ \
	"02013b"  /* OpCode=GSM0480_OP_CODE_PROCESS_USS_REQ */ \
	"300b"    /* Sequence tag, len=11 */ \
	"04010f"  /* DCS: Default 7-bit alphabet */ \
	"0406aa510c061b01" /* USSD text: *#100#, len=6 */

#define FACILITY_IE_RSP \
	"a225"    /* ReturnResult, len=37 */ \
	"020101"  /* InvokeID=1 */ \
	"3020"    /* Sequence tag, len=32 */ \
	"02013b"  /* OpCode=GSM0480_OP_CODE_PROCESS_USS_REQ */ \
	"301b"    /* Sequence tag, len=27 */ \
	"04010f"  /* DCS: Default 7-bit alphabet */ \
	"0416d9775d0e2ae3e965f73cfd7683d27310cd06bbc51a0d"

static void perform_lu(void)
{
	struct vlr_subscr *vsub;

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

	vsub = vlr_subscr_find_by_imsi(net->vlr, IMSI, __func__);
	VERBOSE_ASSERT(vsub != NULL, == true, "%d");
	VERBOSE_ASSERT(strcmp(vsub->imsi, IMSI), == 0, "%d");
	VAL_ASSERT("LAC", vsub->cgi.lai.lac, == 23, "%u");
	vlr_subscr_put(vsub, __func__);

	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);
}

static void _test_ss_ussd_mo(enum osmo_rat_type via_ran)
{
	/* TODO: UTRAN requires auth and ciph */
	rx_from_ran = via_ran;

	/* Perform Location Update */
	perform_lu();

	BTW("after a while, a new conn sends a CM Service Request");

	cm_service_result_sent = RES_NONE;
	ms_sends_msg("05247803305886089910070000006402");
	OSMO_ASSERT(g_conn);
	OSMO_ASSERT(g_conn->fi);
	OSMO_ASSERT(g_conn->vsub);
	VERBOSE_ASSERT(cm_service_result_sent, == RES_ACCEPT, "%d");
	EXPECT_ACCEPTED(true);

	/* MT: GSM 04.80 RELEASE COMPLETE with Facility IE */
	gsup_expect_tx("20" /* OSMO_GSUP_MSGT_PROC_SS_REQUEST */
		"0108" "09710000004026f0" /* IMSI TLV */
		"3004" "20000001" /* Session ID TLV */
		"3101" "01" /* Session state: BEGIN */
		"3515" FACILITY_IE_REQ);
	dtap_expect_tx("8b2a" "1c27" FACILITY_IE_RSP);
	expect_release_clear(via_ran);

	/* MO: GSM 04.80 REGISTER with Facility IE and SS version IE */
	ms_sends_msg("0b7b" "1c15" FACILITY_IE_REQ "7f0100");
	gsup_rx("20" /* OSMO_GSUP_MSGT_PROC_SS_REQUEST */
		"0108" "09710000004026f0" /* IMSI TLV */
		"3004" "20000001" /* Session ID TLV */
		"3101" "03" /* Session state: END */
		"3527" FACILITY_IE_RSP, NULL);
	VERBOSE_ASSERT(dtap_tx_confirmed, == true, "%d");
	ASSERT_RELEASE_CLEAR(via_ran);

	btw("all requests serviced, conn has been released");
	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);
}

static void _test_ss_ussd_no(enum osmo_rat_type via_ran)
{
	struct vlr_subscr *vsub;

	/* TODO: UTRAN requires auth and ciph */
	rx_from_ran = via_ran;

	/* Perform Location Update */
	perform_lu();

	BTW("after a while, HLR initiates SS/USSD session");

	paging_expect_imsi(IMSI);
	paging_sent = false;
	vsub = vlr_subscr_find_by_imsi(net->vlr, IMSI, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 0, "%d");

	/* MT: GSM 04.80 REGISTER with request */
	gsup_rx("20" /* OSMO_GSUP_MSGT_PROC_SS_REQUEST */
		"0108" "09710000004026f0" /* IMSI TLV */
		"3004" "20000101" /* Session ID TLV */
		"3101" "01" /* Session state: BEGIN */
		"3515" FACILITY_IE_REQ, NULL);

	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 1, "%d");
	vlr_subscr_put(vsub, __func__);
	vsub = NULL;
	VERBOSE_ASSERT(paging_sent, == true, "%d");
	VERBOSE_ASSERT(paging_stopped, == false, "%d");

	btw("the subscriber and its pending request should remain");
	vsub = vlr_subscr_find_by_imsi(net->vlr, IMSI, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 1, "%d");
	vlr_subscr_put(vsub, __func__);

	btw("MS replies with Paging Response, we deliver the NC/USSD");

	dtap_expect_tx("0b3b" "1c15" FACILITY_IE_REQ);
	ms_sends_msg("06270703305882089910070000006402");
	VERBOSE_ASSERT(dtap_tx_confirmed, == true, "%d");
	VERBOSE_ASSERT(paging_stopped, == true, "%d");

	btw("MS responds to SS/USSD request");

	/* MO: GSM 04.80 FACILITY with response */
	gsup_expect_tx("20" /* OSMO_GSUP_MSGT_PROC_SS_REQUEST */
		"0108" "09710000004026f0" /* IMSI TLV */
		"3004" "20000101" /* Session ID TLV */
		"3101" "02" /* Session state: CONTINUE */
		"3527" FACILITY_IE_RSP);
	ms_sends_msg("8b3a" "27" FACILITY_IE_RSP);
	VERBOSE_ASSERT(dtap_tx_confirmed, == true, "%d");
	VERBOSE_ASSERT(paging_stopped, == true, "%d");

	btw("HLR terminates the session");

	/* MT: GSM 04.80 RELEASE COMPLETE without Facility IE */
	dtap_expect_tx("0b2a");
	expect_release_clear(via_ran);
	gsup_rx("20" /* OSMO_GSUP_MSGT_PROC_SS_REQUEST */
		"0108" "09710000004026f0" /* IMSI TLV */
		"3004" "20000101" /* Session ID TLV */
		"3101" "03", /* Session state: END */
		NULL);
	VERBOSE_ASSERT(dtap_tx_confirmed, == true, "%d");
	ASSERT_RELEASE_CLEAR(via_ran);

	btw("all requests serviced, conn has been released");
	bss_sends_clear_complete();
	EXPECT_CONN_COUNT(0);
}

static void test_ss_ussd_mo_geran()
{
	comment_start();
	_test_ss_ussd_mo(OSMO_RAT_GERAN_A);
	clear_vlr();
	comment_end();
}

static void test_ss_ussd_no_geran()
{
	comment_start();
	_test_ss_ussd_no(OSMO_RAT_GERAN_A);
	clear_vlr();
	comment_end();
}

msc_vlr_test_func_t msc_vlr_tests[] = {
	/* TODO: UTRAN requires auth and enc */
	test_ss_ussd_mo_geran, /* MS-originated */
	test_ss_ussd_no_geran, /* Network-originated */
	NULL
};
