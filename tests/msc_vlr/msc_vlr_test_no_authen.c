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

static void test_no_authen()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000004620";
	/* No auth only works on GERAN */
	rx_from_ran = OSMO_RAT_GERAN_A;

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

	btw("LU was successful, and the conn has already been closed");
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	BTW("after a while, a new conn sends a CM Service Request (MO SMS)");
	cm_service_result_sent = RES_NONE;
	ms_sends_msg("05 24 74 03 30 58 86 08 99 10 07 00 00 00 64 02");
	VERBOSE_ASSERT(cm_service_result_sent, == RES_ACCEPT, "%d");
	EXPECT_ACCEPTED(true);

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

	btw("MS replies with Paging Response, we deliver the SMS");
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
	ms_sends_msg("06270703305882089910070000006402");
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

static void test_no_authen_tmsi()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000004620";

	rx_from_ran = OSMO_RAT_GERAN_A;

	comment_start();

	net->vlr->cfg.assign_tmsi = true;

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

	BTW("after a while, a new conn sends a CM Service Request using above TMSI");
	cm_service_result_sent = RES_NONE;
	ms_sends_msg("05247403305886" "05f4" "03020100");
	VERBOSE_ASSERT(cm_service_result_sent, == RES_ACCEPT, "%d");
	EXPECT_ACCEPTED(true);

	/* Release connection */
	expect_bssap_clear();
	conn_conclude_cm_service_req(g_msub, MSC_A_USE_CM_SERVICE_SMS);

	btw("all requests serviced, conn has been released");
	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	BTW("an SMS is sent, MS is paged using above TMSI");
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

	btw("MS replies with Paging Response using TMSI, we deliver the SMS");
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
	ms_sends_msg("06270703305882" "05f4" "03020100");
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
	ms_sends_msg("050130" "05f4" "03020100");
	EXPECT_CONN_COUNT(0);
	 */

	BTW("subscriber sends LU Request, this time with the TMSI");
	btw("Location Update request causes a GSUP LU request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("04010809710000004026f0" CN_DOMAIN VLR_TO_HLR);
	ms_sends_msg("050802008168000130" "05f4" "03020100");
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

static void test_no_authen_imei()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000004620";

	rx_from_ran = OSMO_RAT_GERAN_A;

	comment_start();

	net->vlr->cfg.check_imei_rqd = true;

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
	/* 3GPP TS 23.003: 6.2.1 Composition of IMEI: the IMEI ends with a
	 * spare digit that shall be sent as zero by the MS. */
	ms_sends_msg("0559084a32244332244302");

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

static void test_no_authen_tmsi_imei()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000004620";

	rx_from_ran = OSMO_RAT_GERAN_A;

	comment_start();

	net->vlr->cfg.assign_tmsi = true;
	net->vlr->cfg.check_imei_rqd = true;

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

	btw("HLR accepts the IMEI");
	gsup_rx("32010809710000004026f0510100" HLR_TO_VLR, NULL);

	btw("a LU Accept with a new TMSI was sent, waiting for TMSI Realloc Compl");
	EXPECT_CONN_COUNT(1);
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS sends TMSI Realloc Complete");
	expect_bssap_clear();
	ms_sends_msg("055b");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	btw("LU was successful, and the conn has already been closed");
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	btw("Subscriber has the IMEI and TMSI");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(strcmp(vsub->imei, "42342342342342"), == 0, "%d");
	VERBOSE_ASSERT(vsub->tmsi, == 0x03020100, "0x%08x");
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

static void test_no_authen_imeisv()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000004620";

	/* No auth only works on GERAN */
	rx_from_ran = OSMO_RAT_GERAN_A;

	comment_start();

	net->vlr->cfg.retrieve_imeisv_early = true;

	btw("Location Update request causes an IMEISV ID request back to the MS");
	lu_result_sent = RES_NONE;
	dtap_expect_tx("051803");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(dtap_tx_confirmed);

	btw("MS replies with an Identity Response, causes LU to commence with a GSUP LU request to HLR");
	gsup_expect_tx("04010809710000004026f0" CN_DOMAIN VLR_TO_HLR);
	ms_sends_msg("0559094332244332244372f5");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("Subscriber has the IMEISV from the ID Response");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(strcmp(vsub->imeisv, "4234234234234275"), == 0, "%d");
	vlr_subscr_put(vsub, __func__);

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

	btw("LU was successful, and the conn has already been closed");
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");
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

static void test_no_authen_imeisv_imei()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000004620";

	rx_from_ran = OSMO_RAT_GERAN_A;

	comment_start();

	net->vlr->cfg.retrieve_imeisv_early = true;
	net->vlr->cfg.check_imei_rqd = true;

	btw("Location Update request causes an IMEISV ID request back to the MS");
	lu_result_sent = RES_NONE;
	dtap_expect_tx("051803");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(dtap_tx_confirmed);

	btw("MS replies with an Identity Response, causes an early GSUP Check IMEI request to HLR");
	gsup_expect_tx("30010809710000004026f050080724433224433224" VLR_TO_HLR);
	ms_sends_msg("0559094332244332244372f5");
	OSMO_ASSERT(gsup_tx_confirmed);

	btw("Subscriber has the IMEISV from the ID Response");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(strcmp(vsub->imeisv, "4234234234234275"), == 0, "%d");
	vlr_subscr_put(vsub, __func__);

	btw("HLR accepts the IMEI, VLR responds with LU Request");
	expect_bssap_clear();
	gsup_rx("32010809710000004026f0510100" HLR_TO_VLR,
		"04010809710000004026f0" CN_DOMAIN VLR_TO_HLR);
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
	gsup_rx("06010809710000004026f0" HLR_TO_VLR, NULL);

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

static void test_no_authen_imeisv_tmsi()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000004620";

	rx_from_ran = OSMO_RAT_GERAN_A;

	comment_start();

	net->vlr->cfg.retrieve_imeisv_early = true;
	net->vlr->cfg.assign_tmsi = true;

	btw("Location Update request causes an IMEISV ID request back to the MS");
	lu_result_sent = RES_NONE;
	dtap_expect_tx("051803");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(dtap_tx_confirmed);

	btw("MS replies with an Identity Response, causes LU to commence with a GSUP LU request to HLR");
	gsup_expect_tx("04010809710000004026f0" CN_DOMAIN VLR_TO_HLR);
	ms_sends_msg("0559094332244332244372f5");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("Subscriber has the IMEISV from the ID Response");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(strcmp(vsub->imeisv, "4234234234234275"), == 0, "%d");
	vlr_subscr_put(vsub, __func__);

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000004026f00804036470f1" HLR_TO_VLR,
		"12010809710000004026f0" VLR_TO_HLR);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("having received subscriber data does not mean acceptance");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();
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


	BTW("subscriber sends LU Request, this time with the TMSI");
	btw("Location Update request causes an IMEISV ID request back to the MS");
	lu_result_sent = RES_NONE;
	dtap_expect_tx("051803");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(dtap_tx_confirmed);

	btw("MS replies with an Identity Response, causes LU to commence with a GSUP LU request to HLR");
	gsup_expect_tx("04010809710000004026f0" CN_DOMAIN VLR_TO_HLR);
	ms_sends_msg("0559095332244332244372f6");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("Subscriber has the IMEISV from the ID Response");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(strcmp(vsub->imeisv, "5234234234234276"), == 0, "%d");
	vlr_subscr_put(vsub, __func__);

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000004026f00804036470f1" HLR_TO_VLR,
		"12010809710000004026f0" VLR_TO_HLR);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("having received subscriber data does not mean acceptance");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();
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

static void test_no_authen_imeisv_tmsi_imei()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000004620";

	rx_from_ran = OSMO_RAT_GERAN_A;

	comment_start();

	net->vlr->cfg.retrieve_imeisv_early = true;
	net->vlr->cfg.assign_tmsi = true;
	net->vlr->cfg.check_imei_rqd = true;

	btw("Location Update request causes an IMEISV ID request back to the MS");
	lu_result_sent = RES_NONE;
	dtap_expect_tx("051803");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(dtap_tx_confirmed);

	btw("MS replies with an Identity Response, causes an early GSUP Check IMEI request to HLR");
	gsup_expect_tx("30010809710000004026f050080724433224433224" VLR_TO_HLR);
	ms_sends_msg("0559094332244332244372f5");
	OSMO_ASSERT(gsup_tx_confirmed);

	btw("Subscriber has the IMEISV from the ID Response");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(strcmp(vsub->imeisv, "4234234234234275"), == 0, "%d");
	vlr_subscr_put(vsub, __func__);

	btw("HLR accepts the IMEI, VLR responds with LU Request");
	expect_bssap_clear();
	gsup_rx("32010809710000004026f0510100" HLR_TO_VLR,
		"04010809710000004026f0" CN_DOMAIN VLR_TO_HLR);
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
	gsup_rx("06010809710000004026f0" HLR_TO_VLR, NULL);

	btw("a LU Accept with a new TMSI was sent, waiting for TMSI Realloc Compl");
	EXPECT_CONN_COUNT(1);
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS sends TMSI Realloc Complete");
	expect_bssap_clear();
	ms_sends_msg("055b");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	btw("LU was successful, and the conn has already been closed");
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	btw("Subscriber has the IMEISV, IMEI and TMSI");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(strcmp(vsub->imeisv, "4234234234234275"), == 0, "%d");
	VERBOSE_ASSERT(strcmp(vsub->imei, "42342342342342"), == 0, "%d");
	VERBOSE_ASSERT(vsub->tmsi, == 0x03020100, "0x%08x");
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

static void test_no_authen_subscr_expire()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000004620";

	/* No auth only works on GERAN */
	rx_from_ran = OSMO_RAT_GERAN_A;

	comment_start();

	fake_time_start();

	/* The test framework has already started the VLR before fake time was active.
	 * Manually schedule this timeout in fake time. */
	osmo_timer_del(&net->vlr->lu_expire_timer);
	osmo_timer_schedule(&net->vlr->lu_expire_timer, VLR_SUBSCRIBER_LU_EXPIRATION_INTERVAL, 0);

	/* Let the LU expiration timer tick once */
	fake_time_passes(VLR_SUBSCRIBER_LU_EXPIRATION_INTERVAL + 1, 0);

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

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT");
	expect_bssap_clear();
	gsup_rx("06010809710000004026f0" HLR_TO_VLR, NULL);

	btw("LU was successful, and the conn has already been closed");
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	ran_sends_clear_complete();
	EXPECT_CONN_COUNT(0);

	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub);
	vlr_subscr_put(vsub, __func__);

	/* Let T3212 (periodic Location update timer) expire */
	fake_time_passes(vlr_timer_secs(net->vlr, 3212, 3312) + 60 * 4, 0);

	/* The subscriber should now be gone. */
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi, __func__);
	OSMO_ASSERT(vsub == NULL);

	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

msc_vlr_test_func_t msc_vlr_tests[] = {
	test_no_authen,
	test_no_authen_tmsi,
	test_no_authen_imei,
	test_no_authen_tmsi_imei,
	test_no_authen_imeisv,
	test_no_authen_imeisv_imei,
	test_no_authen_imeisv_tmsi,
	test_no_authen_imeisv_tmsi_imei,
	test_no_authen_subscr_expire,
	NULL
};
