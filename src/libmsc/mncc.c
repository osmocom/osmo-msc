/* mncc.c - utility routines for the MNCC API between the 04.08
 *	    message parsing and the actual Call Control logic */

/* (C) 2008-2018 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009 by Andreas Eversberg <Andreas.Eversberg@versatel.de>
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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include <osmocom/msc/gsm_04_08.h>
#include <osmocom/msc/debug.h>
#include <osmocom/msc/mncc.h>
#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/transaction.h>


static const struct value_string mncc_names[] = {
	{ MNCC_SETUP_REQ, "MNCC_SETUP_REQ" },
	{ MNCC_SETUP_IND, "MNCC_SETUP_IND" },
	{ MNCC_SETUP_RSP, "MNCC_SETUP_RSP" },
	{ MNCC_SETUP_CNF, "MNCC_SETUP_CNF" },
	{ MNCC_SETUP_COMPL_REQ, "MNCC_SETUP_COMPL_REQ" },
	{ MNCC_SETUP_COMPL_IND, "MNCC_SETUP_COMPL_IND" },
	{ MNCC_CALL_CONF_IND, "MNCC_CALL_CONF_IND" },
	{ MNCC_CALL_PROC_REQ, "MNCC_CALL_PROC_REQ" },
	{ MNCC_PROGRESS_REQ, "MNCC_PROGRESS_REQ" },
	{ MNCC_ALERT_REQ, "MNCC_ALERT_REQ" },
	{ MNCC_ALERT_IND, "MNCC_ALERT_IND" },
	{ MNCC_NOTIFY_REQ, "MNCC_NOTIFY_REQ" },
	{ MNCC_NOTIFY_IND, "MNCC_NOTIFY_IND" },
	{ MNCC_DISC_REQ, "MNCC_DISC_REQ" },
	{ MNCC_DISC_IND, "MNCC_DISC_IND" },
	{ MNCC_REL_REQ, "MNCC_REL_REQ" },
	{ MNCC_REL_IND, "MNCC_REL_IND" },
	{ MNCC_REL_CNF, "MNCC_REL_CNF" },
	{ MNCC_FACILITY_REQ, "MNCC_FACILITY_REQ" },
	{ MNCC_FACILITY_IND, "MNCC_FACILITY_IND" },
	{ MNCC_START_DTMF_IND, "MNCC_START_DTMF_IND" },
	{ MNCC_START_DTMF_RSP, "MNCC_START_DTMF_RSP" },
	{ MNCC_START_DTMF_REJ, "MNCC_START_DTMF_REJ" },
	{ MNCC_STOP_DTMF_IND, "MNCC_STOP_DTMF_IND" },
	{ MNCC_STOP_DTMF_RSP, "MNCC_STOP_DTMF_RSP" },
	{ MNCC_MODIFY_REQ, "MNCC_MODIFY_REQ" },
	{ MNCC_MODIFY_IND, "MNCC_MODIFY_IND" },
	{ MNCC_MODIFY_RSP, "MNCC_MODIFY_RSP" },
	{ MNCC_MODIFY_CNF, "MNCC_MODIFY_CNF" },
	{ MNCC_MODIFY_REJ, "MNCC_MODIFY_REJ" },
	{ MNCC_HOLD_IND, "MNCC_HOLD_IND" },
	{ MNCC_HOLD_CNF, "MNCC_HOLD_CNF" },
	{ MNCC_HOLD_REJ, "MNCC_HOLD_REJ" },
	{ MNCC_RETRIEVE_IND, "MNCC_RETRIEVE_IND" },
	{ MNCC_RETRIEVE_CNF, "MNCC_RETRIEVE_CNF" },
	{ MNCC_RETRIEVE_REJ, "MNCC_RETRIEVE_REJ" },
	{ MNCC_USERINFO_REQ, "MNCC_USERINFO_REQ" },
	{ MNCC_USERINFO_IND, "MNCC_USERINFO_IND" },
	{ MNCC_REJ_REQ, "MNCC_REJ_REQ" },
	{ MNCC_REJ_IND, "MNCC_REJ_IND" },
	{ MNCC_BRIDGE, "MNCC_BRIDGE" },
	{ MNCC_FRAME_RECV, "MNCC_FRAME_RECV" },
	{ MNCC_FRAME_DROP, "MNCC_FRAME_DROP" },
	{ MNCC_LCHAN_MODIFY, "MNCC_LCHAN_MODIFY" },
	{ MNCC_RTP_CREATE, "MNCC_RTP_CREATE" },
	{ MNCC_RTP_CONNECT, "MNCC_RTP_CONNECT" },
	{ MNCC_RTP_FREE, "MNCC_RTP_FREE" },
	{ GSM_TCHF_FRAME, "GSM_TCHF_FRAME" },
	{ GSM_TCHF_FRAME_EFR, "GSM_TCHF_FRAME_EFR" },
	{ GSM_TCHH_FRAME, "GSM_TCHH_FRAME" },
	{ GSM_TCH_FRAME_AMR, "GSM_TCH_FRAME_AMR" },
	{ GSM_BAD_FRAME, "GSM_BAD_FRAME" },
	{ 0, NULL },
};

const char *get_mncc_name(int value)
{
	return get_value_string(mncc_names, value);
}

void mncc_set_cause(struct gsm_mncc *data, int loc, int val)
{
	data->fields |= MNCC_F_CAUSE;
	data->cause.location = loc;
	data->cause.value = val;
}


/***********************************************************************
 * MNCC validation code. Move to libosmocore once headers are merged
 ************************************************************************/

#define MNCC_F_ALL 0x3fff

static int check_string_terminated(const char *str, unsigned int size)
{
	int i;
	for (i = 0; i < size; i++) {
		if (str[i] == 0)
			return 0;
	}
	return -EINVAL;
}

static int mncc_check_number(const struct gsm_mncc_number *num, const char *str)
{
	int rc;
	rc = check_string_terminated(num->number, ARRAY_SIZE(num->number));
	if (rc < 0)
		LOGP(DMNCC, LOGL_ERROR, "MNCC %s number not terminated\n", str);
	return rc;
}

static int mncc_check_cause(const struct gsm_mncc_cause *cause)
{
	if (cause->diag_len > sizeof(cause->diag))
		return -EINVAL;
	return 0;
}

static int mncc_check_useruser(const struct gsm_mncc_useruser *uu)
{
	return check_string_terminated(uu->info, ARRAY_SIZE(uu->info));
}

static int mncc_check_facility(const struct gsm_mncc_facility *fac)
{
	return check_string_terminated(fac->info, ARRAY_SIZE(fac->info));
}

static int mncc_check_ssversion(const struct gsm_mncc_ssversion *ssv)
{
	return check_string_terminated(ssv->info, ARRAY_SIZE(ssv->info));
}

static int mncc_prim_check_sign(const struct gsm_mncc *mncc_prim)
{
	int rc;

	if (mncc_prim->fields & ~ MNCC_F_ALL) {
		LOGP(DMNCC, LOGL_ERROR, "Unknown MNCC field mask 0x%x\n", mncc_prim->fields);
		return -EINVAL;
	}

	rc = check_string_terminated(mncc_prim->imsi, sizeof(mncc_prim->imsi));
	if (rc < 0) {
		LOGP(DMNCC, LOGL_ERROR, "MNCC IMSI not terminated\n");
		return rc;
	}

	if (mncc_prim->fields & MNCC_F_CALLED) {
		rc = mncc_check_number(&mncc_prim->called, "called");
		if (rc < 0)
			return rc;
	}

	if (mncc_prim->fields & MNCC_F_CALLING) {
		rc = mncc_check_number(&mncc_prim->calling, "calling");
		if (rc < 0)
			return rc;
	}

	if (mncc_prim->fields & MNCC_F_REDIRECTING) {
		rc = mncc_check_number(&mncc_prim->redirecting, "redirecting");
		if (rc < 0)
			return rc;
	}

	if (mncc_prim->fields & MNCC_F_CONNECTED) {
		rc = mncc_check_number(&mncc_prim->connected, "connected");
		if (rc < 0)
			return rc;
	}

	if (mncc_prim->fields & MNCC_F_CAUSE) {
		rc = mncc_check_cause(&mncc_prim->cause);
		if (rc < 0)
			return rc;
	}

	if (mncc_prim->fields & MNCC_F_USERUSER) {
		rc = mncc_check_useruser(&mncc_prim->useruser);
		if (rc < 0)
			return rc;
	}

	if (mncc_prim->fields & MNCC_F_FACILITY) {
		rc = mncc_check_facility(&mncc_prim->facility);
		if (rc < 0)
			return rc;
	}

	if (mncc_prim->fields & MNCC_F_SSVERSION) {
		rc = mncc_check_ssversion(&mncc_prim->ssversion);
		if (rc < 0)
			return rc;
	}

	if (mncc_prim->fields & MNCC_F_BEARER_CAP) {
		bool m1_found = false;
		int i;

		for (i = 0; i < ARRAY_SIZE(mncc_prim->bearer_cap.speech_ver); i++) {
			if (mncc_prim->bearer_cap.speech_ver[i] == -1) {
				m1_found = true;
				break;
			}
		}
		if (!m1_found) {
			LOGP(DMNCC, LOGL_ERROR, "Unterminated MNCC bearer capability\n");
			return -EINVAL;
		}
	}

	return 0;
}

int mncc_prim_check(const struct gsm_mncc *mncc_prim, unsigned int len)
{
	if (len < sizeof(mncc_prim->msg_type)) {
		LOGP(DMNCC, LOGL_ERROR, "Short MNCC Header\n");
		return -EINVAL;
	}

	switch (mncc_prim->msg_type) {
	case MNCC_SOCKET_HELLO:
		if (len < sizeof(struct gsm_mncc_hello)) {
			LOGP(DMNCC, LOGL_ERROR, "Short MNCC Hello\n");
			return -EINVAL;
		}
		break;
	case GSM_BAD_FRAME:
	case GSM_TCH_FRAME_AMR:
	case GSM_TCHH_FRAME:
	case GSM_TCHF_FRAME_EFR:
	case GSM_TCHF_FRAME:
		if (len < sizeof(struct gsm_data_frame)) {
			LOGP(DMNCC, LOGL_ERROR, "Short MNCC TCH\n");
			return -EINVAL;
		}
		break;
	case MNCC_RTP_FREE:
	case MNCC_RTP_CONNECT:
	case MNCC_RTP_CREATE:
		if (len < sizeof(struct gsm_mncc_rtp)) {
			LOGP(DMNCC, LOGL_ERROR, "Short MNCC RTP\n");
			return -EINVAL;
		}
		break;
	case MNCC_LCHAN_MODIFY:
	case MNCC_FRAME_DROP:
	case MNCC_FRAME_RECV:
		/* FIXME */
		break;
	case MNCC_BRIDGE:
		if (len < sizeof(struct gsm_mncc_bridge)) {
			LOGP(DMNCC, LOGL_ERROR, "Short MNCC BRIDGE\n");
			return -EINVAL;
		}
		break;
	default:
		if (len < sizeof(struct gsm_mncc)) {
			LOGP(DMNCC, LOGL_ERROR, "Short MNCC Signalling\n");
			return -EINVAL;
		}
		return mncc_prim_check_sign(mncc_prim);
	}
	return 0;
}
