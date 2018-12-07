/* Generic signalling/notification infrastructure */
/* (C) 2009-2010, 2015 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010 by On-Waves
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

#pragma once

#include <stdlib.h>
#include <errno.h>

#include <osmocom/msc/gsm_data.h>

#include <osmocom/core/signal.h>

struct msc_a;
struct vty;

/*
 * Signalling subsystems
 */
enum signal_subsystems {
	SS_PAGING,
	SS_SMS,
	SS_SUBSCR,
	SS_SCALL,
};

/* SS_PAGING signals */
enum signal_paging {
	S_PAGING_SUCCEEDED,
	S_PAGING_EXPIRED,
};

/* SS_SMS signals */
enum signal_sms {
	S_SMS_SUBMITTED,	/* A SMS has been successfully submitted to us */
	S_SMS_DELIVERED,	/* A SMS has been successfully delivered to a MS */
	S_SMS_SMMA,		/* A MS tells us it has more space available */
	S_SMS_MEM_EXCEEDED,	/* A MS tells us it has no more space available */
	S_SMS_UNKNOWN_ERROR,	/* A MS tells us it has an error */
};

/* SS_SUBSCR signals */
enum signal_subscr {
	S_SUBSCR_ATTACHED,
	S_SUBSCR_DETACHED,
	S_SUBSCR_IDENTITY,		/* we've received some identity information */
};

/* SS_SCALL signals */
enum signal_scall {
	S_SCALL_SUCCESS,
	S_SCALL_FAILED,
	S_SCALL_DETACHED,
};

/* SS_IPAC_NWL signals */
enum signal_ipaccess {
	S_IPAC_NWL_COMPLETE,
};

enum signal_global {
	S_GLOBAL_BTS_CLOSE_OM,
};

struct paging_signal_data {
	struct vlr_subscr *vsub;
	struct msc_a *msc_a;
};

struct scall_signal_data {
	struct msc_a *msc_a;
	struct vty *vty;
};
struct sms_signal_data {
	/* The transaction where this occured */
	struct gsm_trans *trans;
	/* Can be NULL for SMMA */
	struct gsm_sms *sms;
	/* true when paging was successful */
	bool paging_result;
};
