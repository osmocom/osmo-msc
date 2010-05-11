/* OpenBSC Debugging/Logging support code */

/* (C) 2008-2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008 by Holger Hans Peter Freyther <zecke@selfish.org>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <errno.h>

#include <osmocore/talloc.h>
#include <osmocore/utils.h>
#include <osmocore/logging.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/debug.h>

/* default categories */
static const struct log_info_cat default_categories[] = {
	[DRLL] = {
		.name = "DRLL",
		.description = "Radio Link Layer",
		.color = "\033[1;31m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DCC] = {
		.name = "DCC",
		.description = "Call Control",
		.color = "\033[1;32m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DMM] = {
		.name = "DMM",
		.description = "Mobility Management",
		.color = "\033[1;33m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DRR] = {
		.name = "DRR",
		.description = "Radio Resource",
		.color = "\033[1;34m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DRSL] = {
		.name = "DRSL",
		.description = "Radio Siganlling Link",
		.color = "\033[1;35m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DNM] =	{
		.name = "DNM",
		.description = "Network Management (OML)",
		.color = "\033[1;36m",
		.enabled = 1, .loglevel = LOGL_INFO,
	},
	[DMNCC] = {
		.name = "DMNCC",
		.description = "BSC<->MSC interface",
		.color = "\033[1;39m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DSMS] = {
		.name = "DSMS",
		.description = "Short Message Service",
		.color = "\033[1;37m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DPAG]	= {
		.name = "DPAG",
		.description = "Paging",
		.color = "\033[1;38m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DMEAS] = {
		.name = "DMEAS",
		.description = "Measurement Processing",
		.enabled = 0, .loglevel = LOGL_NOTICE,
	},
	[DMI] = {
		.name = "DMI",
		.description = "mISDN Input Driver",
		.enabled = 0, .loglevel = LOGL_NOTICE,
	},
	[DMIB] = {
		.name = "DMIB",
		.description = "mISDN B-Channels",
		.enabled = 0, .loglevel = LOGL_NOTICE,
	},
	[DMUX] = {
		.name = "DMUX",
		.description = "TRAU Frame Multiplex",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DINP] = {
		.name = "DINP",
		.description = "Input Driver",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DSCCP] = {
		.name = "DSCCP",
		.description = "SCCP Protocol",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DMSC] = {
		.name = "DMSC",
		.description = "Mobile Switching Center",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DMGCP] = {
		.name = "DMGCP",
		.description = "Media Gateway Control Protocol",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DHO] = {
		.name = "DHO",
		.description = "Hand-Over",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DDB] = {
		.name = "DDB",
		.description = "Database",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DREF] = {
		.name = "DREF",
		.description = "Reference Counting",
		.enabled = 0, .loglevel = LOGL_NOTICE,
	},
	[DGPRS] = {
		.name = "DGPRS",
		.description = "GPRS Packet Service",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DNS] = {
		.name = "DNS",
		.description = "GPRS Network Service",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DBSSGP] = {
		.name = "DBSSGP",
		.description = "GPRS BSSGP Protocol",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

enum log_ctxt {
	CTX_SUBSCRIBER,
};

enum log_filter {
	_FLT_ALL = LOG_FILTER_ALL,	/* libosmocore */
	FLT_IMSI = 1,
};

static int filter_fn(const struct log_context *ctx,
		     struct log_target *tar)
{
	struct gsm_subscriber *subscr = ctx->ctx[CTX_SUBSCRIBER];

	if ((tar->filter_map & (1 << FLT_IMSI)) != 0
	    && subscr && strcmp(subscr->imsi, tar->filter_data[FLT_IMSI]) == 0)
		return 1;

	return 0;
}

const struct log_info log_info = {
	.filter_fn = filter_fn,
	.cat = default_categories,
	.num_cat = ARRAY_SIZE(default_categories),
};

void log_set_imsi_filter(struct log_target *target, const char *imsi)
{
	if (imsi) {
		target->filter_map |= (1 << FLT_IMSI);
		target->filter_data[FLT_IMSI] = talloc_strdup(target, imsi);
	} else if (target->filter_data[FLT_IMSI]) {
		target->filter_map &= ~(1 << FLT_IMSI);
		talloc_free(target->filter_data[FLT_IMSI]);
		target->filter_data[FLT_IMSI] = NULL;
	}
}
