/* Filter/overlay data rates for CSD, across MS, RAN and CN limitations */
/*
 * (C) 2023 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Oliver Smith
 *
 * SPDX-License-Identifier: GPL-2.0+
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
 */
#pragma once

#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/mncc.h>
#include <osmocom/mgcp_client/mgcp_client.h>

#include <osmocom/msc/csd_bs.h>
#include <osmocom/msc/sdp_msg.h>

/* Combine various data rate selections to obtain a resulting set allowed by
 * all of them. Members reflect the different entities/stages that select data
 * rates in CSD. Call csd_filter_run() and obtain the resulting set in
 * csd_filter.result. */
struct csd_filter {
	/* The fixed set available on the RAN type, per definition. */
	struct csd_bs_list ran;
	/* The services advertised by the MS Bearer Capabilities */
	struct csd_bs_list ms;
	/* If known, the set the current RAN cell allows / has available. This
	 * may not be available if the BSC does not issue this information
	 * early enough. Should be ignored if empty. */
	struct csd_bs_list bss;

	/* After a channel was assigned, this reflects the chosen BS. */
	enum csd_bs assignment;
};

void csd_filter_set_ran(struct csd_filter *filter, enum osmo_rat_type ran_type);
int csd_filter_run(struct csd_filter *filter, struct sdp_msg *result, const struct sdp_msg *remote);

int csd_filter_to_str_buf(char *buf, size_t buflen, const struct csd_filter *filter,
			    const struct sdp_msg *result, const struct sdp_msg *remote);
char *csd_filter_to_str_c(void *ctx, const struct csd_filter *filter, const struct sdp_msg *result, const struct sdp_msg *remote);
const char *csd_filter_to_str(const struct csd_filter *filter, const struct sdp_msg *result, const struct sdp_msg *remote);
