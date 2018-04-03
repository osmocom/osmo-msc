#pragma once

#include <stdint.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/msc/gsm_data.h>

/* A struct to keep a context information about the LACs a specific BSC is
 * associated with */
struct lac_context {
	struct llist_head list;
	uint16_t lac;
	enum ran_type ran_type;
	struct bsc_context *bsc_context;
};

void msc_lac_update_a(struct gsm_network *network, uint16_t lac, struct bsc_context *bsc_context);
