#pragma once

#include <stdint.h>

struct msgb;
struct gsm_network;

typedef int (*mncc_recv_cb_t)(struct gsm_network *, struct msgb *);

struct gsm_network *gsm_network_init(void *ctx, mncc_recv_cb_t mncc_recv);
