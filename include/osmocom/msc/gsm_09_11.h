#pragma once

#include <osmocom/core/msgb.h>

int gsm0911_rcv_nc_ss(struct gsm_subscriber_connection *conn, struct msgb *msg);
