#pragma once

#include <osmocom/core/msgb.h>

int handle_rcv_ussd(struct gsm_subscriber_connection *conn, struct msgb *msg);
