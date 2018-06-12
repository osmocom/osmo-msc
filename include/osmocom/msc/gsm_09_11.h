#pragma once

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/gsup.h>

int gsm0911_rcv_nc_ss(struct gsm_subscriber_connection *conn, struct msgb *msg);
int gsm0911_gsup_handler(struct vlr_subscr *vsub, struct osmo_gsup_message *gsup);
