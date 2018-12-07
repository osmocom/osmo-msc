#pragma once

struct msc_a;
struct mgsb;
struct gsup_client_mux;
struct osmo_gsup_message;

int gsm0911_rcv_nc_ss(struct msc_a *msc_a, struct msgb *msg);
int gsm0911_gsup_rx(struct gsup_client_mux *gcm, void *data, const struct osmo_gsup_message *msg);
