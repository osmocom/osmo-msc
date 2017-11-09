/* (C) 2017 by sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Philipp Maier
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

#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/fsm.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <osmocom/msc/debug.h>
#include <osmocom/msc/bsc_msc_data.h>
#include <osmocom/msc/osmo_bsc_sigtran.h>

#define RESET_RESEND_INTERVAL 2	/* sec */
#define RESET_RESEND_TIMER_NO 1234	/* FIXME: dig out the real timer number */
#define BAD_CONNECTION_THRESOLD 3	/* connection failures */

enum fsm_states {
	ST_DISC,		/* Disconnected from remote end */
	ST_CONN,		/* We have a confirmed connection */
};

static const struct value_string fsm_state_names[] = {
	{ST_DISC, "ST_DISC (disconnected)"},
	{ST_CONN, "ST_CONN (connected)"},
	{0, NULL},
};

enum fsm_evt {
	EV_RESET_ACK,		/* got reset acknowlegement from remote end */
	EV_N_DISCONNECT,	/* lost a connection */
	EV_N_CONNECT,		/* made a successful connection */
};

static const struct value_string fsm_evt_names[] = {
	{EV_RESET_ACK, "EV_RESET_ACK"},
	{EV_N_DISCONNECT, "EV_N_DISCONNECT"},
	{EV_N_CONNECT, "EV_N_CONNECT"},
	{0, NULL},
};

/* Disconnected state */
static void fsm_disc_cb(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct a_reset_ctx *reset = (struct a_reset_ctx *)data;
	OSMO_ASSERT(reset);
	OSMO_ASSERT(reset->fsm);

	LOGPFSML(reset->fsm, LOGL_NOTICE, "fsm-state (msc-reset): %s, fsm-event: %s\n",
	     get_value_string(fsm_state_names, ST_CONN), get_value_string(fsm_evt_names, event));

	reset->conn_loss_counter = 0;
	osmo_fsm_inst_state_chg(fi, ST_CONN, 0, 0);
}

/* Connected state */
static void fsm_conn_cb(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct a_reset_ctx *reset = (struct a_reset_ctx *)data;
	OSMO_ASSERT(reset);

	LOGPFSML(reset->fsm, LOGL_NOTICE, "fsm-state (msc-reset): %s, fsm-event: %s\n",
	     get_value_string(fsm_state_names, ST_CONN), get_value_string(fsm_evt_names, event));

	switch (event) {
	case EV_N_DISCONNECT:
		if (reset->conn_loss_counter >= BAD_CONNECTION_THRESOLD) {
			LOGPFSML(reset->fsm, LOGL_NOTICE, "SIGTRAN connection down, reconnecting...\n");
			osmo_fsm_inst_state_chg(fi, ST_DISC, RESET_RESEND_INTERVAL, RESET_RESEND_TIMER_NO);
		} else
			reset->conn_loss_counter++;
		break;
	case EV_N_CONNECT:
		reset->conn_loss_counter = 0;
		break;
	}
}

/* Timer callback to retransmit the reset signal */
static int fsm_reset_ack_timeout_cb(struct osmo_fsm_inst *fi)
{
	struct a_reset_ctx *reset = (struct a_reset_ctx *)fi->priv;
	OSMO_ASSERT(reset->fsm);

	LOGPFSML(reset->fsm, LOGL_NOTICE, "reset-ack timeout (T%i) in state %s, resending...\n", fi->T,
	     get_value_string(fsm_state_names, fi->state));

	reset->cb(reset->priv);

	osmo_fsm_inst_state_chg(fi, ST_DISC, RESET_RESEND_INTERVAL, RESET_RESEND_TIMER_NO);
	return 0;
}

static struct osmo_fsm_state fsm_states[] = {
	[ST_DISC] = {
		     .in_event_mask = (1 << EV_RESET_ACK),
		     .out_state_mask = (1 << ST_DISC) | (1 << ST_CONN),
		     .name = "DISC",
		     .action = fsm_disc_cb,
		     },
	[ST_CONN] = {
		     .in_event_mask = (1 << EV_N_DISCONNECT) | (1 << EV_N_CONNECT),
		     .out_state_mask = (1 << ST_DISC) | (1 << ST_CONN),
		     .name = "CONN",
		     .action = fsm_conn_cb,
		     },
};

/* State machine definition */
static struct osmo_fsm fsm = {
	.name = "A-RESET",
	.states = fsm_states,
	.num_states = ARRAY_SIZE(fsm_states),
	.log_subsys = DMSC,
	.timer_cb = fsm_reset_ack_timeout_cb,
};

/* Create and start state machine which handles the reset/reset-ack procedure */
struct a_reset_ctx *a_reset_alloc(const void *ctx, const char *name, void *cb, void *priv)
{
	OSMO_ASSERT(name);

	struct a_reset_ctx *reset;

	/* Register the fsm description (if not already done) */
	if (osmo_fsm_find_by_name(fsm.name) != &fsm)
		osmo_fsm_register(&fsm);

	/* Allocate and configure a new fsm instance */
	reset = talloc_zero(ctx, struct a_reset_ctx);
	OSMO_ASSERT(reset);
	reset->priv = priv;
	reset->cb = cb;
	reset->conn_loss_counter = 0;
	reset->fsm = osmo_fsm_inst_alloc(&fsm, NULL, NULL, LOGL_DEBUG, name);
	OSMO_ASSERT(reset->fsm);
	reset->fsm->priv = reset;
	LOGPFSML(reset->fsm, LOGL_NOTICE, "reset handler fsm created.\n");

	/* kick off reset-ack sending mechanism */
	osmo_fsm_inst_state_chg(reset->fsm, ST_DISC, RESET_RESEND_INTERVAL, RESET_RESEND_TIMER_NO);

	return reset;
}

/* Tear down state machine */
void a_reset_free(struct a_reset_ctx *reset)
{
	OSMO_ASSERT(reset);
	OSMO_ASSERT(reset->fsm);

	osmo_fsm_inst_free(reset->fsm);
	reset->fsm = NULL;

	memset(reset, 0, sizeof(*reset));
	talloc_free(reset);

	LOGPFSML(reset->fsm, LOGL_NOTICE, "reset handler fsm destroyed.\n");
}

/* Confirm that we sucessfully received a reset acknowlege message */
void a_reset_ack_confirm(struct a_reset_ctx *reset)
{
	OSMO_ASSERT(reset);
	OSMO_ASSERT(reset->fsm);

	osmo_fsm_inst_dispatch(reset->fsm, EV_RESET_ACK, reset);
}

/* Report a failed connection */
void a_reset_conn_fail(struct a_reset_ctx *reset)
{
	/* If no reset context is supplied, just drop the info */
	if (!reset)
		return;

	OSMO_ASSERT(reset->fsm);

	osmo_fsm_inst_dispatch(reset->fsm, EV_N_DISCONNECT, reset);
}

/* Report a successful connection */
void a_reset_conn_success(struct a_reset_ctx *reset)
{
	/* If no reset context is supplied, just drop the info */
	if (!reset)
		return;

	OSMO_ASSERT(reset->fsm);

	osmo_fsm_inst_dispatch(reset->fsm, EV_N_CONNECT, reset);
}

/* Check if we have a connection to a specified msc */
bool a_reset_conn_ready(struct a_reset_ctx *reset)
{
	/* If no reset context is supplied, we assume that
	 * the connection can't be ready! */
	if (!reset)
		return false;

	OSMO_ASSERT(reset->fsm);
	if (reset->fsm->state == ST_CONN)
		return true;

	return false;
}
