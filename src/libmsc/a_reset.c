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
#include <osmocom/msc/a_reset.h>

#define RESET_RESEND_INTERVAL 2		/* sec */
#define RESET_RESEND_TIMER_NO 16	/* See also 3GPP TS 48.008 Chapter 3.1.4.1.3.2 */

enum reset_fsm_states {
	ST_DISC,		/* Disconnected from remote end */
	ST_CONN,		/* We have a confirmed connection */
};

enum reset_fsm_evt {
	EV_CONN_ACK,		/* Received either BSSMAP RESET or BSSMAP RESET
				 * ACK from the remote end */
};

/* Reset context data (callbacks, state machine etc...) */
struct reset_ctx {
	/* Callback function to be called when a connection
	 * failure is detected and a rest must occur */
	void (*cb)(void *priv);

	/* Privated data for the callback function */
	void *priv;
};

static const struct value_string fsm_event_names[] = {
	OSMO_VALUE_STRING(EV_CONN_ACK),
	{0, NULL}
};

/* Disconnected state */
static void fsm_disc_cb(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	osmo_fsm_inst_state_chg(fi, ST_CONN, 0, 0);
}

/* Timer callback to retransmit the reset signal */
static int fsm_reset_ack_timeout_cb(struct osmo_fsm_inst *fi)
{
	struct reset_ctx *reset_ctx = (struct reset_ctx *)fi->priv;
	LOGPFSML(fi, LOGL_NOTICE, "(re)sending BSSMAP RESET message...\n");
	reset_ctx->cb(reset_ctx->priv);
	osmo_fsm_inst_state_chg(fi, ST_DISC, RESET_RESEND_INTERVAL, RESET_RESEND_TIMER_NO);
	return 0;
}

static struct osmo_fsm_state reset_fsm_states[] = {
	[ST_DISC] = {
		     .in_event_mask = (1 << EV_CONN_ACK),
		     .out_state_mask = (1 << ST_CONN) | (1 << ST_DISC),
		     .name = "DISC",
		     .action = fsm_disc_cb,
		     },
	[ST_CONN] = {
		     .in_event_mask = (1 << EV_CONN_ACK),
		     .name = "CONN",
		     },
};

/* State machine definition */
static struct osmo_fsm fsm = {
	.name = "A-RESET",
	.states = reset_fsm_states,
	.num_states = ARRAY_SIZE(reset_fsm_states),
	.log_subsys = DMSC,
	.timer_cb = fsm_reset_ack_timeout_cb,
	.event_names = fsm_event_names,
};

/* Create and start state machine which handles the reset/reset-ack procedure */
struct osmo_fsm_inst *a_reset_alloc(void *ctx, const char *name, void *cb,
				    void *priv, bool already_connected)
{
	OSMO_ASSERT(name);

	struct reset_ctx *reset_ctx;
	struct osmo_fsm_inst *reset_fsm;

	/* Register the fsm description (if not already done) */
	if (osmo_fsm_find_by_name(fsm.name) != &fsm)
		osmo_fsm_register(&fsm);

	/* Allocate and configure a new fsm instance */
	reset_ctx = talloc_zero(ctx, struct reset_ctx);
	OSMO_ASSERT(reset_ctx);
	reset_ctx->priv = priv;
	reset_ctx->cb = cb;
        reset_fsm = osmo_fsm_inst_alloc(&fsm, ctx, reset_ctx, LOGL_DEBUG, name);
	OSMO_ASSERT(reset_fsm);

	if (already_connected)
		osmo_fsm_inst_state_chg(reset_fsm, ST_CONN, 0, 0);
	else {
		/* kick off reset-ack sending mechanism */
		osmo_fsm_inst_state_chg(reset_fsm, ST_DISC, RESET_RESEND_INTERVAL,
					RESET_RESEND_TIMER_NO);
	}

	return reset_fsm;
}

/* Confirm that we sucessfully received a reset acknowlege message */
void a_reset_ack_confirm(struct osmo_fsm_inst *reset_fsm)
{
	OSMO_ASSERT(reset_fsm);
	osmo_fsm_inst_dispatch(reset_fsm, EV_CONN_ACK, NULL);
}

/* Check if we have a connection to a specified msc */
bool a_reset_conn_ready(struct osmo_fsm_inst *reset_fsm)
{
	/* If no reset context is supplied, we assume that
	 * the connection can't be ready! */
	if (!reset_fsm)
		return false;

	if (reset_fsm->state == ST_CONN)
		return true;

	return false;
}
