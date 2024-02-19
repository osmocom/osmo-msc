/* mncc_sock.c: Tie the MNCC interface to a unix domain socket */

/* (C) 2008-2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009 by Andreas Eversberg <Andreas.Eversberg@versatel.de>
 * (C) 2012 by Holger Hans Peter Freyther
 * All Rights Reserved
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
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>

#include <osmocom/msc/debug.h>
#include <osmocom/msc/mncc.h>
#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/gsm_04_08.h>

struct mncc_sock_state {
	struct gsm_network *net;
	struct osmo_fd listen_bfd;	/* fd for listen socket */
	struct osmo_fd conn_bfd;		/* fd for connection to lcr */
};

/* input from CC code into mncc_sock */
int mncc_sock_from_cc(struct gsm_network *net, struct msgb *msg)
{
	struct gsm_mncc *mncc_in = (struct gsm_mncc *) msgb_data(msg);
	int msg_type = mncc_in->msg_type;

	/* Check if we currently have a MNCC handler connected */
	if (net->mncc_state->conn_bfd.fd < 0) {
		LOGP(DMNCC, LOGL_ERROR, "mncc_sock receives %s for external CC app "
			"but socket is gone\n", get_mncc_name(msg_type));
		/* free the original message */
		msgb_free(msg);
		return -1;
	}

	/* FIXME: check for some maximum queue depth? */

	/* Actually enqueue the message and mark socket write need */
	msgb_enqueue(&net->upqueue, msg);
	osmo_fd_write_enable(&net->mncc_state->conn_bfd);
	return 0;
}

static void mncc_sock_close(struct mncc_sock_state *state)
{
	struct osmo_fd *bfd = &state->conn_bfd;

	LOGP(DMNCC, LOGL_NOTICE, "MNCC Socket has LOST connection\n");

	osmo_fd_unregister(bfd);
	close(bfd->fd);
	bfd->fd = -1;

	/* re-enable the generation of ACCEPT for new connections */
	osmo_fd_read_enable(&state->listen_bfd);

	/* release all existing calls */
	gsm0408_clear_all_trans(state->net, TRANS_CC);

	/* flush the queue */
	while (!llist_empty(&state->net->upqueue)) {
		struct msgb *msg = msgb_dequeue(&state->net->upqueue);
		msgb_free(msg);
	}
}

static int mncc_sock_read(struct osmo_fd *bfd)
{
	struct mncc_sock_state *state = (struct mncc_sock_state *)bfd->data;
	struct gsm_mncc *mncc_prim;
	struct msgb *msg;
	int rc;

	msg = msgb_alloc(sizeof(*mncc_prim)+256, "mncc_sock_rx");
	if (!msg)
		return -ENOMEM;

	mncc_prim = (struct gsm_mncc *) msg->tail;

	rc = recv(bfd->fd, msg->tail, msgb_tailroom(msg), 0);
	if (rc == 0)
		goto close;

	if (rc < 0) {
		if (errno == EAGAIN)
			return 0;
		goto close;
	}
	msgb_put(msg, rc);

	rc = mncc_prim_check(mncc_prim, rc);
	if (rc == 0)
		rc = mncc_tx_to_cc(state->net, mncc_prim);

	/* as we always synchronously process the message in mncc_send() and
	 * its callbacks, we can free the message here. */
	msgb_free(msg);

	return rc;

close:
	msgb_free(msg);
	mncc_sock_close(state);
	return -1;
}

static int mncc_sock_write(struct osmo_fd *bfd)
{
	struct mncc_sock_state *state = bfd->data;
	struct gsm_network *net = state->net;
	int rc;

	while (!llist_empty(&net->upqueue)) {
		struct msgb *msg, *msg2;
		struct gsm_mncc *mncc_prim;

		/* peek at the beginning of the queue */
		msg = llist_entry(net->upqueue.next, struct msgb, list);
		mncc_prim = (struct gsm_mncc *)msg->data;

		osmo_fd_write_disable(bfd);

		/* bug hunter 8-): maybe someone forgot msgb_put(...) ? */
		if (!msgb_length(msg)) {
			LOGP(DMNCC, LOGL_ERROR, "message type (%d) with ZERO "
				"bytes!\n", mncc_prim->msg_type);
			goto dontsend;
		}

		/* try to send it over the socket */
		rc = write(bfd->fd, msgb_data(msg), msgb_length(msg));
		if (rc == 0)
			goto close;
		if (rc < 0) {
			if (errno == EAGAIN) {
				osmo_fd_write_enable(bfd);
				break;
			}
			goto close;
		}

dontsend:
		/* _after_ we send it, we can deueue */
		msg2 = msgb_dequeue(&net->upqueue);
		assert(msg == msg2);
		msgb_free(msg);
	}
	return 0;

close:
	mncc_sock_close(state);

	return -1;
}

static int mncc_sock_cb(struct osmo_fd *bfd, unsigned int flags)
{
	int rc = 0;

	if (flags & OSMO_FD_READ)
		rc = mncc_sock_read(bfd);
	if (rc < 0)
		return rc;

	if (flags & OSMO_FD_WRITE)
		rc = mncc_sock_write(bfd);

	return rc;
}

/**
 * Send a version indication to the remote.
 */
static void queue_hello(struct mncc_sock_state *mncc)
{
	struct gsm_mncc_hello *hello;
	struct msgb *msg;

	msg = msgb_alloc(512, "mncc hello");
	if (!msg) {
		LOGP(DMNCC, LOGL_ERROR, "Failed to allocate hello.\n");
		mncc_sock_close(mncc);
		return;
	}

	hello = (struct gsm_mncc_hello *) msgb_put(msg, sizeof(*hello));
	hello->msg_type = MNCC_SOCKET_HELLO;
	hello->version = MNCC_SOCK_VERSION;
	hello->mncc_size = sizeof(struct gsm_mncc);
	hello->data_frame_size = sizeof(struct gsm_data_frame);
	hello->called_offset = offsetof(struct gsm_mncc, called);
	hello->signal_offset = offsetof(struct gsm_mncc, signal);
	hello->emergency_offset = offsetof(struct gsm_mncc, emergency);
	hello->lchan_type_offset = offsetof(struct gsm_mncc, lchan_type);

	msgb_enqueue(&mncc->net->upqueue, msg);
	osmo_fd_write_enable(&mncc->conn_bfd);
}

/* accept a new connection */
static int mncc_sock_accept(struct osmo_fd *bfd, unsigned int flags)
{
	struct mncc_sock_state *state = (struct mncc_sock_state *)bfd->data;
	struct osmo_fd *conn_bfd = &state->conn_bfd;
	struct sockaddr_un un_addr;
	socklen_t len;
	int rc;

	len = sizeof(un_addr);
	rc = accept(bfd->fd, (struct sockaddr *) &un_addr, &len);
	if (rc < 0) {
		LOGP(DMNCC, LOGL_ERROR, "Failed to accept a new connection\n");
		return -1;
	}

	if (conn_bfd->fd >= 0) {
		LOGP(DMNCC, LOGL_NOTICE, "MNCC app connects but we already have "
			"another active connection ?!?\n");
		/* We already have one MNCC app connected, this is all we support */
		osmo_fd_read_disable(&state->listen_bfd);
		close(rc);
		return 0;
	}

	osmo_fd_setup(conn_bfd, rc, OSMO_FD_READ, mncc_sock_cb, state, 0);
	if (osmo_fd_register(conn_bfd) != 0) {
		LOGP(DMNCC, LOGL_ERROR, "Failed to register new connection fd\n");
		close(conn_bfd->fd);
		conn_bfd->fd = -1;
		return -1;
	}

	LOGP(DMNCC, LOGL_NOTICE, "MNCC Socket has connection with external "
		"call control application\n");

	queue_hello(state);
	return 0;
}


int mncc_sock_init(struct gsm_network *net, const char *sock_path)
{
	struct mncc_sock_state *state;
	struct osmo_fd *bfd;
	int rc;

	state = talloc_zero(net, struct mncc_sock_state);
	if (!state)
		return -ENOMEM;

	state->net = net;
	state->conn_bfd.fd = -1;

	bfd = &state->listen_bfd;

	bfd->fd = osmo_sock_unix_init(SOCK_SEQPACKET, 0, sock_path,
		OSMO_SOCK_F_BIND);
	if (bfd->fd < 0) {
		LOGP(DMNCC, LOGL_ERROR, "Could not create unix socket: %s: %s\n",
		     sock_path, strerror(errno));
		talloc_free(state);
		return -1;
	}

	osmo_fd_setup(bfd, bfd->fd, OSMO_FD_READ, mncc_sock_accept, state, 0);
	rc = osmo_fd_register(bfd);
	if (rc < 0) {
		LOGP(DMNCC, LOGL_ERROR, "Could not register listen fd: %d\n", rc);
		close(bfd->fd);
		talloc_free(state);
		return rc;
	}

	net->mncc_state = state;

	LOGP(DMNCC, LOGL_NOTICE, "MNCC socket at %s\n", sock_path);
	return 0;
}
