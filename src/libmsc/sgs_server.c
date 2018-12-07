/* (C) 2018-2019 by sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Harald Welte, Philipp Maier
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

#include <errno.h>

#include <osmocom/msc/sgs_iface.h>
#include <osmocom/msc/debug.h>
#include <osmocom/msc/sgs_server.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/select.h>
#include <osmocom/netif/stream.h>
#include <netinet/sctp.h>

#define LOGSGC(sgc, lvl, fmt, args...) \
	LOGP(DSGS, lvl, "%s: " fmt, (sgc)->sockname, ## args)

/* call-back when data arrives on SGs */
static int sgs_conn_readable_cb(struct osmo_stream_srv *conn)
{
	struct osmo_fd *ofd = osmo_stream_srv_get_ofd(conn);
	struct sgs_connection *sgc = osmo_stream_srv_get_data(conn);
	struct msgb *msg = gsm29118_msgb_alloc();
	struct sctp_sndrcvinfo sinfo;
	int flags = 0;
	int rc;

	/* we cannot use osmo_stream_srv_recv() here, as we might get some out-of-band info from
	 * SCTP. FIXME: add something like osmo_stream_srv_recv_sctp() to libosmo-netif and use
	 * it here as well as in libosmo-sigtran */
	rc = sctp_recvmsg(ofd->fd, msgb_data(msg), msgb_tailroom(msg), NULL, NULL, &sinfo, &flags);
	if (rc < 0) {
		osmo_stream_srv_destroy(conn);
		rc = -EBADF;
		goto out;
	} else if (rc == 0) {
		osmo_stream_srv_destroy(conn);
		rc = -EBADF;
		goto out;
	} else {
		msgb_put(msg, rc);
	}

	if (flags & MSG_NOTIFICATION) {
		union sctp_notification *notif = (union sctp_notification *)msgb_data(msg);

		switch (notif->sn_header.sn_type) {
		case SCTP_SHUTDOWN_EVENT:
			osmo_stream_srv_destroy(conn);
			rc = -EBADF;
			break;
		case SCTP_ASSOC_CHANGE:
			/* FIXME: do we have to notify the SGs code about this? */
			break;
		default:
			break;
		}
		rc = 0;
		goto out;
	}

	/* set l2 header, as that's what we use in SGs code */
	msg->l2h = msgb_data(msg);

	if (msgb_sctp_ppid(msg) != 0) {
		LOGSGC(sgc, LOGL_NOTICE, "Ignoring SCTP PPID %ld (spec violation)\n", msgb_sctp_ppid(msg));
		msgb_free(msg);
		return 0;
	}

	/* handle message */
	sgs_iface_rx(sgc, msg);

	return 0;
out:
	msgb_free(msg);
	return rc;
}

/* call-back when new connection is closed ed on SGs */
static int sgs_conn_closed_cb(struct osmo_stream_srv *conn)
{
	struct sgs_connection *sgc = osmo_stream_srv_get_data(conn);

	LOGSGC(sgc, LOGL_NOTICE, "Connection lost\n");
	if (sgc->mme) {
		/* unlink ourselves from the MME context */
		if (sgc->mme->conn == sgc)
			sgc->mme->conn = NULL;
	}
	llist_del(&sgc->entry);
	return 0;
}

/* call-back when new connection is accept() ed on SGs */
static int sgs_accept_cb(struct osmo_stream_srv_link *link, int fd)
{
	struct sgs_state *sgs = osmo_stream_srv_link_get_data(link);
	struct sgs_connection *sgc = talloc_zero(link, struct sgs_connection);
	OSMO_ASSERT(sgc);
	sgc->sgs = sgs;
	osmo_sock_get_name_buf(sgc->sockname, sizeof(sgc->sockname), fd);
	sgc->srv = osmo_stream_srv_create(sgc, link, fd, sgs_conn_readable_cb, sgs_conn_closed_cb, sgc);
	if (!sgc->srv) {
		talloc_free(sgc);
		return -1;
	}
	LOGSGC(sgc, LOGL_INFO, "Accepted new SGs connection\n");
	llist_add_tail(&sgc->entry, &sgs->conn_list);

	return 0;
}

static struct sgs_state *sgs_state_alloc(void *ctx)
{
	struct sgs_state *sgs = talloc_zero(ctx, struct sgs_state);

	INIT_LLIST_HEAD(&sgs->mme_list);
	INIT_LLIST_HEAD(&sgs->conn_list);

	memcpy(sgs->cfg.timer, sgs_state_timer_defaults, sizeof(sgs->cfg.timer));
	memcpy(sgs->cfg.counter, sgs_state_counter_defaults, sizeof(sgs->cfg.counter));
	sgs->cfg.local_port = SGS_PORT_DEFAULT;
	osmo_strlcpy(sgs->cfg.local_addr, DEFAULT_SGS_SERVER_IP, sizeof(sgs->cfg.local_addr));
	osmo_strlcpy(sgs->cfg.vlr_name, DEFAULT_SGS_SERVER_VLR_NAME, sizeof(sgs->cfg.vlr_name));

	return sgs;
}

/*! allocate SGs new sgs state
 *  \param[in] ctx talloc context
 *  \returns returns allocated sgs state, NULL in case of error. */
struct sgs_state *sgs_server_alloc(void *ctx)
{
	struct sgs_state *sgs;
	struct osmo_stream_srv_link *link;

	sgs = sgs_state_alloc(ctx);
	if (!sgs)
		return NULL;

	sgs->srv_link = link = osmo_stream_srv_link_create(ctx);
	if (!sgs->srv_link)
		return NULL;

	osmo_stream_srv_link_set_nodelay(link, true);
	osmo_stream_srv_link_set_addr(link, sgs->cfg.local_addr);
	osmo_stream_srv_link_set_port(link, sgs->cfg.local_port);
	osmo_stream_srv_link_set_proto(link, IPPROTO_SCTP);
	osmo_stream_srv_link_set_data(link, sgs);
	osmo_stream_srv_link_set_accept_cb(link, sgs_accept_cb);

	return sgs;
}

/*! (re)open SGs interface (SCTP)
 *  \param[in] sgs associated sgs state
 *  \returns 0 in case of success, -EINVAL in case of error. */
int sgs_server_open(struct sgs_state *sgs)
{
	int rc;
	struct osmo_fd *ofd = osmo_stream_srv_link_get_ofd(sgs->srv_link);

	rc = osmo_stream_srv_link_open(sgs->srv_link);
	if (rc < 0) {
		LOGP(DSGS, LOGL_ERROR, "SGs socket cannot be opened: %s\n", strerror(errno));
		return -EINVAL;
	}

	LOGP(DSGS, LOGL_NOTICE, "SGs socket bound to %s\n", osmo_sock_get_name2(ofd->fd));
	return 0;
}
