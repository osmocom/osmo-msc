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

#include <osmocom/core/linuxlist.h>
#include <osmocom/netif/stream.h>

void osmo_stream_srv_link_set_data(struct osmo_stream_srv_link *link, void *data) {}
struct osmo_fd *osmo_stream_srv_get_ofd(struct osmo_stream_srv *srv) { return NULL; }
void osmo_stream_srv_destroy(struct osmo_stream_srv *conn) {}
struct osmo_stream_srv *osmo_stream_srv_create(void *ctx, struct osmo_stream_srv_link *link,
					       int fd, int (*cb)(struct osmo_stream_srv *conn),
					       int (*closed_cb)(struct osmo_stream_srv *conn),
					       void *data) { return NULL; }
void osmo_stream_srv_send(struct osmo_stream_srv *conn, struct msgb *msg) {}
void osmo_stream_srv_link_set_proto(struct osmo_stream_srv_link *link, uint16_t proto) {}
struct osmo_fd *osmo_stream_srv_link_get_ofd(struct osmo_stream_srv_link *link) { return NULL; }
struct osmo_stream_srv_link *osmo_stream_srv_link_create(void *ctx) { return NULL; }
void *osmo_stream_srv_get_data(struct osmo_stream_srv *conn) { return NULL; }
void osmo_stream_srv_link_set_nodelay(struct osmo_stream_srv_link *link, bool nodelay) {}
void osmo_stream_srv_link_set_accept_cb(struct osmo_stream_srv_link *link, int (*accept_cb)
					(struct osmo_stream_srv_link *link, int fd)) {}
int osmo_stream_srv_link_open(struct osmo_stream_srv_link *link) { return 0; }
void osmo_stream_srv_link_close(struct osmo_stream_srv_link *link) {}
void *osmo_stream_srv_link_get_data(struct osmo_stream_srv_link *link) { return NULL; }
char *osmo_stream_srv_link_get_sockname(const struct osmo_stream_srv_link *link) { return NULL; }
void osmo_stream_srv_link_set_port(struct osmo_stream_srv_link *link, uint16_t port) {}
void osmo_stream_srv_link_set_addr(struct osmo_stream_srv_link *link, const char *addr) {}
int sctp_recvmsg(int sd, void *msg, size_t len, void *from, void *fromlen, void *info, int *msg_flags) { return 0; }
struct gsm_sms;
struct msc_a;
struct gsm_trans;
struct smpp_esme;
bool smpp_route_smpp_first() { return false; }
void smpp_esme_put(struct smpp_esme *esme) { return; }
int smpp_try_deliver(struct gsm_sms *sms, struct msc_a *msc_a) { return 0; }
int sms_route_mt_sms(struct gsm_trans *trans, struct gsm_sms *gsms) { return 0; }
