/* GTP Hub Implementation */

/* (C) 2015 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr
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
 */

#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <time.h>
#include <limits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <gtp.h>
#include <gtpie.h>

#include <openbsc/gtphub.h>
#include <openbsc/debug.h>
#include <openbsc/gprs_utils.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/socket.h>


#define GTPHUB_DEBUG 1

static const int GTPH_GC_TICK_SECONDS = 1;

void *osmo_gtphub_ctx;

#define LOGERR(fmt, args...) \
	LOGP(DGTPHUB, LOGL_ERROR, fmt, ##args)

#define LOG(fmt, args...) \
	LOGP(DGTPHUB, LOGL_NOTICE, fmt, ##args)

#define ZERO_STRUCT(struct_pointer) memset(struct_pointer, '\0', sizeof(*(struct_pointer)))

/* TODO move this to osmocom/core/select.h ? */
typedef int (*osmo_fd_cb_t)(struct osmo_fd *fd, unsigned int what);

/* TODO move this to osmocom/core/linuxlist.h ? */
#define __llist_first(head) (((head)->next == (head)) ? NULL : (head)->next)
#define llist_first(head, type, entry) llist_entry(__llist_first(head), type, entry)

/* TODO move GTP header stuff to openggsn/gtp/ ? See gtp_decaps*() */

enum gtp_rc {
	GTP_RC_UNKNOWN = 0,
	GTP_RC_TINY = 1,    /* no IEs (like ping/pong) */
	GTP_RC_PDU_C = 2,     /* a real packet with IEs */
	GTP_RC_PDU_U = 3,     /* a real packet with User data */

	GTP_RC_TOOSHORT = -1,
	GTP_RC_UNSUPPORTED_VERSION = -2,
	GTP_RC_INVALID_IE = -3,
};

struct gtp_packet_desc {
	union gtp_packet *data;
	int data_len;
	int header_len;
	int version;
	uint8_t type;
	uint16_t seq;
	uint32_t header_tei;
	int rc; /* enum gtp_rc */
	unsigned int plane_idx;
	union gtpie_member *ie[GTPIE_SIZE];
};

void gsn_addr_copy(struct gsn_addr *gsna, const struct gsn_addr *src)
{
	memcpy(gsna, src, sizeof(struct gsn_addr));
}

int gsn_addr_from_sockaddr(struct gsn_addr *gsna, uint16_t *port,
			   const struct osmo_sockaddr *sa)
{
	char addr_str[256];
	char port_str[6];

	if (osmo_sockaddr_to_strs(addr_str, sizeof(addr_str),
				  port_str, sizeof(port_str),
				  sa, (NI_NUMERICHOST | NI_NUMERICSERV))
	    != 0) {
		return -1;
	}

	if (port)
		*port = atoi(port_str);

	return gsn_addr_from_str(gsna, addr_str);
}

int gsn_addr_from_str(struct gsn_addr *gsna, const char *numeric_addr_str)
{
	int af = AF_INET;
	gsna->len = 4;
	const char *pos = numeric_addr_str;
	for (; *pos; pos++) {
		if (*pos == ':') {
			af = AF_INET6;
			gsna->len = 16;
			break;
		}
	}

	int rc = inet_pton(af, numeric_addr_str, gsna->buf);
	if (rc != 1) {
		LOGERR("Cannot resolve numeric address: '%s'\n", numeric_addr_str);
		return -1;
	}
	return 0;
}

const char *gsn_addr_to_str(const struct gsn_addr *gsna)
{
	static char buf[INET6_ADDRSTRLEN + 1];
	return gsn_addr_to_strb(gsna, buf, sizeof(buf));
}

const char *gsn_addr_to_strb(const struct gsn_addr *gsna,
			     char *strbuf,
			     int strbuf_len)
{
	int af;
	switch (gsna->len) {
	case 4:
		af = AF_INET;
		break;
	case 16:
		af = AF_INET6;
		break;
	default:
		return NULL;
	}

	const char *r = inet_ntop(af, gsna->buf, strbuf, strbuf_len);
	if (!r) {
		LOGERR("Cannot convert gsn_addr to string: %s: len=%d, buf=%s\n",
		       strerror(errno),
		       (int)gsna->len,
		       osmo_hexdump(gsna->buf, sizeof(gsna->buf)));
	}
	return r;
}

int gsn_addr_same(const struct gsn_addr *a, const struct gsn_addr *b)
{
	if (a == b)
		return 1;
	if ((!a) || (!b))
		return 0;
	if (a->len != b->len)
		return 0;
	return (memcmp(a->buf, b->buf, a->len) == 0)? 1 : 0;
}

static int gsn_addr_get(struct gsn_addr *gsna, const struct gtp_packet_desc *p, int idx)
{
	if (p->rc != GTP_RC_PDU_C)
		return -1;

	unsigned int len;
	/* gtpie.h fails to declare gtpie_gettlv()'s first arg as const. */
	if (gtpie_gettlv((union gtpie_member**)p->ie, GTPIE_GSN_ADDR, idx,
			 &len, gsna->buf, sizeof(gsna->buf))
	    != 0)
		return -1;
	gsna->len = len;
	return 0;
}

static int gsn_addr_put(const struct gsn_addr *gsna, struct gtp_packet_desc *p, int idx)
{
	if (p->rc != GTP_RC_PDU_C)
		return -1;

	int ie_idx;
	ie_idx = gtpie_getie(p->ie, GTPIE_GSN_ADDR, idx);

	if (ie_idx < 0)
		return -1;

	struct gtpie_tlv *ie = &p->ie[ie_idx]->tlv;
	int ie_l = ntoh16(ie->l);
	if (ie_l != gsna->len) {
		LOG("Not implemented: replace an IE address of different size:"
		    " replace %d with %d\n", (int)ie_l, (int)gsna->len);
		return -1;
	}

	memcpy(ie->v, gsna->buf, (int)ie_l);
	return 0;
}

/* Validate GTP version 0 data; analogous to validate_gtp1_header(), see there.
 */
void validate_gtp0_header(struct gtp_packet_desc *p)
{
	const struct gtp0_header *pheader = &(p->data->gtp0.h);
	p->rc = GTP_RC_UNKNOWN;
	p->header_len = 0;

	OSMO_ASSERT(p->data_len >= 1);
	OSMO_ASSERT(p->version == 0);

	if (p->data_len < GTP0_HEADER_SIZE) {
		LOGERR("GTP0 packet too short: %d\n", p->data_len);
		p->rc = GTP_RC_TOOSHORT;
		return;
	}

	p->type = ntoh8(pheader->type);
	p->seq = ntoh16(pheader->seq);
	p->header_tei = 0; /* TODO */

	if (p->data_len == GTP0_HEADER_SIZE) {
		p->rc = GTP_RC_TINY;
		p->header_len = GTP0_HEADER_SIZE;
		return;
	}

	/* Check packet length field versus length of packet */
	if (p->data_len != (ntoh16(pheader->length) + GTP0_HEADER_SIZE)) {
		LOGERR("GTP packet length field (%d + %d) does not match"
		       " actual length (%d)\n",
		       GTP0_HEADER_SIZE, (int)ntoh16(pheader->length),
		       p->data_len);
		p->rc = GTP_RC_TOOSHORT;
		return;
	}

	LOG("GTP v0 TID = %" PRIu64 "\n", pheader->tid);
	p->header_len = GTP0_HEADER_SIZE;
	p->rc = GTP_RC_PDU_C;
}

/* Validate GTP version 1 data, and update p->rc with the result, as well as
 * p->header_len in case of a valid header. */
void validate_gtp1_header(struct gtp_packet_desc *p)
{
	const struct gtp1_header_long *pheader = &(p->data->gtp1l.h);
	p->rc = GTP_RC_UNKNOWN;
	p->header_len = 0;

	OSMO_ASSERT(p->data_len >= 1);
	OSMO_ASSERT(p->version == 1);

	if ((p->data_len < GTP1_HEADER_SIZE_LONG)
	    && (p->data_len != GTP1_HEADER_SIZE_SHORT)){
		LOGERR("GTP packet too short: %d\n", p->data_len);
		p->rc = GTP_RC_TOOSHORT;
		return;
	}

	p->type = ntoh8(pheader->type);
	p->header_tei = ntoh32(pheader->tei);
	p->seq = ntoh16(pheader->seq);

	LOG("|GTPv1\n");
	LOG("| type = %" PRIu8 " 0x%02" PRIx8 "\n",
	    p->type, p->type);
	LOG("| length = %" PRIu16 " 0x%04" PRIx16 "\n",
	    ntoh16(pheader->length), ntoh16(pheader->length));
	LOG("| TEI = %" PRIu32 " 0x%08" PRIx32 "\n",
	    p->header_tei, p->header_tei);
	LOG("| seq = %" PRIu16 " 0x%04" PRIx16 "\n",
	    p->seq, p->seq);
	LOG("| npdu = %" PRIu8 " 0x%02" PRIx8 "\n",
	    pheader->npdu, pheader->npdu);
	LOG("| next = %" PRIu8 " 0x%02" PRIx8 "\n",
	    pheader->next, pheader->next);

	if (p->data_len <= GTP1_HEADER_SIZE_LONG) {
		p->rc = GTP_RC_TINY;
		p->header_len = GTP1_HEADER_SIZE_SHORT;
		return;
	}

	/* Check packet length field versus length of packet */
	if (p->data_len != (ntoh16(pheader->length) + GTP1_HEADER_SIZE_SHORT)) {
		LOGERR("GTP packet length field (%d + %d) does not match"
		       " actual length (%d)\n",
		       GTP1_HEADER_SIZE_SHORT, (int)ntoh16(pheader->length),
		       p->data_len);
		p->rc = GTP_RC_TOOSHORT;
		return;
	}

	p->rc = GTP_RC_PDU_C;
	p->header_len = GTP1_HEADER_SIZE_LONG;
}

/* Examine whether p->data of size p->data_len has a valid GTP header. Set
 * p->version, p->rc and p->header_len. On error, p->rc <= 0 (see enum
 * gtp_rc). p->data must point at a buffer with p->data_len set. */
void validate_gtp_header(struct gtp_packet_desc *p)
{
	p->rc = GTP_RC_UNKNOWN;

	/* Need at least 1 byte in order to check version */
	if (p->data_len < 1) {
		LOGERR("Discarding packet - too small: %d\n", p->data_len);
		p->rc = GTP_RC_TOOSHORT;
		return;
	}

	p->version = p->data->flags >> 5;

	switch (p->version) {
	case 0:
		validate_gtp0_header(p);
		break;
	case 1:
		validate_gtp1_header(p);
		break;
	default:
		LOGERR("Unsupported GTP version: %d\n", p->version);
		p->rc = GTP_RC_UNSUPPORTED_VERSION;
		break;
	}
}


/* Return the value of the i'th IMSI IEI by copying to *imsi.
 * The first IEI is reached by passing i = 0.
 * imsi must point at allocated space of (at least) 8 bytes.
 * Return 1 on success, or 0 if not found. */
static int get_ie_imsi(union gtpie_member *ie[], int i, uint8_t *imsi)
{
	return gtpie_gettv0(ie, GTPIE_IMSI, i, imsi, 8) == 0;
}

/* Analogous to get_ie_imsi(). nsapi must point at a single uint8_t. */
static int get_ie_nsapi(union gtpie_member *ie[], int i, uint8_t *nsapi)
{
	return gtpie_gettv1(ie, GTPIE_NSAPI, i, nsapi) == 0;
}

static char imsi_digit_to_char(uint8_t nibble)
{
	nibble &= 0x0f;
	if (nibble > 9)
		return (nibble == 0x0f) ? '\0' : '?';
	return '0' + nibble;
}

/* Return a human readable IMSI string, in a static buffer.
 * imsi must point at 8 octets of IMSI IE encoded IMSI data. */
static int imsi_to_str(uint8_t *imsi, const char **imsi_str)
{
	static char str[17];
	int i;
	char c;

	for (i = 0; i < 8; i++) {
		c = imsi_digit_to_char(imsi[i]);
		if (c == '?')
			return -1;
		str[2*i] = c;

		c = imsi_digit_to_char(imsi[i] >> 4);
		if (c == '?')
			return -1;
		str[2*i + 1] = c;
	}
	str[16] = '\0';
	*imsi_str = str;
	return 1;
}

/* Return 0 if not present, 1 if present and decoded successfully, -1 if
 * present but cannot be decoded. */
static int get_ie_imsi_str(union gtpie_member *ie[], int i, const char **imsi_str)
{
	uint8_t imsi_buf[8];
	if (!get_ie_imsi(ie, i, imsi_buf))
		return 0;
	return imsi_to_str(imsi_buf, imsi_str);
}

/* Return 0 if not present, 1 if present and decoded successfully, -1 if
 * present but cannot be decoded. */
static int get_ie_apn_str(union gtpie_member *ie[], const char **apn_str)
{
	static char apn_buf[GSM_APN_LENGTH];
	unsigned int len;
	if (gtpie_gettlv(ie, GTPIE_APN, 0,
			 &len, apn_buf, sizeof(apn_buf)) != 0)
		return 0;

	if (len < 2) {
		LOGERR("APN IE: invalid length: %d\n",
		       (int)len);
		return -1;
	}

	if (len > (sizeof(apn_buf) - 1))
		len = sizeof(apn_buf) - 1;
	apn_buf[len] = '\0';

	*apn_str = gprs_apn_to_str(apn_buf, (uint8_t*)apn_buf, len);
	if (!(*apn_str)) {
		LOGERR("APN IE: present but cannot be decoded: %s\n",
		       osmo_hexdump((uint8_t*)apn_buf, len));
		return -1;
	}
	return 1;
}


/* Validate header, and index information elements. Write decoded packet
 * information to *res. res->data will point at the given data buffer. On
 * error, p->rc is set <= 0 (see enum gtp_rc). */
static void gtp_decode(const uint8_t *data, int data_len,
		       unsigned int from_plane_idx,
		       struct gtp_packet_desc *res)
{
	ZERO_STRUCT(res);
	res->data = (union gtp_packet*)data;
	res->data_len = data_len;
	res->plane_idx = from_plane_idx;

	validate_gtp_header(res);

	if (res->rc <= 0) {
		LOGERR("INVALID: dropping GTP packet.\n");
		return;
	}

	LOG("Valid GTP header (v%d)\n", res->version);

	if (from_plane_idx == GTPH_PLANE_USER) {
		res->rc = GTP_RC_PDU_U;
		return;
	}

	if (res->rc != GTP_RC_PDU_C) {
		LOG("no IEs in this GTP packet\n");
		return;
	}

	if (gtpie_decaps(res->ie, res->version,
			 (void*)(data + res->header_len),
			 res->data_len - res->header_len) != 0) {
		res->rc = GTP_RC_INVALID_IE;
		LOGERR("INVALID: cannot decode IEs. Dropping GTP packet.\n");
		return;
	}

#if GTPHUB_DEBUG
	int i;

	for (i = 0; i < 10; i++) {
		const char *imsi;
		if (get_ie_imsi_str(res->ie, i, &imsi) < 1)
			break;
		LOG("| IMSI %s\n", imsi);
	}

	for (i = 0; i < 10; i++) {
		uint8_t nsapi;
		if (!get_ie_nsapi(res->ie, i, &nsapi))
			break;
		LOG("| NSAPI %d\n", (int)nsapi);
	}

	for (i = 0; i < 2; i++) {
		struct gsn_addr addr;
		if (gsn_addr_get(&addr, res, i) == 0)
			LOG("| addr %s\n", gsn_addr_to_str(&addr));
	}

	for (i = 0; i < 10; i++) {
		uint32_t tei;
		if (gtpie_gettv4(res->ie, GTPIE_TEI_DI, i, &tei) != 0)
			break;
		LOG("| TEI DI (USER) %" PRIu32 " 0x%08" PRIx32 "\n",
		    tei, tei);
	}

	for (i = 0; i < 10; i++) {
		uint32_t tei;
		if (gtpie_gettv4(res->ie, GTPIE_TEI_C, i, &tei) != 0)
			break;
		LOG("| TEI (CTRL) %" PRIu32 " 0x%08" PRIx32 "\n",
		    tei, tei);
	}
#endif
}


/* expiry */

void expiry_init(struct expiry *exq, int expiry_in_seconds)
{
	ZERO_STRUCT(exq);
	exq->expiry_in_seconds = expiry_in_seconds;
	INIT_LLIST_HEAD(&exq->items);
}

void expiry_add(struct expiry *exq, struct expiring_item *item, time_t now)
{
	item->expiry = now + exq->expiry_in_seconds;

	/* Add/move to the tail to always sort by expiry, ascending. */
	llist_del(&item->entry);
	llist_add_tail(&item->entry, &exq->items);
}

int expiry_tick(struct expiry *exq, time_t now)
{
	int expired = 0;
	struct expiring_item *m, *n;
	llist_for_each_entry_safe(m, n, &exq->items, entry) {
		if (m->expiry <= now) {
			expiring_item_del(m);
			expired ++;
		} else {
			/* The items are added sorted by expiry. So when we hit
			 * an unexpired entry, only more unexpired ones will
			 * follow. */
			break;
		}
	}
	return expired;
}

void expiring_item_init(struct expiring_item *item)
{
	ZERO_STRUCT(item);
	INIT_LLIST_HEAD(&item->entry);
}

void expiring_item_del(struct expiring_item *item)
{
	OSMO_ASSERT(item);
	llist_del(&item->entry);
	INIT_LLIST_HEAD(&item->entry);
	if (item->del_cb) {
		/* avoid loops */
		del_cb_t del_cb = item->del_cb;
		item->del_cb = 0;
		(del_cb)(item);
	}
}


/* nr_map, nr_pool */

void nr_pool_init(struct nr_pool *pool)
{
	*pool = (struct nr_pool){};
}

nr_t nr_pool_next(struct nr_pool *pool)
{
	pool->last_nr ++;

	OSMO_ASSERT(pool->last_nr > 0);
	/* TODO: gracefully handle running out of TEIs. */
	/* TODO: random TEIs. */

	return pool->last_nr;
}

void nr_map_init(struct nr_map *map, struct nr_pool *pool,
		 struct expiry *exq)
{
	ZERO_STRUCT(map);
	map->pool = pool;
	map->add_items_to_expiry = exq;
	INIT_LLIST_HEAD(&map->mappings);
}

void nr_mapping_init(struct nr_mapping *m)
{
	ZERO_STRUCT(m);
	INIT_LLIST_HEAD(&m->entry);
	expiring_item_init(&m->expiry_entry);
}

void nr_map_add(struct nr_map *map, struct nr_mapping *mapping, time_t now)
{
	/* Generate a mapped number */
	mapping->repl = nr_pool_next(map->pool);

	/* Add to the tail to always yield a list sorted by expiry, in
	 * ascending order. */
	llist_add_tail(&mapping->entry, &map->mappings);
	if (map->add_items_to_expiry)
		expiry_add(map->add_items_to_expiry,
			   &mapping->expiry_entry,
			   now);
}

void nr_map_clear(struct nr_map *map)
{
	struct nr_mapping *m;
	struct nr_mapping *n;
	llist_for_each_entry_safe(m, n, &map->mappings, entry) {
		nr_mapping_del(m);
	}
}

int nr_map_empty(const struct nr_map *map)
{
	return llist_empty(&map->mappings);
}

struct nr_mapping *nr_map_get(const struct nr_map *map,
			      void *origin, nr_t nr_orig)
{
	struct nr_mapping *mapping;
	llist_for_each_entry(mapping, &map->mappings, entry) {
		if ((mapping->origin == origin)
		    && (mapping->orig == nr_orig))
			return mapping;
	}
	/* Not found. */
	return NULL;
}

struct nr_mapping *nr_map_get_inv(const struct nr_map *map, nr_t nr_repl)
{
	struct nr_mapping *mapping;
	llist_for_each_entry(mapping, &map->mappings, entry) {
		if (mapping->repl == nr_repl) {
			return mapping;
		}
	}
	/* Not found. */
	return NULL;
}

void nr_mapping_del(struct nr_mapping *mapping)
{
	OSMO_ASSERT(mapping);
	llist_del(&mapping->entry);
	INIT_LLIST_HEAD(&mapping->entry);
	expiring_item_del(&mapping->expiry_entry);
}


/* gtphub */

const char* const gtphub_plane_idx_names[GTPH_PLANE_N] = {
	"CTRL",
	"USER",
};

const uint16_t gtphub_plane_idx_default_port[GTPH_PLANE_N] = {
	2123,
	2152,
};

time_t gtphub_now(void)
{
	struct timespec now_tp;
	OSMO_ASSERT(clock_gettime(CLOCK_MONOTONIC, &now_tp) >= 0);
	return now_tp.tv_sec;
}

/* Remove a gtphub_peer from its list and free it. */
static void gtphub_peer_del(struct gtphub_peer *peer)
{
	nr_map_clear(&peer->seq_map);
	llist_del(&peer->entry);
	talloc_free(peer);
}

static void gtphub_peer_addr_del(struct gtphub_peer_addr *pa)
{
	OSMO_ASSERT(llist_empty(&pa->ports));
	llist_del(&pa->entry);
	talloc_free(pa);
}

static void gtphub_peer_port_del(struct gtphub_peer_port *pp)
{
	OSMO_ASSERT(pp->ref_count == 0);
	llist_del(&pp->entry);
	talloc_free(pp);
}

/* From the information in the gtp_packet_desc, return the address of a GGSN.
 * Return -1 on error. */
static int gtphub_resolve_ggsn(struct gtphub *hub,
			       struct gtp_packet_desc *p,
			       struct gtphub_peer_port **pp);

/* See gtphub_ext.c (wrapped by unit test) */
struct gtphub_peer_port *gtphub_resolve_ggsn_addr(struct gtphub *hub,
						  const char *imsi_str,
						  const char *apn_ni_str);
int gtphub_ares_init(struct gtphub *hub);

static void gtphub_zero(struct gtphub *hub)
{
	ZERO_STRUCT(hub);
}

static int gtphub_sock_init(struct osmo_fd *ofd,
			    const struct gtphub_cfg_addr *addr,
			    osmo_fd_cb_t cb,
			    void *data,
			    int ofd_id)
{
	if (!addr->addr_str) {
		LOGERR("Cannot bind: empty address.\n");
		return -1;
	}
	if (!addr->port) {
		LOGERR("Cannot bind: zero port not permitted.\n");
		return -1;
	}

	ofd->when = BSC_FD_READ;
	ofd->cb = cb;
	ofd->data = data;
	ofd->priv_nr = ofd_id;

	int rc;
	rc = osmo_sock_init_ofd(ofd,
				AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP,
				addr->addr_str, addr->port,
				OSMO_SOCK_F_BIND);
	if (rc < 1) {
		LOGERR("Cannot bind to %s port %d (rc %d)\n",
		       addr->addr_str, (int)addr->port, rc);
		return -1;
	}

	return 0;
}

static void gtphub_bind_init(struct gtphub_bind *b)
{
	ZERO_STRUCT(b);

	INIT_LLIST_HEAD(&b->peers);
}

static int gtphub_bind_start(struct gtphub_bind *b,
			     const struct gtphub_cfg_bind *cfg,
			     osmo_fd_cb_t cb, void *cb_data,
			     unsigned int ofd_id)
{
	if (gsn_addr_from_str(&b->local_addr, cfg->bind.addr_str) != 0)
		return -1;
	if (gtphub_sock_init(&b->ofd, &cfg->bind, cb, cb_data, ofd_id) != 0)
		return -1;
	return 0;
}

/* Recv datagram from from->fd, optionally write sender's address to *from_addr.
 * Return the number of bytes read, zero on error. */
static int gtphub_read(const struct osmo_fd *from,
		       struct osmo_sockaddr *from_addr,
		       uint8_t *buf, size_t buf_len)
{
	/* recvfrom requires the available length to be set in *from_addr_len. */
	if (from_addr)
		from_addr->l = sizeof(from_addr->a);

	errno = 0;
	ssize_t received = recvfrom(from->fd, buf, buf_len, 0,
				    (struct sockaddr*)&from_addr->a, &from_addr->l);
	/* TODO use recvmsg and get a MSG_TRUNC flag to make sure the message
	 * is not truncated. Then maybe reduce buf's size. */

	if (received <= 0) {
		if (errno != EAGAIN)
			LOGERR("error: %s\n", strerror(errno));
		return 0;
	}

	if (from_addr) {
		LOG("from %s\n", osmo_sockaddr_to_str(from_addr));
	}

	if (received <= 0) {
		LOGERR("error: %s\n", strerror(errno));
		return 0;
	}

	LOG("Received %d\n%s\n", (int)received, osmo_hexdump(buf, received));
	return received;
}

inline void gtphub_port_ref_count_inc(struct gtphub_peer_port *pp)
{
	OSMO_ASSERT(pp->ref_count < UINT_MAX);
	pp->ref_count++;
}

inline void gtphub_port_ref_count_dec(struct gtphub_peer_port *pp)
{
	OSMO_ASSERT(pp->ref_count > 0);
	pp->ref_count--;
}

inline void set_seq(struct gtp_packet_desc *p, uint16_t seq)
{
	OSMO_ASSERT(p->version == 1);
	p->data->gtp1l.h.seq = hton16(seq);
	p->seq = seq;
}

inline void set_tei(struct gtp_packet_desc *p, uint32_t tei)
{
	OSMO_ASSERT(p->version == 1);
	p->data->gtp1l.h.tei = hton32(tei);
	p->header_tei = tei;
}

static void gtphub_mapping_del_cb(struct expiring_item *expi);

static struct nr_mapping *gtphub_mapping_new()
{
	struct nr_mapping *nrm;
	nrm = talloc_zero(osmo_gtphub_ctx, struct nr_mapping);
	OSMO_ASSERT(nrm);

	nr_mapping_init(nrm);
	nrm->expiry_entry.del_cb = gtphub_mapping_del_cb;
	return nrm;
}

static const char *gtphub_peer_strb(struct gtphub_peer *peer, char *buf, int buflen)
{
	if (llist_empty(&peer->addresses))
		return "(addressless)";

	struct gtphub_peer_addr *a = llist_first(&peer->addresses,
						 struct gtphub_peer_addr,
						 entry);
	return gsn_addr_to_strb(&a->addr, buf, buflen);
}

static const char *gtphub_port_strb(struct gtphub_peer_port *port, char *buf, int buflen)
{
	if (!port)
		return "(null port)";

	snprintf(buf, buflen, "%s port %d",
		 gsn_addr_to_str(&port->peer_addr->addr),
		 (int)port->port);
	return buf;
}

const char *gtphub_peer_str(struct gtphub_peer *peer)
{
	static char buf[256];
	return gtphub_peer_strb(peer, buf, sizeof(buf));
}

const char *gtphub_peer_str2(struct gtphub_peer *peer)
{
	static char buf[256];
	return gtphub_peer_strb(peer, buf, sizeof(buf));
}

const char *gtphub_port_str(struct gtphub_peer_port *port)
{
	static char buf[256];
	return gtphub_port_strb(port, buf, sizeof(buf));
}

static const char *gtphub_port_str2(struct gtphub_peer_port *port)
{
	static char buf[256];
	return gtphub_port_strb(port, buf, sizeof(buf));
}

static void gtphub_mapping_del_cb(struct expiring_item *expi)
{
	expi->del_cb = 0; /* avoid recursion loops */

	struct nr_mapping *nrm = container_of(expi,
					      struct nr_mapping,
					      expiry_entry);
	llist_del(&nrm->entry);
	INIT_LLIST_HEAD(&nrm->entry); /* mark unused */

	/* Just for log */
	struct gtphub_peer_port *from = nrm->origin;
	OSMO_ASSERT(from);
	LOG("expired: %d: nr mapping from %s: %d->%d\n",
	    (int)nrm->expiry_entry.expiry,
	    gtphub_port_str(from),
	    (int)nrm->orig, (int)nrm->repl);

	gtphub_port_ref_count_dec(from);

	talloc_free(nrm);
}

static struct nr_mapping *gtphub_mapping_have(struct nr_map *map,
					      struct gtphub_peer_port *from,
					      nr_t orig_nr,
					      time_t now)
{
	struct nr_mapping *nrm;

	nrm = nr_map_get(map, from, orig_nr);

	if (!nrm) {
		nrm = gtphub_mapping_new();
		nrm->orig = orig_nr;
		nrm->origin = from;
		nr_map_add(map, nrm, now);
		gtphub_port_ref_count_inc(from);
		LOG("peer %s: MAP %d --> %d\n",
		    gtphub_port_str(from),
		    (int)(nrm->orig), (int)(nrm->repl));
	} else {
		/* restart expiry timeout */
		expiry_add(map->add_items_to_expiry, &nrm->expiry_entry,
			   now);
	}

	OSMO_ASSERT(nrm);
	return nrm;
}

static uint32_t gtphub_tei_mapping_have(struct gtphub *hub,
					int plane_idx,
					struct gtphub_peer_port *from,
					uint32_t orig_tei,
					time_t now)
{
	struct nr_mapping *nrm = gtphub_mapping_have(&hub->tei_map[plane_idx],
						     from, orig_tei, now);
	LOG("New %s TEI: (from %s, TEI %d) <-- TEI %d\n",
	    gtphub_plane_idx_names[plane_idx],
	    gtphub_port_str(from),
	    (int)orig_tei, (int)nrm->repl);

	return (uint32_t)nrm->repl;
}

static void gtphub_map_seq(struct gtp_packet_desc *p,
			   struct gtphub_peer_port *from_port,
			   struct gtphub_peer_port *to_port,
			   time_t now)
{
	/* Store a mapping in to_peer's map, so when we later receive a GTP
	 * packet back from to_peer, the seq nr can be unmapped back to its
	 * origin (from_peer here). */
	struct nr_mapping *nrm;
	nrm = gtphub_mapping_have(&to_port->peer_addr->peer->seq_map,
				  from_port, p->seq, now);

	/* Change the GTP packet to yield the new, mapped seq nr */
	set_seq(p, nrm->repl);
}

static struct gtphub_peer_port *gtphub_unmap_seq(struct gtp_packet_desc *p,
						 struct gtphub_peer_port *responding_port)
{
	OSMO_ASSERT(p->version == 1);
	struct nr_mapping *nrm = nr_map_get_inv(&responding_port->peer_addr->peer->seq_map,
						p->seq);
	if (!nrm)
		return NULL;
	LOG("peer %p: UNMAP %d <-- %d\n", nrm->origin, (int)(nrm->orig), (int)(nrm->repl));
	set_seq(p, nrm->orig);
	return nrm->origin;
}

static void gtphub_check_restart_counter(struct gtphub *hub,
					 struct gtp_packet_desc *p,
					 struct gtphub_peer_port *from)
{
	/* TODO */
	/* If the peer is sending a Recovery IE (7.7.11) with a restart counter
	 * that doesn't match the peer's previously sent restart counter, clear
	 * that peer and cancel PDP contexts. */
}

static void gtphub_map_restart_counter(struct gtphub *hub,
				       struct gtp_packet_desc *p,
				       struct gtphub_peer_port *from,
				       struct gtphub_peer_port *to)
{
	/* TODO */
}

/* gtphub_map_ie_teis() and gtphub_unmap_header_tei():
 *
 * TEI mapping must happen symmetrically. An SGSN contacts gtphub instead of N
 * GGSNs, and a GGSN replies to gtphub for N SGSNs. From either end, TEIs may
 * collide: two GGSNs picking the same TEIs, or two SGSNs picking the same
 * TEIs. Since the opposite side sees the sender address being gtphub's
 * address, TEIs among the SGSNs, and among the GGSNs, must not overlap. If a
 * peer sends a TEI already sent before from a peer of the same side, gtphub
 * replaces it with a TEI not yet seen from that side and remembers the
 * mapping.
 *
 * Consider two SGSNs A and B contacting two GGSNs C and D thru gtphub.
 *
 * A: Create PDP Ctx, I have TEI 1.
 *    --->   gtphub: A has TEI 1, sending 1 for C.
 *              --->   C: gtphub has TEI 1.
 *      	<---   C: Response to TEI 1: I have TEI 11.
 *    <---   gtphub: ok, telling A: 11.
 * A: gtphub's first TEI is 11.                                         (1)
 *
 * B: Create PDP Ctx, I have TEIs 1.
 *    --->   gtphub: 1 already taken for C, sending 2 for B. (map)
 *              --->   C: gtphub also has 2.
 *      	<---   C: Response to TEI 2: I have TEI 12.
 *    <---   gtphub: ok, TEI 2 is actually B with TEI 1. (unmap)
 * B: gtphub's first TEI is 12, as far as I can tell.
 *
 * Now the second GGSN comes into play:
 *
 * A: Create PDP Ctx, I have TEI 2.
 *    --->   gtphub: A also has TEI 2, but for D, sending 1.            (2)
 *              --->   D: gtphub has 1.
 *      	<---   D: Response to TEI 1: I have TEI 11.
 *    <---   gtphub: from D, 1 is A. 11 already taken by C, sending 13. (3)
 * A: gtphub also has TEI 13.                                           (4)
 *
 * And some messages routed through:
 *
 * A: message to TEI 11, see (1).
 *    --->   gtphub: ok, telling C with TEI 11.
 *              --->   C: I see, 11 means reply with 1.
 *      	<---   C: Response to TEI 1
 *    <---   gtphub: 1 from C is actually for A with TEI 1.
 * A: ah, my TEI 1, thanks!
 *
 * A: message to TEI 13, see (4).
 *    --->   gtphub: ok, but not 13, D wanted TEI 11 instead, see (3).
 *              --->   D: I see, 11 means reply with 1.
 *      	<---   D: Response to TEI 1
 *    <---   gtphub: 1 from D is actually for A with TEI 2, see (2).
 * A: ah, my TEI 2, thanks!
 *
 * What if a GGSN initiates a request:
 *
 *              <---   D: Request to gtphub TEI 1
 *    <---   gtphub: 1 from D is for A with 2, see (2).
 * A: my TEI 2 means reply with 13.
 *    --->   gtphub: 13 was D with 11, see (3).
 *              --->   D: 11 from gtphub: a reply to my request for TEI 1.
 *
 * Note that usually, it's the sequence numbers that route a response back to
 * the requesting peer. Nevertheless, the TEI mappings must be carried out to
 * replace the TEIs in the GTP packet that is relayed.
 *
 * Also note: the TEI in the GTP header is "reversed" from the TEI in the IEs:
 * the TEI in the header is used to send something *to* a peer, while the TEI
 * in e.g. a Create PDP Context Request's IE is for routing messages *back*
 * later. */

static int gtphub_unmap_header_tei(struct gtphub_peer_port **to_port_p,
				   struct gtphub *hub,
				   struct gtp_packet_desc *p,
				   struct gtphub_peer_port *from_port)
{
	OSMO_ASSERT(p->version == 1);
	*to_port_p = NULL;

	/* If the header's TEI is zero, no PDP context has been established
	 * yet. If nonzero, a mapping should actually already exist for this
	 * TEI, since it must have been announced in a PDP context creation. */
	uint32_t tei = p->header_tei;
	if (!tei)
		return 0;

	/* to_peer has previously announced a TEI, which was stored and
	 * mapped in from_peer's tei_map. */
	struct nr_mapping *nrm;
	nrm = nr_map_get_inv(&hub->tei_map[p->plane_idx], tei);
	if (!nrm) {
		LOGERR("Received unknown TEI %" PRIu32 " from %s\n",
		       tei, gtphub_port_str(from_port));
		return -1;
	}

	struct gtphub_peer_port *to_port = nrm->origin;
	uint32_t unmapped_tei = nrm->orig;
	set_tei(p, unmapped_tei);

	LOG("Unmapped TEI coming from %s: %d -> %d (to %s)\n",
	    gtphub_port_str(from_port), tei, unmapped_tei,
	    gtphub_port_str2(to_port));

	*to_port_p = to_port;
	return 0;
}

/* Read GSN address IEs from p, and make sure these peer addresses exist in
 * bind[plane_idx] with default ports, in their respective planes (both Ctrl
 * and User). Map TEIs announced in IEs, and write mapped TEIs in-place into
 * the packet p. */
static int gtphub_handle_pdp_ctx_ies(struct gtphub *hub,
				     struct gtphub_bind from_bind[],
				     struct gtphub_bind to_bind[],
				     struct gtp_packet_desc *p,
				     time_t now)
{
	OSMO_ASSERT(p->plane_idx == GTPH_PLANE_CTRL);

	int rc;
	int plane_idx;

	switch (p->type) {
	case GTP_CREATE_PDP_REQ:
	case GTP_CREATE_PDP_RSP:
		/* Go for it below */
		break;
	default:
		/* Nothing to do for this message type. */
		return 0;
	}

	/* TODO enforce a Request only from SGSN, a Response only from GGSN? */

	osmo_static_assert((GTPH_PLANE_CTRL == 0) && (GTPH_PLANE_USER == 1),
			   plane_nrs_match_GSN_addr_IE_indices);

	uint8_t ie_type[] = { GTPIE_TEI_C, GTPIE_TEI_DI };
	int ie_mandatory = (p->type == GTP_CREATE_PDP_REQ);

	for (plane_idx = 0; plane_idx < 2; plane_idx++) {
		struct gsn_addr addr_from_ie;
		uint32_t tei_from_ie;
		int ie_idx;

		/* Fetch GSN Address and TEI from IEs */
		rc = gsn_addr_get(&addr_from_ie, p, plane_idx);
		if (rc) {
			LOGERR("Cannot read %s GSN Address IE\n",
			       gtphub_plane_idx_names[plane_idx]);
			return -1;
		}
		LOG("Read %s GSN addr %s (%d)\n",
		    gtphub_plane_idx_names[plane_idx],
		    gsn_addr_to_str(&addr_from_ie),
		    addr_from_ie.len);

		ie_idx = gtpie_getie(p->ie, ie_type[plane_idx], 0);
		if (ie_idx < 0) {
			if (ie_mandatory) {
				LOGERR("Create PDP Context message invalid:"
				       " missing IE %d\n", (int)ie_type[plane_idx]);
				return -1;
			}
			tei_from_ie = 0;
		}
		else
			tei_from_ie = ntoh32(p->ie[ie_idx]->tv4.v);

		/* Make sure an entry for this peer address with default port
		 * exists */
		struct gtphub_peer_port *peer_from_ie =
			gtphub_port_have(hub, &from_bind[plane_idx],
					 &addr_from_ie,
					 gtphub_plane_idx_default_port[plane_idx]);

		if (tei_from_ie) {
			/* Create TEI mapping and replace in GTP packet IE */
			uint32_t mapped_tei =
				gtphub_tei_mapping_have(hub, plane_idx,
							peer_from_ie,
							tei_from_ie,
							now);
			p->ie[ie_idx]->tv4.v = hton32(mapped_tei);
		}

		/* Replace the GSN address to reflect gtphub. */
		rc = gsn_addr_put(&to_bind[plane_idx].local_addr, p, plane_idx);
		if (rc) {
			LOGERR("Cannot write %s GSN Address IE\n",
			       gtphub_plane_idx_names[plane_idx]);
			return -1;
		}
	}

	return 0;
}

static int gtphub_write(const struct osmo_fd *to,
			const struct osmo_sockaddr *to_addr,
			const uint8_t *buf, size_t buf_len)
{
	errno = 0;
	ssize_t sent = sendto(to->fd, buf, buf_len, 0,
			      (struct sockaddr*)&to_addr->a, to_addr->l);

	if (to_addr) {
		LOG("to %s\n", osmo_sockaddr_to_str(to_addr));
	}

	if (sent == -1) {
		LOGERR("error: %s\n", strerror(errno));
		return -EINVAL;
	}

	if (sent != buf_len)
		LOGERR("sent(%d) != data_len(%d)\n", (int)sent, (int)buf_len);
	else
		LOG("Sent %d\n%s\n", (int)sent, osmo_hexdump(buf, sent));

	return 0;
}

static int from_ggsns_read_cb(struct osmo_fd *from_ggsns_ofd, unsigned int what)
{
	unsigned int plane_idx = from_ggsns_ofd->priv_nr;
	OSMO_ASSERT(plane_idx < GTPH_PLANE_N);
	LOG("\n\n=== reading from GGSN (%s)\n", gtphub_plane_idx_names[plane_idx]);
	if (!(what & BSC_FD_READ))
		return 0;

	struct gtphub *hub = from_ggsns_ofd->data;

	static uint8_t buf[4096];
	struct osmo_sockaddr from_addr;
	struct osmo_sockaddr to_addr;
	struct osmo_fd *to_ofd;
	size_t len;
	uint8_t *reply_buf;

	len = gtphub_read(from_ggsns_ofd, &from_addr, buf, sizeof(buf));
	if (len < 1)
		return 0;

	len = gtphub_from_ggsns_handle_buf(hub, plane_idx, &from_addr, buf, len,
					   gtphub_now(),
					   &reply_buf, &to_ofd, &to_addr);
	if (len < 1)
		return 0;

	return gtphub_write(to_ofd, &to_addr, reply_buf, len);
}

static int gtphub_unmap(struct gtphub *hub,
			struct gtp_packet_desc *p,
			struct gtphub_peer_port *from,
			struct gtphub_peer_port *to_proxy,
			struct gtphub_peer_port **final_unmapped,
			struct gtphub_peer_port **unmapped_from_seq,
			struct gtphub_peer_port **unmapped_from_tei)
{
	/* Always (try to) unmap sequence and TEI numbers, which need to be
	 * replaced in the packet. Either way, give precedence to the proxy, if
	 * configured. */

	struct gtphub_peer_port *from_seq = NULL;
	struct gtphub_peer_port *from_tei = NULL;
	struct gtphub_peer_port *unmapped = NULL;

	if (unmapped_from_seq)
		*unmapped_from_seq = from_seq;
	if (unmapped_from_tei)
		*unmapped_from_tei = from_tei;
	if (final_unmapped)
		*final_unmapped = unmapped;

	from_seq = gtphub_unmap_seq(p, from);

	if (gtphub_unmap_header_tei(&from_tei, hub, p, from) < 0)
		return -1;

	struct gtphub_peer *from_peer = from->peer_addr->peer;
	if (from_seq && from_tei && (from_seq != from_tei)) {
		LOGERR("Seq unmap and TEI unmap yield two different peers. Using seq unmap."
		       "(from %s %s: seq %d yields %s, tei %u yields %s)\n",
		       gtphub_plane_idx_names[p->plane_idx],
		       gtphub_peer_str(from_peer),
		       (int)p->seq,
		       gtphub_port_str(from_seq),
		       (int)p->header_tei,
		       gtphub_port_str2(from_tei)
		       );
	}
	unmapped = (from_seq? from_seq : from_tei);

	if (unmapped && to_proxy && (unmapped != to_proxy)) {
		LOGERR("Unmap yields a different peer than the configured proxy. Using proxy."
		       " unmapped: %s  proxy: %s\n",
		       gtphub_port_str(unmapped),
		       gtphub_port_str2(to_proxy)
		       );
	}
	unmapped = (to_proxy? to_proxy : unmapped);

	if (!unmapped) {
		/* Return no error, but returned pointers are all NULL. */
		return 0;
	}

	LOG("from seq %p; from tei %p; unmapped => %p\n",
	    from_seq, from_tei, unmapped);

	if (unmapped_from_seq)
		*unmapped_from_seq = from_seq;
	if (unmapped_from_tei)
		*unmapped_from_tei = from_tei;
	if (final_unmapped)
		*final_unmapped = unmapped;
	return 0;
}

static int gsn_addr_to_sockaddr(struct gsn_addr *src,
				uint16_t port,
				struct osmo_sockaddr *dst)
{
	return osmo_sockaddr_init_udp(dst, gsn_addr_to_str(src), port);
}

/* If p is an Echo request, replace p's data with the matching response and
 * return 1. If p is no Echo request, return 0, or -1 if an invalid packet is
 * detected. */
static int gtphub_handle_echo(struct gtphub *hub, struct gtp_packet_desc *p, uint8_t **reply_buf)
{
	if (p->type != GTP_ECHO_REQ)
		return 0;

	static uint8_t echo_response_data[14] = {
		0x32,	/* flags */
		GTP_ECHO_RSP,
		0x00, 14 - 8, /* Length in network byte order */
		0x00, 0x00, 0x00, 0x00,	/* Zero TEI */
		0, 0,	/* Seq, to be replaced */
		0, 0,	/* no extensions */
		0x0e,	/* Recovery IE */
		0	/* Recovery counter, to be replaced */
	};
	uint16_t *seq = (uint16_t*)&echo_response_data[8];
	uint8_t *recovery = &echo_response_data[13];

	*seq = hton16(p->seq);
	*recovery = hub->restart_counter;

	*reply_buf = echo_response_data;

	return sizeof(echo_response_data);
}

struct gtphub_peer_port *gtphub_known_addr_have_port(const struct gtphub_bind *bind,
						     const struct osmo_sockaddr *addr);

/* Parse buffer as GTP packet, replace elements in-place and return the ofd and
 * address to forward to. Return a pointer to the osmo_fd, but copy the
 * sockaddr to *to_addr. The reason for this is that the sockaddr may expire at
 * any moment, while the osmo_fd is guaranteed to persist. Return the number of
 * bytes to forward, 0 or less on failure. */
int gtphub_from_ggsns_handle_buf(struct gtphub *hub,
				 unsigned int plane_idx,
				 const struct osmo_sockaddr *from_addr,
				 uint8_t *buf,
				 size_t received,
				 time_t now,
				 uint8_t **reply_buf,
				 struct osmo_fd **to_ofd,
				 struct osmo_sockaddr *to_addr)
{
	LOG("<- rx %s from GGSN %s\n",
	    gtphub_plane_idx_names[plane_idx],
	    osmo_sockaddr_to_str(from_addr));

	static struct gtp_packet_desc p;
	gtp_decode(buf, received, plane_idx, &p);

	if (p.rc <= 0)
		return -1;

	int reply_len;
	reply_len = gtphub_handle_echo(hub, &p, reply_buf);
	if (reply_len > 0) {
		/* It was an echo. Nothing left to do. */
		osmo_sockaddr_copy(to_addr, from_addr);
		*to_ofd = &hub->to_ggsns[plane_idx].ofd;
		return reply_len;
	}
	if (reply_len < 0)
		return -1;

	*to_ofd = &hub->to_sgsns[plane_idx].ofd;

	/* If a GGSN proxy is configured, check that it's indeed that proxy
	 * talking to us. A proxy is a forced 1:1 connection, e.g. to another
	 * gtphub, so no-one else is allowed to talk to us from that side. */
	struct gtphub_peer_port *ggsn = hub->ggsn_proxy[plane_idx];
	if (ggsn) {
		if (osmo_sockaddr_cmp(&ggsn->sa, from_addr) != 0) {
			LOGERR("Rejecting: GGSN proxy configured, but GTP packet"
			       " received on GGSN bind is from another sender:"
			       " proxy: %s  sender: %s\n",
			       gtphub_port_str(ggsn),
			       osmo_sockaddr_to_str(from_addr));
			return -1;
		}
	}

	if (!ggsn) {
		/* Find a GGSN peer with a matching address. The sender's port
		 * may in fact differ. */
		ggsn = gtphub_known_addr_have_port(&hub->to_ggsns[plane_idx],
						   from_addr);
	}

	/* If any PDP context has been created, we already have an entry for
	 * this GGSN. If we don't have an entry, the GGSN has nothing to tell
	 * us about. */
	if (!ggsn) {
		LOGERR("Dropping packet: unknown GGSN peer: %s\n",
		       osmo_sockaddr_to_str(from_addr));
		return -1;
	}

	LOG("GGSN peer: %s\n", gtphub_port_str(ggsn));

	struct gtphub_peer_port *sgsn_from_seq;
	struct gtphub_peer_port *sgsn;
	if (gtphub_unmap(hub, &p, ggsn,
			 hub->sgsn_proxy[plane_idx],
			 &sgsn, &sgsn_from_seq,
			 NULL /* not interested, got it in &sgsn already */
			)
	    != 0) {
		return -1;
	}

	if (!sgsn) {
		/* A GGSN initiated request would go to a known TEI. So this is
		 * bogus. */
		LOGERR("No SGSN to send to. Dropping packet.\n");
		return -1;
	}

	if (plane_idx == GTPH_PLANE_CTRL) {
		/* This may be a Create PDP Context response. If it is, there are other
		 * addresses in the GTP message to set up apart from the sender. */
		if (gtphub_handle_pdp_ctx_ies(hub, hub->to_ggsns,
					      hub->to_sgsns, &p, now)
		    != 0)
			return -1;
	}

	gtphub_check_restart_counter(hub, &p, ggsn);
	gtphub_map_restart_counter(hub, &p, ggsn, sgsn);

	/* If the GGSN is replying to an SGSN request, the sequence nr has
	 * already been unmapped above (sgsn_from_seq != NULL), and we need not
	 * create a new mapping. */
	if (!sgsn_from_seq)
		gtphub_map_seq(&p, ggsn, sgsn, now);

	osmo_sockaddr_copy(to_addr, &sgsn->sa);

	*reply_buf = (uint8_t*)p.data;

	LOG("<-- Forward to SGSN: %d bytes to %s\n",
	    (int)received, osmo_sockaddr_to_str(to_addr));
	return received;
}

static int from_sgsns_read_cb(struct osmo_fd *from_sgsns_ofd, unsigned int what)
{
	unsigned int plane_idx = from_sgsns_ofd->priv_nr;
	OSMO_ASSERT(plane_idx < GTPH_PLANE_N);
	LOG("\n\n=== reading from SGSN (%s)\n", gtphub_plane_idx_names[plane_idx]);

	if (!(what & BSC_FD_READ))
		return 0;

	struct gtphub *hub = from_sgsns_ofd->data;

	static uint8_t buf[4096];
	struct osmo_sockaddr from_addr;
	struct osmo_sockaddr to_addr;
	struct osmo_fd *to_ofd;
	size_t len;
	uint8_t *reply_buf;

	len = gtphub_read(from_sgsns_ofd, &from_addr, buf, sizeof(buf));
	if (len < 1)
		return 0;

	len = gtphub_from_sgsns_handle_buf(hub, plane_idx, &from_addr, buf, len,
					   gtphub_now(),
					   &reply_buf, &to_ofd, &to_addr);
	if (len < 1)
		return 0;

	return gtphub_write(to_ofd, &to_addr, reply_buf, len);
}

/* Analogous to gtphub_from_ggsns_handle_buf(), see the comment there. */
int gtphub_from_sgsns_handle_buf(struct gtphub *hub,
				 unsigned int plane_idx,
				 const struct osmo_sockaddr *from_addr,
				 uint8_t *buf,
				 size_t received,
				 time_t now,
				 uint8_t **reply_buf,
				 struct osmo_fd **to_ofd,
				 struct osmo_sockaddr *to_addr)
{
	LOG("-> rx %s from SGSN %s\n",
	    gtphub_plane_idx_names[plane_idx],
	    osmo_sockaddr_to_str(from_addr));

	static struct gtp_packet_desc p;
	gtp_decode(buf, received, plane_idx, &p);

	if (p.rc <= 0)
		return -1;

	int reply_len;
	reply_len = gtphub_handle_echo(hub, &p, reply_buf);
	if (reply_len > 0) {
		/* It was an echo. Nothing left to do. */
		osmo_sockaddr_copy(to_addr, from_addr);
		*to_ofd = &hub->to_ggsns[plane_idx].ofd;
		return reply_len;
	}
	if (reply_len < 0)
		return -1;

	*to_ofd = &hub->to_ggsns[plane_idx].ofd;

	/* If an SGSN proxy is configured, check that it's indeed that proxy
	 * talking to us. A proxy is a forced 1:1 connection, e.g. to another
	 * gtphub, so no-one else is allowed to talk to us from that side. */
	struct gtphub_peer_port *sgsn = hub->sgsn_proxy[plane_idx];
	if (sgsn) {
		if (osmo_sockaddr_cmp(&sgsn->sa, from_addr) != 0) {
			LOGERR("Rejecting: GGSN proxy configured, but GTP packet"
			       " received on GGSN bind is from another sender:"
			       " proxy: %s  sender: %s\n",
			       gtphub_port_str(sgsn),
			       osmo_sockaddr_to_str(from_addr));
			return -1;
		}
	}

	if (!sgsn) {
		/* If any contact has been made before, we already have an
		 * entry for this SGSN. The port may differ. */
		sgsn = gtphub_known_addr_have_port(&hub->to_sgsns[plane_idx],
						   from_addr);
	}

	if (!sgsn) {
		/* A new peer. If this is on the Ctrl plane, an SGSN may make
		 * first contact without being known yet, so create the peer
		 * struct for the current sender. */
		if (plane_idx != GTPH_PLANE_CTRL) {
			LOGERR("User plane peer was not announced by PDP Context, discarding: %s\n",
			       osmo_sockaddr_to_str(from_addr));
			return -1;
		}

		struct gsn_addr from_gsna;
		uint16_t from_port;
		if (gsn_addr_from_sockaddr(&from_gsna, &from_port, from_addr) != 0)
			return -1;

		sgsn = gtphub_port_have(hub, &hub->to_sgsns[plane_idx],
					&from_gsna, from_port);
	}

	if (!sgsn) {
		/* This could theoretically happen for invalid address data or somesuch. */
		LOGERR("Dropping packet: invalid SGSN peer: %s\n",
		       osmo_sockaddr_to_str(from_addr));
		return -1;
	}
	LOG("SGSN peer: %s\n", gtphub_port_str(sgsn));

	struct gtphub_peer_port *ggsn_from_seq;
	struct gtphub_peer_port *ggsn;
	if (gtphub_unmap(hub, &p, sgsn,
			 hub->ggsn_proxy[plane_idx],
			 &ggsn, &ggsn_from_seq,
			 NULL /* not interested, got it in &ggsn already */
			)
	    != 0) {
		return -1;
	}

	/* See what our GGSN guess would be from the packet data per se. */
	/* TODO maybe not do this always? */
	struct gtphub_peer_port *ggsn_from_packet;
	if (gtphub_resolve_ggsn(hub, &p, &ggsn_from_packet) < 0)
		return -1;

	if (ggsn_from_packet && ggsn
	    && (ggsn_from_packet != ggsn)) {
		LOGERR("GGSN implied from packet does not match unmapped"
		       " GGSN, using unmapped GGSN:"
		       " from packet: %s  unmapped: %s\n",
		       gtphub_port_str(ggsn_from_packet),
		       gtphub_port_str2(ggsn));
		/* TODO return -1; ? */
	}

	if (!ggsn)
		ggsn = ggsn_from_packet;

	if (!ggsn) {
		LOGERR("No GGSN to send to. Dropping packet.\n");
		return -1;
	}

	if (plane_idx == GTPH_PLANE_CTRL) {
		/* This may be a Create PDP Context requst. If it is, there are other
		 * addresses in the GTP message to set up apart from the sender. */
		if (gtphub_handle_pdp_ctx_ies(hub, hub->to_sgsns,
					      hub->to_ggsns, &p, now)
		    != 0)
			return -1;
	}

	gtphub_check_restart_counter(hub, &p, sgsn);
	gtphub_map_restart_counter(hub, &p, sgsn, ggsn);

	/* If the SGSN is replying to a GGSN request, the sequence nr has
	 * already been unmapped above (unmap_ggsn != NULL), and we need not
	 * create a new outgoing sequence map. */
	if (!ggsn_from_seq)
		gtphub_map_seq(&p, sgsn, ggsn, now);

	osmo_sockaddr_copy(to_addr, &ggsn->sa);

	*reply_buf = (uint8_t*)p.data;

	LOG("--> Forward to GGSN: %d bytes to %s\n",
	    (int)received, osmo_sockaddr_to_str(to_addr));
	return received;
}

static void resolved_gssn_del_cb(struct expiring_item *expi)
{
	struct gtphub_resolved_ggsn *ggsn;
	ggsn = container_of(expi, struct gtphub_resolved_ggsn, expiry_entry);

	gtphub_port_ref_count_dec(ggsn->peer);
	llist_del(&ggsn->entry);

	ggsn->expiry_entry.del_cb = 0;
	expiring_item_del(&ggsn->expiry_entry);

	talloc_free(ggsn);
}

void gtphub_resolved_ggsn(struct gtphub *hub, const char *apn_oi_str,
			  struct gsn_addr *resolved_addr,
			  time_t now)
{
	struct gtphub_peer_port *pp;
	struct gtphub_resolved_ggsn *ggsn;

	LOG("Resolved GGSN callback: %s %s\n",
	    apn_oi_str, osmo_hexdump((unsigned char*)resolved_addr, sizeof(*resolved_addr)));

	pp = gtphub_port_have(hub, &hub->to_ggsns[GTPH_PLANE_CTRL],
			      resolved_addr, 2123);
	if (!pp) {
		LOGERR("Internal: Cannot create/find peer '%s'\n",
		       gsn_addr_to_str(resolved_addr));
		return;
	}

	ggsn = talloc_zero(osmo_gtphub_ctx, struct gtphub_resolved_ggsn);
	OSMO_ASSERT(ggsn);

	ggsn->peer = pp;
	gtphub_port_ref_count_inc(pp);

	strncpy(ggsn->apn_oi_str, apn_oi_str, sizeof(ggsn->apn_oi_str));

	ggsn->expiry_entry.del_cb = resolved_gssn_del_cb;
	expiry_add(&hub->expire_tei_maps, &ggsn->expiry_entry, now);

	llist_add(&ggsn->entry, &hub->resolved_ggsns);
}

static int gtphub_gc_peer_port(struct gtphub_peer_port *pp)
{
	return pp->ref_count == 0;
}

static int gtphub_gc_peer_addr(struct gtphub_peer_addr *pa)
{
	struct gtphub_peer_port *pp, *npp;
	llist_for_each_entry_safe(pp, npp, &pa->ports, entry) {
		if (gtphub_gc_peer_port(pp)) {
			LOG("expired: peer %s\n",
			    gtphub_port_str(pp));
			gtphub_peer_port_del(pp);
		}
	}
	return llist_empty(&pa->ports);
}

static int gtphub_gc_peer(struct gtphub_peer *p)
{
	struct gtphub_peer_addr *pa, *npa;
	llist_for_each_entry_safe(pa, npa, &p->addresses, entry) {
		if (gtphub_gc_peer_addr(pa)) {
			gtphub_peer_addr_del(pa);
		}
	}

	/* Note that there's a ref_count in each gtphub_peer_port instance
	 * listed within p->addresses, referenced by TEI mappings from
	 * hub->tei_map. As long as those don't expire, this peer will stay. */

	LOG("gc peer %p llist_empty %d  seq_map_empty %d\n", p,
	(int)llist_empty(&p->addresses), (int) nr_map_empty(&p->seq_map));
	if (! nr_map_empty(&p->seq_map)) {
		printf("not empty\n");
		struct nr_mapping *nrm;
		llist_for_each_entry(nrm, &p->seq_map.mappings, entry) {
			printf("%p %s %d -> %d\n",
			       nrm->origin, gtphub_port_str(nrm->origin),nrm->orig, nrm->repl);
		}
	}
	return llist_empty(&p->addresses)
		&& nr_map_empty(&p->seq_map);
}

static void gtphub_gc_bind(struct gtphub_bind *b)
{
	struct gtphub_peer *p, *n;
	llist_for_each_entry_safe(p, n, &b->peers, entry) {
		if (gtphub_gc_peer(p)) {
			gtphub_peer_del(p);
		}
	}
}

void gtphub_gc(struct gtphub *hub, time_t now)
{
	int expired;
	expired = expiry_tick(&hub->expire_seq_maps, now);
	expired += expiry_tick(&hub->expire_tei_maps, now);

	/* ... */

	if (expired) {
		int i;
		for (i = 0; i < GTPH_PLANE_N; i++) {
			gtphub_gc_bind(&hub->to_sgsns[i]);
			gtphub_gc_bind(&hub->to_ggsns[i]);
		}
	}
}

static void gtphub_gc_cb(void *data)
{
	struct gtphub *hub = data;
	gtphub_gc(hub, gtphub_now());
	osmo_timer_schedule(&hub->gc_timer, GTPH_GC_TICK_SECONDS, 0);
}

static void gtphub_gc_start(struct gtphub *hub)
{
	hub->gc_timer.cb = gtphub_gc_cb;
	hub->gc_timer.data = hub;

	osmo_timer_schedule(&hub->gc_timer, GTPH_GC_TICK_SECONDS, 0);
}

/* called by unit tests */
void gtphub_init(struct gtphub *hub)
{
	gtphub_zero(hub);

	INIT_LLIST_HEAD(&hub->resolved_ggsns);

	expiry_init(&hub->expire_seq_maps, GTPH_SEQ_MAPPING_EXPIRY_SECS);
	expiry_init(&hub->expire_tei_maps, GTPH_TEI_MAPPING_EXPIRY_MINUTES * 60);

	int plane_idx;
	for (plane_idx = 0; plane_idx < GTPH_PLANE_N; plane_idx++) {
		nr_pool_init(&hub->tei_pool[plane_idx]);
		nr_map_init(&hub->tei_map[plane_idx],
			    &hub->tei_pool[plane_idx],
			    &hub->expire_tei_maps);

		gtphub_bind_init(&hub->to_ggsns[plane_idx]);
		gtphub_bind_init(&hub->to_sgsns[plane_idx]);
	}
}

static int gtphub_make_proxy(struct gtphub *hub,
			     struct gtphub_peer_port **pp,
			     struct gtphub_bind *bind,
			     const struct gtphub_cfg_addr *addr)
{
	if (!addr->addr_str)
		return 0;

	struct gsn_addr gsna;
	if (gsn_addr_from_str(&gsna, addr->addr_str) != 0)
		return -1;

	*pp = gtphub_port_have(hub, bind, &gsna, addr->port);

	/* This is *the* proxy. Make sure it is never expired. */
	gtphub_port_ref_count_inc(*pp);
	return 0;
}

int gtphub_start(struct gtphub *hub, struct gtphub_cfg *cfg)
{
	int rc;

	gtphub_init(hub);
	gtphub_ares_init(hub);

	/* TODO set hub->restart_counter from external file. */

	int plane_idx;
	for (plane_idx = 0; plane_idx < GTPH_PLANE_N; plane_idx++) {
		rc = gtphub_bind_start(&hub->to_ggsns[plane_idx],
				       &cfg->to_ggsns[plane_idx],
				       from_ggsns_read_cb, hub, plane_idx);
		if (rc) {
			LOGERR("Failed to bind for GGSNs (%s)\n",
			       gtphub_plane_idx_names[plane_idx]);
			return rc;
		}

		rc = gtphub_bind_start(&hub->to_sgsns[plane_idx],
				       &cfg->to_sgsns[plane_idx],
				       from_sgsns_read_cb, hub, plane_idx);
		if (rc) {
			LOGERR("Failed to bind for SGSNs (%s)\n",
			       gtphub_plane_idx_names[plane_idx]);
			return rc;
		}
	}


	for (plane_idx = 0; plane_idx < GTPH_PLANE_N; plane_idx++) {
		if (gtphub_make_proxy(hub,
				      &hub->sgsn_proxy[plane_idx],
				      &hub->to_sgsns[plane_idx],
				      &cfg->sgsn_proxy[plane_idx])
		    != 0) {
			LOGERR("Cannot configure SGSN proxy %s port %d.\n",
			       cfg->sgsn_proxy[plane_idx].addr_str,
			       (int)cfg->sgsn_proxy[plane_idx].port);
			return -1;
		}
		if (gtphub_make_proxy(hub,
				      &hub->ggsn_proxy[plane_idx],
				      &hub->to_ggsns[plane_idx],
				      &cfg->ggsn_proxy[plane_idx])
		    != 0) {
			LOGERR("Cannot configure GGSN proxy.\n");
			return -1;
		}
	}

	for (plane_idx = 0; plane_idx < GTPH_PLANE_N; plane_idx++) {
		if (hub->sgsn_proxy[plane_idx])
			LOG("Using SGSN %s proxy %s\n",
			    gtphub_plane_idx_names[plane_idx],
			    gtphub_port_str(hub->sgsn_proxy[plane_idx]));
	}

	for (plane_idx = 0; plane_idx < GTPH_PLANE_N; plane_idx++) {
		if (hub->sgsn_proxy[plane_idx])
			LOG("Using GGSN %s proxy %s\n",
			    gtphub_plane_idx_names[plane_idx],
			    gtphub_port_str(hub->ggsn_proxy[plane_idx]));
	}

	gtphub_gc_start(hub);
	return 0;
}

static struct gtphub_peer_addr *gtphub_peer_find_addr(const struct gtphub_peer *peer,
						      const struct gsn_addr *addr)
{
	struct gtphub_peer_addr *a;
	llist_for_each_entry(a, &peer->addresses, entry) {
		if (gsn_addr_same(&a->addr, addr))
			return a;
	}
	return NULL;
}

static struct gtphub_peer_port *gtphub_addr_find_port(const struct gtphub_peer_addr *a,
						      uint16_t port)
{
	OSMO_ASSERT(port);
	struct gtphub_peer_port *pp;
	llist_for_each_entry(pp, &a->ports, entry) {
		if (pp->port == port)
			return pp;
	}
	return NULL;
}

static struct gtphub_peer_addr *gtphub_addr_find(const struct gtphub_bind *bind,
						 const struct gsn_addr *addr)
{
	struct gtphub_peer *peer;
	llist_for_each_entry(peer, &bind->peers, entry) {
		struct gtphub_peer_addr *a = gtphub_peer_find_addr(peer, addr);
		if (a)
			return a;
	}
	return NULL;
}

static struct gtphub_peer_port *gtphub_port_find(const struct gtphub_bind *bind,
						 const struct gsn_addr *addr,
						 uint16_t port)
{
	struct gtphub_peer_addr *a = gtphub_addr_find(bind, addr);
	if (!a)
		return NULL;
	return gtphub_addr_find_port(a, port);
}

struct gtphub_peer_port *gtphub_port_find_sa(const struct gtphub_bind *bind,
					     const struct osmo_sockaddr *addr)
{
	struct gsn_addr gsna;
	uint16_t port;
	gsn_addr_from_sockaddr(&gsna, &port, addr);
	return gtphub_port_find(bind, &gsna, port);
}

static struct gtphub_peer *gtphub_peer_new(struct gtphub *hub,
					   struct gtphub_bind *bind)
{
	struct gtphub_peer *peer = talloc_zero(osmo_gtphub_ctx, struct gtphub_peer);
	OSMO_ASSERT(peer);

	INIT_LLIST_HEAD(&peer->addresses);

	nr_pool_init(&peer->seq_pool);
	nr_map_init(&peer->seq_map, &peer->seq_pool, &hub->expire_seq_maps);

	/* TODO use something random to pick the initial sequence nr.
	   0x6d31 produces the ASCII character sequence 'm1', currently used in
	   gtphub_nc_test.sh. */
	peer->seq_pool.last_nr = 0x6d31 - 1;

	llist_add(&peer->entry, &bind->peers);
	return peer;
}

static struct gtphub_peer_addr *gtphub_peer_add_addr(struct gtphub_peer *peer,
						     const struct gsn_addr *addr)
{
	struct gtphub_peer_addr *a;
	a = talloc_zero(osmo_gtphub_ctx, struct gtphub_peer_addr);
	OSMO_ASSERT(a);
	a->peer = peer;
	gsn_addr_copy(&a->addr, addr);
	INIT_LLIST_HEAD(&a->ports);
	llist_add(&a->entry, &peer->addresses);

	return a;
}

static struct gtphub_peer_addr *gtphub_addr_have(struct gtphub *hub,
						 struct gtphub_bind *bind,
						 const struct gsn_addr *addr)
{
	struct gtphub_peer_addr *a = gtphub_addr_find(bind, addr);
	if (a)
		return a;

	/* If we haven't found an address, that means we need to create an
	 * entirely new peer for the new address. More addresses may be added
	 * to this peer later, but not via this function. */
	struct gtphub_peer *peer = gtphub_peer_new(hub, bind);

	a = gtphub_peer_add_addr(peer, addr);
	
	LOG("New peer address: %s\n",
	    gsn_addr_to_str(&a->addr));

	return a;
}

static struct gtphub_peer_port *gtphub_addr_add_port(struct gtphub_peer_addr *a,
						     uint16_t port)
{
	struct gtphub_peer_port *pp;

	pp = talloc_zero(osmo_gtphub_ctx, struct gtphub_peer_port);
	OSMO_ASSERT(pp);
	pp->peer_addr = a;
	pp->port = port;

	if (gsn_addr_to_sockaddr(&a->addr, port, &pp->sa) != 0) {
		talloc_free(pp);
		return NULL;
	}

	llist_add(&pp->entry, &a->ports);

	LOG("New peer port: %s port %d\n",
	    gsn_addr_to_str(&a->addr),
	    (int)port);

	return pp;
}

struct gtphub_peer_port *gtphub_port_have(struct gtphub *hub,
					  struct gtphub_bind *bind,
					  const struct gsn_addr *addr,
					  uint16_t port)
{
	struct gtphub_peer_addr *a = gtphub_addr_have(hub, bind, addr);

	struct gtphub_peer_port *pp = gtphub_addr_find_port(a, port);
	if (pp)
		return pp;

	return gtphub_addr_add_port(a, port);
}

/* Find a GGSN peer with a matching address. If the address is known but the
 * port not, create a new port for that peer address. */
struct gtphub_peer_port *gtphub_known_addr_have_port(const struct gtphub_bind *bind,
						     const struct osmo_sockaddr *addr)
{
	struct gtphub_peer_addr *pa;
	struct gtphub_peer_port *pp;

	struct gsn_addr gsna;
	uint16_t port;
	gsn_addr_from_sockaddr(&gsna, &port, addr);

	pa = gtphub_addr_find(bind, &gsna);
	if (!pa)
		return NULL;

	pp = gtphub_addr_find_port(pa, port);

	if (!pp)
		pp = gtphub_addr_add_port(pa, port);

	return pp;
}


/* Return 0 if the message in p is not applicable for GGSN resolution, -1 if
 * resolution should be possible but failed, and 1 if resolution was
 * successful. *pp will be set to NULL if <1 is returned. */
static int gtphub_resolve_ggsn(struct gtphub *hub,
			       struct gtp_packet_desc *p,
			       struct gtphub_peer_port **pp)
{
	*pp = NULL;

	/* TODO determine from message type whether IEs should be present? */

	int rc;
	const char *imsi_str;
	rc = get_ie_imsi_str(p->ie, 0, &imsi_str);
	if (rc < 1)
		return rc;
	OSMO_ASSERT(imsi_str);

	const char *apn_str;
	rc = get_ie_apn_str(p->ie, &apn_str);
	if (rc < 1)
		return rc;
	OSMO_ASSERT(apn_str);

	*pp = gtphub_resolve_ggsn_addr(hub, imsi_str, apn_str);
	return (*pp)? 1 : -1;
}


/* TODO move to osmocom/core/socket.c ? */
/* The caller is required to call freeaddrinfo(*result), iff zero is returned. */
/* use this in osmo_sock_init() to remove dup. */
static int _osmo_getaddrinfo(struct addrinfo **result,
			     uint16_t family, uint16_t type, uint8_t proto,
			     const char *host, uint16_t port)
{
	struct addrinfo hints;
	char portbuf[16];

	sprintf(portbuf, "%u", port);
	memset(&hints, '\0', sizeof(struct addrinfo));
	hints.ai_family = family;
	if (type == SOCK_RAW) {
		/* Workaround for glibc, that returns EAI_SERVICE (-8) if
		 * SOCK_RAW and IPPROTO_GRE is used.
		 */
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_protocol = IPPROTO_UDP;
	} else {
		hints.ai_socktype = type;
		hints.ai_protocol = proto;
	}

	return getaddrinfo(host, portbuf, &hints, result);
}

/* TODO move to osmocom/core/socket.c ? */
int osmo_sockaddr_init(struct osmo_sockaddr *addr,
		       uint16_t family, uint16_t type, uint8_t proto,
		       const char *host, uint16_t port)
{
	struct addrinfo *res;
	int rc;
	rc = _osmo_getaddrinfo(&res, family, type, proto, host, port);

	if (rc != 0) {
		LOGERR("getaddrinfo returned error %d\n", (int)rc);
		return -EINVAL;
	}

	OSMO_ASSERT(res->ai_addrlen <= sizeof(addr->a));
	memcpy(&addr->a, res->ai_addr, res->ai_addrlen);
	addr->l = res->ai_addrlen;
	freeaddrinfo(res);

	return 0;
}

int osmo_sockaddr_to_strs(char *addr_str, size_t addr_str_len,
			  char *port_str, size_t port_str_len,
			  const struct osmo_sockaddr *addr,
			  int flags)
{
       int rc;

       if ((addr->l < 1) || (addr->l > sizeof(addr->a))) {
	       LOGP(DGTPHUB, LOGL_ERROR, "Invalid address size: %d\n", addr->l);
	       return -1;
       }

       if (addr->l > sizeof(addr->a)) {
	       LOGP(DGTPHUB, LOGL_ERROR, "Invalid address: too long: %d\n", addr->l);
	       return -1;
       }

       rc = getnameinfo((struct sockaddr*)&addr->a, addr->l,
			addr_str, addr_str_len,
			port_str, port_str_len,
			flags);

       if (rc)
	       LOGP(DGTPHUB, LOGL_ERROR, "Invalid address: %s: %s\n", gai_strerror(rc),
		    osmo_hexdump((uint8_t*)&addr->a, addr->l));

       return rc;
}

const char *osmo_sockaddr_to_strb(const struct osmo_sockaddr *addr,
				  char *buf, size_t buf_len)
{
	const int portbuf_len = 6;
	OSMO_ASSERT(buf_len > portbuf_len);
	char *portbuf = buf + buf_len - portbuf_len;
	buf_len -= portbuf_len;
	if (osmo_sockaddr_to_strs(buf, buf_len,
				  portbuf, portbuf_len,
				  addr,
				  NI_NUMERICHOST | NI_NUMERICSERV))
		return NULL;

	char *pos = buf + strnlen(buf, buf_len-1);
	size_t len = buf_len - (pos - buf);

	snprintf(pos, len, " port %s", portbuf);
	buf[buf_len-1] = '\0';

	return buf;
}

const char *osmo_sockaddr_to_str(const struct osmo_sockaddr *addr)
{
	static char buf[256];
	const char *result = osmo_sockaddr_to_strb(addr, buf, sizeof(buf));
	if (! result)
		return "(invalid)";
	return result;
}

int osmo_sockaddr_cmp(const struct osmo_sockaddr *a, const struct osmo_sockaddr *b)
{
	if (a == b)
		return 0;
	if (!a)
		return -1;
	if (!b)
		return 1;
	if (a->l != b->l) {
		/* Lengths are not the same, but determine the order. Will
		 * anyone ever sort a list by osmo_sockaddr though...? */
		int cmp = memcmp(&a->a, &b->a, (a->l < b->l)? a->l : b->l);
		if (cmp == 0) {
			if (a->l < b->l)
				return -1;
			else
				return 1;
		}
		return cmp;
	}
	return memcmp(&a->a, &b->a, a->l);
}

void osmo_sockaddr_copy(struct osmo_sockaddr *dst, const struct osmo_sockaddr *src)
{
	OSMO_ASSERT(src->l <= sizeof(dst->a));
	memcpy(&dst->a, &src->a, src->l);
	dst->l = src->l;
}