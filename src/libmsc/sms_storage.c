/* Persistent SMS storage on disk (replaces old sqlite3 code)
 * (C) 2022 by Harald Welte <laforge@osmocom.org>
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
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/* SMS life cycle:
 *
 * allocation:
 * 	- received from RAN (04.11)
 * 	- received from SMPP
 * 	- received from GSUP
 * 	- received from SGs
 * 	- read from storage [on start]
 *
 * release:
 * 	- after delivery (via RAN or SGs)
 * 	- after expiration (of validity timeout)
 * 	- after removal of file from FS (inotify)
 *
 * look-up:
 * 	- by subscriber when subscriber has lchan open
 * 	- by ID on deletion from FS
 *
 * When a SMS is allocated on the main thread (it was received from some interface),
 * we don't add it to any linked list yet, and hence don't start any delivery yet. We first
 * send it over the inter-thread queue to the storage thread.  Once committed to disk, the
 * storage thread will send it back to the main thread, so it can be added to some list and
 * is eligible for delivery attempts.  This way we prevent any races where the main thread
 * might deliver (and subsequently free!) the SMS while the storage thread still needs its
 * memory until write has completed.
 *
 * SMS memory allocation is guarded by a mutex; this way both threads can allocate SMS
 * without corrupting thread-unsafe talloc structures.
 *
 * SMS memory free must happen only on the main thread, as this may want to decrement
 * vlr_subscr and esme use counts.
 *
 */

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "config.h"

#ifdef HAVE_INOTIFY
#include <sys/inotify.h>
#endif

#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/it_q.h>
#include <osmocom/core/bit64gen.h>

#include <osmocom/gsm/gsm0411_utils.h>
#include <osmocom/gsm/protocol/gsm_04_11.h>

#include <osmocom/msc/debug.h>
#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/gsm_04_11.h>
#include <osmocom/msc/sms_storage.h>
#include <osmocom/msc/vlr.h>

/* all the state of a SMS storage instance */
struct sms_storage_inst {
	const struct sms_storage_cfg *cfg;
	pthread_t thread;

	struct {
		/* opendir/readdir handle while we read the directory on start-up */
		DIR *dir;
		struct osmo_timer_list timer;
		unsigned int count;
	} boot_read;

#ifdef HAVE_INOTIFY
	struct {
		struct osmo_fd ofd;
		int wd;
	} inotify;
#endif

	/* global list of penidng SMSs */
	struct llist_head pending;

	/* inter-thread message queues for both directions */
	struct {
		struct osmo_it_q *itq;
		/* talloc context + mutex */
		void *ctx;
		pthread_mutex_t ctx_mutex;
	} main2storage;
	struct {
		struct osmo_it_q *itq;
		/* talloc context + mutex */
		void *ctx;
		pthread_mutex_t ctx_mutex;
	} storage2main;
};

/***********************************************************************
 * Inter-Thread communication
 ***********************************************************************/

/* Storage -> Main thread events */
enum smss_s2m_op {
	SMSS_S2M_OP_NULL,
	/* SMS storage has read a SMS from disk, asks main thread to add it to queue */
	SMSS_S2M_OP_SMS_FROM_DISK_IND,
	/* SMS storage confirms having written SMS to disk; main thread adds it to queue */
	SMSS_S2M_OP_SMS_TO_DISK_CFM,
	/* SMS storage has detected a sms was deleted from disk; main thread must forget it */
	SMSS_S2M_OP_SMS_DELETED_ON_DISK_IND,
};

struct smss_s2m_evt {
	struct llist_head list;

	enum smss_s2m_op op;

	union {
		struct {
			struct gsm_sms *sms;
		} sms_from_disk_ind;
		struct {
			struct gsm_sms *sms;
		} sms_to_disk_cfm;
		struct {
			unsigned long long id;
		} sms_deleted_on_disk_ind;
	};
};

/* Main -> Storage thread events */
enum smss_m2s_op {
	SMSS_M2S_OP_NULL,
	/* main thread asks storage thread to store a SMS on disk */
	SMSS_M2S_OP_SMS_TO_DISK_REQ,
	/* main thread asks storage thread to delete a SMS from disk (expiration, delivered) */
	SMSS_M2S_OP_SMS_DELETE_FROM_DISK_REQ,
};

struct smss_m2s_evt {
	struct llist_head list;

	enum smss_m2s_op op;

	union {
		struct {
			struct gsm_sms *sms;
		} sms_to_disk_req;
		struct {
			unsigned long long id;
			enum smss_delete_cause cause;
		} sms_delete_from_disk_req;
	};
};

static struct smss_s2m_evt *s2m_alloc(struct sms_storage_inst *ssi, enum smss_s2m_op op)
{
	struct smss_s2m_evt *evt;
	pthread_mutex_lock(&ssi->storage2main.ctx_mutex);
	evt = talloc_zero(ssi->storage2main.ctx, struct smss_s2m_evt);
	pthread_mutex_unlock(&ssi->storage2main.ctx_mutex);
	if (evt)
		evt->op = op;
	return evt;
}

static void s2m_free(struct sms_storage_inst *ssi, struct smss_s2m_evt *evt)
{
	pthread_mutex_lock(&ssi->storage2main.ctx_mutex);
	talloc_free(evt);
	pthread_mutex_unlock(&ssi->storage2main.ctx_mutex);
}

static struct smss_m2s_evt *m2s_alloc(struct sms_storage_inst *ssi, enum smss_m2s_op op)
{
	struct smss_m2s_evt *evt;
	pthread_mutex_lock(&ssi->main2storage.ctx_mutex);
	evt = talloc_zero(ssi->main2storage.ctx, struct smss_m2s_evt);
	pthread_mutex_unlock(&ssi->main2storage.ctx_mutex);
	if (evt)
		evt->op = op;
	return evt;
}

static void m2s_free(struct sms_storage_inst *ssi, struct smss_m2s_evt *evt)
{
	pthread_mutex_lock(&ssi->main2storage.ctx_mutex);
	talloc_free(evt);
	pthread_mutex_unlock(&ssi->main2storage.ctx_mutex);
}

/***********************************************************************
 * Disk I/O functions
 ***********************************************************************/

#define SUBDIR_CURRENT		"current"
#define SUBDIR_DELIVERED	"delivered"
#define SUBDIR_EXPIRED		"expired"

/* generate the fully-qualified on-disk filename for a SMS */
static int _sms_gen_fq_path(struct sms_storage_inst *ssi, char *fq_path, size_t fq_path_len,
			    const char *subdir, unsigned long long id)
{
	int rc;

	rc = snprintf(fq_path, fq_path_len, "%s/%s/%llu.osms", ssi->cfg->storage_dir, subdir, id);
	if (rc >= fq_path_len) {
		LOGP(DSMSS, LOGL_ERROR, "Overflowing buffer while composing file path\n");
		return -EINVAL;
	}
	return rc;
}

#define SMS_ON_DISK_MAGIC		0x05305350
#define SMS_ON_DISK_VERSION		1

/* sms_on_disk.flags bitmask */
#define SMS_ON_DISK_F_REPLY_PATH_REQ	(1U << 0)
#define SMS_ON_DISK_F_STATUS_REP_REQ	(1U << 1)
#define SMS_ON_DISK_F_IS_REPORT		(1U << 2)
#define SMS_ON_DISK_F_UD_HDR_IND	(1U << 3)

enum sms_on_disk_source {
	SMS_ON_DISK_SOURCE_UNKNOWN,
	SMS_ON_DISK_SOURCE_RAN_GSM,		/* SMS submitted via GSM RAN */
	SMS_ON_DISK_SOURCE_RAN_UMTS,		/* SMS submitted via UMTS RAN */
	SMS_ON_DISK_SOURCE_SGs,			/* SMS submitted via SGs (LTE NAS) */
	SMS_ON_DISK_SOURCE_SMPP,		/* SMS submitted via SMPP ESME */
	SMS_ON_DISK_SOURCE_VTY,			/* SMS submitted via VTY interface */
	/* none of the below currently implemented */
	SMS_ON_DISK_SOURCE_RAN_GPRS,		/* SMS submitted via GPRS RAN */
	SMS_ON_DISK_SOURCE_IMS,			/* SMS submitted via SGs (LTE NAS) */
	SMS_ON_DISK_SOURCE_EXTERNAL,		/* SMS generated by external program */
};

struct sms_on_disk_addr {
	uint8_t ton;				/* type of number */
	uint8_t npi;				/* numbering plan information */
	uint16_t _pad;				/* align */
	char digits[21+1];			/* NUL terminated ASCII digits */
	uint8_t _pad2[6];			/* align to multiple-dword */
} __attribute__((packed));

struct sms_on_disk {
	uint32_t magic;				/* magic value to identify msg */
	uint32_t version;			/* storage format version */
	uint32_t source_id;			/* enum sms_on_disk_source */
	uint32_t flags;				/* SMS_ON_DISK_F_* bitmask */

	uint64_t received_ts;			/* receive (submit) timestamp */
	uint64_t valid_until_ts;		/* absolute validity period timestamp */

	struct sms_on_disk_addr src_addr;	/* sender address */
	struct sms_on_disk_addr dst_addr;	/* recipient address */

	uint8_t tp_pid;				/* TP-PID (protocol ID) */
	uint8_t tp_dcs;				/* TP-DCS (data coding scheme) */
	uint8_t tp_mr;				/* TP-MR (message reference) */
	uint8_t user_data_len;			/* number of septets in user_data below */

	uint8_t user_data_octets;		/* number of octets used in user_data below */
	uint8_t pad[3];

	uint8_t user_data[256];
} __attribute__ ((packed));

static void gsm_sms_addr_to_storage(struct sms_on_disk_addr *out, const struct gsm_sms_addr *in)
{
	out->ton = in->ton;
	out->npi = in->npi;
	OSMO_STRLCPY_ARRAY(out->digits, in->addr);
}

static void gsm_sms_addr_from_storage(struct gsm_sms_addr *out, const struct sms_on_disk_addr *in)
{
	out->ton = in->ton;
	out->npi = in->npi;
	OSMO_STRLCPY_ARRAY(out->addr, in->digits);
}

static enum sms_on_disk_source source_id_gsms2sod(uint32_t source)
{
	switch (source) {
	case SMS_SOURCE_MS_GSM:
		return SMS_ON_DISK_SOURCE_RAN_GSM;
	case SMS_SOURCE_MS_UMTS:
		return SMS_ON_DISK_SOURCE_RAN_UMTS;
	case SMS_SOURCE_MS_SGS:
		return SMS_ON_DISK_SOURCE_SGs;
	case SMS_SOURCE_SMPP:
		return SMS_ON_DISK_SOURCE_SMPP;
	case SMS_SOURCE_VTY:
		return SMS_ON_DISK_SOURCE_VTY;
	case SMS_SOURCE_UNKNOWN:
	default:
		return SMS_ON_DISK_SOURCE_UNKNOWN;
	}
}

/* serialize 'sms' and write it to 'fd' */
static int _sms_storage_write(struct sms_storage_inst *ssi, int fd, const struct gsm_sms *sms)
{
	struct sms_on_disk _sod, *sod = &_sod;
	uint32_t flags = 0;
	int rc;

	memset(sod, 0, sizeof(*sod));
	sod->magic = htonl(SMS_ON_DISK_MAGIC);
	sod->version = htonl(SMS_ON_DISK_VERSION);

	sod->source_id = htonl(source_id_gsms2sod(sms->source));

	if (sms->reply_path_req)
		flags |= SMS_ON_DISK_F_REPLY_PATH_REQ;
	if (sms->status_rep_req)
		flags |= SMS_ON_DISK_F_STATUS_REP_REQ;
	if (sms->is_report)
		flags |= SMS_ON_DISK_F_IS_REPORT;
	if (sms->ud_hdr_ind)
		flags |= SMS_ON_DISK_F_UD_HDR_IND;
	sod->flags = htonl(flags);

	gsm_sms_addr_to_storage(&sod->src_addr, &sms->src);
	gsm_sms_addr_to_storage(&sod->dst_addr, &sms->dst);

	osmo_store64be(sms->created, &sod->received_ts);
	osmo_store64be(sms->validity_minutes + sms->created, &sod->valid_until_ts);

	sod->tp_pid = sms->protocol_id;
	sod->tp_dcs = sms->data_coding_scheme;
	sod->tp_mr = sms->msg_ref;

	sod->user_data_len = sms->user_data_len;
	if (gsm338_get_sms_alphabet(sms->data_coding_scheme) == DCS_7BIT_DEFAULT)
		sod->user_data_octets = gsm_get_octet_len(sms->user_data_len);
	else
		sod->user_data_octets = sms->user_data_len;
	memcpy(sod->user_data, sms->user_data, sod->user_data_octets);

	rc = write(fd, sod, sizeof(*sod));
	if (rc < 0)
		return -errno;
	if (rc < sizeof(*sod))
		return -1;

	LOGP(DSMSS, LOGL_DEBUG, "Wrote SMS %llu (%s->%s, PID=0x%02x, DCS=0x%02x) to disk\n",
		sms->id, sms->src.addr, sms->dst.addr, sms->protocol_id, sms->data_coding_scheme);
	return 0;
}

static int sms_storage_write(struct sms_storage_inst *ssi, const struct gsm_sms *sms)
{
	char fq_path[PATH_MAX+1];
	int rc, fd;

	rc = _sms_gen_fq_path(ssi, fq_path, sizeof(fq_path), SUBDIR_CURRENT, sms->id);
	if (rc < 0)
		return rc;

	rc = open(fq_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (rc < 0) {
		LOGP(DSMSS, LOGL_ERROR, "Error opening SMS file '%s' for write: %s\n",
		     fq_path, strerror(errno));
		return -errno;
	}
	fd = rc;

	/* actually serialize the SMS into the on-disk storage format */
	rc = _sms_storage_write(ssi, fd, sms);

	close(fd);
	return rc;
}

static uint32_t source_id_sod2gsms(enum sms_on_disk_source sod)
{
	switch (sod) {
	case SMS_ON_DISK_SOURCE_RAN_GSM:
		return SMS_SOURCE_MS_UMTS;
	case SMS_ON_DISK_SOURCE_SGs:
		return SMS_SOURCE_MS_SGS;
	case SMS_ON_DISK_SOURCE_SMPP:
		return SMS_SOURCE_SMPP;
	case SMS_ON_DISK_SOURCE_VTY:
		return SMS_SOURCE_VTY;
	case SMS_ON_DISK_SOURCE_UNKNOWN:
	default:
		return SMS_SOURCE_UNKNOWN;
	}
}

/* read from 'fd' and de- serialize SMS into 'out' */
static int _sms_storage_read(struct sms_storage_inst *ssi, struct gsm_sms *out, int fd)
{
	struct sms_on_disk _sod, *sod = &_sod;
	uint32_t flags;
	int rc;

	rc = read(fd, sod, sizeof(*sod));
	if (rc < 0)
		return -errno;
	if (rc < sizeof(*sod))
		return -1;

	if (sod->magic != htonl(SMS_ON_DISK_MAGIC))
		return -EINVAL;

	if (sod->version != htonl(SMS_ON_DISK_VERSION))
		return -EINVAL;

	flags = ntohl(sod->flags);
	out->reply_path_req = (flags & SMS_ON_DISK_F_REPLY_PATH_REQ);
	out->status_rep_req = (flags & SMS_ON_DISK_F_STATUS_REP_REQ);
	out->is_report = (flags & SMS_ON_DISK_F_IS_REPORT);
	out->ud_hdr_ind = (flags & SMS_ON_DISK_F_UD_HDR_IND);

	out->source = source_id_sod2gsms(ntohl(sod->source_id));

	gsm_sms_addr_from_storage(&out->src, &sod->src_addr);
	gsm_sms_addr_from_storage(&out->dst, &sod->dst_addr);

	out->created = osmo_load64le(&sod->received_ts);
	out->validity_minutes = osmo_load64le(&sod->valid_until_ts) - out->created;

	out->protocol_id = sod->tp_pid;
	out->data_coding_scheme = sod->tp_dcs;
	out->msg_ref = sod->tp_mr;

	out->user_data_len = sod->user_data_len;
	memcpy(out->user_data, sod->user_data, sod->user_data_octets);

	LOGP(DSMSS, LOGL_DEBUG, "Read SMS %llu (%s->%s, PID=0x%02x, DCS=0x%02x) from disk\n",
		out->id, out->src.addr, out->dst.addr, out->protocol_id, out->data_coding_scheme);

	return 0;
}

static struct gsm_sms *sms_storage_read(struct sms_storage_inst *ssi, unsigned long long id)
{
	char fq_path[PATH_MAX+1];
	struct gsm_sms *out = sms_alloc();
	int rc, fd;

	if (!out)
		return NULL;

	rc = _sms_gen_fq_path(ssi, fq_path, sizeof(fq_path), SUBDIR_CURRENT, id);
	if (rc < 0)
		goto out_free;


	rc = open(fq_path, O_RDONLY);
	if (rc < 0) {
		LOGP(DSMSS, LOGL_ERROR, "Error opening SMS file '%s' for read: %s\n",
		     fq_path, strerror(errno));
		goto out_free;
	}
	fd = rc;

	out->id = id;

	/* actually de-serialize the SMS into the on-disk storage format */
	rc = _sms_storage_read(ssi, out, fd);

	close(fd);

	if (rc < 0)
		goto out_free;

	return out;

out_free:
	sms_free(out);
	return out;
}

static int sms_storage_delete(struct sms_storage_inst *ssi, unsigned long long id,
			      enum smss_delete_cause cause)
{
	char fq_path[PATH_MAX+1];
	const char *move_subdir = NULL;
	int rc;

	switch (cause) {
	case SMSS_DELETE_CAUSE_EXPIRED:
		if (!ssi->cfg->unlink_expired)
			move_subdir = SUBDIR_EXPIRED;
		break;
	default:
		if (!ssi->cfg->unlink_delivered)
			move_subdir = SUBDIR_DELIVERED;
		break;
	}

	rc = _sms_gen_fq_path(ssi, fq_path, sizeof(fq_path), SUBDIR_CURRENT, id);
	if (rc < 0)
		return rc;

	if (move_subdir) {
		char new_path[PATH_MAX+1];
		rc = _sms_gen_fq_path(ssi, new_path, sizeof(fq_path), move_subdir, id);
		if (rc < 0)
			return rc;

		/* just move */
		rc = rename(fq_path, new_path);
		if (rc < 0) {
			LOGP(DSMSS, LOGL_ERROR, "Error renaming SMS file '%s'->'%s':%s\n",
			     fq_path, new_path, strerror(errno));
			return -errno;
		}
	} else {
		/* delete completely */
		rc = unlink(fq_path);
		if (rc < 0) {
			LOGP(DSMSS, LOGL_ERROR, "Error deleting SMS file '%s': %s\n", fq_path,
			     strerror(errno));
			return -errno;
		}
	}

	return 0;
}

/***********************************************************************
 * inotify - get notifications about files deleted on disk
 ***********************************************************************/

#ifdef HAVE_INOTIFY
static void sms_file_was_deleted(struct sms_storage_inst *ssi, const char *fname)
{
	struct smss_s2m_evt *evt;
	unsigned long long id;
	int rc;

	rc = sscanf(fname, "%llu.osms", &id);
	if (rc != 1) {
		LOGP(DSMSS, LOGL_NOTICE, "Detected file deletion of '%s', but cannot determine "
		     "SMS ID from file name!\n", fname);
		return;
	}

	evt = s2m_alloc(ssi, SMSS_S2M_OP_SMS_DELETED_ON_DISK_IND);
	if (!evt)
		return;

	evt->sms_deleted_on_disk_ind.id = id;

	LOGP(DSMSS, LOGL_INFO, "Detected SMS %llu was deleted externally from disk\n",
	     evt->sms_deleted_on_disk_ind.id);

	rc = osmo_it_q_enqueue(ssi->storage2main.itq, evt, list);
	if (rc < 0) {
		s2m_free(ssi, evt);
	}
}

static int inotify_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct sms_storage_inst *ssi = ofd->data;
	uint8_t buf[8192] __attribute__ ((aligned(__alignof__(struct inotify_event))));
	const struct inotify_event *evt;
	int len;

	if (!(what & OSMO_FD_READ))
		return 0;

	len = read(ofd->fd, buf, sizeof(buf));
	if (len < 0)
		return len;

	for (uint8_t *ptr = buf; ptr < buf + len; ptr += sizeof(*evt) + evt->len) {
		evt = (const struct inotify_event *) ptr;

		if (evt->wd == -1 && (evt->mask & IN_Q_OVERFLOW)) {
			LOGP(DSMSS, LOGL_NOTICE, "inotify overflow: Too many delete events on "
			     "SMS filesystem, some events were lost!\n");
			continue;
		}

		if (evt->wd != ssi->inotify.wd)
			continue;

		if (evt->mask & (IN_DELETE|IN_MOVED_FROM)) {
			if (evt->len)
				sms_file_was_deleted(ssi, evt->name);
		}

		if (evt->mask & IN_IGNORED) {
			/* TODO: log ERROR: directory deleted / FS unmounted */
			LOGP(DSMSS, LOGL_ERROR, "inotify reports entire SMS storage directory "
			     "deleted or filesystem unmounted!\n");
		}
	}

	return 0;
}


#endif


/***********************************************************************
 * Storage Thread
 ***********************************************************************/

/* main thread has sent us something */
static void main2storage_read_cb(struct osmo_it_q *q, struct llist_head *item)
{
	struct smss_m2s_evt *evt = container_of(item, struct smss_m2s_evt, list);
	struct sms_storage_inst *ssi = q->data;

	switch (evt->op) {
	case SMSS_M2S_OP_NULL:
		break;
	case SMSS_M2S_OP_SMS_TO_DISK_REQ:
		/* main thread asks storage thread to store a SMS on disk */
		sms_storage_write(ssi, evt->sms_to_disk_req.sms);
		break;
	case SMSS_M2S_OP_SMS_DELETE_FROM_DISK_REQ:
		/* main thread asks storage thread to delete a SMS from disk (expiration, delivered) */
		sms_storage_delete(ssi, evt->sms_delete_from_disk_req.id,
				   evt->sms_delete_from_disk_req.cause);
		break;
	default:
		break;
	}
	m2s_free(ssi, evt);
}

static void boot_read_tmr_cb(void *data)
{
	struct sms_storage_inst *ssi = data;
	struct smss_s2m_evt *evt;
	unsigned long long id;
	struct dirent *dent;
	struct gsm_sms *out;
	int rc;

	OSMO_ASSERT(ssi->boot_read.dir);

	errno = 0;
	dent = readdir(ssi->boot_read.dir);
	if (!dent) {
		if (errno) {
			LOGP(DSMSS, LOGL_ERROR, "Error during bootstrap readdir: %s\n", strerror(errno));
		} else {
			LOGP(DSMSS, LOGL_NOTICE, "Completed bootstrap read of storage: %u SMS read\n",
			     ssi->boot_read.count);
		}
		closedir(ssi->boot_read.dir);
		ssi->boot_read.dir = NULL;
		return;
	}

	/* skip anything that's not a normal file */
	if (dent->d_type != DT_REG) {
		/* suppress printing log messages about . and .. */
		if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
			goto next;
		LOGP(DSMSS, LOGL_NOTICE, "bootstrap read: skipping '%s' (not a regular file)\n",
		     dent->d_name);
		goto next;
	}

	rc = sscanf(dent->d_name, "%llu.osms", &id);
	if (rc != 1) {
		LOGP(DSMSS, LOGL_NOTICE, "Found file '%s', but cannot determine "
		     "SMS ID from file name!\n", dent->d_name);
		goto next;
	}

	/* skip any unparseable IDs */
	if (id == ULLONG_MAX) {
		LOGP(DSMSS, LOGL_NOTICE, "bootstrap read: skipping '%s' (not unsigned long long)\n",
		     dent->d_name);
		goto next;
	}

	out = sms_storage_read(ssi, id);
	if (!out)
		goto next;

	evt = s2m_alloc(ssi, SMSS_S2M_OP_SMS_FROM_DISK_IND);
	if (!evt)
		goto next;

	evt->sms_from_disk_ind.sms = out;

	rc = osmo_it_q_enqueue(ssi->storage2main.itq, evt, list);
	if (rc < 0)
		s2m_free(ssi, evt);

	ssi->boot_read.count++;

next:
	/* read next message in 50ms to avoid overloading the it_q or the MSC in general */
	osmo_timer_schedule(&ssi->boot_read.timer, 0, 50000);
}

/* SMS storage thread main function */
static void *sms_storage_main(void *arg)
{
	struct sms_storage_inst *ssi = arg;
	char current_dir[PATH_MAX+8+1];

	osmo_ctx_init("sms-storage");
	osmo_select_init();

	snprintf(current_dir, sizeof(current_dir), "%s/%s", ssi->cfg->storage_dir, SUBDIR_CURRENT);
	ssi->boot_read.dir = opendir(current_dir);
	if (!ssi->boot_read.dir) {
		LOGP(DSMSS, LOGL_ERROR, "Cannot open SMS directory '%s': %s\n",
			ssi->cfg->storage_dir, strerror(errno));
		pthread_exit(NULL);
	}
	osmo_timer_setup(&ssi->boot_read.timer, boot_read_tmr_cb, ssi);

	/* register inter-thread queue to our local thread select/poll loop */
	OSMO_ASSERT(osmo_fd_register(&ssi->main2storage.itq->event_ofd) == 0);

#ifdef HAVE_INOTIFY
	/* register inotify fd to our local thread select/poll loop */
	OSMO_ASSERT(osmo_fd_register(&ssi->inotify.ofd) == 0);
#endif

	/* TODO: on startup: iterate over all files, read them and send to main thread */
	boot_read_tmr_cb(ssi);

	while (true) {
		osmo_select_main(0);
	}
}

/***********************************************************************
 * Main Thread
 ***********************************************************************/

/* storage thread has sent us something */
static void storage2main_read_cb(struct osmo_it_q *q, struct llist_head *item)
{
	struct smss_s2m_evt *evt = container_of(item, struct smss_s2m_evt, list);
	struct sms_storage_inst *ssi = q->data;
	struct gsm_sms *sms = NULL;

	switch (evt->op) {
	case SMSS_S2M_OP_NULL:
		break;
	case SMSS_S2M_OP_SMS_FROM_DISK_IND:
		/* SMS storage has read a SMS from disk, asks main thread to add it to queue */
		sms = evt->sms_from_disk_ind.sms;
		sms->state = GSM_SMS_ST_DELIVERY_PENDING;
		/* add to global list of pending SMS */
		llist_add_tail(&sms->list, &ssi->pending);
		/* add to per-subscriber list of pending SMS */
		if (sms->receiver)
			llist_add_tail(&sms->vsub_list, &sms->receiver->sms.pending);
		break;
	case SMSS_S2M_OP_SMS_TO_DISK_CFM:
		/* SMS storage confirms having written SMS to disk; main thread adds it to queue */
		sms = evt->sms_to_disk_cfm.sms;
		sms->state = GSM_SMS_ST_DELIVERY_PENDING;
		/* add to global list of pending SMS */
		llist_add_tail(&sms->list, &ssi->pending);
		/* add to per-subscriber list of pending SMS */
		if (sms->receiver)
			llist_add_tail(&sms->vsub_list, &sms->receiver->sms.pending);
		break;
	case SMSS_S2M_OP_SMS_DELETED_ON_DISK_IND:
		/* SMS storage has detected a sms was deleted from disk; main thread must forget it */
		sms_free(sms);
		break;
	default:
		break;

	}
	s2m_free(ssi, evt);
}

/* request storage of given SMS to disk. Return value just confirms we were able
 * to enqueue the request to the storage thread, and *not* that it was stored. */
int sms_storage_to_disk_req(struct sms_storage_inst *ssi, struct gsm_sms *sms)
{
	struct smss_m2s_evt *evt = m2s_alloc(ssi, SMSS_M2S_OP_SMS_TO_DISK_REQ);
	enum gsm_sms_state st = sms->state;
	int rc;

	if (!evt)
		return -ENOMEM;

	sms->state = GSM_SMS_ST_STORAGE_PENDING;
	evt->sms_to_disk_req.sms = sms;

	rc = osmo_it_q_enqueue(ssi->main2storage.itq, evt, list);
	if (rc < 0) {
		m2s_free(ssi, evt);
		sms->state = st;
		return rc;
	}
	return 0;
}

/* request storage of given SMS to disk. Return value just confirms we were able
 * to enqueue the request to the storage thread, and *not* that it was deleted. */
int sms_storage_delete_from_disk_req(struct sms_storage_inst *ssi, unsigned long long id,
				     enum smss_delete_cause cause)
{
	struct smss_m2s_evt *evt = m2s_alloc(ssi, SMSS_M2S_OP_SMS_DELETE_FROM_DISK_REQ);
	int rc;

	if (!evt)
		return -ENOMEM;

	evt->sms_delete_from_disk_req.id = id;
	evt->sms_delete_from_disk_req.cause = cause;

	rc = osmo_it_q_enqueue(ssi->main2storage.itq, evt, list);
	if (rc < 0) {
		m2s_free(ssi, evt);
		return rc;
	}
	return 0;
}

/***********************************************************************
 * Initialization
 ***********************************************************************/

static int sms_storage_ensure_subdir(const struct sms_storage_cfg *scfg, const char *subdir)
{
	char sub_dir[PATH_MAX+8+1];
	struct stat st;
	int rc;

	snprintf(sub_dir, sizeof(sub_dir), "%s/%s", scfg->storage_dir, subdir);

	rc = stat(sub_dir, &st);
	if (rc < 0) {
		if (errno == ENOENT) {
			LOGP(DSMSS, LOGL_NOTICE, "SMS storage sub-dir '%s' doesn't exist, attempting to "
			     "create it\n", sub_dir);
			if (mkdir(sub_dir, 0700) != 0) {
				LOGP(DSMSS, LOGL_ERROR, "Unable to create SMS storage sub-dir '%s': %s\n",
		     		     sub_dir, strerror(errno));
				return -errno;
			}
		} else {
			LOGP(DSMSS, LOGL_ERROR, "Unable to access SMS storage sub-dir '%s': %s\n",
			     sub_dir, strerror(errno));
			return -errno;
		}
	}
	/* TODO: test if we can write */

	return 0;
}

static int sms_storage_ensure_subdirs(const struct sms_storage_cfg *scfg)
{
	int rc;

	rc = sms_storage_ensure_subdir(scfg, SUBDIR_CURRENT);
	if (rc < 0)
		return rc;

	rc = sms_storage_ensure_subdir(scfg, SUBDIR_DELIVERED);
	if (rc < 0)
		return rc;

	rc = sms_storage_ensure_subdir(scfg, SUBDIR_EXPIRED);
	if (rc < 0)
		return rc;

	return 0;
}


struct sms_storage_inst *sms_storage_init(void *ctx, const struct sms_storage_cfg *scfg)
{
	struct sms_storage_inst *ssi = talloc_zero(ctx, struct sms_storage_inst);
	struct stat st;
	int rc;

	if (!ssi)
		return NULL;

	ssi->cfg = scfg;
	INIT_LLIST_HEAD(&ssi->pending);

	/* test if scfg->storage_dir exists */
	rc = stat(scfg->storage_dir, &st);
	if (rc < 0) {
		if (errno == ENOENT) {
			LOGP(DSMSS, LOGL_NOTICE, "SMS storage path '%s' doesn't exist, attempting to "
			     "create it\n", scfg->storage_dir);
			if (mkdir(scfg->storage_dir, 0700) != 0) {
				LOGP(DSMSS, LOGL_ERROR, "Unable to create SMS storage dir '%s': %s\n",
		     		     scfg->storage_dir, strerror(errno));
				return NULL;
			}
		} else {
			LOGP(DSMSS, LOGL_ERROR, "Unable to access storage path '%s': %s\n",
			     scfg->storage_dir, strerror(errno));
			return NULL;
		}
	}
	/* TODO: test if we can write */

	rc = sms_storage_ensure_subdirs(scfg);
	if (rc < 0)
		goto out_free;

	ssi->main2storage.itq = osmo_it_q_alloc(ssi, "sms_main2storage", 1000, main2storage_read_cb, ssi);
	if (!ssi->main2storage.itq)
		goto out_free;
	pthread_mutex_init(&ssi->main2storage.ctx_mutex, NULL);

	ssi->storage2main.itq = osmo_it_q_alloc(ssi, "sms_storage2main", 1000, storage2main_read_cb, ssi);
	if (!ssi->storage2main.itq)
		goto out_main2storage;
	pthread_mutex_init(&ssi->storage2main.ctx_mutex, NULL);

	/* register storage->main inter-thread queue to main thread select/poll loop */
	rc = osmo_fd_register(&ssi->storage2main.itq->event_ofd);
	if (rc < 0)
		goto out_storage2main;

#ifdef HAVE_INOTIFY
	int inotify_fd = inotify_init1(IN_NONBLOCK);
	char current_dir[PATH_MAX+8+1];

	if (inotify_fd < 0) {
		LOGP(DSMSS, LOGL_ERROR, "Error during inotify_init(): %s\n", strerror(errno));
		goto out_m2s_unreg;
	}
	/* just setup, don't register.  We later register this in the storage thread! */
	osmo_fd_setup(&ssi->inotify.ofd, inotify_fd, OSMO_FD_READ, inotify_fd_cb, ssi, 0);

	snprintf(current_dir, sizeof(current_dir), "%s/%s", scfg->storage_dir, SUBDIR_CURRENT);
	rc = inotify_add_watch(inotify_fd, current_dir, IN_DELETE | IN_MOVED_FROM | IN_ONLYDIR);
	if (rc < 0) {
		LOGP(DSMSS, LOGL_ERROR, "Cannot add inotify watcher for '%s': %s\n",
			current_dir, strerror(errno));
		goto out_close_inotify;
	}
	ssi->inotify.wd = rc;
#endif

	if (pthread_create(&ssi->thread, NULL, sms_storage_main, ssi)) {
		LOGP(DSMSS, LOGL_ERROR, "Error starting SMS storage thread\n");
		goto out_all;
	}

	return ssi;

out_all:
#ifdef HAVE_INOTIFY
out_close_inotify:
	close(inotify_fd);
#endif
out_m2s_unreg:
	osmo_fd_unregister(&ssi->storage2main.itq->event_ofd);
out_storage2main:
	osmo_it_q_destroy(ssi->storage2main.itq);
out_main2storage:
	osmo_it_q_destroy(ssi->main2storage.itq);
out_free:
	talloc_free(ssi);

	return NULL;
}
