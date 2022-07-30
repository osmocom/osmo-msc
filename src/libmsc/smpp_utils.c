
/* (C) 2012-2022 by Harald Welte <laforge@gnumonks.org>
 *
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
 */

#include "config.h"

#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/logging.h>
#include <osmocom/netif/stream.h>

#include <osmocom/msc/debug.h>
#include <osmocom/msc/smpp.h>

#include <smpp34.h>
#include <smpp34_structs.h>
#include <smpp34_params.h>

/*! \brief retrieve SMPP command ID from a msgb */
uint32_t smpp_msgb_cmdid(struct msgb *msg)
{
	uint8_t *tmp = msgb_data(msg) + 4;
	return ntohl(*(uint32_t *)tmp);
}

uint32_t esme_inc_seq_nr(struct esme *esme)
{
	esme->own_seq_nr++;
	if (esme->own_seq_nr > 0x7fffffff)
		esme->own_seq_nr = 1;

	return esme->own_seq_nr;
}

void esme_read_state_reset(struct esme *esme)
{
	if (esme->read_msg) {
		msgb_free(esme->read_msg);
		esme->read_msg = NULL;
	}
	esme->read_idx = 0;
	esme->read_len = 0;
	esme->read_state = READ_ST_IN_LEN;
}

/* !\brief call-back when per-ESME TCP socket has some data to be read */
int esme_read_callback(struct esme *esme, int fd)
{
	uint32_t len;
	uint8_t *lenptr = (uint8_t *) &len;
	uint8_t *cur;
	struct msgb *msg;
	ssize_t rdlen, rc;

	switch (esme->read_state) {
	case READ_ST_IN_LEN:
		rdlen = sizeof(uint32_t) - esme->read_idx;
		rc = read(fd, lenptr + esme->read_idx, rdlen);
		if (rc < 0)
			LOGPESME(esme, LOGL_ERROR, "read returned %zd (%s)\n", rc, strerror(errno));
		OSMO_FD_CHECK_READ(rc, dead_socket);

		esme->read_idx += rc;

		if (esme->read_idx >= sizeof(uint32_t)) {
			esme->read_len = ntohl(len);
			if (esme->read_len < 8 || esme->read_len > UINT16_MAX) {
				LOGPESME(esme, LOGL_ERROR, "length invalid %u\n",  esme->read_len);
				goto dead_socket;
			}

			msg = msgb_alloc(esme->read_len, "SMPP Rx");
			if (!msg)
				return -ENOMEM;
			esme->read_msg = msg;
			cur = msgb_put(msg, sizeof(uint32_t));
			memcpy(cur, lenptr, sizeof(uint32_t));
			esme->read_state = READ_ST_IN_MSG;
			esme->read_idx = sizeof(uint32_t);
		}
		break;
	case READ_ST_IN_MSG:
		msg = esme->read_msg;
		rdlen = esme->read_len - esme->read_idx;
		rc = read(fd, msg->tail, OSMO_MIN(rdlen, msgb_tailroom(msg)));
		if (rc < 0)
			LOGPESME(esme, LOGL_ERROR, "read returned %zd (%s)\n", rc, strerror(errno));
		OSMO_FD_CHECK_READ(rc, dead_socket);

		esme->read_idx += rc;
		msgb_put(msg, rc);

		if (esme->read_idx >= esme->read_len)
			return 1;
		break;
	}

	return 0;
dead_socket:
	esme_read_state_reset(esme);
	return -EBADF;
}

int esme_write_callback(struct esme *esme, int fd, struct msgb *msg)
{
	int rc = write(fd, msgb_data(msg), msgb_length(msg));
	if (rc == 0) {
		return 0;
	} else if (rc < msgb_length(msg)) {
		LOGPESME(esme, LOGL_ERROR, "Short write\n");
		return -1;
	}

	return rc;
}

/*! \brief pack a libsmpp34 data strcutrure and send it to the ESME */
int pack_and_send(struct esme *esme, uint32_t type, void *ptr)
{
	struct msgb *msg;
	int rc, rlen;

	/* the socket was closed. Avoid allocating + enqueueing msgb, see
	 * https://osmocom.org/issues/3278 */
	if (!esme->srv)
		return -EIO;

	msg = msgb_alloc(4096, "SMPP_Tx");
	if (!msg)
		return -ENOMEM;

	rc = smpp34_pack(type, msg->tail, msgb_tailroom(msg), &rlen, ptr);
	if (rc != 0) {
		LOGPESMERR(esme, "during smpp34_pack()\n");
		msgb_free(msg);
		return -EINVAL;
	}
	msgb_put(msg, rlen);

	osmo_stream_srv_send(esme->srv, msg);

	return 0;
}

int smpp_determine_scheme(uint8_t dcs, uint8_t *data_coding, int *mode)
{
	if ((dcs & 0xF0) == 0xF0) {
		if (dcs & 0x04) {
			/* bit 2 == 1: 8bit data */
			*data_coding = 0x02;
			*mode = MODE_8BIT;
		} else {
			/* bit 2 == 0: default alphabet */
			*data_coding = 0x01;
			*mode = MODE_7BIT;
		}
	} else if ((dcs & 0xE0) == 0) {
		switch (dcs & 0xC) {
		case 0:
			*data_coding = 0x01;
			*mode = MODE_7BIT;
			break;
		case 4:
			*data_coding = 0x02;
			*mode = MODE_8BIT;
			break;
		case 8:
			*data_coding = 0x08;     /* UCS-2 */
			*mode = MODE_8BIT;
			break;
		default:
			goto unknown_mo;
		}
	} else {
unknown_mo:
		LOGP(DLSMS, LOGL_ERROR, "SMPP MO Unknown Data Coding 0x%02x\n", dcs);
		return -1;
	}

	return 0;

}

/* convert a 'struct tm' holding relative time to an absolute one by adding it to t_now */
static void relative2absolute(struct tm *tm, time_t t_now)
{
	struct tm tm_now;

	localtime_r(&t_now, &tm_now);

	tm->tm_year += tm_now.tm_year;
	tm->tm_mon += tm_now.tm_mon;
	tm->tm_mday += tm_now.tm_mday;
	tm->tm_hour += tm_now.tm_hour;
	tm->tm_min += tm_now.tm_min;
	tm->tm_sec += tm_now.tm_sec;
}

#ifndef HAVE_TIMEGM
/* for systems without a timegm() function, provide a reimplementation */
static time_t timegm(struct tm *tm)
{
	const char *orig_tz = getenv("TZ");
	time_t ret;

	setenv("TZ", "UTC", 1);

	ret = mktime(tm);

	if (orig_tz)
		setenv("TZ", orig_tz, 1);
	else
		unsetenv("TZ");

	return ret;
}
#endif


/*! Parse a SMPP time format as defined in SMPP v3.4 7.1.1.
 *  \param[in] vp string containing the time as encoded in SMPP v3.4
 *  \param[in] t_now pointer to a time value for 'now'. Can be NULL, then we call time() ourselves.
 *  \returns time_t value in seconds since the epoch of the absolute decoded time */
time_t smpp_parse_time_format(const char *vp, time_t *t_now)
{
	unsigned int year, month, day, hour, minute, second, tenth, gmt_off_quarter;
	char plus_minus_relative;
	int gmt_off_minutes;
	struct tm tm;
	time_t ret;
	int rc;

	memset(&tm, 0, sizeof(tm));

	if (vp[0] == '\0')
		return 0;

	/* YYMMDDhhmmsstnnp (where p can be -, + or R) */
	rc = sscanf(vp, "%2u%2u%2u%2u%2u%2u%1u%2u%c", &year, &month, &day, &hour, &minute,
		    &second, &tenth, &gmt_off_quarter, &plus_minus_relative);
	if (rc != 9)
		return (time_t) -1;

	tm.tm_year = year;
	/* month handling differs between absolute/relative below... */
	tm.tm_mday = day;
	tm.tm_hour = hour;
	tm.tm_min = minute;
	tm.tm_sec = second;
	tm.tm_isdst = 0;

	switch (plus_minus_relative) {
	case '+':	/* time is in quarter hours advanced compared to UTC */
		if (year < 70)
			tm.tm_year += 100;
		tm.tm_mon = month - 1;
		gmt_off_minutes = 15 * gmt_off_quarter;
		tm.tm_min -= gmt_off_minutes;
		ret = timegm(&tm);
		break;
	case '-':	/* time is in quarter hours retared compared to UTC */
		if (year < 70)
			tm.tm_year += 100;
		tm.tm_mon = month - 1;
		gmt_off_minutes = 15 * gmt_off_quarter;
		tm.tm_min += gmt_off_minutes;
		ret = timegm(&tm);
		break;
	case 'R':
		/* relative time */
		tm.tm_mon = month;
		if (t_now)
			relative2absolute(&tm, *t_now);
		else
			relative2absolute(&tm, time(NULL));
		/* here we do want local time, as we're passing local time in above! */
		ret = mktime(&tm);
		break;
	default:
		return (time_t) -1;
	}

	return ret;
}
