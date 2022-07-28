
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

#include <osmocom/core/logging.h>
#include <osmocom/netif/stream.h>
#include <osmocom/smpp/smpp_smsc.h>

/*! \brief retrieve SMPP command ID from a msgb */
uint32_t smpp_msgb_cmdid(struct msgb *msg)
{
	uint8_t *tmp = msgb_data(msg) + 4;
	return ntohl(*(uint32_t *)tmp);
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
