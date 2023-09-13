/* GSM Mobile Radio Interface Layer 3 messages on the A-bis interface
 * 3GPP TS 04.08 version 7.21.0 Release 1998 / ETSI TS 100 940 V7.21.0 */

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008, 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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
 *
 */

#ifndef _MNCC_H
#define _MNCC_H

#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/mncc.h>

#include <stdint.h>
#include <netinet/in.h>

struct gsm_network;
struct msgb;
struct gsm0808_channel_type;


/* One end of a call */
struct gsm_call {
	struct llist_head entry;

	/* network handle */
	struct gsm_network *net;

	/* the 'local' transaction */
	uint32_t callref;
	/* the 'remote' transaction */
	uint32_t remote_ref;
};

#define MNCC_SETUP_REQ		0x0101
#define MNCC_SETUP_IND		0x0102
#define MNCC_SETUP_RSP		0x0103
#define MNCC_SETUP_CNF		0x0104
#define MNCC_SETUP_COMPL_REQ	0x0105
#define MNCC_SETUP_COMPL_IND	0x0106
/* MNCC_REJ_* is performed via MNCC_REL_* */
#define MNCC_CALL_CONF_IND	0x0107
#define MNCC_CALL_PROC_REQ	0x0108
#define MNCC_PROGRESS_REQ	0x0109
#define MNCC_ALERT_REQ		0x010a
#define MNCC_ALERT_IND		0x010b
#define MNCC_NOTIFY_REQ		0x010c
#define MNCC_NOTIFY_IND		0x010d
#define MNCC_DISC_REQ		0x010e
#define MNCC_DISC_IND		0x010f
#define MNCC_REL_REQ		0x0110
#define MNCC_REL_IND		0x0111
#define MNCC_REL_CNF		0x0112
#define MNCC_FACILITY_REQ	0x0113
#define MNCC_FACILITY_IND	0x0114
#define MNCC_START_DTMF_IND	0x0115
#define MNCC_START_DTMF_RSP	0x0116
#define MNCC_START_DTMF_REJ	0x0117
#define MNCC_STOP_DTMF_IND	0x0118
#define MNCC_STOP_DTMF_RSP	0x0119
#define MNCC_MODIFY_REQ		0x011a
#define MNCC_MODIFY_IND		0x011b
#define MNCC_MODIFY_RSP		0x011c
#define MNCC_MODIFY_CNF		0x011d
#define MNCC_MODIFY_REJ		0x011e
#define MNCC_HOLD_IND		0x011f
#define MNCC_HOLD_CNF		0x0120
#define MNCC_HOLD_REJ		0x0121
#define MNCC_RETRIEVE_IND	0x0122
#define MNCC_RETRIEVE_CNF	0x0123
#define MNCC_RETRIEVE_REJ	0x0124
#define MNCC_USERINFO_REQ	0x0125
#define MNCC_USERINFO_IND	0x0126
#define MNCC_REJ_REQ		0x0127
#define MNCC_REJ_IND		0x0128

#define MNCC_BRIDGE		0x0200
#define MNCC_FRAME_RECV		0x0201
#define MNCC_FRAME_DROP		0x0202
#define MNCC_LCHAN_MODIFY	0x0203
#define MNCC_RTP_CREATE		0x0204
#define MNCC_RTP_CONNECT	0x0205
#define MNCC_RTP_FREE		0x0206

#define GSM_TCHF_FRAME		0x0300
#define GSM_TCHF_FRAME_EFR	0x0301
#define GSM_TCHH_FRAME		0x0302
#define GSM_TCH_FRAME_AMR	0x0303
#define GSM_BAD_FRAME		0x03ff

#define MNCC_SOCKET_HELLO	0x0400

#define GSM_MAX_FACILITY	128
#define GSM_MAX_SSVERSION	128
#define GSM_MAX_USERUSER	128

#define	MNCC_F_BEARER_CAP	0x0001
#define MNCC_F_CALLED		0x0002
#define MNCC_F_CALLING		0x0004
#define MNCC_F_REDIRECTING	0x0008
#define MNCC_F_CONNECTED	0x0010
#define MNCC_F_CAUSE		0x0020
#define MNCC_F_USERUSER		0x0040
#define MNCC_F_PROGRESS		0x0080
#define MNCC_F_EMERGENCY	0x0100
#define MNCC_F_FACILITY		0x0200
#define MNCC_F_SSVERSION	0x0400
#define MNCC_F_CCCAP		0x0800
#define MNCC_F_KEYPAD		0x1000
#define MNCC_F_SIGNAL		0x2000
#define MNCC_F_GCR		0x4000

/* UPDATEME when adding new MNCC_F_* entries above */
#define MNCC_F_ALL		0x7fff

struct gsm_mncc {
	/* context based information */
	uint32_t	msg_type;
	uint32_t	callref;

	/* which fields are present */
	uint32_t	fields;

	/* data derived information (MNCC_F_ based) */
	struct gsm_mncc_bearer_cap	bearer_cap;
	struct gsm_mncc_number		called;
	struct gsm_mncc_number		calling;
	struct gsm_mncc_number		redirecting;
	struct gsm_mncc_number		connected;
	struct gsm_mncc_cause		cause;
	struct gsm_mncc_progress	progress;
	struct gsm_mncc_useruser	useruser;
	struct gsm_mncc_facility	facility;
	struct gsm_mncc_cccap		cccap;
	struct gsm_mncc_ssversion	ssversion;
	struct	{
		int		sup;
		int		inv;
	} clir;
	int		signal;

	/* data derived information, not MNCC_F based */
	int		keypad;
	int		more;
	int		notify; /* 0..127 */
	int		emergency;
	char		imsi[16];

	unsigned char	lchan_type;
	unsigned char	lchan_mode;

	/* Global Call Reference (encoded as per 3GPP TS 29.205) */
	uint8_t		gcr[16];

	/* A buffer to contain SDP ('\0' terminated) */
	char		sdp[1024];
};

struct gsm_data_frame {
	uint32_t	msg_type;
	uint32_t	callref;
	unsigned char	data[0];
};

#define MNCC_SOCK_VERSION	8
struct gsm_mncc_hello {
	uint32_t	msg_type;
	uint32_t	version;

	/* send the sizes of the structs */
	uint32_t	mncc_size;
	uint32_t	data_frame_size;

	/* send some offsets */
	uint32_t	called_offset;
	uint32_t	signal_offset;
	uint32_t	emergency_offset;
	uint32_t	lchan_type_offset;
};

struct gsm_mncc_rtp {
	uint32_t	msg_type;
	uint32_t	callref;
	struct sockaddr_storage addr;
	uint32_t	payload_type;
	uint32_t	payload_msg_type;
	char		sdp[1024];
};

struct gsm_mncc_bridge {
	uint32_t	msg_type;
	uint32_t	callref[2];
};

union mncc_msg {
	uint32_t msg_type;
	struct gsm_mncc signal;
	struct gsm_mncc_hello hello;
	struct gsm_data_frame data_frame;
	struct gsm_mncc_rtp rtp;
	struct gsm_mncc_bridge bridge;
};

const char *get_mncc_name(int value);
void mncc_set_cause(struct gsm_mncc *data, int loc, int val);

/* input from CC code into mncc_builtin */
int int_mncc_recv(struct gsm_network *net, struct msgb *msg);

/* input from CC code into mncc_sock */
int mncc_sock_from_cc(struct gsm_network *net, struct msgb *msg);

int mncc_sock_init(struct gsm_network *net, const char *sock_path);

#define mncc_is_data_frame(msg_type) \
	(msg_type == GSM_TCHF_FRAME \
		|| msg_type == GSM_TCHF_FRAME_EFR \
		|| msg_type == GSM_TCHH_FRAME \
		|| msg_type == GSM_TCH_FRAME_AMR \
		|| msg_type == GSM_BAD_FRAME)

int mncc_prim_check(const struct gsm_mncc *mncc_prim, unsigned int len);
int mncc_check_sdp_termination(const char *label, const struct gsm_mncc *mncc, unsigned int len, const char *sdp);

int mncc_bearer_cap_to_channel_type(struct gsm0808_channel_type *ct, const struct gsm_mncc_bearer_cap *bc);

#endif
