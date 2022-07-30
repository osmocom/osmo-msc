#pragma once

#define SMPP_DEFAULT_PORT 2775

/* Length limits according to SMPP 3.4 spec including NUL-byte: */
#define SMPP_SYS_ID_LEN	15
#define SMPP_PASSWD_LEN	8

#define MODE_7BIT	7
#define MODE_8BIT	8

enum esme_read_state {
	READ_ST_IN_LEN = 0,
	READ_ST_IN_MSG = 1,
};

struct esme {
	uint32_t own_seq_nr;

    /* represents the TCP connection we accept()ed for this ESME */
	struct osmo_stream_srv *srv;
	struct osmo_wqueue wqueue;
	enum esme_read_state read_state;
	uint32_t read_len;
	uint32_t read_idx;
	struct msgb *read_msg;

	uint8_t smpp_version;
	char system_id[SMPP_SYS_ID_LEN + 1];
	char password[SMPP_SYS_ID_LEN + 1];
};

#define LOGPESME(ESME, LEVEL, FMT, ARGS...)            \
	LOGP(DSMPP, LEVEL, "[%s] " FMT, (ESME)->system_id, ##ARGS)

#define LOGPESMERR(ESME, FMT, ARGS...)                 \
	LOGPESME(ESME, LOGL_ERROR, "Error (%s) " FMT, smpp34_strerror, ##ARGS)

/*! \brief Ugly wrapper. libsmpp34 should do this itself! */
#define SMPP34_UNPACK(rc, type, str, data, len) {	\
		memset(str, 0, sizeof(*str));				\
		rc = smpp34_unpack(type, str, data, len); }

#define PACK_AND_SEND(esme, ptr)	pack_and_send(esme, (ptr)->command_id, ptr)

/*! \brief initialize the libsmpp34 data structure for a response */
#define INIT_RESP(type, resp, req) {						\
		memset((resp), 0, sizeof(*(resp)));                 \
		(resp)->command_length	= 0;						\
		(resp)->command_id	= type;							\
		(resp)->command_status	= ESME_ROK;					\
		(resp)->sequence_number	= (req)->sequence_number; }

/* This macro should be called after a call to read() in the read_cb of an
 * osmo_fd to properly check for errors.
 * rc is the return value of read, err_label is the label to jump to in case of
 * an error. The code there should handle closing the connection.
 * FIXME: This code should go in libosmocore utils.h so it can be used by other
 * projects as well.
 * */
#define OSMO_FD_CHECK_READ(rc, err_label) do {				\
	if (rc < 0) {                                           \
		/* EINTR is a non-fatal error, just try again */    \
		if (errno == EINTR)                                  \
			return 0;                                       \
		goto err_label;                                     \
	} else if (rc == 0) {                                    \
		goto err_label;                                     \
	}                                        } while (0)

uint32_t smpp_msgb_cmdid(struct msgb *msg);
uint32_t esme_inc_seq_nr(struct esme *esme);
void esme_read_state_reset(struct esme *esme);
int esme_write_callback(struct esme *esme, int fd, struct msgb *msg);
int esme_read_callback(struct esme *esme, int fd);
int pack_and_send(struct esme *esme, uint32_t type, void *ptr);
