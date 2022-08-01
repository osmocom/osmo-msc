#pragma once

#include <osmocom/msc/gsm_data.h>

/* Length limits according to SMPP 3.4 spec including NUL-byte: */
#define SMPP_SYS_ID_LEN	15
#define SMPP_PASSWD_LEN	8

enum esme_read_state {
	READ_ST_IN_LEN = 0,
	READ_ST_IN_MSG = 1,
};

/* struct representing SMPP's External Short Messaging Entity */
struct esme {
	uint32_t own_seq_nr;

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

struct esme *esme_alloc(void *ctx);
uint32_t smpp_msgb_cmdid(struct msgb *msg);
uint32_t esme_inc_seq_nr(struct esme *esme);
int pack_and_send(struct esme *esme, uint32_t type, void *ptr);
int smpp_msc_alloc_init(void *ctx);
int smpp_msc_start(struct gsm_network *net);
