#ifndef _GSM_04_11_H
#define _GSM_04_11_H

#include <osmocom/gsm/protocol/gsm_04_11.h>
#include <osmocom/msc/gsm_04_11_gsup.h>

struct vlr_subscr;
struct ran_conn;
struct gsm_trans;
struct msc_a;

#define UM_SAPI_SMS 3	/* See GSM 04.05/04.06 */

struct gsm_network;
struct msgb;

int gsm0411_rcv_sms(struct msc_a *msc_a, struct msgb *msg);

struct gsm_sms *sms_alloc(void);
void sms_free(struct gsm_sms *sms);
struct gsm_sms *sms_from_text(struct vlr_subscr *receiver,
			      const char *sender_msisdn,
			      int dcs, const char *text);

int gsm411_send_sms(struct gsm_network *net,
		    struct vlr_subscr *vsub,
		    struct gsm_sms *sms);
int gsm411_send_rp_data(struct gsm_network *net, struct vlr_subscr *vsub,
			size_t sm_rp_oa_len, const uint8_t *sm_rp_oa,
			size_t sm_rp_ud_len, const uint8_t *sm_rp_ud,
			bool sm_rp_mmts_ind, const uint8_t *gsup_source_name,
			size_t gsup_source_name_len);

void gsm411_sapi_n_reject(struct msc_a *msc_a);

int gsm411_send_rp_ack(struct gsm_trans *trans, uint8_t msg_ref);
int gsm411_send_rp_error(struct gsm_trans *trans, uint8_t msg_ref,
			 uint8_t cause);

#endif
