#ifndef _GSM_04_08_H
#define _GSM_04_08_H

#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/msc/transaction.h>

struct msgb;
struct gsm_bts;
struct gsm_network;
struct gsm_trans;
struct ran_conn;
struct amr_multirate_conf;
struct amr_mode;
struct msc_a;

#define GSM48_ALLOC_SIZE	2048
#define GSM48_ALLOC_HEADROOM	256

static inline struct msgb *gsm48_msgb_alloc_name(const char *name)
{
	return msgb_alloc_headroom(GSM48_ALLOC_SIZE, GSM48_ALLOC_HEADROOM,
				   name);
}

void cm_service_request_concludes(struct msc_a *msc_a, struct msgb *msg, enum osmo_cm_service_type type);

/* config options controlling the behaviour of the lower leves */
void gsm0408_clear_all_trans(struct gsm_network *net, enum trans_type type);

int gsm0408_rcvmsg(struct msgb *msg, uint8_t link_id);
/* don't use "enum gsm_chreq_reason_t" to avoid circular dependency */
void gsm_net_update_ctype(struct gsm_network *net);

int gsm48_tx_simple(struct msc_a *msc_a, uint8_t pdisc, uint8_t msg_type);
int gsm48_tx_mm_info(struct msc_a *msc_a);
int gsm48_tx_mm_auth_req(struct msc_a *msc_a, uint8_t *rand, uint8_t *autn, int key_seq);
int gsm48_tx_mm_auth_rej(struct msc_a *msc_a);
int gsm48_tx_mm_serv_ack(struct msc_a *msc_a);
int gsm48_tx_mm_serv_rej(struct msc_a *msc_a, enum gsm48_reject_value value);
int gsm48_send_rr_release(struct gsm_lchan *lchan);
int gsm48_send_rr_ciph_mode(struct gsm_lchan *lchan, int want_imeisv);
int gsm48_send_rr_app_info(struct msc_a *msc_a, uint8_t apdu_id, uint8_t apdu_len, const uint8_t *apdu);
int gsm48_send_rr_ass_cmd(struct gsm_lchan *dest_lchan, struct gsm_lchan *lchan, uint8_t power_class);
int gsm48_send_ho_cmd(struct gsm_lchan *old_lchan, struct gsm_lchan *new_lchan, uint8_t power_command, uint8_t ho_ref);

int mncc_tx_to_cc(struct gsm_network *net, int msg_type, void *arg);

/* convert a ASCII phone number to call-control BCD */
int encode_bcd_number(uint8_t *bcd_lv, uint8_t max_len,
		      int h_len, const char *input);
int decode_bcd_number(char *output, int output_len, const uint8_t *bcd_lv,
		      int h_len);

int send_siemens_mrpci(struct gsm_lchan *lchan, uint8_t *classmark2_lv);
int gsm48_extract_mi(uint8_t *classmark2, int length, char *mi_string, uint8_t *mi_type);
int gsm48_paging_extract_mi(struct gsm48_pag_resp *pag, int length, char *mi_string, uint8_t *mi_type);

int gsm48_lchan_modify(struct gsm_lchan *lchan, uint8_t lchan_mode);
int gsm48_rx_rr_modif_ack(struct msgb *msg);

struct msgb *gsm48_create_mm_serv_rej(enum gsm48_reject_value value);
struct msgb *gsm48_create_loc_upd_rej(uint8_t cause);
void gsm48_lchan2chan_desc(struct gsm48_chan_desc *cd,
			   const struct gsm_lchan *lchan);

void release_security_operation(struct ran_conn *conn);
void allocate_security_operation(struct ran_conn *conn);

int gsm48_multirate_config(uint8_t *lv, const struct amr_multirate_conf *mr, const struct amr_mode *modes);

int gsm48_tch_rtp_create(struct gsm_trans *trans);
int gsm48_conn_sendmsg(struct msgb *msg, struct ran_conn *conn, struct gsm_trans *trans);
struct msgb *gsm48_create_mm_info(struct gsm_network *net);

int gsm0408_rcv_cc(struct msc_a *msc_a, struct msgb *msg);
int gsm0408_rcv_mm(struct msc_a *msc_a, struct msgb *msg);
int gsm0408_rcv_rr(struct msc_a *msc_a, struct msgb *msg);

int msc_vlr_tx_cm_serv_acc(void *msc_conn_ref, enum osmo_cm_service_type cm_service_type);

int compl_l3_msg_is_r99(const struct msgb *msg);

#endif
