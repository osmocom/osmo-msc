/* GSM 08.08 like API for OpenBSC */

#ifndef OPENBSC_BSC_API_H
#define OPENBSC_BSC_API_H

#include "gsm_data.h"

#define BSC_API_CONN_POL_ACCEPT	0
#define BSC_API_CONN_POL_REJECT	1

struct bsc_api {
	/*! \brief BTS->MSC: tell MSC a SAPI was not established */
	void (*sapi_n_reject)(struct gsm_subscriber_connection *conn, int dlci);
	/*! \brief MS->MSC: Tell MSC that ciphering has been enabled */
	void (*cipher_mode_compl)(struct gsm_subscriber_connection *conn,
				  struct msgb *msg, uint8_t chosen_encr);
	/*! \brief MS->MSC: New MM context with L3 payload */
	int (*compl_l3)(struct gsm_subscriber_connection *conn,
			struct msgb *msg, uint16_t chosen_channel); 
	/*! \brief MS->BSC/MSC: Um L3 message */
	void (*dtap)(struct gsm_subscriber_connection *conn, uint8_t link_id,
			struct msgb *msg);
	/*! \brief BSC->MSC: Assignment of lchan successful */
	void (*assign_compl)(struct gsm_subscriber_connection *conn,
			  uint8_t rr_cause, uint8_t chosen_channel,
			  uint8_t encr_alg_id, uint8_t speech_mode);
	/*! \brief BSC->MSC: Assignment of lchan failed */
	void (*assign_fail)(struct gsm_subscriber_connection *conn,
			 uint8_t cause, uint8_t *rr_cause);
	/*! \brief BSC->MSC: RR conn has been cleared */
	int (*clear_request)(struct gsm_subscriber_connection *conn,
			      uint32_t cause);
	/*! \brief BSC->MSC: Classmark Update */
	void (*classmark_chg)(struct gsm_subscriber_connection *conn,
			      const uint8_t *cm2, uint8_t cm2_len,
			      const uint8_t *cm3, uint8_t cm3_len);

	/**
	 * Configure the multirate setting on this channel. If it is
	 * not implemented AMR5.9 will be used.
	 */
	void (*mr_config)(struct gsm_subscriber_connection *conn,
				struct gsm_lchan *lchan, int full_rate);

	/** Callback for additional actions during conn cleanup */
	void (*conn_cleanup)(struct gsm_subscriber_connection *conn);
};

#endif
