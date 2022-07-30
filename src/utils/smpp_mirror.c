#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>

#include <netinet/in.h>

#include <smpp34.h>
#include <smpp34_structs.h>
#include <smpp34_params.h>

#include <osmocom/core/application.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/write_queue.h>

#include <osmocom/msc/debug.h>
#include <osmocom/msc/smpp.h>


/* FIXME: merge with smpp_smsc.c */

static struct tlv_t *find_tlv(struct tlv_t *head, uint16_t tag)
{
	struct tlv_t *t;

	for (t = head; t != NULL; t = t->next) {
		if (t->tag == tag)
			return t;
	}
	return NULL;
}

static int smpp_handle_deliver(struct esme *esme, struct msgb *msg)
{
	struct deliver_sm_t deliver;
	struct deliver_sm_resp_t deliver_r;
	struct submit_sm_t submit;
	tlv_t *t;
	int rc;

	memset(&deliver, 0, sizeof(deliver));
	SMPP34_UNPACK(rc, DELIVER_SM, &deliver, msgb_data(msg), msgb_length(msg));
	if (rc < 0)
		return rc;

	INIT_RESP(DELIVER_SM_RESP, &deliver_r, &deliver);

	PACK_AND_SEND(esme, &deliver_r);

	memset(&submit, 0, sizeof(submit));
	submit.command_id = SUBMIT_SM;
	submit.command_status = ESME_ROK;
	submit.sequence_number = esme_inc_seq_nr(esme);

	submit.dest_addr_ton =  deliver.source_addr_ton;
	submit.dest_addr_npi =  deliver.source_addr_npi;
	memcpy(submit.destination_addr, deliver.source_addr,
		OSMO_MIN(sizeof(submit.destination_addr),
			 sizeof(deliver.source_addr)));

	submit.source_addr_ton = deliver.dest_addr_ton;
	submit.source_addr_npi = deliver.dest_addr_npi;
	memcpy(submit.source_addr, deliver.destination_addr,
		OSMO_MIN(sizeof(submit.source_addr),
			 sizeof(deliver.destination_addr)));

	/* Mirror delivery receipts as a delivery acknowledgements. */
	if (deliver.esm_class == 0x04) {
		LOGP(DSMPP, LOGL_DEBUG, "%s\n", deliver.short_message);
		submit.esm_class = 0x08;
	} else {
		submit.esm_class = deliver.esm_class;
	}

	submit.registered_delivery = deliver.registered_delivery;
	submit.protocol_id = deliver.protocol_id;
	submit.priority_flag = deliver.priority_flag;
	memcpy(submit.schedule_delivery_time, deliver.schedule_delivery_time,
	       OSMO_MIN(sizeof(submit.schedule_delivery_time),
		        sizeof(deliver.schedule_delivery_time)));
	memcpy(submit.validity_period, deliver.validity_period,
		OSMO_MIN(sizeof(submit.validity_period),
			 sizeof(deliver.validity_period)));
	submit.registered_delivery = deliver.registered_delivery;
	submit.replace_if_present_flag = deliver.replace_if_present_flag;
	submit.data_coding = deliver.data_coding;
	submit.sm_default_msg_id = deliver.sm_default_msg_id;
	submit.sm_length = deliver.sm_length;
	memcpy(submit.short_message, deliver.short_message,
		OSMO_MIN(sizeof(submit.short_message),
			 sizeof(deliver.short_message)));

	/* FIXME: More TLV? */
	t = find_tlv(deliver.tlv, TLVID_user_message_reference);
	if (t) {
		tlv_t tlv;

		memset(&tlv, 0, sizeof(tlv));
		tlv.tag = TLVID_user_message_reference;
		tlv.length = 2;
		tlv.value.val16 = t->value.val16;
		build_tlv(&submit.tlv, &tlv);
	}

	return PACK_AND_SEND(esme, &submit);
}

static int bind_transceiver(struct esme *esme)
{
	struct bind_transceiver_t bind;

	memset(&bind, 0, sizeof(bind));
	bind.command_id = BIND_TRANSCEIVER;
	bind.sequence_number = esme_inc_seq_nr(esme);
	snprintf((char *)bind.system_id, sizeof(bind.system_id), "%s", esme->system_id);
	snprintf((char *)bind.password, sizeof(bind.password), "%s", esme->password);
	snprintf((char *)bind.system_type, sizeof(bind.system_type), "mirror");
	bind.interface_version = esme->smpp_version;

	return PACK_AND_SEND(esme, &bind);
}

static int smpp_pdu_rx(struct esme *esme, struct msgb *msg)
{
	uint32_t cmd_id = smpp_msgb_cmdid(msg);
	int rc;

	switch (cmd_id) {
	case DELIVER_SM:
		rc = smpp_handle_deliver(esme, msg);
		break;
	default:
		LOGP(DSMPP, LOGL_NOTICE, "unhandled case %d\n", cmd_id);
		rc = 0;
		break;
	}

	return rc;
}

static int esme_read_cb(struct osmo_fd *ofd)
{
	struct esme *esme = ofd->data;
	int rc = esme_read_callback(esme, ofd->fd);

	switch (rc) {
	case 1:
		rc = smpp_pdu_rx(esme, esme->read_msg);
		esme_read_state_reset(esme);
		break;
	case -EBADF:
		exit(2342);
		break;
	default:
		return rc;
	}

	return 0;
}

static int esme_write_cb(struct osmo_fd *ofd, struct msgb *msg)
{
	if (esme_write_callback(ofd->data, ofd->fd, msg) == 0)
		exit(99);

	return 0;
}

static int smpp_esme_init(struct esme *esme, const char *host, uint16_t port)
{
	int rc;

	if (port == 0)
		port = 2775;

	esme->own_seq_nr = rand();
	esme_inc_seq_nr(esme);
	osmo_wqueue_init(&esme->wqueue, 10);
	esme->wqueue.bfd.data = esme;
	esme->wqueue.read_cb = esme_read_cb;
	esme->wqueue.write_cb = esme_write_cb;

	rc = osmo_sock_init_ofd(&esme->wqueue.bfd, AF_UNSPEC, SOCK_STREAM,
				IPPROTO_TCP, host, port, OSMO_SOCK_F_CONNECT);
	if (rc < 0)
		return rc;

	return bind_transceiver(esme);
}

static const struct log_info_cat smpp_mirror_default_categories[] = {
	[DSMPP] = {
		.name = "DSMPP",
		.description = "SMPP interface for external SMS apps",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

const struct log_info log_info = {
	.cat = smpp_mirror_default_categories,
	.num_cat = ARRAY_SIZE(smpp_mirror_default_categories),
};

int main(int argc, char **argv)
{
	struct esme esme;
	char *host = "localhost";
	int port = 0;
	int rc;
	void *ctx = talloc_named_const(NULL, 0, "smpp_mirror");

	msgb_talloc_ctx_init(ctx, 0);

	memset(&esme, 0, sizeof(esme));

	osmo_init_logging2(ctx, &log_info);

	snprintf((char *) esme.system_id, sizeof(esme.system_id), "mirror");
	snprintf((char *) esme.password, sizeof(esme.password), "mirror");
	esme.smpp_version = 0x34;

	if (argc >= 2)
		host = argv[1];
	if (argc >= 3)
		port = atoi(argv[2]);

	rc = smpp_esme_init(&esme, host, port);
	if (rc < 0)
		exit(1);

	while (1) {
		osmo_select_main(0);
	}

	exit(0);
}
