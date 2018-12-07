#ifndef _SILENT_CALL_H
#define _SILENT_CALL_H

struct gsm0808_channel_type;
struct gsm_trans;

int gsm_silent_call_start(struct vlr_subscr *vsub,
	const struct gsm0808_channel_type *ct,
	const char *traffic_dst_ip, uint16_t traffic_dst_port,
	struct vty *vty);

extern int gsm_silent_call_stop(struct vlr_subscr *vsub);

void trans_silent_call_free(struct gsm_trans *trans);

#if 0
extern int silent_call_rx(struct ran_conn *conn, struct msgb *msg);
extern int silent_call_reroute(struct ran_conn *conn, struct msgb *msg);
#endif

#endif /* _SILENT_CALL_H */
