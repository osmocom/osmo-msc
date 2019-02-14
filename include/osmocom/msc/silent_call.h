#ifndef _SILENT_CALL_H
#define _SILENT_CALL_H

struct ran_conn;
struct gsm0808_channel_type;

extern int gsm_silent_call_start(struct vlr_subscr *vsub,
		struct gsm0808_channel_type *ct,
		const char *traffic_dst_ip, uint16_t traffic_dst_port,
		void *data);
extern int gsm_silent_call_stop(struct vlr_subscr *vsub);

#if 0
extern int silent_call_rx(struct ran_conn *conn, struct msgb *msg);
extern int silent_call_reroute(struct ran_conn *conn, struct msgb *msg);
#endif

#endif /* _SILENT_CALL_H */
