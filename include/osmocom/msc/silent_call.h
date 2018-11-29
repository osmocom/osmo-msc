#ifndef _SILENT_CALL_H
#define _SILENT_CALL_H

struct ran_conn;

extern int gsm_silent_call_start(struct vlr_subscr *vsub,
                                 void *data, int type);
extern int gsm_silent_call_stop(struct vlr_subscr *vsub);

#if 0
extern int silent_call_rx(struct ran_conn *conn, struct msgb *msg);
extern int silent_call_reroute(struct ran_conn *conn, struct msgb *msg);
#endif

#endif /* _SILENT_CALL_H */
