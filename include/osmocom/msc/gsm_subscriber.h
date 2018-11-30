#ifndef _GSM_SUBSCR_H
#define _GSM_SUBSCR_H

#include <stdbool.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>

#include <osmocom/msc/gsm_data.h>

struct ran_conn;
struct msgb;

typedef int gsm_cbfn(unsigned int hooknum, unsigned int event, struct msgb *msg,
		     void *data, void *param);

/*
 * Struct for pending channel requests. This is managed in the
 * llist_head requests of each subscriber. The reference counting
 * should work in such a way that a subscriber with a pending request
 * remains in memory.
 */
struct subscr_request {
       struct llist_head entry;

       /* human readable label to be able to log pending request kinds */
       const char *label;

       /* the callback data */
       gsm_cbfn *cbfn;
       void *param;
};

/*
 * Paging handling with authentication
 */
struct subscr_request *subscr_request_conn(struct vlr_subscr *vsub,
					   gsm_cbfn *cbfn, void *param,
					   const char *label);

void subscr_remove_request(struct subscr_request *req);

void subscr_paging_cancel(struct vlr_subscr *vsub, enum gsm_paging_event event);
int subscr_paging_dispatch(unsigned int hooknum, unsigned int event,
			   struct msgb *msg, void *data, void *param);

/* Find an allocated channel for a specified subscriber */
struct ran_conn *connection_for_subscr(struct vlr_subscr *vsub);

#endif /* _GSM_SUBSCR_H */
