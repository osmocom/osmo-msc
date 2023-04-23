#ifndef OPENBSC_VTY_H
#define OPENBSC_VTY_H

#include <osmocom/vty/vty.h>
#include <osmocom/vty/buffer.h>
#include <osmocom/vty/command.h>

struct gsm_network;
struct vty;

void openbsc_vty_print_statistics(struct vty *vty, struct gsm_network *);

struct buffer *vty_argv_to_buffer(int argc, const char *argv[], int base);

extern struct cmd_element cfg_description_cmd;
extern struct cmd_element cfg_no_description_cmd;

enum bsc_vty_node {
	GSMNET_NODE = _LAST_OSMOVTY_NODE + 1,
	MGW_NODE,
	SUBSCR_NODE,
	MSC_NODE,
	MNCC_INT_NODE,
	SMPP_NODE,
	SMPP_ESME_NODE,
	HLR_NODE,
	CFG_SGS_NODE,
	SMSC_NODE,
	ASCI_NODE,
	GCR_NODE,
	VGC_NODE,
	VBC_NODE,
};

int bsc_vty_init_extra(void);

void msc_vty_init(struct gsm_network *msc_network);
void smsc_vty_init(struct gsm_network *msc_network);

struct gsm_network *gsmnet_from_vty(struct vty *vty);

#endif
