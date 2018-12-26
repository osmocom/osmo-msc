/* Manage identity of neighboring BSS cells for inter-BSC handover */
#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <osmocom/core/linuxlist.h>

struct vty;
struct gsm_network;
struct gsm_bts;
struct neighbor_ident_list;
struct gsm0808_cell_id_list2;

#define NEIGHBOR_IDENT_KEY_ANY_BTS -1

#define BSIC_ANY 0xff

struct neighbor_ident_key {
	int from_bts; /*< BTS nr 0..255 or NEIGHBOR_IDENT_KEY_ANY_BTS */
	uint16_t arfcn;
	uint8_t bsic;
};

const char *neighbor_ident_key_name(const struct neighbor_ident_key *ni_key);

struct neighbor_ident_list *neighbor_ident_init(void *talloc_ctx);
void neighbor_ident_free(struct neighbor_ident_list *nil);

bool neighbor_ident_key_match(const struct neighbor_ident_key *entry,
			      const struct neighbor_ident_key *search_for,
			      bool exact_match);

int neighbor_ident_add(struct neighbor_ident_list *nil, const struct neighbor_ident_key *key,
		       const struct gsm0808_cell_id_list2 *val);
const struct gsm0808_cell_id_list2 *neighbor_ident_get(const struct neighbor_ident_list *nil,
						       const struct neighbor_ident_key *key);
bool neighbor_ident_del(struct neighbor_ident_list *nil, const struct neighbor_ident_key *key);
void neighbor_ident_clear(struct neighbor_ident_list *nil);

void neighbor_ident_iter(const struct neighbor_ident_list *nil,
			 bool (* iter_cb )(const struct neighbor_ident_key *key,
					   const struct gsm0808_cell_id_list2 *val,
					   void *cb_data),
			 void *cb_data);

void neighbor_ident_vty_init(struct gsm_network *net, struct neighbor_ident_list *nil);
void neighbor_ident_vty_write(struct vty *vty, const char *indent, struct gsm_bts *bts);

#define NEIGHBOR_IDENT_VTY_KEY_PARAMS "arfcn <0-1023> bsic (<0-63>|any)"
#define NEIGHBOR_IDENT_VTY_KEY_DOC \
	"ARFCN of neighbor cell\n" "ARFCN value\n" \
	"BSIC of neighbor cell\n" "BSIC value\n" \
	"for all BSICs / use any BSIC in this ARFCN\n"
bool neighbor_ident_vty_parse_key_params(struct vty *vty, const char **argv,
					 struct neighbor_ident_key *key);
bool neighbor_ident_bts_parse_key_params(struct vty *vty, struct gsm_bts *bts, const char **argv,
					 struct neighbor_ident_key *key);
