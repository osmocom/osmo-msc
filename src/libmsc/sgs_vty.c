/* (C) 2018-2019 by sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Harald Welte, Philipp Maier
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <string.h>
#include <errno.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/msc/vty.h>
#include <osmocom/netif/stream.h>
#include <osmocom/msc/sgs_iface.h>
#include <osmocom/msc/sgs_server.h>
#include <osmocom/msc/debug.h>
#include <osmocom/gsm/tlv.h>

struct cmd_node cfg_sgs_node = {
	CFG_SGS_NODE,
	"%s(config-sgs)# ",
	1
};

DEFUN(cfg_sgs, cfg_sgs_cmd,
      "sgs",
      "Configure the SGs interface\n")
{
	vty->index = g_sgs;
	vty->node = CFG_SGS_NODE;

	return CMD_SUCCESS;
}

DEFUN(cfg_sgs_local_ip, cfg_sgs_local_ip_cmd,
      "local-ip A.B.C.D",
      "Set the Local IP Address of the SGs interface\n"
      "Local IP Address of the SGs interface\n")
{
	struct sgs_state *sgs = vty->index;
	int rc;

	osmo_strlcpy(sgs->cfg.local_addr, argv[0], sizeof(sgs->cfg.local_addr));
	osmo_stream_srv_link_set_addr(sgs->srv_link, sgs->cfg.local_addr);

	if (vty->type != VTY_FILE) {
		rc = sgs_server_open(sgs);
		if (rc < 0)
			return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_sgs_local_port, cfg_sgs_local_port_cmd,
      "local-port <0-65535>",
      "Set the local SCTP port of the SGs interface\n"
      "Local SCTP port of the SGs interface\n")
{
	struct sgs_state *sgs = vty->index;
	int rc;

	sgs->cfg.local_port = atoi(argv[0]);
	osmo_stream_srv_link_set_port(sgs->srv_link, sgs->cfg.local_port);

	if (vty->type != VTY_FILE) {
		rc = sgs_server_open(sgs);
		if (rc < 0)
			return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_sgs_vlr_name, cfg_sgs_vlr_name_cmd,
      "vlr-name FQDN",
      "Set the SGs VLR Name as per TS 29.118 9.4.22\n"
      "Fully-Qualified Domain Name of this VLR\n")
{
	struct sgs_state *sgs = vty->index;
	osmo_strlcpy(sgs->cfg.vlr_name, argv[0], sizeof(sgs->cfg.vlr_name));

	return CMD_SUCCESS;
}

DEFUN(cfg_sgs_timer, cfg_sgs_timer_cmd,
      "timer (ts5|ts6-2|ts7|ts11|ts14|ts15) <1-120>",
      "Configure SGs Timer\n"
      "Paging procedure guard timer\n"
      "TMSI reallocation guard timer\n"
      "Non-EPS alert procedure guard timer\n"
      "VLR reset guard timer\n"
      "UE fallback prcoedure timer\n"
      "MO UE fallback procedure guard timer\n"
      "Time in seconds\n")
{
	struct sgs_state *sgs = vty->index;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(sgs->cfg.timer); i++) {
		if (!strcasecmp(argv[0], vlr_sgs_state_timer_name(i))) {
			sgs->cfg.timer[i] = atoi(argv[1]);
			return CMD_SUCCESS;
		}
	}

	return CMD_WARNING;
}

DEFUN(cfg_sgs_counter, cfg_sgs_counter_cmd,
      "counter (ns7|ns11) <0-255>",
      "Configure SGs Counter\n"
      "Non-EPS alert request retry counter\n"
      "VLR reset retry counter\n" "Counter value\n")
{
	struct sgs_state *sgs = vty->index;
	unsigned int i = 0;

	for (i = 0; i < ARRAY_SIZE(sgs->cfg.counter); i++) {
		if (!strcasecmp(argv[0], vlr_sgs_state_counter_name(i))) {
			sgs->cfg.counter[i] = atoi(argv[1]);
			return CMD_SUCCESS;
		}
	}

	return CMD_WARNING;
}

DEFUN(show_sgs_conn, show_sgs_conn_cmd,
      "show sgs-connections", SHOW_STR
      "Show SGs interface connections / MMEs\n")
{
	struct sgs_connection *sgc;

	llist_for_each_entry(sgc, &g_sgs->conn_list, entry) {
		vty_out(vty, " %s %s%s", sgc->sockname, sgc->mme ? sgc->mme->fqdn : "", VTY_NEWLINE);
	}
	return CMD_SUCCESS;
}

static int config_write_sgs(struct vty *vty)
{
	struct sgs_state *sgs = g_sgs;
	unsigned int i;
	char str_buf[256];

	vty_out(vty, "sgs%s", VTY_NEWLINE);
	vty_out(vty, " local-port %u%s", sgs->cfg.local_port, VTY_NEWLINE);
	vty_out(vty, " local-ip %s%s", sgs->cfg.local_addr, VTY_NEWLINE);
	vty_out(vty, " vlr-name %s%s", sgs->cfg.vlr_name, VTY_NEWLINE);

	for (i = 0; i < ARRAY_SIZE(sgs->cfg.timer); i++) {
		if (sgs->cfg.timer[i] == sgs_state_timer_defaults[i])
			continue;
		osmo_str_tolower_buf(str_buf, sizeof(str_buf), vlr_sgs_state_timer_name(i));
		vty_out(vty, " timer %s %u%s", str_buf, sgs->cfg.timer[i], VTY_NEWLINE);
	}

	for (i = 0; i < ARRAY_SIZE(sgs->cfg.counter); i++) {
		if (sgs->cfg.counter[i] == sgs_state_counter_defaults[i])
			continue;
		osmo_str_tolower_buf(str_buf, sizeof(str_buf), vlr_sgs_state_counter_name(i));
		vty_out(vty, " counter %s %u%s", str_buf, sgs->cfg.counter[i], VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

void sgs_vty_init(void)
{
	/* configuration commands / nodes */
	install_element(CONFIG_NODE, &cfg_sgs_cmd);
	install_node(&cfg_sgs_node, config_write_sgs);
	install_element(CFG_SGS_NODE, &cfg_sgs_local_ip_cmd);
	install_element(CFG_SGS_NODE, &cfg_sgs_local_port_cmd);
	install_element(CFG_SGS_NODE, &cfg_sgs_timer_cmd);
	install_element(CFG_SGS_NODE, &cfg_sgs_counter_cmd);
	install_element(CFG_SGS_NODE, &cfg_sgs_vlr_name_cmd);

	install_element_ve(&show_sgs_conn_cmd);
}
