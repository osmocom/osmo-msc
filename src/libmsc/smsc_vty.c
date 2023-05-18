/* SMSC interface to VTY */
/* (C) 2016-2018 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * Based on OpenBSC interface to quagga VTY (libmsc/vty_interface_layer3.c)
 * (C) 2009-2022 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009-2011 by Holger Hans Peter Freyther
 * All Rights Reserved
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

#include "config.h"

#include <osmocom/vty/command.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/misc.h>

#include <osmocom/msc/vty.h>
#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/sms_queue.h>


static struct gsm_network *gsmnet;
static struct sms_queue_config *smqcfg;

/***********************************************************************
 * SMSC Config Node
 ***********************************************************************/

static struct cmd_node smsc_node = {
	SMSC_NODE,
	"%s(config-smsc)# ",
	1,
};

DEFUN(cfg_smsc, cfg_smsc_cmd,
      "smsc", "Configure SMSC options")
{
	vty->node = SMSC_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_sms_database, cfg_sms_database_cmd,
	"database PATH",
	"Set the path to the MSC-SMS database file\n"
	"Relative or absolute file system path to the database file (default is '" SMS_DEFAULT_DB_FILE_PATH "')\n")
{
	osmo_talloc_replace_string(smqcfg, &smqcfg->db_file_path, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_sms_queue_max, cfg_sms_queue_max_cmd,
      "queue max-pending <1-500>",
      "SMS Queue\n" "SMS to deliver in parallel\n" "Amount\n")
{
	smqcfg->max_pending = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_sms_queue_fail, cfg_sms_queue_fail_cmd,
      "queue max-failure <1-500>",
      "SMS Queue\n" "Maximum number of delivery failures before giving up\n" "Amount\n")
{
	smqcfg->max_fail = atoi(argv[0]);
	return CMD_SUCCESS;
}

#define DB_STR "SMS Database Configuration\n"

DEFUN(cfg_sms_db_del_delivered, cfg_sms_db_del_delivered_cmd,
      "database delete-delivered (0|1)",
      DB_STR "Configure if delivered SMS are deleted from DB\n"
      "Do not delete SMS after delivery\n"
      "Delete SMS after delivery\n")
{
	smqcfg->delete_delivered = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_sms_db_del_expired, cfg_sms_db_del_expired_cmd,
      "database delete-expired (0|1)",
      DB_STR "Configure if expired SMS are deleted from DB\n"
      "Do not delete SMS after expiration of validity period\n"
      "Delete SMS after expiration of validity period\n")
{
	smqcfg->delete_expired = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_sms_def_val_per, cfg_sms_def_val_per_cmd,
      "validity-period (minimum|default) <1-5256000>",
      "Configure validity period for SMS\n"
      "Minimum SMS validity period in minutes\n"
      "Default SMS validity period in minutes\n"
      "Validity period in minutes\n")
{
	if (!strcmp(argv[0], "minimum"))
		smqcfg->minimum_validity_mins = atoi(argv[1]);
	else
		smqcfg->default_validity_mins = atoi(argv[1]);
	return CMD_SUCCESS;
}


/***********************************************************************
 * View / Enable Node
 ***********************************************************************/

DEFUN(show_smsqueue,
      show_smsqueue_cmd,
      "show sms-queue",
      SHOW_STR "Display SMSqueue statistics\n")
{
	sms_queue_stats(gsmnet->sms_queue, vty);
	return CMD_SUCCESS;
}

DEFUN(smsqueue_trigger,
      smsqueue_trigger_cmd,
      "sms-queue trigger",
      "SMS Queue\n" "Trigger sending messages\n")
{
	sms_queue_trigger(gsmnet->sms_queue);
	return CMD_SUCCESS;
}

DEFUN(smsqueue_max,
      smsqueue_max_cmd,
      "sms-queue max-pending <1-500>",
      "SMS Queue\n" "SMS to deliver in parallel\n" "Amount\n")
{
	int max_pending = atoi(argv[0]);
	vty_out(vty, "%% SMSqueue old max: %d new: %d%s",
		smqcfg->max_pending, max_pending, VTY_NEWLINE);
	smqcfg->max_pending = max_pending;
	return CMD_SUCCESS;
}

DEFUN(smsqueue_clear,
      smsqueue_clear_cmd,
      "sms-queue clear",
      "SMS Queue\n" "Clear the queue of pending SMS\n")
{
	sms_queue_clear(gsmnet->sms_queue);
	return CMD_SUCCESS;
}

DEFUN(smsqueue_fail,
      smsqueue_fail_cmd,
      "sms-queue max-failure <1-500>",
      "SMS Queue\n" "Maximum amount of delivery failures\n" "Amount\n")
{
	int max_fail = atoi(argv[0]);
	vty_out(vty, "%% SMSqueue max failure old: %d new: %d%s",
		smqcfg->max_fail, max_fail, VTY_NEWLINE);
	smqcfg->max_fail = max_fail;
	return CMD_SUCCESS;
}

static int config_write_smsc(struct vty *vty)
{
	vty_out(vty, "smsc%s", VTY_NEWLINE);

	if (smqcfg->db_file_path && strcmp(smqcfg->db_file_path, SMS_DEFAULT_DB_FILE_PATH))
		vty_out(vty, " database %s%s", smqcfg->db_file_path, VTY_NEWLINE);

	vty_out(vty, " queue max-pending %u%s", smqcfg->max_pending, VTY_NEWLINE);
	vty_out(vty, " queue max-failure %u%s", smqcfg->max_fail, VTY_NEWLINE);

	vty_out(vty, " database delete-delivered %u%s", smqcfg->delete_delivered, VTY_NEWLINE);
	vty_out(vty, " database delete-expired %u%s", smqcfg->delete_expired, VTY_NEWLINE);

	vty_out(vty, " validity-period minimum %u%s", smqcfg->minimum_validity_mins, VTY_NEWLINE);
	vty_out(vty, " validity-period default %u%s", smqcfg->default_validity_mins, VTY_NEWLINE);

	return 0;
}

void smsc_vty_init(struct gsm_network *msc_network)
{
	OSMO_ASSERT(gsmnet == NULL);
	gsmnet = msc_network;
	smqcfg = msc_network->sms_queue_cfg;

	/* config node */
	install_element(CONFIG_NODE, &cfg_smsc_cmd);
	install_node(&smsc_node, config_write_smsc);
	install_element(SMSC_NODE, &cfg_sms_database_cmd);
	install_element(SMSC_NODE, &cfg_sms_queue_max_cmd);
	install_element(SMSC_NODE, &cfg_sms_queue_fail_cmd);
	install_element(SMSC_NODE, &cfg_sms_db_del_delivered_cmd);
	install_element(SMSC_NODE, &cfg_sms_db_del_expired_cmd);
	install_element(SMSC_NODE, &cfg_sms_def_val_per_cmd);

	/* enable node */
	install_element(ENABLE_NODE, &smsqueue_trigger_cmd);
	install_element(ENABLE_NODE, &smsqueue_max_cmd);
	install_element(ENABLE_NODE, &smsqueue_clear_cmd);
	install_element(ENABLE_NODE, &smsqueue_fail_cmd);

	/* view / enable node */
	install_element_ve(&show_smsqueue_cmd);
}
