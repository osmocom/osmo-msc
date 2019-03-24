/* OsmoMSC - Circuit-Switched Core Network (MSC+VLR+HLR+SMSC) implementation
 */

/* (C) 2016 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Based on OsmoNITB:
 * (C) 2008-2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009-2012 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>

#define _GNU_SOURCE
#include <getopt.h>

/* build switches from the configure script */
#include "../../bscconfig.h"

#include <osmocom/msc/db.h>
#include <osmocom/core/application.h>
#include <osmocom/core/select.h>
#include <osmocom/core/stats.h>
#include <osmocom/msc/debug.h>
#include <osmocom/abis/abis.h>
#include <osmocom/abis/e1_input.h>
#include <osmocom/core/talloc.h>
#include <osmocom/msc/signal.h>
#include <osmocom/msc/sms_queue.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/ports.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/misc.h>
#include <osmocom/msc/vty.h>
#include <osmocom/msc/mncc.h>
#include <osmocom/msc/rrlp.h>
#include <osmocom/ctrl/control_if.h>
#include <osmocom/ctrl/control_vty.h>
#include <osmocom/ctrl/ports.h>
#include <osmocom/msc/smpp.h>
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/mgcp_client/mgcp_client.h>
#include <osmocom/msc/sgs_iface.h>
#include <osmocom/msc/sgs_server.h>

#ifdef BUILD_IU
#include <osmocom/ranap/iu_client.h>
#endif

#include <osmocom/msc/msc_ifaces.h>
#include <osmocom/msc/iucs.h>
#include <osmocom/msc/iucs_ranap.h>
#include <osmocom/msc/a_iface.h>

static const char * const osmomsc_copyright =
	"OsmoMSC - Osmocom Circuit-Switched Core Network implementation\r\n"
	"Copyright (C) 2016 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>\r\n"
	"Based on OsmoNITB:\r\n"
	"  (C) 2008-2010 by Harald Welte <laforge@gnumonks.org>\r\n"
	"  (C) 2009-2012 by Holger Hans Peter Freyther <zecke@selfish.org>\r\n"
	"Contributions by Daniel Willmann, Jan Lübbe, Stefan Schmidt\r\n"
	"Dieter Spaar, Andreas Eversberg, Sylvain Munaut, Neels Hofmeyr\r\n\r\n"
	"License AGPLv3+: GNU AGPL version 3 or later <http://gnu.org/licenses/agpl-3.0.html>\r\n"
	"This is free software: you are free to change and redistribute it.\r\n"
	"There is NO WARRANTY, to the extent permitted by law.\r\n";

void *tall_msc_ctx = NULL;

/* satisfy deps from libbsc legacy.
   TODO double check these */
void *tall_map_ctx = NULL;
/* end deps from libbsc legacy. */

static struct {
	const char *database_name;
	const char *config_file;
	int daemonize;
	const char *mncc_sock_path;
	int use_db_counter;
} msc_cmdline_config = {
	.database_name = "sms.db",
	.config_file = "osmo-msc.cfg",
	.use_db_counter = 1,
};

/* timer to store statistics */
#define DB_SYNC_INTERVAL	60, 0
#define EXPIRE_INTERVAL		10, 0

static struct osmo_timer_list db_sync_timer;

static int quit = 0;

static void print_usage()
{
	printf("Usage: osmo-msc\n");
}

static void print_help()
{
	printf("  Some useful help...\n");
	printf("  -h --help                  This text.\n");
	printf("  -d option --debug=DCC:DMM:DRR:  Enable debugging.\n");
	printf("  -D --daemonize             Fork the process into a background daemon.\n");
	printf("  -c --config-file filename  The config file to use.\n");
	printf("  -s --disable-color\n");
	printf("  -l --database db-name      The database to use.\n");
	printf("  -T --timestamp             Prefix every log line with a timestamp.\n");
	printf("  -V --version               Print the version of OsmoMSC.\n");
	printf("  -e --log-level number      Set a global loglevel.\n");
	printf("  -M --mncc-sock-path PATH   Disable built-in MNCC handler and offer socket.\n");
	printf("  -C --no-dbcounter          Disable regular syncing of counters to database.\n");
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"debug", 1, 0, 'd'},
			{"daemonize", 0, 0, 'D'},
			{"config-file", 1, 0, 'c'},
			{"disable-color", 0, 0, 's'},
			{"database", 1, 0, 'l'},
			{"timestamp", 0, 0, 'T'},
			{"version", 0, 0, 'V' },
			{"log-level", 1, 0, 'e'},
			{"mncc-sock-path", 1, 0, 'M'},
			{"no-dbcounter", 0, 0, 'C'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hd:Dsl:TVc:e:CM:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_usage();
			print_help();
			exit(0);
		case 's':
			log_set_use_color(osmo_stderr_target, 0);
			break;
		case 'd':
			log_parse_category_mask(osmo_stderr_target, optarg);
			break;
		case 'D':
			msc_cmdline_config.daemonize = 1;
			break;
		case 'l':
			msc_cmdline_config.database_name = optarg;
			break;
		case 'c':
			msc_cmdline_config.config_file = optarg;
			break;
		case 'T':
			log_set_print_timestamp(osmo_stderr_target, 1);
			break;
		case 'e':
			log_set_log_level(osmo_stderr_target, atoi(optarg));
			break;
		case 'M':
			msc_cmdline_config.mncc_sock_path = optarg;
			break;
		case 'C':
			msc_cmdline_config.use_db_counter = 0;
			break;
		case 'V':
			print_version(1);
			exit(0);
			break;
		default:
			/* catch unknown options *as well as* missing arguments. */
			fprintf(stderr, "Error in command line options. Exiting.\n");
			exit(-1);
		}
	}
}

struct gsm_network *msc_network_alloc(void *ctx,
				      mncc_recv_cb_t mncc_recv)
{
	struct gsm_network *net = gsm_network_init(ctx, mncc_recv);
	if (!net)
		return NULL;

	net->name_long = talloc_strdup(net, "OsmoMSC");
	net->name_short = talloc_strdup(net, "OsmoMSC");

	net->gsup_server_addr_str = talloc_strdup(net,
						  MSC_HLR_REMOTE_IP_DEFAULT);
	net->gsup_server_port = MSC_HLR_REMOTE_PORT_DEFAULT;

	mgcp_client_conf_init(&net->mgw.conf);

	return net;
}

void msc_network_shutdown(struct gsm_network *net)
{
	/* nothing here yet */
}

static struct gsm_network *msc_network = NULL;

extern void *tall_vty_ctx;
static void signal_handler(int signal)
{
	fprintf(stdout, "signal %u received\n", signal);

	switch (signal) {
	case SIGINT:
	case SIGTERM:
		LOGP(DMSC, LOGL_NOTICE, "Terminating due to signal %d\n", signal);
		quit++;
		break;
	case SIGABRT:
		osmo_generate_backtrace();
		/* in case of abort, we want to obtain a talloc report
		 * and then return to the caller, who will abort the process */
	case SIGUSR1:
		talloc_report(tall_vty_ctx, stderr);
		talloc_report_full(tall_msc_ctx, stderr);
		break;
	case SIGUSR2:
		talloc_report_full(tall_vty_ctx, stderr);
		break;
	default:
		break;
	}
}

/* timer handling */
static int _db_store_counter(struct osmo_counter *counter, void *data)
{
	return db_store_counter(counter);
}

static void db_sync_timer_cb(void *data)
{
	/* store counters to database and re-schedule */
	osmo_counters_for_each(_db_store_counter, NULL);
	osmo_timer_schedule(&db_sync_timer, DB_SYNC_INTERVAL);
}

static int msc_vty_go_parent(struct vty *vty)
{
	switch (vty->node) {
	case GSMNET_NODE:
		vty->node = CONFIG_NODE;
		vty->index = NULL;
		break;
	case SMPP_ESME_NODE:
		vty->node = SMPP_NODE;
		vty->index = NULL;
		break;
	case SMPP_NODE:
	case MSC_NODE:
	case MNCC_INT_NODE:
		vty->node = CONFIG_NODE;
		vty->index = NULL;
		break;
	case SUBSCR_NODE:
		vty->node = ENABLE_NODE;
		vty->index = NULL;
		break;
	default:
		osmo_ss7_vty_go_parent(vty);
	}

	return vty->node;
}

static int msc_vty_is_config_node(struct vty *vty, int node)
{
	/* Check if libosmo-sccp declares the node in
	 * question as config node */
	if (osmo_ss7_is_config_node(vty, node))
		return 1;

	switch (node) {
	/* add items that are not config */
	case SUBSCR_NODE:
	case CONFIG_NODE:
		return 0;

	default:
		return 1;
	}
}

static struct vty_app_info msc_vty_info = {
	.name		= "OsmoMSC",
	.version	= PACKAGE_VERSION,
	.go_parent_cb	= msc_vty_go_parent,
	.is_config_node	= msc_vty_is_config_node,
};

#ifdef BUILD_IU
static int rcvmsg_iu_cs(struct msgb *msg, struct gprs_ra_id *ra_id, uint16_t *sai)
{
	DEBUGP(DIUCS, "got IuCS message %d bytes: %s\n", msg->len, msgb_hexdump(msg));
	if (ra_id) {
		DEBUGP(DIUCS, "got IuCS message on %s\n", osmo_rai_name(ra_id));
	}

	return gsm0408_rcvmsg_iucs(msc_network, msg, ra_id? &ra_id->lac : NULL);
}

static int rx_iu_event(struct ranap_ue_conn_ctx *ctx, enum ranap_iu_event_type type,
		       void *data)
{
	DEBUGP(DIUCS, "got IuCS event %u: %s\n", type,
	       ranap_iu_event_type_str(type));

	return iucs_rx_ranap_event(msc_network, ctx, type, data);
}
#endif

#define DEFAULT_M3UA_REMOTE_IP "127.0.0.1"
#define DEFAULT_PC "0.23.1"

static struct osmo_sccp_instance *sccp_setup(void *ctx, uint32_t cs7_instance,
					     const char *label, const char *default_pc_str)
{
	int default_pc = osmo_ss7_pointcode_parse(NULL, default_pc_str);
	if (default_pc < 0)
		return NULL;

	return osmo_sccp_simple_client_on_ss7_id(ctx, cs7_instance, label, default_pc,
						 OSMO_SS7_ASP_PROT_M3UA,
						 0, NULL, /* local: use arbitrary port and 0.0.0.0. */
						 0, /* remote: use protocol default port */
						 DEFAULT_M3UA_REMOTE_IP);
	/* Note: If a differing remote IP is to be used, it was already entered in the vty config at
	 * 'cs7' / 'asp' / 'remote-ip', and this default remote IP has no effect.
	 * Similarly, 'cs7' / 'listen' can specify the local IP address. */
}

static int ss7_setup(void *ctx)
{
	uint32_t cs7_instance_a = msc_network->a.cs7_instance;
#if BUILD_IU
	uint32_t cs7_instance_iu = msc_network->iu.cs7_instance;

	if (cs7_instance_a == cs7_instance_iu) {
		/* Create one single SCCP instance which will be used for both,
		 * Iu and A at the same time, under the same point-code */
		LOGP(DMSC, LOGL_NOTICE, "CS7 Instance identifiers: A = Iu = %u\n", cs7_instance_a);

		msc_network->a.sccp = sccp_setup(ctx, cs7_instance_a, "OsmoMSC-A-Iu", DEFAULT_PC);
		if (!msc_network->a.sccp)
			return -EINVAL;

		msc_network->iu.sccp = msc_network->a.sccp;
	} else {
		/* Create two separate SCCP instances to run A and Iu independently on different
		 * pointcodes */
		LOGP(DMSC, LOGL_NOTICE, "CS7 Instance identifiers: A = %u, Iu = %u\n",
		     cs7_instance_a, cs7_instance_iu);

		msc_network->a.sccp = sccp_setup(ctx, cs7_instance_a, "OsmoMSC-A", DEFAULT_PC);
		if (!msc_network->a.sccp)
			return -EINVAL;

		msc_network->iu.sccp = sccp_setup(ctx, cs7_instance_iu, "OsmoMSC-Iu", DEFAULT_PC);
		if (!msc_network->iu.sccp)
			return -EINVAL;
	}
#else
	/* No Iu support, just open up an A instance */
	msc_network->a.sccp = sccp_setup(ctx, cs7_instance_a, "OsmoMSC-A", DEFAULT_PC);
	if (!msc_network->a.sccp)
		return -EINVAL;
#endif

	return 0;
}

static const struct log_info_cat msc_default_categories[] = {
	[DRLL] = {
		.name = "DRLL",
		.description = "A-bis Radio Link Layer (RLL)",
		.color = "\033[1;31m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DCC] = {
		.name = "DCC",
		.description = "Layer3 Call Control (CC)",
		.color = "\033[1;32m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DMM] = {
		.name = "DMM",
		.description = "Layer3 Mobility Management (MM)",
		.color = "\033[1;33m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DRR] = {
		.name = "DRR",
		.description = "Layer3 Radio Resource (RR)",
		.color = "\033[1;34m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DMNCC] = {
		.name = "DMNCC",
		.description = "MNCC API for Call Control application",
		.color = "\033[1;39m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DPAG]	= {
		.name = "DPAG",
		.description = "Paging Subsystem",
		.color = "\033[1;38m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DMSC] = {
		.name = "DMSC",
		.description = "Mobile Switching Center",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DMGCP] = {
		.name = "DMGCP",
		.description = "Media Gateway Control Protocol",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DHO] = {
		.name = "DHO",
		.description = "Hand-Over",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DDB] = {
		.name = "DDB",
		.description = "Database Layer",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DREF] = {
		.name = "DREF",
		.description = "Reference Counting",
		.enabled = 0, .loglevel = LOGL_NOTICE,
	},
	[DCTRL] = {
		.name = "DCTRL",
		.description = "Control interface",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DSMPP] = {
		.name = "DSMPP",
		.description = "SMPP interface for external SMS apps",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DRANAP] = {
		.name = "DRANAP",
		.description = "Radio Access Network Application Part Protocol",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DVLR] = {
		.name = "DVLR",
		.description = "Visitor Location Register",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DIUCS] = {
		.name = "DIUCS",
		.description = "Iu-CS Protocol",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DBSSAP] = {
		.name = "DBSSAP",
		.description = "BSSAP Protocol (A Interface)",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DSGS] = {
		.name = "DSGS",
		.description = "SGs Interface (SGsAP)",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},


};

static int filter_fn(const struct log_context *ctx, struct log_target *tar)
{
	const struct vlr_subscr *vsub = ctx->ctx[LOG_CTX_VLR_SUBSCR];

	if ((tar->filter_map & (1 << LOG_FLT_VLR_SUBSCR)) != 0
	    && vsub && vsub == tar->filter_data[LOG_FLT_VLR_SUBSCR])
		return 1;

	return 0;
}

const struct log_info log_info = {
	.filter_fn = filter_fn,
	.cat = msc_default_categories,
	.num_cat = ARRAY_SIZE(msc_default_categories),
};

extern void *tall_gsms_ctx;
extern void *tall_call_ctx;
extern void *tall_trans_ctx;

int main(int argc, char **argv)
{
	int rc;

	/* Track the use of talloc NULL memory contexts */
	talloc_enable_null_tracking();

	osmo_fsm_term_safely(true);

	msc_vty_info.copyright	= osmomsc_copyright;

	tall_msc_ctx = talloc_named_const(NULL, 1, "osmo_msc");
	msc_vty_info.tall_ctx = tall_msc_ctx;

	msgb_talloc_ctx_init(tall_msc_ctx, 0);
	osmo_signal_talloc_ctx_init(tall_msc_ctx);
	tall_gsms_ctx = talloc_named_const(tall_msc_ctx, 0, "sms");
	tall_call_ctx = talloc_named_const(tall_msc_ctx, 0, "gsm_call");
	tall_trans_ctx = talloc_named_const(tall_msc_ctx, 0, "transaction");

	osmo_init_logging2(tall_msc_ctx, &log_info);
	osmo_stats_init(tall_msc_ctx);

	/* For --version, vty_init() must be called before handling options */
	vty_init(&msc_vty_info);

	osmo_ss7_init();
	osmo_ss7_vty_init_asp(tall_msc_ctx);
	osmo_sccp_vty_init();

	/* Parse options */
	handle_options(argc, argv);

	/* Allocate global gsm_network struct.
	 * At first set the internal MNCC as default, may be changed below according to cfg or cmdline option. */
	msc_network = msc_network_alloc(tall_msc_ctx, int_mncc_recv);
	if (!msc_network)
		return -ENOMEM;

	if (msc_vlr_alloc(msc_network)) {
		fprintf(stderr, "Failed to allocate VLR\n");
		exit(1);
	}

	ctrl_vty_init(tall_msc_ctx);
	logging_vty_add_cmds(&log_info);
	osmo_talloc_vty_add_cmds();
	msc_vty_init(msc_network);

#ifdef BUILD_SMPP
	if (smpp_openbsc_alloc_init(tall_msc_ctx) < 0)
		return -1;
#endif
	sgs_iface_init(tall_msc_ctx, msc_network);

	rc = vty_read_config_file(msc_cmdline_config.config_file, NULL);
	if (rc < 0) {
		LOGP(DMSC, LOGL_FATAL, "Failed to parse the config file: '%s'\n",
		     msc_cmdline_config.config_file);
		return 1;
	}

	/* Initialize MNCC socket if appropriate. If the cmdline option -M is present, it overrides the .cfg file
	 * setting 'msc' / 'mncc external MNCC_SOCKET_PATH'. Note that when -M is given, it "bleeds" back into the vty
	 * 'write' command and is reflected in the written out 'mncc external' cfg. */
	if (msc_cmdline_config.mncc_sock_path) {
		LOGP(DMNCC, LOGL_NOTICE,
		     "MNCC socket path is configured from commandline argument -M."
		     " This affects a written-back config file. Instead consider using the config file directly"
		     " ('msc' / 'mncc external MNCC_SOCKET_PATH').\n");
		gsm_network_set_mncc_sock_path(msc_network, msc_cmdline_config.mncc_sock_path);
	}
	if (msc_network->mncc_sock_path) {
		msc_network->mncc_recv = mncc_sock_from_cc;
		rc = mncc_sock_init(msc_network,
				    msc_network->mncc_sock_path);
		if (rc) {
			fprintf(stderr, "MNCC socket initialization failed. exiting.\n");
			exit(1);
		}
	} else
		DEBUGP(DMNCC, "Using internal MNCC handler.\n");

	/* start telnet after reading config for vty_get_bind_addr() */
	rc = telnet_init_dynif(tall_msc_ctx, &msc_network,
			       vty_get_bind_addr(), OSMO_VTY_PORT_MSC);
	if (rc < 0)
		return 2;

	/* BSC stuff is to be split behind an A-interface to be used with
	 * OsmoBSC, but there is no need to remove it yet. Most of the
	 * following code until iu_init() is legacy. */

#ifdef BUILD_SMPP
	smpp_openbsc_start(msc_network);
#endif

	/* start control interface after reading config for
	 * ctrl_vty_get_bind_addr() */
	msc_network->ctrl = ctrl_interface_setup_dynip(msc_network, ctrl_vty_get_bind_addr(),
						       OSMO_CTRL_PORT_MSC, NULL);
	if (!msc_network->ctrl) {
		printf("Failed to initialize control interface. Exiting.\n");
		return -1;
	}

#if 0
TODO: we probably want some of the _net_ ctrl commands from bsc_base_ctrl_cmds_install().
	if (bsc_base_ctrl_cmds_install() != 0) {
		printf("Failed to initialize the BSC control commands.\n");
		return -1;
	}
#endif

	if (msc_ctrl_cmds_install(msc_network) != 0) {
		printf("Failed to initialize the MSC control commands.\n");
		return -1;
	}

	/* seed the PRNG */
	srand(time(NULL));
	/* TODO: is this used for crypto?? Improve randomness, at least we
	 * should try to use the nanoseconds part of the current time. */

	if (db_init(msc_cmdline_config.database_name)) {
		printf("DB: Failed to init database: %s\n",
		       msc_cmdline_config.database_name);
		return 4;
	}

	osmo_fsm_log_addr(true);
	if (msc_vlr_start(msc_network)) {
		fprintf(stderr, "Failed to start VLR\n");
		exit(1);
	}

	ran_conn_init();

	if (db_prepare()) {
		printf("DB: Failed to prepare database.\n");
		return 5;
	}

	/* setup the timer */
	osmo_timer_setup(&db_sync_timer, db_sync_timer_cb, NULL);
	if (msc_cmdline_config.use_db_counter)
		osmo_timer_schedule(&db_sync_timer, DB_SYNC_INTERVAL);

	signal(SIGINT, &signal_handler);
	signal(SIGTERM, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGUSR2, &signal_handler);
	osmo_init_ignore_signals();

	/* start the SMS queue */
	if (sms_queue_start(msc_network, 20) != 0)
		return -1;

	msc_network->mgw.client = mgcp_client_init(
			msc_network, &msc_network->mgw.conf);

	if (mgcp_client_connect(msc_network->mgw.client)) {
		printf("MGCPGW connect failed\n");
		return 7;
	}

	if (ss7_setup(tall_msc_ctx)) {
		printf("Setting up SCCP client failed.\n");
		return 8;
	}

	if (sgs_server_open(g_sgs)) {
		printf("Starting SGs server failed\n");
		return 9;
	}

#ifdef BUILD_IU
	/* Set up IuCS */
	ranap_iu_init(tall_msc_ctx, DRANAP, "OsmoMSC-IuCS", msc_network->iu.sccp, rcvmsg_iu_cs, rx_iu_event);
#endif

	/* Set up A interface */
	a_init(msc_network->a.sccp, msc_network);

	/* Init RRLP handlers */
	msc_rrlp_init();

	if (msc_cmdline_config.daemonize) {
		rc = osmo_daemonize();
		if (rc < 0) {
			perror("Error during daemonize");
			return 6;
		}
	}

	while (!quit) {
		log_reset_context();
		osmo_select_main(0);
	}

	msc_network_shutdown(msc_network);
	osmo_signal_dispatch(SS_L_GLOBAL, S_L_GLOBAL_SHUTDOWN, NULL);
	sleep(3);

	log_fini();

	/**
	 * Report the heap state of root context, then free,
	 * so both ASAN and Valgrind are happy...
	 */
	talloc_report_full(tall_msc_ctx, stderr);
	talloc_free(tall_msc_ctx);

	/* FIXME: VTY code still uses NULL-context */
	talloc_free(tall_vty_ctx);

	/**
	 * Report the heap state of NULL context, then free,
	 * so both ASAN and Valgrind are happy...
	 */
	talloc_report_full(NULL, stderr);
	talloc_disable_null_tracking();
	return 0;
}
