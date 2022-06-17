/* Simple HLR/VLR database backend using sqlite3 */
/* (C) 2008 by Jan Luebbe <jluebbe@debian.org>
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009,2022 by Harald Welte <laforge@gnumonks.org>
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

#include <stdint.h>
#include <inttypes.h>
#include <libgen.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sqlite3.h>

#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/gsm_subscriber.h>
#include <osmocom/msc/gsm_04_11.h>
#include <osmocom/msc/db.h>
#include <osmocom/msc/debug.h>
#include <osmocom/msc/vlr.h>

#include <osmocom/gsm/protocol/gsm_23_003.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/statistics.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/utils.h>

enum stmt_idx {
	DB_STMT_SMS_STORE,
	DB_STMT_SMS_GET,
	DB_STMT_SMS_GET_NEXT_UNSENT,
	DB_STMT_SMS_GET_UNSENT_FOR_SUBSCR,
	DB_STMT_SMS_GET_NEXT_UNSENT_RR_MSISDN,
	DB_STMT_SMS_MARK_DELIVERED,
	DB_STMT_SMS_INC_DELIVER_ATTEMPTS,
	DB_STMT_SMS_DEL_BY_MSISDN,
	DB_STMT_SMS_DEL_BY_ID,
	DB_STMT_SMS_DEL_EXPIRED,
	DB_STMT_SMS_GET_VALID_UNTIL_BY_ID,
	DB_STMT_SMS_GET_OLDEST_EXPIRED,
	_NUM_DB_STMT
};

struct db_context {
	char *fname;
	sqlite3 *db;
	sqlite3_stmt *stmt[_NUM_DB_STMT];
};

static struct db_context *g_dbc;


/***********************************************************************
 * DATABASE SCHEMA AND MIGRATION
 ***********************************************************************/

#define SCHEMA_REVISION "6"

enum {
	SCHEMA_META,
	INSERT_META,
	SCHEMA_SUBSCRIBER,
	SCHEMA_AUTH,
	SCHEMA_EQUIPMENT,
	SCHEMA_EQUIPMENT_WATCH,
	SCHEMA_SMS,
	SCHEMA_VLR,
	SCHEMA_APDU,
	SCHEMA_COUNTERS,
	SCHEMA_RATE,
	SCHEMA_AUTHKEY,
	SCHEMA_AUTHLAST,
};

static const char *create_stmts[] = {
	[SCHEMA_META] = "CREATE TABLE IF NOT EXISTS Meta ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"key TEXT UNIQUE NOT NULL, "
		"value TEXT NOT NULL"
		")",
	[INSERT_META] = "INSERT OR IGNORE INTO Meta "
		"(key, value) "
		"VALUES "
		"('revision', " SCHEMA_REVISION ")",
	[SCHEMA_SUBSCRIBER] = "CREATE TABLE IF NOT EXISTS Subscriber ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"created TIMESTAMP NOT NULL, "
		"updated TIMESTAMP NOT NULL, "
		"imsi NUMERIC UNIQUE NOT NULL, "
		"name TEXT, "
		"extension TEXT UNIQUE, "
		"authorized INTEGER NOT NULL DEFAULT 0, "
		"tmsi TEXT UNIQUE, "
		"lac INTEGER NOT NULL DEFAULT 0, "
		"expire_lu TIMESTAMP DEFAULT NULL"
		")",
	[SCHEMA_AUTH] = "CREATE TABLE IF NOT EXISTS AuthToken ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"subscriber_id INTEGER UNIQUE NOT NULL, "
		"created TIMESTAMP NOT NULL, "
		"token TEXT UNIQUE NOT NULL"
		")",
	[SCHEMA_EQUIPMENT] = "CREATE TABLE IF NOT EXISTS Equipment ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"created TIMESTAMP NOT NULL, "
		"updated TIMESTAMP NOT NULL, "
		"name TEXT, "
		"classmark1 NUMERIC, "
		"classmark2 BLOB, "
		"classmark3 BLOB, "
		"imei NUMERIC UNIQUE NOT NULL"
		")",
	[SCHEMA_EQUIPMENT_WATCH] = "CREATE TABLE IF NOT EXISTS EquipmentWatch ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"created TIMESTAMP NOT NULL, "
		"updated TIMESTAMP NOT NULL, "
		"subscriber_id NUMERIC NOT NULL, "
		"equipment_id NUMERIC NOT NULL, "
		"UNIQUE (subscriber_id, equipment_id) "
		")",
	[SCHEMA_SMS] = "CREATE TABLE IF NOT EXISTS SMS ("
		/* metadata, not part of sms */
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"created TIMESTAMP NOT NULL, "
		"sent TIMESTAMP, "
		"deliver_attempts INTEGER NOT NULL DEFAULT 0, "
		/* data directly copied/derived from SMS */
		"valid_until TIMESTAMP, "
		"reply_path_req INTEGER NOT NULL, "
		"status_rep_req INTEGER NOT NULL, "
		"is_report INTEGER NOT NULL, "
		"msg_ref INTEGER NOT NULL, "
		"protocol_id INTEGER NOT NULL, "
		"data_coding_scheme INTEGER NOT NULL, "
		"ud_hdr_ind INTEGER NOT NULL, "
		"src_addr TEXT NOT NULL, "
		"src_ton INTEGER NOT NULL, "
		"src_npi INTEGER NOT NULL, "
		"dest_addr TEXT NOT NULL, "
		"dest_ton INTEGER NOT NULL, "
		"dest_npi INTEGER NOT NULL, "
		"user_data BLOB, "	/* TP-UD */
		/* additional data, interpreted from SMS */
		"header BLOB, "		/* UD Header */
		"text TEXT "		/* decoded UD after UDH */
		")",
	[SCHEMA_VLR] = "CREATE TABLE IF NOT EXISTS VLR ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"created TIMESTAMP NOT NULL, "
		"updated TIMESTAMP NOT NULL, "
		"subscriber_id NUMERIC UNIQUE NOT NULL, "
		"last_bts NUMERIC NOT NULL "
		")",
	[SCHEMA_APDU] = "CREATE TABLE IF NOT EXISTS ApduBlobs ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"created TIMESTAMP NOT NULL, "
		"apdu_id_flags INTEGER NOT NULL, "
		"subscriber_id INTEGER NOT NULL, "
		"apdu BLOB "
		")",
	[SCHEMA_COUNTERS] = "CREATE TABLE IF NOT EXISTS Counters ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"timestamp TIMESTAMP NOT NULL, "
		"value INTEGER NOT NULL, "
		"name TEXT NOT NULL "
		")",
	[SCHEMA_RATE] = "CREATE TABLE IF NOT EXISTS RateCounters ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"timestamp TIMESTAMP NOT NULL, "
		"value INTEGER NOT NULL, "
		"name TEXT NOT NULL, "
		"idx INTEGER NOT NULL "
		")",
	[SCHEMA_AUTHKEY] = "CREATE TABLE IF NOT EXISTS AuthKeys ("
		"subscriber_id INTEGER PRIMARY KEY, "
		"algorithm_id INTEGER NOT NULL, "
		"a3a8_ki BLOB "
		")",
	[SCHEMA_AUTHLAST] = "CREATE TABLE IF NOT EXISTS AuthLastTuples ("
		"subscriber_id INTEGER PRIMARY KEY, "
		"issued TIMESTAMP NOT NULL, "
		"use_count INTEGER NOT NULL DEFAULT 0, "
		"key_seq INTEGER NOT NULL, "
		"rand BLOB NOT NULL, "
		"sres BLOB NOT NULL, "
		"kc BLOB NOT NULL "
		")",
};

/***********************************************************************
 * PREPARED STATEMENTS
 ***********************************************************************/

/* don't change this order as the code assumes this ordering when dereferencing
 * database query results! */
#define SEL_COLUMNS \
	"id," \
	"strftime('%s',created)," \
	"sent," \
	"deliver_attempts," \
	"strftime('%s', valid_until)," \
	"reply_path_req," \
	"status_rep_req," \
	"is_report," \
	"msg_ref," \
	"protocol_id," \
	"data_coding_scheme," \
	"ud_hdr_ind," \
	"src_addr," \
	"src_ton," \
	"src_npi," \
	"dest_addr," \
	"dest_ton," \
	"dest_npi," \
	"user_data," \
	"header," \
	"text"

enum db_sms_column_idx {
	COL_ID,
	COL_CREATED,
	COL_SENT,
	COL_DELIVER_ATTEMPTS,
	COL_VALID_UNTIL,
	COL_REPLY_PATH_REQ,
	COL_STATUS_REP_REQ,
	COL_IS_REPORT,
	COL_MSG_REF,
	COL_PROTOCOL_ID,
	COL_DATA_CODING_SCHEME,
	COL_UD_HDR_IND,
	COL_SRC_ADDR,
	COL_SRC_TON,
	COL_SRC_NPI,
	COL_DEST_ADDR,
	COL_DEST_TON,
	COL_DEST_NPI,
	COL_USER_DATA,
	COL_HEADER,
	COL_TEXT,
};

static const char *stmt_sql[] = {
	[DB_STMT_SMS_STORE] =
		"INSERT INTO SMS "
		 "(created, valid_until, reply_path_req, status_rep_req, is_report, "
		 " msg_ref, protocol_id, data_coding_scheme, ud_hdr_ind, user_data, text, "
		 " dest_addr, dest_ton, dest_npi, src_addr, src_ton, src_npi) "
		"VALUES "
		 "(datetime($created, 'unixepoch'), datetime($valid_until, 'unixepoch'), "
		 "$reply_path_req, $status_rep_req, $is_report, "
		 "$msg_ref, $protocol_id, $data_coding_scheme, $ud_hdr_ind, $user_data, $text, "
		 "$dest_addr, $dest_ton, $dest_npi, $src_addr, $src_ton, $src_npi)",
	[DB_STMT_SMS_GET] = "SELECT " SEL_COLUMNS " FROM SMS WHERE SMS.id = $id",
	[DB_STMT_SMS_GET_NEXT_UNSENT] =
		"SELECT " SEL_COLUMNS " FROM SMS"
		" WHERE sent IS NULL"
		" AND id >= $id"
		" AND deliver_attempts <= $attempts"
		" ORDER BY id LIMIT 1",
	[DB_STMT_SMS_GET_UNSENT_FOR_SUBSCR] =
		"SELECT " SEL_COLUMNS " FROM SMS"
		" WHERE sent IS NULL"
		" AND dest_addr = $dest_addr"
		" AND deliver_attempts <= $attempts"
		" ORDER BY id LIMIT 1",
	[DB_STMT_SMS_GET_NEXT_UNSENT_RR_MSISDN] =
		"SELECT " SEL_COLUMNS " FROM SMS"
		" WHERE sent IS NULL"
		" AND dest_addr > $dest_addr"
		" AND deliver_attempts <= $attempts"
		" ORDER BY dest_addr, id LIMIT 1",
	[DB_STMT_SMS_MARK_DELIVERED] =
		"UPDATE SMS "
		" SET sent = datetime('now') "
		" WHERE id = $id",
	[DB_STMT_SMS_INC_DELIVER_ATTEMPTS] =
		"UPDATE SMS "
		" SET deliver_attempts = deliver_attempts + 1 "
		" WHERE id = $id",
	[DB_STMT_SMS_DEL_BY_MSISDN] =
		"DELETE FROM SMS WHERE src_addr=$src_addr OR dest_addr=$dest_addr",
	[DB_STMT_SMS_DEL_BY_ID] =
		"DELETE FROM SMS WHERE id = $id AND sent is NOT NULL",
	[DB_STMT_SMS_DEL_EXPIRED] =
		"DELETE FROM SMS WHERE id = $id",
	[DB_STMT_SMS_GET_VALID_UNTIL_BY_ID] =
		"SELECT strftime('%s', valid_until) FROM SMS WHERE id = $id",
	[DB_STMT_SMS_GET_OLDEST_EXPIRED] =
		"SELECT id, strftime('%s', valid_until) FROM SMS ORDER BY valid_until LIMIT 1",
};

/***********************************************************************
 * libsqlite3 helpers
 ***********************************************************************/

/* libsqlite3 call-back for error logging */
static void sql3_error_log_cb(void *arg, int err_code, const char *msg)
{
	LOGP(DDB, LOGL_ERROR, "SQLITE3: (%d) %s\n", err_code, msg);
	osmo_log_backtrace(DDB, LOGL_ERROR);
}

/* libsqlite3 call-back for normal logging */
static void sql3_sql_log_cb(void *arg, sqlite3 *s3, const char *stmt, int type)
{
	switch (type) {
	case 0:
		LOGP(DDB, LOGL_DEBUG, "Opened database\n");
		break;
	case 1:
		LOGP(DDB, LOGL_DEBUG, "%s\n", stmt);
		break;
	case 2:
		LOGP(DDB, LOGL_DEBUG, "Closed database\n");
		break;
	default:
		LOGP(DDB, LOGL_DEBUG, "Unknown %d\n", type);
		break;
	}
}

/* remove statement bindings and reset statement to be re-executed */
static void db_remove_reset(sqlite3_stmt *stmt)
{
	sqlite3_clear_bindings(stmt);
	/* sqlite3_reset() just repeats an error code already evaluated during sqlite3_step(). */
	/* coverity[CHECKED_RETURN] */
	sqlite3_reset(stmt);
}

/** bind blob arg and do proper cleanup in case of failure. If param_name is
 * NULL, bind to the first parameter (useful for SQL statements that have only
 * one parameter). */
static bool db_bind_blob(sqlite3_stmt *stmt, const char *param_name,
			 const uint8_t *blob, size_t blob_len)
{
	int rc;
	int idx = param_name ? sqlite3_bind_parameter_index(stmt, param_name) : 1;
	if (idx < 1) {
		LOGP(DDB, LOGL_ERROR, "Error composing SQL, cannot bind parameter '%s'\n",
		     param_name);
		return false;
	}
	rc = sqlite3_bind_blob(stmt, idx, blob, blob_len, SQLITE_STATIC);
	if (rc != SQLITE_OK) {
		LOGP(DDB, LOGL_ERROR, "Error binding blob to SQL parameter %s: %d\n",
		     param_name ? param_name : "#1", rc);
		db_remove_reset(stmt);
		return false;
	}
	return true;
}

/** bind text arg and do proper cleanup in case of failure. If param_name is
 * NULL, bind to the first parameter (useful for SQL statements that have only
 * one parameter). */
static bool db_bind_text(sqlite3_stmt *stmt, const char *param_name, const char *text)
{
	int rc;
	int idx = param_name ? sqlite3_bind_parameter_index(stmt, param_name) : 1;
	if (idx < 1) {
		LOGP(DDB, LOGL_ERROR, "Error composing SQL, cannot bind parameter '%s'\n",
		     param_name);
		return false;
	}
	rc = sqlite3_bind_text(stmt, idx, text, -1, SQLITE_STATIC);
	if (rc != SQLITE_OK) {
		LOGP(DDB, LOGL_ERROR, "Error binding text to SQL parameter %s: %d\n",
		     param_name ? param_name : "#1", rc);
		db_remove_reset(stmt);
		return false;
	}
	return true;
}

/** bind int arg and do proper cleanup in case of failure. If param_name is
 * NULL, bind to the first parameter (useful for SQL statements that have only
 * one parameter). */
static bool db_bind_int(sqlite3_stmt *stmt, const char *param_name, int nr)
{
	int rc;
	int idx = param_name ? sqlite3_bind_parameter_index(stmt, param_name) : 1;
	if (idx < 1) {
		LOGP(DDB, LOGL_ERROR, "Error composing SQL, cannot bind parameter '%s'\n",
		     param_name);
		return false;
	}
	rc = sqlite3_bind_int(stmt, idx, nr);
	if (rc != SQLITE_OK) {
		LOGP(DDB, LOGL_ERROR, "Error binding int64 to SQL parameter %s: %d\n",
		     param_name ? param_name : "#1", rc);
		db_remove_reset(stmt);
		return false;
	}
	return true;
}

/** bind int64 arg and do proper cleanup in case of failure. If param_name is
 * NULL, bind to the first parameter (useful for SQL statements that have only
 * one parameter). */
static bool db_bind_int64(sqlite3_stmt *stmt, const char *param_name, int64_t nr)
{
	int rc;
	int idx = param_name ? sqlite3_bind_parameter_index(stmt, param_name) : 1;
	if (idx < 1) {
		LOGP(DDB, LOGL_ERROR, "Error composing SQL, cannot bind parameter '%s'\n",
		     param_name);
		return false;
	}
	rc = sqlite3_bind_int64(stmt, idx, nr);
	if (rc != SQLITE_OK) {
		LOGP(DDB, LOGL_ERROR, "Error binding int64 to SQL parameter %s: %d\n",
		     param_name ? param_name : "#1", rc);
		db_remove_reset(stmt);
		return false;
	}
	return true;
}

/* callback for sqlite3_exec() below */
static int db_rev_exec_cb(void *priv, int num_cols, char **vals, char **names)
{
	char **rev_s = priv;
	OSMO_ASSERT(!strcmp(names[0], "value"));
	*rev_s = talloc_strdup(NULL, vals[0]);
	return 0;
}

static int check_db_revision(struct db_context *dbc)
{
	char *errstr = NULL;
	char *rev_s;
	int db_rev = 0;
	int rc;

	/* Make a query */
	rc = sqlite3_exec(dbc->db, "SELECT value FROM Meta WHERE key = 'revision'",
			  db_rev_exec_cb, &rev_s, &errstr);
	if (rc != SQLITE_OK) {
		LOGP(DDB, LOGL_ERROR, "Cannot execute SELECT value from META: %s\n", errstr);
		sqlite3_free(errstr);
		return -EINVAL;
	}

	if (!strcmp(rev_s, SCHEMA_REVISION)) {
		/* Everything is fine */
		talloc_free(rev_s);
		return 0;
	}

	LOGP(DDB, LOGL_NOTICE, "Detected DB Revision %s, expected %s\n", rev_s, SCHEMA_REVISION);

	db_rev = atoi(rev_s);
	talloc_free(rev_s);

	/* Incremental migration waterfall */
	switch (db_rev) {
	case 2:
	case 3:
	case 4:
		LOGP(DDB, LOGL_FATAL, "You must use osmo-msc 1.1.0 to 1.8.0 to upgrade database "
		     "schema from '%u' to '5', sorry\n", db_rev);
		break;
	case 5:
		LOGP(DDB, LOGL_FATAL, "The storage format of BINARY data in the database "
		     "has changed. In order to deliver any pending SMS in your database, "
		     "you must manually convert your database from "
		     "'%u' to '6'. Alternatively you can use a fresh, blank database "
		     "with this version of osmo-msc, sorry.\n", db_rev);
		return -1;
		break;
	default:
		LOGP(DDB, LOGL_FATAL, "Invalid database schema revision '%d'.\n", db_rev);
		return -EINVAL;
	}

	return 0;

//error:
	LOGP(DDB, LOGL_FATAL, "Failed to update database from schema revision '%d'.\n", db_rev);
	talloc_free(rev_s);

	return -EINVAL;
}

/***********************************************************************
 * USER API
 ***********************************************************************/

int db_init(void *ctx, const char *fname, bool enable_sqlite_logging)
{
	unsigned int i;
	int rc;
	bool has_sqlite_config_sqllog = false;

	g_dbc = talloc_zero(ctx, struct db_context);
	OSMO_ASSERT(g_dbc);

	/* we are a single-threaded program; we want to avoid all the mutex/etc. overhead */
	sqlite3_config(SQLITE_CONFIG_SINGLETHREAD);

	LOGP(DDB, LOGL_NOTICE, "Init database connection to '%s' using SQLite3 lib version %s\n",
	     fname, sqlite3_libversion());

	g_dbc->fname = talloc_strdup(g_dbc, fname);

	for (i = 0; i < 0xfffff; i++) {
		const char *o = sqlite3_compileoption_get(i);
		if (!o)
			break;
		LOGP(DDB, LOGL_DEBUG, "SQLite3 compiled with '%s'\n", o);
		if (!strcmp(o, "ENABLE_SQLLOG"))
			has_sqlite_config_sqllog = true;
	}

	if (enable_sqlite_logging) {
		rc = sqlite3_config(SQLITE_CONFIG_LOG, sql3_error_log_cb, NULL);
		if (rc != SQLITE_OK)
			LOGP(DDB, LOGL_NOTICE, "Unable to set SQLite3 error log callback\n");
	}

	if (has_sqlite_config_sqllog) {
		rc = sqlite3_config(SQLITE_CONFIG_SQLLOG, sql3_sql_log_cb, NULL);
		if (rc != SQLITE_OK)
			LOGP(DDB, LOGL_NOTICE, "Unable to set SQLite3 SQL log callback\n");
	} else {
		LOGP(DDB, LOGL_DEBUG, "Not setting SQL log callback:"
		     " SQLite3 compiled without support for it\n");
	}

	rc = sqlite3_open(g_dbc->fname, &g_dbc->db);
	if (rc != SQLITE_OK) {
		LOGP(DDB, LOGL_ERROR, "Unable to open DB; rc =%d\n", rc);
		talloc_free(g_dbc);
		return -1;
	}

	/* enable extended result codes */
	rc = sqlite3_extended_result_codes(g_dbc->db, 1);
	if (rc != SQLITE_OK) {
		LOGP(DDB, LOGL_ERROR, "Unable to enable SQLite3 extended result codes\n");
		/* non-fatal */
	}

	char *err_msg;
	rc = sqlite3_exec(g_dbc->db, "PRAGMA journal_mode=WAL; PRAGMA synchronous = NORMAL;", 0, 0, &err_msg);
	if (rc != SQLITE_OK) {
		LOGP(DDB, LOGL_ERROR, "Unable to set Write-Ahead Logging: %s\n", err_msg);
		sqlite3_free(err_msg);
		/* non-fatal */
	}

	rc = sqlite3_exec(g_dbc->db, "PRAGMA secure_delete=0;", 0, 0, &err_msg);
	if (rc != SQLITE_OK) {
		LOGP(DDB, LOGL_ERROR, "Unable to disable SECURE_DELETE: %s\n", err_msg);
		sqlite3_free(err_msg);
		/* non-fatal */
	}

	return 0;
}

int db_fini(void)
{
	unsigned int i;
	int rc;

	if (!g_dbc)
		return 0;

	for (i = 0; i < ARRAY_SIZE(g_dbc->stmt); i++) {
		/* it is ok to call finalize on NULL */
		sqlite3_finalize(g_dbc->stmt[i]);
	}

	/* Ask sqlite3 to close DB */
	rc = sqlite3_close(g_dbc->db);
	if (rc != SQLITE_OK) { /* Make sure it's actually closed! */
		LOGP(DDB, LOGL_ERROR, "Couldn't close database: (rc=%d) %s\n",
			rc, sqlite3_errmsg(g_dbc->db));
	}

	talloc_free(g_dbc);
	g_dbc = NULL;

	return 0;
}

/* run (execute) a series of SQL statements */
static int db_run_statements(struct db_context *dbc, const char **statements, size_t statements_count)
{
	int i;
	for (i = 0; i < statements_count; i++) {
		const char *stmt_str = statements[i];
		char *errmsg = NULL;
		int rc;

		rc = sqlite3_exec(dbc->db, stmt_str, NULL, NULL, &errmsg);
		if (rc != SQLITE_OK) {
			LOGP(DDB, LOGL_ERROR, "SQL error during SQL statement '%s': %s\n", stmt_str, errmsg);
			sqlite3_free(errmsg);
			return -1;
		}
	}
	return 0;
}

int db_prepare(void)
{
	unsigned int i;
	int rc;

	OSMO_ASSERT(g_dbc);
	rc = db_run_statements(g_dbc, create_stmts, ARRAY_SIZE(create_stmts));
	if (rc < 0) {
		LOGP(DDB, LOGL_ERROR, "Failed to create some table.\n");
		return 1;
	}

	if (check_db_revision(g_dbc) < 0) {
		LOGP(DDB, LOGL_FATAL, "Database schema revision invalid, "
			"please update your database schema\n");
                return -1;
	}

	/* prepare all SQL statements */
	for (i = 0; i < ARRAY_SIZE(g_dbc->stmt); i++) {
		rc = sqlite3_prepare_v2(g_dbc->db, stmt_sql[i], -1,
					&g_dbc->stmt[i], NULL);
		if (rc != SQLITE_OK) {
			LOGP(DDB, LOGL_ERROR, "Unable to prepare SQL statement '%s'\n", stmt_sql[i]);
			return -1;
		}
	}

	return 0;
}

/* store an [unsent] SMS to the database */
int db_sms_store(struct gsm_sms *sms)
{
	OSMO_ASSERT(g_dbc);
	sqlite3_stmt *stmt = g_dbc->stmt[DB_STMT_SMS_STORE];
	time_t now, validity_timestamp;
	int rc;

	now = time(NULL);
	validity_timestamp = now + sms->validity_minutes * 60;

	db_bind_int64(stmt, "$created", (int64_t) now);
	db_bind_int64(stmt, "$valid_until", (int64_t) validity_timestamp);
	db_bind_int(stmt, "$reply_path_req", sms->reply_path_req);
	db_bind_int(stmt, "$status_rep_req", sms->status_rep_req);
	db_bind_int(stmt, "$is_report", sms->is_report);
	db_bind_int(stmt, "$msg_ref", sms->msg_ref);
	db_bind_int(stmt, "$protocol_id", sms->protocol_id);
	db_bind_int(stmt, "$data_coding_scheme", sms->data_coding_scheme);
	db_bind_int(stmt, "$ud_hdr_ind", sms->ud_hdr_ind);
	/* FIXME: do we need to use legacy DBI compatible quoting of sms->user_data? */
	db_bind_blob(stmt, "$user_data", sms->user_data, sms->user_data_len);
	db_bind_text(stmt, "$text", (char *)sms->text);
	db_bind_text(stmt, "$dest_addr", (char *)sms->dst.addr);
	db_bind_int(stmt, "$dest_ton", sms->dst.ton);
	db_bind_int(stmt, "$dest_npi", sms->dst.npi);
	db_bind_text(stmt, "$src_addr", (char *)sms->src.addr);
	db_bind_int(stmt, "$src_ton", sms->src.ton);
	db_bind_int(stmt, "$src_npi", sms->src.npi);

	/* execute statement */
	rc = sqlite3_step(stmt);
	db_remove_reset(stmt);
	if (rc != SQLITE_DONE) {
		LOGP(DDB, LOGL_ERROR, "Cannot create SMS: SQL error: (%d) %s\n", rc, sqlite3_errmsg(g_dbc->db));
		return -EIO;
	}

	sms->id = sqlite3_last_insert_rowid(g_dbc->db);

	LOGP(DLSMS, LOGL_INFO, "Stored SMS id=%llu in DB\n", sms->id);

	return 0;
}

static void parse_tp_ud_from_result(struct gsm_sms *sms, sqlite3_stmt *stmt)
{
	const unsigned char *user_data;
	unsigned int user_data_len;
	unsigned int text_len;
	const char *text;

	/* Retrieve TP-UDL (User-Data-Length) in octets (regardless of DCS) */
	user_data_len = sqlite3_column_bytes(stmt, COL_USER_DATA);
	if (user_data_len > sizeof(sms->user_data)) {
		LOGP(DDB, LOGL_ERROR,
		     "SMS TP-UD length %u is too big, truncating to %zu\n",
		     user_data_len, sizeof(sms->user_data));
		user_data_len = (uint8_t) sizeof(sms->user_data);
	}
	sms->user_data_len = user_data_len;

	/* Retrieve the TP-UD (User-Data) itself */
	if (user_data_len > 0) {
		user_data = sqlite3_column_blob(stmt, COL_USER_DATA);
		memcpy(sms->user_data, user_data, user_data_len);
	}

	/* Retrieve the text length (excluding '\0') */
	text_len = sqlite3_column_bytes(stmt, COL_TEXT);
	if (text_len >= sizeof(sms->text)) {
		LOGP(DDB, LOGL_ERROR,
		     "SMS text length %u is too big, truncating to %zu\n",
		     text_len, sizeof(sms->text) - 1);
		/* OSMO_STRLCPY_ARRAY() does truncation for us */
	}

	/* Retrieve the text parsed from TP-UD (User-Data) */
	text = (const char *)sqlite3_column_text(stmt, COL_TEXT);
	if (text)
		OSMO_STRLCPY_ARRAY(sms->text, text);
}

static struct gsm_sms *sms_from_result(struct gsm_network *net, sqlite3_stmt *stmt)
{
	struct gsm_sms *sms = sms_alloc();
	const char *daddr, *saddr;
	time_t validity_timestamp;

	if (!sms)
		return NULL;

	sms->id = sqlite3_column_int64(stmt, COL_ID);

	sms->created = sqlite3_column_int64(stmt, COL_CREATED);
	validity_timestamp = sqlite3_column_int64(stmt, COL_VALID_UNTIL);

	sms->validity_minutes = (validity_timestamp - sms->created) / 60;
	sms->reply_path_req = sqlite3_column_int(stmt, COL_REPLY_PATH_REQ);
	sms->status_rep_req = sqlite3_column_int(stmt, COL_STATUS_REP_REQ);
	sms->is_report = sqlite3_column_int(stmt, COL_IS_REPORT);
	sms->msg_ref = sqlite3_column_int(stmt, COL_MSG_REF);
	sms->ud_hdr_ind = sqlite3_column_int(stmt, COL_UD_HDR_IND);
	sms->protocol_id = sqlite3_column_int(stmt, COL_PROTOCOL_ID);
	sms->data_coding_scheme = sqlite3_column_int(stmt, COL_DATA_CODING_SCHEME);

	sms->dst.npi = sqlite3_column_int(stmt, COL_DEST_NPI);
	sms->dst.ton = sqlite3_column_int(stmt, COL_DEST_TON);
	daddr = (const char *)sqlite3_column_text(stmt, COL_DEST_ADDR);
	if (daddr)
		OSMO_STRLCPY_ARRAY(sms->dst.addr, daddr);

	if (net != NULL) /* db_sms_test passes NULL, so we need to be tolerant */
		sms->receiver = vlr_subscr_find_by_msisdn(net->vlr, sms->dst.addr,
							  VSUB_USE_SMS_RECEIVER);

	sms->src.npi = sqlite3_column_int(stmt, COL_SRC_NPI);
	sms->src.ton = sqlite3_column_int(stmt, COL_SRC_TON);
	saddr = (const char *)sqlite3_column_text(stmt, COL_SRC_ADDR);
	if (saddr)
		OSMO_STRLCPY_ARRAY(sms->src.addr, saddr);

	/* Parse TP-UD, TP-UDL and decoded text */
	parse_tp_ud_from_result(sms, stmt);

	return sms;
}

struct gsm_sms *db_sms_get(struct gsm_network *net, unsigned long long id)
{
	OSMO_ASSERT(g_dbc);
	sqlite3_stmt *stmt = g_dbc->stmt[DB_STMT_SMS_GET];
	struct gsm_sms *sms;
	int rc;

	db_bind_int64(stmt, "$id", id);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_ROW) {
		db_remove_reset(stmt);
		return NULL;
	}

	sms = sms_from_result(net, stmt);

	db_remove_reset(stmt);
	return sms;
}

struct gsm_sms *db_sms_get_next_unsent(struct gsm_network *net,
				       unsigned long long min_sms_id,
				       int max_failed)
{
	OSMO_ASSERT(g_dbc);
	sqlite3_stmt *stmt = g_dbc->stmt[DB_STMT_SMS_GET_NEXT_UNSENT];
	struct gsm_sms *sms;
	int rc;

	db_bind_int64(stmt, "$id", min_sms_id);
	db_bind_int(stmt, "$attempts", max_failed);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_ROW) {
		db_remove_reset(stmt);
		return NULL;
	}

	sms = sms_from_result(net, stmt);

	db_remove_reset(stmt);
	return sms;
}

/* retrieve the next unsent SMS for a given subscriber */
struct gsm_sms *db_sms_get_unsent_for_subscr(struct vlr_subscr *vsub,
					     int max_failed)
{
	OSMO_ASSERT(g_dbc);
	sqlite3_stmt *stmt = g_dbc->stmt[DB_STMT_SMS_GET_UNSENT_FOR_SUBSCR];
	struct gsm_network *net = vsub->vlr->user_ctx;
	struct gsm_sms *sms;
	int rc;

	if (!vsub->lu_complete)
		return NULL;

	/* A subscriber having no phone number cannot possibly receive SMS. */
	if (*vsub->msisdn == '\0')
		return NULL;

	db_bind_text(stmt, "$dest_addr", vsub->msisdn);
	db_bind_int(stmt, "$attempts", max_failed);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_ROW) {
		db_remove_reset(stmt);
		return NULL;
	}

	sms = sms_from_result(net, stmt);

	db_remove_reset(stmt);
	return sms;
}

struct gsm_sms *db_sms_get_next_unsent_rr_msisdn(struct gsm_network *net,
						 const char *last_msisdn,
						 int max_failed)
{
	OSMO_ASSERT(g_dbc);
	sqlite3_stmt *stmt = g_dbc->stmt[DB_STMT_SMS_GET_NEXT_UNSENT_RR_MSISDN];
	struct gsm_sms *sms;
	int rc;

	db_bind_text(stmt, "$dest_addr", last_msisdn);
	db_bind_int(stmt, "$attempts", max_failed);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_ROW) {
		db_remove_reset(stmt);
		return NULL;
	}

	sms = sms_from_result(net, stmt);

	db_remove_reset(stmt);

	return sms;
}

/* mark a given SMS as delivered */
int db_sms_mark_delivered(struct gsm_sms *sms)
{
	sqlite3_stmt *stmt;
	int rc;

	/* this only happens in unit tests that don't db_init() */
	if (!g_dbc)
		return 0;

	stmt = g_dbc->stmt[DB_STMT_SMS_MARK_DELIVERED];
	db_bind_int64(stmt, "$id", sms->id);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		db_remove_reset(stmt);
		LOGP(DDB, LOGL_ERROR, "Failed to mark SMS %llu as sent.\n", sms->id);
		return 1;
	}

	db_remove_reset(stmt);
	return 0;
}

/* increase the number of attempted deliveries */
int db_sms_inc_deliver_attempts(struct gsm_sms *sms)
{
	sqlite3_stmt *stmt;
	int rc;

	/* this only happens in unit tests that don't db_init() */
	if (!g_dbc)
		return 0;

	stmt = g_dbc->stmt[DB_STMT_SMS_INC_DELIVER_ATTEMPTS];
	db_bind_int64(stmt, "$id", sms->id);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		db_remove_reset(stmt);
		LOGP(DDB, LOGL_ERROR, "Failed to inc deliver attempts for SMS %llu.\n", sms->id);
		return 1;
	}

	db_remove_reset(stmt);
	return 0;
}

/* Drop all pending SMS to or from the given extension */
int db_sms_delete_by_msisdn(const char *msisdn)
{
	OSMO_ASSERT(g_dbc);
	sqlite3_stmt *stmt = g_dbc->stmt[DB_STMT_SMS_DEL_BY_MSISDN];
	int rc;

	if (!msisdn || !*msisdn)
		return 0;

	db_bind_text(stmt, "$src_addr", msisdn);
	db_bind_text(stmt, "$dest_addr", msisdn);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		db_remove_reset(stmt);
		LOGP(DDB, LOGL_ERROR, "Failed to delete SMS for %s\n", msisdn);
		return -1;
	}

	db_remove_reset(stmt);
	return 0;
}

int db_sms_delete_sent_message_by_id(unsigned long long sms_id)
{
	OSMO_ASSERT(g_dbc);
	sqlite3_stmt *stmt = g_dbc->stmt[DB_STMT_SMS_DEL_BY_ID];
	int rc;

	db_bind_int64(stmt, "$id", sms_id);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		db_remove_reset(stmt);
		LOGP(DDB, LOGL_ERROR, "Failed to delete SMS %llu.\n", sms_id);
		return 1;
	}

	db_remove_reset(stmt);
	return 0;
}

static int delete_expired_sms(unsigned long long sms_id, time_t validity_timestamp)
{
	OSMO_ASSERT(g_dbc);
	sqlite3_stmt *stmt = g_dbc->stmt[DB_STMT_SMS_DEL_EXPIRED];
	time_t now;
	int rc;

	now = time(NULL);

	/* Net yet expired */
	if (validity_timestamp > now)
		return -1;

	db_bind_int64(stmt, "$id", sms_id);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		db_remove_reset(stmt);
		LOGP(DDB, LOGL_ERROR, "Failed to delete SMS %llu.\n", sms_id);
		return -1;
	}

	db_remove_reset(stmt);
	return 0;
}

int db_sms_delete_expired_message_by_id(unsigned long long sms_id)
{
	OSMO_ASSERT(g_dbc);
	sqlite3_stmt *stmt = g_dbc->stmt[DB_STMT_SMS_GET_VALID_UNTIL_BY_ID];
	time_t validity_timestamp;
	int rc;

	db_bind_int64(stmt, "$id", sms_id);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_ROW) {
		db_remove_reset(stmt);
		return -1;
	}

	validity_timestamp = sqlite3_column_int64(stmt, 0);

	db_remove_reset(stmt);
	return delete_expired_sms(sms_id, validity_timestamp);
}

void db_sms_delete_oldest_expired_message(void)
{
	OSMO_ASSERT(g_dbc);
	sqlite3_stmt *stmt = g_dbc->stmt[DB_STMT_SMS_GET_OLDEST_EXPIRED];
	int rc;

	rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW) {
		unsigned long long sms_id;
		time_t validity_timestamp;

		sms_id = sqlite3_column_int64(stmt, 0);
		validity_timestamp = sqlite3_column_int64(stmt, 1);
		delete_expired_sms(sms_id, validity_timestamp);
	}

	db_remove_reset(stmt);
}
