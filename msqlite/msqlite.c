


#include "config.h"
#include "mutt.h"
#include "mx.h"
#include "url.h"
#include "mailbox.h"
#include "browser.h"
#include "msqlite.h"
#include "string.h"
#include "strings.h"
#include "sort.h"

#ifdef	USE_HCACHE
#include "hcache.h"
#endif

#include "sqlite3.h"

#include <sys/time.h>
#include <sys/avl.h>
#include <sys/debug.h>


typedef struct msqlite {
	CONTEXT *msql_ctx;

	sqlite3 *msql_db;

	char *msql_file;
	char *msql_mbox;

	hrtime_t msql_last_check;
	char *msql_last_update_stamp;

	avl_tree_t msql_msgid_to_data;
} msqlite_t;

typedef struct msqlite_data {
	char *msqd_message_id;
	char *msqd_history_id;
	char *msqd_thread_id;
	avl_node_t msqd_node;

	HEADER *msqd_header;

	int msqd_last_deleted;
} msqlite_data_t;

static int
msqlite_data_comparator(const void *lp, const void *rp)
{
	const msqlite_data_t *lmsqd = lp;
	const msqlite_data_t *rmsqd = rp;
	int cmp;

	cmp = strcmp(lmsqd->msqd_message_id, rmsqd->msqd_message_id);

	return (cmp < 0 ? -1 : cmp > 0 ? 1 : 0);
}

#if 0
static void
msqlite_data_add(msqlite_t *msql, msqlite_data_t *msqd)
{
	avl_index_t where;

	if (avl_find(&msql->msql_msgid_to_data, msqd) != NULL) {
		mutt_error("duplicate message ID %s in avl tree?!",
		    msqd->msqd_message_id);
		mutt_sleep(2);
		abort();
	}

	avl_insert(&kj
}
#endif

static int
mx_parse_sqlite_path(const char *path, char **file, char **mbox)
{
	char *t = strdup(path);
	char *t_scheme = NULL, *t_file = NULL, *t_mbox = NULL;
	char *a;

	t_scheme = t;
	if ((a = strchr(t_scheme, '|')) == NULL) {
		mutt_error("invalid sqlite path (1): %s", path);
		free(t);
		return (-1);
	}
	*a = '\0';

	t_file = a + 1;
	if ((a = strchr(t_file, '|')) == NULL) {
		mutt_error("invalid sqlite path (2): %s", path);
		free(t);
		return (-1);
	}
	*a = '\0';

	t_mbox = a + 1;

	if (strcmp(t_scheme, "sqlite") != 0 || strlen(t_file) < 1) {
		mutt_error("invalid sqlite path (3): %s", path);
		free(t);
		return (-1);
	}

	if (file != NULL) {
		*file = safe_strdup(t_file);
	}
	if (mbox != NULL) {
		while (*t_mbox == '/') /* XXX mutt seems to add a "/" */
			t_mbox++;
		*mbox = safe_strdup(t_mbox);
	}

	free(t);
	return (0);
}

int
mx_is_msqlite(const char *path)
{
	if (path == NULL) {
		return (0);
	}

	return (mx_parse_sqlite_path(path, NULL, NULL) == 0);
}

static void
msqlite_add_folder(struct browser_state *state, const char *file,
    const char *name, const char *typ)
{
	if (state->entrylen + 1 >= state->entrymax) {
		safe_realloc(&state->entry, sizeof (struct folder_file) *
		    (state->entrymax += 256));
		bzero(state->entry + state->entrylen,
		    (sizeof (struct folder_file) * (state->entrymax -
		    state->entrylen)));
	}

	int idx = state->entrylen;
	state->entrylen++;

	char tmp[500];
	snprintf(tmp, sizeof (tmp), "%s", name);
	state->entry[idx].name = safe_strdup(tmp);

	snprintf(tmp, sizeof (tmp), "%s (%s)", name, typ);
	state->entry[idx].desc = safe_strdup(tmp);
}

static int
msqlite_close_database(sqlite3 **dbp)
{
	if (sqlite3_close(*dbp) != SQLITE_OK) {
		mutt_message("sqlite3_close failed: %s", sqlite3_errmsg(*dbp));
		return (-1);
	}

	*dbp = NULL;
	return (0);
}

static int
msqlite_open_database(const char *path, sqlite3 **dbp)
{
	int r;

	if ((r = sqlite3_open_v2(path, dbp, SQLITE_OPEN_READWRITE, NULL)) !=
	    SQLITE_OK) {
		mutt_message("sqlite3_open_v2 (%s) failed: %s", path,
		    sqlite3_errstr(r));

		*dbp = NULL;
		return (-1);
	}

	return (0);
}

#define	QUERY_LABELS \
	"SELECT\n" \
	"	l.name,\n" \
	"	l.type\n" \
	"FROM\n" \
	"	label l\n" \
	"ORDER BY\n" \
	"	l.type ASC,\n" \
	"	l.name ASC\n"

int
msqlite_browse(const char *f, struct browser_state *state)
{
	char *file = NULL, *mbox = NULL;
	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc = 0;
	int rr;

	if (mx_parse_sqlite_path(f, &file, &mbox) != 0) {
		return (-1);
	}

	if (msqlite_open_database(file, &db) != 0) {
		free(file);
		free(mbox);
		return (-1);
	}

	if (sqlite3_prepare(db, QUERY_LABELS, strlen(QUERY_LABELS), &stmt,
	    NULL) != SQLITE_OK) {
		mutt_error("prepare failed: %s", sqlite3_errmsg(db));
		mutt_sleep(1);
		rc = -1;
		goto skip_query;
	}

	msqlite_add_folder(state, file, "archive", "XXX");

	while ((rr = sqlite3_step(stmt)) == SQLITE_ROW) {
		const char *name = (char *)sqlite3_column_text(stmt, 0);
		const char *type = (char *)sqlite3_column_text(stmt, 1);

		if (strncmp(name, "CATEGORY_", strlen("CATEGORY_")) == 0) {
			continue;
		}

		msqlite_add_folder(state, file, name, type);
	}

	if (rr != SQLITE_DONE) {
		mutt_error("query failed: %s", sqlite3_errmsg(db));
		mutt_sleep(1);
	}

skip_query:
	sqlite3_finalize(stmt);

	if (msqlite_close_database(&db) != 0) {
		return (-1);
	}

	return (rc);
}

static int
msqlite_open_mailbox_append(CONTEXT *ctx)
{
	fprintf(stderr, "ENTER: %s\n", __func__);
	abort();
}

static int
msqlite_close_mailbox(CONTEXT *ctx)
{
	msqlite_t *msql = ctx->data;

	if (msql == NULL) {
		return (0);
	}

	if (sqlite3_close(msql->msql_db) != SQLITE_OK) {
		mutt_message("sqlite3_close failed");
		return (-1);
	}

	msqlite_data_t *msqd;
	void *cookie = NULL;
	while ((msqd = avl_destroy_nodes(&msql->msql_msgid_to_data,
	    &cookie)) != NULL) {
		safe_free(&msqd->msqd_message_id);
		safe_free(&msqd->msqd_history_id);
		safe_free(&msqd->msqd_thread_id);
		safe_free(&msqd);
	}
	avl_destroy(&msql->msql_msgid_to_data);

	free(msql->msql_file);
	free(msql->msql_mbox);
	free(msql);
	ctx->data = NULL;

	return (0);
}

static int
msqlite_open_mailbox(CONTEXT *ctx)
{
	msqlite_t *msql;
	int r;

	/*
	 * XXX we get here first!
	 */

	if ((msql = calloc(1, sizeof (*msql))) == NULL) {
		mutt_perror("msqlite_open_mailbox");
		return (-1);
	}

	/*
	 * XXX This should perhaps use the mutt-internal hash_create()?
	 */
	avl_create(&msql->msql_msgid_to_data, msqlite_data_comparator,
	    sizeof (msqlite_data_t), offsetof(msqlite_data_t, msqd_node));

	if (mx_parse_sqlite_path(ctx->path, &msql->msql_file,
	    &msql->msql_mbox) != 0) {
		free(msql);
		mutt_sleep(1);
		return (-1);
	}

	msql->msql_ctx = ctx;
	ctx->data = msql;

	mutt_message(_("opening sqlite db..."));

	if ((r = sqlite3_open_v2(msql->msql_file, &msql->msql_db,
	    SQLITE_OPEN_READWRITE, NULL)) != SQLITE_OK) {
		mutt_message("sqlite3_open_v2 (%s) failed: %s",
		    msql->msql_file, sqlite3_errstr(r));
		free(msql);
		ctx->data = NULL;
		return (-1);
	}

	mutt_message(_("open ok"));

	bzero(ctx->rights, sizeof (ctx->rights));
	mutt_bit_set(ctx->rights, MUTT_ACL_DELETE);

	return (0);
}

int
msqlite_sync_mailbox(CONTEXT *ctx, int *index_hint)
{
	//msqlite_t *msql = ctx->data;
	int i, j;
	//int reopen = 0;

	/*
	 * Find things that the user has marked as deleted:
	 */
	for (i = 0; i < ctx->msgcount; i++) {
		msqlite_data_t *msqd = ctx->hdrs[i]->data;
		HEADER *h = ctx->hdrs[i];

		if (h->deleted != msqd->msqd_last_deleted) {
			mutt_message("message %s deleted!",
			    msqd->msqd_message_id);
			mutt_sleep(1);

			h->active = 0;
		}
	}

	int old_count = ctx->msgcount;
	for (i = 0, j = 0; i < old_count; i++) {
		msqlite_data_t *msqd = ctx->hdrs[i]->data;
		HEADER *h = ctx->hdrs[i];

		if (h->active) {
			if (index_hint != NULL && *index_hint == i) {
				/*
				 * The index hint refers to this index in the
				 * table prior to modification.
				 */
				*index_hint = j;
			}

			h->index = j++;
		} else if (msqd != NULL) {
			/*
			 * Detach our private data from the now-inactive HEADER:
			 */
			msqd->msqd_header = NULL;
			h->data = NULL;
		}
	}

	mx_update_tables(ctx, 0);
	mutt_clear_threads(ctx);

	return (0);
	//fprintf(stderr, "ENTER: %s\n", __func__);
	//abort();
}


int
msqlite_open_new_message(MESSAGE *msg, CONTEXT *ctx, HEADER *hdr)
{
	fprintf(stderr, "ENTER: %s\n", __func__);
	abort();
}

static int
make_message_tempfile(FILE **fpp)
{
	FILE *fp;
	char tempfile[_POSIX_PATH_MAX];

	/*
	 * Open a temporary file...?
	 */
	mutt_mktemp(tempfile, sizeof (tempfile));
	if ((fp = safe_fopen(tempfile, "w+")) == NULL) {
		mutt_error(_("could not create temporary file %s"), tempfile);
		mutt_sleep(2);
		return (-1);
	}
	unlink(tempfile);

	*fpp = fp;
	return (0);
}

#define	QUERY_GET_LABEL_ID						\
	"SELECT\n"							\
	"	l.id\n"							\
	"FROM\n"							\
	"	label l\n"						\
	"WHERE\n"							\
	"	l.name = ?\n"

static char *
get_label_id(msqlite_t *msql, const char *name)
{
	sqlite3_stmt *stmt = NULL;
	char *label_id = NULL;
	int sqlite_fail = 1;
	int e = 0;

	if (sqlite3_prepare(msql->msql_db, QUERY_GET_LABEL_ID,
	    strlen(QUERY_GET_LABEL_ID), &stmt, NULL) != SQLITE_OK) {
		goto out;
	}

	if (sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC) != SQLITE_OK) {
		goto out;
	}

	switch (sqlite3_step(stmt)) {
	case SQLITE_ROW:
		sqlite_fail = 0;
		label_id = safe_strdup((char *)sqlite3_column_text(stmt, 0));
		break;

	case SQLITE_DONE:
		/*
		 * No match.
		 */
		sqlite_fail = 0;
		e = ENOENT;
		break;
	}

out:
	if (sqlite_fail) {
		mutt_error("get_label_id: %s", sqlite3_errmsg(msql->msql_db));
		mutt_sleep(1);
		e = EPROTO;
	}
	sqlite3_finalize(stmt);
	errno = e;
	return (label_id);
}

#define	QUERY_UPDATE_STAMP						\
	"SELECT\n"							\
	"	value\n"						\
	"FROM\n"							\
	"	update_stamp\n"						\
	"WHERE\n"							\
	"	key = ?\n"

static char *
get_update_stamp(msqlite_t *msql, const char *name)
{
	sqlite3_stmt *stmt = NULL;
	char *out = NULL;
	int sqlite_fail = 1;
	int e = 0;

	if (sqlite3_prepare(msql->msql_db, QUERY_UPDATE_STAMP,
	    strlen(QUERY_UPDATE_STAMP), &stmt, NULL) != SQLITE_OK) {
		goto out;
	}

	if (sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC) != SQLITE_OK) {
		goto out;
	}

	switch (sqlite3_step(stmt)) {
	case SQLITE_ROW:
		sqlite_fail = 0;
		out = safe_strdup((char *)sqlite3_column_text(stmt, 0));
		break;

	case SQLITE_DONE:
		/*
		 * No match.
		 */
		sqlite_fail = 0;
		e = ENOENT;
		break;
	}

out:
	if (sqlite_fail) {
		mutt_error("get_update_stamp(%s): %s",
		    name, sqlite3_errmsg(msql->msql_db));
		mutt_sleep(1);
		e = EPROTO;
	}
	sqlite3_finalize(stmt);
	errno = e;
	return (out);
}

#define	QUERY_MESSAGE_LABELS \
	"SELECT\n" \
	"	mtl.label_id\n" \
	"FROM\n" \
	"	message_to_label mtl\n" \
	"WHERE\n" \
	"	mtl.message_id = ?\n"

#define	QUERY_MESSAGE_RAW \
	"SELECT\n" \
	"	mr.raw\n" \
	"FROM\n" \
	"	message_raw mr\n" \
	"WHERE\n" \
	"	mr.id = ?\n"

static int
flags_from_db(msqlite_t *msql, const char *msg_id, HEADER *h, int *did_update)
{
	sqlite3_stmt *stmt;
	int orig_read, orig_flagged;

	if (sqlite3_prepare_v2(msql->msql_db, QUERY_MESSAGE_LABELS,
	    strlen(QUERY_MESSAGE_LABELS), &stmt, NULL) != SQLITE_OK) {
		sqlite3_finalize(stmt);
		mutt_error("fetch_from_db(%s): %s", msg_id,
		    sqlite3_errmsg(msql->msql_db));
		mutt_sleep(1);
		return (-1);
	}

	if (sqlite3_bind_text(stmt, 1, msg_id, -1,
	    SQLITE_STATIC) != SQLITE_OK) {
		mutt_error("sqlite3_bind_text: %s", sqlite3_errmsg(
		    msql->msql_db));
		mutt_sleep(1);
		return (-1);
	}

	orig_read = h->read;
	orig_flagged = h->flagged;

	h->read = 1;
	h->flagged = 0;

	int r;
	while ((r = sqlite3_step(stmt)) == SQLITE_ROW) {
		const char *l = (const char *)sqlite3_column_text(stmt, 0);

		if (strcmp(l, "UNREAD") == 0) {
			h->read = 0;
		} else if (strcmp(l, "STARRED") == 0) {
			h->flagged = 1;
		}
	}

	if (r != SQLITE_DONE) {
		mutt_error("msg %s flags error: %s", msg_id, sqlite3_errmsg(
		    msql->msql_db));
		mutt_sleep(2);
		sqlite3_finalize(stmt);
		return (-1);
	}

	if (did_update != NULL) {
		if (orig_read != h->read || orig_flagged != h->flagged)
			*did_update = 1;
	}

	sqlite3_finalize(stmt);
	return (0);
}

static int
fetch_from_db(msqlite_t *msql, const char *msg_id, FILE *fp)
{
	sqlite3_stmt *stmt;

	if (sqlite3_prepare_v2(msql->msql_db, QUERY_MESSAGE_RAW,
	    strlen(QUERY_MESSAGE_RAW), &stmt, NULL) != SQLITE_OK) {
		sqlite3_finalize(stmt);
		mutt_error("fetch_from_db(%s): %s", msg_id,
		    sqlite3_errmsg(msql->msql_db));
		mutt_sleep(1);
		return (-1);
	}

	if (sqlite3_bind_text(stmt, 1, msg_id, -1,
	    SQLITE_STATIC) != SQLITE_OK) {
		mutt_error("sqlite3_bind_text: %s", sqlite3_errmsg(
		    msql->msql_db));
		mutt_sleep(1);
		return (-1);
	}

	switch (sqlite3_step(stmt)) {
	case SQLITE_ROW:
		break;

	case SQLITE_DONE:
		mutt_error("msg %s not found in DB", msg_id);
		sqlite3_finalize(stmt);
		return (-1);

	default:
		mutt_error("msg %s error: %s", msg_id, sqlite3_errmsg(
		    msql->msql_db));
		mutt_sleep(2);
		sqlite3_finalize(stmt);
		return (-1);
	}

	const char *raw = (const char *)sqlite3_column_text(stmt, 0);
	int outlen;
	char *decoded = safe_malloc(strlen(raw) + 1);

	if ((outlen = mutt_from_base64url(decoded, raw)) < 0) {
		mutt_message("mutt_from_base64 fail");
		mutt_sleep(2);

		safe_free(&decoded);
		return (-1);
	}

	/*
	 * Scrub the decoded mail message of carriage returns.
	 */
	int i, j;
	for (i = 0, j = 0; i < outlen; i++) {
		if (decoded[i] == '\r') {
			continue;
		}

		decoded[j++] = decoded[i];
	}
	decoded[j] = '\0';

	/*
	 * Write the decoded and scrubbed mail message to the temporary file.
	 * Note that we do _not_ write the trailing NUL byte.
	 */
	fwrite(decoded, j, 1, fp);

	sqlite3_finalize(stmt);

	safe_free(&decoded);
	return (0);
}

#if 1
#define	QUERY_LABEL_MESSAGE_LIST \
	"SELECT\n" \
	"	m.id,\n" \
	"	m.history_id,\n" \
	"	m.thread_id,\n" \
	"	m.internal_date\n" \
	"FROM\n" \
	"	message m INNER JOIN message_to_label mtl\n" \
	"		ON (m.id = mtl.message_id)\n" \
	"WHERE\n" \
	"	mtl.label_id = ?\n" \
	"ORDER BY\n" \
	"	m.id ASC\n"
#else
#define	QUERY_LABEL_MESSAGE_LIST \
	"SELECT\n" \
	"	mtl.message_id AS id\n" \
	"FROM\n" \
	"	message_to_label mtl\n" \
	"WHERE\n" \
	"	mtl.label_id = ?\n" \
	"ORDER BY\n" \
	"	mtl.message_id ASC\n"
#endif

#define	QUERY_MESSAGE_LIST \
	"SELECT\n" \
	"	m.id,\n" \
	"	m.history_id,\n" \
	"	m.thread_id,\n" \
	"	m.internal_date\n" \
	"FROM\n" \
	"	message m\n" \
	"ORDER BY\n" \
	"	m.id ASC\n"

static int
get_from_db(msqlite_t *msql, const char *label_id, const char *thread_id, int *new_mail)
{
	CONTEXT *ctx = msql->msql_ctx;
	sqlite3_stmt *stmt;
	int r;
	FILE *fp;
	int updated_flags = 0;
	int updated_mail = 0;

	*new_mail = 0;

	mutt_message(_("make message tempfile"));
	if (make_message_tempfile(&fp) != 0) {
		return (-1);
	}

	mutt_message(_("prepare"));

	const char *q = (label_id == NULL) ? QUERY_MESSAGE_LIST :
	    QUERY_LABEL_MESSAGE_LIST;

	if (sqlite3_prepare_v2(msql->msql_db, q, strlen(q), &stmt,
	    NULL) != SQLITE_OK) {
		mutt_error("sqlite3_prepare fail");
		mutt_sleep(1);
		return (-1);
	}
	if (label_id != NULL && sqlite3_bind_text(stmt, 1, label_id, -1,
	    SQLITE_STATIC) != SQLITE_OK) {
		mutt_error("sqlite3_bind_text fail: %s", sqlite3_errmsg(
		    msql->msql_db));
		mutt_sleep(1);
		return (-1);
	}

	mutt_message(_("fetching from database..."));

	int count = 0;
	int oldmsgcount = ctx->msgcount;
	while ((r = sqlite3_step(stmt)) == SQLITE_ROW) {
		msqlite_data_t msqd_search;
		msqlite_data_t *msqd = NULL;
		const char *msg_id = (const char *)sqlite3_column_text(
		    stmt, 0);
		const char *hist_id = (const char *)sqlite3_column_text(
		    stmt, 1);
		const char *thr_id = (const char *)sqlite3_column_text(
		    stmt, 2);
		int64_t internal_date = sqlite3_column_int64(stmt, 3);

		/*
		 * First, check to see if we already have this message
		 * loaded.
		 */
		msqd_search.msqd_message_id = (char *)msg_id;
		if ((msqd = avl_find(&msql->msql_msgid_to_data,
		    &msqd_search, NULL)) != NULL) {
			if (msqd->msqd_header == NULL) {
				/*
				 * XXX DELETED...
				 */
				continue;
			}

			/*
			 * This message existed already.  Just update the
			 * flags.
			 */
			if (flags_from_db(msql, msg_id, msqd->msqd_header,
			    &updated_flags) != 0) {
				mutt_message("update flags failure (msg %s)",
				    msg_id);
				mutt_sleep(2);
			}
			continue;
		}

		/*
		 * This is a new message.  Fetch the entire contents from
		 * the database.
		 */
		errno = 0;
		rewind(fp);
		if (errno != 0) {
			/*
			 * XXX
			 */
			mutt_perror("rewind cache file");
			mutt_sleep(2);
			exit(10);
		}
		if (fetch_from_db(msql, msg_id, fp) != 0) {
			continue;
		}

		if (ctx->msgcount + 1 >= ctx->hdrmax) {
			mx_alloc_memory(ctx);
		}

		ctx->msgcount++;
		int idx = ctx->msgcount - 1;

		if (idx % 1000 == 0 && idx > 0) {
			mutt_message("getting message headers (%d)...", idx);
		}

		VERIFY3P(ctx->hdrs[idx], ==, NULL);
		ctx->hdrs[idx] = mutt_new_header();

		ctx->hdrs[idx]->index = idx;

		/*
		 * Get "read" and "flagged" from the DB:
		 */
		if (flags_from_db(msql, msg_id, ctx->hdrs[idx], NULL) != 0) {
			safe_free(&ctx->hdrs[idx]);
			ctx->msgcount--;
			continue;
		}

		msqd = safe_calloc(1, sizeof (*msqd));
		msqd->msqd_header = ctx->hdrs[idx];
		msqd->msqd_message_id = safe_strdup(msg_id);
		msqd->msqd_history_id = safe_strdup(hist_id);
		msqd->msqd_thread_id = safe_strdup(thr_id);
		msqd->msqd_last_deleted = 0;

		avl_add(&msql->msql_msgid_to_data, msqd);

		ctx->hdrs[idx]->active = 1;
		ctx->hdrs[idx]->old = 0;
		ctx->hdrs[idx]->deleted = 0;
		ctx->hdrs[idx]->replied = 0;
		ctx->hdrs[idx]->changed = 0;
		ctx->hdrs[idx]->received = internal_date / 1000;
		ctx->hdrs[idx]->data = msqd;

		rewind(fp);
		ctx->hdrs[idx]->env = mutt_read_rfc822_header(fp,
		    ctx->hdrs[idx], 0, 0);

		updated_mail = 1;
		count++;
	}

	if (r != SQLITE_DONE) {
		mutt_error("sqlite3_step fail");
		mutt_sleep(2);
	}

	mutt_message(_("update ctx"));
	mx_update_context(ctx, ctx->msgcount - oldmsgcount);

	mutt_message(_("finalize"));

	sqlite3_finalize(stmt);

	mutt_message(_("fclose"));

	safe_fclose(&fp);

	*new_mail = updated_mail ? MUTT_NEW_MAIL : updated_flags ? MUTT_FLAGS : 0;

	return (0);
}

#define	QUERY_THREAD_MESSAGE_LIST \
	"SELECT\n" \
	"	m.id,\n" \
	"	m.history_id,\n" \
	"	m.thread_id,\n" \
	"	m.internal_date\n" \
	"FROM\n" \
	"	message m\n" \
	"WHERE\n" \
	"	m.thread_id = ?\n" \
	"ORDER BY\n" \
	"	m.id ASC\n"

int
msqlite_entire_thread(CONTEXT *ctx, HEADER *h)
{
	msqlite_t *msql = ctx->data;

	if (h->data == NULL) {
		mutt_error("message does not have private data!");
		return (-1);
	}

	msqlite_data_t *msqd = h->data;
	mutt_message("loading thread \"%s\"", msqd->msqd_thread_id);

	for (int i = 0; i < ctx->msgcount; i++) {
		ctx->hdr[i]->active = 0;
	}

	mx_update_tables(ctx, 0);
	mutt_clear_threads(ctx);

	get_from_db(msql, NULL, msqd->msqd_thread_id, NULL);

	mx_update_tables(ctx, 0);
	mutt_clear_threads(ctx);

	return (0);
}

int
msqlite_check_mailbox(CONTEXT *ctx, int *index_hint)
{
	msqlite_t *msql = ctx->data;

	/*
	 * We should only even look at the database once every few seconds
	 * or so.
	 */
	if (msql->msql_last_check != 0) {
		if (gethrtime() - msql->msql_last_check < 2000000000LL) {
			return (0);
		}
	}

	/*
	 * We get here second!
	 */
	char *label_id, *update_stamp;
	int new_mail = 0;

	/*
	 * Determine the Label ID of the "folder" we are viewing:
	 */
	if (strcmp(msql->msql_mbox, "archive") == 0) {
		/*
		 * XXX This is the equivalent of "All Mail"...
		 */
		label_id = NULL;
	} else if ((label_id = get_label_id(msql, msql->msql_mbox)) == NULL) {
		mutt_error("could not find label \"%s\"",
		    msql->msql_mbox);
		mutt_sleep(2);
		return (-1);
	}

	/*
	 * Check to see if the database has been externally modified:
	 * XXX jclulow
	 */
	if ((update_stamp = get_update_stamp(msql, "global")) == NULL &&
	    errno != ENOENT) {
		mutt_error("could not read update stamp \"global\"");
		mutt_sleep(2);
		safe_free(&label_id);
		return (-1);
	} else if (update_stamp != NULL) {
		if (msql->msql_last_update_stamp == NULL) {
			msql->msql_last_update_stamp = update_stamp;
			goto update;
		}

		if (strcmp(update_stamp, msql->msql_last_update_stamp) == 0) {
			/*
			 * There has been no change.
			 */
			safe_free(&update_stamp);
			goto no_update;
		}

		safe_free(&msql->msql_last_update_stamp);
		msql->msql_last_update_stamp = update_stamp;
	}

update:
	get_from_db(msql, label_id, &new_mail);

no_update:
	safe_free(&label_id);
	msql->msql_last_check = gethrtime();
	return (new_mail);
}

static int
msqlite_close_message(CONTEXT *ctx, MESSAGE *msg)
{
	return (safe_fclose(&msg->fp));
}

static int
msqlite_fetch_message(CONTEXT *ctx, MESSAGE *msg, int msgno)
{
	msqlite_t *msql = ctx->data;
	HEADER *h = ctx->hdrs[msgno];
	ENVELOPE *newenv;

	char buf[LONG_STRING];

	/*
	 * Get here third!
	 */

	if (msg->fp == NULL) {
		msqlite_data_t *msqd = h->data;

		if (make_message_tempfile(&msg->fp) != 0) {
			return (-1);
		}

		if (fetch_from_db(msql, msqd->msqd_message_id, msg->fp) != 0) {
			return (-1);
		}
	}

	fflush(msg->fp);
	if (ferror(msg->fp)) {
		mutt_perror("cache file");
		safe_fclose(&msg->fp);
		return (-1);
	}

	errno = 0;
	rewind(msg->fp);
	if (errno != 0) {
		/*
		 * XXX
		 */
		mutt_perror("rewind cache file");
		mutt_sleep(2);
		exit(10);
	}

	newenv = mutt_read_rfc822_header(msg->fp, h, 0, 0);
	mutt_merge_envelopes(h->env, &newenv);

	h->lines = 0;
	fgets(buf, sizeof (buf), msg->fp);
	while (!feof(msg->fp)) {
		h->lines++;
		fgets(buf, sizeof (buf), msg->fp);
	}

	h->content->length = ftell(msg->fp) - h->content->offset;

	mutt_clear_error();
	rewind(msg->fp);

	return (0);
}

int
msqlite_commit_message(CONTEXT *ctx, MESSAGE *msg, HEADER *hdr)
{
	fprintf(stderr, "ENTER: %s\n", __func__);
	abort();
}

int
msqlite_check_empty(const char *path)
{
	fprintf(stderr, "ENTER: %s\n", __func__);
	abort();
}

struct mx_ops mx_msqlite_ops = {
	.open = msqlite_open_mailbox,
	.close = msqlite_close_mailbox,

	.check = msqlite_check_mailbox,

	.open_msg = msqlite_fetch_message,
	.close_msg = msqlite_close_message,

	.sync = msqlite_sync_mailbox
};
