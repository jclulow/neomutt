#ifndef	_MSQLITE_H
#define	_MSQLITE_H

#include "browser.h"

/*
 * Return 1 if this is a SQLite mailbox file, or 0 otherwise.
 */
extern int mx_is_msqlite(const char *path);

/*
 * Save changes to disk.
 * Return 0 on success or -1 on failure.
 * XXX NB: IMAP calls their sync hook with EXPUNGE set to 1.
 */
extern int msqlite_sync_mailbox (CONTEXT *ctx, int *index_hint);

/*
 * looks like 0 is OK, otherwise (-1?) not OK?
 * XXX look at imap_open_new_message() 
 */
extern int msqlite_open_new_message (MESSAGE *msg, CONTEXT *ctx, HEADER *hdr);

extern int msqlite_check_mailbox (CONTEXT *ctx, int *index_hint);

extern int msqlite_commit_message (CONTEXT *ctx, MESSAGE *msg, HEADER *hdr);

extern int msqlite_check_empty (const char *path);

extern int msqlite_browse(const char *f, struct browser_state *state);

extern int msqlite_entire_thread(CONTEXT *, HEADER *);

/*
 * XXX NOTES
 *
 * ctx->mx_close gets set to a function pointer for call in mx_fastclose_mailbox()...
 */

extern struct mx_ops mx_msqlite_ops;

#endif	/* !_MSQLITE_H */
