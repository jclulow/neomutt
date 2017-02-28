#ifndef BUFFER_INCLUDED
#define BUFFER_INCLUDED

#include <sys/types.h>

typedef struct
{
  char *data;	/* pointer to data */
  char *dptr;	/* current read/write position */
  size_t dsize;	/* length of data */
  int destroy;	/* destroy `data' when done? */
} BUFFER;

/* flags for mutt_extract_token() */
#define MUTT_TOKEN_EQUAL      1       /* treat '=' as a special */
#define MUTT_TOKEN_CONDENSE   (1<<1)  /* ^(char) to control chars (macros) */
#define MUTT_TOKEN_SPACE      (1<<2)  /* don't treat whitespace as a term */
#define MUTT_TOKEN_QUOTE      (1<<3)  /* don't interpret quotes */
#define MUTT_TOKEN_PATTERN    (1<<4)  /* !)|~ are terms (for patterns) */
#define MUTT_TOKEN_COMMENT    (1<<5)  /* don't reap comments */
#define MUTT_TOKEN_SEMICOLON  (1<<6)  /* don't treat ; as special */

BUFFER *mutt_buffer_new (void);
BUFFER * mutt_buffer_init (BUFFER *);
BUFFER * mutt_buffer_from (char *);
void mutt_buffer_free(BUFFER **);
int mutt_buffer_printf (BUFFER*, const char*, ...);
void mutt_buffer_addstr (BUFFER* buf, const char* s);
void mutt_buffer_addch (BUFFER* buf, char c);
int mutt_extract_token (BUFFER *, BUFFER *, int);

#endif

