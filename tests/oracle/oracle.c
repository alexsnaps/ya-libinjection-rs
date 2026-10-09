/*
 * The reference half of tests/differential.rs: runs libinjection itself,
 * the C library, over inputs and dumps everything it makes of them.
 *
 * Reads one hex-encoded input per line on stdin and writes one line per
 * input on stdout, with these space-separated fields:
 *
 *   S<0|1>:<fingerprint>       libinjection_sqli()
 *
 *   and for each of the six quote/dialect contexts k:
 *   T<k>:<tokens>/<stats>      the token stream, and the tokenizer's counters
 *   F<k>:<tokens>              the folded tokens
 *   P<k>:<fingerprint>,<0|1>   the fingerprint, and whether it is SQLi
 *
 *   X<0|1>                     libinjection_xss()
 *
 *   and for each of the five HTML contexts k:
 *   x<k>:<0|1>:<tokens>        libinjection_is_xss(), and the HTML5 tokens
 *
 * tests/differential.rs builds this against the sources in
 * tests/upstream/src and prints the same dump from the Rust port.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libinjection.h"
#include "libinjection_html5.h"
#include "libinjection_sqli.h"
#include "libinjection_xss.h"

static int hex_value(int c) { return c <= '9' ? c - '0' : (c | 32) - 'a' + 10; }

static void print_hex(const char *p, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        printf("%02x", (unsigned char)p[i]);
    }
}

static void print_token(const struct libinjection_sqli_token *t) {
    printf("[%02x %zu %zu %d %02x %02x ", (unsigned char)t->type, t->pos,
           t->len, t->count, (unsigned char)t->str_open,
           (unsigned char)t->str_close);
    print_hex(t->val, t->len);
    printf("]");
}

int main(void) {
    static const int contexts[] = {
        FLAG_QUOTE_NONE | FLAG_SQL_ANSI,   FLAG_QUOTE_NONE | FLAG_SQL_MYSQL,
        FLAG_QUOTE_SINGLE | FLAG_SQL_ANSI, FLAG_QUOTE_SINGLE | FLAG_SQL_MYSQL,
        FLAG_QUOTE_DOUBLE | FLAG_SQL_ANSI, FLAG_QUOTE_DOUBLE | FLAG_SQL_MYSQL};
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;

    while ((n = getline(&line, &cap, stdin)) > 0) {
        size_t len = 0;
        size_t i;
        int k;
        int count;
        char fingerprint[8];
        char *input;

        while (len * 2 + 1 < (size_t)n && line[len * 2] != '\n') {
            len++;
        }
        /* An exact-size heap copy, so that sanitizers see any read past
         * the end of the input. */
        input = malloc(len ? len : 1);
        if (input == NULL) {
            return 1;
        }
        for (i = 0; i < len; i++) {
            input[i] = (char)(hex_value(line[2 * i]) << 4 |
                              hex_value(line[2 * i + 1]));
        }

        count = libinjection_sqli(input, len, fingerprint);
        printf("S%d:%s", count, fingerprint);
        for (k = 0; k < 6; k++) {
            struct libinjection_sqli_state sf;

            libinjection_sqli_init(&sf, input, len, contexts[k]);
            printf(" T%d:", k);
            while (libinjection_sqli_tokenize(&sf)) {
                print_token(sf.current);
            }
            printf("/%d,%d,%d", sf.stats_tokens, sf.stats_comment_ddx,
                   sf.stats_comment_hash);

            libinjection_sqli_init(&sf, input, len, contexts[k]);
            count = libinjection_sqli_fold(&sf);
            printf(" F%d:", k);
            for (i = 0; i < (size_t)count; i++) {
                print_token(&sf.tokenvec[i]);
            }

            printf(" P%d:%s", k,
                   libinjection_sqli_fingerprint(&sf, contexts[k]));
            printf(",%d", libinjection_sqli_check_fingerprint(&sf));
        }

        printf(" X%d", (int)libinjection_xss(input, len));
        for (k = 0; k < 5; k++) {
            h5_state_t hs;

            printf(" x%d:%d:", k, (int)libinjection_is_xss(input, len, k));
            libinjection_h5_init(&hs, input, len, (enum html5_flags)k);
            while (libinjection_h5_next(&hs) == LIBINJECTION_RESULT_TRUE) {
                printf("(%d %zu %zu)", (int)hs.token_type,
                       (size_t)(hs.token_start - input), hs.token_len);
            }
        }
        printf("\n");
        free(input);
    }
    free(line);
    return 0;
}
