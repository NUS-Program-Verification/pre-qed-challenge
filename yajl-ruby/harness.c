#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <api/yajl_gen.h>
#include <api/yajl_parse.h>
#include <api/yajl_version.h>
#include "preqed_ltl.h"

/* containers the harness tracks; below YAJL_MAX_DEPTH (256, yajl_common.h), so the generator never hits its own limit */
#define MAX_NESTING 64

typedef struct {
    const uint8_t *p;
    size_t n;
} payload;

typedef struct {
    unsigned calls, cancel_at;
} events;

static yajl_handle parser;
static events parser_events;
static unsigned char *error_text;          /* from yajl_get_error, released with yajl_free_error */
static const unsigned char *last_chunk;    /* text of the last parse call, for verbose errors */
static unsigned last_chunk_len;

static yajl_gen gen;
static int gen_internal;                   /* generator writes through yajl_buf_append */
static unsigned gen_html_safe;
static char open_kinds[MAX_NESTING];       /* 'm' / 'a' for each container the harness opened */
static unsigned depth;
static unsigned gen_output;

static uint8_t byte(payload in, size_t i) { return i < in.n ? in.p[i] : 0; }
static long integer(payload in) {
    unsigned long v = 0;
    for (size_t i = 0; i < in.n && i < sizeof v; i++) v = v << 8 | in.p[i];
    return (long)v;
}

/* parser callbacks: count events, optionally cancel at the Nth one */
static int note(void *ctx) {
    events *e = ctx;
    return !e->cancel_at || ++e->calls != e->cancel_at;
}
static int cb_null(void *c) { return note(c); }
static int cb_bool(void *c, int v) { (void)v; return note(c); }
static int cb_int(void *c, long v) { (void)v; return note(c); }
static int cb_double(void *c, double v) { (void)v; return note(c); }
static int cb_number(void *c, const char *s, unsigned n) { (void)s; (void)n; return note(c); }
static int cb_string(void *c, const unsigned char *s, unsigned n) { (void)s; (void)n; return note(c); }
static int cb_map_open(void *c) { return note(c); }
static int cb_map_key(void *c, const unsigned char *s, unsigned n) { (void)s; (void)n; return note(c); }
static int cb_map_close(void *c) { return note(c); }
static int cb_array_open(void *c) { return note(c); }
static int cb_array_close(void *c) { return note(c); }

static const yajl_callbacks raw_callbacks = { cb_null, cb_bool, cb_int, cb_double, cb_number, cb_string,
                                              cb_map_open, cb_map_key, cb_map_close, cb_array_open, cb_array_close };
static const yajl_callbacks converted_callbacks = { cb_null, cb_bool, cb_int, cb_double, NULL, cb_string,
                                                    cb_map_open, cb_map_key, cb_map_close, cb_array_open, cb_array_close };
static const yajl_callbacks partial_callbacks = { cb_null, cb_bool, NULL, NULL, NULL, cb_string,
                                                  cb_map_open, cb_map_key, cb_map_close, cb_array_open, cb_array_close };

static void *my_malloc(void *ctx, unsigned n) { (void)ctx; return malloc(n); }
static void *my_realloc(void *ctx, void *p, unsigned n) { (void)ctx; return realloc(p, n); }
static void my_free(void *ctx, void *p) { (void)ctx; free(p); }
static yajl_alloc_funcs custom_alloc = { my_malloc, my_realloc, my_free, NULL };

static void print_cb(void *ctx, const char *s, unsigned n) {
    (void)ctx;
    (void)s;
    gen_output += n;
}

#define REPORT(api, stmt, ok_cond) \
    do { if (preqed_call(#api)) { stmt; preqed_result(#api, (ok_cond)); } } while (0)
#define REPORT_VOID(api, stmt) REPORT(api, stmt, 1)

/* yajl_gen_alloc's internal buffer is installed as (yajl_print_t)&yajl_buf_append, whose first parameter
 * type differs; every write through it is a call through an incompatible function pointer (UBSan
 * -fsanitize=function). Writes go only to generators that have a real print callback. */
static int gen_writable(void) { return gen && !gen_internal; }

/* parser */

/* byte 0: bit 0 allowComments, bit 1 checkUTF8, bits 2-4 callback set (none / numbers converted /
   partial / raw), bit 5 NULL config, bit 6 custom allocator; byte 1: cancel at the Nth callback (0 = never) */
/* ltl: parser_lifecycle */
static void call_yajl_alloc(payload in) {
    if (parser) return;
    uint8_t f = byte(in, 0);
    yajl_parser_config cfg = { f & 1, f >> 1 & 1 };
    const yajl_callbacks *cb = f & 4 ? NULL : f & 8 ? &converted_callbacks : f & 16 ? &partial_callbacks : &raw_callbacks;
    parser_events = (events){ 0, byte(in, 1) };
    if (!preqed_call("yajl_alloc")) return;
    parser = yajl_alloc(cb, f & 32 ? NULL : &cfg, f & 64 ? &custom_alloc : NULL, &parser_events);
    preqed_result("yajl_alloc", parser != NULL);
}
/* ltl: parser_lifecycle */
static void call_yajl_parse(payload in) {
    if (!parser) return;
    last_chunk = in.p;
    last_chunk_len = (unsigned)in.n;
    REPORT(yajl_parse, yajl_status rc = yajl_parse(parser, in.p, (unsigned)in.n),
           rc == yajl_status_ok || rc == yajl_status_insufficient_data);
}
/* ltl: parser_lifecycle */
static void call_yajl_parse_complete(payload in) {
    (void)in;
    if (!parser) return;
    /* yajl_parse_complete parses " " internally; error offsets then refer to that text */
    last_chunk = (const unsigned char *)" ";
    last_chunk_len = 1;
    REPORT(yajl_parse_complete, yajl_status rc = yajl_parse_complete(parser),
           rc == yajl_status_ok || rc == yajl_status_insufficient_data);
}
/* ltl: parser_lifecycle */
static void call_yajl_reset_parser(payload in) {
    (void)in;
    if (!parser) return;
    REPORT_VOID(yajl_reset_parser, yajl_reset_parser(parser));
}
/* ltl: parser_lifecycle */
static void call_yajl_get_bytes_consumed(payload in) {
    (void)in;
    if (!parser) return;
    REPORT_VOID(yajl_get_bytes_consumed, (void)yajl_get_bytes_consumed(parser));
}
/* ltl: parser_lifecycle, error_string_freed_through_parser */
static void call_yajl_get_error(payload in) {
    if (!parser || error_text) return;
    /* verbose rendering indexes jsonText at the consumed offset; it must be the last chunk parsed */
    int verbose = (byte(in, 0) & 1) && last_chunk && yajl_get_bytes_consumed(parser) <= last_chunk_len;
    if (!preqed_call("yajl_get_error")) return;
    error_text = yajl_get_error(parser, verbose, last_chunk, last_chunk_len);
    preqed_result("yajl_get_error", error_text != NULL);
}
/* ltl: parser_lifecycle, error_string_freed_through_parser */
static void call_yajl_free_error(payload in) {
    (void)in;
    if (!parser || !error_text) return;
    REPORT_VOID(yajl_free_error, yajl_free_error(parser, error_text));
    error_text = NULL;
}
/* ltl: parser_lifecycle, error_string_freed_through_parser */
static void call_yajl_free(payload in) {
    (void)in;
    if (!parser || error_text) return;
    REPORT_VOID(yajl_free, yajl_free(parser));
    parser = NULL;
    last_chunk = NULL;
}

static void call_yajl_status_to_string(payload in) {
    REPORT(yajl_status_to_string, const char *s = yajl_status_to_string((yajl_status)(byte(in, 0) % 7)), s != NULL);
}

static void call_yajl_version(payload in) {
    (void)in;
    REPORT_VOID(yajl_version, (void)yajl_version());
}

/* generator */

static yajl_gen_config gen_config(payload in) {
    /* yajl_gen_config.indentString: spaces, tab, and two odd strings (newline, non-whitespace) yajl accepts as-is */
    static const char *const indents[] = { "  ", "\t", "\n ", "bad!", "" };
    yajl_gen_config cfg = { byte(in, 0) & 1, indents[byte(in, 2) % 5], byte(in, 1) % 4 };  /* beautify, indent, htmlSafe 0..3 */
    return cfg;
}

static void opened_generator(uint8_t flags, const yajl_gen_config *cfg) {
    gen_html_safe = flags & 8 ? 0 : cfg->htmlSafe;
    depth = 0;
}
/* ltl: generator_lifecycle */
static void call_yajl_gen_alloc(payload in) {
    if (gen) return;
    yajl_gen_config cfg = gen_config(in);
    uint8_t f = byte(in, 0);
    if (!preqed_call("yajl_gen_alloc")) return;
    gen = yajl_gen_alloc(f & 8 ? NULL : &cfg, f & 16 ? &custom_alloc : NULL);
    preqed_result("yajl_gen_alloc", gen != NULL);
    gen_internal = 1;
    opened_generator(f, &cfg);
}

/* byte 0: bit 1 = no print callback (internal buffer), bit 3 NULL config, bit 4 custom allocator */
/* ltl: generator_lifecycle */
static void call_yajl_gen_alloc2(payload in) {
    if (gen) return;
    yajl_gen_config cfg = gen_config(in);
    uint8_t f = byte(in, 0);
    int with_callback = !(f & 2);
    if (!preqed_call("yajl_gen_alloc2")) return;
    gen = yajl_gen_alloc2(with_callback ? print_cb : NULL, f & 8 ? NULL : &cfg, f & 16 ? &custom_alloc : NULL, NULL);
    preqed_result("yajl_gen_alloc2", gen != NULL);
    gen_internal = !with_callback;
    opened_generator(f, &cfg);
}
/* ltl: generator_lifecycle */
static void call_yajl_gen_free(payload in) {
    (void)in;
    if (!gen) return;
    REPORT_VOID(yajl_gen_free, yajl_gen_free(gen));
    gen = NULL;
}

#define GEN(api, ...) \
    do { if (preqed_call(#api)) { yajl_gen_status rc = api(gen, ##__VA_ARGS__); preqed_result(#api, rc == yajl_gen_status_ok); } } while (0)
/* ltl: generator_lifecycle */
static void call_yajl_gen_integer(payload in) {
    if (!gen_writable()) return;
    GEN(yajl_gen_integer, integer(in));
}
/* ltl: generator_lifecycle */
static void call_yajl_gen_long(payload in) {
    if (!gen_writable()) return;
    GEN(yajl_gen_long, integer(in));
}
/* ltl: generator_lifecycle */
static void call_yajl_gen_double(payload in) {
    if (!gen_writable()) return;
    double v = 0;
    memcpy(&v, in.p, in.n < sizeof v ? in.n : sizeof v);
    GEN(yajl_gen_double, v);
}
/* ltl: generator_lifecycle */
static void call_yajl_gen_number(payload in) {
    if (!gen_writable()) return;
    GEN(yajl_gen_number, (const char *)in.p, (unsigned)in.n);
}
/* ltl: generator_lifecycle */
static void call_yajl_gen_string(payload in) {
    if (!gen_writable()) return;
    /* yajl_encode.c:92 checks len - end >= 2 for 0xe2 0x80 but then reads str[end + 2] */
    if (gen_html_safe == 2 && in.n >= 2 && in.p[in.n - 2] == 0xe2 && in.p[in.n - 1] == 0x80) return;
    GEN(yajl_gen_string, in.p, (unsigned)in.n);
}
/* ltl: generator_lifecycle */
static void call_yajl_gen_null(payload in) {
    (void)in;
    if (!gen_writable()) return;
    GEN(yajl_gen_null);
}
/* ltl: generator_lifecycle */
static void call_yajl_gen_bool(payload in) {
    if (!gen_writable()) return;
    GEN(yajl_gen_bool, byte(in, 0) & 1);
}
/* ltl: generator_lifecycle */
static void call_yajl_gen_map_open(payload in) {
    (void)in;
    if (!gen_writable() || depth >= MAX_NESTING) return;
    if (!preqed_call("yajl_gen_map_open")) return;
    yajl_gen_status rc = yajl_gen_map_open(gen);
    preqed_result("yajl_gen_map_open", rc == yajl_gen_status_ok);
    if (rc == yajl_gen_status_ok) open_kinds[depth++] = 'm';
}
/* ltl: generator_lifecycle */
static void call_yajl_gen_array_open(payload in) {
    (void)in;
    if (!gen_writable() || depth >= MAX_NESTING) return;
    if (!preqed_call("yajl_gen_array_open")) return;
    yajl_gen_status rc = yajl_gen_array_open(gen);
    preqed_result("yajl_gen_array_open", rc == yajl_gen_status_ok);
    if (rc == yajl_gen_status_ok) open_kinds[depth++] = 'a';
}

/* DECREMENT_DEPTH (yajl_gen.c:181) wraps the unsigned depth before checking it, so a close with nothing
 * open leaves depth == UINT_MAX and later writes index g->state out of bounds. Close only what was opened. */
/* ltl: generator_lifecycle */
static void call_yajl_gen_map_close(payload in) {
    (void)in;
    if (!gen_writable() || !depth || open_kinds[depth - 1] != 'm') return;
    if (!preqed_call("yajl_gen_map_close")) return;
    yajl_gen_status rc = yajl_gen_map_close(gen);
    preqed_result("yajl_gen_map_close", rc == yajl_gen_status_ok);
    if (rc == yajl_gen_status_ok) depth--;
}
/* ltl: generator_lifecycle */
static void call_yajl_gen_array_close(payload in) {
    (void)in;
    if (!gen_writable() || !depth || open_kinds[depth - 1] != 'a') return;
    if (!preqed_call("yajl_gen_array_close")) return;
    yajl_gen_status rc = yajl_gen_array_close(gen);
    preqed_result("yajl_gen_array_close", rc == yajl_gen_status_ok);
    if (rc == yajl_gen_status_ok) depth--;
}
/* ltl: generator_lifecycle */
static void call_yajl_gen_get_buf(payload in) {
    (void)in;
    if (!gen) return;
    const unsigned char *buf;
    unsigned len;
    REPORT(yajl_gen_get_buf, yajl_gen_status rc = yajl_gen_get_buf(gen, &buf, &len), rc == yajl_gen_status_ok);
}
/* ltl: generator_lifecycle */
static void call_yajl_gen_clear(payload in) {
    (void)in;
    if (!gen) return;
    REPORT_VOID(yajl_gen_clear, yajl_gen_clear(gen));
}

/* dispatch */

static void (*const api[])(payload) = {
    call_yajl_alloc, call_yajl_parse, call_yajl_parse_complete, call_yajl_reset_parser,
    call_yajl_get_bytes_consumed, call_yajl_get_error, call_yajl_free_error, call_yajl_free,
    call_yajl_status_to_string, call_yajl_version,
    call_yajl_gen_alloc, call_yajl_gen_alloc2, call_yajl_gen_free,
    call_yajl_gen_integer, call_yajl_gen_long, call_yajl_gen_double, call_yajl_gen_number, call_yajl_gen_string,
    call_yajl_gen_null, call_yajl_gen_bool, call_yajl_gen_map_open, call_yajl_gen_map_close,
    call_yajl_gen_array_open, call_yajl_gen_array_close, call_yajl_gen_get_buf, call_yajl_gen_clear,
};

#define API_COUNT (sizeof api / sizeof api[0])

static void cleanup(void) {
    if (error_text) yajl_free_error(parser, error_text);
    if (parser) yajl_free(parser);
    if (gen) yajl_gen_free(gen);
    parser = NULL;
    error_text = NULL;
    last_chunk = NULL;
    gen = NULL;
    depth = 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    preqed_reset();
    size_t off = 0;
    while (size - off >= 3) {
        uint8_t op = data[off];
        size_t len = (size_t)data[off + 1] | (size_t)data[off + 2] << 8;
        off += 3;
        if (len > size - off) break;
        payload in = { data + off, len };
        api[op % API_COUNT](in);
        off += len;
    }
    cleanup();
    return 0;
}
