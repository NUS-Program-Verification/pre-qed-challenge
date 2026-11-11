#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <plugin-hostd/pin.h>
#include <plugin-hostd/protocol.h>
#include "preqed_ltl.h"

#define FILE_PATH "plugin-hostd-harness.bin"
/* CLAP params / LV2 ports per layout call */
#define MAX_ITEMS 16

typedef struct {
    const uint8_t *p;
    size_t n;
} payload;

static phd_sha256_t sha;
static int sha_live;        /* init done, final not yet */
static char hex[PHD_SHA256_HEX_LEN + 1];
static int hex_valid;

static char text[PHD_LINE_MAX];
static char *words[PHD_LINE_WORDS_MAX];
/* parameter names / port symbols (up to 8 payload bytes each) and up to 4 LV2 properties per port */
static char names[MAX_ITEMS][32];
static const char *props[MAX_ITEMS][4];
static phd_layout_clap_param_t clap_params[MAX_ITEMS];
static phd_layout_lv2_port_t lv2_ports[MAX_ITEMS];
/* phd_layout_* output collected by buffer_sink; 64 KiB fits 16 items */
static char sink_buf[1 << 16];
static size_t sink_len;

static uint8_t byte(payload in, size_t i) { return i < in.n ? in.p[i] : 0; }
static payload rest(payload in, size_t skip) {
    payload r = { in.p + (skip < in.n ? skip : in.n), in.n > skip ? in.n - skip : 0 };
    return r;
}
static const char *cstr(char *dst, size_t cap, payload in) {
    size_t n = in.n < cap - 1 ? in.n : cap - 1;
    memcpy(dst, in.p, n);
    dst[n] = 0;
    return dst;
}
static double number(payload in, size_t i) {
    double d = 0;
    if (i + sizeof d <= in.n) memcpy(&d, in.p + i, sizeof d);
    return d;
}

/* payload as whitespace-separated words, the way the daemon splits a line */
static int split_words(payload in) {
    cstr(text, sizeof text, in);
    memset(words, 0, sizeof words);
    int count = 0;
    char *save = NULL;
    for (char *w = strtok_r(text, " ", &save); w && count < PHD_LINE_WORDS_MAX; w = strtok_r(NULL, " ", &save))
        words[count++] = w;
    return count;
}

static void buffer_sink(void *ctx, const char *data, size_t size) {
    (void)ctx;
    if (size > sizeof sink_buf - sink_len) size = sizeof sink_buf - sink_len;
    memcpy(sink_buf + sink_len, data, size);
    sink_len += size;
}

/* byte 0: count 0..16; then 12 bytes per param: id (2), flags (1, bit 7 = NULL name), min (8, double), range (1) */
static size_t build_clap_params(payload in) {
    size_t count = byte(in, 0) % (MAX_ITEMS + 1);
    payload body = rest(in, 1);
    for (size_t i = 0; i < count; i++) {
        payload item = rest(body, i * 12);
        clap_params[i].id = byte(item, 0) | byte(item, 1) << 8;
        clap_params[i].flags = byte(item, 2);
        clap_params[i].min = number(item, 3);
        clap_params[i].max = clap_params[i].min + byte(item, 11);
        clap_params[i].def = clap_params[i].min;
        clap_params[i].name = byte(item, 2) & 0x80 ? NULL : cstr(names[i], sizeof names[i], (payload){ item.p, item.n < 8 ? item.n : 8 });
    }
    return count;
}

/* byte 0: count 0..16; then 12 bytes per port: index, output/has bits (bit 7 = NULL symbol), min (8), range, nproperties 0..3 */
static size_t build_lv2_ports(payload in) {
    size_t count = byte(in, 0) % (MAX_ITEMS + 1);
    payload body = rest(in, 1);
    for (size_t i = 0; i < count; i++) {
        payload item = rest(body, i * 12);
        lv2_ports[i].index = byte(item, 0);
        lv2_ports[i].output = byte(item, 1) & 1;
        lv2_ports[i].has = byte(item, 1) >> 1 & 7;
        lv2_ports[i].min = number(item, 2);
        lv2_ports[i].max = lv2_ports[i].min + byte(item, 10);
        lv2_ports[i].def = lv2_ports[i].min;
        lv2_ports[i].symbol = byte(item, 1) & 0x80 ? NULL : cstr(names[i], sizeof names[i], (payload){ item.p, item.n < 8 ? item.n : 8 });
        lv2_ports[i].nproperties = byte(item, 11) % 4;
        for (size_t k = 0; k < lv2_ports[i].nproperties; k++) props[i][k] = names[(i + k + 1) % MAX_ITEMS];
        lv2_ports[i].properties = props[i];
    }
    return count;
}

#define REPORT(api, expr, ok_cond) \
    do { if (preqed_call(#api)) { int rc = (expr); preqed_result(#api, (ok_cond)); } } while (0)
#define REPORT_VOID(api, expr) do { if (preqed_call(#api)) { expr; preqed_result(#api, 1); } } while (0)

/* sha256 */
/* ltl: sha256_context_lifecycle */
static void call_phd_sha256_init(payload in) {
    (void)in;
    REPORT_VOID(phd_sha256_init, phd_sha256_init(&sha));
    sha_live = 1;
}
/* ltl: sha256_context_lifecycle */
static void call_phd_sha256_update(payload in) {
    if (!sha_live) return;
    REPORT_VOID(phd_sha256_update, phd_sha256_update(&sha, in.p, in.n));
}
/* ltl: sha256_context_lifecycle */
static void call_phd_sha256_final(payload in) {
    (void)in;
    if (!sha_live) return;
    REPORT_VOID(phd_sha256_final, phd_sha256_final(&sha, hex));
    sha_live = 0;
    hex_valid = 1;
}

static void call_phd_sha256_hex(payload in) {
    REPORT_VOID(phd_sha256_hex, phd_sha256_hex(in.p, in.n, hex));
    hex_valid = 1;
}

static void call_phd_pin_fd_digest(payload in) {
    int fd = open(FILE_PATH, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return;
    ssize_t written = write(fd, in.p, in.n);
    (void)written;
    if (!preqed_call("phd_pin_fd_digest")) {
        close(fd);
        return;
    }
    int rc = phd_pin_fd_digest(fd, hex);
    preqed_result("phd_pin_fd_digest", rc == 0);
    hex_valid = rc == 0;
    close(fd);
}

/* pins */

static void call_phd_pin_hex_valid(payload in) {
    const char *s = byte(in, 0) & 1 && hex_valid ? hex : cstr(text, sizeof text, rest(in, 1));
    REPORT_VOID(phd_pin_hex_valid, phd_pin_hex_valid(s));
}

static void call_phd_pin_layout_parse(payload in) {
    char scheme[32], out[PHD_SHA256_HEX_LEN + 1];
    char token[128];
    if (byte(in, 0) & 1 && hex_valid) {
        cstr(scheme, sizeof scheme, rest(in, 1));
        snprintf(token, sizeof token, "%s:%s", scheme, hex);
    } else {
        cstr(token, sizeof token, rest(in, 1));
    }
    REPORT(phd_pin_layout_parse, phd_pin_layout_parse(token, scheme, 1 + byte(in, 0) % sizeof scheme, out), rc == 0);
}

/* layouts */

static void call_phd_layout_put(payload in) {
    sink_len = 0;
    REPORT_VOID(phd_layout_put, phd_layout_put(buffer_sink, NULL, cstr(text, sizeof text, in)));
}

static void call_phd_layout_number(payload in) {
    sink_len = 0;
    REPORT_VOID(phd_layout_number, phd_layout_number(buffer_sink, NULL, number(in, 1), byte(in, 0) & 1));
}

static void call_phd_layout_text(payload in) {
    sink_len = 0;
    REPORT_VOID(phd_layout_text, phd_layout_text(buffer_sink, NULL, cstr(text, sizeof text, in)));
}

static void call_phd_layout_uint(payload in) {
    sink_len = 0;
    uint32_t v = byte(in, 1) | byte(in, 2) << 8 | byte(in, 3) << 16 | (uint32_t)byte(in, 4) << 24;
    REPORT_VOID(phd_layout_uint, phd_layout_uint(buffer_sink, NULL, v, byte(in, 0) & 1));
}

static void call_phd_layout_clap_order(payload in) {
    size_t count = build_clap_params(in);
    if (count < 2) return;
    const phd_layout_clap_param_t *a = &clap_params[0], *b = &clap_params[1];
    REPORT_VOID(phd_layout_clap_order, phd_layout_clap_order(&a, &b));
}

static void call_phd_layout_lv2_order(payload in) {
    size_t count = build_lv2_ports(in);
    if (count < 2) return;
    const phd_layout_lv2_port_t *a = &lv2_ports[0], *b = &lv2_ports[1];
    REPORT_VOID(phd_layout_lv2_order, phd_layout_lv2_order(&a, &b));
}

static void call_phd_layout_bytewise(payload in) {
    size_t count = build_lv2_ports(in);
    if (count < 1 || lv2_ports[0].nproperties < 2) return;
    REPORT_VOID(phd_layout_bytewise, phd_layout_bytewise(&lv2_ports[0].properties[0], &lv2_ports[0].properties[1]));
}

static void call_phd_layout_clap_write(payload in) {
    size_t count = build_clap_params(in);
    sink_len = 0;
    REPORT(phd_layout_clap_write, phd_layout_clap_write(clap_params, count, buffer_sink, NULL), rc == 0);
}

static void call_phd_layout_lv2_write(payload in) {
    size_t count = build_lv2_ports(in);
    sink_len = 0;
    REPORT(phd_layout_lv2_write, phd_layout_lv2_write(lv2_ports, count, buffer_sink, NULL), rc == 0);
}
/* ltl: sha256_context_lifecycle */
static void call_phd_layout_hash_sink(payload in) {
    if (!sha_live) return;
    REPORT_VOID(phd_layout_hash_sink, phd_layout_hash_sink(&sha, (const char *)in.p, in.n));
}

static void call_phd_layout_clap_digest(payload in) {
    size_t count = build_clap_params(in);
    if (!preqed_call("phd_layout_clap_digest")) return;
    int rc = phd_layout_clap_digest(clap_params, count, hex);
    preqed_result("phd_layout_clap_digest", rc == 0);
    hex_valid = rc == 0;
}

static void call_phd_layout_lv2_digest(payload in) {
    size_t count = build_lv2_ports(in);
    if (!preqed_call("phd_layout_lv2_digest")) return;
    int rc = phd_layout_lv2_digest(lv2_ports, count, hex);
    preqed_result("phd_layout_lv2_digest", rc == 0);
    hex_valid = rc == 0;
}

/* protocol word validators */

static void call_phd_pool_name_valid(payload in) {
    REPORT_VOID(phd_pool_name_valid, phd_pool_name_valid(cstr(text, sizeof text, in)));
}

static void call_phd_string_valid(payload in) {
    REPORT_VOID(phd_string_valid, phd_string_valid(cstr(text, sizeof text, in)));
}

static void call_phd_color_valid(payload in) {
    REPORT_VOID(phd_color_valid, phd_color_valid(cstr(text, sizeof text, in)));
}

static void call_phd_track_kind(payload in) {
    REPORT_VOID(phd_track_kind, phd_track_kind(byte(in, 0) & 1 ? NULL : cstr(text, sizeof text, rest(in, 1))));
}

static void call_phd_track_info_valid(payload in) {
    int count = split_words(in);
    REPORT_VOID(phd_track_info_valid, phd_track_info_valid(words, count));
}

static void call_phd_number_in(payload in) {
    int lo = (int8_t)byte(in, 0), hi = lo + byte(in, 1);
    REPORT_VOID(phd_number_in, phd_number_in(cstr(text, sizeof text, rest(in, 2)), lo, hi));
}

static void call_phd_note_valid(payload in) {
    int count = split_words(in);
    if (count < 1) return;
    REPORT_VOID(phd_note_valid, phd_note_valid(words, count));
}

static void call_phd_is_note_verb(payload in) {
    REPORT_VOID(phd_is_note_verb, phd_is_note_verb(cstr(text, sizeof text, in)));
}

/* dispatch */

static void (*const api[])(payload) = {
    call_phd_sha256_init, call_phd_sha256_update, call_phd_sha256_final,
    call_phd_sha256_hex, call_phd_pin_fd_digest,
    call_phd_pin_hex_valid, call_phd_pin_layout_parse,
    call_phd_layout_put, call_phd_layout_number, call_phd_layout_text, call_phd_layout_uint,
    call_phd_layout_clap_order, call_phd_layout_lv2_order, call_phd_layout_bytewise,
    call_phd_layout_clap_write, call_phd_layout_lv2_write, call_phd_layout_hash_sink,
    call_phd_layout_clap_digest, call_phd_layout_lv2_digest,
    call_phd_pool_name_valid, call_phd_string_valid, call_phd_color_valid, call_phd_track_kind,
    call_phd_track_info_valid, call_phd_number_in, call_phd_note_valid, call_phd_is_note_verb,
};

#define API_COUNT (sizeof api / sizeof api[0])

static void cleanup(void) {
    sha_live = hex_valid = 0;
    sink_len = 0;
    unlink(FILE_PATH);
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
