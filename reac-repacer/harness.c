#include <stdint.h>
#include <string.h>
#include "repace_conf.h"
#include "repace_wire.h"
#include "preqed_ltl.h"

/* larger than any REAC frame (1492 B) */
#define FRAME_CAP 2048

typedef struct {
    const uint8_t *p;
    size_t n;
} payload;

/* one frame buffer: loaded from the payload, then rewritten in place by untag / slot_write / restamp / mute */
static uint8_t frame[FRAME_CAP];
static size_t frame_len;
static char text[RP_LOCK_MAX + 1];

static uint8_t byte(payload in, size_t i) { return i < in.n ? in.p[i] : 0; }
static payload rest(payload in, size_t skip) {
    payload r = { in.p + (skip < in.n ? skip : in.n), in.n > skip ? in.n - skip : 0 };
    return r;
}
static int32_t s24(payload in, size_t i) {
    int32_t v = byte(in, i) | byte(in, i + 1) << 8 | byte(in, i + 2) << 16;
    return v >= 0x800000 ? v - 0x1000000 : v;
}

#define REPORT(api, stmt, ok_cond) \
    do { if (preqed_call(#api)) { stmt; preqed_result(#api, (ok_cond)); } } while (0)
#define REPORT_VOID(api, stmt) REPORT(api, stmt, 1)

static void call_set_frame(payload in) {
    frame_len = in.n < FRAME_CAP ? in.n : FRAME_CAP;
    memcpy(frame, in.p, frame_len);
}

/* wire readers */

static void call_rp_fwd_class(payload in) {
    REPORT(rp_fwd_class, int c = rp_fwd_class(frame, frame_len, byte(in, 0) & 1), c != RP_FWD_DROP);
}

static void call_rp_ret_accept(payload in) {
    (void)in;
    REPORT(rp_ret_accept, int a = rp_ret_accept(frame, frame_len), a == 1);
}

static void call_rp_ds_accept(payload in) {
    (void)in;
    REPORT(rp_ds_accept, int a = rp_ds_accept(frame, frame_len), a == 1);
}

static void call_rp_meter_counter(payload in) {
    (void)in;
    uint16_t ctr;
    REPORT(rp_meter_counter, int a = rp_meter_counter(frame, frame_len, &ctr), a == 1);
}

/* "The frame holds at least 16 bytes" (repace_wire.h) */
static void call_rp_counter(payload in) {
    (void)in;
    if (frame_len < 16) return;
    REPORT_VOID(rp_counter, (void)rp_counter(frame));
}

static void call_rp_frame_channels(payload in) {
    long len = byte(in, 0) & 1 ? (long)frame_len : (long)(byte(in, 1) | byte(in, 2) << 8);
    REPORT(rp_frame_channels, int nch = rp_frame_channels(len), nch > 0);
}

static void call_rp_copy_untag(payload in) {
    (void)in;
    if (!preqed_call("rp_copy_untag")) return;
    size_t len = rp_copy_untag(frame, frame_len);
    preqed_result("rp_copy_untag", len > 0);
    if (len) frame_len = len;
}

static void call_rp_slot_width(payload in) {
    REPORT(rp_slot_width, int w = rp_slot_width(frame, frame_len, (int8_t)byte(in, 0)), w > 0);
}

static void call_rp_slot_read(payload in) {
    int32_t v[12];  /* 12 time-samples per slot */
    REPORT(rp_slot_read, int ok = rp_slot_read(frame, frame_len, (int8_t)byte(in, 0), v), ok == 1);
}

static void call_rp_slot_write(payload in) {
    int32_t v[12];  /* a slot carries 12 time-samples (repace_wire.h: "12 time-samples of nch s24 channels") */
    for (int i = 0; i < 12; i++) v[i] = s24(in, 1 + 3 * (size_t)i);
    REPORT(rp_slot_write, int ok = rp_slot_write(frame, frame_len, (int8_t)byte(in, 0), v), ok == 1);
}

/* writes bytes 14-15 */
static void call_rp_restamp(payload in) {
    if (frame_len < 16) return;
    REPORT_VOID(rp_restamp, rp_restamp(frame, byte(in, 0) | byte(in, 1) << 8 | (unsigned)byte(in, 2) << 16));  /* 24-bit counter */
}

static void call_rp_mute(payload in) {
    (void)in;
    REPORT_VOID(rp_mute, rp_mute(frame, frame_len));
}

/* config readers */

static void call_rp_hot_clamp(payload in) {
    struct rp_hot hot;
    int32_t raw[6];  /* five rp_hot fields and margin_max, as 4-byte integers (any value: rp_hot_clamp clamps) */
    for (size_t i = 0; i < 6; i++)
        raw[i] = (int32_t)((uint32_t)byte(in, 4 * i) | (uint32_t)byte(in, 4 * i + 1) << 8 |
                           (uint32_t)byte(in, 4 * i + 2) << 16 | (uint32_t)byte(in, 4 * i + 3) << 24);
    hot = (struct rp_hot){ raw[0], raw[1], raw[2], raw[3], raw[4] };
    REPORT_VOID(rp_hot_clamp, rp_hot_clamp(&hot, raw[5] < 0 ? 0 : raw[5]));
}

static void call_rp_uci_int(payload in) {
    int cur = (int8_t)byte(in, 0);
    payload reply = rest(in, 1);
    /* repace_conf.h: returns the parsed value or `cur`; there is no failure value, so every call succeeds */
    REPORT_VOID(rp_uci_int, (void)rp_uci_int((const char *)reply.p, reply.n, cur));
}

static void call_rp_lock_lookup(payload in) {
    /* the three rates rp_lock_lookup accepts (repace_conf.h) and one it must reject */
    static const long rates[] = { 44100, 48000, 96000, 22050 };
    char port[16];
    size_t plen = byte(in, 1) % sizeof port;
    payload body = rest(in, 2);
    if (plen > body.n) plen = body.n;
    memcpy(port, body.p, plen);
    port[plen] = 0;
    payload lock = rest(body, plen);
    size_t n = lock.n < RP_LOCK_MAX ? lock.n : RP_LOCK_MAX;
    memcpy(text, lock.p, n);
    REPORT(rp_lock_lookup, long period = rp_lock_lookup(text, n, port, rates[byte(in, 0) % 4]), period > 0);
}

/* dispatch */

static void (*const api[])(payload) = {
    call_set_frame,
    call_rp_fwd_class, call_rp_ret_accept, call_rp_ds_accept, call_rp_meter_counter, call_rp_counter,
    call_rp_frame_channels, call_rp_copy_untag, call_rp_slot_width, call_rp_slot_read, call_rp_slot_write,
    call_rp_restamp, call_rp_mute,
    call_rp_hot_clamp, call_rp_uci_int, call_rp_lock_lookup,
};

#define API_COUNT (sizeof api / sizeof api[0])

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    preqed_reset();
    frame_len = 0;
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
    return 0;
}
