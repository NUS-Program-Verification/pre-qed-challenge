#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <diginet/diginet.h>
#include <diginet/diginet_codec.h>
#include <diginet/transport/diginet_io.h>
#include <diginet/transport/diginet_session.h>
#include "preqed_ltl.h"

typedef struct {
    const uint8_t *p;
    size_t n;
} payload;

static const struct diginet_personality *personality;   /* NULL selects the Control|24 layout */
static struct diginet_cmd cmd;                           /* last encoded command */
static int cmd_valid;
static uint8_t body[DIGINET_MAX_BODY_LEN];               /* body built from commands or payload */
static size_t body_len;
static uint8_t frame_buf[DIGINET_MAX_FRAME_LEN];         /* built or parsed frame bytes */
static size_t frame_len;
static struct diginet_frame frame;                       /* points into frame_buf */
static int frame_valid;
static struct diginet_cursor cursor;
static int cursor_valid;
static struct diginet_decoder decoder;
static int decoder_valid;
static struct diginet_session_config cfg;                /* the config diginet_session_init copies */

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

#define REPORT(api, expr, ok_cond) \
    do { if (preqed_call(#api)) { int rc = (expr); preqed_result(#api, (ok_cond)); } } while (0)
#define REPORT_VOID(api, expr) do { if (preqed_call(#api)) { expr; preqed_result(#api, 1); } } while (0)

static void take_cmd(const char *api, int rc) {
    preqed_result(api, rc == DIGINET_OK);
    cmd_valid = rc == DIGINET_OK;
}

/* personalities */

static void call_diginet_personality_from_name(payload in) {
    char name[16];
    if (!preqed_call("diginet_personality_from_name")) return;
    personality = diginet_personality_from_name(cstr(name, sizeof name, in));
    preqed_result("diginet_personality_from_name", personality != NULL);
}

static void call_diginet_personality_of(payload in) {
    if (!preqed_call("diginet_personality_of")) return;
    personality = diginet_personality_of((enum diginet_desk)(byte(in, 0) % 4));  /* UNKNOWN, CONTROL24, PROCONTROL and one past the enum */
    preqed_result("diginet_personality_of", personality != NULL);
}

/* encoders: produce cmd */

static void call_diginet_fader_encode(payload in) {
    if (!preqed_call("diginet_fader_encode")) return;
    take_cmd("diginet_fader_encode", diginet_fader_encode(personality, byte(in, 0), byte(in, 1) | byte(in, 2) << 8, &cmd));
}

static void call_diginet_button_encode(payload in) {
    if (!preqed_call("diginet_button_encode")) return;
    take_cmd("diginet_button_encode", diginet_button_encode(byte(in, 0), byte(in, 1), byte(in, 2) & 1, &cmd));
}

static void call_diginet_touch_encode(payload in) {
    if (!preqed_call("diginet_touch_encode")) return;
    take_cmd("diginet_touch_encode", diginet_touch_encode(personality, byte(in, 0), byte(in, 1) & 1, &cmd));
}

static void call_diginet_vpot_encode(payload in) {
    if (!preqed_call("diginet_vpot_encode")) return;
    take_cmd("diginet_vpot_encode", diginet_vpot_encode(personality, byte(in, 0), (int8_t)byte(in, 1), &cmd));
}

static void call_diginet_jog_encode(payload in) {
    if (!preqed_call("diginet_jog_encode")) return;
    take_cmd("diginet_jog_encode", diginet_jog_encode((int8_t)byte(in, 0), &cmd));
}

static void call_diginet_ring_encode(payload in) {
    if (!preqed_call("diginet_ring_encode")) return;
    take_cmd("diginet_ring_encode", diginet_ring_encode(personality, byte(in, 0), byte(in, 1) | byte(in, 2) << 8, &cmd));
}

static void call_diginet_ring_dot(payload in) {
    REPORT_VOID(diginet_ring_dot, diginet_ring_dot(byte(in, 0)));
}

static void call_diginet_ring_fill(payload in) {
    REPORT_VOID(diginet_ring_fill, diginet_ring_fill(byte(in, 0)));
}

static void call_diginet_meter_encode(payload in) {
    if (!preqed_call("diginet_meter_encode")) return;
    take_cmd("diginet_meter_encode", diginet_meter_encode(personality, byte(in, 0), byte(in, 1) & 1, byte(in, 2), &cmd));
}

static void call_diginet_meter_mask(payload in) {
    REPORT_VOID(diginet_meter_mask, diginet_meter_mask(byte(in, 0)));
}

static void call_diginet_meter_segments(payload in) {
    REPORT_VOID(diginet_meter_segments, diginet_meter_segments(byte(in, 0) | byte(in, 1) << 8));
}

static void call_diginet_strip_leds_encode(payload in) {
    if (!preqed_call("diginet_strip_leds_encode")) return;
    take_cmd("diginet_strip_leds_encode", diginet_strip_leds_encode(personality, byte(in, 0), byte(in, 1), &cmd));
}

static void call_diginet_counter_leds_encode(payload in) {
    if (!preqed_call("diginet_counter_leds_encode")) return;
    take_cmd("diginet_counter_leds_encode", diginet_counter_leds_encode(personality, byte(in, 0), &cmd));
}

static void call_diginet_scribble_text(payload in) {
    char text[32];
    uint8_t chars[DIGINET_SCRIBBLE_MAX];
    REPORT_VOID(diginet_scribble_text, diginet_scribble_text(cstr(text, sizeof text, rest(in, 1)), chars, 1 + byte(in, 0) % DIGINET_SCRIBBLE_MAX));
}

static void call_diginet_scribble_encode(payload in) {
    char text[32];
    uint8_t chars[DIGINET_SCRIBBLE_MAX];
    unsigned n = personality ? personality->scribble_chars : 4;  /* NULL personality = Control|24, 4 chars per strip */
    diginet_scribble_text(cstr(text, sizeof text, rest(in, 1)), chars, n);
    if (!preqed_call("diginet_scribble_encode")) return;
    take_cmd("diginet_scribble_encode", diginet_scribble_encode(personality, byte(in, 0), chars, &cmd));
}

static void call_diginet_seg7(payload in) {
    REPORT_VOID(diginet_seg7, diginet_seg7((char)byte(in, 0)));
}

static void call_diginet_counter_text(payload in) {
    char text[32];
    uint8_t seg[DIGINET_COUNTER_DIGITS], dots;
    REPORT(diginet_counter_text, diginet_counter_text(cstr(text, sizeof text, in), seg, &dots), rc == DIGINET_OK);
}

static void call_diginet_counter_encode(payload in) {
    char text[32];
    uint8_t seg[DIGINET_COUNTER_DIGITS], dots;
    if (diginet_counter_text(cstr(text, sizeof text, in), seg, &dots) != DIGINET_OK) return;
    if (!preqed_call("diginet_counter_encode")) return;
    take_cmd("diginet_counter_encode", diginet_counter_encode(personality, seg, dots, &cmd));
}

static void call_diginet_sysex_encode(payload in) {
    payload data = rest(in, 2);
    if (!preqed_call("diginet_sysex_encode")) return;
    take_cmd("diginet_sysex_encode", diginet_sysex_encode(byte(in, 0), byte(in, 1), data.p, data.n, &cmd));
}

/* body: appended commands or raw payload */

static void call_append_cmd_to_body(payload in) {
    (void)in;
    if (!cmd_valid || body_len + cmd.len > sizeof body) return;
    memcpy(body + body_len, cmd.bytes, cmd.len);
    body_len += cmd.len;
}

static void call_set_body(payload in) {
    body_len = in.n < sizeof body ? in.n : sizeof body;
    memcpy(body, in.p, body_len);
}

static void call_diginet_body_check(payload in) {
    (void)in;
    REPORT(diginet_body_check, diginet_body_check(body, body_len), rc == DIGINET_OK);
}

static void call_diginet_sum16(payload in) {
    (void)in;
    REPORT_VOID(diginet_sum16, diginet_sum16(body, body_len));
}

/* frames */
/* ltl: frame_parsed_before_use, cursor_initialised_before_next, decoder_initialised_before_next */
static void call_diginet_frame_build(payload in) {
    struct diginet_header h;
    memset(&h, 0, sizeof h);
    h.send_counter = byte(in, 0) | byte(in, 1) << 8;
    h.ack_counter = byte(in, 2);
    h.retry = byte(in, 3);
    h.cmd = byte(in, 4);
    h.num_commands = byte(in, 5);
    uint8_t dst[DIGINET_MAC_LEN] = { DIGINET_OUI_0, DIGINET_OUI_1, DIGINET_OUI_2, byte(in, 6), byte(in, 7), byte(in, 8) };
    uint8_t src[DIGINET_MAC_LEN] = { byte(in, 9), byte(in, 10), byte(in, 11), byte(in, 12), byte(in, 13), byte(in, 14) };
    if (byte(in, 15) & 4) memcpy(dst, cfg.host_mac, DIGINET_MAC_LEN);       /* a frame for the session's host */
    if (byte(in, 15) & 8) memset(dst, 0xff, DIGINET_MAC_LEN);               /* Ethernet broadcast, where a desk announces */
    if (byte(in, 15) & 16) memcpy(src, (uint8_t[]){ DIGINET_OUI_0, DIGINET_OUI_1, DIGINET_OUI_2 }, 3);  /* from the Digidesign OUI, as a desk sends */
    size_t cap = byte(in, 15) & 1 ? byte(in, 16) : sizeof frame_buf;
    if (!preqed_call("diginet_frame_build")) return;
    int rc = diginet_frame_build(frame_buf, cap, dst, src, &h, body, body_len, byte(in, 15) & 2 ? DIGINET_SUM_ZERO : DIGINET_SUM_BODY);
    preqed_result("diginet_frame_build", rc > 0);
    if (rc > 0) frame_len = (size_t)rc;
    frame_valid = 0;
    cursor_valid = decoder_valid = 0;
}

static void call_set_frame_bytes(payload in) {
    frame_len = in.n < sizeof frame_buf ? in.n : sizeof frame_buf;
    memcpy(frame_buf, in.p, frame_len);
    frame_valid = 0;
    cursor_valid = decoder_valid = 0;
}
/* ltl: frame_parsed_before_use, cursor_initialised_before_next, decoder_initialised_before_next */
static void call_diginet_frame_parse(payload in) {
    (void)in;
    if (!preqed_call("diginet_frame_parse")) return;
    int rc = diginet_frame_parse(frame_buf, frame_len, &frame);
    preqed_result("diginet_frame_parse", rc == DIGINET_OK);
    frame_valid = rc == DIGINET_OK;
    cursor_valid = decoder_valid = 0;
}
/* ltl: frame_parsed_before_use */
static void call_diginet_frame_is_keepalive(payload in) {
    (void)in;
    if (!frame_valid) return;
    REPORT_VOID(diginet_frame_is_keepalive, diginet_frame_is_keepalive(&frame));
}

static void call_diginet_mac_is_digidesign(payload in) {
    uint8_t mac[DIGINET_MAC_LEN] = { byte(in, 0), byte(in, 1), byte(in, 2), byte(in, 3), byte(in, 4), byte(in, 5) };
    REPORT_VOID(diginet_mac_is_digidesign, diginet_mac_is_digidesign(byte(in, 6) & 1 && frame_valid ? frame.src : mac));
}
/* ltl: frame_parsed_before_use */
static void call_diginet_announce_parse(payload in) {
    (void)in;
    if (!frame_valid) return;
    struct diginet_announce a;
    REPORT(diginet_announce_parse, diginet_announce_parse(&frame, &a), rc == DIGINET_OK);
}

static void call_diginet_strerror(payload in) {
    if (!preqed_call("diginet_strerror")) return;
    preqed_result("diginet_strerror", diginet_strerror(-(int)(byte(in, 0) % 16)) != NULL);
}

/* message cursor over the parsed frame body */
/* ltl: frame_parsed_before_use, cursor_initialised_before_next */
static void call_diginet_cursor_init(payload in) {
    (void)in;
    if (!frame_valid) return;
    REPORT_VOID(diginet_cursor_init, diginet_cursor_init(&cursor, frame.body, frame.body_len));
    cursor_valid = 1;
}
/* ltl: cursor_initialised_before_next */
static void call_diginet_msg_next(payload in) {
    (void)in;
    if (!cursor_valid) return;
    struct diginet_msg m;
    REPORT(diginet_msg_next, diginet_msg_next(&cursor, &m), rc >= 0);
}

/* event decoder over the parsed frame body */
/* ltl: frame_parsed_before_use, decoder_initialised_before_next */
static void call_diginet_decoder_init(payload in) {
    if (!frame_valid) return;
    REPORT_VOID(diginet_decoder_init, diginet_decoder_init(&decoder, byte(in, 0) & 1 ? NULL : personality, frame.body, frame.body_len));
    decoder_valid = 1;
}
/* ltl: decoder_initialised_before_next */
static void call_diginet_decoder_next(payload in) {
    (void)in;
    if (!decoder_valid) return;
    struct diginet_event ev;
    REPORT(diginet_decoder_next, diginet_decoder_next(&decoder, &ev), rc >= 0);
}

/* transport: one session over an in-memory io or over one end of a socketpair */

#define RXQ_MAX 8                                        /* frames the in-memory io holds for recv */
static uint8_t rxq[RXQ_MAX][DIGINET_MAX_FRAME_LEN];
static size_t rxq_len[RXQ_MAX];
static unsigned rxq_head, rxq_count;
static int mem_send_errno;                               /* 0: send succeeds, else it returns -mem_send_errno */
static uint64_t clock_now;                               /* the harness clock in microseconds; only moves forward */

static int mem_send(void *ctx, const uint8_t *f, size_t len) {
    (void)ctx; (void)f; (void)len;
    return -mem_send_errno;
}

static int mem_recv(void *ctx, uint8_t *buf, size_t cap, int timeout_ms) {
    (void)ctx; (void)timeout_ms;
    if (!rxq_count) return 0;                            /* 0 = nothing came (diginet_io.h) */
    size_t n = rxq_len[rxq_head] < cap ? rxq_len[rxq_head] : cap;
    memcpy(buf, rxq[rxq_head], n);
    rxq_head = (rxq_head + 1) % RXQ_MAX;
    rxq_count--;
    return (int)n;
}

static uint64_t mem_now(void *ctx) { (void)ctx; return clock_now; }

static const struct diginet_io mem_io = { NULL, mem_send, mem_recv, mem_now };
static struct diginet_io fd_io;                          /* filled by diginet_io_fd */
static struct diginet_fd_io fd_store;                    /* must outlive fd_io (diginet_io.h) */
static int sock[2] = { -1, -1 };                         /* SOCK_SEQPACKET socketpair; one end backs fd_io */
static int fd_peer = -1;                                 /* the other end: the harness writes desk frames here */
static struct diginet_session session;
static int session_on_fd;                                /* the session's io is fd_io */

static void on_notice(void *ctx, const struct diginet_notice *n) {
    volatile uint8_t sink;
    (void)ctx;
    for (size_t i = 0; i < n->body_len; i++) sink = n->body[i];   /* body/body_len must be readable (diginet_session.h N_DATA) */
    (void)sink;
}

/* u16 time units of 1 us, 1 ms or 100 ms: reaches every timer of diginet_session_config */
static uint64_t advance(payload in, size_t i) {
    static const uint32_t unit[] = { 1, 1000, 100000 };
    clock_now += (uint64_t)(byte(in, i) | byte(in, i + 1) << 8) * unit[byte(in, i + 2) % 3];
    return clock_now;
}

static void call_set_session_config(payload in) {
    for (size_t i = 0; i < DIGINET_MAC_LEN; i++) {
        cfg.host_mac[i] = byte(in, i);
        cfg.desk_mac[i] = byte(in, DIGINET_MAC_LEN + i);
    }
    cfg.desk_mac_set = byte(in, 12) & 1;
    cfg.auto_wake = byte(in, 12) >> 1 & 1;
    cfg.sum_mode = byte(in, 12) & 4 ? DIGINET_SUM_ZERO : DIGINET_SUM_BODY;
    cfg.keepalive_ms = byte(in, 13) | byte(in, 14) << 8;
    cfg.ack_timeout_ms = byte(in, 15);
    cfg.max_retries = byte(in, 16) % 8;
    cfg.backoff_ms = byte(in, 17) | byte(in, 18) << 8;
    cfg.offline_ms = byte(in, 19) | byte(in, 20) << 8;
    cfg.wake_timeout_ms = byte(in, 21) | byte(in, 22) << 8;
    cfg.display_gap_us = byte(in, 23) | byte(in, 24) << 8;
    cfg.max_cmds = byte(in, 25) | (byte(in, 26) & 1) << 8;   /* 0..511: init accepts 1..255 */
    cfg.max_body = byte(in, 27) | (byte(in, 28) & 7) << 8;   /* 0..2047: init accepts 24..DIGINET_MAX_BODY_LEN */
}

static void call_push_rx_frame(payload in) {
    payload f = byte(in, 0) & 1 ? (payload){ frame_buf, frame_len } : rest(in, 1);
    if (byte(in, 0) & 2) {
        if (fd_peer >= 0) send(fd_peer, f.p, f.n, 0);   /* non-blocking: a full socket drops the frame */
        return;
    }
    if (rxq_count == RXQ_MAX) return;
    unsigned i = (rxq_head + rxq_count++) % RXQ_MAX;
    rxq_len[i] = f.n < DIGINET_MAX_FRAME_LEN ? f.n : DIGINET_MAX_FRAME_LEN;
    memcpy(rxq[i], f.p, rxq_len[i]);
}

static void call_set_send_result(payload in) {
    mem_send_errno = byte(in, 0);
}

static void call_diginet_clock_us(payload in) {
    (void)in;
    REPORT_VOID(diginet_clock_us, diginet_clock_us());
}

static void call_diginet_io_fd(payload in) {
    /* non-blocking, so a full buffer fails a send with -EAGAIN instead of hanging; skip when out of descriptors */
    if (sock[0] < 0 && socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sock) < 0) return;
    int end = byte(in, 0) & 1;
    REPORT_VOID(diginet_io_fd, diginet_io_fd(&fd_io, &fd_store, sock[end]));
    fd_peer = sock[!end];
}

static void call_diginet_packet_open(payload in) {
    char ifname[32];                                     /* longer than IFNAMSIZ, so the -EINVAL path is reachable */
    uint8_t mac[DIGINET_MAC_LEN];
    if (!preqed_call("diginet_packet_open")) return;
    int fd = diginet_packet_open(cstr(ifname, sizeof ifname, in), mac);
    preqed_result("diginet_packet_open", fd >= 0);
    if (fd >= 0) close(fd);                              /* only with CAP_NET_RAW; never used by the session */
}

static void call_diginet_state_name(payload in) {
    if (!preqed_call("diginet_state_name")) return;
    preqed_result("diginet_state_name", diginet_state_name((enum diginet_session_state)(byte(in, 0) % 5)) != NULL);  /* IDLE..CLOSED and one past the enum */
}

static void call_diginet_reason_name(payload in) {
    if (!preqed_call("diginet_reason_name")) return;
    preqed_result("diginet_reason_name", diginet_reason_name((enum diginet_reason)(byte(in, 0) % 10)) != NULL);  /* NONE..CLOSED and one past the enum */
}

static void call_diginet_session_config_default(payload in) {
    (void)in;
    REPORT_VOID(diginet_session_config_default, diginet_session_config_default(&cfg));
}

/* ltl: session_init_before_use, session_no_wake_after_close */
static void call_diginet_session_init(payload in) {
    int on_fd = byte(in, 0) & 1 && fd_io.send;           /* fd_io is an io once diginet_io_fd filled it */
    if (!preqed_call("diginet_session_init")) return;
    int rc = diginet_session_init(&session, &cfg, on_fd ? &fd_io : &mem_io, on_notice, NULL);
    preqed_result("diginet_session_init", rc == DIGINET_OK);
    if (rc == DIGINET_OK) session_on_fd = on_fd;
}

/* ltl: session_init_before_use */
static void call_diginet_session_rx(payload in) {
    payload f = byte(in, 0) & 1 ? (payload){ frame_buf, frame_len } : rest(in, 4);
    uint64_t now = advance(in, 1);
    REPORT(diginet_session_rx, diginet_session_rx(&session, f.p, f.n, now), rc == DIGINET_OK);
}

/* ltl: session_init_before_use */
static void call_diginet_session_tick(payload in) {
    uint64_t now = advance(in, 0);
    REPORT(diginet_session_tick, diginet_session_tick(&session, now), rc == DIGINET_OK);
}

/* ltl: session_init_before_use */
static void call_diginet_session_deadline(payload in) {
    uint64_t now = advance(in, 0);
    if (!preqed_call("diginet_session_deadline")) return;
    preqed_result("diginet_session_deadline", diginet_session_deadline(&session, now) >= now);
}

/* ltl: session_init_before_use */
static void call_diginet_session_poll(payload in) {
    /* fd_io's recv really sleeps: 0 keeps one input from blocking for up to a second; -1 = no cap */
    int wait = session_on_fd ? 0 : byte(in, 3) & 1 ? -1 : byte(in, 4);
    advance(in, 0);
    REPORT(diginet_session_poll, diginet_session_poll(&session, wait), rc == 0);
}

/* ltl: session_init_before_use */
static void call_diginet_session_submit(payload in) {
    struct diginet_cmd c;
    memset(&c, 0, sizeof c);
    c.len = 1 + byte(in, 1) % DIGINET_CMD_MAX_LEN;
    c.display = byte(in, 2) & 1;
    c.key = DIGINET_KEY(byte(in, 3) % 10, byte(in, 4) | byte(in, 5) << 8);   /* kind 0 (none), FADER..KEEPALIVE */
    payload b = rest(in, 6);
    memcpy(c.bytes, b.p, b.n < c.len ? b.n : c.len);
    REPORT(diginet_session_submit, diginet_session_submit(&session, byte(in, 0) & 1 && cmd_valid ? &cmd : &c), rc == DIGINET_OK);
}

/* ltl: session_init_before_use, session_no_wake_after_close */
static void call_diginet_session_wake(payload in) {
    uint64_t now = advance(in, 0);
    REPORT(diginet_session_wake, diginet_session_wake(&session, now), rc == DIGINET_OK);
}

/* ltl: session_init_before_use, session_no_wake_after_close */
static void call_diginet_session_close(payload in) {
    uint64_t now = advance(in, 0);
    REPORT(diginet_session_close, diginet_session_close(&session, now), rc == 0);
}

/* dispatch */

static void (*const api[])(payload) = {
    call_diginet_personality_from_name, call_diginet_personality_of,
    call_diginet_fader_encode, call_diginet_button_encode, call_diginet_touch_encode, call_diginet_vpot_encode,
    call_diginet_jog_encode, call_diginet_ring_encode, call_diginet_ring_dot, call_diginet_ring_fill,
    call_diginet_meter_encode, call_diginet_meter_mask, call_diginet_meter_segments,
    call_diginet_strip_leds_encode, call_diginet_counter_leds_encode,
    call_diginet_scribble_text, call_diginet_scribble_encode, call_diginet_seg7, call_diginet_counter_text,
    call_diginet_counter_encode, call_diginet_sysex_encode,
    call_append_cmd_to_body, call_set_body, call_diginet_body_check, call_diginet_sum16,
    call_diginet_frame_build, call_set_frame_bytes, call_diginet_frame_parse, call_diginet_frame_is_keepalive,
    call_diginet_mac_is_digidesign, call_diginet_announce_parse, call_diginet_strerror,
    call_diginet_cursor_init, call_diginet_msg_next, call_diginet_decoder_init, call_diginet_decoder_next,
    call_set_session_config, call_push_rx_frame, call_set_send_result,
    call_diginet_clock_us, call_diginet_io_fd, call_diginet_packet_open, call_diginet_state_name,
    call_diginet_reason_name, call_diginet_session_config_default, call_diginet_session_init,
    call_diginet_session_rx, call_diginet_session_tick, call_diginet_session_deadline,
    call_diginet_session_poll, call_diginet_session_submit, call_diginet_session_wake,
    call_diginet_session_close,
};

#define API_COUNT (sizeof api / sizeof api[0])

static void cleanup(void) {
    personality = NULL;
    cmd_valid = frame_valid = cursor_valid = decoder_valid = 0;
    body_len = frame_len = 0;
    memset(&session, 0, sizeof session);
    memset(&cfg, 0, sizeof cfg);
    memset(&fd_io, 0, sizeof fd_io);
    session_on_fd = 0;
    for (int i = 0; i < 2; i++) {
        if (sock[i] >= 0) close(sock[i]);
        sock[i] = -1;
    }
    fd_peer = -1;
    rxq_head = rxq_count = 0;
    mem_send_errno = 0;
    clock_now = 0;
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
