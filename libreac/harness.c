#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <reac/reac.h>
#include <reac/reac_arbitration.h>
#include <reac/reac_box_facts.h>
#include <reac/reac_boxreg.h>
#include <reac/reac_braid.h>
#include <reac/reac_clock.h>
#include <reac/reac_code.h>
#include <reac/reac_cfg.h>
#include <reac/reac_ctrl.h>
#include <reac/reac_ctrlblk.h>
#include <reac/reac_decode.h>
#include <reac/reac_disco.h>
#include <reac/reac_encode.h>
#include <reac/reac_envflag.h>
#include <reac/reac_fsm.h>
#include <reac/reac_grant.h>
#include <reac/reac_headamp_tx.h>
#include <reac/reac_hunt.h>
#include <reac/reac_identity.h>
#include <reac/reac_knock.h>
#include <reac/reac_link.h>
#include <reac/reac_link_state.h>
#include <reac/reac_macaddr.h>
#include <reac/reac_master.h>
#include <reac/reac_master_fsm.h>
#include <reac/reac_ports.h>
#include <reac/reac_role.h>
#include <reac/reac_sample.h>
#include <reac/reac_scene_body.h>
#include <reac/reac_slots.h>
#include <reac/reac_tapwait.h>
#include <reac/reac_tunables.h>
#include <reac/reac_upstream.h>
#include <reac/transport/reac_carrier.h>
#include <reac/transport/reac_conf.h>
#include <reac/transport/reac_etf_qdisc.h>
#include <reac/transport/reac_ifname.h>
#include <reac/transport/reac_ifscan.h>
#include <reac/transport/reac_linkmon.h>
#include <reac/transport/reac_mac.h>
#include <reac/transport/reac_pacer.h>
#include <reac/transport/reac_pace_watch.h>
#include <reac/transport/reac_ring.h>
#include <reac/transport/reac_role_swap.h>
#include <reac/transport/reac_rt.h>
#include <reac/transport/reac_rx.h>
#include <reac/transport/reac_seglock.h>
#include <reac/transport/reac_segment_ident.h>
#include <reac/transport/reac_slave.h>
#include <reac/transport/reac_tap.h>
#include <reac/transport/reac_topo.h>
#include <reac/transport/reac_tx.h>
#include <reac/transport/reac_vlan.h>
#include <reac/pcap_source.h>
#include <reac/reac_capture.h>
#include <reac/reac_packet_socket.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
#include "preqed_ltl.h"

typedef struct {
    const uint8_t *p;
    size_t n;
} payload;

/* one live wire-byte buffer, one audio region, one decoded region; 4096 holds the largest REAC frame (1492 B) */
static uint8_t bytes[4096];
static size_t bytes_len;
static uint8_t audio[REAC_AUDIO_BYTES];
static uint8_t pcm[REAC_AUDIO_BYTES];
static uint8_t scene[REAC_SCENE_BYTES];
static int scene_valid;
/* 34 = one control block (reac_ctrlblk.h uint8_t blk[34]) */
static uint8_t sweep[REAC_GRANT_SWEEP_MAX][34];
static float plane[REAC_MAX_CHANNELS][REAC_SAMPLES_PER_PKT];
static float *planes[REAC_MAX_CHANNELS];
static char pin_buf[REAC_BOXREG_NAME_MAX];

/* one live instance per stateful family */
static struct reac_fsm fsm;
static int fsm_valid;
static struct reac_master master;
static int master_valid;
static struct reac_identity ident;
static struct reac_identity_frag ident_frag;
static int ident_valid;
static struct reac_disco_table table;
static int table_valid;
static struct reac_disco_peer_lock lock;
static int lock_valid;
static struct reac_disco_gate gate;
static int gate_valid;
static struct reac_hunt hunt;
static int hunt_valid;
static struct reac_knock knock;
static int knock_valid;
static struct reac_dll dll;
static int dll_valid;
static struct reac_clock_disc disc;
static int disc_valid;
static struct reac_headamp_tx hamptx;
static int hamptx_valid;
static struct reac_boxreg boxreg;
static int boxreg_valid;
static struct reac_grant_alloc alloc;
static int alloc_valid;
static struct reac_ctrl_parsed parsed;
static int parsed_valid;
static uint64_t now_ns;

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
    do { if (preqed_call(#api)) { int rc_ = (expr); preqed_result(#api, (ok_cond)); } } while (0)
#define REPORT_VOID(api, expr) do { if (preqed_call(#api)) { expr; preqed_result(#api, 1); } } while (0)

/* Argument conventions used throughout: enum arguments are `byte % <enumerator count>` (a few use
   `+ 8` to also pass values past the end, which the API must reject); MACs are 6 payload bytes */
static void mac_of(payload in, size_t off, uint8_t out[6]) {
    for (size_t i = 0; i < 6; i++)
        out[i] = byte(in, off + i);
}

/* box widths are even, 2..REAC_BOX_MAX_CHANNELS (reac.h) */
static int box_width_of(payload in, size_t i) {
    return 2 * (1 + byte(in, i) % (REAC_BOX_MAX_CHANNELS / 2));
}

/* monotonic clock for the time-based APIs: advances 1 ns plus 0..15 s per call */
static uint64_t tick(payload in) {
    now_ns += 1ULL + (uint64_t)(byte(in, 0) & 0x0f) * 1000000000ULL;
    return now_ns;
}

static void mode_of(payload in, struct reac_mode *m) {
    m->sample_rate = (int)byte(in, 0) * 1000;  /* 0..255 kHz; reac_mode_for accepts only the real rates */
    m->n_channels = box_width_of(in, 1);
    m->samples_per_pkt = (int)(byte(in, 2) % (REAC_SAMPLES_PER_PKT + 1));
}

/* fill every channel plane with s24le samples from the payload (3 bytes each); n_src 0..REAC_MAX_CHANNELS */
static float *const *planes_from(payload in, int *n_src) {
    size_t k = 0;
    for (int ch = 0; ch < REAC_MAX_CHANNELS; ch++)
        for (int s = 0; s < REAC_SAMPLES_PER_PKT; s++, k += 3) {
            uint8_t b[3] = { byte(in, k), byte(in, k + 1), byte(in, k + 2) };
            plane[ch][s] = reac_s24le_to_f32(b);
        }
    for (int ch = 0; ch < REAC_MAX_CHANNELS; ch++)
        planes[ch] = plane[ch];
    *n_src = (int)(byte(in, 0) % (REAC_MAX_CHANNELS + 1));
    return planes;
}

static const struct reac_box_model *catalogue_at(payload in) {
    size_t n = 0;
    const struct reac_box_model *t = reac_box_catalogue(&n);
    return t && n ? &t[byte(in, 31) % n] : NULL;
}

static void sighting_of(payload in, struct reac_disco_sighting *s) {
    memset(s, 0, sizeof *s);
    mac_of(in, 0, s->mac);
    s->role = (enum reac_disco_role)(byte(in, 6) % 3);
    s->has_decl = byte(in, 7) & 1;
    s->decl_in = (uint8_t)box_width_of(in, 8);
    s->decl_out = (uint8_t)box_width_of(in, 9);
    s->family = (uint8_t)(byte(in, 10) % 4);
    s->announced_slots = byte(in, 11);
    s->channels = (unsigned)box_width_of(in, 12);
}

static void entry_of(payload in, struct reac_disco_entry *e) {
    struct reac_disco_sighting s;
    sighting_of(in, &s);
    memset(e, 0, sizeof *e);
    memcpy(e->mac, s.mac, 6);
    e->role = s.role;
    e->has_decl = s.has_decl;
    e->decl_in = s.decl_in;
    e->decl_out = s.decl_out;
    e->family = s.family;
    e->announced_slots = s.announced_slots;
    e->channels = s.channels;
    e->owned = (int)byte(in, 13) & 1;
    e->first_seen_ns = now_ns;
    e->last_seen_ns = now_ns > (uint64_t)byte(in, 14) * 100000000ULL
                    ? now_ns - (uint64_t)byte(in, 14) * 100000000ULL : 0;
}

static void block_of(payload in, uint8_t out[32]) {
    for (size_t i = 0; i < 32; i++)
        out[i] = byte(in, i);
}

static void noop_prop(void *ctx, const char *key, const char *value) {
    (void)ctx; (void)key; (void)value;
}

/* harness record: wire bytes to be parsed, from the payload */

static void call_set_frame(payload in) {
    bytes_len = in.n < sizeof bytes ? in.n : sizeof bytes;
    memcpy(bytes, in.p, bytes_len);
}

/* reac.h */

static void call_reac_box_width_ok(payload in) {
    REPORT_VOID(reac_box_width_ok, (void)reac_box_width_ok((int)byte(in, 0)));
}

static void call_reac_frame_is_master_downstream(payload in) {
    (void)in;
    REPORT_VOID(reac_frame_is_master_downstream, (void)reac_frame_is_master_downstream(bytes_len));
}

static void call_reac_frame_channels(payload in) {
    (void)in;
    REPORT_VOID(reac_frame_channels, (void)reac_frame_channels(bytes_len));
}

static void call_reac_mode_for(payload in) {
    REPORT(reac_mode_for, reac_mode_for((int)byte(in, 0) * 1000 + (int)byte(in, 1)) != NULL, rc_);
}

static void call_reac_pace_code(payload in) {
    REPORT_VOID(reac_pace_code, (void)reac_pace_code((int)byte(in, 0) | (int)byte(in, 1) << 8));
}

static void call_reac_rate_snap(payload in) {
    double pps = (double)((unsigned)byte(in, 0) | (unsigned)byte(in, 1) << 8);
    REPORT_VOID(reac_rate_snap, (void)reac_rate_snap(pps));
}

static void call_reac_frame_is_reac(payload in) {
    (void)in;
    REPORT_VOID(reac_frame_is_reac, (void)reac_frame_is_reac(bytes, bytes_len));
}

static void call_reac_frame_clean_len(payload in) {
    REPORT_VOID(reac_frame_clean_len, (void)reac_frame_clean_len(in.n));
}

static void call_reac_frame_counter(payload in) {
    (void)in;
    if (bytes_len < 16) return;   /* caller must ensure len >= 16 (reac.h) */
    REPORT_VOID(reac_frame_counter, (void)reac_frame_counter(bytes));
}

static void call_reac_counter_gap(payload in) {
    REPORT_VOID(reac_counter_gap,
                (void)reac_counter_gap((uint16_t)(byte(in, 0) | byte(in, 1) << 8),
                                       (uint16_t)(byte(in, 2) | byte(in, 3) << 8)));
}

static void call_reac_version(payload in) {
    (void)in;
    REPORT(reac_version, reac_version() != NULL, rc_);
}

/* reac_decode.h */

static void call_reac_frame_inspect(payload in) {
    struct reac_mode m;
    mode_of(in, &m);
    if (!preqed_call("reac_frame_inspect")) return;
    struct reac_frame f = reac_frame_inspect(bytes, bytes_len, &m);
    preqed_result("reac_frame_inspect", f.valid);
}

static void call_reac_decode(payload in) {
    struct reac_mode m;
    mode_of(in, &m);
    REPORT(reac_decode, reac_decode(bytes, bytes_len, &m, pcm), rc_ >= 0);
}

static void call_reac_decode_plain_le(payload in) {
    struct reac_mode m;
    mode_of(in, &m);
    REPORT(reac_decode_plain_le, reac_decode_plain_le(bytes, bytes_len, &m, pcm), rc_ >= 0);
}

/* reac_upstream.h */

static void call_reac_upstream_channels(payload in) {
    (void)in;
    REPORT(reac_upstream_channels, reac_upstream_channels(bytes_len), rc_ >= 0);
}

static void call_reac_upstream_decode(payload in) {
    (void)in;
    REPORT(reac_upstream_decode, reac_upstream_decode(bytes, bytes_len, pcm), rc_ >= 0);
}

/* reac_encode.h */

static void call_reac_braid_encode(payload in) {
    int n_src = 0;
    float *const *pl = planes_from(in, &n_src);
    REPORT_VOID(reac_braid_encode,
                reac_braid_encode(audio, box_width_of(in, 1), pl, n_src,
                                  (int)(byte(in, 2) % (REAC_SAMPLES_PER_PKT + 1))));
}

static void call_reac_downstream_build(payload in) {
    int n_src = 0;
    float *const *pl = planes_from(in, &n_src);
    uint8_t src[6];
    mac_of(in, 3, src);
    if (!preqed_call("reac_downstream_build")) return;
    int rc = reac_downstream_build(bytes, pl, (int)(byte(in, 1) % (REAC_MAX_CHANNELS + 1)),
                                   (int)(byte(in, 2) % (REAC_SAMPLES_PER_PKT + 1)),
                                   (uint16_t)(byte(in, 0) | byte(in, 9) << 8), src);
    preqed_result("reac_downstream_build", rc == REAC_FRAME_BYTES);
    if (rc > 0) bytes_len = (size_t)rc;
}

/* reac_sample.h */

static void call_reac_s24le_to_f32(payload in) {
    uint8_t b[3] = { byte(in, 0), byte(in, 1), byte(in, 2) };
    REPORT_VOID(reac_s24le_to_f32, (void)reac_s24le_to_f32(b));
}

static void call_reac_f32_to_s24le(payload in) {
    uint8_t b[3];
    REPORT_VOID(reac_f32_to_s24le,
                reac_f32_to_s24le((float)((int)byte(in, 0) - 128) / 64.0f, b));
}

/* reac_braid.h */

static void call_reac_braid_pos(payload in) {
    int n_ch = box_width_of(in, 2);
    size_t pos[3];
    REPORT_VOID(reac_braid_pos,
                reac_braid_pos((int)(byte(in, 0) % REAC_SAMPLES_PER_PKT),
                               (int)(byte(in, 1) % (unsigned)n_ch), n_ch, pos));
}

/* reac_envflag.h */

static void call_reac_envflag_parse(payload in) {
    char name[32];
    REPORT(reac_envflag_parse, reac_envflag_parse(cstr(name, sizeof name, in)), rc_ >= 0);
}

static void call_reac_envflag(payload in) {
    char name[32];
    REPORT_VOID(reac_envflag, (void)reac_envflag(cstr(name, sizeof name, in), (int)byte(in, 31) & 1));
}

/* reac_role.h */

static void call_reac_role_parse(payload in) {
    char text[16];
    enum reac_role out;
    REPORT(reac_role_parse, reac_role_parse(cstr(text, sizeof text, in), &out), rc_ == 0);
}

static void call_reac_role_name(payload in) {
    REPORT(reac_role_name, reac_role_name((enum reac_role)(byte(in, 0) & 1)) != NULL, rc_);
}

static void call_reac_role_intent_explicit_only(payload in) {
    REPORT_VOID(reac_role_intent_explicit_only,
                (void)reac_role_intent_explicit_only((enum reac_role_intent)(byte(in, 0) % 5)));
}

static void call_reac_role_intent_transmits(payload in) {
    REPORT_VOID(reac_role_intent_transmits,
                (void)reac_role_intent_transmits((enum reac_role_intent)(byte(in, 0) % 5)));
}

static void call_reac_role_intent_parse(payload in) {
    char text[16];
    enum reac_role_intent out;
    REPORT(reac_role_intent_parse, reac_role_intent_parse(cstr(text, sizeof text, in), &out), rc_ == 0);
}

static void call_reac_role_intent_name(payload in) {
    REPORT(reac_role_intent_name, reac_role_intent_name((enum reac_role_intent)(byte(in, 0) % 5)) != NULL, rc_);
}

static void call_reac_role_from_intent(payload in) {
    REPORT_VOID(reac_role_from_intent,
                (void)reac_role_from_intent((enum reac_role_intent)(byte(in, 0) % 5)));
}

static void call_reac_role_validate(payload in) {
    REPORT(reac_role_validate,
           reac_role_validate((enum reac_role)(byte(in, 0) & 1), (int)byte(in, 1) & 1), rc_ == 0);
}

/* reac_code.h */

static void call_reac_code_token(payload in) {
    REPORT(reac_code_token, reac_code_token((enum reac_code)byte(in, 0)) != NULL, rc_);
}

static void call_reac_code_emit(payload in) {
    char text[32], *buf = NULL;
    size_t len = 0;
    cstr(text, sizeof text, in);
    if (!preqed_call("reac_code_emit")) return;
    FILE *out = open_memstream(&buf, &len);
    if (!out) {
        preqed_result("reac_code_emit", 0);
        return;
    }
    reac_code_emit(out, text, (enum reac_code)byte(in, 31), "%s|%u\n", text, (unsigned)in.n);
    int ok = fclose(out) == 0 && buf != NULL && len > 0;
    free(buf);
    preqed_result("reac_code_emit", ok);
}

/* reac_clock.h */

static void call_reac_clock_hierarchy(payload in) {
    int n = 0;
    if (!preqed_call("reac_clock_hierarchy")) return;
    const enum reac_clock_source *h = reac_clock_hierarchy((enum reac_role)(byte(in, 0) & 1), &n);
    preqed_result("reac_clock_hierarchy", h != NULL && n >= 0);
}

static void call_reac_clock_select(payload in) {
    REPORT_VOID(reac_clock_select,
                (void)reac_clock_select((enum reac_role)(byte(in, 0) & 1),
                                        (uint32_t)byte(in, 1) | (uint32_t)byte(in, 2) << 8));
}

static void call_reac_clock_source_name(payload in) {
    REPORT(reac_clock_source_name, reac_clock_source_name((enum reac_clock_source)(byte(in, 0) % REAC_CLOCK_SRC_COUNT)) != NULL, rc_);
}

static void call_reac_clock_quality_name(payload in) {
    REPORT(reac_clock_quality_name, reac_clock_quality_name((enum reac_clock_quality)(byte(in, 0) % REAC_CLOCK_Q_COUNT)) != NULL, rc_);
}

static void call_reac_clock_quality_can_own(payload in) {
    REPORT_VOID(reac_clock_quality_can_own,
                (void)reac_clock_quality_can_own((enum reac_clock_quality)(byte(in, 0) % REAC_CLOCK_Q_COUNT)));
}

static void call_reac_clock_name_quality(payload in) {
    char name[32];
    const char *n = byte(in, 0) & 1 ? NULL : cstr(name, sizeof name, rest(in, 1));
    REPORT_VOID(reac_clock_name_quality, (void)reac_clock_name_quality(n));
}

static void call_reac_clock_name_is_designated(payload in) {
    char name[24], desig[24];
    REPORT_VOID(reac_clock_name_is_designated,
                (void)reac_clock_name_is_designated(cstr(name, sizeof name, in),
                                                    cstr(desig, sizeof desig, rest(in, 16))));
}

static void call_reac_clock_grade_name(payload in) {
    char name[24], desig[24];
    REPORT_VOID(reac_clock_grade_name,
                (void)reac_clock_grade_name(cstr(name, sizeof name, in),
                                            cstr(desig, sizeof desig, rest(in, 16))));
}

static void call_reac_clock_select_graded(payload in) {
    enum reac_clock_quality q[REAC_CLOCK_SRC_COUNT];
    for (int i = 0; i < REAC_CLOCK_SRC_COUNT; i++)
        q[i] = (enum reac_clock_quality)(byte(in, 4 + (size_t)i) % REAC_CLOCK_Q_COUNT);
    REPORT_VOID(reac_clock_select_graded,
                (void)reac_clock_select_graded((enum reac_role)(byte(in, 0) & 1),
                                               (uint32_t)byte(in, 1) | (uint32_t)byte(in, 2) << 8,
                                               q, (enum reac_clock_quality)(byte(in, 3) % REAC_CLOCK_Q_COUNT)));
}

static void call_reac_clock_stability_name(payload in) {
    REPORT(reac_clock_stability_name, reac_clock_stability_name((enum reac_clock_stability)(byte(in, 0) % 3)) != NULL, rc_);
}
/* ltl: dll_init_before_update */
static void call_reac_dll_init(payload in) {
    if (!preqed_call("reac_dll_init")) return;
    reac_dll_init(&dll, (long)(1 + (byte(in, 0) | byte(in, 1) << 8)));
    preqed_result("reac_dll_init", 1);
    dll_valid = 1;
}
/* ltl: dll_init_before_update */
static void call_reac_dll_update(payload in) {
    if (!dll_valid) return;
    double ppm = (double)((int)byte(in, 0) - 128) * ((double)byte(in, 1) / 8.0 + 0.5);
    REPORT(reac_dll_update, reac_dll_update(&dll, ppm), rc_ == 1);
}
/* ltl: dll_init_before_update */
static void call_reac_dll_period_ns(payload in) {
    (void)in;
    if (!dll_valid) return;
    REPORT_VOID(reac_dll_period_ns, (void)reac_dll_period_ns(&dll));
}
/* ltl: dll_init_before_update */
static void call_reac_dll_applied_ppm(payload in) {
    (void)in;
    if (!dll_valid) return;
    REPORT_VOID(reac_dll_applied_ppm, (void)reac_dll_applied_ppm(&dll));
}
/* ltl: dll_init_before_update */
static void call_reac_dll_resid_sigma(payload in) {
    (void)in;
    if (!dll_valid) return;
    REPORT_VOID(reac_dll_resid_sigma, (void)reac_dll_resid_sigma(&dll));
}
/* ltl: dll_init_before_update */
static void call_reac_dll_stability(payload in) {
    (void)in;
    if (!dll_valid) return;
    REPORT_VOID(reac_dll_stability, (void)reac_dll_stability(&dll));
}
/* ltl: dll_init_before_update */
static void call_reac_dll_stability_reset(payload in) {
    (void)in;
    if (!dll_valid) return;
    REPORT_VOID(reac_dll_stability_reset, reac_dll_stability_reset(&dll));
}

static void call_reac_clock_quality_apply(payload in) {
    REPORT_VOID(reac_clock_quality_apply,
                (void)reac_clock_quality_apply((enum reac_clock_source)(byte(in, 0) % REAC_CLOCK_SRC_COUNT),
                                               (enum reac_clock_quality)(byte(in, 1) % REAC_CLOCK_Q_COUNT),
                                               (enum reac_clock_stability)(byte(in, 2) % 3)));
}

static void call_reac_clock_state_name(payload in) {
    REPORT(reac_clock_state_name, reac_clock_state_name((enum reac_clock_state)(byte(in, 0) % 4)) != NULL, rc_);
}
/* ltl: clock_disc_init_before_update */
static void call_reac_clock_disc_init(payload in) {
    if (!preqed_call("reac_clock_disc_init")) return;
    reac_clock_disc_init(&disc, (enum reac_role)(byte(in, 0) & 1),
                         (long)(1 + (byte(in, 1) | byte(in, 2) << 8)));
    preqed_result("reac_clock_disc_init", 1);
    disc_valid = 1;
}
/* ltl: clock_disc_init_before_update */
static void call_reac_clock_disc_set_quality(payload in) {
    if (!disc_valid) return;
    REPORT_VOID(reac_clock_disc_set_quality,
                reac_clock_disc_set_quality(&disc, (enum reac_clock_source)(byte(in, 0) % REAC_CLOCK_SRC_COUNT),
                                            (enum reac_clock_quality)(byte(in, 1) % REAC_CLOCK_Q_COUNT)));
}
/* ltl: clock_disc_init_before_update */
static void call_reac_clock_disc_quality(payload in) {
    (void)in;
    if (!disc_valid) return;
    REPORT_VOID(reac_clock_disc_quality, (void)reac_clock_disc_quality(&disc));
}
/* ltl: clock_disc_init_before_update */
static void call_reac_clock_disc_update(payload in) {
    if (!disc_valid) return;
    double ppm = (double)((int)byte(in, 1) - 128);
    REPORT_VOID(reac_clock_disc_update,
                reac_clock_disc_update(&disc, (uint32_t)byte(in, 0) | (uint32_t)byte(in, 2) << 8,
                                       ppm, (int)byte(in, 3) & 1));
}
/* ltl: clock_disc_init_before_update */
static void call_reac_clock_disc_period_ns(payload in) {
    (void)in;
    if (!disc_valid) return;
    REPORT_VOID(reac_clock_disc_period_ns, (void)reac_clock_disc_period_ns(&disc));
}
/* ltl: clock_disc_init_before_update */
static void call_reac_clock_disc_describe(payload in) {
    char text[256];
    if (!disc_valid) return;
    size_t cap = 1 + byte(in, 0) % sizeof text;
    REPORT(reac_clock_disc_describe, reac_clock_disc_describe(&disc, text, cap) != NULL, rc_);
}

static void call_reac_clock_describe(payload in) {
    char text[256];
    size_t cap = 1 + byte(in, 3) % sizeof text;
    REPORT(reac_clock_describe, reac_clock_describe((enum reac_role)(byte(in, 0) & 1),
                               (enum reac_clock_source)(byte(in, 1) % REAC_CLOCK_SRC_COUNT),
                               (enum reac_clock_state)(byte(in, 2) % 4), text, cap) != NULL, rc_);
}

static void call_reac_clock_describe_full(payload in) {
    char text[256], label[24];
    size_t cap = 1 + byte(in, 3) % sizeof text;
    const char *l = byte(in, 4) & 1 ? NULL : cstr(label, sizeof label, rest(in, 5));
    REPORT(reac_clock_describe_full, reac_clock_describe_full((enum reac_role)(byte(in, 0) & 1),
                                    (enum reac_clock_source)(byte(in, 1) % REAC_CLOCK_SRC_COUNT),
                                    (enum reac_clock_state)(byte(in, 2) % 4),
                                    (enum reac_clock_quality)(byte(in, 6) % REAC_CLOCK_Q_COUNT),
                                    l, text, cap) != NULL, rc_);
}

static void call_reac_clock_ppm_from_rate_diff(payload in) {
    REPORT_VOID(reac_clock_ppm_from_rate_diff,
                (void)reac_clock_ppm_from_rate_diff(1.0 + (double)((int)byte(in, 0) - 128) / 64.0));
}

static void call_reac_clock_name_is_hardware(payload in) {
    char name[32];
    const char *n = byte(in, 0) & 1 ? NULL : cstr(name, sizeof name, rest(in, 1));
    REPORT_VOID(reac_clock_name_is_hardware, (void)reac_clock_name_is_hardware(n));
}

/* reac_identity.h */

static void call_reac_identity_init(payload in) {
    (void)in;
    if (!preqed_call("reac_identity_init")) return;
    reac_identity_init(&ident);
    preqed_result("reac_identity_init", 1);
    /* the fragment reassembly buffer is zero-initialised with the accumulator */
    memset(&ident_frag, 0, sizeof ident_frag);
    ident_valid = 1;
}

static void call_reac_identity_ingest(payload in) {
    payload body = rest(in, 2);
    uint16_t addr;
    switch (byte(in, 0) % 4) {
    case 0: addr = REAC_IDENTITY_ADDR_FIRMWARE; break;
    case 1: addr = REAC_IDENTITY_ADDR_REAC_VERSION; break;
    case 2: addr = REAC_IDENTITY_ADDR_MODEL_NAME; break;
    default: addr = (uint16_t)(byte(in, 1) | byte(in, 2) << 8); break;
    }
    if (!ident_valid) return;
    REPORT(reac_identity_ingest, reac_identity_ingest(&ident, addr, body.p, body.n), rc_ >= 0);
}

static void call_reac_identity_fw_str(payload in) {
    char text[32];
    size_t cap = 1 + byte(in, 2) % sizeof text;
    REPORT(reac_identity_fw_str,
           reac_identity_fw_str((uint16_t)(byte(in, 0) | byte(in, 1) << 8), text, cap), rc_ >= 0);
}

static void call_reac_identity_reac_ver_str(payload in) {
    char text[32];
    size_t cap = 1 + byte(in, 6) % sizeof text;
    REPORT(reac_identity_reac_ver_str,
           reac_identity_reac_ver_str((uint16_t)(byte(in, 0) | byte(in, 1) << 8),
                                      (uint16_t)(byte(in, 2) | byte(in, 3) << 8),
                                      (uint16_t)(byte(in, 4) | byte(in, 5) << 8), text, cap), rc_ >= 0);
}

/* reac_ports.h */

static void call_reac_ports_parse(payload in) {
    uint8_t block[32];
    struct reac_box_ports ports;
    block_of(in, block);
    REPORT(reac_ports_parse, reac_ports_parse(block, &ports), rc_ == 0);
}

static void call_reac_ports_unknown(payload in) {
    uint8_t block[32], first = 0;
    block_of(in, block);
    REPORT(reac_ports_unknown, reac_ports_unknown(block, &first), rc_ >= 0);
}

/* reac_macaddr.h */

static void call_reac_mac_compose(payload in) {
    uint8_t hw[6], out[6];
    mac_of(in, 1, hw);
    REPORT(reac_mac_compose, reac_mac_compose((int)byte(in, 0), hw, out), rc_ == 0);
}

static void call_reac_mac_fallback(payload in) {
    uint8_t out[6];
    (void)in;
    REPORT(reac_mac_fallback, reac_mac_fallback(out), rc_ < 0);
}

static void call_reac_mac_roland_standin(payload in) {
    uint8_t hw[6], out[6];
    mac_of(in, 0, hw);
    REPORT(reac_mac_roland_standin, reac_mac_roland_standin(hw, out), rc_ == 0);
}

static void call_reac_mac48_pack(payload in) {
    uint8_t mac[6];
    mac_of(in, 0, mac);
    REPORT_VOID(reac_mac48_pack, (void)reac_mac48_pack(mac));
}

static void call_reac_mac48_unpack(payload in) {
    uint8_t out[6];
    uint64_t packed = 0;
    for (size_t i = 0; i < 8; i++)
        packed = packed << 8 | byte(in, i);
    REPORT_VOID(reac_mac48_unpack, reac_mac48_unpack(packed, out));
}

/* reac_fsm.h */
/* ltl: fsm_init_before_step */
static void call_reac_fsm_init(payload in) {
    (void)in;
    if (!preqed_call("reac_fsm_init")) return;
    reac_fsm_init(&fsm);
    preqed_result("reac_fsm_init", 1);
    fsm_valid = 1;
}
/* ltl: fsm_init_before_step */
static void call_reac_fsm_step(payload in) {
    enum reac_fsm_event ev = (enum reac_fsm_event)(byte(in, 0) % 4);
    if (!fsm_valid) return;
    if (ev == FSM_EV_RX && !parsed_valid) return;   /* rx must be a parsed frame (reac_fsm.h) */
    REPORT_VOID(reac_fsm_step,
                (void)reac_fsm_step(&fsm, ev, ev == FSM_EV_RX ? &parsed : NULL));
}

/* reac_master_fsm.h */

static void call_reac_master_fsm_classify(payload in) {
    REPORT_VOID(reac_master_fsm_classify,
                (void)reac_master_fsm_classify((enum reac_master_rx_event)(byte(in, 0) % 6),
                                               (int)byte(in, 1) & 1, (int)byte(in, 2) & 1,
                                               (int)byte(in, 3) & 1));
}

static void call_reac_master_fsm_step(payload in) {
    REPORT_VOID(reac_master_fsm_step,
                (void)reac_master_fsm_step((enum reac_master_state)(byte(in, 0) % 4),
                                           (enum reac_master_ev)(byte(in, 1) % REAC_M_EV_COUNT)));
}

/* reac_master.h */

static void call_reac_mixer_profile_by_name(payload in) {
    char name[16];
    REPORT(reac_mixer_profile_by_name, reac_mixer_profile_by_name(cstr(name, sizeof name, in)) != NULL, rc_);
}

static void call_reac_mixer_profile_at(payload in) {
    REPORT(reac_mixer_profile_at, reac_mixer_profile_at((int)byte(in, 0)) != NULL, rc_);
}

static void call_reac_mixer_resolve_rate(payload in) {
    const struct reac_mixer_profile *mixer =
        byte(in, 3) & 1 ? NULL : reac_mixer_profile_at((int)(byte(in, 2) % 4));
    int clamped = 0;
    if (!preqed_call("reac_mixer_resolve_rate")) return;
    int rc = reac_mixer_resolve_rate(mixer, (int)byte(in, 0) * 1000 + (int)byte(in, 1) * 100, &clamped);
    preqed_result("reac_mixer_resolve_rate",
                   rc == REAC_CFG_RATE_44100 || rc == REAC_CFG_RATE_48000 || rc == REAC_CFG_RATE_96000);
}

static void call_reac_master_tunables_set(payload in) {
    /* reac_tunables.h: ms valid in (0, 600000), s in (0, 3600], others ignored; each table has the
       boundaries on both sides plus the measured 1600 ms default */
    static const long dwell_ms[] = { 0, 1, 1600, 600000, 600001, -1 };
    static const long dwell_s[] = { 0, 1, 2, 3600, 3601 };
    struct reac_master_tunables t;
    if (byte(in, 0) & 0x80) {
        REPORT_VOID(reac_master_tunables_set, reac_master_tunables_set(NULL));
        return;
    }
    t.grant_on_declare = (int)byte(in, 1) & 1;
    t.grant_dwell_ms = dwell_ms[byte(in, 2) % (sizeof dwell_ms / sizeof dwell_ms[0])];
    t.grant_dwell_s = dwell_s[byte(in, 3) % (sizeof dwell_s / sizeof dwell_s[0])];
    t.no_enroll = (int)byte(in, 4) & 1;
    t.est_scene = (int)byte(in, 5) & 1;
    REPORT_VOID(reac_master_tunables_set, reac_master_tunables_set(&t));
}
/* ltl: master_init_before_use */
static void call_reac_master_identity_answered(payload in) {
    if (!master_valid) return;
    REPORT_VOID(reac_master_identity_answered,
                reac_master_identity_answered(&master, (int)byte(in, 0) & 1));
}
/* ltl: master_init_before_use */
static void call_reac_master_init(payload in) {
    static const int fps[] = { 3675, 4000, 8000 };   /* reac_master_init's rates */
    uint8_t src[6];
    struct reac_console_cfg cfg;
    int use_cfg = byte(in, 6) & 1;
    mac_of(in, 0, src);
    cfg.out_channels = byte(in, 7);
    cfg.console_field = byte(in, 8);
    if (!preqed_call("reac_master_init")) return;
    reac_master_init(&master, src, use_cfg ? &cfg : NULL, fps[byte(in, 9) % 3]);
    preqed_result("reac_master_init", 1);
    master_valid = 1;
}
/* ltl: master_init_before_use */
static void call_reac_master_has_box(payload in) {
    (void)in;
    if (!master_valid) return;
    REPORT_VOID(reac_master_has_box, (void)reac_master_has_box(&master));
}
/* ltl: master_init_before_use */
static void call_reac_master_set_box(payload in) {
    if (!master_valid) return;
    REPORT_VOID(reac_master_set_box,
                reac_master_set_box(&master, box_width_of(in, 0),
                                    byte(in, 1) & 1 ? box_width_of(in, 2) : 0,
                                    (int)(byte(in, 3) % (REAC_HEADAMP_MAX_CH + 1))));
}
/* ltl: master_init_before_use */
static void call_reac_master_forget_box(payload in) {
    (void)in;
    if (!master_valid) return;
    REPORT_VOID(reac_master_forget_box, reac_master_forget_box(&master));
}
/* ltl: master_init_before_use */
static void call_reac_master_regrant(payload in) {
    (void)in;
    if (!master_valid) return;
    REPORT_VOID(reac_master_regrant, reac_master_regrant(&master));
}
/* ltl: master_init_before_use */
static void call_reac_master_set_headamp_src(payload in) {
    (void)in;
    if (!master_valid) return;
    REPORT_VOID(reac_master_set_headamp_src,
                reac_master_set_headamp_src(&master, hamptx_valid ? &hamptx : NULL));
}
/* ltl: master_init_before_use */
static void call_reac_master_rx(payload in) {
    uint8_t src[6];
    const uint8_t *blk = bytes_len >= REAC_CTRL_BLOCK_END ? bytes + REAC_CTRL_BLOCK_OFF : NULL;
    mac_of(in, 0, src);
    if (!master_valid) return;
    REPORT_VOID(reac_master_rx,
                (void)reac_master_rx(&master, (enum reac_master_rx_event)(byte(in, 6) % 6), src, blk));
}
/* ltl: master_init_before_use */
static void call_reac_master_next(payload in) {
    uint16_t counter = 0;
    int tmpl_idx = 0;
    (void)in;
    if (!master_valid) return;
    REPORT_VOID(reac_master_next, (void)reac_master_next(&master, &counter, &tmpl_idx));
}
/* ltl: master_init_before_use */
static void call_reac_master_stamp(payload in) {
    /* the frame must already be a built downstream frame (reac_master.h) */
    if (!master_valid || bytes_len < REAC_FRAME_BYTES) return;
    REPORT(reac_master_stamp,
           reac_master_stamp(&master, bytes, (enum reac_master_emit)(byte(in, 0) % 9),
                             (int)byte(in, 1)), rc_ == 0);
}

static void call_reac_master_state_name(payload in) {
    REPORT(reac_master_state_name, reac_master_state_name((enum reac_master_state)(byte(in, 0) % 4)) != NULL, rc_);
}

static void call_reac_master_rx_event_name(payload in) {
    REPORT(reac_master_rx_event_name, reac_master_rx_event_name((enum reac_master_rx_event)(byte(in, 0) % 6)) != NULL, rc_);
}

static void call_reac_master_drop_name(payload in) {
    REPORT(reac_master_drop_name, reac_master_drop_name((enum reac_master_drop_reason)(byte(in, 0) % 6)) != NULL, rc_);
}
/* ltl: master_init_before_use */
static void call_reac_master_grant_anchor(payload in) {
    (void)in;
    if (!master_valid) return;
    REPORT_VOID(reac_master_grant_anchor, (void)reac_master_grant_anchor(&master));
}

/* reac_hunt.h */

static void call_reac_hunt_verdict_name(payload in) {
    REPORT(reac_hunt_verdict_name, reac_hunt_verdict_name((enum reac_hunt_verdict)(byte(in, 0) % 4)) != NULL, rc_);
}
/* ltl: hunt_init_before_use */
static void call_reac_hunt_init(payload in) {
    uint8_t mac[6];
    mac_of(in, 0, mac);
    if (!preqed_call("reac_hunt_init")) return;
    reac_hunt_init(&hunt, mac, tick(in));
    preqed_result("reac_hunt_init", 1);
    hunt_valid = 1;
}
/* ltl: hunt_init_before_use */
static void call_reac_hunt_pin(payload in) {
    if (!hunt_valid) return;
    REPORT_VOID(reac_hunt_pin, reac_hunt_pin(&hunt, (enum reac_role)(byte(in, 0) & 1)));
}
/* ltl: hunt_init_before_use */
static void call_reac_hunt_silence_proven(payload in) {
    (void)in;
    if (!hunt_valid) return;
    REPORT_VOID(reac_hunt_silence_proven, reac_hunt_silence_proven(&hunt));
}
/* ltl: hunt_init_before_use */
static void call_reac_hunt_observe(payload in) {
    struct reac_disco_sighting s;
    if (!hunt_valid) return;
    if (!preqed_call("reac_hunt_observe")) return;
    int rc = reac_hunt_observe(&hunt, bytes, bytes_len, tick(in), &s);
    preqed_result("reac_hunt_observe", rc >= 0);
}
/* ltl: hunt_init_before_use */
static void call_reac_hunt_step(payload in) {
    if (!hunt_valid) return;
    REPORT_VOID(reac_hunt_step, (void)reac_hunt_step(&hunt, tick(in)));
}
/* ltl: hunt_init_before_use */
static void call_reac_hunt_role(payload in) {
    (void)in;
    if (!hunt_valid) return;
    REPORT_VOID(reac_hunt_role, (void)reac_hunt_role(&hunt));
}
/* ltl: hunt_init_before_use */
static void call_reac_hunt_heard_anything(payload in) {
    (void)in;
    if (!hunt_valid) return;
    REPORT_VOID(reac_hunt_heard_anything, (void)reac_hunt_heard_anything(&hunt));
}

/* reac_knock.h */
/* ltl: knock_init_before_step */
static void call_reac_knock_init(payload in) {
    if (!preqed_call("reac_knock_init")) return;
    reac_knock_init(&knock, tick(in));
    preqed_result("reac_knock_init", 1);
    knock_valid = 1;
}
/* ltl: knock_init_before_step */
static void call_reac_knock_heard(payload in) {
    if (!knock_valid) return;
    REPORT_VOID(reac_knock_heard, reac_knock_heard(&knock, tick(in)));
}
/* ltl: knock_init_before_step */
static void call_reac_knock_step(payload in) {
    if (!knock_valid) return;
    REPORT_VOID(reac_knock_step, (void)reac_knock_step(&knock, tick(in)));
}

/* reac_tapwait.h */

static void call_reac_tapwait_binds(payload in) {
    struct reac_tapwait_in tw;
    if (!preqed_call("reac_tapwait_binds")) return;
    tw.tapped = (int)byte(in, 0) & 1;
    tw.untagged = byte(in, 1);
    tw.last_heard_ns = byte(in, 2) & 1 ? now_ns - (uint64_t)byte(in, 3) * 1000000000ULL : 0;
    tw.now_ns = tick(in);
    reac_tapwait_binds(&tw);
    preqed_result("reac_tapwait_binds", 1);
}

/* reac_arbitration.h */

static void call_reac_rival_kind_of(payload in) {
    struct reac_disco_entry e;
    entry_of(in, &e);
    REPORT_VOID(reac_rival_kind_of, (void)reac_rival_kind_of(byte(in, 15) & 1 ? NULL : &e));
}

static void call_reac_master_only_cadence_frames(payload in) {
    REPORT_VOID(reac_master_only_cadence_frames,
                (void)reac_master_only_cadence_frames((int)byte(in, 0) | (int)byte(in, 1) << 8));
}

static void call_reac_master_only_cadence_ns(payload in) {
    REPORT_VOID(reac_master_only_cadence_ns,
                (void)reac_master_only_cadence_ns((int)byte(in, 0) | (int)byte(in, 1) << 8));
}

static void call_reac_sender_kind(payload in) {
    struct reac_disco_entry e;
    entry_of(in, &e);
    REPORT_VOID(reac_sender_kind,
                (void)reac_sender_kind(byte(in, 15) & 1 ? NULL : &e, now_ns,
                                       (int)byte(in, 16) | (int)byte(in, 4) << 8));
}

static void call_reac_rival_kind_from_channels(payload in) {
    REPORT_VOID(reac_rival_kind_from_channels,
                (void)reac_rival_kind_from_channels((unsigned)byte(in, 0)));
}

static void call_reac_rival_kind_name(payload in) {
    REPORT(reac_rival_kind_name, reac_rival_kind_name((enum reac_rival_kind)(byte(in, 0) % 5)) != NULL, rc_);
}

static void call_reac_rival_refusal(payload in) {
    REPORT(reac_rival_refusal, reac_rival_refusal((enum reac_rival_kind)(byte(in, 0) % 5)) != NULL, rc_);
}

static void call_reac_segment_refusal(payload in) {
    REPORT(reac_segment_refusal, reac_segment_refusal((enum reac_rival_kind)(byte(in, 0) % 5), (int)byte(in, 1) & 1,
                                (int)byte(in, 2) & 1, 1 + (uint64_t)byte(in, 3)) != NULL, rc_);
}

static void call_reac_segment_master_name(payload in) {
    REPORT(reac_segment_master_name, reac_segment_master_name((enum reac_segment_master)(byte(in, 0) % 3)) != NULL, rc_);
}

static void call_reac_pace_source_name(payload in) {
    REPORT(reac_pace_source_name, reac_pace_source_name((enum reac_pace_source)(byte(in, 0) % 5)) != NULL, rc_);
}

static void call_reac_pace_from_clock(payload in) {
    REPORT_VOID(reac_pace_from_clock,
                (void)reac_pace_from_clock((enum reac_clock_source)(byte(in, 0) % REAC_CLOCK_SRC_COUNT),
                                           (enum reac_clock_state)(byte(in, 1) % 4)));
}

static void call_reac_arbitrate(payload in) {
    struct reac_arbitration arb;
    uint8_t mac[6];
    mac_of(in, 0, mac);
    if (!preqed_call("reac_arbitrate")) return;
    reac_arbitrate(table_valid ? &table : NULL, mac, (enum reac_master_state)(byte(in, 6) % 4),
                   (enum reac_pace_source)(byte(in, 7) % 5), tick(in), &arb);
    preqed_result("reac_arbitrate", 1);
}

/* reac_disco.h */

static void call_reac_disco_role_name(payload in) {
    REPORT(reac_disco_role_name, reac_disco_role_name((enum reac_disco_role)(byte(in, 0) % 3)) != NULL, rc_);
}

static void call_reac_disco_classify(payload in) {
    struct reac_disco_sighting s;
    uint8_t mac[6];
    mac_of(in, 0, mac);
    if (!preqed_call("reac_disco_classify")) return;
    int rc = reac_disco_classify(bytes, bytes_len, mac, &s);
    preqed_result("reac_disco_classify", rc == 0);
}
/* ltl: peer_lock_init_before_classify */
static void call_reac_disco_peer_lock_init(payload in) {
    (void)in;
    if (!preqed_call("reac_disco_peer_lock_init")) return;
    reac_disco_peer_lock_init(&lock);
    preqed_result("reac_disco_peer_lock_init", 1);
    lock_valid = 1;
}
/* ltl: peer_lock_init_before_classify */
static void call_reac_disco_classify_on_segment(payload in) {
    struct reac_disco_sighting s;
    uint8_t mac[6];
    mac_of(in, 0, mac);
    if (!lock_valid) return;
    if (!preqed_call("reac_disco_classify_on_segment")) return;
    int rc = reac_disco_classify_on_segment(&lock, bytes, bytes_len, mac, &s);
    preqed_result("reac_disco_classify_on_segment", rc == 0);
}
/* ltl: gate_init_before_push */
static void call_reac_disco_gate_init(payload in) {
    (void)in;
    if (!preqed_call("reac_disco_gate_init")) return;
    reac_disco_gate_init(&gate);
    preqed_result("reac_disco_gate_init", 1);
    gate_valid = 1;
}
/* ltl: gate_init_before_push */
static void call_reac_disco_gate_should_push(payload in) {
    struct reac_disco_sighting s;
    if (!gate_valid) return;
    sighting_of(in, &s);
    REPORT(reac_disco_gate_should_push, reac_disco_gate_should_push(&gate, &s, tick(in)), rc_ >= 0);
}
/* ltl: disco_table_init_before_use */
static void call_reac_disco_table_init(payload in) {
    (void)in;
    if (!preqed_call("reac_disco_table_init")) return;
    reac_disco_table_init(&table);
    preqed_result("reac_disco_table_init", 1);
    table_valid = 1;
}
/* ltl: disco_table_init_before_use */
static void call_reac_disco_table_observe(payload in) {
    struct reac_disco_sighting s;
    if (!table_valid) return;
    sighting_of(in, &s);
    REPORT(reac_disco_table_observe,
           reac_disco_table_observe(&table, &s, (int)byte(in, 13) & 1, tick(in)), rc_ >= 0);
}
/* ltl: disco_table_init_before_use */
static void call_reac_disco_table_age(payload in) {
    if (!table_valid) return;
    REPORT(reac_disco_table_age, reac_disco_table_age(&table, tick(in)), rc_ >= 0);
}
/* ltl: disco_table_init_before_use */
static void call_reac_disco_table_json(payload in) {
    char text[REAC_DISCO_JSON_MAX];
    size_t cap = 3 + byte(in, 0) % (REAC_DISCO_JSON_MAX - 2);
    if (!table_valid) return;
    REPORT(reac_disco_table_json, reac_disco_table_json(&table, now_ns, text, cap), rc_ >= 0);
}

/* reac_boxreg.h */
/* ltl: boxreg_init_before_use */
static void call_reac_boxreg_init(payload in) {
    if (!preqed_call("reac_boxreg_init")) return;
    reac_boxreg_init(&boxreg, (int)byte(in, 0));
    preqed_result("reac_boxreg_init", 1);
    boxreg_valid = 1;
}
/* ltl: boxreg_init_before_use */
static void call_reac_boxreg_find(payload in) {
    uint8_t mac[6];
    mac_of(in, 0, mac);
    if (!boxreg_valid) return;
    REPORT(reac_boxreg_find, reac_boxreg_find(&boxreg, mac), rc_ >= -1);
}
/* ltl: boxreg_init_before_use */
static void call_reac_boxreg_add(payload in) {
    uint8_t mac[6];
    mac_of(in, 0, mac);
    if (!boxreg_valid) return;
    REPORT(reac_boxreg_add, reac_boxreg_add(&boxreg, mac, box_width_of(in, 6)), rc_ >= 0);
}
/* ltl: boxreg_init_before_use */
static void call_reac_boxreg_declare(payload in) {
    char name[REAC_BOXREG_NAME_MAX];
    const char *n = byte(in, 7) & 1 ? NULL : cstr(name, sizeof name, rest(in, 8));
    if (!boxreg_valid) return;
    REPORT(reac_boxreg_declare,
           reac_boxreg_declare(&boxreg, box_width_of(in, 0), n,
                               (int)byte(in, 1) & 1 ? (int)(byte(in, 2) % (REAC_BOXREG_FABRIC + 1)) : -1),
           rc_ >= 0);
}
/* ltl: boxreg_init_before_use */
static void call_reac_boxreg_set_name(payload in) {
    char name[REAC_BOXREG_NAME_MAX];
    const char *n = byte(in, 7) & 1 ? NULL : cstr(name, sizeof name, rest(in, 8));
    if (!boxreg_valid) return;
    REPORT_VOID(reac_boxreg_set_name, reac_boxreg_set_name(&boxreg, (int)byte(in, 0), n));
}

/* reac_box_facts.h */

static void call_reac_box_family_of(payload in) {
    (void)in;
    if (!ident_valid) return;
    REPORT_VOID(reac_box_family_of, (void)reac_box_family_of(&ident));
}

static void call_reac_box_family_stem(payload in) {
    REPORT(reac_box_family_stem, reac_box_family_stem((enum reac_box_family)(byte(in, 0) % 4)) != NULL, rc_);
}

static void call_reac_box_name(payload in) {
    char said[24], name[REAC_BOX_NAME_MAX], token[REAC_BOX_NAME_TOKEN_MAX],
         display[REAC_BOX_NAME_DISPLAY_MAX];
    const char *s = byte(in, 0) & 1 ? NULL : cstr(said, sizeof said, rest(in, 3));
    REPORT(reac_box_name,
           reac_box_name((enum reac_box_family)(byte(in, 1) % 4), s,
                         byte(in, 2) & 1 ? 0 : box_width_of(in, 4),
                         byte(in, 2) & 2 ? 0 : box_width_of(in, 5),
                         name, sizeof name, token, sizeof token, display, sizeof display),
           rc_ == 0);
}

static void call_reac_box_catalogue_defect(payload in) {
    char display[REAC_BOX_NAME_DISPLAY_MAX];
    const struct reac_box_model *m = catalogue_at(in);
    if (!preqed_call("reac_box_catalogue_defect")) return;
    reac_box_catalogue_defect(m, byte(in, 1) & 1 ? 0 : box_width_of(in, 2),
                              byte(in, 1) & 2 ? 0 : box_width_of(in, 3),
                              cstr(display, sizeof display, rest(in, 6)));
    preqed_result("reac_box_catalogue_defect", 1);
}

/* reac_grant.h */

static void call_reac_grant_alloc_fits(payload in) {
    REPORT_VOID(reac_grant_alloc_fits,
                (void)reac_grant_alloc_fits((int)byte(in, 0), (int)byte(in, 1)));
}

static void call_reac_grant_allocate(payload in) {
    struct reac_grant_alloc out;
    if (!preqed_call("reac_grant_allocate")) return;
    int rc = reac_grant_allocate(&out, (int)byte(in, 0) % (REAC_HEADAMP_MAX_CH + 8),
                                 (int)byte(in, 1) % (REAC_GRANT_MAX_WIDTH + 8));
    preqed_result("reac_grant_allocate", rc == 0);
    if (rc == 0) {
        alloc = out;
        alloc_valid = 1;
    }
}

static void call_reac_grant_build_sweep(payload in) {
    (void)in;
    if (!alloc_valid) return;
    if (!preqed_call("reac_grant_build_sweep")) return;
    int rc = reac_grant_build_sweep(sweep, REAC_GRANT_SWEEP_MAX, &alloc,
                                    hamptx_valid ? &hamptx : NULL);
    preqed_result("reac_grant_build_sweep", rc > 0);
}

static void call_reac_grant_headamp_value(payload in) {
    if (!hamptx_valid) return;
    REPORT_VOID(reac_grant_headamp_value,
                (void)reac_grant_headamp_value(&hamptx, (uint8_t)(byte(in, 0) % REAC_HEADAMP_MAX_CH),
                                               (uint8_t)(byte(in, 1) % 4)));
}

/* reac_headamp_tx.h */

static void call_reac_headamp_pack(payload in) {
    REPORT_VOID(reac_headamp_pack,
                (void)reac_headamp_pack((uint8_t)(byte(in, 0) % REAC_HEADAMP_MAX_CH),
                                        (uint8_t)(byte(in, 1) % 4), byte(in, 2)));
}

static void call_reac_headamp_unpack(payload in) {
    uint8_t ch = 0, param = 0, value = 0;
    uint32_t w = (uint32_t)byte(in, 0) << 16 | (uint32_t)byte(in, 1) << 8 | byte(in, 2);
    REPORT_VOID(reac_headamp_unpack, reac_headamp_unpack(w, &ch, &param, &value));
}
/* ltl: headamp_tx_init_before_set */
static void call_reac_headamp_tx_init(payload in) {
    (void)in;
    if (!preqed_call("reac_headamp_tx_init")) return;
    reac_headamp_tx_init(&hamptx);
    preqed_result("reac_headamp_tx_init", 1);
    hamptx_valid = 1;
}
/* ltl: headamp_tx_init_before_set */
static void call_reac_headamp_tx_set(payload in) {
    if (!hamptx_valid) return;
    REPORT(reac_headamp_tx_set,
           reac_headamp_tx_set(&hamptx, (uint8_t)(byte(in, 0) % REAC_HEADAMP_MAX_CH),
                               (uint8_t)(byte(in, 1) % 4), byte(in, 2)), rc_ == 0);
}

static void call_reac_headamp_default(payload in) {
    REPORT_VOID(reac_headamp_default, (void)reac_headamp_default((uint8_t)(byte(in, 0) % 4)));
}
/* ltl: headamp_tx_init_before_set */
static void call_reac_headamp_tx_effective(payload in) {
    REPORT_VOID(reac_headamp_tx_effective,
                (void)reac_headamp_tx_effective(hamptx_valid ? &hamptx : NULL,
                                                (uint8_t)(byte(in, 0) % REAC_HEADAMP_MAX_CH),
                                                (uint8_t)(byte(in, 1) % 4)));
}
/* ltl: headamp_tx_init_before_set */
static void call_reac_headamp_tx_arm_scene(payload in) {
    if (!hamptx_valid) return;
    REPORT_VOID(reac_headamp_tx_arm_scene,
                reac_headamp_tx_arm_scene(&hamptx, byte(in, 0), byte(in, 1)));
}
/* ltl: headamp_tx_init_before_set */
static void call_reac_headamp_tx_set_resweep(payload in) {
    if (!hamptx_valid) return;
    REPORT_VOID(reac_headamp_tx_set_resweep,
                reac_headamp_tx_set_resweep(&hamptx, (uint32_t)byte(in, 0) | (uint32_t)byte(in, 1) << 8));
}
/* ltl: headamp_tx_init_before_set */
static void call_reac_headamp_tx_next(payload in) {
    uint8_t ch = 0, param = 0, value = 0;
    (void)in;
    if (!hamptx_valid) return;
    REPORT_VOID(reac_headamp_tx_next, (void)reac_headamp_tx_next(&hamptx, &ch, &param, &value));
}

/* reac_link.h */

static void call_reac_link_fill_descriptor(payload in) {
    if (bytes_len < REAC_CTRL_BLOCK_END) return;   /* stamps the [18:50] block */
    REPORT_VOID(reac_link_fill_descriptor,
                reac_link_fill_descriptor(bytes, (enum reac_link_desc)byte(in, 0)));
}

static void call_reac_link_desc_for(payload in) {
    REPORT_VOID(reac_link_desc_for,
                (void)reac_link_desc_for((enum reac_fsm_state)(byte(in, 0) % 7), (int)byte(in, 1) & 1));
}

static void call_reac_link_slave_burst(payload in) {
    int n_src = 0;
    float *const *pl = planes_from(in, &n_src);
    uint8_t master[6], src[6];
    mac_of(in, 1, master);
    mac_of(in, 7, src);
    if (!preqed_call("reac_link_slave_burst")) return;
    int rc = reac_link_slave_burst((int)byte(in, 0), bytes, master, src,
                                   (uint16_t)(byte(in, 13) | byte(in, 14) << 8), box_width_of(in, 15),
                                   pl, (int)(byte(in, 16) % (REAC_SAMPLES_PER_PKT + 1)));
    preqed_result("reac_link_slave_burst", rc >= 0);
    if (rc > 0) bytes_len = (size_t)rc;
}

/* reac_link_state.h */

static void call_reac_link_state_from_master(payload in) {
    REPORT_VOID(reac_link_state_from_master,
                (void)reac_link_state_from_master((enum reac_master_state)(byte(in, 0) % 4),
                                                  (int)byte(in, 1) & 1));
}

static void call_reac_link_state_name(payload in) {
    REPORT(reac_link_state_name, reac_link_state_name((enum reac_link_state)(byte(in, 0) % 4)) != NULL, rc_);
}

static void call_reac_box_mac_publish(payload in) {
    uint64_t mac48 = 0;
    for (size_t i = 0; i < 8; i++)
        mac48 = mac48 << 8 | byte(in, i);
    REPORT_VOID(reac_box_mac_publish, reac_box_mac_publish(mac48, noop_prop, NULL));
}

static void call_reac_box_master_identity_publish(payload in) {
    uint64_t mac48 = 0;
    for (size_t i = 0; i < 8; i++)
        mac48 = mac48 << 8 | byte(in, i);
    REPORT_VOID(reac_box_master_identity_publish,
                reac_box_master_identity_publish((unsigned)byte(in, 9), mac48, (int)byte(in, 10) & 1,
                                                 noop_prop, NULL));
}

static void call_reac_box_identity_publish(payload in) {
    (void)in;
    REPORT_VOID(reac_box_identity_publish,
                reac_box_identity_publish(ident_valid ? &ident : NULL, noop_prop, NULL));
}

/* reac_ctrl.h */

static void call_reac_ctrl_classify_box_frame(payload in) {
    struct reac_ctrl_parsed out;
    enum reac_master_rx_event ev = REAC_M_RX_BOX_BCAST_FILLER;
    uint8_t mac[6];
    mac_of(in, 0, mac);
    if (!preqed_call("reac_ctrl_classify_box_frame")) return;
    int rc = reac_ctrl_classify_box_frame(bytes, bytes_len, mac, &out, &ev);
    preqed_result("reac_ctrl_classify_box_frame", rc == 0);
}

/* reac_ctrlblk.h */

static void call_reac_ctrl_block_cksum_stamp(payload in) {
    uint8_t block[REAC_CTRL_BLOCK_LEN];
    block_of(in, block);
    REPORT_VOID(reac_ctrl_block_cksum_stamp, reac_ctrl_block_cksum_stamp(block));
}

static void call_reac_ctrl_checksum_apply(payload in) {
    if (bytes_len < REAC_CTRL_BLOCK_END) return;   /* rewrites frame[49] */
    (void)in;
    REPORT_VOID(reac_ctrl_checksum_apply, reac_ctrl_checksum_apply(bytes));
}

static void call_reac_ctrl_checksum_verify(payload in) {
    (void)in;
    if (bytes_len < REAC_CTRL_BLOCK_END) return;
    REPORT(reac_ctrl_checksum_verify, reac_ctrl_checksum_verify(bytes), rc_ == 0);
}

static void call_reac_ctrl_record_cksum_stamp(payload in) {
    uint8_t rec[64];
    payload body = rest(in, 0);
    size_t n = body.n < sizeof rec ? body.n : sizeof rec;
    if (n < 1) return;   /* the record's last byte is the checksum */
    memcpy(rec, body.p, n);
    REPORT_VOID(reac_ctrl_record_cksum_stamp, reac_ctrl_record_cksum_stamp(rec, n));
}

static void call_reac_ctrl_record_cksum_verify(payload in) {
    uint8_t rec[64];
    payload body = rest(in, 0);
    size_t n = body.n < sizeof rec ? body.n : sizeof rec;
    if (n < 1) return;
    memcpy(rec, body.p, n);
    REPORT(reac_ctrl_record_cksum_verify, reac_ctrl_record_cksum_verify(rec, n), rc_ == 0);
}

static void call_reac_ctrl_build_scene_step(payload in) {
    uint8_t blk[34];
    if (!scene_valid) return;
    REPORT(reac_ctrl_build_scene_step,
           reac_ctrl_build_scene_step(blk, scene, REAC_SCENE_BYTES,
                                      (int)byte(in, 0) % (REAC_SCENE_STEPS + 2)), rc_ == 0);
}

static void call_reac_ctrl_scene_set_mac(payload in) {
    uint8_t mac[6];
    mac_of(in, 0, mac);
    if (!scene_valid) return;
    REPORT(reac_ctrl_scene_set_mac,
           reac_ctrl_scene_set_mac(scene, (int)byte(in, 6) & 1 ? REAC_SCENE_BYTES : (size_t)byte(in, 7) * 64,
                                   mac), rc_ == 0);
}

static void call_reac_ctrl_scene_build(payload in) {
    uint8_t mac[6];
    mac_of(in, 0, mac);
    if (!preqed_call("reac_ctrl_scene_build")) return;
    int rc = reac_ctrl_scene_build(scene, REAC_SCENE_BYTES, mac);
    preqed_result("reac_ctrl_scene_build", rc == 0);
    scene_valid = rc == 0;
}

static void call_reac_headamp_sens_cdb(payload in) {
    REPORT_VOID(reac_headamp_sens_cdb,
                (void)reac_headamp_sens_cdb(byte(in, 0), (int)byte(in, 1) & 1));
}

static void call_reac_headamp_sens_value_cdb(payload in) {
    REPORT_VOID(reac_headamp_sens_value_cdb,
                (void)reac_headamp_sens_value_cdb((int)byte(in, 0) - 200, (int)byte(in, 1) & 1));
}

static void call_reac_headamp_sens_db(payload in) {
    REPORT_VOID(reac_headamp_sens_db, (void)reac_headamp_sens_db(byte(in, 0), (int)byte(in, 1) & 1));
}

static void call_reac_headamp_sens_value(payload in) {
    REPORT_VOID(reac_headamp_sens_value,
                (void)reac_headamp_sens_value((int)byte(in, 0) - 128, (int)byte(in, 1) & 1));
}

static void call_reac_ctrl_kind_name(payload in) {
    REPORT(reac_ctrl_kind_name, reac_ctrl_kind_name((enum reac_ctrl_kind)(byte(in, 0) % 14)) != NULL, rc_);
}

static void call_reac_ctrl_parse(payload in) {
    (void)in;
    struct reac_ctrl_parsed out;
    if (!preqed_call("reac_ctrl_parse")) return;
    enum reac_ctrl_kind kind = reac_ctrl_parse(bytes, bytes_len, &out);
    preqed_result("reac_ctrl_parse", kind != REAC_CTRL_NONE);
    parsed = out;
    parsed_valid = kind != REAC_CTRL_NONE;
}

static void call_reac_box_model_block(payload in) {
    uint8_t blk[32];
    const struct reac_box_model *m = catalogue_at(in);
    REPORT(reac_box_model_block,
           reac_box_model_block(m, (enum reac_box_block)(byte(in, 1) % 7), blk), rc_ >= 0);
}

static void call_reac_box_model_upstream_width(payload in) {
    const struct reac_box_model *m = catalogue_at(in);
    REPORT(reac_box_model_upstream_width, reac_box_model_upstream_width(m), rc_ > 0);
}

static void call_reac_ctrl_build_as(payload in) {
    const struct reac_box_model *m = catalogue_at(in);
    int n_src = 0;
    float *const *pl = planes_from(in, &n_src);
    uint8_t master[6], src[6];
    mac_of(in, 1, master);
    mac_of(in, 7, src);
    if (!preqed_call("reac_ctrl_build_as")) return;
    int rc = (int)reac_ctrl_build_as(bytes, m, (enum reac_box_block)(byte(in, 13) % 7), master, src,
                                     (uint16_t)(byte(in, 14) | byte(in, 15) << 8), pl,
                                     (int)(byte(in, 16) % (REAC_SAMPLES_PER_PKT + 1)));
    preqed_result("reac_ctrl_build_as", rc > 0);
    if (rc > 0) bytes_len = (size_t)rc;
}

static void call_reac_box_catalogue_by_token(payload in) {
    char token[16];
    REPORT(reac_box_catalogue_by_token, reac_box_catalogue_by_token(cstr(token, sizeof token, in)) != NULL, rc_);
}

static void call_reac_box_catalogue_by_width(payload in) {
    REPORT(reac_box_catalogue_by_width, reac_box_catalogue_by_width((int)byte(in, 0)) != NULL, rc_);
}

static void call_reac_box_catalogue(payload in) {
    size_t count = 0;
    (void)in;
    REPORT(reac_box_catalogue, reac_box_catalogue(&count) != NULL && count > 0, rc_);
}

static void call_reac_box_catalogue_match(payload in) {
    (void)in;
    REPORT(reac_box_catalogue_match, reac_box_catalogue_match(bytes, bytes_len) != NULL, rc_);
}

static void call_reac_ctrl_box_frame_len(payload in) {
    REPORT_VOID(reac_ctrl_box_frame_len, (void)reac_ctrl_box_frame_len((int)byte(in, 0)));
}

static void call_reac_ctrl_build_box_hb(payload in) {
    uint8_t master[6], src[6];
    mac_of(in, 1, master);
    mac_of(in, 7, src);
    if (!preqed_call("reac_ctrl_build_box_hb")) return;
    size_t rc = reac_ctrl_build_box_hb(bytes, master, src,
                                       (uint16_t)(byte(in, 13) | byte(in, 14) << 8), box_width_of(in, 15));
    preqed_result("reac_ctrl_build_box_hb", rc > 0);
    if (rc > 0) bytes_len = rc;
}

static void call_reac_ctrl_build_upstream_filler(payload in) {
    int n_src = 0;
    float *const *pl = planes_from(in, &n_src);
    uint8_t master[6], src[6];
    mac_of(in, 1, master);
    mac_of(in, 7, src);
    if (!preqed_call("reac_ctrl_build_upstream_filler")) return;
    size_t rc = reac_ctrl_build_upstream_filler(bytes, master, src,
                                                (uint16_t)(byte(in, 13) | byte(in, 14) << 8),
                                                box_width_of(in, 15), pl,
                                                (int)(byte(in, 16) % (REAC_SAMPLES_PER_PKT + 1)));
    preqed_result("reac_ctrl_build_upstream_filler", rc > 0);
    if (rc > 0) bytes_len = rc;
}

static void call_reac_ctrl_build_flood_filler(payload in) {
    int n_src = 0;
    float *const *pl = planes_from(in, &n_src);
    uint8_t bcast[6], src[6];
    mac_of(in, 1, bcast);
    mac_of(in, 7, src);
    if (!preqed_call("reac_ctrl_build_flood_filler")) return;
    size_t rc = reac_ctrl_build_flood_filler(bytes, bcast, src,
                                             (uint16_t)(byte(in, 13) | byte(in, 14) << 8),
                                             box_width_of(in, 15), pl,
                                             (int)(byte(in, 16) % (REAC_SAMPLES_PER_PKT + 1)));
    preqed_result("reac_ctrl_build_flood_filler", rc > 0);
    if (rc > 0) bytes_len = rc;
}

static void call_reac_box_pin_notice(payload in) {
    const char *pin;
    cstr(pin_buf, sizeof pin_buf, rest(in, 1));
    pin = byte(in, 0) & 1 ? NULL : pin_buf;
    REPORT_VOID(reac_box_pin_notice,
                (void)reac_box_pin_notice(&pin, byte(in, 32) & 1 ? NULL : pin_buf));
}

static void call_reac_ctrl_build_config_announce(payload in) {
    uint8_t master[6], src[6];
    mac_of(in, 1, master);
    mac_of(in, 7, src);
    if (!preqed_call("reac_ctrl_build_config_announce")) return;
    size_t rc = reac_ctrl_build_config_announce(bytes, master, src,
                                                (uint16_t)(byte(in, 13) | byte(in, 14) << 8),
                                                box_width_of(in, 15));
    preqed_result("reac_ctrl_build_config_announce", rc > 0);
    if (rc > 0) bytes_len = rc;
}

static void call_reac_ctrl_build_identity_first(payload in) {
    uint8_t master[6], src[6];
    mac_of(in, 1, master);
    mac_of(in, 7, src);
    if (!preqed_call("reac_ctrl_build_identity_first")) return;
    size_t rc = reac_ctrl_build_identity_first(bytes, master, src,
                                               (uint16_t)(byte(in, 13) | byte(in, 14) << 8),
                                               box_width_of(in, 15));
    preqed_result("reac_ctrl_build_identity_first", rc > 0);
    if (rc > 0) bytes_len = rc;
}

static void call_reac_ctrl_build_identity_last(payload in) {
    uint8_t master[6], src[6];
    mac_of(in, 1, master);
    mac_of(in, 7, src);
    if (!preqed_call("reac_ctrl_build_identity_last")) return;
    size_t rc = reac_ctrl_build_identity_last(bytes, master, src,
                                              (uint16_t)(byte(in, 13) | byte(in, 14) << 8),
                                              box_width_of(in, 15));
    preqed_result("reac_ctrl_build_identity_last", rc > 0);
    if (rc > 0) bytes_len = rc;
}

static void call_reac_ctrl_identity_poll_block(payload in) {
    uint8_t blk[34];
    REPORT(reac_ctrl_identity_poll_block,
           reac_ctrl_identity_poll_block((int)byte(in, 0) % (REAC_GRANT_GROUPB_LEN + 1), blk), rc_ == 0);
}

static void call_reac_ctrl_identity_fragment(payload in) {
    (void)in;
    uint16_t addr = 0;
    const uint8_t *body = NULL;
    size_t body_len = 0;
    if (!ident_valid) return;   /* f is zero-initialised with the identity */
    REPORT(reac_ctrl_identity_fragment,
           reac_ctrl_identity_fragment(&ident_frag, bytes, bytes_len, &addr, &body, &body_len), rc_ >= 0);
}

static void call_reac_ctrl_identity_reply(payload in) {
    uint16_t addr = 0;
    const uint8_t *body = NULL;
    size_t body_len = 0;
    (void)in;
    REPORT(reac_ctrl_identity_reply,
           reac_ctrl_identity_reply(bytes, bytes_len, &addr, &body, &body_len), rc_ >= 0);
}

static void call_reac_ctrl_build_coldconnect(payload in) {
    int n_src = 0;
    float *const *pl = planes_from(in, &n_src);
    uint8_t master[6], src[6];
    mac_of(in, 1, master);
    mac_of(in, 7, src);
    if (!preqed_call("reac_ctrl_build_coldconnect")) return;
    size_t rc = reac_ctrl_build_coldconnect(bytes, master, src,
                                            (uint16_t)(byte(in, 13) | byte(in, 14) << 8),
                                            box_width_of(in, 15), pl,
                                            (int)(byte(in, 16) % (REAC_SAMPLES_PER_PKT + 1)));
    preqed_result("reac_ctrl_build_coldconnect", rc > 0);
    if (rc > 0) bytes_len = rc;
}

static void call_reac_ctrl_build_config_announce_box_master(payload in) {
    uint8_t master[6], src[6];
    mac_of(in, 1, master);
    mac_of(in, 7, src);
    if (!preqed_call("reac_ctrl_build_config_announce_box_master")) return;
    size_t rc = reac_ctrl_build_config_announce_box_master(bytes, master, src,
                                                          (uint16_t)(byte(in, 13) | byte(in, 14) << 8),
                                                          box_width_of(in, 15));
    preqed_result("reac_ctrl_build_config_announce_box_master", rc > 0);
    if (rc > 0) bytes_len = rc;
}

static void call_reac_ctrl_build_coldconnect_head(payload in) {
    int n_src = 0;
    float *const *pl = planes_from(in, &n_src);
    uint8_t master[6], src[6];
    mac_of(in, 1, master);
    mac_of(in, 7, src);
    if (!preqed_call("reac_ctrl_build_coldconnect_head")) return;
    size_t rc = reac_ctrl_build_coldconnect_head(bytes, master, src,
                                                 (uint16_t)(byte(in, 13) | byte(in, 14) << 8),
                                                 box_width_of(in, 15), pl,
                                                 (int)(byte(in, 16) % (REAC_SAMPLES_PER_PKT + 1)));
    preqed_result("reac_ctrl_build_coldconnect_head", rc > 0);
    if (rc > 0) bytes_len = rc;
}

static void call_reac_ctrl_build_coldconnect_0013(payload in) {
    int n_src = 0;
    float *const *pl = planes_from(in, &n_src);
    uint8_t master[6], src[6];
    mac_of(in, 1, master);
    mac_of(in, 7, src);
    if (!preqed_call("reac_ctrl_build_coldconnect_0013")) return;
    size_t rc = reac_ctrl_build_coldconnect_0013(bytes, master, src,
                                                 (uint16_t)(byte(in, 13) | byte(in, 14) << 8),
                                                 box_width_of(in, 15), pl,
                                                 (int)(byte(in, 16) % (REAC_SAMPLES_PER_PKT + 1)));
    preqed_result("reac_ctrl_build_coldconnect_0013", rc > 0);
    if (rc > 0) bytes_len = rc;
}

static void call_reac_ctrl_build_coldconnect_0016(payload in) {
    int n_src = 0;
    float *const *pl = planes_from(in, &n_src);
    uint8_t master[6], src[6];
    mac_of(in, 1, master);
    mac_of(in, 7, src);
    if (!preqed_call("reac_ctrl_build_coldconnect_0016")) return;
    size_t rc = reac_ctrl_build_coldconnect_0016(bytes, master, src,
                                                 (uint16_t)(byte(in, 13) | byte(in, 14) << 8),
                                                 box_width_of(in, 15), pl,
                                                 (int)(byte(in, 16) % (REAC_SAMPLES_PER_PKT + 1)));
    preqed_result("reac_ctrl_build_coldconnect_0016", rc > 0);
    if (rc > 0) bytes_len = rc;
}

static void call_reac_ctrl_build_coldconnect_001a(payload in) {
    int n_src = 0;
    float *const *pl = planes_from(in, &n_src);
    uint8_t master[6], src[6];
    mac_of(in, 1, master);
    mac_of(in, 7, src);
    if (!preqed_call("reac_ctrl_build_coldconnect_001a")) return;
    size_t rc = reac_ctrl_build_coldconnect_001a(bytes, master, src,
                                                 (uint16_t)(byte(in, 13) | byte(in, 14) << 8),
                                                 box_width_of(in, 15), pl,
                                                 (int)(byte(in, 16) % (REAC_SAMPLES_PER_PKT + 1)));
    preqed_result("reac_ctrl_build_coldconnect_001a", rc > 0);
    if (rc > 0) bytes_len = rc;
}

static void call_reac_ctrl_build_headamp(payload in) {
    uint8_t master[6], src[6];
    mac_of(in, 1, master);
    mac_of(in, 7, src);
    if (!preqed_call("reac_ctrl_build_headamp")) return;
    size_t rc = reac_ctrl_build_headamp(bytes, master, src,
                                        (uint16_t)(byte(in, 13) | byte(in, 14) << 8), byte(in, 15),
                                        (uint8_t)(byte(in, 16) % 4), byte(in, 17));
    preqed_result("reac_ctrl_build_headamp", rc > 0);
    if (rc > 0) bytes_len = rc;
}

static void call_reac_ctrl_stamp_headamp(payload in) {
    if (bytes_len < REAC_CTRL_BLOCK_END) return;   /* overlays an already-built frame */
    REPORT(reac_ctrl_stamp_headamp,
           reac_ctrl_stamp_headamp(bytes, byte(in, 0), (uint8_t)(byte(in, 1) % 4), byte(in, 2)),
           rc_ == 0);
}

static void call_reac_headamp_param_name(payload in) {
    REPORT(reac_headamp_param_name, reac_headamp_param_name((uint8_t)(byte(in, 0) % 4)) != NULL, rc_);
}

static void call_reac_ctrl_headamp_record_verify(payload in) {
    (void)in;
    if (bytes_len < REAC_CTRL_BLOCK_END) return;
    REPORT(reac_ctrl_headamp_record_verify, reac_ctrl_headamp_record_verify(bytes), rc_ == 0);
}

static void call_reac_headamp_group_of(payload in) {
    REPORT_VOID(reac_headamp_group_of,
                (void)reac_headamp_group_of(byte(in, 0), (uint8_t)(byte(in, 1) % 4)));
}

static void call_reac_headamp_record_carries(payload in) {
    REPORT_VOID(reac_headamp_record_carries,
                (void)reac_headamp_record_carries(byte(in, 0), (uint8_t)(byte(in, 1) % 4)));
}

static void call_reac_ctrl_build_grant_sweep(payload in) {
    uint8_t values[REAC_GRANT_MAX_WIDTH * REAC_HEADAMP_NPARAMS];
    int width = box_width_of(in, 0);
    for (size_t i = 0; i < sizeof values; i++)
        values[i] = byte(in, 1 + i);
    if (!preqed_call("reac_ctrl_build_grant_sweep")) return;
    int rc = reac_ctrl_build_grant_sweep(sweep, REAC_GRANT_SWEEP_MAX, byte(in, 2), width, values);
    preqed_result("reac_ctrl_build_grant_sweep", rc > 0);
}

/* ---- libreac-transport (transport/src) and the src/ sources it opens through ----
   One object per family, driven over in-memory io: wire frames reach the fd-based readers
   through one end of a socketpair, pcap and conf files are memfds opened by their
   /proc/self/fd path, netlink datagrams are built in an aligned buffer, and every
   timestamp comes from the payload-driven clock (now_ns, advance()). Sockets that need
   CAP_NET_RAW / CAP_NET_ADMIN are called for real and fail cleanly without them. */

#define PCAP_MAX_RECORDS 64                              /* bounds a tap's realtime replay span */
static int pcap_fd = -1;                                 /* memfd: a pcap the harness builds */
static unsigned pcap_records;
static uint32_t pcap_clock_us;                           /* record timestamps: +0..255 us each */
static int pcap_swapped;
static int file_fd = -1;                                 /* memfd: raw payload bytes (conf / pcap) */
static int sock[2] = { -1, -1 };                         /* SOCK_SEQPACKET socketpair, non-blocking */
static int fd_peer = -1;                                 /* the end the harness writes frames into */
static int sock_end = -1;                                /* the end the library reads */
static uint8_t nlbuf[4096] __attribute__((aligned(8)));  /* one netlink datagram */
static size_t nl_len;
static float flat[REAC_MAX_CHANNELS * 64];               /* planar c*n+s source for reac_ring_write */
static uint8_t popbuf[4096];                             /* >= any frame ring slot_sz the harness asks for */

static struct reac_ring ring;
static int ring_valid;
static struct reac_frame_ring fring;
static int fring_valid;
static struct reac_discard_watch dwatch;
static struct reac_clock_label clabel;
static struct reac_pace_watch pwatch;
static int pwatch_valid;
static struct reac_role_swap rswap;
static int rswap_valid;
static struct reac_seglock seglock;                      /* zeroed = holds nothing (reac_seglock.h) */
static struct reac_segment_heard heard;
static int heard_valid;
static struct reac_slave slave;
static int slave_valid, slave_open_ok, slave_running;
static struct reac_tap_survey survey;
static int survey_valid;
static struct reac_tap tap;
static int tap_valid;
static struct reac_topo topo;
static int topo_valid;
static struct reac_topo_tap ttap;
static struct reac_ifscan ifscan;
static int ifscan_valid;
static struct reac_linkmon linkmon;
static int linkmon_valid;
static struct reac_rx rx;
static struct reac_ring rx_ring;
static int rx_valid, rx_running;
static struct pcap_source psrc;
static int psrc_valid;
static struct reac_capture cap = { -1 };
static int cap_blocking;
static struct reac_tx tx;
static int pkt_fd = -1;                                  /* a deaf packet socket, only with CAP_NET_RAW */
static struct reac_pacer pacer;
static int pacer_valid, pacer_open_ok, pacer_running;
static char vlan_minted[IFNAMSIZ];                       /* a netdev reac_vlan_create made */
static char rx_source[48], tap_source[48];               /* cfg.source: the feeder threads keep the pointer */
static int etf_present_ifindex;                          /* an ifindex reac_etf_qdisc_state found etf on */

/* time units of 1 us, 1 ms, 1 s or 1 ns: u16 count + unit byte; reaches every window the
   transport keeps (pace watch 2 s / 5 ms gap, discard 30 s, health 10 s, holds 3-30 s) */
static uint64_t advance(payload in, size_t i) {
    static const uint64_t unit[] = { 1000ULL, 1000000ULL, 1000000000ULL, 1ULL };
    now_ns += (uint64_t)(byte(in, i) | byte(in, i + 1) << 8) * unit[byte(in, i + 2) % 4];
    return now_ns;
}

/* interface names: the container's loopback, names that need not exist, or payload text */
static const char *ifname_of(char *dst, payload in, size_t i) {
    static const char *const names[] = { "lo", "eth0", "eth1", "enp1s0", "reac0", "wlan0", "" };
    unsigned k = byte(in, i) % 8;
    if (k < 7) return strcpy(dst, names[k]);
    return cstr(dst, 20, rest(in, i + 1));               /* may exceed IFNAMSIZ: the refusal paths */
}

/* a name the harness never shares with a host netdev: the netlink writers (vlan create/up,
   link admin) run only against interfaces this process drives (reac_vlan.h) */
static const char *own_ifname(char *dst, payload in, size_t i) {
    snprintf(dst, IFNAMSIZ, "rfz%u", byte(in, i) % 8);
    return dst;
}

static const char *fd_path(char *dst, size_t cap, int fd) {
    snprintf(dst, cap, "/proc/self/fd/%d", fd);
    return dst;
}

static int memfd_reset(int *fd, const char *name) {
    if (*fd < 0) *fd = memfd_create(name, MFD_CLOEXEC);
    if (*fd < 0) return -1;
    if (ftruncate(*fd, 0) != 0) return -1;
    return 0;
}

static void put32(uint8_t *p, uint32_t v, int be) {
    for (int i = 0; i < 4; i++)
        p[i] = (uint8_t)(be ? v >> (24 - 8 * i) : v >> (8 * i));
}

/* harness records: files, frames into the socketpair, netlink datagrams */

/* the rx / tap feeder threads replay pcap_fd in a loop: it is rewritten only while none runs */
static int pcap_in_use(void) { return rx_running || tap.started; }

static void call_set_pcap_header(payload in) {
    uint8_t h[24];
    if (pcap_in_use() || memfd_reset(&pcap_fd, "reac-pcap") != 0) return;
    pcap_swapped = byte(in, 0) & 1;                      /* classic pcap, either byte order */
    put32(h, 0xa1b2c3d4u, pcap_swapped);
    h[4] = 0; h[5] = 2; h[6] = 0; h[7] = 4;              /* version 2.4 */
    if (!pcap_swapped) { h[4] = 2; h[5] = 0; h[6] = 4; h[7] = 0; }
    put32(h + 8, 0, pcap_swapped);
    put32(h + 12, 0, pcap_swapped);
    put32(h + 16, 65535, pcap_swapped);
    put32(h + 20, byte(in, 1) & 2 ? byte(in, 2) : 1, pcap_swapped);   /* link-type 1 = Ethernet */
    if (write(pcap_fd, h, sizeof h) != (ssize_t)sizeof h) return;
    pcap_records = 0;
    pcap_clock_us = 0;
}

static void call_add_pcap_record(payload in) {
    uint8_t rec[16], f[4096 + 4];
    payload body = byte(in, 0) & 1 ? (payload){ bytes, bytes_len } : rest(in, 4);
    size_t n = body.n < 4096 ? body.n : 4096;
    if (pcap_fd < 0 || pcap_in_use() || pcap_records >= PCAP_MAX_RECORDS) return;
    if (byte(in, 0) & 2 && n >= 12) {                    /* an 802.1Q tag, as a trunk mirror delivers */
        memcpy(f, body.p, 12);
        f[12] = 0x81; f[13] = 0x00; f[14] = byte(in, 2) & 0x0f; f[15] = byte(in, 3);
        memcpy(f + 16, body.p + 12, n - 12);
        n += 4;
    } else {
        memcpy(f, body.p, n);
    }
    pcap_clock_us += byte(in, 1);
    put32(rec, 1700000000u, pcap_swapped);
    put32(rec + 4, pcap_clock_us, pcap_swapped);
    size_t caplen = byte(in, 0) & 4 ? n / 2 : n;         /* a snaplen-truncated record */
    put32(rec + 8, (uint32_t)caplen, pcap_swapped);
    put32(rec + 12, (uint32_t)n, pcap_swapped);
    if (write(pcap_fd, rec, sizeof rec) != (ssize_t)sizeof rec) return;
    if (write(pcap_fd, f, caplen) != (ssize_t)caplen) return;
    pcap_records++;
}

static void call_set_file(payload in) {
    if (memfd_reset(&file_fd, "reac-file") != 0) return;
    if (in.n && write(file_fd, in.p, in.n) != (ssize_t)in.n) return;
}

static void open_socketpair(void) {
    if (sock[0] >= 0) return;
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sock) < 0) return;
    sock_end = sock[0];
    fd_peer = sock[1];
}

/* one frame, or a run of copies whose u16 counter [14..15] advances by 1, as a stream does */
static void call_push_wire_frame(payload in) {
    uint8_t f[sizeof bytes];
    payload src = byte(in, 0) & 1 ? (payload){ bytes, bytes_len } : rest(in, 2);
    unsigned count = byte(in, 0) & 2 ? 1 + byte(in, 1) % 64 : 1;
    if (src.n > sizeof f) src.n = sizeof f;
    memcpy(f, src.p, src.n);
    open_socketpair();
    if (fd_peer < 0) return;
    for (unsigned i = 0; i < count; i++) {
        if (send(fd_peer, f, src.n, MSG_DONTWAIT) < 0) return;   /* a full socket drops the rest */
        if (src.n >= 16 && (f[14] = (uint8_t)(f[14] + 1)) == 0) f[15]++;
    }
}

/* one RTM_NEWLINK / RTM_DELLINK for an interface, optionally followed by NLMSG_DONE, or raw bytes */
static void call_set_netlink(payload in) {
    char name[24];
    if (byte(in, 0) & 0x80) {
        payload raw = rest(in, 1);
        nl_len = raw.n < sizeof nlbuf ? raw.n : sizeof nlbuf;
        memcpy(nlbuf, raw.p, nl_len);
        return;
    }
    memset(nlbuf, 0, sizeof nlbuf);
    struct nlmsghdr *nh = (struct nlmsghdr *)nlbuf;
    struct ifinfomsg *ifi = NLMSG_DATA(nh);
    nh->nlmsg_type = byte(in, 0) & 1 ? RTM_DELLINK : RTM_NEWLINK;
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_type = byte(in, 1) & 1 ? ARPHRD_LOOPBACK : ARPHRD_ETHER;
    ifi->ifi_index = 1 + byte(in, 2) % 16;
    ifi->ifi_flags = (byte(in, 3) & 1 ? 0x10000 : 0) | (byte(in, 3) & 2 ? IFF_LOOPBACK : 0) | IFF_UP;
    ifname_of(name, in, 4);
    struct rtattr *rta = (struct rtattr *)((uint8_t *)ifi + NLMSG_ALIGN(sizeof *ifi));
    size_t nlen = strlen(name) + 1;
    rta->rta_type = IFLA_IFNAME;
    rta->rta_len = (unsigned short)RTA_LENGTH(nlen);
    memcpy(RTA_DATA(rta), name, nlen);
    nh->nlmsg_len = NLMSG_LENGTH(NLMSG_ALIGN(sizeof *ifi) + RTA_ALIGN(rta->rta_len));
    nl_len = NLMSG_ALIGN(nh->nlmsg_len);
    if (byte(in, 0) & 2) {                               /* the end of a dump */
        struct nlmsghdr *done = (struct nlmsghdr *)(nlbuf + nl_len);
        done->nlmsg_type = NLMSG_DONE;
        done->nlmsg_len = NLMSG_LENGTH(sizeof(int));
        nl_len += NLMSG_ALIGN(done->nlmsg_len);
    }
}

/* reac_detect_rate_fd (reac.h) over the socketpair; window 1..3 ms so one input stays fast */

static void call_reac_detect_rate_fd(payload in) {
    open_socketpair();
    if (sock_end < 0) return;
    REPORT(reac_detect_rate_fd, reac_detect_rate_fd(sock_end, 1 + byte(in, 0) % 3), rc_ > 0);
}

/* reac_capture.h: the capture reads whichever fd it holds; the socketpair end stands in for the
   AF_PACKET socket reac_capture_open makes with CAP_NET_RAW */

static void call_use_socketpair_capture(payload in) {
    (void)in;
    open_socketpair();
    if (cap.fd >= 0 || sock_end < 0) return;
    cap.fd = sock_end;
    cap_blocking = 0;
}
/* ltl: capture_closed_before_reopen */
static void call_reac_capture_open(payload in) {
    char name[24];
    if (cap.fd >= 0) return;                              /* the open would drop the fd it holds */
    REPORT(reac_capture_open, reac_capture_open(&cap, ifname_of(name, in, 0)), rc_ == 0);
}

static void call_reac_capture_set_nonblock(payload in) {
    int nb = byte(in, 0) & 1;
    if (cap.fd < 0) return;
    if (!preqed_call("reac_capture_set_nonblock")) return;
    int rc = reac_capture_set_nonblock(&cap, nb);
    preqed_result("reac_capture_set_nonblock", rc == 0);
    if (rc == 0) cap_blocking = !nb;
}

static void call_reac_capture_next(payload in) {
    uint8_t buf[2048];
    if (cap.fd < 0 || cap_blocking) return;               /* a blocking read with no writer thread never returns */
    REPORT(reac_capture_next, reac_capture_next(&cap, buf, 1 + byte(in, 0) % sizeof buf), rc_ >= 0);
}
/* ltl: capture_closed_before_reopen */
static void call_reac_capture_close(payload in) {
    (void)in;
    int fd = cap.fd;
    REPORT_VOID(reac_capture_close, reac_capture_close(&cap));
    if (fd >= 0 && fd == sock_end) sock[0] = sock_end = -1;
}

/* reac_packet_socket.h */
/* ltl: packet_socket_deaf_before_bind */
static void call_reac_packet_socket_deaf(payload in) {
    int flags = (byte(in, 0) & 1 ? SOCK_NONBLOCK : 0) | (byte(in, 0) & 2 ? SOCK_CLOEXEC : 0);
    if (pkt_fd >= 0) return;
    if (!preqed_call("reac_packet_socket_deaf")) return;
    pkt_fd = reac_packet_socket_deaf(flags);
    preqed_result("reac_packet_socket_deaf", pkt_fd >= 0);
}
/* ltl: packet_socket_deaf_before_bind */
static void call_reac_packet_socket_bind(payload in) {
    if (pkt_fd < 0) return;                               /* binds a deaf packet socket (reac_packet_socket.h) */
    REPORT(reac_packet_socket_bind,
           reac_packet_socket_bind(pkt_fd, byte(in, 0) % 4, byte(in, 1) & 1 ? REAC_ETHERTYPE : 0), rc_ == 0);
}

static void call_reac_packet_socket_bound(payload in) {
    if (!preqed_call("reac_packet_socket_bound")) return;
    int fd = reac_packet_socket_bound(byte(in, 0) % 4, byte(in, 1) & 1 ? REAC_ETHERTYPE : 0, SOCK_NONBLOCK);
    preqed_result("reac_packet_socket_bound", fd >= 0);
    if (fd >= 0) close(fd);
}

/* pcap_source.h */
/* ltl: pcap_source_open_before_next */
static void call_pcap_source_open(payload in) {
    char path[48];
    int fd = byte(in, 0) & 1 ? file_fd : pcap_fd;
    if (fd < 0 || psrc_valid) return;                    /* an open over an open source drops its FILE */
    if (!preqed_call("pcap_source_open")) return;
    int rc = pcap_source_open(&psrc, fd_path(path, sizeof path, fd));
    preqed_result("pcap_source_open", rc == 0);
    if (rc == 0) psrc_valid = 1;
}
/* ltl: pcap_source_open_before_next */
static void call_pcap_source_next(payload in) {
    uint64_t ts = 0;
    if (!psrc_valid) return;
    REPORT(pcap_source_next,
           pcap_source_next(&psrc, bytes, byte(in, 0) & 1 ? (size_t)byte(in, 1) : sizeof bytes,
                            byte(in, 2) & 1 ? NULL : &ts), rc_ >= 0);
    bytes_len = 0;                                         /* the buffer holds a record now, of unknown length */
}
/* ltl: pcap_source_open_before_next */
static void call_pcap_source_close(payload in) {
    (void)in;
    if (!psrc_valid) return;
    REPORT_VOID(pcap_source_close, pcap_source_close(&psrc));
    psrc_valid = 0;
}

/* reac_carrier.h, reac_mac.h, reac_ifname.h */

static void call_reac_link_carrier(payload in) {
    char name[24];
    REPORT(reac_link_carrier, reac_link_carrier(ifname_of(name, in, 0)), rc_ >= 0);
}

static void call_reac_mac_default_src(payload in) {
    char name[24];
    uint8_t out[6];
    REPORT(reac_mac_default_src, reac_mac_default_src(byte(in, 0) == 0xff ? NULL : ifname_of(name, in, 0), out), rc_ == 0);   /* NULL: reac_mac.h */
}

static void call_reac_ifname_bus_addr(payload in) {
    char name[24], addr[REAC_IFNAME_ADDR_MAX];
    enum reac_ifname_bus kind;
    REPORT(reac_ifname_bus_addr,
           reac_ifname_bus_addr(NULL, ifname_of(name, in, 1), &kind, addr, 1 + byte(in, 0) % sizeof addr), rc_ == 0);
}

static void call_reac_ifname_rank(payload in) {
    static const char *const addrs[] = { "0000:83:00.0", "0000:02:00.0", "4-2", "4-1", "1-1.3", "0000:83:00.1" };
    char self[24];
    int n = byte(in, 0) % 7;
    REPORT(reac_ifname_rank, reac_ifname_rank(addrs, n, byte(in, 1) & 1 ? addrs[byte(in, 2) % 6] : cstr(self, sizeof self, rest(in, 3))), rc_ > 0);
}

static void call_reac_ifname_derive(payload in) {
    char name[24], out[32];
    REPORT(reac_ifname_derive,
           reac_ifname_derive((enum reac_ifname_bus)(byte(in, 0) % 4), (int)byte(in, 1) - 2, ifname_of(name, in, 3),
                              out, 1 + byte(in, 2) % sizeof out), rc_ >= 0);
}

/* reac_tx.h */

static void call_reac_eth_crc32(payload in) {
    REPORT_VOID(reac_eth_crc32, (void)reac_eth_crc32(byte(in, 0) & 1 ? bytes : in.p, byte(in, 0) & 1 ? bytes_len : in.n));
}
/* ltl: tx_open_before_emit */
static void call_reac_tx_open(payload in) {
    char name[24];
    if (tx.handle) return;                                /* the open would drop the handle it holds */
    REPORT(reac_tx_open, reac_tx_open(&tx, ifname_of(name, in, 0)), rc_ == 0);
}
/* ltl: tx_open_before_emit */
static void call_reac_tx_emit(payload in) {
    int n_src = 0;
    float *const *pl = planes_from(in, &n_src);
    if (!tx.handle) return;
    REPORT(reac_tx_emit, reac_tx_emit(&tx, pl, n_src, (int)(byte(in, 1) % (REAC_SAMPLES_PER_PKT + 1))), rc_ > 0);
}
/* ltl: tx_open_before_emit */
static void call_reac_tx_close(payload in) {
    (void)in;
    REPORT_VOID(reac_tx_close, reac_tx_close(&tx));
}

/* reac_ring.h */
/* ltl: ring_init_before_use */
static void call_reac_ring_init(payload in) {
    if (ring_valid) return;                               /* init would drop the allocated buffer */
    if (!preqed_call("reac_ring_init")) return;
    int rc = reac_ring_init(&ring, byte(in, 0) % (REAC_MAX_CHANNELS + 2), (uint32_t)(byte(in, 1) | (byte(in, 2) & 0x0f) << 8));
    preqed_result("reac_ring_init", rc == 0);
    if (rc == 0) ring_valid = 1;
}
/* ltl: ring_init_before_use */
static void call_reac_ring_free(payload in) {
    (void)in;
    if (!ring_valid) return;
    REPORT_VOID(reac_ring_free, reac_ring_free(&ring));
    ring_valid = 0;
}
/* ltl: ring_init_before_use */
static void call_reac_ring_readable(payload in) {
    (void)in;
    if (!ring_valid) return;
    REPORT_VOID(reac_ring_readable, (void)reac_ring_readable(&ring));
}
/* ltl: ring_init_before_use */
static void call_reac_ring_writable(payload in) {
    (void)in;
    if (!ring_valid) return;
    REPORT_VOID(reac_ring_writable, (void)reac_ring_writable(&ring));
}
/* ltl: ring_init_before_use */
static void call_reac_ring_write(payload in) {
    uint32_t n = byte(in, 0) % 65, src = byte(in, 1) % (REAC_MAX_CHANNELS + 2);
    if (!ring_valid) return;
    for (size_t i = 0; i < sizeof flat / sizeof flat[0]; i++)
        flat[i] = (float)((int)byte(in, 2 + i % 64) - 128) / 128.0f;
    if (src * n > sizeof flat / sizeof flat[0]) src = (uint32_t)(sizeof flat / sizeof flat[0]) / (n ? n : 1);
    REPORT_VOID(reac_ring_write, (void)reac_ring_write(&ring, flat, n, src));
}
/* ltl: ring_init_before_use */
static void call_reac_ring_read_planar(payload in) {
    if (!ring_valid) return;
    for (int ch = 0; ch < REAC_MAX_CHANNELS; ch++)
        planes[ch] = plane[ch];
    REPORT_VOID(reac_ring_read_planar,
                (void)reac_ring_read_planar(&ring, planes, byte(in, 0) % (REAC_MAX_CHANNELS + 1), byte(in, 1) % (REAC_SAMPLES_PER_PKT + 1)));
}
/* ltl: ring_init_before_use */
static void call_reac_ring_trim(payload in) {
    if (!ring_valid) return;
    REPORT_VOID(reac_ring_trim, (void)reac_ring_trim(&ring, (uint32_t)(byte(in, 0) | byte(in, 1) << 8)));
}

/* reac_pacer.h: the frame ring and the pure helpers */
/* ltl: frame_ring_init_before_use */
static void call_reac_frame_ring_init(payload in) {
    if (fring_valid) return;                              /* init memsets the ring over its buffers */
    if (!preqed_call("reac_frame_ring_init")) return;
    int rc = reac_frame_ring_init(&fring, byte(in, 0), 1 + (uint32_t)(byte(in, 1) | (byte(in, 2) & 0x0f) << 8) % sizeof popbuf);
    preqed_result("reac_frame_ring_init", rc == 0);
    if (rc == 0) fring_valid = 1;
}
/* ltl: frame_ring_init_before_use */
static void call_reac_frame_ring_free(payload in) {
    (void)in;
    if (!fring_valid) return;
    REPORT_VOID(reac_frame_ring_free, reac_frame_ring_free(&fring));
    fring_valid = 0;
}
/* ltl: frame_ring_init_before_use */
static void call_reac_frame_ring_push(payload in) {
    payload f = byte(in, 0) & 1 ? (payload){ bytes, bytes_len } : rest(in, 1);
    if (!fring_valid) return;
    REPORT_VOID(reac_frame_ring_push, (void)reac_frame_ring_push(&fring, f.p, (uint16_t)f.n));
}
/* ltl: frame_ring_init_before_use */
static void call_reac_frame_ring_pop(payload in) {
    (void)in;
    if (!fring_valid) return;
    REPORT_VOID(reac_frame_ring_pop, (void)reac_frame_ring_pop(&fring, popbuf));
}
/* ltl: frame_ring_init_before_use */
static void call_reac_frame_ring_readable(payload in) {
    (void)in;
    if (!fring_valid) return;
    REPORT_VOID(reac_frame_ring_readable, (void)reac_frame_ring_readable(&fring));
}
/* ltl: frame_ring_init_before_use */
static void call_reac_frame_ring_trim(payload in) {
    if (!fring_valid) return;
    REPORT_VOID(reac_frame_ring_trim, (void)reac_frame_ring_trim(&fring, byte(in, 0), byte(in, 1)));
}

static void call_reac_frame_ring_trim_count(payload in) {
    REPORT_VOID(reac_frame_ring_trim_count,
                (void)reac_frame_ring_trim_count((uint32_t)(byte(in, 0) | byte(in, 1) << 8),
                                                 (uint32_t)(byte(in, 2) | byte(in, 3) << 8),
                                                 (uint32_t)(byte(in, 4) | byte(in, 5) << 8)));
}

static void call_reac_pacer_tunables_set(payload in) {
    static const unsigned floor[] = { 0, 95, 96, 512, 4096, 4097 };
    struct reac_pacer_tunables t = { floor[byte(in, 0) % 6], byte(in, 1) & 1 };
    REPORT_VOID(reac_pacer_tunables_set, reac_pacer_tunables_set(&t));
}

static void call_reac_pacer_guard_floor(payload in) {
    (void)in;
    REPORT(reac_pacer_guard_floor, (int)reac_pacer_guard_floor(), rc_ > 0);
}

static void call_reac_pacer_guard_high(payload in) {
    REPORT_VOID(reac_pacer_guard_high, (void)reac_pacer_guard_high((uint32_t)(byte(in, 0) | byte(in, 1) << 8)));
}

static void call_reac_discard_watch_step(payload in) {
    double fps = 0;
    uint64_t now = advance(in, 0);
    REPORT_VOID(reac_discard_watch_step,
                (void)reac_discard_watch_step(&dwatch, now, (uint64_t)byte(in, 3) * byte(in, 4), &fps));
}

static void call_reac_pacer_period_ns(payload in) {
    REPORT(reac_pacer_period_ns, (int)(reac_pacer_period_ns((int)(byte(in, 0) | byte(in, 1) << 8) - 8) > 0), rc_);
}

static void call_reac_catchup_default_slots(payload in) {
    REPORT(reac_catchup_default_slots, (int)reac_catchup_default_slots((int)(byte(in, 0) | byte(in, 1) << 8) - 8), rc_ >= 1);
}

static void call_reac_clock_label_set(payload in) {
    char name[40];
    REPORT(reac_clock_label_set, reac_clock_label_set(&clabel, cstr(name, sizeof name, in)), rc_ >= 0);
}

static void call_reac_clock_label_get(payload in) {
    char out[REAC_CLOCK_LABEL_MAX + 4];
    REPORT(reac_clock_label_get, reac_clock_label_get(&clabel, out, 1 + byte(in, 0) % sizeof out), rc_ == 1);
}

static void call_reac_pacer_backend_name(payload in) {
    REPORT(reac_pacer_backend_name, reac_pacer_backend_name((enum reac_pacer_backend)(byte(in, 0) % 3)) != NULL, rc_);
}

static void call_reac_pacer_backend_resolve(payload in) {
    char name[24];
    enum reac_conf_layer layer;
    int understood = 1;
    if (!preqed_call("reac_pacer_backend_resolve")) return;
    reac_pacer_backend_resolve(byte(in, 0) & 1 ? NULL : ifname_of(name, in, 1), byte(in, 0) & 2 ? "/nonexistent" : NULL,
                               byte(in, 0) & 4 ? NULL : &layer, byte(in, 0) & 8 ? NULL : &understood);
    preqed_result("reac_pacer_backend_resolve", understood);
}

static void call_reac_pacer_lead_us_resolve(payload in) {
    char name[24];
    enum reac_conf_layer layer;
    int understood = 1;
    if (!preqed_call("reac_pacer_lead_us_resolve")) return;
    reac_pacer_lead_us_resolve(byte(in, 0) & 1 ? NULL : ifname_of(name, in, 1), byte(in, 0) & 2 ? "/nonexistent" : NULL,
                               byte(in, 0) & 4 ? NULL : &layer, byte(in, 0) & 8 ? NULL : &understood);
    preqed_result("reac_pacer_lead_us_resolve", understood);
}

static void call_reac_pacer_mono_ns(payload in) {
    (void)in;
    REPORT(reac_pacer_mono_ns, reac_pacer_mono_ns() > 0, rc_);
}

/* reac_pacer.h: the pacer. reac_pacer_open needs CAP_NET_RAW; without it the harness builds the
   pacer by hand the way reac-pw's offline test does (tests/test_reac_pacer.c "construct the
   pacer by hand (frame ring + master FSM only, fd = -1)") with the fields reac_pacer_open sets
   before its socket. The PACER-THREAD-ONLY calls are exposed for exactly that (reac_pacer.h). */

static void call_use_offline_pacer(payload in) {
    static const int fps[] = { 3675, 4000, 8000 };
    uint8_t src[6];
    if (pacer_valid || pacer_running) return;
    mac_of(in, 1, src);
    memset(&pacer, 0, sizeof pacer);
    atomic_store(&pacer.recognized_headamp_base, -1);
    pacer.fps = fps[byte(in, 0) % 3];
    pacer.period_ns = reac_pacer_period_ns(pacer.fps);
    pacer.catchup_max_slots = reac_catchup_default_slots(pacer.fps);
    pacer.prev_state = REAC_M_IDLE;
    pacer.drivable_mask = byte(in, 7) & 7 ? byte(in, 7) & 7 : REAC_RATE_ALL_BITS;
    atomic_store(&pacer.rate_hz, pacer.fps * REAC_SAMPLES_PER_PKT);
    pacer.clock_follow = byte(in, 8) & 1;
    pacer.slot_period_ns = pacer.period_ns;
    reac_clock_disc_init(&pacer.clock, REAC_ROLE_MASTER, pacer.period_ns);
    atomic_store(&pacer.ring_depth_min, UINT32_MAX);
    memcpy(pacer.src, src, 6);
    struct reac_console_cfg ccfg = REAC_CONSOLE_CFG_IDLE;
    ccfg.console_field = reac_pace_code(pacer.fps);
    reac_master_init(&pacer.master, pacer.src, &ccfg, pacer.fps);
    reac_headamp_tx_init(&pacer.headamp);
    reac_master_set_headamp_src(&pacer.master, &pacer.headamp);
    if (reac_frame_ring_init(&pacer.ring, (uint32_t)pacer.fps / 4, REAC_PACER_SLOT_SZ) != 0) return;
    pacer_valid = 1;
}
/* ltl: pacer_started_after_open */
static void call_reac_pacer_open(payload in) {
    char name[24];
    uint8_t src[6];
    struct reac_pacer_cfg cfg;
    static const int fps[] = { 3675, 4000, 8000 };       /* the slot cadences (reac_pacer_cfg) */
    if (pacer_valid || pacer_running) return;             /* open memsets the pacer: close it first */
    memset(&cfg, 0, sizeof cfg);
    mac_of(in, 2, src);
    cfg.ifname = ifname_of(name, in, 0);
    cfg.fps = fps[byte(in, 1) % 3];
    cfg.cpu = -1;
    cfg.src_mac = byte(in, 8) & 1 ? NULL : src;
    cfg.clock_follow = byte(in, 8) >> 1 & 1;
    cfg.catchup_max_slots = (int)(byte(in, 9) % 6) - 1;
    if (!preqed_call("reac_pacer_open")) return;
    int rc = reac_pacer_open(&pacer, &cfg);
    preqed_result("reac_pacer_open", rc == 0);
    if (rc == 0) pacer_valid = pacer_open_ok = 1;
}
/* ltl: pacer_started_after_open */
static void call_reac_pacer_start(payload in) {
    (void)in;
    if (!pacer_open_ok || pacer_running) return;          /* the thread sends on the opened socket */
    if (!preqed_call("reac_pacer_start")) return;
    int rc = reac_pacer_start(&pacer);
    preqed_result("reac_pacer_start", rc == 0);
    if (rc == 0) pacer_running = 1;
}
/* ltl: pacer_started_after_open */
static void call_reac_pacer_stop(payload in) {
    (void)in;
    if (!pacer_valid) return;
    REPORT_VOID(reac_pacer_stop, reac_pacer_stop(&pacer));
    pacer_running = 0;
}
/* ltl: pacer_started_after_open */
static void call_reac_pacer_close(payload in) {
    (void)in;
    if (!pacer_valid || pacer_running) return;
    REPORT_VOID(reac_pacer_close, reac_pacer_close(&pacer));
    pacer_valid = pacer_open_ok = 0;
}

static void call_reac_pacer_submit(payload in) {
    payload f = byte(in, 0) & 1 ? (payload){ bytes, bytes_len } : rest(in, 1);
    if (!pacer_valid) return;
    REPORT_VOID(reac_pacer_submit, (void)reac_pacer_submit(&pacer, f.p, (uint16_t)f.n));
}
/* ltl: pacer_started_after_open */
static void call_reac_pacer_rx_ingest(payload in) {
    (void)in;
    if (!pacer_valid || pacer_running) return;            /* PACER THREAD ONLY (reac_pacer.h) */
    REPORT_VOID(reac_pacer_rx_ingest, reac_pacer_rx_ingest(&pacer, bytes, bytes_len));
}

static void call_reac_pacer_read_identity(payload in) {
    struct reac_identity id;
    (void)in;
    if (!pacer_valid) return;
    REPORT_VOID(reac_pacer_read_identity, reac_pacer_read_identity(&pacer, &id));
}

static void call_reac_pacer_box_mac48(payload in) {
    (void)in;
    if (!pacer_valid) return;
    REPORT_VOID(reac_pacer_box_mac48, (void)reac_pacer_box_mac48(&pacer));
}

static void call_reac_pacer_log_drain(payload in) {
    char *buf = NULL;
    size_t len = 0;
    (void)in;
    if (!pacer_valid) return;
    if (!preqed_call("reac_pacer_log_drain")) return;
    FILE *out = open_memstream(&buf, &len);
    if (!out) {
        preqed_result("reac_pacer_log_drain", 0);
        return;
    }
    int n = reac_pacer_log_drain(&pacer, out);
    fclose(out);
    free(buf);
    preqed_result("reac_pacer_log_drain", n >= 0);
}

static void call_reac_pacer_headamp_set(payload in) {
    if (!pacer_valid) return;
    REPORT_VOID(reac_pacer_headamp_set,
                (void)reac_pacer_headamp_set(&pacer, byte(in, 0), (uint8_t)(byte(in, 1) % 5), byte(in, 2)));
}
/* ltl: pacer_started_after_open */
static void call_reac_pacer_headamp_drain(payload in) {
    (void)in;
    if (!pacer_valid || pacer_running) return;            /* PACER THREAD ONLY */
    REPORT(reac_pacer_headamp_drain, reac_pacer_headamp_drain(&pacer), rc_ >= 0);
}

static void call_reac_pacer_request_rate(payload in) {
    static const int hz[] = { 44100, 48000, 96000 };
    if (!pacer_valid) return;
    REPORT_VOID(reac_pacer_request_rate, reac_pacer_request_rate(&pacer, hz[byte(in, 0) % 3]));
}

static void call_reac_pacer_request_reestablish(payload in) {
    static const int cause[] = { 0, REAC_PEV_CAUSE_LINK_UP, REAC_PEV_CAUSE_LINK_DOWN, REAC_PEV_CAUSE_RATE_CHANGE };
    if (!pacer_valid) return;
    REPORT_VOID(reac_pacer_request_reestablish, reac_pacer_request_reestablish(&pacer, cause[byte(in, 0) % 4]));
}
/* ltl: pacer_started_after_open */
static void call_reac_pacer_apply_rate(payload in) {
    static const int hz[] = { 44100, 48000, 96000 };     /* already accepted by reac_rate_cfg_decide */
    if (!pacer_valid || pacer_running) return;            /* PACER THREAD ONLY */
    REPORT(reac_pacer_apply_rate, reac_pacer_apply_rate(&pacer, hz[byte(in, 0) % 3]), rc_ > 0);
}
/* ltl: pacer_started_after_open */
static void call_reac_pacer_rate_drain(payload in) {
    (void)in;
    if (!pacer_valid || pacer_running) return;            /* PACER THREAD ONLY */
    REPORT(reac_pacer_rate_drain, reac_pacer_rate_drain(&pacer), rc_ >= 0);
}

static void call_reac_pacer_clock_publish(payload in) {
    char label[40];
    uint64_t now = advance(in, 4);
    if (!pacer_valid) return;
    REPORT_VOID(reac_pacer_clock_publish,
                reac_pacer_clock_publish(&pacer, (enum reac_clock_source)(byte(in, 0) % REAC_CLOCK_SRC_COUNT),
                                         byte(in, 1) & 1, ((int)byte(in, 2) - 128) * 100,
                                         byte(in, 1) & 2 ? NULL : cstr(label, sizeof label, rest(in, 8)),
                                         (enum reac_clock_quality)(byte(in, 3) % REAC_CLOCK_Q_COUNT), now));
}

static void call_reac_pacer_clock_publish_graph(payload in) {
    static const char *const names[] = { "api.alsa.0", "clock.system.monotonic", "RME Babyface Pro", "" };
    char ref[24];
    uint64_t now = advance(in, 4);
    if (!pacer_valid) return;
    REPORT_VOID(reac_pacer_clock_publish_graph,
                reac_pacer_clock_publish_graph(&pacer, byte(in, 0) & 4 ? NULL : names[byte(in, 0) % 4], byte(in, 1) & 1,
                                               1.0 + ((double)byte(in, 2) - 128) / 1e5, now,
                                               byte(in, 3) & 1 ? NULL : cstr(ref, sizeof ref, rest(in, 8))));
}
/* ltl: pacer_started_after_open */
static void call_reac_pacer_clock_tick(payload in) {
    uint64_t now = advance(in, 0);
    if (!pacer_valid || pacer_running) return;            /* PACER THREAD ONLY */
    REPORT(reac_pacer_clock_tick, (int)(reac_pacer_clock_tick(&pacer, now) > 0), rc_);
}

static void call_reac_pacer_pace_source(payload in) {
    (void)in;
    if (!pacer_valid) return;
    REPORT_VOID(reac_pacer_pace_source, (void)reac_pacer_pace_source(&pacer));
}

static void call_reac_pacer_backend(payload in) {
    (void)in;
    if (!pacer_valid) return;
    REPORT_VOID(reac_pacer_backend, (void)reac_pacer_backend(&pacer));
}

static void call_reac_pacer_backend_refusal(payload in) {
    (void)in;
    if (!pacer_valid) return;
    REPORT_VOID(reac_pacer_backend_refusal, (void)reac_pacer_backend_refusal(&pacer));
}

static void call_reac_pacer_health_poll(payload in) {
    struct reac_pacer_health h;
    uint64_t now = advance(in, 0);
    if (!pacer_valid) return;
    REPORT(reac_pacer_health_poll, reac_pacer_health_poll(&pacer, now, &h), rc_ >= 0);
}

/* reac_pace_watch.h */
/* ltl: pace_watch_init_before_use */
static void call_reac_pace_watch_init(payload in) {
    static const int rate[] = { 44100, 48000, 96000, 0 };
    if (!preqed_call("reac_pace_watch_init")) return;
    reac_pace_watch_init(&pwatch, rate[byte(in, 0) % 4]);
    preqed_result("reac_pace_watch_init", 1);
    pwatch_valid = 1;
}
/* ltl: pace_watch_init_before_use */
static void call_reac_pace_watch_reset(payload in) {
    if (!pwatch_valid) return;
    REPORT_VOID(reac_pace_watch_reset, reac_pace_watch_reset(&pwatch, advance(in, 0)));
}
/* ltl: pace_watch_init_before_use */
static void call_reac_pace_watch_frame(payload in) {
    /* a run of frames at one spacing: a verdict needs REAC_PACE_MIN_FRAMES in a 2 s window */
    unsigned count = 1 + (byte(in, 3) | (byte(in, 4) & 0x0f) << 8);
    if (!pwatch_valid) return;
    for (unsigned i = 0; i < count; i++) {
        uint64_t now = advance(in, 0);
        REPORT_VOID(reac_pace_watch_frame, (void)reac_pace_watch_frame(&pwatch, now));
    }
}
/* ltl: pace_watch_init_before_use */
static void call_reac_pace_watch_observed(payload in) {
    (void)in;
    if (!pwatch_valid) return;
    REPORT_VOID(reac_pace_watch_observed, (void)reac_pace_watch_observed(&pwatch));
}
/* ltl: pace_watch_init_before_use */
static void call_reac_pace_watch_configured(payload in) {
    (void)in;
    if (!pwatch_valid) return;
    REPORT_VOID(reac_pace_watch_configured, (void)reac_pace_watch_configured(&pwatch));
}

/* reac_role_swap.h */
/* ltl: role_swap_init_before_use */
static void call_reac_role_swap_init(payload in) {
    if (!preqed_call("reac_role_swap_init")) return;
    reac_role_swap_init(&rswap, (enum reac_role)(byte(in, 0) & 1));
    preqed_result("reac_role_swap_init", 1);
    rswap_valid = 1;
}
/* ltl: role_swap_init_before_use */
static void call_reac_role_swap_request(payload in) {
    if (!rswap_valid) return;
    REPORT_VOID(reac_role_swap_request, (void)reac_role_swap_request(&rswap, (enum reac_role)(byte(in, 0) & 1)));
}
/* ltl: role_swap_init_before_use */
static void call_reac_role_swap_opened(payload in) {
    if (!rswap_valid) return;
    REPORT_VOID(reac_role_swap_opened, reac_role_swap_opened(&rswap, (enum reac_role)(byte(in, 0) & 1)));
}
/* ltl: role_swap_init_before_use */
static void call_reac_role_swap_closed(payload in) {
    (void)in;
    if (!rswap_valid) return;
    REPORT_VOID(reac_role_swap_closed, reac_role_swap_closed(&rswap));
}
/* ltl: role_swap_init_before_use */
static void call_reac_role_swap_state(payload in) {
    if (!rswap_valid) return;
    REPORT(reac_role_swap_state, reac_role_swap_state(&rswap, (enum reac_role_engine)(byte(in, 0) % 3)) != NULL, rc_);
}

static void call_reac_role_engine_of_master(payload in) {
    REPORT_VOID(reac_role_engine_of_master,
                (void)reac_role_engine_of_master(byte(in, 0) & 1, (enum reac_master_state)(byte(in, 1) % 4)));
}

static void call_reac_role_engine_of_slave(payload in) {
    REPORT_VOID(reac_role_engine_of_slave, (void)reac_role_engine_of_slave(byte(in, 0) & 1, byte(in, 1) & 1));
}

static void call_reac_role_emits_headamp(payload in) {
    REPORT_VOID(reac_role_emits_headamp, (void)reac_role_emits_headamp((enum reac_role)(byte(in, 0) & 1)));
}

/* reac_rt.h */

static void call_reac_rt_prio_source_name(payload in) {
    REPORT(reac_rt_prio_source_name, reac_rt_prio_source_name((enum reac_rt_prio_source)(byte(in, 0) % 5)) != NULL, rc_);
}

static void call_reac_rt_prio_parse(payload in) {
    char text[16];
    enum reac_rt_prio_source src;
    REPORT(reac_rt_prio_parse, reac_rt_prio_parse(byte(in, 0) == 0xff ? NULL : cstr(text, sizeof text, rest(in, 1)), &src) > 0,
           rc_);   /* NULL value: reac_rt.h */
}

static void call_reac_rt_prio_preempts_audio(payload in) {
    REPORT_VOID(reac_rt_prio_preempts_audio, (void)reac_rt_prio_preempts_audio((int)byte(in, 0) - 8));
}

static void call_reac_rt_prio_resolve(payload in) {
    enum reac_rt_prio_source src;
    REPORT(reac_rt_prio_resolve,
           reac_rt_prio_resolve((int)byte(in, 0) % 100 - 1, byte(in, 1) & 1 ? "/nonexistent" : NULL, &src) > 0, rc_);
}

struct rt_go { int prio; enum reac_rt_prio_source src; int rc; };

static void *rt_go_thread(void *arg) {
    struct rt_go *g = arg;
    g->rc = reac_rt_thread_go("reac_fuzz", g->prio, g->src);
    return NULL;
}

static void call_reac_rt_thread_go(payload in) {
    /* it re-schedules the CALLING thread, which is a wire-clock thread in the library
       (reac_pacer.c, reac_slave.c), never the fuzzer's own loop */
    struct rt_go g = { 1 + byte(in, 0) % 99, (enum reac_rt_prio_source)(byte(in, 1) % 4), -1 };
    pthread_t t;
    if (!preqed_call("reac_rt_thread_go")) return;
    if (pthread_create(&t, NULL, rt_go_thread, &g) == 0) pthread_join(t, NULL);
    preqed_result("reac_rt_thread_go", g.rc == 0);
}

/* reac_conf.h, reac_tunables.h */

static void call_reac_conf_layer_name(payload in) {
    REPORT(reac_conf_layer_name, reac_conf_layer_name((enum reac_conf_layer)(byte(in, 0) % 8)) != NULL, rc_);
}

static void call_reac_conf_lookup(payload in) {
    static const char *const keys[] = { "REACPW_PACER", "REACPW_RT_PRIO", "REAC_RATE", "REAC_ROLE", "HOME" };
    char seg[24], out[64];
    REPORT_VOID(reac_conf_lookup,
                (void)reac_conf_lookup(keys[byte(in, 0) % 5], byte(in, 1) & 1 ? NULL : ifname_of(seg, in, 3),
                                       byte(in, 1) & 2 ? "/nonexistent" : NULL, out, 1 + byte(in, 2) % sizeof out));
}

static void call_reac_conf_read_file(payload in) {
    static const char *const keys[] = { "REACPW_PACER", "REACPW_RT_PRIO", "REAC_RATE", "A", "" };
    char path[48], key[24], out[64];
    if (file_fd < 0) return;
    const char *k = byte(in, 0) & 0x80 ? cstr(key, sizeof key, rest(in, 2)) : keys[byte(in, 0) % 5];
    REPORT(reac_conf_read_file,
           reac_conf_read_file(fd_path(path, sizeof path, file_fd), k, out, 1 + byte(in, 1) % sizeof out), rc_ == 1);
}

static void call_reac_transport_tunables_set(payload in) {
    char allow[32];
    struct reac_transport_tunables t = { byte(in, 0) & 1 ? NULL : cstr(allow, sizeof allow, rest(in, 1)), byte(in, 0) >> 1 & 1 };   /* NULL allow_wireless: reac_tunables.h */
    REPORT_VOID(reac_transport_tunables_set, reac_transport_tunables_set(&t));
}

/* reac_seglock.h */
/* ltl: seglock_released_before_reclaim */
static void call_reac_seglock_init(payload in) {
    (void)in;
    if (reac_seglock_held(&seglock)) return;              /* init forgets a held claim without releasing it */
    if (!preqed_call("reac_seglock_init")) return;
    reac_seglock_init(&seglock);
    preqed_result("reac_seglock_init", 1);
}
/* ltl: seglock_released_before_reclaim */
static void call_reac_seglock_claim(payload in) {
    char name[24];
    if (reac_seglock_held(&seglock)) return;              /* claim re-inits the lock first (reac_seglock.c) */
    REPORT(reac_seglock_claim, reac_seglock_claim(&seglock, ifname_of(name, in, 0)), rc_ == 0);
}

static void call_reac_seglock_held(payload in) {
    (void)in;
    REPORT_VOID(reac_seglock_held, (void)reac_seglock_held(&seglock));
}
/* ltl: seglock_released_before_reclaim */
static void call_reac_seglock_release(payload in) {
    (void)in;
    REPORT_VOID(reac_seglock_release, reac_seglock_release(&seglock));
}

/* reac_segment_ident.h */

static void call_reac_segment_name(payload in) {
    char inst[24];
    REPORT(reac_segment_name, reac_segment_name(byte(in, 0) & 1 ? NULL : cstr(inst, sizeof inst, rest(in, 1))) != NULL, rc_);
}
/* ltl: segment_heard_init_before_step */
static void call_reac_segment_heard_init(payload in) {
    if (!preqed_call("reac_segment_heard_init")) return;
    reac_segment_heard_init(&heard, (uint64_t)byte(in, 0) << 8 | byte(in, 1));
    preqed_result("reac_segment_heard_init", 1);
    heard_valid = 1;
}
/* ltl: segment_heard_init_before_step */
static void call_reac_segment_heard_step(payload in) {
    if (!heard_valid) return;
    REPORT_VOID(reac_segment_heard_step,
                (void)reac_segment_heard_step(&heard, (uint64_t)byte(in, 0) << 8 | byte(in, 1),
                                              byte(in, 2) & 1 ? REAC_SEGMENT_HEARD_QUIET_TICKS : (int)byte(in, 3) % 30));
}

static uint64_t mac48_of(payload in, size_t i) {
    uint8_t mac[6];
    mac_of(in, i, mac);
    return byte(in, i + 6) & 1 ? 0 : reac_mac48_pack(mac);
}

static void call_reac_segment_answer_slave(payload in) {
    struct reac_segment_answer a;
    REPORT_VOID(reac_segment_answer_slave,
                reac_segment_answer_slave(&a, byte(in, 0) & 1, mac48_of(in, 1), (int)byte(in, 8) * 1000 - 1000, byte(in, 9) % 48));
}

static void call_reac_segment_answer_slave_kind(payload in) {
    struct reac_segment_answer a;
    REPORT_VOID(reac_segment_answer_slave_kind,
                reac_segment_answer_slave_kind(&a, byte(in, 0) & 1, mac48_of(in, 1), (int)byte(in, 8) * 1000 - 1000,
                                               (enum reac_rival_kind)(byte(in, 9) % 5)));
}

static void call_reac_segment_answer_refused(payload in) {
    struct reac_segment_answer a;
    REPORT_VOID(reac_segment_answer_refused,
                reac_segment_answer_refused(&a, byte(in, 0) % 48, mac48_of(in, 1), (int)byte(in, 8) * 1000 - 1000));
}

static void call_reac_segment_answer_refused_kind(payload in) {
    struct reac_segment_answer a;
    REPORT_VOID(reac_segment_answer_refused_kind,
                reac_segment_answer_refused_kind(&a, (enum reac_rival_kind)(byte(in, 0) % 5), mac48_of(in, 1),
                                                 (int)byte(in, 8) * 1000 - 1000));
}

/* reac_slave.h */

static void slave_cfg_of(payload in, struct reac_slave_cfg *cfg, char *name, uint8_t src[6]) {
    memset(cfg, 0, sizeof *cfg);
    mac_of(in, 2, src);
    cfg->ifname = ifname_of(name, in, 0);
    cfg->box_channels = (int)byte(in, 1) % 48;
    cfg->sample_rate = 48000;
    cfg->src_mac = byte(in, 8) & 1 ? NULL : src;
    cfg->box_master = byte(in, 8) >> 1 & 1;
    cfg->box_master_frame_box = byte(in, 8) >> 2 & 1;
    cfg->box_master_burst_chanmap = byte(in, 8) >> 3 & 1;
    cfg->box_master_fill_noise = byte(in, 8) >> 4 & 1;
    cfg->tag = byte(in, 8) & 0x20 ? NULL : "[fz] ";
    cfg->model = byte(in, 8) & 0x40 ? catalogue_at(in) : NULL;
}
/* ltl: slave_init_before_step */
static void call_reac_slave_fsm_init(payload in) {
    struct reac_slave_cfg cfg;
    char name[24];
    uint8_t src[6];
    if (slave_running) return;
    slave_cfg_of(in, &cfg, name, src);
    if (slave_open_ok) return;                            /* the init drops the open handle: close first */
    if (!preqed_call("reac_slave_fsm_init")) return;
    reac_slave_fsm_init(&slave, &cfg);
    preqed_result("reac_slave_fsm_init", 1);
    slave_valid = 1;
}
/* ltl: slave_init_before_step */
static void call_reac_slave_open(payload in) {
    struct reac_slave_cfg cfg;
    char name[24];
    uint8_t src[6];
    if (slave_running || slave_open_ok) return;
    slave_cfg_of(in, &cfg, name, src);
    if (!preqed_call("reac_slave_open")) return;
    int rc = reac_slave_open(&slave, &cfg, ring_valid && byte(in, 9) & 1 ? &ring : NULL);
    preqed_result("reac_slave_open", rc == 0);
    if (rc == 0) slave_valid = slave_open_ok = 1;
}
/* ltl: slave_init_before_step */
static void call_reac_slave_start(payload in) {
    (void)in;
    if (!slave_open_ok || slave_running) return;
    if (!preqed_call("reac_slave_start")) return;
    int rc = reac_slave_start(&slave);
    preqed_result("reac_slave_start", rc == 0);
    if (rc == 0) slave_running = 1;
}
/* ltl: slave_init_before_step */
static void call_reac_slave_set_phy_up(payload in) {
    if (!slave_valid) return;
    REPORT_VOID(reac_slave_set_phy_up, reac_slave_set_phy_up(&slave, byte(in, 0) & 1));
}
/* ltl: slave_init_before_step */
static void call_reac_slave_stop(payload in) {
    (void)in;
    if (!slave_valid) return;
    REPORT_VOID(reac_slave_stop, reac_slave_stop(&slave));
    slave_running = 0;
}
/* ltl: slave_init_before_step */
static void call_reac_slave_close(payload in) {
    (void)in;
    if (!slave_valid || slave_running) return;
    REPORT_VOID(reac_slave_close, reac_slave_close(&slave));
    slave_open_ok = 0;
}
/* ltl: slave_init_before_step */
static void call_reac_slave_step_rx(payload in) {
    (void)in;
    if (!slave_valid || slave_running || !parsed_valid) return;   /* the engine thread owns the FSM */
    REPORT_VOID(reac_slave_step_rx, (void)reac_slave_step_rx(&slave, &parsed));
}
/* ltl: slave_init_before_step */
static void call_reac_slave_step_tick(payload in) {
    (void)in;
    if (!slave_valid || slave_running) return;
    REPORT_VOID(reac_slave_step_tick, (void)reac_slave_step_tick(&slave));
}
/* ltl: slave_init_before_step */
static void call_reac_slave_step_phy(payload in) {
    if (!slave_valid || slave_running) return;
    REPORT_VOID(reac_slave_step_phy, (void)reac_slave_step_phy(&slave, byte(in, 0) & 1));
}

static void call_reac_slave_headamp_gain(payload in) {
    REPORT_VOID(reac_slave_headamp_gain, (void)reac_slave_headamp_gain(byte(in, 0), byte(in, 1) & 1));
}
/* ltl: slave_init_before_step */
static void call_reac_slave_headamp_rx(payload in) {
    struct reac_ctrl_parsed p;
    (void)in;
    if (!slave_valid || slave_running) return;
    /* a head-amp record the caller has record-checksum-verified (reac_slave.h) */
    if (bytes_len < REAC_CTRL_BLOCK_END || reac_ctrl_parse(bytes, bytes_len, &p) == REAC_CTRL_NONE ||
        reac_ctrl_headamp_record_verify(bytes) != 0)
        return;
    REPORT(reac_slave_headamp_rx, reac_slave_headamp_rx(&slave, &p), rc_ >= 0);
}

static void call_reac_slave_apply_input_gain(payload in) {
    int n_src = 0;
    float *const *pl = planes_from(in, &n_src);
    if (!slave_valid) return;
    REPORT_VOID(reac_slave_apply_input_gain,
                reac_slave_apply_input_gain(pl, n_src, (int)(byte(in, 1) % (REAC_SAMPLES_PER_PKT + 1)), slave.ha_gain));
}

/* reac_tap.h: the survey (pure) and the tap (pcap replay of the harness-built pcap) */
/* ltl: tap_survey_init_before_use */
static void call_reac_tap_survey_init(payload in) {
    (void)in;
    if (!preqed_call("reac_tap_survey_init")) return;
    reac_tap_survey_init(&survey);
    preqed_result("reac_tap_survey_init", 1);
    survey_valid = 1;
}
/* ltl: tap_survey_init_before_use */
static void call_reac_tap_survey_set_self(payload in) {
    uint8_t mac[6];
    mac_of(in, 1, mac);
    if (!survey_valid) return;
    REPORT_VOID(reac_tap_survey_set_self, reac_tap_survey_set_self(&survey, byte(in, 0) & 1 ? NULL : mac));
}
/* ltl: tap_survey_init_before_use */
static void call_reac_tap_survey_frame(payload in) {
    if (!survey_valid) return;
    uint64_t ts = byte(in, 3) & 1 ? 0 : advance(in, 0) / 1000;
    REPORT(reac_tap_survey_frame, reac_tap_survey_frame(&survey, bytes, bytes_len, ts), rc_ >= 0);
}
/* ltl: tap_survey_init_before_use */
static void call_reac_tap_survey_rate(payload in) {
    (void)in;
    if (!survey_valid) return;
    REPORT(reac_tap_survey_rate, reac_tap_survey_rate(&survey), rc_ > 0);
}
/* ltl: tap_survey_init_before_use */
static void call_reac_tap_survey_resolve(payload in) {
    if (!survey_valid) return;
    REPORT_VOID(reac_tap_survey_resolve, (void)reac_tap_survey_resolve(&survey, advance(in, 0) / 1000));
}
/* ltl: tap_survey_init_before_use */
static void call_reac_tap_survey_master(payload in) {
    (void)in;
    if (!survey_valid) return;
    REPORT(reac_tap_survey_master, reac_tap_survey_master(&survey) != NULL, rc_);
}
/* ltl: tap_survey_init_before_use */
static void call_reac_tap_survey_box(payload in) {
    uint8_t mac[6];
    mac_of(in, 0, mac);
    if (!survey_valid) return;
    REPORT(reac_tap_survey_box, reac_tap_survey_box(&survey, byte(in, 6) & 1 && bytes_len >= 12 ? bytes + 6 : mac) != NULL, rc_);
}
/* ltl: tap_opened_before_serve */
static void call_reac_tap_open(payload in) {
    uint8_t self[6];
    struct reac_tap_cfg cfg;
    if (tap_valid) return;
    mac_of(in, 3, self);
    memset(&cfg, 0, sizeof cfg);
    cfg.kind = byte(in, 0) & 1 ? REAC_RX_LIVE : REAC_RX_PCAP;
    if (cfg.kind == REAC_RX_PCAP && pcap_fd < 0) return;
    cfg.source = cfg.kind == REAC_RX_PCAP ? fd_path(tap_source, sizeof tap_source, pcap_fd) : ifname_of(tap_source, in, 1);
    cfg.forced_rate = byte(in, 0) & 2 ? 48000 : 0;
    cfg.survey_ms = 1 + byte(in, 2) % 4;                  /* LIVE only; the open fails first without CAP_NET_RAW */
    cfg.survey_frames = byte(in, 2);
    cfg.self_mac = byte(in, 0) & 4 ? self : NULL;
    if (!preqed_call("reac_tap_open")) return;
    int rc = reac_tap_open(&tap, &cfg);
    preqed_result("reac_tap_open", rc == 0);
    if (rc == 0) tap_valid = 1;
}
/* ltl: tap_opened_before_serve */
static void call_reac_tap_stream_count(payload in) {
    (void)in;
    if (!tap_valid) return;
    REPORT_VOID(reac_tap_stream_count, (void)reac_tap_stream_count(&tap));
}
/* ltl: tap_opened_before_serve */
static void call_reac_tap_stream_at(payload in) {
    if (!tap_valid) return;
    REPORT(reac_tap_stream_at, reac_tap_stream_at(&tap, byte(in, 0) % (REAC_TAP_MAX_STREAMS + 1)) != NULL, rc_);
}
/* ltl: tap_opened_before_serve */
static void call_reac_tap_ring_at(payload in) {
    if (!tap_valid) return;
    if (!preqed_call("reac_tap_ring_at")) return;
    struct reac_ring *r = reac_tap_ring_at(&tap, byte(in, 0) % (REAC_TAP_MAX_STREAMS + 1));
    preqed_result("reac_tap_ring_at", r != NULL);
    if (r) (void)reac_ring_readable(r);                    /* the consumer side reads what the feeder wrote */
}
/* ltl: tap_opened_before_serve */
static void call_reac_tap_start(payload in) {
    (void)in;
    if (!tap_valid) return;
    REPORT(reac_tap_start, reac_tap_start(&tap), rc_ == 0);
}
/* ltl: tap_opened_before_serve */
static void call_reac_tap_stop(payload in) {
    (void)in;
    if (!tap_valid) return;
    REPORT_VOID(reac_tap_stop, reac_tap_stop(&tap));
}
/* ltl: tap_opened_before_serve */
static void call_reac_tap_close(payload in) {
    (void)in;
    if (!tap_valid) return;
    REPORT_VOID(reac_tap_close, reac_tap_close(&tap));
    tap_valid = 0;
}

/* reac_rx.h */

static void call_reac_rx_iface_present(payload in) {
    char name[24];
    REPORT_VOID(reac_rx_iface_present, (void)reac_rx_iface_present(ifname_of(name, in, 0)));
}

static void call_reac_rx_iface_index(payload in) {
    char name[24];
    REPORT_VOID(reac_rx_iface_index, (void)reac_rx_iface_index(ifname_of(name, in, 0)));
}

static void call_reac_rx_binding_lost(payload in) {
    REPORT_VOID(reac_rx_binding_lost, (void)reac_rx_binding_lost(byte(in, 0) % 4, byte(in, 1) % 4));
}
/* ltl: rx_opened_before_feed */
static void call_reac_rx_open(payload in) {
    static const int rate[] = { 0, 44100, 48000, 96000 };
    struct reac_rx_cfg cfg;
    if (rx_valid) return;                                 /* the open re-sizes the ring: close first */
    memset(&cfg, 0, sizeof cfg);
    cfg.kind = byte(in, 0) & 1 ? REAC_RX_LIVE : REAC_RX_PCAP;
    if (cfg.kind == REAC_RX_PCAP && pcap_fd < 0) return;
    cfg.source = cfg.kind == REAC_RX_PCAP ? fd_path(rx_source, sizeof rx_source, pcap_fd) : ifname_of(rx_source, in, 2);
    cfg.forced_rate = rate[byte(in, 1) % 4];
    cfg.pcap_realtime = 0;                                /* flat out: the feeder never sleeps on record timestamps */
    cfg.accept = (enum reac_rx_accept)(byte(in, 0) >> 1 & 1);
    if (!preqed_call("reac_rx_open")) return;
    int rc = reac_rx_open(&rx, &cfg, &rx_ring);
    preqed_result("reac_rx_open", rc == 0);
    if (rc == 0) rx_valid = 1;
}
/* ltl: rx_opened_before_feed */
static void call_reac_rx_start(payload in) {
    (void)in;
    if (!rx_valid || rx_running) return;
    if (!preqed_call("reac_rx_start")) return;
    int rc = reac_rx_start(&rx);
    preqed_result("reac_rx_start", rc == 0);
    if (rc == 0) rx_running = 1;
}
/* ltl: rx_opened_before_feed */
static void call_reac_rx_stop(payload in) {
    (void)in;
    if (!rx_running) return;                              /* it joins the feeder thread */
    REPORT_VOID(reac_rx_stop, reac_rx_stop(&rx));
    rx_running = 0;
}
/* ltl: rx_opened_before_feed */
static void call_reac_rx_peer_reset(payload in) {
    uint8_t mac[6];
    mac_of(in, 0, mac);
    if (!rx_valid) return;
    REPORT_VOID(reac_rx_peer_reset, reac_rx_peer_reset(&rx, mac, byte(in, 6) % 4));
}
/* ltl: rx_opened_before_feed */
static void call_reac_rx_session_end(payload in) {
    (void)in;
    if (!rx_valid) return;
    REPORT_VOID(reac_rx_session_end, reac_rx_session_end(&rx));
}
/* ltl: rx_opened_before_feed */
static void call_reac_rx_close(payload in) {
    (void)in;
    if (!rx_valid || rx_running) return;
    REPORT_VOID(reac_rx_close, reac_rx_close(&rx));
    reac_ring_free(&rx_ring);                             /* the ring is freed by its owner (reac_rx.c) */
    rx_valid = 0;
}

/* reac_topo.h */

static const char *parent_of(char *dst, payload in, size_t i) {
    snprintf(dst, IFNAMSIZ, "eth%u", byte(in, i) % 10);   /* 10 names for 8 parent slots */
    return dst;
}

static void call_reac_topo_kind_name(payload in) {
    REPORT(reac_topo_kind_name, reac_topo_kind_name((enum reac_topo_kind)(byte(in, 0) % 5)) != NULL, rc_);
}

static void call_reac_topo_verb_name(payload in) {
    REPORT(reac_topo_verb_name, reac_topo_verb_name((enum reac_topo_verb)(byte(in, 0) % 4)) != NULL, rc_);
}

static void call_reac_topo_classify(payload in) {
    uint16_t vid = 0;
    REPORT_VOID(reac_topo_classify,
                (void)reac_topo_classify(bytes, bytes_len, byte(in, 0) & 1, (uint16_t)(byte(in, 1) | byte(in, 2) << 8),
                                         byte(in, 0) & 2 ? NULL : &vid));
}
/* ltl: topo_init_before_use */
static void call_reac_topo_init(payload in) {
    (void)in;
    if (!preqed_call("reac_topo_init")) return;
    reac_topo_init(&topo);
    preqed_result("reac_topo_init", 1);
    topo_valid = 1;
}
/* ltl: topo_init_before_use */
static void call_reac_topo_watch(payload in) {
    char p[IFNAMSIZ];
    if (!topo_valid) return;
    REPORT(reac_topo_watch, reac_topo_watch(&topo, parent_of(p, in, 0)), rc_ == 0);
}
/* ltl: topo_init_before_use */
static void call_reac_topo_unwatch(payload in) {
    char p[IFNAMSIZ];
    if (!topo_valid) return;
    REPORT_VOID(reac_topo_unwatch, reac_topo_unwatch(&topo, parent_of(p, in, 0), advance(in, 1)));
}
/* ltl: topo_init_before_use */
static void call_reac_topo_saw(payload in) {
    char p[IFNAMSIZ];
    if (!topo_valid) return;
    REPORT_VOID(reac_topo_saw, reac_topo_saw(&topo, parent_of(p, in, 0), (enum reac_topo_kind)(byte(in, 1) % 4),
                                             (uint16_t)(byte(in, 2) % 24), advance(in, 3)));
}
/* ltl: topo_init_before_use */
static void call_reac_topo_ensured(payload in) {
    char p[IFNAMSIZ];
    if (!topo_valid) return;
    REPORT_VOID(reac_topo_ensured, reac_topo_ensured(&topo, parent_of(p, in, 0), (uint16_t)(byte(in, 1) % 24), byte(in, 2) & 1));
}
/* ltl: topo_init_before_use */
static void call_reac_topo_ensure_failed(payload in) {
    char p[IFNAMSIZ];
    if (!topo_valid) return;
    REPORT_VOID(reac_topo_ensure_failed, reac_topo_ensure_failed(&topo, parent_of(p, in, 0), (uint16_t)(byte(in, 1) % 24), advance(in, 2)));
}
/* ltl: topo_init_before_use */
static void call_reac_topo_tick(payload in) {
    if (!topo_valid) return;
    REPORT_VOID(reac_topo_tick, reac_topo_tick(&topo, advance(in, 0)));
}
/* ltl: topo_init_before_use */
static void call_reac_topo_release_all(payload in) {
    (void)in;
    if (!topo_valid) return;
    REPORT_VOID(reac_topo_release_all, reac_topo_release_all(&topo));
}
/* ltl: topo_init_before_use */
static void call_reac_topo_next(payload in) {
    struct reac_topo_event ev;
    (void)in;
    if (!topo_valid) return;
    REPORT(reac_topo_next, reac_topo_next(&topo, &ev), rc_ >= 0);
}
/* ltl: topo_init_before_use */
static void call_reac_topo_find(payload in) {
    char p[IFNAMSIZ];
    if (!topo_valid) return;
    REPORT(reac_topo_find, reac_topo_find(&topo, parent_of(p, in, 0)) != NULL, rc_);
}
/* ltl: topo_init_before_use */
static void call_reac_topo_vlan_find(payload in) {
    char p[IFNAMSIZ];
    if (!topo_valid) return;
    REPORT(reac_topo_vlan_find, reac_topo_vlan_find(&topo, parent_of(p, in, 0), (uint16_t)(byte(in, 1) % 24)) != NULL, rc_);
}
/* ltl: topo_init_before_use */
static void call_reac_topo_is_trunk(payload in) {
    char p[IFNAMSIZ];
    if (!topo_valid) return;
    REPORT_VOID(reac_topo_is_trunk, (void)reac_topo_is_trunk(&topo, parent_of(p, in, 0)));
}
/* ltl: topo_init_before_use */
static void call_reac_topo_untagged_on_trunk(payload in) {
    char p[IFNAMSIZ];
    if (!topo_valid) return;
    REPORT_VOID(reac_topo_untagged_on_trunk, (void)reac_topo_untagged_on_trunk(&topo, parent_of(p, in, 0)));
}
/* ltl: topo_init_before_use */
static void call_reac_topo_count(payload in) {
    char p[IFNAMSIZ];
    if (!topo_valid) return;
    REPORT(reac_topo_count, reac_topo_count(&topo, parent_of(p, in, 0), (enum reac_topo_vstate)(byte(in, 1) % 3)), rc_ >= 0);
}
/* ltl: topo_init_before_use */
static void call_reac_topo_heard_vids(payload in) {
    char p[IFNAMSIZ];
    uint16_t vids[REAC_TOPO_MAX_VLANS];
    if (!topo_valid) return;
    REPORT(reac_topo_heard_vids,
           reac_topo_heard_vids(&topo, parent_of(p, in, 0), byte(in, 1) & 1 ? NULL : vids, byte(in, 2) % (REAC_TOPO_MAX_VLANS + 1)),
           rc_ >= 0);
}

static void call_reac_topo_is_stacked(payload in) {
    char name[24];
    REPORT_VOID(reac_topo_is_stacked, (void)reac_topo_is_stacked(NULL, ifname_of(name, in, 0)));
}
/* ltl: topo_tap_open_before_read */
static void call_reac_topo_tap_open(payload in) {
    char name[24];
    if (ttap.handle) return;                              /* the open would drop the handle it holds */
    REPORT(reac_topo_tap_open, reac_topo_tap_open(&ttap, ifname_of(name, in, 0)), rc_ == 0);
}

static void call_reac_topo_tap_fd(payload in) {
    (void)in;
    REPORT_VOID(reac_topo_tap_fd, (void)reac_topo_tap_fd(&ttap));
}
/* ltl: topo_tap_open_before_read */
static void call_reac_topo_tap_read(payload in) {
    struct reac_topo_frame f;
    (void)in;
    if (!ttap.handle) return;
    REPORT(reac_topo_tap_read, reac_topo_tap_read(&ttap, &f), rc_ >= 0);
}
/* ltl: topo_tap_open_before_read */
static void call_reac_topo_tap_next(payload in) {
    enum reac_topo_kind kind;
    uint16_t vid;
    (void)in;
    if (!ttap.handle) return;
    REPORT(reac_topo_tap_next, reac_topo_tap_next(&ttap, &kind, &vid), rc_ >= 0);
}
/* ltl: topo_tap_open_before_read */
static void call_reac_topo_tap_close(payload in) {
    (void)in;
    REPORT_VOID(reac_topo_tap_close, reac_topo_tap_close(&ttap));
}

/* reac_vlan.h, reac_etf_qdisc.h: rtnetlink writers need CAP_NET_ADMIN */

static void call_reac_vlan_name(payload in) {
    char p[24], out[IFNAMSIZ + 8];
    REPORT(reac_vlan_name, reac_vlan_name(ifname_of(p, in, 3), (uint16_t)(byte(in, 0) | byte(in, 1) << 8), out, 1 + byte(in, 2) % sizeof out),
           rc_ == 0);
}

static void call_reac_vlan_query(payload in) {
    char name[24];
    int ours = 0;
    REPORT(reac_vlan_query, reac_vlan_query(ifname_of(name, in, 1), byte(in, 0) & 1 ? NULL : &ours), rc_ >= 0);
}
/* ltl: vlan_deleted_only_if_minted */
static void call_reac_vlan_create(payload in) {
    char parent[IFNAMSIZ];
    uint16_t vid = 1 + byte(in, 1) % 4094;
    own_ifname(parent, in, 0);
    if (!preqed_call("reac_vlan_create")) return;
    int rc = reac_vlan_create(parent, vid);
    preqed_result("reac_vlan_create", rc == 0);
    if (rc == 0 && reac_vlan_name(parent, vid, vlan_minted, sizeof vlan_minted) != 0) vlan_minted[0] = 0;
}

static void call_reac_vlan_up(payload in) {
    char name[IFNAMSIZ];
    REPORT(reac_vlan_up, reac_vlan_up(vlan_minted[0] && byte(in, 1) & 1 ? vlan_minted : own_ifname(name, in, 0)), rc_ == 0);
}

static void call_reac_link_admin(payload in) {
    char name[IFNAMSIZ];
    REPORT(reac_link_admin, reac_link_admin(vlan_minted[0] && byte(in, 1) & 1 ? vlan_minted : own_ifname(name, in, 0), byte(in, 2) & 1),
           rc_ == 0);
}
/* ltl: vlan_deleted_only_if_minted */
static void call_reac_vlan_delete(payload in) {
    (void)in;
    if (!vlan_minted[0]) return;                          /* only a netdev this process minted (reac_vlan.h) */
    REPORT(reac_vlan_delete, reac_vlan_delete(vlan_minted), rc_ == 0);
    vlan_minted[0] = 0;
}
/* ltl: etf_qdisc_removed_only_if_found */
static void call_reac_etf_qdisc_state(payload in) {
    char kind[16];
    int ifindex = 1 + byte(in, 0) % 4;
    if (!preqed_call("reac_etf_qdisc_state")) return;
    enum reac_etf_qdisc_state st = reac_etf_qdisc_state(ifindex, byte(in, 1) & 1 ? NULL : kind, 1 + byte(in, 2) % sizeof kind);
    preqed_result("reac_etf_qdisc_state", st != REAC_ETF_QDISC_UNREADABLE);
    if (st == REAC_ETF_QDISC_PRESENT) etf_present_ifindex = ifindex;
}

static void call_reac_etf_qdisc_stats_read(payload in) {
    struct reac_etf_qdisc_stats st;
    REPORT(reac_etf_qdisc_stats_read, reac_etf_qdisc_stats_read((int)(byte(in, 0) % 5), &st), rc_ == 0);
}

static void call_reac_etf_qdisc_install(payload in) {
    /* an ifindex past any the host or container has: the add is refused, never applied */
    REPORT(reac_etf_qdisc_install, reac_etf_qdisc_install(100000 + byte(in, 0), (uint32_t)(byte(in, 1) | byte(in, 2) << 8) * 16), rc_ == 0);
}
/* ltl: etf_qdisc_removed_only_if_found */
static void call_reac_etf_qdisc_remove(payload in) {
    (void)in;
    if (!etf_present_ifindex) return;                     /* removes only an etf the state read found (reac_etf_qdisc.h) */
    REPORT(reac_etf_qdisc_remove, reac_etf_qdisc_remove(etf_present_ifindex), rc_ == 0);
    etf_present_ifindex = 0;
}

static void call_reac_etf_qdisc_fix(payload in) {
    REPORT(reac_etf_qdisc_fix, reac_etf_qdisc_fix(-(int)byte(in, 0) % 128) != NULL, rc_);
}

static void call_reac_etf_qdisc_add_msg(payload in) {
    uint8_t buf[REAC_ETF_QDISC_ADD_LEN + 8] __attribute__((aligned(8)));
    REPORT(reac_etf_qdisc_add_msg,
           (int)reac_etf_qdisc_add_msg(buf, byte(in, 0) % sizeof buf, (int)byte(in, 1) - 1, (uint32_t)(byte(in, 2) | byte(in, 3) << 8) * 16,
                                       byte(in, 4)), rc_ > 0);
}

static void call_reac_etf_qdisc_del_msg(payload in) {
    uint8_t buf[REAC_ETF_QDISC_DEL_LEN + 8] __attribute__((aligned(8)));
    REPORT(reac_etf_qdisc_del_msg, (int)reac_etf_qdisc_del_msg(buf, byte(in, 0) % sizeof buf, (int)byte(in, 1) - 1, byte(in, 2)), rc_ > 0);
}

/* reac_ifscan.h */

static void call_reac_ifscan_state_name(payload in) {
    REPORT(reac_ifscan_state_name, reac_ifscan_state_name((enum reac_ifscan_state)(byte(in, 0) % 6)) != NULL, rc_);
}

static void call_reac_ifscan_verb_name(payload in) {
    REPORT(reac_ifscan_verb_name, reac_ifscan_verb_name((enum reac_ifscan_verb)(byte(in, 0) % 7)) != NULL, rc_);
}

static void call_reac_ifscan_is_wireless(payload in) {
    char name[24];
    REPORT_VOID(reac_ifscan_is_wireless, (void)reac_ifscan_is_wireless(NULL, ifname_of(name, in, 0)));
}

static void call_reac_ifscan_wireless_allowed(payload in) {
    static const char *const lists[] = { NULL, "", "*", "wlan0", "eth0,wlan0", "wlan0," };
    char name[24], list[32];
    const char *l = byte(in, 0) & 0x80 ? cstr(list, sizeof list, rest(in, 2)) : lists[byte(in, 0) % 6];
    REPORT_VOID(reac_ifscan_wireless_allowed, (void)reac_ifscan_wireless_allowed(l, ifname_of(name, in, 1)));
}
/* ltl: ifscan_init_before_use */
static void call_reac_ifscan_init(payload in) {
    (void)in;
    if (ifscan.handle) return;                            /* the init drops the open watch: close first */
    if (!preqed_call("reac_ifscan_init")) return;
    reac_ifscan_init(&ifscan);
    preqed_result("reac_ifscan_init", 1);
    ifscan_valid = 1;
}
/* ltl: ifscan_init_before_use */
static void call_reac_ifscan_open(payload in) {
    if (ifscan.handle) return;
    if (!preqed_call("reac_ifscan_open")) return;
    int rc = reac_ifscan_open(&ifscan, advance(in, 0));
    preqed_result("reac_ifscan_open", rc == 0);
    ifscan_valid = 1;                                     /* a failed open leaves the pure core initialised (reac_ifscan.h) */
}
/* ltl: ifscan_init_before_use */
static void call_reac_ifscan_close(payload in) {
    (void)in;
    if (!ifscan_valid) return;
    REPORT_VOID(reac_ifscan_close, reac_ifscan_close(&ifscan));
}
/* ltl: ifscan_init_before_use */
static void call_reac_ifscan_observe(payload in) {
    char name[24];
    if (!ifscan_valid) return;
    REPORT_VOID(reac_ifscan_observe, reac_ifscan_observe(&ifscan, parent_of(name, in, 0), 1 + byte(in, 1) % 20, byte(in, 2) & 1,
                                                         byte(in, 2) >> 1 & 1, advance(in, 3)));
}
/* ltl: ifscan_init_before_use */
static void call_reac_ifscan_gone(payload in) {
    char name[24];
    if (!ifscan_valid) return;
    REPORT_VOID(reac_ifscan_gone, reac_ifscan_gone(&ifscan, parent_of(name, in, 0), 1 + byte(in, 1) % 20, advance(in, 2)));
}
/* ltl: ifscan_init_before_use */
static void call_reac_ifscan_heard(payload in) {
    char name[24];
    if (!ifscan_valid) return;
    REPORT_VOID(reac_ifscan_heard, reac_ifscan_heard(&ifscan, parent_of(name, in, 0), advance(in, 1)));
}
/* ltl: ifscan_init_before_use */
static void call_reac_ifscan_serve_failed(payload in) {
    char name[24];
    if (!ifscan_valid) return;
    REPORT_VOID(reac_ifscan_serve_failed, reac_ifscan_serve_failed(&ifscan, parent_of(name, in, 0), advance(in, 1)));
}
/* ltl: ifscan_init_before_use */
static void call_reac_ifscan_tick(payload in) {
    if (!ifscan_valid) return;
    REPORT_VOID(reac_ifscan_tick, reac_ifscan_tick(&ifscan, advance(in, 0)));
}
/* ltl: ifscan_init_before_use */
static void call_reac_ifscan_next(payload in) {
    struct reac_ifscan_event ev;
    (void)in;
    if (!ifscan_valid) return;
    REPORT(reac_ifscan_next, reac_ifscan_next(&ifscan, &ev), rc_ >= 0);
}
/* ltl: ifscan_init_before_use */
static void call_reac_ifscan_find(payload in) {
    char name[24];
    if (!ifscan_valid) return;
    REPORT(reac_ifscan_find, reac_ifscan_find(&ifscan, parent_of(name, in, 0)) != NULL, rc_);
}
/* ltl: ifscan_init_before_use */
static void call_reac_ifscan_count(payload in) {
    if (!ifscan_valid) return;
    REPORT(reac_ifscan_count, reac_ifscan_count(&ifscan, (enum reac_ifscan_state)(byte(in, 0) % 5)), rc_ >= 0);
}
/* ltl: ifscan_init_before_use */
static void call_reac_ifscan_feed(payload in) {
    if (!ifscan_valid) return;
    REPORT_VOID(reac_ifscan_feed, reac_ifscan_feed(&ifscan, nlbuf, nl_len, advance(in, 0)));
}
/* ltl: ifscan_init_before_use */
static void call_reac_ifscan_fd(payload in) {
    (void)in;
    if (!ifscan_valid) return;
    REPORT_VOID(reac_ifscan_fd, (void)reac_ifscan_fd(&ifscan));
}
/* ltl: ifscan_init_before_use */
static void call_reac_ifscan_drain(payload in) {
    if (!ifscan_valid) return;
    REPORT_VOID(reac_ifscan_drain, reac_ifscan_drain(&ifscan, advance(in, 0)));
}
/* ltl: ifscan_init_before_use */
static void call_reac_ifscan_resync(payload in) {
    if (!ifscan_valid) return;
    REPORT(reac_ifscan_resync, reac_ifscan_resync(&ifscan, advance(in, 0)), rc_ == 0);
}

/* reac_linkmon.h */
/* ltl: linkmon_init_before_use */
static void call_reac_linkmon_init(payload in) {
    char name[24];
    if (linkmon.handle) return;                           /* the init drops the open watch: close first */
    if (!preqed_call("reac_linkmon_init")) return;
    reac_linkmon_init(&linkmon, ifname_of(name, in, 0));
    preqed_result("reac_linkmon_init", 1);
    linkmon_valid = 1;
}
/* ltl: linkmon_init_before_use */
static void call_reac_linkmon_open(payload in) {
    char name[24];
    if (linkmon.handle) return;
    if (!preqed_call("reac_linkmon_open")) return;
    int rc = reac_linkmon_open(&linkmon, ifname_of(name, in, 0));
    preqed_result("reac_linkmon_open", rc == 0);
    linkmon_valid = 1;                                    /* a failed open leaves it safe and inert (reac_linkmon.h) */
}
/* ltl: linkmon_init_before_use */
static void call_reac_linkmon_close(payload in) {
    (void)in;
    if (!linkmon_valid) return;
    REPORT_VOID(reac_linkmon_close, reac_linkmon_close(&linkmon));
}
/* ltl: linkmon_init_before_use */
static void call_reac_linkmon_fd(payload in) {
    (void)in;
    if (!linkmon_valid) return;
    REPORT_VOID(reac_linkmon_fd, (void)reac_linkmon_fd(&linkmon));
}
/* ltl: linkmon_init_before_use */
static void call_reac_linkmon_drain(payload in) {
    (void)in;
    if (!linkmon_valid) return;
    REPORT_VOID(reac_linkmon_drain, (void)reac_linkmon_drain(&linkmon));
}
/* ltl: linkmon_init_before_use */
static void call_reac_linkmon_resync(payload in) {
    (void)in;
    if (!linkmon_valid) return;
    REPORT(reac_linkmon_resync, reac_linkmon_resync(&linkmon), rc_ == 0);
}
/* ltl: linkmon_init_before_use */
static void call_reac_linkmon_observe(payload in) {
    char name[24];
    if (!linkmon_valid) return;
    REPORT_VOID(reac_linkmon_observe, reac_linkmon_observe(&linkmon, ifname_of(name, in, 1), (int)(byte(in, 0) % 3) - 1));
}
/* ltl: linkmon_init_before_use */
static void call_reac_linkmon_feed(payload in) {
    (void)in;
    if (!linkmon_valid) return;
    REPORT_VOID(reac_linkmon_feed, reac_linkmon_feed(&linkmon, nlbuf, nl_len));
}
/* ltl: linkmon_init_before_use */
static void call_reac_linkmon_take(payload in) {
    (void)in;
    if (!linkmon_valid) return;
    REPORT_VOID(reac_linkmon_take, (void)reac_linkmon_take(&linkmon));
}
/* ltl: linkmon_init_before_use */
static void call_reac_linkmon_carrier(payload in) {
    (void)in;
    if (!linkmon_valid) return;
    REPORT_VOID(reac_linkmon_carrier, (void)reac_linkmon_carrier(&linkmon));
}

/* cleanup of the transport state: threads first, then handles, rings and files */
static void transport_cleanup(void) {
    if (tap_valid) reac_tap_close(&tap);
    if (rx_running) reac_rx_stop(&rx);
    if (rx_valid) reac_ring_free(&rx_ring);
    if (pacer_valid) {
        reac_pacer_stop(&pacer);
        reac_pacer_close(&pacer);
    }
    if (slave_valid) {
        reac_slave_stop(&slave);
        reac_slave_close(&slave);
    }
    if (ring_valid) reac_ring_free(&ring);
    if (fring_valid) reac_frame_ring_free(&fring);
    if (psrc_valid) pcap_source_close(&psrc);
    if (cap.fd == sock_end) cap.fd = -1;                  /* the socketpair loop below closes it */
    reac_capture_close(&cap);
    reac_tx_close(&tx);
    reac_topo_tap_close(&ttap);
    reac_seglock_release(&seglock);
    if (ifscan_valid) reac_ifscan_close(&ifscan);
    if (linkmon_valid) reac_linkmon_close(&linkmon);
    if (pkt_fd >= 0) close(pkt_fd);
    pkt_fd = -1;
    for (int i = 0; i < 2; i++) {
        if (sock[i] >= 0) close(sock[i]);
        sock[i] = -1;
    }
    sock_end = fd_peer = -1;
    if (pcap_fd >= 0 && ftruncate(pcap_fd, 0) != 0) { close(pcap_fd); pcap_fd = -1; }
    if (file_fd >= 0 && ftruncate(file_fd, 0) != 0) { close(file_fd); file_fd = -1; }
    pcap_records = 0;
    nl_len = 0;
    memset(&dwatch, 0, sizeof dwatch);
    memset(&clabel, 0, sizeof clabel);
    ring_valid = fring_valid = pwatch_valid = rswap_valid = heard_valid = 0;
    slave_valid = slave_open_ok = slave_running = 0;
    survey_valid = tap_valid = topo_valid = ifscan_valid = linkmon_valid = 0;
    rx_valid = rx_running = psrc_valid = cap_blocking = 0;
    pacer_valid = pacer_open_ok = pacer_running = 0;
    vlan_minted[0] = 0;
    etf_present_ifindex = 0;
    struct reac_transport_tunables tt = REAC_TRANSPORT_TUNABLES_DEFAULT;
    struct reac_pacer_tunables pt = REAC_PACER_TUNABLES_DEFAULT;
    reac_transport_tunables_set(&tt);
    reac_pacer_tunables_set(&pt);
}

/* dispatch */

static void (*const api[])(payload) = {
    call_set_frame,
    call_reac_box_width_ok, call_reac_frame_is_master_downstream, call_reac_frame_channels,
    call_reac_mode_for, call_reac_pace_code, call_reac_rate_snap, call_reac_frame_is_reac,
    call_reac_frame_clean_len, call_reac_frame_counter, call_reac_counter_gap, call_reac_version,
    call_reac_frame_inspect, call_reac_decode, call_reac_decode_plain_le,
    call_reac_upstream_channels, call_reac_upstream_decode,
    call_reac_braid_encode, call_reac_downstream_build,
    call_reac_s24le_to_f32, call_reac_f32_to_s24le, call_reac_braid_pos,
    call_reac_envflag_parse, call_reac_envflag,
    call_reac_role_parse, call_reac_role_name, call_reac_role_intent_explicit_only,
    call_reac_role_intent_transmits, call_reac_role_intent_parse, call_reac_role_intent_name,
    call_reac_role_from_intent, call_reac_role_validate,
    call_reac_code_token, call_reac_code_emit,
    call_reac_clock_hierarchy, call_reac_clock_select, call_reac_clock_source_name,
    call_reac_clock_quality_name, call_reac_clock_quality_can_own, call_reac_clock_name_quality,
    call_reac_clock_name_is_designated, call_reac_clock_grade_name, call_reac_clock_select_graded,
    call_reac_clock_stability_name, call_reac_dll_init, call_reac_dll_update,
    call_reac_dll_period_ns, call_reac_dll_applied_ppm, call_reac_dll_resid_sigma,
    call_reac_dll_stability, call_reac_dll_stability_reset, call_reac_clock_quality_apply,
    call_reac_clock_state_name, call_reac_clock_disc_init, call_reac_clock_disc_set_quality,
    call_reac_clock_disc_quality, call_reac_clock_disc_update, call_reac_clock_disc_period_ns,
    call_reac_clock_disc_describe, call_reac_clock_describe, call_reac_clock_describe_full,
    call_reac_clock_ppm_from_rate_diff, call_reac_clock_name_is_hardware,
    call_reac_identity_init, call_reac_identity_ingest, call_reac_identity_fw_str,
    call_reac_identity_reac_ver_str,
    call_reac_ports_parse, call_reac_ports_unknown,
    call_reac_mac_compose, call_reac_mac_fallback, call_reac_mac_roland_standin,
    call_reac_mac48_pack, call_reac_mac48_unpack,
    call_reac_fsm_init, call_reac_fsm_step,
    call_reac_master_fsm_classify, call_reac_master_fsm_step,
    call_reac_mixer_profile_by_name, call_reac_mixer_profile_at, call_reac_mixer_resolve_rate,
    call_reac_master_tunables_set, call_reac_master_identity_answered, call_reac_master_init,
    call_reac_master_has_box, call_reac_master_set_box, call_reac_master_forget_box,
    call_reac_master_regrant, call_reac_master_set_headamp_src, call_reac_master_rx,
    call_reac_master_next, call_reac_master_stamp, call_reac_master_state_name,
    call_reac_master_rx_event_name, call_reac_master_drop_name, call_reac_master_grant_anchor,
    call_reac_hunt_verdict_name, call_reac_hunt_init, call_reac_hunt_pin,
    call_reac_hunt_silence_proven, call_reac_hunt_observe, call_reac_hunt_step,
    call_reac_hunt_role, call_reac_hunt_heard_anything,
    call_reac_knock_init, call_reac_knock_heard, call_reac_knock_step,
    call_reac_tapwait_binds,
    call_reac_rival_kind_of, call_reac_master_only_cadence_frames,
    call_reac_master_only_cadence_ns, call_reac_sender_kind, call_reac_rival_kind_from_channels,
    call_reac_rival_kind_name, call_reac_rival_refusal, call_reac_segment_refusal,
    call_reac_segment_master_name, call_reac_pace_source_name, call_reac_pace_from_clock,
    call_reac_arbitrate,
    call_reac_disco_role_name, call_reac_disco_classify, call_reac_disco_peer_lock_init,
    call_reac_disco_classify_on_segment, call_reac_disco_gate_init,
    call_reac_disco_gate_should_push, call_reac_disco_table_init,
    call_reac_disco_table_observe, call_reac_disco_table_age, call_reac_disco_table_json,
    call_reac_boxreg_init, call_reac_boxreg_find, call_reac_boxreg_add,
    call_reac_boxreg_declare, call_reac_boxreg_set_name,
    call_reac_box_family_of, call_reac_box_family_stem, call_reac_box_name,
    call_reac_box_catalogue_defect,
    call_reac_grant_alloc_fits, call_reac_grant_allocate, call_reac_grant_build_sweep,
    call_reac_grant_headamp_value,
    call_reac_headamp_pack, call_reac_headamp_unpack, call_reac_headamp_tx_init,
    call_reac_headamp_tx_set, call_reac_headamp_default, call_reac_headamp_tx_effective,
    call_reac_headamp_tx_arm_scene, call_reac_headamp_tx_set_resweep, call_reac_headamp_tx_next,
    call_reac_link_fill_descriptor, call_reac_link_desc_for, call_reac_link_slave_burst,
    call_reac_link_state_from_master, call_reac_link_state_name, call_reac_box_mac_publish,
    call_reac_box_master_identity_publish, call_reac_box_identity_publish,
    call_reac_ctrl_classify_box_frame,
    call_reac_ctrl_block_cksum_stamp, call_reac_ctrl_checksum_apply,
    call_reac_ctrl_checksum_verify, call_reac_ctrl_record_cksum_stamp,
    call_reac_ctrl_record_cksum_verify, call_reac_ctrl_build_scene_step,
    call_reac_ctrl_scene_set_mac, call_reac_ctrl_scene_build,
    call_reac_headamp_sens_cdb, call_reac_headamp_sens_value_cdb, call_reac_headamp_sens_db,
    call_reac_headamp_sens_value, call_reac_ctrl_kind_name, call_reac_ctrl_parse,
    call_reac_box_model_block, call_reac_box_model_upstream_width, call_reac_ctrl_build_as,
    call_reac_box_catalogue_by_token, call_reac_box_catalogue_by_width,
    call_reac_box_catalogue, call_reac_box_catalogue_match, call_reac_ctrl_box_frame_len,
    call_reac_ctrl_build_box_hb, call_reac_ctrl_build_upstream_filler,
    call_reac_ctrl_build_flood_filler, call_reac_box_pin_notice,
    call_reac_ctrl_build_config_announce, call_reac_ctrl_build_identity_first,
    call_reac_ctrl_build_identity_last, call_reac_ctrl_identity_poll_block,
    call_reac_ctrl_identity_fragment, call_reac_ctrl_identity_reply,
    call_reac_ctrl_build_coldconnect, call_reac_ctrl_build_config_announce_box_master,
    call_reac_ctrl_build_coldconnect_head, call_reac_ctrl_build_coldconnect_0013,
    call_reac_ctrl_build_coldconnect_0016, call_reac_ctrl_build_coldconnect_001a,
    call_reac_ctrl_build_headamp, call_reac_ctrl_stamp_headamp,
    call_reac_headamp_param_name, call_reac_ctrl_headamp_record_verify,
    call_reac_headamp_group_of, call_reac_headamp_record_carries,
    call_reac_ctrl_build_grant_sweep,
    call_set_pcap_header, call_add_pcap_record, call_set_file, call_push_wire_frame, call_set_netlink,
    call_reac_detect_rate_fd, call_use_socketpair_capture, call_reac_capture_open,
    call_reac_capture_set_nonblock, call_reac_capture_next, call_reac_capture_close,
    call_reac_packet_socket_deaf, call_reac_packet_socket_bind, call_reac_packet_socket_bound,
    call_pcap_source_open, call_pcap_source_next, call_pcap_source_close, call_reac_link_carrier,
    call_reac_mac_default_src, call_reac_ifname_bus_addr, call_reac_ifname_rank,
    call_reac_ifname_derive, call_reac_eth_crc32, call_reac_tx_open, call_reac_tx_emit,
    call_reac_tx_close, call_reac_ring_init, call_reac_ring_free, call_reac_ring_readable,
    call_reac_ring_writable, call_reac_ring_write, call_reac_ring_read_planar, call_reac_ring_trim,
    call_reac_frame_ring_init, call_reac_frame_ring_free, call_reac_frame_ring_push,
    call_reac_frame_ring_pop, call_reac_frame_ring_readable, call_reac_frame_ring_trim,
    call_reac_frame_ring_trim_count, call_reac_pacer_tunables_set, call_reac_pacer_guard_floor,
    call_reac_pacer_guard_high, call_reac_discard_watch_step, call_reac_pacer_period_ns,
    call_reac_catchup_default_slots, call_reac_clock_label_set, call_reac_clock_label_get,
    call_reac_pacer_backend_name, call_reac_pacer_backend_resolve, call_reac_pacer_lead_us_resolve,
    call_reac_pacer_mono_ns, call_use_offline_pacer, call_reac_pacer_open, call_reac_pacer_start,
    call_reac_pacer_stop, call_reac_pacer_close, call_reac_pacer_submit, call_reac_pacer_rx_ingest,
    call_reac_pacer_read_identity, call_reac_pacer_box_mac48, call_reac_pacer_log_drain,
    call_reac_pacer_headamp_set, call_reac_pacer_headamp_drain, call_reac_pacer_request_rate,
    call_reac_pacer_request_reestablish, call_reac_pacer_apply_rate, call_reac_pacer_rate_drain,
    call_reac_pacer_clock_publish, call_reac_pacer_clock_publish_graph, call_reac_pacer_clock_tick,
    call_reac_pacer_pace_source, call_reac_pacer_backend, call_reac_pacer_backend_refusal,
    call_reac_pacer_health_poll, call_reac_pace_watch_init, call_reac_pace_watch_reset,
    call_reac_pace_watch_frame, call_reac_pace_watch_observed, call_reac_pace_watch_configured,
    call_reac_role_swap_init, call_reac_role_swap_request, call_reac_role_swap_opened,
    call_reac_role_swap_closed, call_reac_role_swap_state, call_reac_role_engine_of_master,
    call_reac_role_engine_of_slave, call_reac_role_emits_headamp, call_reac_rt_prio_source_name,
    call_reac_rt_prio_parse, call_reac_rt_prio_preempts_audio, call_reac_rt_prio_resolve,
    call_reac_rt_thread_go, call_reac_conf_layer_name, call_reac_conf_lookup, call_reac_conf_read_file,
    call_reac_transport_tunables_set, call_reac_seglock_init, call_reac_seglock_claim,
    call_reac_seglock_held, call_reac_seglock_release, call_reac_segment_name,
    call_reac_segment_heard_init, call_reac_segment_heard_step, call_reac_segment_answer_slave,
    call_reac_segment_answer_slave_kind, call_reac_segment_answer_refused,
    call_reac_segment_answer_refused_kind, call_reac_slave_fsm_init, call_reac_slave_open,
    call_reac_slave_start, call_reac_slave_set_phy_up, call_reac_slave_stop, call_reac_slave_close,
    call_reac_slave_step_rx, call_reac_slave_step_tick, call_reac_slave_step_phy,
    call_reac_slave_headamp_gain, call_reac_slave_headamp_rx, call_reac_slave_apply_input_gain,
    call_reac_tap_survey_init, call_reac_tap_survey_set_self, call_reac_tap_survey_frame,
    call_reac_tap_survey_rate, call_reac_tap_survey_resolve, call_reac_tap_survey_master,
    call_reac_tap_survey_box, call_reac_tap_open, call_reac_tap_stream_count, call_reac_tap_stream_at,
    call_reac_tap_ring_at, call_reac_tap_start, call_reac_tap_stop, call_reac_tap_close,
    call_reac_rx_iface_present, call_reac_rx_iface_index, call_reac_rx_binding_lost, call_reac_rx_open,
    call_reac_rx_start, call_reac_rx_stop, call_reac_rx_peer_reset, call_reac_rx_session_end,
    call_reac_rx_close, call_reac_topo_kind_name, call_reac_topo_verb_name, call_reac_topo_classify,
    call_reac_topo_init, call_reac_topo_watch, call_reac_topo_unwatch, call_reac_topo_saw,
    call_reac_topo_ensured, call_reac_topo_ensure_failed, call_reac_topo_tick,
    call_reac_topo_release_all, call_reac_topo_next, call_reac_topo_find, call_reac_topo_vlan_find,
    call_reac_topo_is_trunk, call_reac_topo_untagged_on_trunk, call_reac_topo_count,
    call_reac_topo_heard_vids, call_reac_topo_is_stacked, call_reac_topo_tap_open,
    call_reac_topo_tap_fd, call_reac_topo_tap_read, call_reac_topo_tap_next, call_reac_topo_tap_close,
    call_reac_vlan_name, call_reac_vlan_query, call_reac_vlan_create, call_reac_vlan_up,
    call_reac_link_admin, call_reac_vlan_delete, call_reac_etf_qdisc_state,
    call_reac_etf_qdisc_stats_read, call_reac_etf_qdisc_install, call_reac_etf_qdisc_remove,
    call_reac_etf_qdisc_fix, call_reac_etf_qdisc_add_msg, call_reac_etf_qdisc_del_msg,
    call_reac_ifscan_state_name, call_reac_ifscan_verb_name, call_reac_ifscan_is_wireless,
    call_reac_ifscan_wireless_allowed, call_reac_ifscan_init, call_reac_ifscan_open,
    call_reac_ifscan_close, call_reac_ifscan_observe, call_reac_ifscan_gone, call_reac_ifscan_heard,
    call_reac_ifscan_serve_failed, call_reac_ifscan_tick, call_reac_ifscan_next, call_reac_ifscan_find,
    call_reac_ifscan_count, call_reac_ifscan_feed, call_reac_ifscan_fd, call_reac_ifscan_drain,
    call_reac_ifscan_resync, call_reac_linkmon_init, call_reac_linkmon_open, call_reac_linkmon_close,
    call_reac_linkmon_fd, call_reac_linkmon_drain, call_reac_linkmon_resync, call_reac_linkmon_observe,
    call_reac_linkmon_feed, call_reac_linkmon_take, call_reac_linkmon_carrier,
};

#define API_COUNT (sizeof api / sizeof api[0])

static void cleanup(void) {
    bytes_len = 0;
    scene_valid = 0;
    parsed_valid = 0;
    alloc_valid = 0;
    fsm_valid = master_valid = ident_valid = table_valid = lock_valid = gate_valid = 0;
    hunt_valid = knock_valid = dll_valid = disc_valid = hamptx_valid = boxreg_valid = 0;
    now_ns = 0;
    pin_buf[0] = 0;
    transport_cleanup();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    preqed_reset();
    size_t off = 0;
    while (size - off >= 4) {
        unsigned op = (unsigned)data[off] | (unsigned)data[off + 1] << 8;   /* more than 256 APIs */
        size_t len = (size_t)data[off + 2] | (size_t)data[off + 3] << 8;
        off += 4;
        if (len > size - off) break;
        payload in = { data + off, len };
        api[op % API_COUNT](in);
        off += len;
    }
    cleanup();
    return 0;
}
