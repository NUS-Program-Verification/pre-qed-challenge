#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <cgif.h>
#include "preqed_ltl.h"

#define GIF_PATH "cgif-harness.gif"
/* frame width/height 1..64: large enough for multi-row LZW, small enough for ~1k exec/s under ASan */
#define MAX_DIM 64

typedef struct {
    const uint8_t *p;
    size_t n;
} payload;

static CGIF *gif;
static CGIFrgb *rgb;
static uint16_t gif_w, gif_h, rgb_w, rgb_h;

/* palettes: up to 256 RGB entries; image: MAX_DIM^2 pixels of up to 4 channels (RGBA) */
static uint8_t global_palette[256 * 3];
static uint8_t local_palette[256 * 3];
static uint8_t image[MAX_DIM * MAX_DIM * 4];
static size_t written;

static uint8_t byte(payload in, size_t i) { return i < in.n ? in.p[i] : 0; }
static payload rest(payload in, size_t skip) {
    payload r = { in.p + (skip < in.n ? skip : in.n), in.n > skip ? in.n - skip : 0 };
    return r;
}
static uint16_t dim(uint8_t b) { return 1 + b % MAX_DIM; }
static void fill(uint8_t *dst, size_t len, payload src) {
    for (size_t i = 0; i < len; i++) dst[i] = src.n ? src.p[i % src.n] : 0;
}

static int write_cb(void *ctx, const uint8_t *data, size_t n) {
    (void)ctx;
    (void)data;
    written += n;
    return 0;
}

#define REPORT(api, expr, ok_cond) \
    do { if (preqed_call(#api)) { int rc = (expr); preqed_result(#api, (ok_cond)); } } while (0)

/* index-based API */

/* byte 0: one bit per CGIF_ATTR_ and CGIF_GEN_ flag, bit 5 = write to GIF_PATH instead of the callback;
   bytes 1-2 width/height, 3 loop count, 4 palette size 1..256, rest palette RGB */
/* ltl: gif_lifecycle */
static void call_cgif_newgif(payload in) {
    if (gif) return;
    uint8_t flags = byte(in, 0);
    CGIF_Config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.width = gif_w = dim(byte(in, 1));
    cfg.height = gif_h = dim(byte(in, 2));
    cfg.attrFlags = (flags & 1 ? CGIF_ATTR_IS_ANIMATED : 0) | (flags & 2 ? CGIF_ATTR_NO_GLOBAL_TABLE : 0) |
                    (flags & 4 ? CGIF_ATTR_HAS_TRANSPARENCY : 0) | (flags & 8 ? CGIF_ATTR_NO_LOOP : 0);
    cfg.genFlags = flags & 16 ? CGIF_GEN_KEEP_IDENT_FRAMES : 0;
    cfg.numLoops = byte(in, 3);
    cfg.numGlobalPaletteEntries = 1 + byte(in, 4);
    fill(global_palette, cfg.numGlobalPaletteEntries * 3, rest(in, 5));
    cfg.pGlobalPalette = global_palette;
    if (flags & 32) cfg.path = GIF_PATH;
    else cfg.pWriteFn = write_cb;
    if (!preqed_call("cgif_newgif")) return;
    gif = cgif_newgif(&cfg);
    preqed_result("cgif_newgif", gif != NULL);
}

/* byte 0: frame attr/gen flag bits; 1 delay (1/100 s), 2 transparent index, 3 local palette size 1..256;
   the rest fills the local palette and the pixel indices (out-of-range indices are cgif's to reject) */
/* ltl: gif_lifecycle */
static void call_cgif_addframe(payload in) {
    if (!gif) return;
    uint8_t flags = byte(in, 0);
    CGIF_FrameConfig cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.attrFlags = (flags & 1 ? CGIF_FRAME_ATTR_USE_LOCAL_TABLE : 0) | (flags & 2 ? CGIF_FRAME_ATTR_HAS_ALPHA : 0) |
                    (flags & 4 ? CGIF_FRAME_ATTR_HAS_SET_TRANS : 0) | (flags & 8 ? CGIF_FRAME_ATTR_INTERLACED : 0);
    cfg.genFlags = (flags & 16 ? CGIF_FRAME_GEN_USE_TRANSPARENCY : 0) | (flags & 32 ? CGIF_FRAME_GEN_USE_DIFF_WINDOW : 0);
    cfg.delay = byte(in, 1);
    cfg.transIndex = byte(in, 2);
    cfg.numLocalPaletteEntries = 1 + byte(in, 3);
    fill(local_palette, cfg.numLocalPaletteEntries * 3, rest(in, 4));
    cfg.pLocalPalette = local_palette;
    fill(image, (size_t)gif_w * gif_h, rest(in, 4));
    cfg.pImageData = image;
    REPORT(cgif_addframe, cgif_addframe(gif, &cfg), rc == CGIF_OK);
}
/* ltl: gif_lifecycle */
static void call_cgif_close(payload in) {
    (void)in;
    if (!gif) return;
    REPORT(cgif_close, cgif_close(gif), rc == CGIF_OK);
    gif = NULL;
}

/* RGB API */
/* ltl: rgb_gif_lifecycle */
static void call_cgif_rgb_newgif(payload in) {
    if (rgb) return;
    uint8_t flags = byte(in, 0);
    CGIFrgb_Config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.width = rgb_w = dim(byte(in, 1));
    cfg.height = rgb_h = dim(byte(in, 2));
    cfg.attrFlags = (flags & 1 ? CGIF_ATTR_IS_ANIMATED : 0) | (flags & 8 ? CGIF_ATTR_NO_LOOP : 0);
    cfg.numLoops = byte(in, 3);
    if (flags & 32) cfg.path = GIF_PATH;
    else cfg.pWriteFn = write_cb;
    if (!preqed_call("cgif_rgb_newgif")) return;
    rgb = cgif_rgb_newgif(&cfg);
    preqed_result("cgif_rgb_newgif", rgb != NULL);
}

/* byte 0: bit 0 RGBA (else RGB), bits 1-2 frame attr flags; byte 1 delay; rest = pixel data */
/* ltl: rgb_gif_lifecycle */
static void call_cgif_rgb_addframe(payload in) {
    if (!rgb) return;
    uint8_t flags = byte(in, 0);
    CGIFrgb_FrameConfig cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.fmtChan = flags & 1 ? CGIF_CHAN_FMT_RGBA : CGIF_CHAN_FMT_RGB;
    cfg.attrFlags = (flags & 2 ? CGIF_RGB_FRAME_ATTR_INTERLACED : 0) | (flags & 4 ? CGIF_RGB_FRAME_ATTR_NO_DITHERING : 0);
    cfg.delay = byte(in, 1);
    fill(image, (size_t)rgb_w * rgb_h * cfg.fmtChan, rest(in, 2));
    cfg.pImageData = image;
    REPORT(cgif_rgb_addframe, cgif_rgb_addframe(rgb, &cfg), rc == CGIF_OK);
}
/* ltl: rgb_gif_lifecycle */
static void call_cgif_rgb_close(payload in) {
    (void)in;
    if (!rgb) return;
    REPORT(cgif_rgb_close, cgif_rgb_close(rgb), rc == CGIF_OK);
    rgb = NULL;
}

/* dispatch */

static void (*const api[])(payload) = {
    call_cgif_newgif, call_cgif_addframe, call_cgif_close,
    call_cgif_rgb_newgif, call_cgif_rgb_addframe, call_cgif_rgb_close,
};

#define API_COUNT (sizeof api / sizeof api[0])

static void cleanup(void) {
    if (gif) cgif_close(gif);
    if (rgb) cgif_rgb_close(rgb);
    gif = NULL;
    rgb = NULL;
    written = 0;
    unlink(GIF_PATH);
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
