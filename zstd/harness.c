/* the experimental ("static linking only") sections of zstd.h and zdict.h are part of the API under test */
#define ZSTD_STATIC_LINKING_ONLY
#define ZDICT_STATIC_LINKING_ONLY
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zstd.h>
#include <zstd_errors.h>
#include <zdict.h>
#include "preqed_ltl.h"

/* 1 MiB output buffers: more than ZSTD_compressBound of the largest (64 KiB) input */
#define OUT_CAP (1 << 20)

typedef struct {
    const uint8_t *p;
    size_t n;
} payload;

static ZSTD_CCtx *cctx;
static ZSTD_DCtx *dctx;
static ZSTD_CDict *cdict;
static ZSTD_DDict *ddict;
static int cctx_uses_cdict, dctx_uses_ddict;   /* ctx holds a reference to the dict object */
static int c_streaming;                        /* a streaming frame is open on cctx */
static int c_failed;                           /* a streaming call failed; ZSTD_CCtx_reset is required before streaming again */
static int c_inited;                           /* a ZSTD_initCStream* variant succeeded on cctx: precondition of ZSTD_resetCStream */
static int c_begun;                            /* buffer-less session open on cctx: 1 = ZSTD_compressBegin*, 2 = begun with the CDict */
static int d_begun;                            /* ZSTD_decompressBegin on dctx and no other decompression since: block API precondition */
/* object emplaced in a caller-owned workspace by ZSTD_initStatic*(): it has no free function (zstd.h Note 2) */
static int cctx_static, dctx_static, cdict_static, ddict_static;
static void *cctx_ws, *dctx_ws, *cdict_ws, *ddict_ws;   /* those workspaces; malloc'ed so ASan checks their bounds */
/* heap copies of dictionaries handed over by reference (ZSTD_dlm_byRef): zstd.h requires the buffer to outlive the
 * object and stay unmodified, so each copy is released only after the object that references it */
static unsigned char *cctx_dict_ref, *dctx_dict_ref, *cdict_ref, *ddict_ref;
static ZSTD_CCtx_params *cparams;
static ZSTD_threadPool *pool;
static int cctx_uses_pool;                     /* cctx was given the pool; it may keep using it until it is freed */

static unsigned char compressed[OUT_CAP];
static size_t compressed_len;
static unsigned char decompressed[OUT_CAP];
static unsigned char scratch[OUT_CAP];
/* 64 KiB dictionary, from the payload or ZDICT_trainFromBuffer; stays put while a CDict/DDict references it */
static unsigned char dict_buf[1 << 16];
static size_t dict_len;
/* Each context needs its own prefix, unchanged until its frame ends. */
static unsigned char cprefix[1 << 12], dprefix[1 << 12];
static size_t prefix_len;
static int d_streaming; /* incomplete or failed decompression frame */
/* repeated payload: makes inputs long and redundant enough to reach the match finders */
static unsigned char expanded[1 << 16];
/* buffer-less compression (zstd.h: "prior input is still accessible and unmodified"): the session's dictionary and
 * every input block are kept here, contiguous, until the next ZSTD_compressBegin*; 256 KiB = two maximum blocks */
static unsigned char bl_dict[1 << 16];
static unsigned char bl_src[1 << 18];
static size_t bl_src_len;
/* block-level decompression: regenerated blocks stay contiguous here, they are the history of the next block */
static unsigned char blocks[1 << 18];
static size_t blocks_len;
/* last ZSTD_generateSequences() result and the source and level it was generated from */
static ZSTD_Sequence *seqs;
static size_t seq_count;
static int seq_merged;                         /* ZSTD_mergeBlockDelimiters removed the block delimiters */
static int seq_level;
static unsigned char seq_src[1 << 16];
static size_t seq_src_len;
static int producer_mode;                      /* state of the registered sequence producer, see producer() */

static uint8_t byte(payload in, size_t i) { return i < in.n ? in.p[i] : 0; }
static payload rest(payload in, size_t skip) {
    payload r = { in.p + (skip < in.n ? skip : in.n), in.n > skip ? in.n - skip : 0 };
    return r;
}
/* compression level -3..19: negative = fast levels, 0 = default, 19 = ZSTD_maxCLevel() without ultra */
static int level(uint8_t b) { return (int)b % 23 - 3; }
/* byte 0 bit 0: repeat the rest of the payload 1..32 times (byte 0 / 8) up to sizeof expanded */
static payload expand(payload in) {
    payload body = rest(in, 1);
    if (!body.n || !(byte(in, 0) & 1)) return body;
    size_t total = body.n * (1 + byte(in, 0) / 8);
    if (total > sizeof expanded) total = sizeof expanded;
    for (size_t i = 0; i < total; i++) expanded[i] = body.p[i % body.n];
    payload r = { expanded, total };
    return r;
}
/* decompressor input: byte 0 bit 1 picks the last compressed output, otherwise the payload */
static payload compressed_or(payload in) {
    if (byte(in, 0) & 2) {
        payload c = { compressed, compressed_len };
        return c;
    }
    return rest(in, 1);
}
/* dictionary: byte 0 bit 2 picks dict_buf, otherwise the payload (raw-content dictionary) */
static payload dict_or(payload in) {
    if (byte(in, 0) & 4 && dict_len) {
        payload d = { dict_buf, dict_len };
        return d;
    }
    return rest(in, 1);
}
static ZSTD_EndDirective end_directive(uint8_t b) {
    static const ZSTD_EndDirective d[] = { ZSTD_e_continue, ZSTD_e_flush, ZSTD_e_end };
    return d[b % 3];
}
static ZSTD_ResetDirective reset_directive(uint8_t b) {
    static const ZSTD_ResetDirective d[] = { ZSTD_reset_session_only, ZSTD_reset_parameters, ZSTD_reset_session_and_parameters };
    return d[b % 3];
}
static ZSTD_cParameter c_param(uint8_t b) {
    /* every stable ZSTD_c_* parameter (zstd.h); values come from the payload, out-of-bound ones are rejected by the library */
    static const ZSTD_cParameter p[] = {
        ZSTD_c_compressionLevel, ZSTD_c_windowLog, ZSTD_c_hashLog, ZSTD_c_chainLog, ZSTD_c_searchLog,
        ZSTD_c_minMatch, ZSTD_c_targetLength, ZSTD_c_strategy, ZSTD_c_targetCBlockSize,
        ZSTD_c_enableLongDistanceMatching, ZSTD_c_ldmHashLog, ZSTD_c_ldmMinMatch, ZSTD_c_ldmBucketSizeLog,
        ZSTD_c_ldmHashRateLog, ZSTD_c_contentSizeFlag, ZSTD_c_checksumFlag, ZSTD_c_dictIDFlag,
        ZSTD_c_nbWorkers, ZSTD_c_jobSize, ZSTD_c_overlapLog,
        /* experimental: frame format (ZSTD_f_zstd1_magicless pairs with ZSTD_DCtx_setFormat) */
        ZSTD_c_format,
    };
    return p[b % (sizeof p / sizeof p[0])];
}
/* parameter value: payload bytes 1..2 as int16; out-of-bound values are rejected by the library */
static int c_value(ZSTD_cParameter p, payload in) {
    int value = (int)(int16_t)(byte(in, 1) | byte(in, 2) << 8);
    /* 0..2 worker threads: reaches the multi-threaded paths without spawning many threads per run */
    if (p == ZSTD_c_nbWorkers) return (uint8_t)value % 3;
    /* logs 21..31 are valid but size tables and windows up to several GiB; libFuzzer's malloc limit is 2 GiB */
    if ((p == ZSTD_c_windowLog || p == ZSTD_c_hashLog || p == ZSTD_c_chainLog || p == ZSTD_c_ldmHashLog) && value > 20 && value <= 31)
        return 20;
    return value;
}
/* compression parameters of a level, sized for the largest harness input (sizeof expanded) */
static ZSTD_compressionParameters level_cparams(uint8_t b) { return ZSTD_getCParams(level(b), sizeof expanded, 0); }
/* compression parameters taken verbatim from 8 payload bytes: any value, valid or not */
static ZSTD_compressionParameters raw_cparams(payload in) {
    ZSTD_compressionParameters p = { byte(in, 0), byte(in, 1), byte(in, 2), byte(in, 3), byte(in, 4),
                                     byte(in, 5) | (unsigned)byte(in, 6) << 8, (ZSTD_strategy)byte(in, 7) };
    return p;
}
/* valid compression parameters: byte 0 bit 0 picks the payload values clamped by ZSTD_adjustCParams ("all parameters
 * will be clamped within valid range", sized for sizeof expanded), otherwise those of the level in byte 1 */
static ZSTD_compressionParameters c_params(payload in) {
    if (byte(in, 0) & 1) return ZSTD_adjustCParams(raw_cparams(rest(in, 2)), sizeof expanded, 0);
    return level_cparams(byte(in, 1));
}
static ZSTD_frameParameters f_params(uint8_t b) {
    ZSTD_frameParameters f = { b & 1, b >> 1 & 1, b >> 2 & 1 };   /* contentSizeFlag, checksumFlag, noDictIDFlag */
    return f;
}
/* bytes 0..9 as c_params, byte 10 as f_params */
static ZSTD_parameters z_params(payload in) {
    ZSTD_parameters p = { c_params(in), f_params(byte(in, 10)) };
    return p;
}
/* pledged source size: unknown, or 0..16320 bytes (same choice as call_ZSTD_CCtx_setPledgedSrcSize) */
static unsigned long long pledged(uint8_t flag, uint8_t b) { return flag & 1 ? ZSTD_CONTENTSIZE_UNKNOWN : b * 64u; }
static unsigned char *dup_bytes(payload d) {
    unsigned char *copy = malloc(d.n ? d.n : 1);
    if (copy && d.n) memcpy(copy, d.p, d.n);
    return copy;
}
/* the CCtx / DCtx is gone: drop every piece of state tied to it */
static void cctx_gone(void) {
    cctx = NULL;
    cctx_static = cctx_uses_cdict = cctx_uses_pool = c_streaming = c_failed = c_inited = c_begun = 0;
    free(cctx_ws);
    free(cctx_dict_ref);
    cctx_ws = cctx_dict_ref = NULL;
}
static void dctx_gone(void) {
    dctx = NULL;
    dctx_static = dctx_uses_ddict = d_begun = d_streaming = 0;
    free(dctx_ws);
    free(dctx_dict_ref);
    dctx_ws = dctx_dict_ref = NULL;
}
/* every ZSTD_initCStream* / ZSTD_resetCStream starts with ZSTD_CCtx_reset(session_only), which cannot fail */
static void stream_reset_done(size_t rc) {
    c_streaming = c_failed = c_begun = 0;
    if (!ZSTD_isError(rc)) c_inited = 1;
}
/* allocator for ZSTD_create*_advanced: plain malloc/free behind the ZSTD_customMem interface */
static void *custom_alloc(void *opaque, size_t size) { (void)opaque; return malloc(size); }
static void custom_free(void *opaque, void *address) { (void)opaque; free(address); }
static ZSTD_customMem custom_mem(uint8_t b) {
    ZSTD_customMem custom = { custom_alloc, custom_free, NULL };
    return b & 1 ? custom : ZSTD_defaultCMem;
}

#define REPORT(api, expr, ok_cond) \
    do { if (preqed_call(#api)) { size_t rc = (expr); preqed_result(#api, (ok_cond)); } } while (0)
#define REPORT_OK(api, expr) REPORT(api, expr, !ZSTD_isError(rc))
#define REPORT_VOID(api, expr) do { if (preqed_call(#api)) { expr; preqed_result(#api, 1); } } while (0)

/* version and helpers */

static void call_ZSTD_versionNumber(payload in) { (void)in; REPORT_VOID(ZSTD_versionNumber, ZSTD_versionNumber()); }
static void call_ZSTD_versionString(payload in) {
    (void)in;
    if (!preqed_call("ZSTD_versionString")) return;
    preqed_result("ZSTD_versionString", ZSTD_versionString() != NULL);
}
static void call_ZSTD_minCLevel(payload in) { (void)in; REPORT_VOID(ZSTD_minCLevel, ZSTD_minCLevel()); }
static void call_ZSTD_maxCLevel(payload in) { (void)in; REPORT_VOID(ZSTD_maxCLevel, ZSTD_maxCLevel()); }
static void call_ZSTD_defaultCLevel(payload in) { (void)in; REPORT_VOID(ZSTD_defaultCLevel, ZSTD_defaultCLevel()); }
static void call_ZSTD_compressBound(payload in) {
    REPORT(ZSTD_compressBound, ZSTD_compressBound(in.n), rc >= in.n);
}
static void call_ZSTD_isError(payload in) {
    /* zstd encodes errors as (size_t)-code; codes 0..127 cover every ZSTD_ErrorCode plus unknown ones */
    REPORT_VOID(ZSTD_isError, ZSTD_isError((size_t)-(byte(in, 0) % 128)));
}
static void call_ZSTD_getErrorCode(payload in) {
    REPORT_VOID(ZSTD_getErrorCode, ZSTD_getErrorCode((size_t)-(byte(in, 0) % 128)));
}
static void call_ZSTD_getErrorName(payload in) {
    if (!preqed_call("ZSTD_getErrorName")) return;
    preqed_result("ZSTD_getErrorName", ZSTD_getErrorName((size_t)-(byte(in, 0) % 128)) != NULL);
}
static void call_ZSTD_getErrorString(payload in) {
    if (!preqed_call("ZSTD_getErrorString")) return;
    preqed_result("ZSTD_getErrorString", ZSTD_getErrorString((ZSTD_ErrorCode)(byte(in, 0) % 128)) != NULL);
}
static void call_ZSTD_cParam_getBounds(payload in) {
    if (!preqed_call("ZSTD_cParam_getBounds")) return;
    ZSTD_bounds b = ZSTD_cParam_getBounds(c_param(byte(in, 0)));
    preqed_result("ZSTD_cParam_getBounds", !ZSTD_isError(b.error));
}
static void call_ZSTD_dParam_getBounds(payload in) {
    (void)in;
    if (!preqed_call("ZSTD_dParam_getBounds")) return;
    ZSTD_bounds b = ZSTD_dParam_getBounds(ZSTD_d_windowLogMax);
    preqed_result("ZSTD_dParam_getBounds", !ZSTD_isError(b.error));
}
static void call_ZSTD_CStreamInSize(payload in) { (void)in; REPORT_VOID(ZSTD_CStreamInSize, ZSTD_CStreamInSize()); }
static void call_ZSTD_CStreamOutSize(payload in) { (void)in; REPORT_VOID(ZSTD_CStreamOutSize, ZSTD_CStreamOutSize()); }
static void call_ZSTD_DStreamInSize(payload in) { (void)in; REPORT_VOID(ZSTD_DStreamInSize, ZSTD_DStreamInSize()); }
static void call_ZSTD_DStreamOutSize(payload in) { (void)in; REPORT_VOID(ZSTD_DStreamOutSize, ZSTD_DStreamOutSize()); }

/* frame inspection */

static void call_ZSTD_getFrameContentSize(payload in) {
    payload src = compressed_or(in);
    if (!preqed_call("ZSTD_getFrameContentSize")) return;
    unsigned long long size = ZSTD_getFrameContentSize(src.p, src.n);
    preqed_result("ZSTD_getFrameContentSize", size != ZSTD_CONTENTSIZE_ERROR);
}
static void call_ZSTD_getDecompressedSize(payload in) {
    payload src = compressed_or(in);
    REPORT_VOID(ZSTD_getDecompressedSize, ZSTD_getDecompressedSize(src.p, src.n));
}
static void call_ZSTD_findFrameCompressedSize(payload in) {
    payload src = compressed_or(in);
    REPORT_OK(ZSTD_findFrameCompressedSize, ZSTD_findFrameCompressedSize(src.p, src.n));
}
static void call_ZSTD_getDictID_fromFrame(payload in) {
    payload src = compressed_or(in);
    REPORT_VOID(ZSTD_getDictID_fromFrame, ZSTD_getDictID_fromFrame(src.p, src.n));
}
static void call_ZSTD_getDictID_fromDict(payload in) {
    payload d = dict_or(in);
    REPORT_VOID(ZSTD_getDictID_fromDict, ZSTD_getDictID_fromDict(d.p, d.n));
}

/* one-shot */

static void call_ZSTD_compress(payload in) {
    payload src = expand(rest(in, 1));
    if (!preqed_call("ZSTD_compress")) return;
    size_t rc = ZSTD_compress(compressed, OUT_CAP, src.p, src.n, level(byte(in, 0)));
    preqed_result("ZSTD_compress", !ZSTD_isError(rc));
    if (!ZSTD_isError(rc)) compressed_len = rc;
}
static void call_ZSTD_decompress(payload in) {
    payload src = compressed_or(in);
    REPORT_OK(ZSTD_decompress, ZSTD_decompress(decompressed, OUT_CAP, src.p, src.n));
}
/* ltl: cctx_lifecycle, no_oneshot_during_streaming_session, bufferless_compress_session */
static void call_ZSTD_compress_usingDict(payload in) {
    if (!cctx || c_streaming) return;
    payload d = dict_or(in);
    payload src = expand(rest(in, 2 + (byte(in, 0) & 4 ? 0 : d.n)));
    if (!preqed_call("ZSTD_compress_usingDict")) return;
    c_begun = 0;
    size_t rc = ZSTD_compress_usingDict(cctx, compressed, OUT_CAP, src.p, src.n, d.p, d.n, level(byte(in, 1)));
    preqed_result("ZSTD_compress_usingDict", !ZSTD_isError(rc));
    if (!ZSTD_isError(rc)) compressed_len = rc;
}
/* ltl: dctx_lifecycle, block_decode_after_begin */
static void call_ZSTD_decompress_usingDict(payload in) {
    if (!dctx) return;
    payload d = dict_or(in);
    payload src = compressed_or(in);
    REPORT_OK(ZSTD_decompress_usingDict, ZSTD_decompress_usingDict(dctx, decompressed, OUT_CAP, src.p, src.n, d.p, d.n));
    d_begun = 0;
}

/* compression context */
/* ltl: cctx_lifecycle */
static void call_ZSTD_createCCtx(payload in) {
    (void)in;
    if (cctx) return;
    if (!preqed_call("ZSTD_createCCtx")) return;
    cctx = ZSTD_createCCtx();
    preqed_result("ZSTD_createCCtx", cctx != NULL);
}
/* ltl: cctx_lifecycle */
static void call_ZSTD_createCStream(payload in) {
    (void)in;
    if (cctx) return;
    if (!preqed_call("ZSTD_createCStream")) return;
    cctx = ZSTD_createCStream();
    preqed_result("ZSTD_createCStream", cctx != NULL);
}
/* ltl: cctx_lifecycle, cdict_outlives_reference, no_oneshot_during_streaming_session, reset_after_streaming_error, static_objects_have_no_free, thread_pool_outlives_cctx, bufferless_compress_session, reset_cstream_after_init */
static void call_ZSTD_freeCCtx(payload in) {
    (void)in;
    if (!cctx || cctx_static) return;
    REPORT(ZSTD_freeCCtx, ZSTD_freeCCtx(cctx), rc == 0);
    cctx_gone();
}
/* ltl: cctx_lifecycle, cdict_outlives_reference, no_oneshot_during_streaming_session, reset_after_streaming_error, static_objects_have_no_free, thread_pool_outlives_cctx, bufferless_compress_session, reset_cstream_after_init */
static void call_ZSTD_freeCStream(payload in) {
    (void)in;
    if (!cctx || cctx_static) return;
    REPORT(ZSTD_freeCStream, ZSTD_freeCStream(cctx), rc == 0);
    cctx_gone();
}
/* ltl: cctx_lifecycle */
static void call_ZSTD_sizeof_CCtx(payload in) {
    (void)in;
    if (!cctx) return;
    REPORT(ZSTD_sizeof_CCtx, ZSTD_sizeof_CCtx(cctx), rc > 0);
}
/* ltl: cctx_lifecycle */
static void call_ZSTD_sizeof_CStream(payload in) {
    (void)in;
    if (!cctx) return;
    REPORT(ZSTD_sizeof_CStream, ZSTD_sizeof_CStream(cctx), rc > 0);
}
/* ltl: cctx_lifecycle, no_oneshot_during_streaming_session, bufferless_compress_session */
static void call_ZSTD_compressCCtx(payload in) {
    if (!cctx || c_streaming) return;
    payload src = expand(rest(in, 1));
    if (!preqed_call("ZSTD_compressCCtx")) return;
    c_begun = 0;
    size_t rc = ZSTD_compressCCtx(cctx, compressed, OUT_CAP, src.p, src.n, level(byte(in, 0)));
    preqed_result("ZSTD_compressCCtx", !ZSTD_isError(rc));
    if (!ZSTD_isError(rc)) compressed_len = rc;
}
/* ltl: cctx_lifecycle */
static void call_ZSTD_CCtx_setParameter(payload in) {
    if (!cctx) return;
    ZSTD_cParameter p = c_param(byte(in, 0));
    REPORT_OK(ZSTD_CCtx_setParameter, ZSTD_CCtx_setParameter(cctx, p, c_value(p, in)));
}
/* ltl: cctx_lifecycle */
static void call_ZSTD_CCtx_setPledgedSrcSize(payload in) {
    if (!cctx) return;
    unsigned long long size = byte(in, 0) & 1 ? ZSTD_CONTENTSIZE_UNKNOWN : byte(in, 1) * 64u;
    REPORT_OK(ZSTD_CCtx_setPledgedSrcSize, ZSTD_CCtx_setPledgedSrcSize(cctx, size));
}
/* ltl: cctx_lifecycle, cdict_outlives_reference, no_oneshot_during_streaming_session, reset_after_streaming_error, bufferless_compress_session */
static void call_ZSTD_CCtx_reset(payload in) {
    if (!cctx) return;
    ZSTD_ResetDirective d = reset_directive(byte(in, 0));
    if (!preqed_call("ZSTD_CCtx_reset")) return;
    c_begun = 0;
    size_t rc = ZSTD_CCtx_reset(cctx, d);
    preqed_result("ZSTD_CCtx_reset", !ZSTD_isError(rc));
    if (!ZSTD_isError(rc) && d != ZSTD_reset_parameters) c_streaming = c_failed = 0;
    if (!ZSTD_isError(rc) && d != ZSTD_reset_session_only) cctx_uses_cdict = 0;
}
/* ltl: cctx_lifecycle, no_oneshot_during_streaming_session, bufferless_compress_session */
static void call_ZSTD_compress2(payload in) {
    if (!cctx || c_streaming) return;
    payload src = expand(in);
    if (!preqed_call("ZSTD_compress2")) return;
    c_begun = 0;
    size_t rc = ZSTD_compress2(cctx, compressed, OUT_CAP, src.p, src.n);
    preqed_result("ZSTD_compress2", !ZSTD_isError(rc));
    if (!ZSTD_isError(rc)) compressed_len = rc;
}
/* ltl: cctx_lifecycle, no_oneshot_during_streaming_session, reset_after_streaming_error, bufferless_compress_session */
static void call_ZSTD_compressStream2(payload in) {
    if (!cctx || c_failed) return;
    payload src = expand(rest(in, 1));
    ZSTD_EndDirective mode = end_directive(byte(in, 0));
    ZSTD_inBuffer input = { src.p, src.n, 0 };
    ZSTD_outBuffer output = { compressed, OUT_CAP, compressed_len };
    if (!preqed_call("ZSTD_compressStream2")) return;
    c_begun = 0;
    size_t rc = ZSTD_compressStream2(cctx, &output, &input, mode);
    preqed_result("ZSTD_compressStream2", !ZSTD_isError(rc));
    compressed_len = output.pos;
    if (ZSTD_isError(rc)) c_failed = 1;
    else c_streaming = !(mode == ZSTD_e_end && rc == 0);
}
/* ltl: cctx_lifecycle, cdict_outlives_reference, no_oneshot_during_streaming_session, reset_after_streaming_error, bufferless_compress_session, reset_cstream_after_init */
static void call_ZSTD_initCStream(payload in) {
    if (!cctx) return;
    if (!preqed_call("ZSTD_initCStream")) return;
    size_t rc = ZSTD_initCStream(cctx, level(byte(in, 0)));
    preqed_result("ZSTD_initCStream", !ZSTD_isError(rc));
    stream_reset_done(rc);
    if (!ZSTD_isError(rc)) cctx_uses_cdict = 0;
}
/* ltl: cctx_lifecycle, no_oneshot_during_streaming_session, reset_after_streaming_error, bufferless_compress_session */
static void call_ZSTD_compressStream(payload in) {
    if (!cctx || c_failed) return;
    payload src = expand(in);
    ZSTD_inBuffer input = { src.p, src.n, 0 };
    ZSTD_outBuffer output = { compressed, OUT_CAP, compressed_len };
    if (!preqed_call("ZSTD_compressStream")) return;
    c_begun = 0;
    size_t rc = ZSTD_compressStream(cctx, &output, &input);
    preqed_result("ZSTD_compressStream", !ZSTD_isError(rc));
    compressed_len = output.pos;
    if (ZSTD_isError(rc)) c_failed = 1;
    else c_streaming = 1;
}
/* ltl: cctx_lifecycle, no_oneshot_during_streaming_session, reset_after_streaming_error, bufferless_compress_session */
static void call_ZSTD_flushStream(payload in) {
    (void)in;
    if (!cctx || c_failed) return;
    ZSTD_outBuffer output = { compressed, OUT_CAP, compressed_len };
    if (!preqed_call("ZSTD_flushStream")) return;
    c_begun = 0;
    size_t rc = ZSTD_flushStream(cctx, &output);
    preqed_result("ZSTD_flushStream", rc == 0);
    compressed_len = output.pos;
    if (ZSTD_isError(rc)) c_failed = 1;
    else c_streaming = 1;
}
/* ltl: cctx_lifecycle, no_oneshot_during_streaming_session, reset_after_streaming_error, bufferless_compress_session */
static void call_ZSTD_endStream(payload in) {
    (void)in;
    if (!cctx || c_failed) return;
    ZSTD_outBuffer output = { compressed, OUT_CAP, compressed_len };
    if (!preqed_call("ZSTD_endStream")) return;
    c_begun = 0;
    size_t rc = ZSTD_endStream(cctx, &output);
    preqed_result("ZSTD_endStream", rc == 0);
    compressed_len = output.pos;
    if (ZSTD_isError(rc)) c_failed = 1;
    else c_streaming = rc != 0;
}
/* ltl: cctx_lifecycle, cdict_outlives_reference */
static void call_ZSTD_CCtx_loadDictionary(payload in) {
    if (!cctx) return;
    payload d = dict_or(in);
    if (!preqed_call("ZSTD_CCtx_loadDictionary")) return;
    size_t rc = ZSTD_CCtx_loadDictionary(cctx, d.p, d.n);
    preqed_result("ZSTD_CCtx_loadDictionary", !ZSTD_isError(rc));
    /* inside a session the call fails (stage_wrong) and the CDict reference stays */
    if (!ZSTD_isError(rc)) cctx_uses_cdict = 0;
}
/* ltl: cctx_lifecycle, cdict_outlives_reference */
static void call_ZSTD_CCtx_refCDict(payload in) {
    if (!cctx) return;
    ZSTD_CDict *ref = byte(in, 0) & 1 ? NULL : cdict;
    if (!preqed_call("ZSTD_CCtx_refCDict")) return;
    size_t rc = ZSTD_CCtx_refCDict(cctx, ref);
    preqed_result("ZSTD_CCtx_refCDict", !ZSTD_isError(rc));
    if (!ZSTD_isError(rc)) cctx_uses_cdict = ref != NULL;
}
/* ltl: cctx_lifecycle, cdict_outlives_reference */
static void call_ZSTD_CCtx_refPrefix(payload in) {
    if (!cctx || c_streaming) return;
    prefix_len = in.n < sizeof cprefix ? in.n : sizeof cprefix;
    memcpy(cprefix, in.p, prefix_len);
    if (!preqed_call("ZSTD_CCtx_refPrefix")) return;
    size_t rc = ZSTD_CCtx_refPrefix(cctx, prefix_len ? cprefix : NULL, prefix_len);
    preqed_result("ZSTD_CCtx_refPrefix", !ZSTD_isError(rc));
    if (!ZSTD_isError(rc)) cctx_uses_cdict = 0;
}

/* decompression context */
/* ltl: dctx_lifecycle */
static void call_ZSTD_createDCtx(payload in) {
    (void)in;
    if (dctx) return;
    if (!preqed_call("ZSTD_createDCtx")) return;
    dctx = ZSTD_createDCtx();
    preqed_result("ZSTD_createDCtx", dctx != NULL);
}
/* ltl: dctx_lifecycle */
static void call_ZSTD_createDStream(payload in) {
    (void)in;
    if (dctx) return;
    if (!preqed_call("ZSTD_createDStream")) return;
    dctx = ZSTD_createDStream();
    preqed_result("ZSTD_createDStream", dctx != NULL);
}
/* ltl: dctx_lifecycle, ddict_outlives_reference, static_objects_have_no_free, block_decode_after_begin */
static void call_ZSTD_freeDCtx(payload in) {
    (void)in;
    if (!dctx || dctx_static) return;
    REPORT(ZSTD_freeDCtx, ZSTD_freeDCtx(dctx), rc == 0);
    dctx_gone();
}
/* ltl: dctx_lifecycle, ddict_outlives_reference, static_objects_have_no_free, block_decode_after_begin */
static void call_ZSTD_freeDStream(payload in) {
    (void)in;
    if (!dctx || dctx_static) return;
    REPORT(ZSTD_freeDStream, ZSTD_freeDStream(dctx), rc == 0);
    dctx_gone();
}
/* ltl: dctx_lifecycle */
static void call_ZSTD_sizeof_DCtx(payload in) {
    (void)in;
    if (!dctx) return;
    REPORT(ZSTD_sizeof_DCtx, ZSTD_sizeof_DCtx(dctx), rc > 0);
}
/* ltl: dctx_lifecycle */
static void call_ZSTD_sizeof_DStream(payload in) {
    (void)in;
    if (!dctx) return;
    REPORT(ZSTD_sizeof_DStream, ZSTD_sizeof_DStream(dctx), rc > 0);
}
/* ltl: dctx_lifecycle, block_decode_after_begin */
static void call_ZSTD_decompressDCtx(payload in) {
    if (!dctx) return;
    payload src = compressed_or(in);
    REPORT_OK(ZSTD_decompressDCtx, ZSTD_decompressDCtx(dctx, decompressed, OUT_CAP, src.p, src.n));
    d_begun = 0;
}
/* ltl: dctx_lifecycle */
static void call_ZSTD_DCtx_setParameter(payload in) {
    if (!dctx) return;
    /* 0 = default, 10..27 valid, 1..9 rejected; 27 is ZSTD_WINDOWLOG_LIMIT_DEFAULT, the limit zstd.h sets "to preserve
     * host's memory from unreasonable requirements" (28..31 let a frame header request a multi-GiB buffer) */
    REPORT_OK(ZSTD_DCtx_setParameter, ZSTD_DCtx_setParameter(dctx, ZSTD_d_windowLogMax, byte(in, 0) % 28));
}
/* ltl: dctx_lifecycle, ddict_outlives_reference, block_decode_after_begin */
static void call_ZSTD_DCtx_reset(payload in) {
    if (!dctx) return;
    ZSTD_ResetDirective d = reset_directive(byte(in, 0));
    if (!preqed_call("ZSTD_DCtx_reset")) return;
    d_begun = 0;
    size_t rc = ZSTD_DCtx_reset(dctx, d);
    preqed_result("ZSTD_DCtx_reset", !ZSTD_isError(rc));
    if (!ZSTD_isError(rc) && d != ZSTD_reset_parameters) d_streaming = 0;
    if (!ZSTD_isError(rc) && d != ZSTD_reset_session_only) dctx_uses_ddict = 0;
}
/* ltl: dctx_lifecycle, ddict_outlives_reference, block_decode_after_begin */
static void call_ZSTD_initDStream(payload in) {
    (void)in;
    if (!dctx) return;
    REPORT_OK(ZSTD_initDStream, ZSTD_initDStream(dctx));
    dctx_uses_ddict = d_begun = d_streaming = 0;
}
/* ltl: dctx_lifecycle, block_decode_after_begin */
static void call_ZSTD_decompressStream(payload in) {
    if (!dctx) return;
    payload src = compressed_or(in);
    ZSTD_inBuffer input = { src.p, src.n, 0 };
    /* bit 3: 1..4081-byte output window, so decompression stops mid-frame and resumes */
    ZSTD_outBuffer output = { decompressed, byte(in, 0) & 8 ? 1 + byte(in, 1) * 16u : OUT_CAP, 0 };
    if (!preqed_call("ZSTD_decompressStream")) return;
    size_t rc = ZSTD_decompressStream(dctx, &output, &input);
    preqed_result("ZSTD_decompressStream", !ZSTD_isError(rc));
    d_begun = 0;
    d_streaming = rc != 0;
}
/* ltl: dctx_lifecycle, ddict_outlives_reference, static_objects_have_no_free */
static void call_ZSTD_DCtx_loadDictionary(payload in) {
    /* zstd.h ZSTD_initStatic*() Limitation 1: a static context is not compatible with internal dictionary creation */
    if (!dctx || dctx_static) return;
    payload d = dict_or(in);
    if (!preqed_call("ZSTD_DCtx_loadDictionary")) return;
    size_t rc = ZSTD_DCtx_loadDictionary(dctx, d.p, d.n);
    preqed_result("ZSTD_DCtx_loadDictionary", !ZSTD_isError(rc));
    /* inside a frame the call fails (stage_wrong) and the DDict reference stays */
    if (!ZSTD_isError(rc)) dctx_uses_ddict = 0;
}
/* ltl: dctx_lifecycle, ddict_outlives_reference */
static void call_ZSTD_DCtx_refDDict(payload in) {
    if (!dctx) return;
    ZSTD_DDict *ref = byte(in, 0) & 1 ? NULL : ddict;
    if (!preqed_call("ZSTD_DCtx_refDDict")) return;
    size_t rc = ZSTD_DCtx_refDDict(dctx, ref);
    preqed_result("ZSTD_DCtx_refDDict", !ZSTD_isError(rc));
    if (!ZSTD_isError(rc)) dctx_uses_ddict = ref != NULL;
}
/* ltl: dctx_lifecycle, ddict_outlives_reference, static_objects_have_no_free */
static void call_ZSTD_DCtx_refPrefix(payload in) {
    if (!dctx || dctx_static || d_streaming) return;   /* the prefix becomes an internal DDict: see call_ZSTD_DCtx_loadDictionary */
    prefix_len = in.n < sizeof dprefix ? in.n : sizeof dprefix;
    memcpy(dprefix, in.p, prefix_len);
    if (!preqed_call("ZSTD_DCtx_refPrefix")) return;
    size_t rc = ZSTD_DCtx_refPrefix(dctx, prefix_len ? dprefix : NULL, prefix_len);
    preqed_result("ZSTD_DCtx_refPrefix", !ZSTD_isError(rc));
    if (!ZSTD_isError(rc)) dctx_uses_ddict = 0;
}

/* dictionaries */
/* ltl: cdict_outlives_reference */
static void call_ZSTD_createCDict(payload in) {
    if (cdict) return;
    payload d = dict_or(in);
    if (!preqed_call("ZSTD_createCDict")) return;
    cdict = ZSTD_createCDict(d.p, d.n, level(byte(in, 1)));
    preqed_result("ZSTD_createCDict", cdict != NULL);
}
/* ltl: cdict_outlives_reference, static_objects_have_no_free, bufferless_compress_session */
static void call_ZSTD_freeCDict(payload in) {
    (void)in;
    if (!cdict || cdict_static || cctx_uses_cdict || c_begun == 2) return;
    /* the monitor also counts ZSTD_CCtx_refCDict(NULL) as a reference: when it filters the call the CDict stays */
    if (!preqed_call("ZSTD_freeCDict")) return;
    preqed_result("ZSTD_freeCDict", ZSTD_freeCDict(cdict) == 0);
    cdict = NULL;
    free(cdict_ref);
    cdict_ref = NULL;
}
/* ltl: cdict_outlives_reference */
static void call_ZSTD_sizeof_CDict(payload in) {
    (void)in;
    if (!cdict) return;
    REPORT(ZSTD_sizeof_CDict, ZSTD_sizeof_CDict(cdict), rc > 0);
}
/* ltl: cdict_outlives_reference */
static void call_ZSTD_getDictID_fromCDict(payload in) {
    (void)in;
    if (!cdict) return;
    REPORT_VOID(ZSTD_getDictID_fromCDict, ZSTD_getDictID_fromCDict(cdict));
}
/* ltl: cctx_lifecycle, cdict_outlives_reference, no_oneshot_during_streaming_session, bufferless_compress_session */
static void call_ZSTD_compress_usingCDict(payload in) {
    if (!cctx || !cdict || c_streaming) return;
    payload src = expand(in);
    if (!preqed_call("ZSTD_compress_usingCDict")) return;
    c_begun = 0;
    size_t rc = ZSTD_compress_usingCDict(cctx, compressed, OUT_CAP, src.p, src.n, cdict);
    preqed_result("ZSTD_compress_usingCDict", !ZSTD_isError(rc));
    if (!ZSTD_isError(rc)) compressed_len = rc;
}
/* ltl: ddict_outlives_reference */
static void call_ZSTD_createDDict(payload in) {
    if (ddict) return;
    payload d = dict_or(in);
    if (!preqed_call("ZSTD_createDDict")) return;
    ddict = ZSTD_createDDict(d.p, d.n);
    preqed_result("ZSTD_createDDict", ddict != NULL);
}
/* ltl: ddict_outlives_reference, static_objects_have_no_free */
static void call_ZSTD_freeDDict(payload in) {
    (void)in;
    if (!ddict || ddict_static || dctx_uses_ddict) return;
    /* the monitor also counts ZSTD_DCtx_refDDict(NULL) as a reference: when it filters the call the DDict stays */
    if (!preqed_call("ZSTD_freeDDict")) return;
    preqed_result("ZSTD_freeDDict", ZSTD_freeDDict(ddict) == 0);
    ddict = NULL;
    free(ddict_ref);
    ddict_ref = NULL;
}
/* ltl: ddict_outlives_reference */
static void call_ZSTD_sizeof_DDict(payload in) {
    (void)in;
    if (!ddict) return;
    REPORT(ZSTD_sizeof_DDict, ZSTD_sizeof_DDict(ddict), rc > 0);
}
/* ltl: ddict_outlives_reference */
static void call_ZSTD_getDictID_fromDDict(payload in) {
    (void)in;
    if (!ddict) return;
    REPORT_VOID(ZSTD_getDictID_fromDDict, ZSTD_getDictID_fromDDict(ddict));
}
/* ltl: dctx_lifecycle, ddict_outlives_reference, block_decode_after_begin */
static void call_ZSTD_decompress_usingDDict(payload in) {
    if (!dctx || !ddict) return;
    payload src = compressed_or(in);
    REPORT_OK(ZSTD_decompress_usingDDict, ZSTD_decompress_usingDDict(dctx, decompressed, OUT_CAP, src.p, src.n, ddict));
    d_begun = 0;
}

/* dictionary builder */

static void call_ZDICT_trainFromBuffer(payload in) {
    payload samples = expand(in);
    /* at least 64 bytes split into 1..32 equal samples; fewer bytes cannot train anything */
    if (samples.n < 64) return;
    size_t sizes[32];
    unsigned count = 1 + byte(in, 0) % 32;
    size_t each = samples.n / count;
    for (unsigned i = 0; i < count; i++) sizes[i] = each;
    if (!preqed_call("ZDICT_trainFromBuffer")) return;
    size_t rc = ZDICT_trainFromBuffer(dict_buf, sizeof dict_buf, samples.p, sizes, count);
    preqed_result("ZDICT_trainFromBuffer", !ZDICT_isError(rc));
    if (!ZDICT_isError(rc)) dict_len = rc;
}
static void call_ZDICT_finalizeDictionary(payload in) {
    payload samples = expand(rest(in, 1));
    if (samples.n < 64) return;
    size_t sizes[8];  /* 1..8 samples; the first half of the bytes is the dictionary content */
    unsigned count = 1 + byte(in, 0) % 8;
    for (unsigned i = 0; i < count; i++) sizes[i] = samples.n / count;
    ZDICT_params_t params = { level(byte(in, 1)), byte(in, 0) & 1, byte(in, 1) };
    size_t content = samples.n / 2;
    if (!preqed_call("ZDICT_finalizeDictionary")) return;
    size_t rc = ZDICT_finalizeDictionary(scratch, sizeof dict_buf, samples.p, content, samples.p, sizes, count, params);
    preqed_result("ZDICT_finalizeDictionary", !ZDICT_isError(rc));
    if (!ZDICT_isError(rc)) {
        memcpy(dict_buf, scratch, rc);
        dict_len = rc;
    }
}
static void call_ZDICT_getDictID(payload in) {
    payload d = dict_or(in);
    REPORT_VOID(ZDICT_getDictID, ZDICT_getDictID(d.p, d.n));
}
static void call_ZDICT_getDictHeaderSize(payload in) {
    payload d = dict_or(in);
    REPORT_VOID(ZDICT_getDictHeaderSize, ZDICT_getDictHeaderSize(d.p, d.n));
}
static void call_ZDICT_isError(payload in) {
    REPORT_VOID(ZDICT_isError, ZDICT_isError((size_t)-(byte(in, 0) % 128)));
}
static void call_ZDICT_getErrorName(payload in) {
    if (!preqed_call("ZDICT_getErrorName")) return;
    preqed_result("ZDICT_getErrorName", ZDICT_getErrorName((size_t)-(byte(in, 0) % 128)) != NULL);
}

/* ===== experimental API (ZSTD_STATIC_LINKING_ONLY / ZDICT_STATIC_LINKING_ONLY) ===== */

/* frame inspection */

static void call_ZSTD_findDecompressedSize(payload in) {
    payload src = compressed_or(in);
    if (!preqed_call("ZSTD_findDecompressedSize")) return;
    unsigned long long size = ZSTD_findDecompressedSize(src.p, src.n);
    preqed_result("ZSTD_findDecompressedSize", size != ZSTD_CONTENTSIZE_ERROR);
}
static void call_ZSTD_decompressBound(payload in) {
    payload src = compressed_or(in);
    if (!preqed_call("ZSTD_decompressBound")) return;
    unsigned long long size = ZSTD_decompressBound(src.p, src.n);
    preqed_result("ZSTD_decompressBound", size != ZSTD_CONTENTSIZE_ERROR);
}
static void call_ZSTD_frameHeaderSize(payload in) {
    payload src = compressed_or(in);
    /* inputs shorter than ZSTD_FRAMEHEADERSIZE_PREFIX get the documented error code */
    REPORT_OK(ZSTD_frameHeaderSize, ZSTD_frameHeaderSize(src.p, src.n));
}
static void call_ZSTD_decompressionMargin(payload in) {
    payload src = compressed_or(in);
    REPORT_OK(ZSTD_decompressionMargin, ZSTD_decompressionMargin(src.p, src.n));
}
static void call_ZSTD_isFrame(payload in) {
    payload src = compressed_or(in);
    REPORT_VOID(ZSTD_isFrame, ZSTD_isFrame(src.p, src.n));
}
static void call_ZSTD_isSkippableFrame(payload in) {
    payload src = compressed_or(in);
    REPORT_VOID(ZSTD_isSkippableFrame, ZSTD_isSkippableFrame(src.p, src.n));
}
static void call_ZSTD_writeSkippableFrame(payload in) {
    payload src = rest(in, 1);
    if (!preqed_call("ZSTD_writeSkippableFrame")) return;
    /* appended to the frames already in `compressed`; magicVariant 0..15 is valid, 16..31 the documented error */
    size_t rc = ZSTD_writeSkippableFrame(compressed + compressed_len, OUT_CAP - compressed_len, src.p, src.n, byte(in, 0) % 32);
    preqed_result("ZSTD_writeSkippableFrame", !ZSTD_isError(rc));
    if (!ZSTD_isError(rc)) compressed_len += rc;
}
static void call_ZSTD_readSkippableFrame(payload in) {
    payload src = compressed_or(in);
    unsigned variant;
    REPORT_OK(ZSTD_readSkippableFrame, ZSTD_readSkippableFrame(scratch, OUT_CAP, &variant, src.p, src.n));
}
static void call_ZSTD_decodingBufferSize_min(payload in) {
    /* window 1 B..512 GiB; content size unknown or 0..16 MiB */
    unsigned long long window = 1ULL << byte(in, 0) % 40;
    unsigned long long content = byte(in, 1) & 1 ? ZSTD_CONTENTSIZE_UNKNOWN : (unsigned long long)byte(in, 2) << 16;
    REPORT_OK(ZSTD_decodingBufferSize_min, ZSTD_decodingBufferSize_min(window, content));
}
static void call_ZSTD_isDeterministicBuild(payload in) { (void)in; REPORT_VOID(ZSTD_isDeterministicBuild, ZSTD_isDeterministicBuild()); }

/* memory estimation and parameter helpers */

static void call_ZSTD_estimateCCtxSize(payload in) {
    REPORT_OK(ZSTD_estimateCCtxSize, ZSTD_estimateCCtxSize(level(byte(in, 0))));
}
static void call_ZSTD_estimateCCtxSize_usingCParams(payload in) {
    ZSTD_compressionParameters cp = c_params(in);
    REPORT_OK(ZSTD_estimateCCtxSize_usingCParams, ZSTD_estimateCCtxSize_usingCParams(cp));
}
static void call_ZSTD_estimateCStreamSize(payload in) {
    REPORT_OK(ZSTD_estimateCStreamSize, ZSTD_estimateCStreamSize(level(byte(in, 0))));
}
static void call_ZSTD_estimateCStreamSize_usingCParams(payload in) {
    ZSTD_compressionParameters cp = c_params(in);
    REPORT_OK(ZSTD_estimateCStreamSize_usingCParams, ZSTD_estimateCStreamSize_usingCParams(cp));
}
static void call_ZSTD_estimateDCtxSize(payload in) { (void)in; REPORT(ZSTD_estimateDCtxSize, ZSTD_estimateDCtxSize(), rc > 0); }
static void call_ZSTD_estimateDStreamSize(payload in) {
    /* maximum window size 1 B..2 GiB */
    REPORT_OK(ZSTD_estimateDStreamSize, ZSTD_estimateDStreamSize((size_t)1 << byte(in, 0) % 32));
}
static void call_ZSTD_estimateDStreamSize_fromFrame(payload in) {
    payload src = compressed_or(in);
    REPORT_OK(ZSTD_estimateDStreamSize_fromFrame, ZSTD_estimateDStreamSize_fromFrame(src.p, src.n));
}
static void call_ZSTD_estimateCDictSize(payload in) {
    REPORT_OK(ZSTD_estimateCDictSize, ZSTD_estimateCDictSize(dict_or(in).n, level(byte(in, 1))));
}
static void call_ZSTD_estimateCDictSize_advanced(payload in) {
    ZSTD_compressionParameters cp = c_params(rest(in, 1));
    ZSTD_dictLoadMethod_e method = byte(in, 0) & 1 ? ZSTD_dlm_byRef : ZSTD_dlm_byCopy;
    REPORT_OK(ZSTD_estimateCDictSize_advanced, ZSTD_estimateCDictSize_advanced(dict_or(in).n, cp, method));
}
static void call_ZSTD_estimateDDictSize(payload in) {
    ZSTD_dictLoadMethod_e method = byte(in, 0) & 1 ? ZSTD_dlm_byRef : ZSTD_dlm_byCopy;
    REPORT_OK(ZSTD_estimateDDictSize, ZSTD_estimateDDictSize(dict_or(in).n, method));
}
static void call_ZSTD_checkCParams(payload in) {
    REPORT_OK(ZSTD_checkCParams, ZSTD_checkCParams(raw_cparams(in)));
}
static void call_ZSTD_adjustCParams(payload in) {
    /* zstd.h: "cPar can be invalid : all parameters will be clamped within valid range in the @return struct";
     * srcSize unknown or 0..255 KiB, dictSize 0..16 KiB */
    unsigned long long src_size = byte(in, 8) & 1 ? ZSTD_CONTENTSIZE_UNKNOWN : byte(in, 9) * 1024u;
    if (!preqed_call("ZSTD_adjustCParams")) return;
    ZSTD_compressionParameters cp = ZSTD_adjustCParams(raw_cparams(in), src_size, byte(in, 10) * 64u);
    preqed_result("ZSTD_adjustCParams", !ZSTD_isError(ZSTD_checkCParams(cp)));
}

/* compression context: parameter structures, advanced one-shots */
/* ltl: cctx_lifecycle */
static void call_ZSTD_CCtx_getParameter(payload in) {
    if (!cctx) return;
    int value;
    REPORT_OK(ZSTD_CCtx_getParameter, ZSTD_CCtx_getParameter(cctx, c_param(byte(in, 0)), &value));
}
/* ltl: cctx_lifecycle */
static void call_ZSTD_CCtx_setCParams(payload in) {
    if (!cctx) return;
    ZSTD_compressionParameters cp = c_params(in);
    REPORT_OK(ZSTD_CCtx_setCParams, ZSTD_CCtx_setCParams(cctx, cp));
}
/* ltl: cctx_lifecycle */
static void call_ZSTD_CCtx_setFParams(payload in) {
    if (!cctx) return;
    REPORT_OK(ZSTD_CCtx_setFParams, ZSTD_CCtx_setFParams(cctx, f_params(byte(in, 0))));
}
/* ltl: cctx_lifecycle */
static void call_ZSTD_CCtx_setParams(payload in) {
    if (!cctx) return;
    ZSTD_parameters params = z_params(in);
    REPORT_OK(ZSTD_CCtx_setParams, ZSTD_CCtx_setParams(cctx, params));
}
/* ltl: cctx_lifecycle */
static void call_ZSTD_getFrameProgression(payload in) {
    (void)in;
    if (!cctx) return;
    REPORT_VOID(ZSTD_getFrameProgression, ZSTD_getFrameProgression(cctx));
}
/* ltl: cctx_lifecycle */
static void call_ZSTD_toFlushNow(payload in) {
    (void)in;
    if (!cctx) return;
    REPORT_VOID(ZSTD_toFlushNow, ZSTD_toFlushNow(cctx));
}
/* ltl: cctx_lifecycle, no_oneshot_during_streaming_session, bufferless_compress_session */
static void call_ZSTD_compress_advanced(payload in) {
    if (!cctx || c_streaming) return;
    payload d = dict_or(in);
    ZSTD_parameters params = z_params(rest(in, 1));
    payload src = expand(rest(in, 12));
    if (!preqed_call("ZSTD_compress_advanced")) return;
    c_begun = 0;
    size_t rc = ZSTD_compress_advanced(cctx, compressed, OUT_CAP, src.p, src.n, d.p, d.n, params);
    preqed_result("ZSTD_compress_advanced", !ZSTD_isError(rc));
    if (!ZSTD_isError(rc)) compressed_len = rc;
}
/* ltl: cctx_lifecycle, cdict_outlives_reference, no_oneshot_during_streaming_session, bufferless_compress_session */
static void call_ZSTD_compress_usingCDict_advanced(payload in) {
    if (!cctx || !cdict || c_streaming) return;
    payload src = expand(rest(in, 1));
    if (!preqed_call("ZSTD_compress_usingCDict_advanced")) return;
    c_begun = 0;
    size_t rc = ZSTD_compress_usingCDict_advanced(cctx, compressed, OUT_CAP, src.p, src.n, cdict, f_params(byte(in, 0)));
    preqed_result("ZSTD_compress_usingCDict_advanced", !ZSTD_isError(rc));
    if (!ZSTD_isError(rc)) compressed_len = rc;
}
/* ltl: cctx_lifecycle, cdict_outlives_reference, static_objects_have_no_free */
static void call_ZSTD_CCtx_loadDictionary_byReference(payload in) {
    /* zstd.h ZSTD_initStatic*() Limitation 1: a static context is not compatible with internal dictionary creation
     * (the CDict built from a referenced dictionary would be malloc'ed and never freed) */
    if (!cctx || cctx_static) return;
    unsigned char *copy = dup_bytes(dict_or(in));
    size_t size = dict_or(in).n;
    if (!copy) return;
    if (preqed_call("ZSTD_CCtx_loadDictionary_byReference")) {
        size_t rc = ZSTD_CCtx_loadDictionary_byReference(cctx, copy, size);
        preqed_result("ZSTD_CCtx_loadDictionary_byReference", !ZSTD_isError(rc));
        if (!ZSTD_isError(rc)) {
            /* success means no session is open and the previous dictionary was dropped (ZSTD_clearAllDicts) */
            free(cctx_dict_ref);
            cctx_dict_ref = copy;
            cctx_uses_cdict = 0;
            return;
        }
    }
    free(copy);
}

/* thread pool */
/* ltl: thread_pool_outlives_cctx */
static void call_ZSTD_createThreadPool(payload in) {
    if (pool) return;
    if (!preqed_call("ZSTD_createThreadPool")) return;
    pool = ZSTD_createThreadPool(1 + byte(in, 0) % 4);   /* 1..4 threads */
    preqed_result("ZSTD_createThreadPool", pool != NULL);
}
/* ltl: thread_pool_outlives_cctx */
static void call_ZSTD_freeThreadPool(payload in) {
    (void)in;
    if (!pool || cctx_uses_pool) return;
    if (!preqed_call("ZSTD_freeThreadPool")) return;
    ZSTD_freeThreadPool(pool);
    preqed_result("ZSTD_freeThreadPool", 1);
    pool = NULL;
}
/* ltl: cctx_lifecycle, thread_pool_outlives_cctx */
static void call_ZSTD_CCtx_refThreadPool(payload in) {
    if (!cctx) return;
    /* zstd.h: "use NULL argument value to use an internal thread pool" */
    ZSTD_threadPool *ref = byte(in, 0) & 1 ? NULL : pool;
    if (!preqed_call("ZSTD_CCtx_refThreadPool")) return;
    size_t rc = ZSTD_CCtx_refThreadPool(cctx, ref);
    preqed_result("ZSTD_CCtx_refThreadPool", !ZSTD_isError(rc));
    /* Held until the CCtx is freed, also after a later ref of NULL: the multi-threading context created with the
     * pool keeps it (repro.c case 3). */
    if (!ZSTD_isError(rc)) cctx_uses_pool = 1;
}

/* advanced streaming initialisers (deprecated; each starts with ZSTD_CCtx_reset(session_only)) */
/* ltl: cctx_lifecycle, cdict_outlives_reference, no_oneshot_during_streaming_session, reset_after_streaming_error, bufferless_compress_session, reset_cstream_after_init */
static void call_ZSTD_initCStream_srcSize(payload in) {
    if (!cctx) return;
    if (!preqed_call("ZSTD_initCStream_srcSize")) return;
    size_t rc = ZSTD_initCStream_srcSize(cctx, level(byte(in, 0)), pledged(byte(in, 1), byte(in, 2)));
    preqed_result("ZSTD_initCStream_srcSize", !ZSTD_isError(rc));
    stream_reset_done(rc);
    if (!ZSTD_isError(rc)) cctx_uses_cdict = 0;   /* "ZSTD_CCtx_refCDict(zcs, NULL); // clear the dictionary (if any)" */
}
/* ltl: cctx_lifecycle, cdict_outlives_reference, no_oneshot_during_streaming_session, reset_after_streaming_error, bufferless_compress_session, reset_cstream_after_init */
static void call_ZSTD_initCStream_usingDict(payload in) {
    if (!cctx) return;
    payload d = dict_or(in);
    if (!preqed_call("ZSTD_initCStream_usingDict")) return;
    size_t rc = ZSTD_initCStream_usingDict(cctx, d.p, d.n, level(byte(in, 1)));
    preqed_result("ZSTD_initCStream_usingDict", !ZSTD_isError(rc));
    stream_reset_done(rc);
    if (!ZSTD_isError(rc)) cctx_uses_cdict = 0;   /* ZSTD_CCtx_loadDictionary replaced the reference */
}
/* ltl: cctx_lifecycle, cdict_outlives_reference, no_oneshot_during_streaming_session, reset_after_streaming_error, bufferless_compress_session, reset_cstream_after_init */
static void call_ZSTD_initCStream_advanced(payload in) {
    if (!cctx) return;
    payload d = dict_or(in);
    ZSTD_parameters params = z_params(rest(in, 3));
    if (!preqed_call("ZSTD_initCStream_advanced")) return;
    size_t rc = ZSTD_initCStream_advanced(cctx, d.p, d.n, params, pledged(byte(in, 1), byte(in, 2)));
    preqed_result("ZSTD_initCStream_advanced", !ZSTD_isError(rc));
    stream_reset_done(rc);
    if (!ZSTD_isError(rc)) cctx_uses_cdict = 0;
}
/* ltl: cctx_lifecycle, cdict_outlives_reference, no_oneshot_during_streaming_session, reset_after_streaming_error, bufferless_compress_session, reset_cstream_after_init */
static void call_ZSTD_initCStream_usingCDict(payload in) {
    (void)in;
    if (!cctx || !cdict) return;
    if (!preqed_call("ZSTD_initCStream_usingCDict")) return;
    size_t rc = ZSTD_initCStream_usingCDict(cctx, cdict);
    preqed_result("ZSTD_initCStream_usingCDict", !ZSTD_isError(rc));
    stream_reset_done(rc);
    if (!ZSTD_isError(rc)) cctx_uses_cdict = 1;   /* "cdict will just be referenced, and must outlive compression session" */
}
/* ltl: cctx_lifecycle, cdict_outlives_reference, no_oneshot_during_streaming_session, reset_after_streaming_error, bufferless_compress_session, reset_cstream_after_init */
static void call_ZSTD_initCStream_usingCDict_advanced(payload in) {
    if (!cctx || !cdict) return;
    if (!preqed_call("ZSTD_initCStream_usingCDict_advanced")) return;
    size_t rc = ZSTD_initCStream_usingCDict_advanced(cctx, cdict, f_params(byte(in, 0)), pledged(byte(in, 1), byte(in, 2)));
    preqed_result("ZSTD_initCStream_usingCDict_advanced", !ZSTD_isError(rc));
    stream_reset_done(rc);
    if (!ZSTD_isError(rc)) cctx_uses_cdict = 1;
}
/* ltl: cctx_lifecycle, no_oneshot_during_streaming_session, reset_after_streaming_error, bufferless_compress_session, reset_cstream_after_init */
static void call_ZSTD_resetCStream(payload in) {
    /* zstd.h: "zcs must be init at least once before using ZSTD_resetCStream()" */
    if (!cctx || !c_inited) return;
    if (!preqed_call("ZSTD_resetCStream")) return;
    size_t rc = ZSTD_resetCStream(cctx, pledged(byte(in, 0), byte(in, 1)));
    preqed_result("ZSTD_resetCStream", !ZSTD_isError(rc));
    stream_reset_done(rc);
}

/* block-level sequence producer */

/* ZSTD_sequenceProducer_F; *state selects the parse of the block:
 *   0: one literals-only sequence
 *   1: every run of a repeated byte becomes a match at offset 1
 *   2: ZSTD_SEQUENCE_PRODUCER_ERROR (zstd falls back or fails, per ZSTD_c_enableSeqProducerFallback)
 * Parses 0 and 1 meet the validity conditions of zstd.h: lengths sum to srcSize, every match is at least
 * ZSTD_MINMATCH_MIN (3) long, offset 1 never reaches before the block, a final literals-only sequence has offset 0.
 * A match is at most 65535 long: a block can encode a single length above 16 bits. */
static size_t producer(void *state, ZSTD_Sequence *out, size_t cap, const void *src, size_t n,
                       const void *dict, size_t dict_size, int compression_level, size_t window_size) {
    const unsigned char *s = src;
    size_t count = 0, lit = 0;
    (void)dict; (void)dict_size; (void)compression_level; (void)window_size;
    if (*(int *)state == 2) return ZSTD_SEQUENCE_PRODUCER_ERROR;
    for (size_t i = 1; *(int *)state == 1 && i < n; ) {
        size_t run = 0;
        while (i + run < n && s[i + run] == s[i + run - 1] && run < 65535) run++;
        if (run < 3) { i++; continue; }
        if (count + 1 >= cap) return ZSTD_SEQUENCE_PRODUCER_ERROR;
        ZSTD_Sequence match = { 1, (unsigned)(i - lit), (unsigned)run, 0 };
        out[count++] = match;
        i += run;
        lit = i;
    }
    if (lit < n) {
        if (count >= cap) return ZSTD_SEQUENCE_PRODUCER_ERROR;
        ZSTD_Sequence last = { 0, (unsigned)(n - lit), 0, 0 };
        out[count++] = last;
    }
    return count;
}
/* ltl: cctx_lifecycle */
static void call_ZSTD_registerSequenceProducer(payload in) {
    if (!cctx) return;
    if (!preqed_call("ZSTD_registerSequenceProducer")) return;
    producer_mode = byte(in, 0) % 3;
    /* bit 7: "The sequence producer can be 'cleared' by registering a NULL function pointer" */
    ZSTD_registerSequenceProducer(cctx, &producer_mode, byte(in, 0) & 128 ? NULL : producer);
    preqed_result("ZSTD_registerSequenceProducer", 1);
}

/* buffer-less streaming compression and block-level compression (deprecated) */

/* a ZSTD_compressBegin* variant returned: the previous session is over, a successful one starts a new frame */
static void begin_done(size_t rc, int kind) {
    c_begun = ZSTD_isError(rc) ? 0 : kind;
    if (!ZSTD_isError(rc)) compressed_len = bl_src_len = 0;
}
/* input of a buffer-less call, appended to bl_src: contiguous with the blocks before it and as long-lived */
static const unsigned char *bl_append(payload src) {
    memcpy(bl_src + bl_src_len, src.p, src.n);
    bl_src_len += src.n;
    return bl_src + bl_src_len - src.n;
}
/* ltl: cctx_lifecycle, no_oneshot_during_streaming_session, bufferless_compress_session */
static void call_ZSTD_compressBegin(payload in) {
    if (!cctx || c_streaming) return;
    if (!preqed_call("ZSTD_compressBegin")) return;
    size_t rc = ZSTD_compressBegin(cctx, level(byte(in, 0)));
    preqed_result("ZSTD_compressBegin", !ZSTD_isError(rc));
    begin_done(rc, 1);
}
/* ltl: cctx_lifecycle, no_oneshot_during_streaming_session, bufferless_compress_session */
static void call_ZSTD_compressBegin_usingDict(payload in) {
    if (!cctx || c_streaming) return;
    payload d = dict_or(in);
    if (!preqed_call("ZSTD_compressBegin_usingDict")) return;
    /* the dictionary is referenced for the whole session: bl_dict is rewritten only here, where the old session ends */
    memcpy(bl_dict, d.p, d.n);
    size_t rc = ZSTD_compressBegin_usingDict(cctx, bl_dict, d.n, level(byte(in, 1)));
    preqed_result("ZSTD_compressBegin_usingDict", !ZSTD_isError(rc));
    begin_done(rc, 1);
}
/* ltl: cctx_lifecycle, no_oneshot_during_streaming_session, bufferless_compress_session */
static void call_ZSTD_compressBegin_advanced(payload in) {
    if (!cctx || c_streaming) return;
    payload d = dict_or(in);
    ZSTD_parameters params = z_params(rest(in, 3));
    if (!preqed_call("ZSTD_compressBegin_advanced")) return;
    memcpy(bl_dict, d.p, d.n);
    size_t rc = ZSTD_compressBegin_advanced(cctx, bl_dict, d.n, params, pledged(byte(in, 1), byte(in, 2)));
    preqed_result("ZSTD_compressBegin_advanced", !ZSTD_isError(rc));
    begin_done(rc, 1);
}
/* ltl: cctx_lifecycle, cdict_outlives_reference, no_oneshot_during_streaming_session, bufferless_compress_session */
static void call_ZSTD_compressBegin_usingCDict(payload in) {
    (void)in;
    if (!cctx || !cdict || c_streaming) return;
    if (!preqed_call("ZSTD_compressBegin_usingCDict")) return;
    size_t rc = ZSTD_compressBegin_usingCDict(cctx, cdict);
    preqed_result("ZSTD_compressBegin_usingCDict", !ZSTD_isError(rc));
    begin_done(rc, 2);   /* the session may search the CDict's tables in place: it must outlive the session */
}
/* ltl: cctx_lifecycle, cdict_outlives_reference, no_oneshot_during_streaming_session, bufferless_compress_session */
static void call_ZSTD_compressBegin_usingCDict_advanced(payload in) {
    if (!cctx || !cdict || c_streaming) return;
    if (!preqed_call("ZSTD_compressBegin_usingCDict_advanced")) return;
    size_t rc = ZSTD_compressBegin_usingCDict_advanced(cctx, cdict, f_params(byte(in, 0)), pledged(byte(in, 1), byte(in, 2)));
    preqed_result("ZSTD_compressBegin_usingCDict_advanced", !ZSTD_isError(rc));
    begin_done(rc, 2);
}
/* ltl: cctx_lifecycle, bufferless_compress_session */
static void call_ZSTD_compressContinue(payload in) {
    payload src = expand(in);
    if (!cctx || !c_begun || src.n > sizeof bl_src - bl_src_len) return;
    if (!preqed_call("ZSTD_compressContinue")) return;
    size_t rc = ZSTD_compressContinue(cctx, compressed + compressed_len, OUT_CAP - compressed_len, bl_append(src), src.n);
    preqed_result("ZSTD_compressContinue", !ZSTD_isError(rc));
    /* zstd.h: "ZSTD_compressContinue() doesn't guarantee recover after a failed compression" */
    if (ZSTD_isError(rc)) c_begun = 0;
    else compressed_len += rc;
}
/* ltl: cctx_lifecycle, bufferless_compress_session */
static void call_ZSTD_compressEnd(payload in) {
    payload src = expand(in);
    if (!cctx || !c_begun || src.n > sizeof bl_src - bl_src_len) return;
    if (!preqed_call("ZSTD_compressEnd")) return;
    size_t rc = ZSTD_compressEnd(cctx, compressed + compressed_len, OUT_CAP - compressed_len, bl_append(src), src.n);
    preqed_result("ZSTD_compressEnd", !ZSTD_isError(rc));
    if (!ZSTD_isError(rc)) compressed_len += rc;
    c_begun = 0;   /* the frame is finished; "ZSTD_CCtx object can be reused (ZSTD_compressBegin()) to compress again" */
}
/* ltl: cctx_lifecycle, bufferless_compress_session */
static void call_ZSTD_getBlockSize(payload in) {
    (void)in;
    if (!cctx || !c_begun) return;
    REPORT(ZSTD_getBlockSize, ZSTD_getBlockSize(cctx), rc <= ZSTD_BLOCKSIZE_MAX);
}
/* ltl: cctx_lifecycle, bufferless_compress_session */
static void call_ZSTD_compressBlock(payload in) {
    if (!cctx || !c_begun) return;
    payload src = expand(in);
    /* block API: "Block size is limited, it must be <= ZSTD_getBlockSize()" */
    size_t max = ZSTD_getBlockSize(cctx);
    if (src.n > max) src.n = max;
    if (src.n > sizeof bl_src - bl_src_len) return;
    if (!preqed_call("ZSTD_compressBlock")) return;
    size_t rc = ZSTD_compressBlock(cctx, compressed, OUT_CAP, bl_append(src), src.n);
    preqed_result("ZSTD_compressBlock", !ZSTD_isError(rc));
    if (ZSTD_isError(rc)) c_begun = 0;
    else if (rc) compressed_len = rc;   /* 0: not compressible, "nothing is produced into `dst`" */
}
/* ltl: cctx_lifecycle, bufferless_compress_session */
static void call_ZSTD_copyCCtx(payload in) {
    if (!cctx || !c_begun) return;
    payload src = expand(rest(in, 1));
    /* cctx is the prepared context (copying works only before its first ZSTD_compressContinue, stage_wrong after).
     * The duplicate is private: it compresses one frame of the pledged size into scratch and is freed. */
    ZSTD_CCtx *copy = ZSTD_createCCtx();
    if (!copy) return;
    if (preqed_call("ZSTD_copyCCtx")) {
        size_t rc = ZSTD_copyCCtx(copy, cctx, byte(in, 0) & 1 ? ZSTD_CONTENTSIZE_UNKNOWN : src.n);
        preqed_result("ZSTD_copyCCtx", !ZSTD_isError(rc));
        if (!ZSTD_isError(rc)) ZSTD_compressEnd(copy, scratch, OUT_CAP, src.p, src.n);
    }
    ZSTD_freeCCtx(copy);
}

/* sequence-level API */
/* ltl: sequence_array_format */
static void call_ZSTD_generateSequences(payload in) {
    payload src = expand(rest(in, 1));
    /* A private CCtx: ZSTD_generateSequences() never disarms the sequence collector it installs, so every later
     * compression on the same context writes into the caller's array (repro.c case 1). */
    ZSTD_CCtx *zc = ZSTD_createCCtx();
    size_t cap = ZSTD_sequenceBound(src.n);   /* "upper-bound for the number of sequences that can be generated" */
    ZSTD_Sequence *out = malloc(cap * sizeof *out);
    if (zc && out && !ZSTD_isError(ZSTD_CCtx_setParameter(zc, ZSTD_c_compressionLevel, level(byte(in, 0)))) &&
        preqed_call("ZSTD_generateSequences")) {
        size_t rc = ZSTD_generateSequences(zc, out, cap, src.p, src.n);
        preqed_result("ZSTD_generateSequences", !ZSTD_isError(rc));
        if (!ZSTD_isError(rc)) {
            free(seqs);
            seqs = out;
            out = NULL;
            seq_count = rc;
            seq_merged = 0;
            seq_level = level(byte(in, 0));
            memcpy(seq_src, src.p, src.n);
            seq_src_len = src.n;
        }
    }
    free(out);
    ZSTD_freeCCtx(zc);
}
/* ltl: sequence_array_format */
static void call_ZSTD_mergeBlockDelimiters(payload in) {
    (void)in;
    if (!seqs) return;
    if (!preqed_call("ZSTD_mergeBlockDelimiters")) return;
    seq_count = ZSTD_mergeBlockDelimiters(seqs, seq_count);
    preqed_result("ZSTD_mergeBlockDelimiters", 1);
    seq_merged = 1;
}
/* ltl: cctx_lifecycle, no_oneshot_during_streaming_session, reset_after_streaming_error, bufferless_compress_session, sequence_array_format */
static void call_ZSTD_compressSequences(payload in) {
    (void)in;
    if (!cctx || !seqs || c_streaming) return;
    /* zstd.h: the array must match ZSTD_c_blockDelimiters ("Behavior is undefined if no block delimiters are
     * provided" in explicit mode), and without ZSTD_c_validateSequences "Invalid Sequences cause undefined behavior":
     * the array was generated under other window / minMatch settings than this CCtx may have, so validation is on. */
    if (ZSTD_isError(ZSTD_CCtx_setParameter(cctx, ZSTD_c_blockDelimiters,
                                            seq_merged ? ZSTD_sf_noBlockDelimiters : ZSTD_sf_explicitBlockDelimiters)) ||
        ZSTD_isError(ZSTD_CCtx_setParameter(cctx, ZSTD_c_validateSequences, 1)))
        return;
    if (!preqed_call("ZSTD_compressSequences")) return;
    c_begun = 0;
    size_t rc = ZSTD_compressSequences(cctx, compressed, OUT_CAP, seqs, seq_count, seq_src, seq_src_len);
    preqed_result("ZSTD_compressSequences", !ZSTD_isError(rc));
    if (!ZSTD_isError(rc)) compressed_len = rc;
    /* ZSTD_compressSequences() returns with the context still inside the streaming session it opened (stage "load",
     * no reset at the end): a one-shot followed by a streaming call then crashes (repro.c case 4). Until a session
     * reset the harness treats the context as mid-session (no one-shot) and as failed (no streaming call). */
    c_streaming = c_failed = 1;
}
/* ltl: sequence_array_format */
static void call_ZSTD_compressSequencesAndLiterals(payload in) {
    (void)in;
    if (!seqs || seq_merged) return;   /* zstd.h: "Only supports explicit delimiter mode" */
    /* zstd.h: the literals are laid out in one buffer, litSize == sum of all litLength, and the buffer is at least
     * 8 bytes larger than litSize; decompressedSize is the size of the source the sequences describe */
    unsigned char *lits = malloc(seq_src_len + 8);
    size_t lit_size = 0, pos = 0;
    /* The sequences are trusted ("does not support Sequences validation"): a private CCtx with the level they were
     * generated at, explicit delimiters, and the defaults for the rest (no validation, no checksum). */
    ZSTD_CCtx *zc = ZSTD_createCCtx();
    int usable = lits && zc && !ZSTD_isError(ZSTD_CCtx_setParameter(zc, ZSTD_c_compressionLevel, seq_level)) &&
                 !ZSTD_isError(ZSTD_CCtx_setParameter(zc, ZSTD_c_blockDelimiters, ZSTD_sf_explicitBlockDelimiters));
    for (size_t i = 0; usable && i < seq_count; i++) {
        if (seqs[i].litLength > seq_src_len - pos) { usable = 0; break; }
        memcpy(lits + lit_size, seq_src + pos, seqs[i].litLength);
        lit_size += seqs[i].litLength;
        pos += seqs[i].litLength;
        if (seqs[i].matchLength > seq_src_len - pos) { usable = 0; break; }
        pos += seqs[i].matchLength;
    }
    if (usable && preqed_call("ZSTD_compressSequencesAndLiterals")) {
        size_t rc = ZSTD_compressSequencesAndLiterals(zc, compressed, OUT_CAP, seqs, seq_count, lits, lit_size, seq_src_len + 8, seq_src_len);
        preqed_result("ZSTD_compressSequencesAndLiterals", !ZSTD_isError(rc));
        if (!ZSTD_isError(rc)) compressed_len = rc;
    }
    ZSTD_freeCCtx(zc);
    free(lits);
}

/* CCtx parameter object */
/* ltl: cctx_params_lifecycle */
static void call_ZSTD_createCCtxParams(payload in) {
    (void)in;
    if (cparams) return;
    if (!preqed_call("ZSTD_createCCtxParams")) return;
    cparams = ZSTD_createCCtxParams();
    preqed_result("ZSTD_createCCtxParams", cparams != NULL);
}
/* ltl: cctx_params_lifecycle */
static void call_ZSTD_freeCCtxParams(payload in) {
    (void)in;
    if (!cparams) return;
    REPORT(ZSTD_freeCCtxParams, ZSTD_freeCCtxParams(cparams), rc == 0);
    cparams = NULL;
}
/* ltl: cctx_params_lifecycle */
static void call_ZSTD_CCtxParams_reset(payload in) {
    (void)in;
    if (!cparams) return;
    REPORT_OK(ZSTD_CCtxParams_reset, ZSTD_CCtxParams_reset(cparams));
}
/* ltl: cctx_params_lifecycle */
static void call_ZSTD_CCtxParams_init(payload in) {
    if (!cparams) return;
    REPORT_OK(ZSTD_CCtxParams_init, ZSTD_CCtxParams_init(cparams, level(byte(in, 0))));
}
/* ltl: cctx_params_lifecycle */
static void call_ZSTD_CCtxParams_init_advanced(payload in) {
    if (!cparams) return;
    ZSTD_parameters params = z_params(in);
    REPORT_OK(ZSTD_CCtxParams_init_advanced, ZSTD_CCtxParams_init_advanced(cparams, params));
}
/* ltl: cctx_params_lifecycle */
static void call_ZSTD_CCtxParams_setParameter(payload in) {
    if (!cparams) return;
    ZSTD_cParameter p = c_param(byte(in, 0));
    REPORT_OK(ZSTD_CCtxParams_setParameter, ZSTD_CCtxParams_setParameter(cparams, p, c_value(p, in)));
}
/* ltl: cctx_params_lifecycle */
static void call_ZSTD_CCtxParams_getParameter(payload in) {
    if (!cparams) return;
    int value;
    REPORT_OK(ZSTD_CCtxParams_getParameter, ZSTD_CCtxParams_getParameter(cparams, c_param(byte(in, 0)), &value));
}
/* ltl: cctx_params_lifecycle */
static void call_ZSTD_CCtxParams_registerSequenceProducer(payload in) {
    if (!cparams) return;
    if (!preqed_call("ZSTD_CCtxParams_registerSequenceProducer")) return;
    producer_mode = byte(in, 0) % 3;
    ZSTD_CCtxParams_registerSequenceProducer(cparams, &producer_mode, byte(in, 0) & 128 ? NULL : producer);
    preqed_result("ZSTD_CCtxParams_registerSequenceProducer", 1);
}
/* ltl: cctx_lifecycle, cctx_params_lifecycle */
static void call_ZSTD_CCtx_setParametersUsingCCtxParams(payload in) {
    (void)in;
    if (!cctx || !cparams) return;
    /* zstd.h ZSTD_initStatic*() Limitation 2: "static cctx currently not compatible with multi-threading" (this entry
     * point copies nbWorkers unchecked, unlike ZSTD_CCtx_setParameter) */
    int workers = 0;
    if (cctx_static && (ZSTD_isError(ZSTD_CCtxParams_getParameter(cparams, ZSTD_c_nbWorkers, &workers)) || workers)) return;
    REPORT_OK(ZSTD_CCtx_setParametersUsingCCtxParams, ZSTD_CCtx_setParametersUsingCCtxParams(cctx, cparams));
}
/* ltl: cctx_params_lifecycle */
static void call_ZSTD_estimateCCtxSize_usingCCtxParams(payload in) {
    (void)in;
    if (!cparams) return;
    REPORT_OK(ZSTD_estimateCCtxSize_usingCCtxParams, ZSTD_estimateCCtxSize_usingCCtxParams(cparams));
}
/* ltl: cctx_params_lifecycle */
static void call_ZSTD_estimateCStreamSize_usingCCtxParams(payload in) {
    (void)in;
    if (!cparams) return;
    REPORT_OK(ZSTD_estimateCStreamSize_usingCCtxParams, ZSTD_estimateCStreamSize_usingCCtxParams(cparams));
}

/* objects in caller-owned workspaces (zstd.h ZSTD_initStatic*(): the workspace is 8-byte aligned, which malloc
 * guarantees, and sized by ZSTD_estimate*Size(); the object lives until cleanup() releases the workspace) */
/* ltl: cctx_lifecycle, static_objects_have_no_free */
static void call_ZSTD_initStaticCCtx(payload in) {
    if (cctx) return;
    ZSTD_compressionParameters cp = level_cparams(byte(in, 0));
    /* bit 0 of byte 1: budget for streaming, otherwise for one-shot compression only */
    size_t size = byte(in, 1) & 1 ? ZSTD_estimateCStreamSize_usingCParams(cp) : ZSTD_estimateCCtxSize_usingCParams(cp);
    void *ws = malloc(size);
    if (!ws) return;
    if (preqed_call("ZSTD_initStaticCCtx")) {
        cctx = ZSTD_initStaticCCtx(ws, size);
        preqed_result("ZSTD_initStaticCCtx", cctx != NULL);
        if (cctx) {
            cctx_ws = ws;
            cctx_static = 1;
            return;
        }
    }
    free(ws);
}
/* ltl: cctx_lifecycle, static_objects_have_no_free */
static void call_ZSTD_initStaticCStream(payload in) {
    if (cctx) return;
    size_t size = ZSTD_estimateCStreamSize_usingCParams(level_cparams(byte(in, 0)));
    void *ws = malloc(size);
    if (!ws) return;
    if (preqed_call("ZSTD_initStaticCStream")) {
        cctx = ZSTD_initStaticCStream(ws, size);
        preqed_result("ZSTD_initStaticCStream", cctx != NULL);
        if (cctx) {
            cctx_ws = ws;
            cctx_static = 1;
            return;
        }
    }
    free(ws);
}
/* ltl: dctx_lifecycle, static_objects_have_no_free */
static void call_ZSTD_initStaticDCtx(payload in) {
    if (dctx) return;
    /* bit 7: budget for one-shot decoding, otherwise for streaming with a 1 KiB..128 KiB window */
    size_t size = byte(in, 0) & 128 ? ZSTD_estimateDCtxSize() : ZSTD_estimateDStreamSize((size_t)1 << (10 + byte(in, 0) % 8));
    void *ws = malloc(size);
    if (!ws) return;
    if (preqed_call("ZSTD_initStaticDCtx")) {
        dctx = ZSTD_initStaticDCtx(ws, size);
        preqed_result("ZSTD_initStaticDCtx", dctx != NULL);
        if (dctx) {
            dctx_ws = ws;
            dctx_static = 1;
            return;
        }
    }
    free(ws);
}
/* ltl: dctx_lifecycle, static_objects_have_no_free */
static void call_ZSTD_initStaticDStream(payload in) {
    if (dctx) return;
    size_t size = ZSTD_estimateDStreamSize((size_t)1 << (10 + byte(in, 0) % 8));
    void *ws = malloc(size);
    if (!ws) return;
    if (preqed_call("ZSTD_initStaticDStream")) {
        dctx = ZSTD_initStaticDStream(ws, size);
        preqed_result("ZSTD_initStaticDStream", dctx != NULL);
        if (dctx) {
            dctx_ws = ws;
            dctx_static = 1;
            return;
        }
    }
    free(ws);
}
static ZSTD_dictContentType_e content_type(uint8_t b) {
    static const ZSTD_dictContentType_e t[] = { ZSTD_dct_auto, ZSTD_dct_rawContent, ZSTD_dct_fullDict };
    return t[b % 3];
}
/* ltl: cdict_outlives_reference, static_objects_have_no_free */
static void call_ZSTD_initStaticCDict(payload in) {
    if (cdict) return;
    payload d = dict_or(in);
    ZSTD_compressionParameters cp = level_cparams(byte(in, 1));
    ZSTD_dictLoadMethod_e method = byte(in, 0) & 1 ? ZSTD_dlm_byRef : ZSTD_dlm_byCopy;
    size_t size = ZSTD_estimateCDictSize_advanced(d.n, cp, method);
    void *ws = malloc(size);
    unsigned char *copy = dup_bytes(d);   /* what a ZSTD_dlm_byRef dictionary references */
    if (ws && copy && preqed_call("ZSTD_initStaticCDict")) {
        /* the slot is shared with heap CDicts, which ZSTD_freeCDict needs non-const; cdict_static keeps this one away from it */
        cdict = (ZSTD_CDict *)ZSTD_initStaticCDict(ws, size, copy, d.n, method, content_type(byte(in, 2)), cp);
        preqed_result("ZSTD_initStaticCDict", cdict != NULL);
        if (cdict) {
            cdict_ws = ws;
            cdict_ref = copy;
            cdict_static = 1;
            return;
        }
    }
    free(ws);
    free(copy);
}
/* ltl: ddict_outlives_reference, static_objects_have_no_free */
static void call_ZSTD_initStaticDDict(payload in) {
    if (ddict) return;
    payload d = dict_or(in);
    ZSTD_dictLoadMethod_e method = byte(in, 0) & 1 ? ZSTD_dlm_byRef : ZSTD_dlm_byCopy;
    size_t size = ZSTD_estimateDDictSize(d.n, method);
    void *ws = malloc(size);
    unsigned char *copy = dup_bytes(d);
    if (ws && copy && preqed_call("ZSTD_initStaticDDict")) {
        ddict = (ZSTD_DDict *)ZSTD_initStaticDDict(ws, size, copy, d.n, method, content_type(byte(in, 1)));
        preqed_result("ZSTD_initStaticDDict", ddict != NULL);
        if (ddict) {
            ddict_ws = ws;
            ddict_ref = copy;
            ddict_static = 1;
            return;
        }
    }
    free(ws);
    free(copy);
}

/* dictionaries by reference */
/* ltl: cdict_outlives_reference */
static void call_ZSTD_createCDict_byReference(payload in) {
    if (cdict) return;
    payload d = dict_or(in);
    unsigned char *copy = dup_bytes(d);
    if (copy && preqed_call("ZSTD_createCDict_byReference")) {
        cdict = ZSTD_createCDict_byReference(copy, d.n, level(byte(in, 1)));
        preqed_result("ZSTD_createCDict_byReference", cdict != NULL);
        if (cdict) {
            cdict_ref = copy;
            return;
        }
    }
    free(copy);
}
/* ltl: ddict_outlives_reference */
static void call_ZSTD_createDDict_byReference(payload in) {
    if (ddict) return;
    payload d = dict_or(in);
    unsigned char *copy = dup_bytes(d);
    if (copy && preqed_call("ZSTD_createDDict_byReference")) {
        ddict = ZSTD_createDDict_byReference(copy, d.n);
        preqed_result("ZSTD_createDDict_byReference", ddict != NULL);
        if (ddict) {
            ddict_ref = copy;
            return;
        }
    }
    free(copy);
}

/* decompression context, experimental */
/* ltl: dctx_lifecycle */
static void call_ZSTD_createDCtx_advanced(payload in) {
    if (dctx) return;
    if (!preqed_call("ZSTD_createDCtx_advanced")) return;
    dctx = ZSTD_createDCtx_advanced(custom_mem(byte(in, 0)));
    preqed_result("ZSTD_createDCtx_advanced", dctx != NULL);
}
/* ltl: dctx_lifecycle */
static void call_ZSTD_createDStream_advanced(payload in) {
    if (dctx) return;
    if (!preqed_call("ZSTD_createDStream_advanced")) return;
    dctx = ZSTD_createDStream_advanced(custom_mem(byte(in, 0)));
    preqed_result("ZSTD_createDStream_advanced", dctx != NULL);
}
/* ltl: dctx_lifecycle */
static void call_ZSTD_DCtx_getParameter(payload in) {
    if (!dctx) return;
    static const ZSTD_dParameter p[] = {
        ZSTD_d_windowLogMax, ZSTD_d_format, ZSTD_d_stableOutBuffer, ZSTD_d_forceIgnoreChecksum,
        ZSTD_d_refMultipleDDicts, ZSTD_d_disableHuffmanAssembly, ZSTD_d_maxBlockSize,
    };
    int value;
    REPORT_OK(ZSTD_DCtx_getParameter, ZSTD_DCtx_getParameter(dctx, p[byte(in, 0) % (sizeof p / sizeof p[0])], &value));
}
/* ltl: dctx_lifecycle */
static void call_ZSTD_DCtx_setFormat(payload in) {
    if (!dctx) return;
    REPORT_OK(ZSTD_DCtx_setFormat, ZSTD_DCtx_setFormat(dctx, byte(in, 0) & 1 ? ZSTD_f_zstd1_magicless : ZSTD_f_zstd1));
}
/* ltl: dctx_lifecycle */
static void call_ZSTD_DCtx_setMaxWindowSize(payload in) {
    if (!dctx) return;
    /* 0..127 MiB: below 1 KiB is the documented error, the top stays under the default limit (1 << 27) */
    REPORT_OK(ZSTD_DCtx_setMaxWindowSize, ZSTD_DCtx_setMaxWindowSize(dctx, (size_t)byte(in, 0) << byte(in, 1) % 20));
}
/* ltl: dctx_lifecycle, ddict_outlives_reference, static_objects_have_no_free */
static void call_ZSTD_DCtx_loadDictionary_byReference(payload in) {
    if (!dctx || dctx_static) return;   /* internal dictionary creation: see call_ZSTD_DCtx_loadDictionary */
    unsigned char *copy = dup_bytes(dict_or(in));
    size_t size = dict_or(in).n;
    if (!copy) return;
    if (preqed_call("ZSTD_DCtx_loadDictionary_byReference")) {
        size_t rc = ZSTD_DCtx_loadDictionary_byReference(dctx, copy, size);
        preqed_result("ZSTD_DCtx_loadDictionary_byReference", !ZSTD_isError(rc));
        if (!ZSTD_isError(rc)) {
            free(dctx_dict_ref);
            dctx_dict_ref = copy;
            dctx_uses_ddict = 0;
            return;
        }
    }
    free(copy);
}
/* ltl: dctx_lifecycle, block_decode_after_begin */
static void call_ZSTD_decompressStream_simpleArgs(payload in) {
    if (!dctx) return;
    payload src = compressed_or(in);
    size_t dst_pos = 0, src_pos = 0;
    /* same output window choice as call_ZSTD_decompressStream */
    size_t cap = byte(in, 0) & 8 ? 1 + byte(in, 1) * 16u : OUT_CAP;
    if (!preqed_call("ZSTD_decompressStream_simpleArgs")) return;
    size_t rc = ZSTD_decompressStream_simpleArgs(dctx, decompressed, cap, &dst_pos, src.p, src.n, &src_pos);
    preqed_result("ZSTD_decompressStream_simpleArgs", !ZSTD_isError(rc));
    d_begun = 0;
    d_streaming = rc != 0;
}
/* ltl: dctx_lifecycle, ddict_outlives_reference, static_objects_have_no_free, block_decode_after_begin */
static void call_ZSTD_initDStream_usingDict(payload in) {
    if (!dctx || dctx_static) return;   /* internal dictionary creation: see call_ZSTD_DCtx_loadDictionary */
    payload d = dict_or(in);
    if (!preqed_call("ZSTD_initDStream_usingDict")) return;
    size_t rc = ZSTD_initDStream_usingDict(dctx, d.p, d.n);
    preqed_result("ZSTD_initDStream_usingDict", !ZSTD_isError(rc));
    d_begun = d_streaming = 0;
    if (!ZSTD_isError(rc)) dctx_uses_ddict = 0;
}
/* ltl: dctx_lifecycle, ddict_outlives_reference, block_decode_after_begin */
static void call_ZSTD_initDStream_usingDDict(payload in) {
    (void)in;
    if (!dctx || !ddict) return;
    if (!preqed_call("ZSTD_initDStream_usingDDict")) return;
    size_t rc = ZSTD_initDStream_usingDDict(dctx, ddict);
    preqed_result("ZSTD_initDStream_usingDDict", !ZSTD_isError(rc));
    d_begun = d_streaming = 0;
    if (!ZSTD_isError(rc)) dctx_uses_ddict = 1;   /* "ddict is referenced, it must outlive decompression session" */
}
/* ltl: dctx_lifecycle, block_decode_after_begin */
static void call_ZSTD_resetDStream(payload in) {
    (void)in;
    if (!dctx) return;
    REPORT_OK(ZSTD_resetDStream, ZSTD_resetDStream(dctx));
    d_begun = d_streaming = 0;
}

/* block-level decompression (deprecated) */
/* ltl: dctx_lifecycle, block_decode_after_begin */
static void call_ZSTD_decompressBegin(payload in) {
    (void)in;
    if (!dctx) return;
    if (!preqed_call("ZSTD_decompressBegin")) return;
    size_t rc = ZSTD_decompressBegin(dctx);
    preqed_result("ZSTD_decompressBegin", !ZSTD_isError(rc));
    d_begun = !ZSTD_isError(rc);
    blocks_len = 0;
}
/* ltl: dctx_lifecycle, block_decode_after_begin */
static void call_ZSTD_decompressBlock(payload in) {
    /* block API: "It is necessary to init context before starting"; a block regenerates at most ZSTD_BLOCKSIZE_MAX bytes */
    if (!dctx || !d_begun || sizeof blocks - blocks_len < ZSTD_BLOCKSIZE_MAX) return;
    payload src = compressed_or(in);
    if (!preqed_call("ZSTD_decompressBlock")) return;
    size_t rc = ZSTD_decompressBlock(dctx, blocks + blocks_len, sizeof blocks - blocks_len, src.p, src.n);
    preqed_result("ZSTD_decompressBlock", !ZSTD_isError(rc));
    if (ZSTD_isError(rc)) d_begun = 0;
    else blocks_len += rc;
}
/* ltl: dctx_lifecycle, block_decode_after_begin */
static void call_ZSTD_insertBlock(payload in) {
    if (!dctx || !d_begun || in.n > sizeof blocks - blocks_len) return;
    if (!preqed_call("ZSTD_insertBlock")) return;
    /* "insert uncompressed block into `dctx` history": it joins the regenerated blocks */
    memcpy(blocks + blocks_len, in.p, in.n);
    size_t rc = ZSTD_insertBlock(dctx, blocks + blocks_len, in.n);
    preqed_result("ZSTD_insertBlock", !ZSTD_isError(rc));
    blocks_len += in.n;
}
static void call_ZSTD_copyDCtx(payload in) {
    payload d = dict_or(in);
    payload src = compressed_or(in);
    /* Private contexts: ZSTD_copyDCtx() also copies the ownership fields (ddictLocal, staticSize), so duplicating a
     * context that owns a dictionary frees it twice (repro.c case 2). The prepared context only references `d`. */
    ZSTD_DCtx *prepared = ZSTD_createDCtx();
    ZSTD_DCtx *copy = ZSTD_createDCtx();
    if (prepared && copy && !ZSTD_isError(ZSTD_decompressBegin_usingDict(prepared, d.p, d.n)) && preqed_call("ZSTD_copyDCtx")) {
        ZSTD_copyDCtx(copy, prepared);
        preqed_result("ZSTD_copyDCtx", 1);
        ZSTD_decompressBlock(copy, scratch, OUT_CAP, src.p, src.n);   /* the duplicate decodes with the prepared state */
    }
    ZSTD_freeDCtx(copy);
    ZSTD_freeDCtx(prepared);
}

/* dictionary builder, experimental */

/* training samples: the expanded payload split into 1..32 equal samples; 0 below 64 bytes (nothing to train on) */
static unsigned split_samples(payload samples, uint8_t b, size_t sizes[32]) {
    unsigned count = 1 + b % 32;
    if (samples.n < 64) return 0;
    for (unsigned i = 0; i < count; i++) sizes[i] = samples.n / count;
    return count;
}
/* notificationLevel 0: the trainers print to stderr otherwise */
static ZDICT_params_t zdict_params(uint8_t b) {
    ZDICT_params_t p = { level(b), 0, b };
    return p;
}
/* a dictionary trained into scratch becomes dict_buf */
static void keep_dict(size_t rc) {
    if (ZDICT_isError(rc) || !rc) return;
    memcpy(dict_buf, scratch, rc);
    dict_len = rc;
}
static void call_ZDICT_trainFromBuffer_cover(payload in) {
    payload samples = expand(rest(in, 3));
    size_t sizes[32];
    unsigned count = split_samples(samples, byte(in, 0), sizes);
    if (!count) return;
    /* zdict.h: k and d are required, 0 < d <= k (reasonable k 16..2048+, d 6..16); other pairs are the documented error */
    ZDICT_cover_params_t params;
    memset(&params, 0, sizeof params);
    params.k = byte(in, 1) * 8u;
    params.d = byte(in, 2) % 20;
    params.zParams = zdict_params(byte(in, 1));
    if (!preqed_call("ZDICT_trainFromBuffer_cover")) return;
    size_t rc = ZDICT_trainFromBuffer_cover(scratch, sizeof dict_buf, samples.p, sizes, count, params);
    preqed_result("ZDICT_trainFromBuffer_cover", !ZDICT_isError(rc));
    keep_dict(rc);
}
static void call_ZDICT_optimizeTrainFromBuffer_cover(payload in) {
    payload samples = expand(rest(in, 3));
    size_t sizes[32];
    unsigned count = split_samples(samples, byte(in, 0), sizes);
    if (!count) return;
    /* zdict.h: k = 0 and d = 0 make the optimizer search (d in {6, 8}, k in [50, 2000]); 1..4 steps instead of the
     * default 40 and 1..2 threads bound the time of one call; splitPoint 0 is the default (1.0) */
    uint8_t b = byte(in, 1);
    ZDICT_cover_params_t params;
    memset(&params, 0, sizeof params);
    params.k = b & 1 ? 0 : 16 + byte(in, 2) * 8u;
    params.d = b & 2 ? 0 : 6 + (b >> 2 & 1) * 2;
    params.steps = 1 + (b >> 3) % 4;
    params.nbThreads = 1 + (b >> 5 & 1);
    params.splitPoint = b >> 6 & 1 ? 0.5 : 0.0;
    params.shrinkDict = b >> 7;
    params.zParams = zdict_params(byte(in, 2));
    if (!preqed_call("ZDICT_optimizeTrainFromBuffer_cover")) return;
    size_t rc = ZDICT_optimizeTrainFromBuffer_cover(scratch, sizeof dict_buf, samples.p, sizes, count, &params);
    preqed_result("ZDICT_optimizeTrainFromBuffer_cover", !ZDICT_isError(rc));
    keep_dict(rc);
}
static void call_ZDICT_trainFromBuffer_fastCover(payload in) {
    payload samples = expand(rest(in, 5));
    size_t sizes[32];
    unsigned count = split_samples(samples, byte(in, 0), sizes);
    if (!count) return;
    /* zdict.h: d and k are required; f is the log of the frequency array, "requires 6 * 2^f bytes of memory" with
     * f <= 31: capped at 20, the default (6 MiB); accel 1..10 is valid, 0 the default, 11 the documented error */
    ZDICT_fastCover_params_t params;
    memset(&params, 0, sizeof params);
    params.k = byte(in, 1) * 8u;
    params.d = byte(in, 2) % 10;
    params.f = byte(in, 3) % 21;
    params.accel = byte(in, 4) % 12;
    params.zParams = zdict_params(byte(in, 1));
    if (!preqed_call("ZDICT_trainFromBuffer_fastCover")) return;
    size_t rc = ZDICT_trainFromBuffer_fastCover(scratch, sizeof dict_buf, samples.p, sizes, count, params);
    preqed_result("ZDICT_trainFromBuffer_fastCover", !ZDICT_isError(rc));
    keep_dict(rc);
}
static void call_ZDICT_trainFromBuffer_legacy(payload in) {
    payload samples = expand(rest(in, 2));
    size_t sizes[32];
    unsigned count = split_samples(samples, byte(in, 0), sizes);
    if (!count) return;
    /* selectivityLevel: "0 means default; larger => select more => larger dictionary" */
    ZDICT_legacy_params_t params = { byte(in, 1) % 16, zdict_params(byte(in, 1)) };
    if (!preqed_call("ZDICT_trainFromBuffer_legacy")) return;
    size_t rc = ZDICT_trainFromBuffer_legacy(scratch, sizeof dict_buf, samples.p, sizes, count, params);
    preqed_result("ZDICT_trainFromBuffer_legacy", !ZDICT_isError(rc));
    keep_dict(rc);
}
static void call_ZDICT_addEntropyTablesFromBuffer(payload in) {
    payload samples = expand(rest(in, 1));
    size_t sizes[32];
    unsigned count = split_samples(samples, byte(in, 0), sizes);
    if (!count) return;
    /* zdict.c: the raw content sits at the end of the buffer (dictBuffer + dictBufferCapacity - dictContentSize) and
     * the header with the entropy tables is written in front of it; at least half of the 64 KiB is left for that */
    size_t content = samples.n / 2 < sizeof dict_buf / 2 ? samples.n / 2 : sizeof dict_buf / 2;
    if (!preqed_call("ZDICT_addEntropyTablesFromBuffer")) return;
    memcpy(scratch + sizeof dict_buf - content, samples.p, content);
    size_t rc = ZDICT_addEntropyTablesFromBuffer(scratch, content, sizeof dict_buf, samples.p, sizes, count);
    preqed_result("ZDICT_addEntropyTablesFromBuffer", !ZDICT_isError(rc));
    keep_dict(rc);
}

/* dispatch */

static void (*const api[])(payload) = {
    call_ZSTD_versionNumber, call_ZSTD_versionString, call_ZSTD_minCLevel, call_ZSTD_maxCLevel,
    call_ZSTD_defaultCLevel, call_ZSTD_compressBound, call_ZSTD_isError,
    call_ZSTD_getErrorCode, call_ZSTD_getErrorName, call_ZSTD_getErrorString, call_ZSTD_cParam_getBounds,
    call_ZSTD_dParam_getBounds, call_ZSTD_CStreamInSize, call_ZSTD_CStreamOutSize, call_ZSTD_DStreamInSize,
    call_ZSTD_DStreamOutSize,
    call_ZSTD_getFrameContentSize, call_ZSTD_getDecompressedSize, call_ZSTD_findFrameCompressedSize,
    call_ZSTD_getDictID_fromFrame, call_ZSTD_getDictID_fromDict,
    call_ZSTD_compress, call_ZSTD_decompress, call_ZSTD_compress_usingDict, call_ZSTD_decompress_usingDict,
    call_ZSTD_createCCtx, call_ZSTD_createCStream, call_ZSTD_freeCCtx, call_ZSTD_freeCStream,
    call_ZSTD_sizeof_CCtx, call_ZSTD_sizeof_CStream, call_ZSTD_compressCCtx, call_ZSTD_CCtx_setParameter,
    call_ZSTD_CCtx_setPledgedSrcSize, call_ZSTD_CCtx_reset, call_ZSTD_compress2, call_ZSTD_compressStream2,
    call_ZSTD_initCStream, call_ZSTD_compressStream, call_ZSTD_flushStream, call_ZSTD_endStream,
    call_ZSTD_CCtx_loadDictionary, call_ZSTD_CCtx_refCDict, call_ZSTD_CCtx_refPrefix,
    call_ZSTD_createDCtx, call_ZSTD_createDStream, call_ZSTD_freeDCtx, call_ZSTD_freeDStream,
    call_ZSTD_sizeof_DCtx, call_ZSTD_sizeof_DStream, call_ZSTD_decompressDCtx, call_ZSTD_DCtx_setParameter,
    call_ZSTD_DCtx_reset, call_ZSTD_initDStream, call_ZSTD_decompressStream, call_ZSTD_DCtx_loadDictionary,
    call_ZSTD_DCtx_refDDict, call_ZSTD_DCtx_refPrefix,
    call_ZSTD_createCDict, call_ZSTD_freeCDict, call_ZSTD_sizeof_CDict, call_ZSTD_getDictID_fromCDict,
    call_ZSTD_compress_usingCDict, call_ZSTD_createDDict, call_ZSTD_freeDDict, call_ZSTD_sizeof_DDict,
    call_ZSTD_getDictID_fromDDict, call_ZSTD_decompress_usingDDict,
    call_ZDICT_trainFromBuffer, call_ZDICT_finalizeDictionary, call_ZDICT_getDictID,
    call_ZDICT_getDictHeaderSize, call_ZDICT_isError, call_ZDICT_getErrorName,    call_ZSTD_findDecompressedSize, call_ZSTD_decompressBound, call_ZSTD_frameHeaderSize,
    call_ZSTD_decompressionMargin, call_ZSTD_isFrame, call_ZSTD_isSkippableFrame, call_ZSTD_writeSkippableFrame,
    call_ZSTD_readSkippableFrame, call_ZSTD_decodingBufferSize_min, call_ZSTD_isDeterministicBuild,
    call_ZSTD_estimateCCtxSize, call_ZSTD_estimateCCtxSize_usingCParams, call_ZSTD_estimateCStreamSize,
    call_ZSTD_estimateCStreamSize_usingCParams, call_ZSTD_estimateDCtxSize, call_ZSTD_estimateDStreamSize,
    call_ZSTD_estimateDStreamSize_fromFrame, call_ZSTD_estimateCDictSize, call_ZSTD_estimateCDictSize_advanced,
    call_ZSTD_estimateDDictSize, call_ZSTD_checkCParams, call_ZSTD_adjustCParams, call_ZSTD_CCtx_getParameter,
    call_ZSTD_CCtx_setCParams, call_ZSTD_CCtx_setFParams, call_ZSTD_CCtx_setParams, call_ZSTD_getFrameProgression,
    call_ZSTD_toFlushNow, call_ZSTD_compress_advanced, call_ZSTD_compress_usingCDict_advanced,
    call_ZSTD_CCtx_loadDictionary_byReference, call_ZSTD_createThreadPool, call_ZSTD_freeThreadPool,
    call_ZSTD_CCtx_refThreadPool, call_ZSTD_initCStream_srcSize, call_ZSTD_initCStream_usingDict,
    call_ZSTD_initCStream_advanced, call_ZSTD_initCStream_usingCDict, call_ZSTD_initCStream_usingCDict_advanced,
    call_ZSTD_resetCStream, call_ZSTD_registerSequenceProducer, call_ZSTD_compressBegin,
    call_ZSTD_compressBegin_usingDict, call_ZSTD_compressBegin_advanced, call_ZSTD_compressBegin_usingCDict,
    call_ZSTD_compressBegin_usingCDict_advanced, call_ZSTD_compressContinue, call_ZSTD_compressEnd,
    call_ZSTD_getBlockSize, call_ZSTD_compressBlock, call_ZSTD_copyCCtx, call_ZSTD_generateSequences,
    call_ZSTD_mergeBlockDelimiters, call_ZSTD_compressSequences, call_ZSTD_compressSequencesAndLiterals,
    call_ZSTD_createCCtxParams, call_ZSTD_freeCCtxParams, call_ZSTD_CCtxParams_reset, call_ZSTD_CCtxParams_init,
    call_ZSTD_CCtxParams_init_advanced, call_ZSTD_CCtxParams_setParameter, call_ZSTD_CCtxParams_getParameter,
    call_ZSTD_CCtxParams_registerSequenceProducer, call_ZSTD_CCtx_setParametersUsingCCtxParams,
    call_ZSTD_estimateCCtxSize_usingCCtxParams, call_ZSTD_estimateCStreamSize_usingCCtxParams,
    call_ZSTD_initStaticCCtx, call_ZSTD_initStaticCStream, call_ZSTD_initStaticDCtx, call_ZSTD_initStaticDStream,
    call_ZSTD_initStaticCDict, call_ZSTD_initStaticDDict, call_ZSTD_createCDict_byReference,
    call_ZSTD_createDDict_byReference, call_ZSTD_createDCtx_advanced, call_ZSTD_createDStream_advanced,
    call_ZSTD_DCtx_getParameter, call_ZSTD_DCtx_setFormat, call_ZSTD_DCtx_setMaxWindowSize,
    call_ZSTD_DCtx_loadDictionary_byReference, call_ZSTD_decompressStream_simpleArgs, call_ZSTD_initDStream_usingDict,
    call_ZSTD_initDStream_usingDDict, call_ZSTD_resetDStream, call_ZSTD_decompressBegin, call_ZSTD_decompressBlock,
    call_ZSTD_insertBlock, call_ZSTD_copyDCtx, call_ZDICT_trainFromBuffer_cover,
    call_ZDICT_optimizeTrainFromBuffer_cover, call_ZDICT_trainFromBuffer_fastCover, call_ZDICT_trainFromBuffer_legacy,
    call_ZDICT_addEntropyTablesFromBuffer,
};

#define API_COUNT (sizeof api / sizeof api[0])

static void cleanup(void) {
    /* a static object has no free function: releasing its workspace (below) is all there is to do */
    if (!cctx_static) ZSTD_freeCCtx(cctx);
    if (!dctx_static) ZSTD_freeDCtx(dctx);
    if (!cdict_static) ZSTD_freeCDict(cdict);
    if (!ddict_static) ZSTD_freeDDict(ddict);
    cctx_gone();
    dctx_gone();
    cdict = NULL;
    ddict = NULL;
    free(cdict_ws);
    free(ddict_ws);
    free(cdict_ref);
    free(ddict_ref);
    cdict_ws = ddict_ws = NULL;
    cdict_ref = ddict_ref = NULL;
    cdict_static = ddict_static = 0;
    ZSTD_freeCCtxParams(cparams);
    cparams = NULL;
    ZSTD_freeThreadPool(pool);   /* after the CCtx that may use it */
    pool = NULL;
    free(seqs);
    seqs = NULL;
    seq_count = seq_src_len = 0;
    seq_merged = 0;
    compressed_len = dict_len = prefix_len = bl_src_len = blocks_len = 0;
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
