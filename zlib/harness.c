#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>
#include "preqed_ltl.h"

/* 1 MiB output buffers: deflateBound of the largest record (64 KiB) fits with room to spare */
#define OUT_CAP (1 << 20)
/* gzopen/gzdopen file; relative so it stays in the fuzzer's cwd, removed in cleanup() */
#define GZ_PATH "zlib-harness.gz"

typedef struct {
    const uint8_t *p;
    size_t n;
} payload;

static z_stream def, inf, back;
static int def_live, inf_live, back_live;
/* Track stream use, finishing, and completion; gz_fresh permits gzbuffer before other calls. */
static int def_used, def_finish, def_end, inf_used, gz_fresh;
static gzFile gz;

/* 32 KiB = the largest window (windowBits 15): inflateBackInit's window and the dictionary getters */
static unsigned char window[1 << 15];
static unsigned char scratch[OUT_CAP];
static unsigned char compressed[OUT_CAP];
static size_t compressed_len;
static unsigned char decompressed[OUT_CAP];

static uLong adler = 1, crc;
static uLong crc_op;

static uint8_t byte(payload in, size_t i) { return i < in.n ? in.p[i] : 0; }
static payload rest(payload in, size_t skip) {
    payload r = { in.p + (skip < in.n ? skip : in.n), in.n > skip ? in.n - skip : 0 };
    return r;
}
/* compression level -1..9; -1 = Z_DEFAULT_COMPRESSION (zlib.h deflateInit) */
static int level(uint8_t b) { return (int)(b % 11) - 1; }
/* Z_DEFAULT_STRATEGY 0, Z_FILTERED 1, Z_HUFFMAN_ONLY 2, Z_RLE 3, Z_FIXED 4 */
static int strategy(uint8_t b) { return b % 5; }
static int window_bits(uint8_t b) {
    /* zlib.h deflateInit2/inflateInit2: 9..15 = zlib wrapper, negative = raw deflate, +16 = gzip (31, 25),
       +32 = inflate auto-detects zlib or gzip (47); 9 and 12 exercise small windows */
    static const int bits[] = { 15, -15, 31, 47, 9, 12, -9, 25 };
    return bits[b % 8];
}
static int deflate_flush(uint8_t b) {
    /* every flush value deflate() accepts */
    static const int f[] = { Z_NO_FLUSH, Z_PARTIAL_FLUSH, Z_SYNC_FLUSH, Z_FULL_FLUSH, Z_FINISH, Z_BLOCK };
    return f[b % 6];
}
static int inflate_flush(uint8_t b) {
    /* every flush value inflate() accepts */
    static const int f[] = { Z_NO_FLUSH, Z_SYNC_FLUSH, Z_FINISH, Z_BLOCK, Z_TREES };
    return f[b % 5];
}
static const char *gz_mode(uint8_t b) {
    /* zlib.h gzopen modes: r/w/a, level digit, strategy letter (h huffman, f filtered, R rle, F fixed),
       T transparent (no compression), e close-on-exec, x exclusive create */
    static const char *modes[] = { "rb", "wb", "wb9", "wb1h", "wbf", "wbR", "wbF", "ab", "wbT", "rbe", "wbx" };
    return modes[b % 11];
}

#define REPORT(api, expr, ok_cond) \
    do { if (preqed_call(#api)) { int rc = (expr); preqed_result(#api, (ok_cond)); } } while (0)
#define REPORT_OK(api, expr) REPORT(api, expr, rc == Z_OK)

/* deflate stream */
/* ltl: deflate_stream_lifecycle, deflate_dictionary_before_data */
static void call_deflateInit(payload in) {
    if (def_live) return;
    memset(&def, 0, sizeof def);
    if (!preqed_call("deflateInit")) return;
    int rc = deflateInit(&def, level(byte(in, 0)));
    preqed_result("deflateInit", rc == Z_OK);
    def_live = rc == Z_OK;
    def_used = def_finish = def_end = 0;
}
/* ltl: deflate_stream_lifecycle, deflate_dictionary_before_data */
static void call_deflateInit2(payload in) {
    if (def_live) return;
    memset(&def, 0, sizeof def);
    if (!preqed_call("deflateInit2")) return;
    int rc = deflateInit2(&def, level(byte(in, 0)), Z_DEFLATED, window_bits(byte(in, 1)),
                          1 + byte(in, 2) % 9, strategy(byte(in, 3)));  /* memLevel 1..9 */
    preqed_result("deflateInit2", rc == Z_OK);
    def_live = rc == Z_OK;
    def_used = def_finish = def_end = 0;
}
/* ltl: deflate_stream_lifecycle, deflate_dictionary_before_data */
static void call_deflate(payload in) {
    if (!def_live || def_end) return;
    payload src = rest(in, 1);
    if (!def_finish) {
        def.next_in = (Bytef *)src.p;
        def.avail_in = (uInt)src.n;
    }
    def.next_out = compressed + compressed_len;
    def.avail_out = (uInt)(OUT_CAP - compressed_len);
    int flush = def_finish ? Z_FINISH : deflate_flush(byte(in, 0));
    if (!preqed_call("deflate")) return;
    int rc = deflate(&def, flush);
    preqed_result("deflate", rc == Z_OK || rc == Z_STREAM_END);
    compressed_len = OUT_CAP - def.avail_out;
    def_used = 1;
    def_finish = flush == Z_FINISH;
    def_end = rc == Z_STREAM_END;
}
/* ltl: deflate_stream_lifecycle, deflate_dictionary_before_data */
static void call_deflateSetDictionary(payload in) {
    if (!def_live || def_finish || !in.n) return;
    REPORT_OK(deflateSetDictionary, deflateSetDictionary(&def, in.p, (uInt)in.n));
}
/* ltl: deflate_stream_lifecycle */
static void call_deflateGetDictionary(payload in) {
    if (!def_live) return;
    if (def_end) return;
    uInt len = 0;
    REPORT_OK(deflateGetDictionary, deflateGetDictionary(&def, byte(in, 0) & 1 ? NULL : window, &len));
}
/* ltl: deflate_stream_lifecycle */
static void call_deflateParams(payload in) {
    if (!def_live || def_finish) return;
    def.next_in = Z_NULL;
    def.avail_in = 0;
    def.next_out = compressed + compressed_len;
    def.avail_out = (uInt)(OUT_CAP - compressed_len);
    REPORT(deflateParams, deflateParams(&def, level(byte(in, 0)), strategy(byte(in, 1))),
           rc == Z_OK || rc == Z_BUF_ERROR);
    def_used = 1;  /* deflateParams may call deflate internally. */
    compressed_len = OUT_CAP - def.avail_out;
}
/* ltl: deflate_stream_lifecycle */
static void call_deflateTune(payload in) {
    if (!def_live || def_finish) return;
    REPORT_OK(deflateTune, deflateTune(&def, byte(in, 0), byte(in, 1), byte(in, 2), byte(in, 3) * 16));
}
/* ltl: deflate_stream_lifecycle */
static void call_deflateBound(payload in) {
    if (!def_live || def_end) return;
    if (!preqed_call("deflateBound")) return;
    uLong bound = deflateBound(&def, in.n);
    preqed_result("deflateBound", bound >= in.n);
}
/* ltl: deflate_stream_lifecycle */
static void call_deflatePending(payload in) {
    (void)in;
    if (!def_live || def_end) return;
    unsigned pending;
    int bits;
    REPORT_OK(deflatePending, deflatePending(&def, &pending, &bits));
}
/* ltl: deflate_stream_lifecycle */
static void call_deflatePrime(payload in) {
    if (!def_live || def_finish) return;
    /* bits 0..16 (zlib.h: at most 16) */
    REPORT_OK(deflatePrime, deflatePrime(&def, byte(in, 0) % 17, byte(in, 1)));
}
/* ltl: deflate_stream_lifecycle */
static void call_deflateSetHeader(payload in) {
    if (!def_live || def_used) return;
    static gz_header hdr;
    static unsigned char extra[256], name[256], comment[256];
    payload text = rest(in, 2);
    size_t len = text.n < 255 ? text.n : 255;
    memcpy(extra, text.p, len);
    memcpy(name, text.p, len);
    memcpy(comment, text.p, len);
    name[len] = comment[len] = 0;
    for (size_t i = 0; i < len; i++) {
        if (!name[i]) name[i] = 1;
        if (!comment[i]) comment[i] = 1;
    }
    memset(&hdr, 0, sizeof hdr);
    hdr.text = byte(in, 0) & 1;
    hdr.hcrc = (byte(in, 0) >> 1) & 1;
    hdr.time = byte(in, 1);
    hdr.os = byte(in, 1) % 14;  /* the 14 OS codes of RFC 1952 */
    hdr.extra = byte(in, 0) & 4 ? extra : Z_NULL;
    hdr.extra_len = (uInt)len;
    hdr.name = byte(in, 0) & 8 ? name : Z_NULL;
    hdr.comment = byte(in, 0) & 16 ? comment : Z_NULL;
    REPORT_OK(deflateSetHeader, deflateSetHeader(&def, &hdr));
}
/* ltl: deflate_stream_lifecycle, deflate_dictionary_before_data */
static void call_deflateReset(payload in) {
    (void)in;
    if (!def_live) return;
    REPORT_OK(deflateReset, deflateReset(&def));
    compressed_len = 0;
    def_used = def_finish = def_end = 0;
}
/* ltl: deflate_stream_lifecycle */
static void call_deflateResetKeep(payload in) {
    (void)in;
    if (!def_live) return;
    REPORT_OK(deflateResetKeep, deflateResetKeep(&def));
    compressed_len = 0;
    def_used = def_finish = def_end = 0;
}
/* ltl: deflate_stream_lifecycle */
static void call_deflateCopy(payload in) {
    (void)in;
    if (!def_live || def_end) return;
    z_stream copy;
    memset(&copy, 0, sizeof copy);
    if (!preqed_call("deflateCopy")) return;
    int rc = deflateCopy(&copy, &def);
    preqed_result("deflateCopy", rc == Z_OK);
    if (rc == Z_OK) deflateEnd(&copy);
}
/* ltl: deflate_stream_lifecycle */
static void call_deflateEnd(payload in) {
    (void)in;
    if (!def_live) return;
    REPORT(deflateEnd, deflateEnd(&def), rc == Z_OK || rc == Z_DATA_ERROR);
    def_live = 0;
}

/* inflate stream */
/* ltl: inflate_stream_lifecycle */
static void call_inflateInit(payload in) {
    (void)in;
    if (inf_live) return;
    memset(&inf, 0, sizeof inf);
    if (!preqed_call("inflateInit")) return;
    int rc = inflateInit(&inf);
    preqed_result("inflateInit", rc == Z_OK);
    inf_live = rc == Z_OK;
    inf_used = 0;
}
/* ltl: inflate_stream_lifecycle */
static void call_inflateInit2(payload in) {
    if (inf_live) return;
    memset(&inf, 0, sizeof inf);
    if (!preqed_call("inflateInit2")) return;
    int rc = inflateInit2(&inf, window_bits(byte(in, 0)));
    preqed_result("inflateInit2", rc == Z_OK);
    inf_live = rc == Z_OK;
    inf_used = 0;
}

/* decompressor input: byte 0 bit 0 picks the stream deflate() produced so far, otherwise the payload after 2 bytes */
static payload inflate_source(payload in) {
    if (byte(in, 0) & 1) {
        payload c = { compressed, compressed_len };
        return c;
    }
    return rest(in, 2);
}
/* ltl: inflate_stream_lifecycle */
static void call_inflate(payload in) {
    if (!inf_live) return;
    payload src = inflate_source(in);
    inf.next_in = (Bytef *)src.p;
    inf.avail_in = (uInt)src.n;
    inf.next_out = decompressed;
    inf.avail_out = OUT_CAP;
    REPORT(inflate, inflate(&inf, inflate_flush(byte(in, 1))),
           rc == Z_OK || rc == Z_STREAM_END || rc == Z_NEED_DICT || rc == Z_BUF_ERROR);
    inf_used = 1;
}
/* ltl: inflate_stream_lifecycle */
static void call_inflateSetDictionary(payload in) {
    if (!inf_live || !in.n) return;
    REPORT_OK(inflateSetDictionary, inflateSetDictionary(&inf, in.p, (uInt)in.n));
}
/* ltl: inflate_stream_lifecycle */
static void call_inflateGetDictionary(payload in) {
    if (!inf_live) return;
    uInt len = 0;
    REPORT_OK(inflateGetDictionary, inflateGetDictionary(&inf, byte(in, 0) & 1 ? NULL : window, &len));
}
/* ltl: inflate_stream_lifecycle */
static void call_inflateSync(payload in) {
    if (!inf_live) return;
    payload src = inflate_source(in);
    inf.next_in = (Bytef *)src.p;
    inf.avail_in = (uInt)src.n;
    REPORT_OK(inflateSync, inflateSync(&inf));
    inf_used = 1;
}
/* ltl: inflate_stream_lifecycle */
static void call_inflateSyncPoint(payload in) {
    (void)in;
    if (!inf_live) return;
    REPORT(inflateSyncPoint, inflateSyncPoint(&inf), rc >= 0);
}
/* ltl: inflate_stream_lifecycle */
static void call_inflateReset(payload in) {
    (void)in;
    if (!inf_live) return;
    REPORT_OK(inflateReset, inflateReset(&inf));
    inf_used = 0;
}
/* ltl: inflate_stream_lifecycle */
static void call_inflateReset2(payload in) {
    if (!inf_live) return;
    REPORT_OK(inflateReset2, inflateReset2(&inf, window_bits(byte(in, 0))));
    inf_used = 0;
}
/* ltl: inflate_stream_lifecycle */
static void call_inflateResetKeep(payload in) {
    (void)in;
    if (!inf_live) return;
    REPORT_OK(inflateResetKeep, inflateResetKeep(&inf));
    inf_used = 0;
}
/* ltl: inflate_stream_lifecycle */
static void call_inflatePrime(payload in) {
    if (!inf_live) return;
    /* bits 0..16, or -1 which zlib.h documents as "clear the bit buffer" */
    int bits = byte(in, 0) & 1 ? -1 : byte(in, 0) % 17;
    REPORT_OK(inflatePrime, inflatePrime(&inf, bits, byte(in, 1)));
}
/* ltl: inflate_stream_lifecycle */
static void call_inflateMark(payload in) {
    (void)in;
    if (!inf_live) return;
    if (!preqed_call("inflateMark")) return;
    long mark = inflateMark(&inf);
    preqed_result("inflateMark", mark != -65536);
}
/* ltl: inflate_stream_lifecycle */
static void call_inflateGetHeader(payload in) {
    (void)in;
    if (!inf_live || inf_used) return;
    static gz_header hdr;
    static unsigned char extra[256], name[256], comment[256];
    memset(&hdr, 0, sizeof hdr);
    hdr.extra = extra;
    hdr.extra_max = sizeof extra;
    hdr.name = name;
    hdr.name_max = sizeof name;
    hdr.comment = comment;
    hdr.comm_max = sizeof comment;
    REPORT_OK(inflateGetHeader, inflateGetHeader(&inf, &hdr));
}
/* ltl: inflate_stream_lifecycle */
static void call_inflateUndermine(payload in) {
    if (!inf_live) return;
    /* Z_DATA_ERROR means this build does not support the requested behavior. */
    REPORT_OK(inflateUndermine, inflateUndermine(&inf, byte(in, 0) & 1));
}
/* ltl: inflate_stream_lifecycle */
static void call_inflateValidate(payload in) {
    if (!inf_live) return;
    REPORT_OK(inflateValidate, inflateValidate(&inf, byte(in, 0) & 1));
}
/* ltl: inflate_stream_lifecycle */
static void call_inflateCodesUsed(payload in) {
    (void)in;
    if (!inf_live) return;
    if (!preqed_call("inflateCodesUsed")) return;
    unsigned long used = inflateCodesUsed(&inf);
    preqed_result("inflateCodesUsed", used != (unsigned long)-1);
}
/* ltl: inflate_stream_lifecycle */
static void call_inflateCopy(payload in) {
    (void)in;
    if (!inf_live) return;
    z_stream copy;
    memset(&copy, 0, sizeof copy);
    if (!preqed_call("inflateCopy")) return;
    int rc = inflateCopy(&copy, &inf);
    preqed_result("inflateCopy", rc == Z_OK);
    if (rc == Z_OK) inflateEnd(&copy);
}
/* ltl: inflate_stream_lifecycle */
static void call_inflateEnd(payload in) {
    (void)in;
    if (!inf_live) return;
    REPORT_OK(inflateEnd, inflateEnd(&inf));
    inf_live = 0;
}

/* inflateBack stream */

typedef struct {
    payload src;
    size_t off;
    unsigned chunk;
    size_t written;
} back_io;

/* inflateBack in/out callbacks (zlib.h in_func/out_func): feed the source in chunks of 1..256 bytes,
   copy output into decompressed[]; out returns non-zero (stop) when the buffer is full */
static unsigned back_in(void *desc, unsigned char **buf) {
    back_io *io = desc;
    size_t n = io->src.n - io->off;
    if (n > io->chunk) n = io->chunk;
    *buf = (unsigned char *)io->src.p + io->off;
    io->off += n;
    return (unsigned)n;
}

static int back_out(void *desc, unsigned char *buf, unsigned n) {
    back_io *io = desc;
    if (n > OUT_CAP - io->written) return 1;
    memcpy(decompressed + io->written, buf, n);
    io->written += n;
    return 0;
}
/* ltl: inflateback_stream_lifecycle */
static void call_inflateBackInit(payload in) {
    if (back_live) return;
    memset(&back, 0, sizeof back);
    if (!preqed_call("inflateBackInit")) return;
    int rc = inflateBackInit(&back, 8 + byte(in, 0) % 8, window);  /* windowBits 8..15 */
    preqed_result("inflateBackInit", rc == Z_OK);
    back_live = rc == Z_OK;
}
/* ltl: inflateback_stream_lifecycle */
static void call_inflateBack(payload in) {
    if (!back_live) return;
    back_io io = { inflate_source(in), 0, 1u + byte(in, 1), 0 };
    if (!io.src.n) return;
    back.next_in = Z_NULL;
    back.avail_in = 0;
    REPORT(inflateBack, inflateBack(&back, back_in, &io, back_out, &io), rc == Z_STREAM_END);
}
/* ltl: inflateback_stream_lifecycle */
static void call_inflateBackEnd(payload in) {
    (void)in;
    if (!back_live) return;
    REPORT_OK(inflateBackEnd, inflateBackEnd(&back));
    back_live = 0;
}

/* one-shot and checksum */

static void call_compress(payload in) {
    uLongf dest_len = OUT_CAP;
    REPORT_OK(compress, compress(scratch, &dest_len, in.p, in.n));
}

static void call_compress2(payload in) {
    uLongf dest_len = OUT_CAP;
    payload src = rest(in, 1);
    REPORT_OK(compress2, compress2(scratch, &dest_len, src.p, src.n, level(byte(in, 0))));
}

static void call_compressBound(payload in) {
    if (!preqed_call("compressBound")) return;
    uLong bound = compressBound(in.n);
    preqed_result("compressBound", bound >= in.n);
}

static void call_uncompress(payload in) {
    uLongf dest_len = OUT_CAP;
    payload src = inflate_source(in);
    REPORT(uncompress, uncompress(decompressed, &dest_len, src.p, src.n), rc == Z_OK);
}

static void call_uncompress2(payload in) {
    uLongf dest_len = OUT_CAP;
    payload src = inflate_source(in);
    uLong source_len = src.n;
    REPORT(uncompress2, uncompress2(decompressed, &dest_len, src.p, &source_len), rc == Z_OK);
}

static void call_adler32(payload in) {
    if (!preqed_call("adler32")) return;
    adler = adler32(byte(in, 0) & 1 ? 0 : adler, in.p, (uInt)in.n);
    preqed_result("adler32", 1);
}

static void call_adler32_z(payload in) {
    if (!preqed_call("adler32_z")) return;
    adler = adler32_z(adler, in.p, in.n);
    preqed_result("adler32_z", 1);
}

static void call_adler32_combine(payload in) {
    if (!preqed_call("adler32_combine")) return;
    adler = adler32_combine(adler, adler32(1, in.p, (uInt)in.n), (z_off_t)in.n);
    preqed_result("adler32_combine", 1);
}

/* zlib.h: the z_off64_t variant of adler32_combine, exported next to it */
static void call_adler32_combine64(payload in) {
    if (!preqed_call("adler32_combine64")) return;
    adler = adler32_combine64(adler, adler32(1, in.p, (uInt)in.n), (z_off64_t)in.n);
    preqed_result("adler32_combine64", 1);
}

static void call_crc32(payload in) {
    if (!preqed_call("crc32")) return;
    crc = crc32(byte(in, 0) & 1 ? 0 : crc, in.p, (uInt)in.n);
    preqed_result("crc32", 1);
}

static void call_crc32_z(payload in) {
    if (!preqed_call("crc32_z")) return;
    crc = crc32_z(crc, in.p, in.n);
    preqed_result("crc32_z", 1);
}

static void call_crc32_combine(payload in) {
    if (!preqed_call("crc32_combine")) return;
    crc = crc32_combine(crc, crc32(0, in.p, (uInt)in.n), (z_off_t)in.n);
    preqed_result("crc32_combine", 1);
}
/* ltl: crc32_combine_op_needs_generated_op */
static void call_crc32_combine_gen(payload in) {
    if (!preqed_call("crc32_combine_gen")) return;
    crc_op = crc32_combine_gen((z_off_t)in.n);
    preqed_result("crc32_combine_gen", 1);
}
/* ltl: crc32_combine_op_needs_generated_op */
static void call_crc32_combine_op(payload in) {
    if (!crc_op) return;
    if (!preqed_call("crc32_combine_op")) return;
    crc = crc32_combine_op(crc, crc32(0, in.p, (uInt)in.n), crc_op);
    preqed_result("crc32_combine_op", 1);
}

static void call_get_crc_table(payload in) {
    (void)in;
    if (!preqed_call("get_crc_table")) return;
    const z_crc_t *table = get_crc_table();
    preqed_result("get_crc_table", table != NULL);
}

static void call_zlibVersion(payload in) {
    (void)in;
    if (!preqed_call("zlibVersion")) return;
    preqed_result("zlibVersion", zlibVersion() != NULL);
}

static void call_zlibCompileFlags(payload in) {
    (void)in;
    if (!preqed_call("zlibCompileFlags")) return;
    zlibCompileFlags();
    preqed_result("zlibCompileFlags", 1);
}

static void call_zError(payload in) {
    if (!preqed_call("zError")) return;
    preqed_result("zError", zError((int)byte(in, 0) % 10 - 6) != NULL);  /* Z_VERSION_ERROR (-6) .. Z_NEED_DICT (2), plus unknown codes */
}

/* gzFile */

/* byte 0 bit 1: write deflate() output to GZ_PATH (a real gzip stream when deflate used windowBits 31),
   otherwise the raw payload, so gzread sees both valid and arbitrary files */
static void write_gz_path(payload in) {
    int fd = open(GZ_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return;
    payload body = rest(in, 1);
    payload src = byte(in, 0) & 2 ? (payload){ compressed, compressed_len } : body;
    ssize_t written = src.n ? write(fd, src.p, src.n) : 0;
    (void)written;
    close(fd);
}
/* ltl: gzfile_lifecycle */
static void call_gzopen(payload in) {
    if (gz) return;
    if (byte(in, 0) & 4) write_gz_path(in);
    if (!preqed_call("gzopen")) return;
    gz = gzopen(GZ_PATH, gz_mode(byte(in, 1)));
    preqed_result("gzopen", gz != NULL);
    gz_fresh = gz != NULL;
}
/* zlib.h: the large-file variant of gzopen, same path and modes */
/* ltl: gzfile_lifecycle */
static void call_gzopen64(payload in) {
    if (gz) return;
    if (byte(in, 0) & 4) write_gz_path(in);
    if (!preqed_call("gzopen64")) return;
    gz = gzopen64(GZ_PATH, gz_mode(byte(in, 1)));
    preqed_result("gzopen64", gz != NULL);
    gz_fresh = gz != NULL;
}
/* ltl: gzfile_lifecycle */
static void call_gzdopen(payload in) {
    if (gz) return;
    if (byte(in, 0) & 4) write_gz_path(in);
    const char *mode = gz_mode(byte(in, 1));
    int fd = open(GZ_PATH, mode[0] == 'r' ? O_RDONLY : O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) return;
    if (!preqed_call("gzdopen")) {
        close(fd);
        return;
    }
    gz = gzdopen(fd, mode);
    preqed_result("gzdopen", gz != NULL);
    gz_fresh = gz != NULL;
    if (!gz) close(fd);
}
/* ltl: gzfile_lifecycle */
static void call_gzbuffer(payload in) {
    if (!gz || !gz_fresh) return;
    REPORT(gzbuffer, gzbuffer(gz, 1u << (byte(in, 0) % 20)), rc == 0);  /* 1 B .. 512 KiB; below 2 is rounded up by zlib */
}
/* ltl: gzfile_lifecycle */
static void call_gzsetparams(payload in) {
    if (!gz) return;
    REPORT_OK(gzsetparams, gzsetparams(gz, level(byte(in, 0)), strategy(byte(in, 1))));
}
/* ltl: gzfile_lifecycle */
static void call_gzread(payload in) {
    if (!gz) return;
    REPORT(gzread, gzread(gz, scratch, 1u + byte(in, 0) * 16u), rc >= 0);
}
/* ltl: gzfile_lifecycle */
static void call_gzfread(payload in) {
    if (!gz) return;
    if (!preqed_call("gzfread")) return;
    z_size_t items = gzfread(scratch, 1 + byte(in, 0), 1 + byte(in, 1), gz);
    preqed_result("gzfread", items > 0 || gzeof(gz));
}
/* ltl: gzfile_lifecycle */
static void call_gzwrite(payload in) {
    if (!gz) return;
    REPORT(gzwrite, gzwrite(gz, in.p, (unsigned)in.n), rc == (int)in.n);
}
/* ltl: gzfile_lifecycle */
static void call_gzfwrite(payload in) {
    if (!gz) return;
    unsigned size = 1 + byte(in, 0);
    payload body = rest(in, 1);
    if (!preqed_call("gzfwrite")) return;
    z_size_t items = gzfwrite(body.p, size, body.n / size, gz);
    preqed_result("gzfwrite", items == body.n / size);
}
/* ltl: gzfile_lifecycle */
static void call_gzprintf(payload in) {
    if (!gz) return;
    static char text[256];
    size_t len = in.n < 255 ? in.n : 255;
    memcpy(text, in.p, len);
    text[len] = 0;
    /* fixed format so arguments match the conversions; the payload is the %s argument, never the format */
    REPORT(gzprintf, gzprintf(gz, "%s|%u", text, (unsigned)in.n), rc > 0);
}
/* ltl: gzfile_lifecycle */
static void call_gzputs(payload in) {
    if (!gz) return;
    static char text[256];
    size_t len = in.n < 255 ? in.n : 255;
    memcpy(text, in.p, len);
    text[len] = 0;
    REPORT(gzputs, gzputs(gz, text), rc >= 0);
}
/* ltl: gzfile_lifecycle */
static void call_gzgets(payload in) {
    if (!gz) return;
    if (!preqed_call("gzgets")) return;
    char *line = gzgets(gz, (char *)scratch, 1 + byte(in, 0));
    preqed_result("gzgets", line != NULL);
}
/* ltl: gzfile_lifecycle */
static void call_gzputc(payload in) {
    if (!gz) return;
    REPORT(gzputc, gzputc(gz, byte(in, 0)), rc == byte(in, 0));
}
/* ltl: gzfile_lifecycle */
static void call_gzgetc(payload in) {
    (void)in;
    if (!gz) return;
    REPORT(gzgetc, gzgetc(gz), rc >= 0);
}
/* zlib.h: the function behind the gzgetc macro, kept "for backward compatibility" */
/* ltl: gzfile_lifecycle */
static void call_gzgetc_(payload in) {
    (void)in;
    if (!gz) return;
    REPORT(gzgetc_, gzgetc_(gz), rc >= 0);
}
/* ltl: gzfile_lifecycle */
static void call_gzungetc(payload in) {
    if (!gz) return;
    REPORT(gzungetc, gzungetc(byte(in, 0), gz), rc == byte(in, 0));
}
/* ltl: gzfile_lifecycle */
static void call_gzflush(payload in) {
    if (!gz) return;
    REPORT_OK(gzflush, gzflush(gz, deflate_flush(byte(in, 0))));
}
/* ltl: gzfile_lifecycle */
static void call_gzseek(payload in) {
    if (!gz) return;
    int whence = byte(in, 0) & 1 ? SEEK_CUR : SEEK_SET;
    if (!preqed_call("gzseek")) return;
    z_off_t pos = gzseek(gz, (z_off_t)byte(in, 1) * (byte(in, 0) & 2 ? -1 : 1), whence);
    preqed_result("gzseek", pos >= 0);
}
/* ltl: gzfile_lifecycle */
static void call_gzrewind(payload in) {
    (void)in;
    if (!gz) return;
    REPORT(gzrewind, gzrewind(gz), rc == 0);
}
/* ltl: gzfile_lifecycle */
static void call_gztell(payload in) {
    (void)in;
    if (!gz) return;
    if (!preqed_call("gztell")) return;
    preqed_result("gztell", gztell(gz) >= 0);
}
/* ltl: gzfile_lifecycle */
static void call_gzoffset(payload in) {
    (void)in;
    if (!gz) return;
    if (!preqed_call("gzoffset")) return;
    preqed_result("gzoffset", gzoffset(gz) >= 0);
}
/* ltl: gzfile_lifecycle */
static void call_gzeof(payload in) {
    (void)in;
    if (!gz) return;
    if (!preqed_call("gzeof")) return;
    gzeof(gz);
    preqed_result("gzeof", 1);
}
/* ltl: gzfile_lifecycle */
static void call_gzdirect(payload in) {
    (void)in;
    if (!gz) return;
    if (!preqed_call("gzdirect")) return;
    gzdirect(gz);
    preqed_result("gzdirect", 1);
}
/* ltl: gzfile_lifecycle */
static void call_gzerror(payload in) {
    (void)in;
    if (!gz) return;
    int err = 0;
    if (!preqed_call("gzerror")) return;
    const char *msg = gzerror(gz, &err);
    preqed_result("gzerror", msg != NULL);
}
/* ltl: gzfile_lifecycle */
static void call_gzclearerr(payload in) {
    (void)in;
    if (!gz) return;
    if (!preqed_call("gzclearerr")) return;
    gzclearerr(gz);
    preqed_result("gzclearerr", 1);
}
/* ltl: gzfile_lifecycle */
static void call_gzclose(payload in) {
    (void)in;
    if (!gz) return;
    REPORT(gzclose, gzclose(gz), rc == Z_OK || rc == Z_BUF_ERROR);
    gz = NULL;
}
/* ltl: gzfile_lifecycle */
static void call_gzclose_r(payload in) {
    (void)in;
    if (!gz) return;
    if (!preqed_call("gzclose_r")) return;
    int rc = gzclose_r(gz);
    preqed_result("gzclose_r", rc == Z_OK || rc == Z_BUF_ERROR);
    if (rc != Z_STREAM_ERROR) gz = NULL;
}
/* ltl: gzfile_lifecycle */
static void call_gzclose_w(payload in) {
    (void)in;
    if (!gz) return;
    if (!preqed_call("gzclose_w")) return;
    int rc = gzclose_w(gz);
    preqed_result("gzclose_w", rc == Z_OK || rc == Z_BUF_ERROR);
    if (rc != Z_STREAM_ERROR) gz = NULL;
}

/* dispatch */

static void (*const api[])(payload) = {
    call_deflateInit, call_deflateInit2, call_deflate, call_deflateSetDictionary,
    call_deflateGetDictionary, call_deflateParams, call_deflateTune, call_deflateBound,
    call_deflatePending, call_deflatePrime, call_deflateSetHeader, call_deflateReset,
    call_deflateResetKeep, call_deflateCopy, call_deflateEnd,

    call_inflateInit, call_inflateInit2, call_inflate, call_inflateSetDictionary,
    call_inflateGetDictionary, call_inflateSync, call_inflateSyncPoint, call_inflateReset,
    call_inflateReset2, call_inflateResetKeep, call_inflatePrime, call_inflateMark,
    call_inflateGetHeader, call_inflateUndermine, call_inflateValidate, call_inflateCodesUsed,
    call_inflateCopy, call_inflateEnd,

    call_inflateBackInit, call_inflateBack, call_inflateBackEnd,

    call_compress, call_compress2, call_compressBound, call_uncompress, call_uncompress2,
    call_adler32, call_adler32_z, call_adler32_combine, call_adler32_combine64,
    call_crc32, call_crc32_z, call_crc32_combine,
    call_crc32_combine_gen, call_crc32_combine_op,
    call_get_crc_table, call_zlibVersion, call_zlibCompileFlags, call_zError,

    call_gzopen, call_gzopen64, call_gzdopen, call_gzbuffer, call_gzsetparams,
    call_gzread, call_gzfread, call_gzwrite, call_gzfwrite, call_gzprintf, call_gzputs,
    call_gzgets, call_gzputc, call_gzgetc, call_gzgetc_, call_gzungetc, call_gzflush, call_gzseek,
    call_gzrewind, call_gztell, call_gzoffset, call_gzeof, call_gzdirect, call_gzerror, call_gzclearerr,
    call_gzclose, call_gzclose_r, call_gzclose_w,
};

#define API_COUNT (sizeof api / sizeof api[0])

static void cleanup(void) {
    if (def_live) deflateEnd(&def);
    if (inf_live) inflateEnd(&inf);
    if (back_live) inflateBackEnd(&back);
    if (gz) gzclose(gz);
    def_live = inf_live = back_live = 0;
    def_used = def_finish = def_end = inf_used = gz_fresh = 0;
    gz = NULL;
    compressed_len = 0;
    adler = 1;
    crc = 0;
    crc_op = 0;
    unlink(GZ_PATH);
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
        void (*f)(payload) = api[op % API_COUNT];
        f(in);
        /* Conservatively disallow gzbuffer after any other operation. */
        if (f != call_gzopen && f != call_gzopen64 && f != call_gzdopen && f != call_gzbuffer) gz_fresh = 0;
        off += len;
    }
    cleanup();
    return 0;
}
