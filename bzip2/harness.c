#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <bzlib.h>
#include "preqed_ltl.h"

/* 1 MiB output buffers: room for any record's output (input is at most 64 KiB after expand()) */
#define OUT_CAP (1 << 20)
#define FILE_PATH "bzip2-harness.bz2"

typedef struct {
    const uint8_t *p;
    size_t n;
} payload;

static bz_stream comp, decomp;
static int comp_live, decomp_live;
static int decomp_stopped;  /* BZ2_bzDecompress returned non-BZ_OK: only BZ2_bzDecompressEnd may follow (manual.xml:1592-1598) */

static FILE *fp;          /* stdio handle owned by the harness while bzf is open */
static BZFILE *bzf;       /* low-level BZFILE from BZ2_bzReadOpen / BZ2_bzWriteOpen */
static int bzf_writing;
static int bzf_stopped;   /* BZ2_bzRead/BZ2_bzWrite set a bzerror other than BZ_OK: only close (or GetUnused) may follow
                             (manual.xml:1862-1870, 2007-2013) */
static BZFILE *hl;        /* high-level handle from BZ2_bzopen / BZ2_bzdopen */
static int hl_writing;

static unsigned char compressed[OUT_CAP];
static size_t compressed_len;
static unsigned char decompressed[OUT_CAP];
static unsigned char scratch[OUT_CAP];
/* 64 KiB: bzip2's mainSort only runs on blocks of 10 KB or more (NOTES.md bzip2) */
static unsigned char expanded[1 << 16];

static uint8_t byte(payload in, size_t i) { return i < in.n ? in.p[i] : 0; }
static payload rest(payload in, size_t skip) {
    payload r = { in.p + (skip < in.n ? skip : in.n), in.n > skip ? in.n - skip : 0 };
    return r;
}
/* bzlib.h: blockSize100k 1..9; workFactor 0..250, 0 = default (30) */
static int block_size(uint8_t b) { return 1 + b % 9; }
static int work_factor(uint8_t b) { return b % 251; }
static int action(uint8_t b) {
    /* the three actions BZ2_bzCompress accepts */
    static const int a[] = { BZ_RUN, BZ_FLUSH, BZ_FINISH };
    return a[b % 3];
}

/* Repeat the payload so blocks become large enough to exercise the full sorter. */
static payload expand(payload in) {
    if (!in.n || !(byte(in, 0) & 1)) return rest(in, 1);
    payload body = rest(in, 1);
    if (!body.n) return body;
    size_t total = body.n * (1 + byte(in, 0) / 8);
    if (total > sizeof expanded) total = sizeof expanded;
    for (size_t i = 0; i < total; i++) expanded[i] = body.p[i % body.n];
    payload r = { expanded, total };
    return r;
}

static payload compressed_or(payload in) {
    if (byte(in, 0) & 2) {
        payload c = { compressed, compressed_len };
        return c;
    }
    return rest(in, 1);
}

static FILE *open_file(const char *mode) {
    return fopen(FILE_PATH, mode);
}

static void write_file(payload src) {
    FILE *f = open_file("wb");
    if (!f) return;
    fwrite(src.p, 1, src.n, f);
    fclose(f);
}

#define REPORT(api, expr, ok_cond) \
    do { if (preqed_call(#api)) { int rc = (expr); preqed_result(#api, (ok_cond)); } } while (0)

/* low-level compression stream */
/* ltl: compress_stream_lifecycle */
static void call_BZ2_bzCompressInit(payload in) {
    if (comp_live) return;
    memset(&comp, 0, sizeof comp);
    if (!preqed_call("BZ2_bzCompressInit")) return;
    int rc = BZ2_bzCompressInit(&comp, block_size(byte(in, 0)), byte(in, 1) % 5, work_factor(byte(in, 2)));  /* verbosity 0..4 */
    preqed_result("BZ2_bzCompressInit", rc == BZ_OK);
    comp_live = rc == BZ_OK;
    compressed_len = 0;
}
/* ltl: compress_stream_lifecycle */
static void call_BZ2_bzCompress(payload in) {
    if (!comp_live) return;
    payload src = expand(rest(in, 1));
    comp.next_in = (char *)src.p;
    comp.avail_in = (unsigned)src.n;
    comp.next_out = (char *)compressed + compressed_len;
    comp.avail_out = (unsigned)(OUT_CAP - compressed_len);
    REPORT(BZ2_bzCompress, BZ2_bzCompress(&comp, action(byte(in, 0))),
           rc == BZ_RUN_OK || rc == BZ_FLUSH_OK || rc == BZ_FINISH_OK || rc == BZ_STREAM_END);
    compressed_len = OUT_CAP - comp.avail_out;
}
/* ltl: compress_stream_lifecycle */
static void call_BZ2_bzCompressEnd(payload in) {
    (void)in;
    if (!comp_live) return;
    REPORT(BZ2_bzCompressEnd, BZ2_bzCompressEnd(&comp), rc == BZ_OK);
    comp_live = 0;
}

/* low-level decompression stream */
/* ltl: decompress_stream_lifecycle */
static void call_BZ2_bzDecompressInit(payload in) {
    if (decomp_live) return;
    memset(&decomp, 0, sizeof decomp);
    if (!preqed_call("BZ2_bzDecompressInit")) return;
    int rc = BZ2_bzDecompressInit(&decomp, byte(in, 0) % 5, byte(in, 1) & 1);  /* verbosity 0..4, small 0/1 */
    preqed_result("BZ2_bzDecompressInit", rc == BZ_OK);
    decomp_live = rc == BZ_OK;
    decomp_stopped = 0;
}
/* ltl: decompress_stream_lifecycle */
static void call_BZ2_bzDecompress(payload in) {
    if (!decomp_live || decomp_stopped) return;
    if (decomp.avail_in == 0) {  /* new input only once the previous input is consumed, as a real caller does */
        payload src = compressed_or(in);
        decomp.next_in = (char *)src.p;
        decomp.avail_in = (unsigned)src.n;
    }
    decomp.next_out = (char *)decompressed;
    decomp.avail_out = byte(in, 0) & 4 ? 1 + byte(in, 1) : OUT_CAP;  /* 1..256 bytes forces BZ_OK partial-output steps */
    if (!preqed_call("BZ2_bzDecompress")) return;
    int rc = BZ2_bzDecompress(&decomp);
    preqed_result("BZ2_bzDecompress", rc == BZ_OK || rc == BZ_STREAM_END);
    decomp_stopped = rc != BZ_OK;
}
/* ltl: decompress_stream_lifecycle */
static void call_BZ2_bzDecompressEnd(payload in) {
    (void)in;
    if (!decomp_live) return;
    REPORT(BZ2_bzDecompressEnd, BZ2_bzDecompressEnd(&decomp), rc == BZ_OK);
    decomp_live = 0;
}

/* BZFILE over a stdio handle */
/* ltl: bzfile_read_lifecycle, bzfile_write_lifecycle */
static void call_BZ2_bzReadOpen(payload in) {
    if (bzf) return;
    write_file(compressed_or(in));
    fp = open_file("rb");
    if (!fp) return;
    payload unused = rest(in, 1);
    int n_unused = byte(in, 0) & 4 ? (int)(unused.n < BZ_MAX_UNUSED ? unused.n : BZ_MAX_UNUSED) : 0;
    int bzerror;
    if (!preqed_call("BZ2_bzReadOpen")) {
        fclose(fp);
        fp = NULL;
        return;
    }
    bzf = BZ2_bzReadOpen(&bzerror, fp, byte(in, 0) >> 4 & 1, byte(in, 0) >> 5 & 1, (void *)unused.p, n_unused);  /* verbosity 0/1, small 0/1 */
    preqed_result("BZ2_bzReadOpen", bzerror == BZ_OK);
    bzf_writing = 0;
    bzf_stopped = 0;
    if (!bzf) {
        fclose(fp);
        fp = NULL;
    }
}
/* ltl: bzfile_read_lifecycle */
static void call_BZ2_bzRead(payload in) {
    if (!bzf || bzf_writing || bzf_stopped) return;
    int bzerror;
    if (!preqed_call("BZ2_bzRead")) return;
    BZ2_bzRead(&bzerror, bzf, scratch, 1 + byte(in, 0) * 256);  /* 1..65281 bytes per read */
    preqed_result("BZ2_bzRead", bzerror == BZ_OK || bzerror == BZ_STREAM_END);
    bzf_stopped = bzerror != BZ_OK;
}
/* ltl: bzfile_read_lifecycle */
static void call_BZ2_bzReadGetUnused(payload in) {
    (void)in;
    if (!bzf || bzf_writing) return;
    int bzerror;
    void *unused;
    int n_unused;
    if (!preqed_call("BZ2_bzReadGetUnused")) return;
    BZ2_bzReadGetUnused(&bzerror, bzf, &unused, &n_unused);
    preqed_result("BZ2_bzReadGetUnused", bzerror == BZ_OK);
}
/* ltl: bzfile_read_lifecycle */
static void call_BZ2_bzReadClose(payload in) {
    (void)in;
    if (!bzf || bzf_writing) return;
    int bzerror;
    if (!preqed_call("BZ2_bzReadClose")) return;
    BZ2_bzReadClose(&bzerror, bzf);
    preqed_result("BZ2_bzReadClose", bzerror == BZ_OK);
    bzf = NULL;
    fclose(fp);
    fp = NULL;
}
/* ltl: bzfile_read_lifecycle, bzfile_write_lifecycle */
static void call_BZ2_bzWriteOpen(payload in) {
    if (bzf) return;
    fp = open_file("wb");
    if (!fp) return;
    int bzerror;
    if (!preqed_call("BZ2_bzWriteOpen")) {
        fclose(fp);
        fp = NULL;
        return;
    }
    bzf = BZ2_bzWriteOpen(&bzerror, fp, block_size(byte(in, 0)), byte(in, 1) % 5, work_factor(byte(in, 2)));  /* verbosity 0..4 */
    preqed_result("BZ2_bzWriteOpen", bzerror == BZ_OK);
    bzf_writing = 1;
    bzf_stopped = 0;
    if (!bzf) {
        fclose(fp);
        fp = NULL;
    }
}
/* ltl: bzfile_write_lifecycle */
static void call_BZ2_bzWrite(payload in) {
    if (!bzf || !bzf_writing || bzf_stopped) return;
    payload src = expand(in);
    int bzerror;
    if (!preqed_call("BZ2_bzWrite")) return;
    BZ2_bzWrite(&bzerror, bzf, (void *)src.p, (int)src.n);
    preqed_result("BZ2_bzWrite", bzerror == BZ_OK);
    bzf_stopped = bzerror != BZ_OK;
}
/* ltl: bzfile_write_lifecycle */
static void call_BZ2_bzWriteClose(payload in) {
    if (!bzf || !bzf_writing) return;
    int bzerror;
    unsigned in_bytes, out_bytes;
    if (!preqed_call("BZ2_bzWriteClose")) return;
    BZ2_bzWriteClose(&bzerror, bzf, byte(in, 0) & 1, &in_bytes, &out_bytes);
    preqed_result("BZ2_bzWriteClose", bzerror == BZ_OK);
    bzf = NULL;
    fclose(fp);
    fp = NULL;
}
/* ltl: bzfile_write_lifecycle */
static void call_BZ2_bzWriteClose64(payload in) {
    if (!bzf || !bzf_writing) return;
    int bzerror;
    unsigned in_lo, in_hi, out_lo, out_hi;
    if (!preqed_call("BZ2_bzWriteClose64")) return;
    BZ2_bzWriteClose64(&bzerror, bzf, byte(in, 0) & 1, &in_lo, &in_hi, &out_lo, &out_hi);
    preqed_result("BZ2_bzWriteClose64", bzerror == BZ_OK);
    bzf = NULL;
    fclose(fp);
    fp = NULL;
}

/* one-shot */

static void call_BZ2_bzBuffToBuffCompress(payload in) {
    payload src = expand(rest(in, 2));
    unsigned dest_len = byte(in, 1) & 1 ? 1 + byte(in, 0) : OUT_CAP;
    REPORT(BZ2_bzBuffToBuffCompress,
           BZ2_bzBuffToBuffCompress((char *)scratch, &dest_len, (char *)src.p, (unsigned)src.n,
                                    block_size(byte(in, 0)), byte(in, 1) % 5, work_factor(byte(in, 1))),
           rc == BZ_OK);
}

static void call_BZ2_bzBuffToBuffDecompress(payload in) {
    payload src = compressed_or(in);
    unsigned dest_len = byte(in, 0) & 4 ? 1 + byte(in, 1) : OUT_CAP;  /* small capacity exercises BZ_OUTBUFF_FULL */
    REPORT(BZ2_bzBuffToBuffDecompress,
           BZ2_bzBuffToBuffDecompress((char *)decompressed, &dest_len, (char *)src.p, (unsigned)src.n,
                                      byte(in, 0) >> 3 & 1, byte(in, 0) >> 4 & 1),  /* small, verbosity */
           rc == BZ_OK);
}

static void call_BZ2_bzlibVersion(payload in) {
    (void)in;
    if (!preqed_call("BZ2_bzlibVersion")) return;
    preqed_result("BZ2_bzlibVersion", BZ2_bzlibVersion() != NULL);
}

/* high-level zlib-style handle */

static const char *hl_mode(uint8_t b) {
    /* bzlib.c:1405-1421 reads the mode letter by letter: the last 'r'/'w' wins (default read), a digit sets the
       block size, anything else is ignored; so "rw" writes and "" / "x" read */
    static const char *const modes[] = { "r", "rb", "w", "wb", "w1", "w9", "wb5", "rw", "", "x" };
    return modes[b % 10];
}
static int mode_writes(const char *m) {
    int w = 0;
    for (; *m; m++) {
        if (*m == 'r') w = 0;
        if (*m == 'w') w = 1;
    }
    return w;
}
/* ltl: highlevel_handle_lifecycle */
static void call_BZ2_bzopen(payload in) {
    if (hl) return;
    const char *mode = hl_mode(byte(in, 0));
    if (!mode_writes(mode)) write_file(compressed_or(rest(in, 1)));
    if (!preqed_call("BZ2_bzopen")) return;
    hl = BZ2_bzopen(FILE_PATH, mode);
    preqed_result("BZ2_bzopen", hl != NULL);
    hl_writing = mode_writes(mode);
}
/* ltl: highlevel_handle_lifecycle */
static void call_BZ2_bzdopen(payload in) {
    if (hl) return;
    const char *mode = hl_mode(byte(in, 0));
    if (!mode_writes(mode)) write_file(compressed_or(rest(in, 1)));
    FILE *f = open_file(mode_writes(mode) ? "wb" : "rb");
    if (!f) return;
    int fd = dup(fileno(f));
    fclose(f);
    if (fd < 0) return;
    if (!preqed_call("BZ2_bzdopen")) {
        close(fd);
        return;
    }
    hl = BZ2_bzdopen(fd, mode);
    preqed_result("BZ2_bzdopen", hl != NULL);
    hl_writing = mode_writes(mode);
    /* when fdopen succeeded but the BZFILE open failed, the library already fclose()d the fd (bzlib.c:1449-1451) */
    if (!hl && fcntl(fd, F_GETFD) != -1) close(fd);
}
/* ltl: highlevel_handle_lifecycle */
static void call_BZ2_bzread(payload in) {
    if (!hl || hl_writing) return;
    REPORT(BZ2_bzread, BZ2_bzread(hl, scratch, 1 + byte(in, 0) * 256), rc >= 0);  /* 1..65281 bytes */
}
/* ltl: highlevel_handle_lifecycle */
static void call_BZ2_bzwrite(payload in) {
    if (!hl || !hl_writing) return;
    payload src = expand(in);
    REPORT(BZ2_bzwrite, BZ2_bzwrite(hl, (void *)src.p, (int)src.n), rc == (int)src.n);
}
/* ltl: highlevel_handle_lifecycle */
static void call_BZ2_bzflush(payload in) {
    (void)in;
    if (!hl) return;
    REPORT(BZ2_bzflush, BZ2_bzflush(hl), rc == 0);
}
/* ltl: highlevel_handle_lifecycle */
static void call_BZ2_bzerror(payload in) {
    (void)in;
    if (!hl) return;
    int errnum;
    if (!preqed_call("BZ2_bzerror")) return;
    preqed_result("BZ2_bzerror", BZ2_bzerror(hl, &errnum) != NULL);
}
/* ltl: highlevel_handle_lifecycle */
static void call_BZ2_bzclose(payload in) {
    (void)in;
    if (!hl) return;
    if (!preqed_call("BZ2_bzclose")) return;
    BZ2_bzclose(hl);
    preqed_result("BZ2_bzclose", 1);
    hl = NULL;
}

/* dispatch */

static void (*const api[])(payload) = {
    call_BZ2_bzCompressInit, call_BZ2_bzCompress, call_BZ2_bzCompressEnd,
    call_BZ2_bzDecompressInit, call_BZ2_bzDecompress, call_BZ2_bzDecompressEnd,
    call_BZ2_bzReadOpen, call_BZ2_bzRead, call_BZ2_bzReadGetUnused, call_BZ2_bzReadClose,
    call_BZ2_bzWriteOpen, call_BZ2_bzWrite, call_BZ2_bzWriteClose, call_BZ2_bzWriteClose64,
    call_BZ2_bzBuffToBuffCompress, call_BZ2_bzBuffToBuffDecompress, call_BZ2_bzlibVersion,
    call_BZ2_bzopen, call_BZ2_bzdopen, call_BZ2_bzread, call_BZ2_bzwrite, call_BZ2_bzflush,
    call_BZ2_bzerror, call_BZ2_bzclose,
};

#define API_COUNT (sizeof api / sizeof api[0])

static void cleanup(void) {
    int bzerror;
    if (comp_live) BZ2_bzCompressEnd(&comp);
    if (decomp_live) BZ2_bzDecompressEnd(&decomp);
    if (bzf && bzf_writing) BZ2_bzWriteClose(&bzerror, bzf, 1, NULL, NULL);
    if (bzf && !bzf_writing) BZ2_bzReadClose(&bzerror, bzf);
    if (fp) fclose(fp);
    if (hl) BZ2_bzclose(hl);
    comp_live = decomp_live = 0;
    bzf = NULL;
    fp = NULL;
    hl = NULL;
    compressed_len = 0;
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
