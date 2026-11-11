#define _GNU_SOURCE
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
/* the vsctool.py-generated counter set of vmod_debug (VSC_debug.vsc); it includes config.h, vdef.h, vas.h
 * and vrt.h (the latter two error out when included twice), and supplies vsc_debug_name / vsc_debug_json */
#include "VSC_debug.c"
#include "vav.h"
#include "vbh.h"
#include "vbm.h"
#include "vbt.h"
#include "vcli.h"
#include "vcs.h"
#include "vct.h"
#include "vnum.h"
#include "vqueue.h"
#include "vre.h"
#include "vre_pcre2.h"
#include "vrnd.h"
#include "vsa.h"
#include "vsb.h"
#include "vsha256.h"
#include "vtcp.h"
#include "vte.h"
#include "vtim.h"
#include "vapi/vsig.h"
#include "vapi/vsl.h"
#include "vapi/vsm.h"
#include "vapi/vsc.h"
#include "vapi/voptget.h"
#include "vut.h"
#include "heritage.h"
#include "vsmw.h"
#include "preqed_ltl.h"

/* longest string handed to the parsers */
#define TEXT_CAP 4096

typedef struct {
    const uint8_t *p;
    size_t n;
} payload;

static struct vsb *vsb;            /* the one live VSB: dynamic or fixed */
static struct vsb fixed;
/* VSB_init's caller-supplied buffer; 128 bytes so fixed-size overflow (VSB_error) is reached */
static char fixed_buf[128];
static int vsb_dynamic, vsb_finished;
static char **argv_held;           /* result of VAV_Parse / VAV_ParseTxt, owned until VAV_Free */
static char *decoded;              /* result of VAV_BackSlashDecode */

static char text[TEXT_CAP + 1];
static char ascii[TEXT_CAP + 1];

static uint8_t byte(payload in, size_t i) { return i < in.n ? in.p[i] : 0; }

/* payload as a NUL-terminated string; returns its end */
static const char *as_text(payload in) {
    size_t n = in.n < TEXT_CAP ? in.n : TEXT_CAP;
    memcpy(text, in.p, n);
    text[n] = 0;
    return text + n;
}

/* vav.c passes chars to ctype(3), which needs unsigned-char-range values */
static const char *as_ascii(payload in) {
    size_t n = in.n < TEXT_CAP ? in.n : TEXT_CAP;
    for (size_t i = 0; i < n; i++) ascii[i] = in.p[i] & 0x80 ? 'x' : (char)in.p[i];
    ascii[n] = 0;
    return ascii + n;
}

/* VAV_ParseTxt reallocs argv past 16 slots without clearing them, and its error returns skip the
 * argv[nargv] = NULL terminator, so VAV_Free then walks uninitialised slots. Count every possible
 * argument start and stay below the realloc point. */
static int vav_slots_safe(const char *t, size_t n) {
    size_t starts = 0;
    for (size_t j = 0; j < n; j++) {
        unsigned char c = (unsigned char)t[j];
        unsigned char prev = j ? (unsigned char)t[j - 1] : ' ';
        int boundary = prev == ' ' || prev == '\t' || prev == '\n' || prev == '\r' || prev == '\v' || prev == '\f' ||
                       prev == ',' || prev == '"' || c == ',' || c == '"';
        int space = c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
        if (!space && boundary && ++starts > 12) return 0;
    }
    return 1;
}

static int quote_mode(uint8_t b) {
    /* every VSB_QUOTE_* base mode (vsb.h); NONL and ESCHEX are added from payload bits, ESCHEX only where valid */
    static const int modes[] = { VSB_QUOTE_PLAIN, VSB_QUOTE_JSON, VSB_QUOTE_HEX, VSB_QUOTE_CSTR, VSB_QUOTE_UNSAFE };
    int how = modes[b % 5] | (b & 8 ? VSB_QUOTE_NONL : 0);
    if (!(how & (VSB_QUOTE_JSON | VSB_QUOTE_HEX)) && (b & 16)) how |= VSB_QUOTE_ESCHEX;
    return how;
}

static int vprintf_wrapper(struct vsb *s, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int r = VSB_vprintf(s, fmt, ap);
    va_end(ap);
    return r;
}

#define REPORT(api, stmt, ok_cond) \
    do { if (preqed_call(#api)) { stmt; preqed_result(#api, (ok_cond)); } } while (0)
#define REPORT_VOID(api, stmt) REPORT(api, stmt, 1)

/* vav: argument vectors */
/* ltl: vav_argv_ownership */
static void call_VAV_Parse(payload in) {
    if (argv_held) return;
    const char *end = as_ascii(in);
    if (!vav_slots_safe(ascii, (size_t)(end - ascii))) return;
    int argc;
    if (!preqed_call("VAV_Parse")) return;
    argv_held = VAV_Parse(ascii, &argc, byte(in, 0) & 7);  /* flags: ARGV_COMMENT 1, ARGV_COMMA 2, ARGV_NOESC 4 */
    preqed_result("VAV_Parse", argv_held && argv_held[0] == NULL);
}
/* ltl: vav_argv_ownership */
static void call_VAV_ParseTxt(payload in) {
    if (argv_held) return;
    const char *end = as_ascii(in);
    if (!vav_slots_safe(ascii, (size_t)(end - ascii))) return;
    int argc;
    if (!preqed_call("VAV_ParseTxt")) return;
    argv_held = VAV_ParseTxt(ascii, end, &argc, byte(in, 0) & 7);  /* same flag bits */
    preqed_result("VAV_ParseTxt", argv_held && argv_held[0] == NULL);
}
/* ltl: vav_argv_ownership */
static void call_VAV_Free(payload in) {
    (void)in;
    if (!argv_held) return;
    REPORT_VOID(VAV_Free, VAV_Free(argv_held));
    argv_held = NULL;
}

static void call_VAV_BackSlash(payload in) {
    as_ascii(in);
    if (ascii[0] != '\\') return;
    char c;
    REPORT(VAV_BackSlash, int rc = VAV_BackSlash(ascii, &c), rc > 0);
}

static void call_VAV_BackSlashDecode(payload in) {
    const char *end = as_ascii(in);
    if (!preqed_call("VAV_BackSlashDecode")) return;
    char *d = VAV_BackSlashDecode(ascii, end);
    preqed_result("VAV_BackSlashDecode", d != NULL);
    if (d) {
        free(decoded);
        decoded = d;
    }
}

/* vnum: number parsing */

static void call_VNUM(payload in) {
    as_text(in);
    REPORT(VNUM, double x = VNUM(text), !isnan(x));
}

static void call_VNUM_duration(payload in) {
    as_text(in);
    REPORT(VNUM_duration, vtim_dur x = VNUM_duration(text), !isnan(x));
}

static void call_VNUM_duration_unit(payload in) {
    const char *end = as_text(in);
    /* base value 0..24.75 in quarter steps; the payload text is the unit */
    REPORT(VNUM_duration_unit, vtim_dur x = VNUM_duration_unit(byte(in, 0) % 100 / 4.0, text, end), !isnan(x));
}

static void call_VNUM_bytes_unit(payload in) {
    const char *end = as_text(in);
    const char *err = NULL;
    /* value 0..24.75, unit text, rel_to 0..32640 (for percentage units) */
    REPORT(VNUM_bytes_unit, VNUM_bytes_unit(byte(in, 0) % 100 / 4.0, text, end, byte(in, in.n - 1) * 128U, &err), err == NULL);
}

static void call_VNUM_2bytes(payload in) {
    as_text(in);
    /* VNUM_2bytes converts the scaled double to uintmax_t without a range check */
    size_t digits = 0;
    for (const char *c = text; *c; c++) digits += *c >= '0' && *c <= '9';
    if (in.n >= 20 || digits > 4 || (digits > 3 && strpbrk(text, "Pp")) || (in.n && (text[0] < '0' || text[0] > '9')))
        return;
    uintmax_t x;
    REPORT(VNUM_2bytes, const char *e = VNUM_2bytes(text, &x, byte(in, 0) * 64U), e == NULL);
}

static void call_VNUM_uint(payload in) {
    const char *end = as_text(in), *q;
    REPORT(VNUM_uint, ssize_t x = VNUM_uint(text, end, &q), x >= 0);
}

static void call_VNUM_hex(payload in) {
    const char *end = as_text(in), *q;
    REPORT(VNUM_hex, ssize_t x = VNUM_hex(text, end, &q), x >= 0);
}

static void call_SF_Parse_Integer(payload in) {
    as_text(in);
    const char *q = text, *err = NULL;
    REPORT(SF_Parse_Integer, SF_Parse_Integer(&q, &err), err == NULL);
}

static void call_SF_Parse_Decimal(payload in) {
    as_text(in);
    const char *q = text, *err = NULL;
    REPORT(SF_Parse_Decimal, SF_Parse_Decimal(&q, byte(in, 0) & 1, &err), err == NULL);
}

static void call_SF_Parse_Number(payload in) {
    as_text(in);
    const char *q = text, *err = NULL;
    REPORT(SF_Parse_Number, SF_Parse_Number(&q, byte(in, 0) & 1, &err), err == NULL);
}

/* vct: character classes and comparisons */

static void call_VCT_invalid_name(payload in) {
    if (!in.n) return;
    const char *end = as_text(in);
    REPORT(VCT_invalid_name, const char *q = VCT_invalid_name(text, end), q == NULL);
}

#define CLASSIFY(name) \
    static void call_##name(payload in) { \
        if (!in.n) return; \
        REPORT_VOID(name, (void)name(in.p[0])); \
    }
CLASSIFY(vct_isows)
CLASSIFY(vct_issp)
CLASSIFY(vct_ishex)
CLASSIFY(vct_islws)
CLASSIFY(vct_isctl)
CLASSIFY(vct_isspace)
CLASSIFY(vct_isdigit)
CLASSIFY(vct_isalpha)
CLASSIFY(vct_islower)
CLASSIFY(vct_isupper)
CLASSIFY(vct_isalnum)
CLASSIFY(vct_isbase64)
CLASSIFY(vct_issep)
CLASSIFY(vct_issepctl)
CLASSIFY(vct_isident1)
CLASSIFY(vct_isident)
CLASSIFY(vct_isxmlnamestart)
CLASSIFY(vct_isxmlname)
CLASSIFY(vct_istchar)
CLASSIFY(vct_ishdrval)

static void call_vct_is(payload in) {
    if (!in.n) return;
    /* class mask: payload byte shifted to bits 6..13 (VCT_HEX..VCT_ID plus unused bits), or VCT_ALPHA */
    REPORT_VOID(vct_is, (void)vct_is(in.p[0], in.n > 1 ? (uint16_t)(in.p[1] << 6) : VCT_ALPHA));
}

static void call_vct_iscrlf(payload in) {
    const char *end = as_text(in);
    REPORT_VOID(vct_iscrlf, (void)vct_iscrlf(text, end));
}

static void call_vct_skipcrlf(payload in) {
    const char *end = as_text(in);
    REPORT_VOID(vct_skipcrlf, (void)vct_skipcrlf(text, end));
}

static void call_vct_casecmp(payload in) {
    as_text(in);
    REPORT_VOID(vct_casecmp, (void)vct_casecmp(text, decoded ? decoded : text));
}

static void call_vct_caselencmp(payload in) {
    as_text(in);
    REPORT_VOID(vct_caselencmp, (void)vct_caselencmp(text, decoded ? decoded : text, (ssize_t)(in.n < 8 ? in.n : 8)));
}

/* vas, vbt */

static void call_VAS_errtxt(payload in) {
    REPORT(VAS_errtxt, const char *q = VAS_errtxt(in.n ? in.p[0] : EINVAL), q != NULL);
}

static void call_VBT_dump(payload in) {
    char buf[512];
    size_t cap = 2 + ((size_t)byte(in, 0) << 8 | byte(in, 1)) % 511;  /* 2..512 bytes, within buf */
    REPORT(VBT_dump, int rc = VBT_dump(cap, buf), rc == 0);
}

/* vsb: string buffers */
/* ltl: vsb_lifecycle, vsb_write_until_finish */
static void call_VSB_new_auto(payload in) {
    (void)in;
    if (vsb) return;
    if (!preqed_call("VSB_new_auto")) return;
    vsb = VSB_new_auto();
    preqed_result("VSB_new_auto", vsb != NULL);
    vsb_dynamic = 1;
    vsb_finished = 0;
}
/* ltl: vsb_lifecycle, vsb_write_until_finish */
static void call_VSB_init(payload in) {
    (void)in;
    if (vsb) return;
    if (!preqed_call("VSB_init")) return;
    vsb = VSB_init(&fixed, fixed_buf, sizeof fixed_buf);
    preqed_result("VSB_init", vsb != NULL);
    vsb_dynamic = 0;
    vsb_finished = 0;
}
/* ltl: vsb_lifecycle, vsb_write_until_finish */
static void call_VSB_clear(payload in) {
    (void)in;
    if (!vsb) return;
    REPORT_VOID(VSB_clear, VSB_clear(vsb));
    vsb_finished = 0;
}
/* ltl: vsb_lifecycle, vsb_write_until_finish */
static void call_VSB_bcat(payload in) {
    if (!vsb || vsb_finished) return;
    REPORT(VSB_bcat, int rc = VSB_bcat(vsb, in.p, (ssize_t)in.n), rc == 0);
}
/* ltl: vsb_lifecycle, vsb_write_until_finish */
static void call_VSB_cat(payload in) {
    if (!vsb || vsb_finished) return;
    as_text(in);
    REPORT(VSB_cat, int rc = VSB_cat(vsb, decoded && (byte(in, 0) & 1) ? decoded : text), rc == 0);
}
/* ltl: vsb_lifecycle, vsb_write_until_finish */
static void call_VSB_putc(payload in) {
    if (!vsb || vsb_finished) return;
    REPORT(VSB_putc, int rc = VSB_putc(vsb, in.n ? in.p[0] : '\n'), rc == 0);
}
/* ltl: vsb_lifecycle, vsb_write_until_finish */
static void call_VSB_printf(payload in) {
    if (!vsb || vsb_finished) return;
    as_text(in);
    REPORT(VSB_printf, int rc = VSB_printf(vsb, "%s:%02x", text, byte(in, 0)), rc == 0);
}
/* ltl: vsb_lifecycle, vsb_write_until_finish */
static void call_VSB_vprintf(payload in) {
    if (!vsb || vsb_finished) return;
    as_text(in);
    REPORT(VSB_vprintf, int rc = vprintf_wrapper(vsb, "[%s/%u]", text, (unsigned)in.n), rc == 0);
}
/* ltl: vsb_lifecycle, vsb_write_until_finish */
static void call_VSB_quote(payload in) {
    if (!vsb || vsb_finished) return;
    REPORT(VSB_quote, VSB_quote(vsb, in.p, (int)in.n, quote_mode(byte(in, 0))), VSB_error(vsb) == 0);
}
/* ltl: vsb_lifecycle, vsb_write_until_finish */
static void call_VSB_quote_pfx(payload in) {
    if (!vsb || vsb_finished) return;
    int how = quote_mode(byte(in, 0));
    if (in.n > 6 && (byte(in, 0) & 32)) how |= VSB_QUOTE_ABBREVIATE;
    char prefix[32];  /* up to 31 payload bytes, NULs replaced so the prefix has its full length */
    size_t plen = byte(in, 1) % sizeof prefix;
    if (plen > in.n) plen = in.n;
    for (size_t j = 0; j < plen; j++) prefix[j] = in.p[j] ? (char)in.p[j] : '_';
    prefix[plen] = 0;
    as_text(in);
    REPORT(VSB_quote_pfx, VSB_quote_pfx(vsb, prefix, text, (int)in.n, how), VSB_error(vsb) == 0);
}
/* ltl: vsb_lifecycle, vsb_write_until_finish */
static void call_VSB_indent(payload in) {
    if (!vsb || vsb_finished) return;
    int amount = (int)(in.n % 8);  /* indent change -7..7 */
    REPORT(VSB_indent, VSB_indent(vsb, byte(in, 0) & 1 ? -amount : amount), VSB_error(vsb) == 0);
}
/* ltl: vsb_lifecycle, vsb_write_until_finish */
static void call_VBT_format(payload in) {
    (void)in;
    if (!vsb || vsb_finished) return;
    REPORT(VBT_format, VBT_format(vsb), VSB_error(vsb) == 0);
}
/* ltl: vsb_lifecycle, vsb_write_until_finish */
static void call_VSB_finish(payload in) {
    (void)in;
    if (!vsb || vsb_finished) return;
    REPORT(VSB_finish, int rc = VSB_finish(vsb), rc == 0);
    vsb_finished = 1;
}
/* ltl: vsb_lifecycle, vsb_write_until_finish */
static void call_VSB_data(payload in) {
    (void)in;
    if (!vsb || !vsb_finished) return;
    REPORT(VSB_data, char *q = VSB_data(vsb), q != NULL);
}
/* ltl: vsb_lifecycle, vsb_write_until_finish */
static void call_VSB_tofile(payload in) {
    (void)in;
    if (!vsb || !vsb_finished) return;
    int fd = open("/dev/null", O_WRONLY);
    if (fd < 0) return;
    REPORT(VSB_tofile, int rc = VSB_tofile(vsb, fd), rc == 0);
    close(fd);
}
/* ltl: vsb_lifecycle */
static void call_VSB_len(payload in) {
    (void)in;
    if (!vsb) return;
    REPORT(VSB_len, ssize_t z = VSB_len(vsb), z >= 0);
}
/* ltl: vsb_lifecycle */
static void call_VSB_error(payload in) {
    (void)in;
    if (!vsb) return;
    REPORT(VSB_error, int e = VSB_error(vsb), e == 0);
}
/* ltl: vsb_lifecycle */
static void call_VSB_destroy(payload in) {
    (void)in;
    if (!vsb || !vsb_dynamic) return;
    REPORT_VOID(VSB_destroy, VSB_destroy(&vsb));
    vsb = NULL;
}
/* ltl: vsb_lifecycle */
static void call_VSB_fini(payload in) {
    (void)in;
    if (!vsb || vsb_dynamic) return;
    REPORT_VOID(VSB_fini, VSB_fini(vsb));
    vsb = NULL;
}

/* payload helpers for the APIs below */

static payload tail(payload in, size_t k) { return k < in.n ? (payload){ in.p + k, in.n - k } : (payload){ in.p, 0 }; }

static unsigned u16_of(payload in, size_t i) { return (unsigned)byte(in, i) << 8 | byte(in, i + 1); }

/* a finite double from 8 payload bytes, |x| < 1e12 (vtim.c converts with (time_t)trunc(t)) */
static double real_of(payload in) {
    double d = 0;
    memcpy(&d, in.p, in.n < sizeof d ? in.n : sizeof d);
    return isfinite(d) ? fmod(d, 1e12) : 0;
}

/* identifier characters only: VSMW writes the ident into its text index (common_vsmw.c ASSERT_SEG_STR) */
static void ident_of(payload in, char *out, size_t cap) {
    static const char cs[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
    size_t n = in.n < cap - 1 ? in.n : cap - 1;
    for (size_t i = 0; i < n; i++) out[i] = cs[in.p[i] % (sizeof cs - 1)];
    out[n] = 0;
}

static FILE *devnull_file(void) {
    static FILE *f;
    if (!f) f = fopen("/dev/null", "w");
    return f;
}

/* a VSL file (vsl.c:54 vsl_file_id "VSL2" + records) as a memfd (regular: mmap cursor) or a pipe (read cursor);
 * returns the fd backing /proc/self/fd/<fd> in path, the caller closes it */
static int vsl_input(payload data, int as_pipe, char *path, size_t cap) {
    static const char id[4] = { 'V', 'S', 'L', '2' };
    static uint32_t words[32768 / 4];
    size_t n = data.n < 32768 ? data.n : 32768;  /* below the pipe buffer, so the writes never block */
    memcpy(words, data.p, n);
    if (as_pipe) {
        /* records of length 0 abort the read(2) cursor (vsl_cursor.c vslc_file_next `l > 2` with VSL_OVERHEAD 3,
         * repro_vsl_file_zero_len.c): walk the records as it does and give those length 1 */
        for (size_t w = 0; (w + VSL_OVERHEAD) * 4 <= n; w += VSL_OVERHEAD + VSL_WORDS(VSL_LEN(words + w)))
            if (VSL_LEN(words + w) == 0) words[w] |= 1;
    }
    data.p = (const uint8_t *)words;
    int fd, w;
    if (as_pipe) {
        int p[2];
        if (pipe(p)) return -1;
        fd = p[0];
        w = p[1];
    } else {
        fd = w = memfd_create("vsl", 0);
        if (fd < 0) return -1;
    }
    int bad = write(w, id, sizeof id) != (ssize_t)sizeof id || (n && write(w, data.p, n) != (ssize_t)n);
    if (as_pipe) close(w);
    if (bad) {
        close(fd);
        return -1;
    }
    snprintf(path, cap, "/proc/self/fd/%d", fd);
    return fd;
}

/* vbh: binary heap */

#define HEAP_SLOTS 32
struct heap_item {
    unsigned key, idx;
    int in;
};
static struct vbh *heap;
static struct heap_item heap_items[HEAP_SLOTS];
static unsigned heap_n;

static int heap_cmp(void *priv, const void *a, const void *b) {
    (void)priv;
    return ((const struct heap_item *)a)->key < ((const struct heap_item *)b)->key;
}
/* vbh.h: the update function is needed when deleting non-root items */
static void heap_update(void *priv, void *a, unsigned idx) {
    (void)priv;
    ((struct heap_item *)a)->idx = idx;
}
static struct heap_item *heap_pick(uint8_t b, int in) {
    for (unsigned k = 0; k < HEAP_SLOTS; k++) {
        struct heap_item *h = &heap_items[(b + k) % HEAP_SLOTS];
        if (h->in == in) return h;
    }
    return NULL;
}
/* ltl: vbh_lifecycle */
static void call_VBH_new(payload in) {
    (void)in;
    if (heap) return;
    if (!preqed_call("VBH_new")) return;
    heap = VBH_new(NULL, heap_cmp, heap_update);
    preqed_result("VBH_new", heap != NULL);
    memset(heap_items, 0, sizeof heap_items);
    heap_n = 0;
}
/* ltl: vbh_lifecycle */
static void call_VBH_insert(payload in) {
    struct heap_item *h;
    if (!heap || !(h = heap_pick(byte(in, 0), 0))) return;
    h->key = u16_of(in, 1);
    REPORT(VBH_insert, VBH_insert(heap, h); h->in = 1; heap_n++, h->idx != VBH_NOIDX);
}
/* ltl: vbh_lifecycle */
static void call_VBH_reorder(payload in) {
    struct heap_item *h;
    if (!heap || !(h = heap_pick(byte(in, 0), 1))) return;
    h->key = u16_of(in, 1);
    REPORT(VBH_reorder, VBH_reorder(heap, h->idx), h->idx != VBH_NOIDX);
}
/* ltl: vbh_lifecycle */
static void call_VBH_delete(payload in) {
    struct heap_item *h;
    if (!heap || !(h = heap_pick(byte(in, 0), 1))) return;
    REPORT(VBH_delete, VBH_delete(heap, h->idx); h->in = 0; heap_n--, h->idx == VBH_NOIDX);
}
/* ltl: vbh_lifecycle */
static void call_VBH_root(payload in) {
    (void)in;
    if (!heap) return;
    if (!preqed_call("VBH_root")) return;
    const struct heap_item *r = VBH_root(heap);
    int ok = (r == NULL) == (heap_n == 0);  /* the root is the item closest to the root by heap_cmp */
    for (unsigned k = 0; ok && r && k < HEAP_SLOTS; k++)
        if (heap_items[k].in && heap_items[k].key < r->key) ok = 0;
    preqed_result("VBH_root", ok);
}
/* ltl: vbh_lifecycle */
static void call_VBH_destroy(payload in) {
    (void)in;
    if (!heap || heap_n) return;  /* vbh.h: "Destroy an empty Binary tree" */
    REPORT(VBH_destroy, VBH_destroy(&heap), heap == NULL);
}

/* vbm: bitmaps */

static struct vbitmap *vb;
static union {
    struct vbitmap s;
    unsigned w[64];
} vb_mem;
/* ltl: vbit_lifecycle */
static void call_vbit_new(payload in) {
    if (vb) return;
    if (!preqed_call("vbit_new")) return;
    vb = vbit_new(u16_of(in, 0) % 4096);
    preqed_result("vbit_new", vb != NULL);
}
/* ltl: vbit_lifecycle */
static void call_vbit_init(payload in) {
    if (vb) return;
    /* VBITMAP_SZ(bits) bytes, capped at the buffer; below sizeof(struct vbitmap) vbit_init returns NULL */
    size_t sz = VBITMAP_SZ(u16_of(in, 0) % 2048);
    if (sz > sizeof vb_mem) sz = byte(in, 0) % sizeof vb_mem;
    if (!preqed_call("vbit_init")) return;
    vb = vbit_init(&vb_mem, sz);
    preqed_result("vbit_init", vb != NULL);
}
/* ltl: vbit_lifecycle */
static void call_vbit_set(payload in) {
    if (!vb) return;
    unsigned bit = u16_of(in, 0) % 8192;
    REPORT(vbit_set, vbit_set(vb, bit), vbit_test(vb, bit) != 0);
}
/* ltl: vbit_lifecycle */
static void call_vbit_clr(payload in) {
    if (!vb) return;
    unsigned bit = u16_of(in, 0) % 8192;
    REPORT(vbit_clr, vbit_clr(vb, bit), vbit_test(vb, bit) == 0);
}
/* ltl: vbit_lifecycle */
static void call_vbit_test(payload in) {
    if (!vb) return;
    REPORT_VOID(vbit_test, (void)vbit_test(vb, u16_of(in, 0) % 8192));
}
/* ltl: vbit_lifecycle */
static void call_vbit_expand(payload in) {
    if (!vb) return;
    unsigned bit = u16_of(in, 0) % 8192;
    if (vbit_rndup(bit, VBITMAP_LUMP) <= vb->nbits) return;  /* vbm.h vbit_expand: assert(bit > vb->nbits) */
    REPORT(vbit_expand, vbit_expand(vb, bit), vb->nbits >= bit);
}
/* ltl: vbit_lifecycle */
static void call_vbit_destroy(payload in) {
    (void)in;
    if (!vb) return;
    REPORT_VOID(vbit_destroy, vbit_destroy(vb); vb = NULL);
}

static void call_vbit_rndup(payload in) {
    unsigned bit = u16_of(in, 0), to = 1 + byte(in, 2);
    REPORT(vbit_rndup, unsigned r = vbit_rndup(bit, to), r >= bit && r % to == 0);
}

/* vre: regular expressions */

static vre_t *re;
static int re_err;

static struct vre_limits re_limits(payload in) {
    /* bounded so pathological patterns stay fast */
    return (struct vre_limits){ .match = 1 + byte(in, 0) * 40U, .depth = 1 + byte(in, 1) * 4U };
}
/* ltl: vre_lifecycle */
static void call_VRE_compile(payload in) {
    if (re) return;
    unsigned opt = (byte(in, 0) & 1 ? VRE_CASELESS : 0) | (byte(in, 0) & 2 ? VRE_NO_AUTO_CAPTURE : 0);
    as_text(tail(in, 1));
    int off;
    if (!preqed_call("VRE_compile")) return;
    re = VRE_compile(text, opt, &re_err, &off, byte(in, 0) & 4);
    preqed_result("VRE_compile", re != NULL);
}
/* ltl: vre_lifecycle */
static void call_VRE_match(payload in) {
    if (!re) return;
    struct vre_limits lim = re_limits(in);
    const char *end = as_text(tail(in, 2));
    REPORT(VRE_match, int rc = VRE_match(re, text, (size_t)(end - text), 0, &lim), rc > 0 || rc == VRE_ERROR_NOMATCH);
}
/* ltl: vre_lifecycle */
static void call_VRE_capture(payload in) {
    if (!re) return;
    struct vre_limits lim = re_limits(in);
    txt groups[10];
    size_t count = 1 + byte(in, 2) % 10;
    const char *end = as_text(tail(in, 3));
    REPORT(VRE_capture, int rc = VRE_capture(re, text, (size_t)(end - text), 0, groups, count, &lim),
           rc > 0 || rc == VRE_ERROR_NOMATCH);
}
/* ltl: vsb_lifecycle, vsb_write_until_finish, vre_lifecycle */
static void call_VRE_sub(payload in) {
    if (!re || !vsb || vsb_finished) return;
    struct vre_limits lim = re_limits(in);
    as_text(tail(in, 3));
    const char *repl = decoded ? decoded : "<\\0|\\1>";  /* \N refers to capture group N */
    REPORT(VRE_sub, int rc = VRE_sub(re, text, repl, vsb, &lim, byte(in, 2) & 1), rc == 1 || rc == VRE_ERROR_NOMATCH);
}
/* ltl: vre_lifecycle */
static void call_VRE_export(payload in) {
    (void)in;
    if (!re) return;
    size_t sz = 0;
    if (!preqed_call("VRE_export")) return;
    vre_t *exp = VRE_export(re, &sz);
    preqed_result("VRE_export", exp != NULL && sz > 0);
    if (exp) VRE_free(&exp);  /* the packed copy is released here; vre_lifecycle tracks the compiled one */
}
/* ltl: vre_lifecycle */
static void call_VRE_unpack(payload in) {
    (void)in;
    if (!re) return;
    REPORT(VRE_unpack, pcre2_code *c = VRE_unpack(re), c != NULL);
}
/* ltl: vre_lifecycle */
static void call_VRE_free(payload in) {
    (void)in;
    if (!re) return;
    REPORT(VRE_free, VRE_free(&re), re == NULL);
}
/* ltl: vsb_lifecycle, vsb_write_until_finish */
static void call_VRE_error(payload in) {
    if (!vsb || vsb_finished) return;
    int err = byte(in, 0) & 1 ? re_err : (int)(int16_t)u16_of(in, 1);
    REPORT(VRE_error, int rc = VRE_error(vsb, err), rc == 0);
}
/* ltl: vsb_lifecycle, vsb_write_until_finish */
static void call_VRE_quote(payload in) {
    if (!vsb || vsb_finished) return;
    as_text(in);
    REPORT(VRE_quote, VRE_quote(vsb, text), VSB_error(vsb) == 0);
}

/* vrnd: random numbers */

static void vrnd_nolock(void) {}
/* vrnd.c VRND_RandomTestable: AN(VRND_Lock), AN(VRND_Unlock) */
static void vrnd_locks(void) {
    if (!VRND_Lock) VRND_Lock = vrnd_nolock;
    if (!VRND_Unlock) VRND_Unlock = vrnd_nolock;
}

static void call_VRND_SeedTestable(payload in) {
    REPORT_VOID(VRND_SeedTestable, VRND_SeedTestable(u16_of(in, 0) << 16 | u16_of(in, 2)));
}

static void call_VRND_RandomTestable(payload in) {
    (void)in;
    vrnd_locks();
    REPORT(VRND_RandomTestable, long r = VRND_RandomTestable(), r >= 0);
}

static void call_VRND_RandomTestableDouble(payload in) {
    (void)in;
    vrnd_locks();
    REPORT(VRND_RandomTestableDouble, double d = VRND_RandomTestableDouble(), d >= 0 && d < 1);
}

static void call_VRND_RandomCrypto(payload in) {
    unsigned char buf[256];
    REPORT(VRND_RandomCrypto, int rc = VRND_RandomCrypto(buf, 1 + byte(in, 0)), rc == 0);
}

static void call_VRND_SeedAll(payload in) {
    (void)in;
    REPORT_VOID(VRND_SeedAll, VRND_SeedAll());
}

/* vsa: socket addresses */

static void *sua_mem;                    /* vsa_suckaddr_len bytes, the 'd' storage of VSA_Build* / VSA_get*name */
static const struct suckaddr *sua_built;  /* points into sua_mem */
static const struct suckaddr *sua_owned;  /* malloc'd: VSA_Malloc, VSA_Clone, VTCP_my_suckaddr; VSA_free */
static int vsa_inited;                    /* bogo_ip / bogo_ip6 are built by VSA_Init */

static void *sua_storage(void) {
    if (!sua_mem) sua_mem = malloc(vsa_suckaddr_len);
    sua_built = NULL;  /* the storage is about to be rewritten */
    return sua_mem;
}
static const struct suckaddr *sua_pick(uint8_t b) {
    const struct suckaddr *c[4];
    int n = 0;
    if (sua_owned) c[n++] = sua_owned;
    if (sua_built) c[n++] = sua_built;
    if (vsa_inited) {
        c[n++] = bogo_ip;
        c[n++] = bogo_ip6;
    }
    return n ? c[b % n] : NULL;
}
/* a sockaddr image from the payload; family IPv4, IPv6 or one VSA does not handle */
static unsigned sockaddr_of(payload in, struct sockaddr_storage *ss) {
    /* AF_UNIX is left out: vsa.c sua_len accepts it, then VSA_Build hits WRONG("VSA protocol vs. size") */
    static const sa_family_t fams[] = { AF_INET, AF_INET6, AF_UNSPEC, AF_APPLETALK };
    memset(ss, 0, sizeof *ss);
    memcpy(ss, tail(in, 2).p, tail(in, 2).n < sizeof *ss ? tail(in, 2).n : sizeof *ss);
    ss->ss_family = fams[byte(in, 0) % 4];
    static const unsigned lens[] = { sizeof(struct sockaddr_in), sizeof(struct sockaddr_in6), 0, 2 };
    return lens[byte(in, 1) % 4];
}

static void call_VSA_Init(payload in) {
    (void)in;
    REPORT(VSA_Init, VSA_Init(), VSA_Sane(bogo_ip) && VSA_Sane(bogo_ip6));
    vsa_inited = 1;
}
/* ltl: vsa_owned_free */
static void call_VSA_Malloc(payload in) {
    if (sua_owned) return;
    struct sockaddr_storage ss;
    unsigned sal = sockaddr_of(in, &ss);
    if (!preqed_call("VSA_Malloc")) return;
    sua_owned = VSA_Malloc(&ss, sal);
    preqed_result("VSA_Malloc", sua_owned != NULL);
}

static void call_VSA_Build(payload in) {
    struct sockaddr_storage ss;
    unsigned sal = sockaddr_of(in, &ss);
    void *d = sua_storage();
    if (!preqed_call("VSA_Build")) return;
    sua_built = VSA_Build(d, &ss, sal);
    preqed_result("VSA_Build", sua_built != NULL);
}

static void call_VSA_BuildFAP(payload in) {
    static const sa_family_t fams[] = { PF_INET, PF_INET6, PF_UNSPEC };
    uint8_t b = byte(in, 0);
    payload a = tail(in, 1);
    unsigned al = b & 4 ? 4 : b & 8 ? 16 : byte(in, 1) % 20, pl = b & 16 ? 2 : byte(in, 2) % 4;
    if (al > a.n) al = 0;
    if (pl > a.n) pl = 0;
    void *d = sua_storage();
    if (!preqed_call("VSA_BuildFAP")) return;
    sua_built = VSA_BuildFAP(d, fams[b % 3], al ? a.p : NULL, al, pl ? a.p : NULL, pl);
    preqed_result("VSA_BuildFAP", sua_built != NULL);
}
/* ltl: vsa_owned_free */
static void call_VSA_Clone(payload in) {
    const struct suckaddr *s = sua_pick(byte(in, 0));
    if (sua_owned || !s) return;
    if (!preqed_call("VSA_Clone")) return;
    sua_owned = VSA_Clone(s);
    preqed_result("VSA_Clone", sua_owned != NULL && VSA_Compare(sua_owned, s) == 0);
}
/* ltl: vsa_owned_free */
static void call_VSA_free(payload in) {
    (void)in;
    if (!sua_owned) return;
    REPORT(VSA_free, VSA_free(&sua_owned), sua_owned == NULL);
}

static void call_VSA_Sane(payload in) {
    const struct suckaddr *s = sua_pick(byte(in, 0));
    if (!s) return;
    REPORT(VSA_Sane, int r = VSA_Sane(s), r != 0);
}

static void call_VSA_Port(payload in) {
    const struct suckaddr *s = sua_pick(byte(in, 0));
    if (!s) return;
    REPORT_VOID(VSA_Port, (void)VSA_Port(s));
}

static void call_VSA_Compare(payload in) {
    const struct suckaddr *a = sua_pick(byte(in, 0)), *b = sua_pick(byte(in, 1));
    if (!a) return;
    REPORT_VOID(VSA_Compare, (void)VSA_Compare(a, b));
}

static void call_VSA_Compare_IP(payload in) {
    const struct suckaddr *a = sua_pick(byte(in, 0)), *b = sua_pick(byte(in, 1));
    if (!a) return;
    REPORT_VOID(VSA_Compare_IP, (void)VSA_Compare_IP(a, b));
}

static void call_VSA_Get_Sockaddr(payload in) {
    const struct suckaddr *s = sua_pick(byte(in, 0));
    if (!s) return;
    socklen_t sl = 0;
    REPORT(VSA_Get_Sockaddr, const void *p = VSA_Get_Sockaddr(s, &sl), p != NULL && sl > 0);
}

static void call_VSA_Get_Proto(payload in) {
    const struct suckaddr *s = sua_pick(byte(in, 0));
    if (!s) return;
    REPORT(VSA_Get_Proto, int p = VSA_Get_Proto(s), p == PF_INET || p == PF_INET6);
}

static void call_VSA_GetPtr(payload in) {
    const struct suckaddr *s = sua_pick(byte(in, 0));
    if (!s) return;
    const unsigned char *dst;
    REPORT(VSA_GetPtr, int r = VSA_GetPtr(s, &dst), r >= 0 && dst != NULL);
}

/* vtcp: TCP helpers, on loopback sockets of this process (listener, client, accepted server end) */

static int tcp_listen = -1, tcp_client = -1, tcp_server = -1;

static void tcp_listener_setup(int fd) {
    if (fd < 0) return;
    if (tcp_listen >= 0) {
        close(fd);
        return;
    }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);  /* the harness accepts without blocking */
    tcp_listen = fd;
}
static unsigned tcp_listen_port(void) {
    struct sockaddr_in6 sa;
    socklen_t sl = sizeof sa;
    if (tcp_listen < 0 || getsockname(tcp_listen, (struct sockaddr *)&sa, &sl)) return 0;
    return ntohs(sa.sin6_port);  /* sin_port and sin6_port share the offset */
}
static void tcp_accept(void) {
    if (tcp_server < 0 && tcp_listen >= 0) tcp_server = accept4(tcp_listen, NULL, NULL, SOCK_NONBLOCK);
}
static void tcp_client_gone(void) {
    tcp_client = -1;
    if (tcp_server >= 0) close(tcp_server);
    tcp_server = -1;
}
/* 127.0.0.1 or ::1 at port; built with VSA_BuildFAP into mem */
static const struct suckaddr *loopback(void *mem, int v6, unsigned port) {
    static const struct in6_addr lo6 = IN6ADDR_LOOPBACK_INIT;
    uint32_t lo4 = htonl(INADDR_LOOPBACK);
    uint16_t p = htons((uint16_t)port);
    return v6 ? VSA_BuildFAP(mem, PF_INET6, &lo6, sizeof lo6, &p, sizeof p) : VSA_BuildFAP(mem, PF_INET, &lo4, sizeof lo4, &p, sizeof p);
}

static void call_VTCP_Check(payload in) {
    static const int errs[] = { 0, ECONNRESET, ENOTCONN, EPIPE, EAGAIN, ETIMEDOUT, ENETDOWN, EHOSTUNREACH, EBADF, EINVAL };
    errno = errs[byte(in, 1) % 10];
    REPORT_VOID(VTCP_Check, (void)VTCP_Check((ssize_t)(int8_t)byte(in, 0)));
}

static void call_VTCP_listen(payload in) {
    if (tcp_listen >= 0) return;
    char mem[256];
    if (vsa_suckaddr_len > sizeof mem) return;
    const struct suckaddr *sa = loopback(mem, byte(in, 0) & 1, 0);
    if (!sa) return;
    const char *err;
    if (!preqed_call("VTCP_listen")) return;
    int fd = VTCP_listen(sa, 1 + byte(in, 1) % 16, &err);
    preqed_result("VTCP_listen", fd >= 0);
    tcp_listener_setup(fd);
}

static void call_VTCP_bind(payload in) {
    char mem[256];
    if (vsa_suckaddr_len > sizeof mem) return;
    const struct suckaddr *sa = loopback(mem, byte(in, 0) & 1, 0);
    if (!sa) return;
    const char *err;
    int fd = -1;
    REPORT(VTCP_bind, fd = VTCP_bind(sa, &err), fd >= 0);
    if (fd >= 0) close(fd);
}

static void call_VTCP_listen_on(payload in) {
    static const char *const addrs[] = { "127.0.0.1", "[::1]", "127.0.0.1:0" };
    char port[8];
    snprintf(port, sizeof port, "%u", byte(in, 1) & 1 ? 0 : u16_of(in, 2));
    const char *err = NULL;
    /* only numeric loopback addresses: VSS_resolver would otherwise do name lookups */
    const char *addr = addrs[byte(in, 0) % 3];
    int fd = -1;
    REPORT(VTCP_listen_on, fd = VTCP_listen_on(addr, port, 1 + byte(in, 4) % 16, &err), fd >= 0);
    tcp_listener_setup(fd);
}
/* ltl: vtcp_client_socket */
static void call_VTCP_connect(payload in) {
    if (tcp_client >= 0 || tcp_listen < 0) return;
    char mem[256];
    if (vsa_suckaddr_len > sizeof mem) return;
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    if (getsockname(tcp_listen, (struct sockaddr *)&ss, &sl)) return;
    const struct suckaddr *sa = loopback(mem, ss.ss_family == AF_INET6, tcp_listen_port());
    if (!sa) return;
    int msec = byte(in, 0) % 4 == 0 ? -1 : byte(in, 0) % 4 == 1 ? 0 : 1 + byte(in, 0) % 50;  /* -1: caller waits */
    if (!preqed_call("VTCP_connect")) return;
    tcp_client = VTCP_connect(sa, msec);
    preqed_result("VTCP_connect", tcp_client >= 0);
    if (tcp_client < 0) tcp_client = -1;
    tcp_accept();
}
/* ltl: vtcp_client_socket */
static void call_VTCP_open(payload in) {
    if (tcp_client >= 0) return;
    char port[8];
    snprintf(port, sizeof port, "%u", byte(in, 0) & 1 ? tcp_listen_port() : u16_of(in, 1));
    const char *err = NULL;
    if (!preqed_call("VTCP_open")) return;
    tcp_client = VTCP_open(byte(in, 0) & 2 ? "[::1]" : "127.0.0.1", port, byte(in, 3) % 50 / 1000.0, &err);
    preqed_result("VTCP_open", tcp_client >= 0);
    if (tcp_client < 0) tcp_client = -1;
    tcp_accept();
}
/* ltl: vtcp_client_socket */
static void call_VTCP_connected(payload in) {
    (void)in;
    if (tcp_client < 0) return;
    if (!preqed_call("VTCP_connected")) return;
    int fd = VTCP_connected(tcp_client);
    preqed_result("VTCP_connected", fd >= 0);
    if (fd < 0) tcp_client_gone();  /* vtcp.c VTCP_connected closes the socket on error */
}
/* ltl: vtcp_client_socket */
static void call_VTCP_close(payload in) {
    (void)in;
    if (tcp_client < 0) return;
    REPORT(VTCP_close, VTCP_close(&tcp_client); tcp_client_gone(), tcp_client == -1);
}
/* ltl: vtcp_client_socket */
static void call_VTCP_blocking(payload in) {
    (void)in;
    if (tcp_client < 0) return;
    REPORT(VTCP_blocking, VTCP_blocking(tcp_client), !(fcntl(tcp_client, F_GETFL) & O_NONBLOCK));
}
/* ltl: vtcp_client_socket */
static void call_VTCP_nonblocking(payload in) {
    (void)in;
    if (tcp_client < 0) return;
    REPORT(VTCP_nonblocking, VTCP_nonblocking(tcp_client), (fcntl(tcp_client, F_GETFL) & O_NONBLOCK) != 0);
}
/* ltl: vtcp_client_socket */
static void call_VTCP_linger(payload in) {
    if (tcp_client < 0) return;
    REPORT(VTCP_linger, int rc = VTCP_linger(tcp_client, byte(in, 0) & 1), rc == 0);
}
/* ltl: vtcp_client_socket */
static void call_VTCP_check_hup(payload in) {
    (void)in;
    if (tcp_client < 0) return;
    REPORT(VTCP_check_hup, int rc = VTCP_check_hup(tcp_client), rc == 0 || rc == 1);
}
/* ltl: vtcp_client_socket */
static void call_VTCP_set_read_timeout(payload in) {
    if (tcp_client < 0) return;
    REPORT_VOID(VTCP_set_read_timeout, VTCP_set_read_timeout(tcp_client, byte(in, 0) & 1 ? INFINITY : byte(in, 0) / 1000.0));
}
/* ltl: vtcp_client_socket */
static void call_VTCP_read(payload in) {
    if (tcp_client < 0) return;
    tcp_accept();
    if (tcp_server >= 0 && in.n > 1) (void)send(tcp_server, in.p + 1, in.n - 1 < 4096 ? in.n - 1 : 4096, MSG_DONTWAIT | MSG_NOSIGNAL);
    char buf[4096];
    /* tmo > 0: VTCP_read polls first, so a socket without data never blocks */
    REPORT(VTCP_read, int rc = VTCP_read(tcp_client, buf, sizeof buf, 0.001 + byte(in, 0) % 4 / 1000.0), rc >= 0);
}
/* ltl: vtcp_client_socket */
static void call_VTCP_myname(payload in) {
    (void)in;
    if (tcp_client < 0) return;
    char a[VTCP_ADDRBUFSIZE], p[VTCP_PORTBUFSIZE];
    REPORT(VTCP_myname, VTCP_myname(tcp_client, a, sizeof a, p, sizeof p), a[0] != 0);
}
/* ltl: vtcp_client_socket */
static void call_VTCP_hisname(payload in) {
    (void)in;
    if (tcp_client < 0) return;
    char a[VTCP_ADDRBUFSIZE], p[VTCP_PORTBUFSIZE];
    REPORT(VTCP_hisname, VTCP_hisname(tcp_client, a, sizeof a, p, sizeof p), strcmp(a, "<none>") != 0);
}
/* ltl: vsa_owned_free, vtcp_client_socket */
static void call_VTCP_my_suckaddr(payload in) {
    (void)in;
    if (tcp_client < 0 || sua_owned) return;
    if (!preqed_call("VTCP_my_suckaddr")) return;
    sua_owned = VTCP_my_suckaddr(tcp_client);
    preqed_result("VTCP_my_suckaddr", sua_owned != NULL && VSA_Sane(sua_owned));
}
/* ltl: vtcp_client_socket */
static void call_VSA_getsockname(payload in) {
    (void)in;
    if (tcp_client < 0) return;
    void *d = sua_storage();
    if (!preqed_call("VSA_getsockname")) return;
    sua_built = VSA_getsockname(tcp_client, d, vsa_suckaddr_len);
    preqed_result("VSA_getsockname", sua_built != NULL);
}
/* ltl: vtcp_client_socket */
static void call_VSA_getpeername(payload in) {
    (void)in;
    if (tcp_client < 0) return;
    void *d = sua_storage();
    if (!preqed_call("VSA_getpeername")) return;
    sua_built = VSA_getpeername(tcp_client, d, vsa_suckaddr_len);
    preqed_result("VSA_getpeername", sua_built != NULL);
}

static void call_VTCP_name(payload in) {
    const struct suckaddr *s = sua_pick(byte(in, 0));
    if (!s) return;
    char a[VTCP_ADDRBUFSIZE], p[VTCP_PORTBUFSIZE];
    REPORT(VTCP_name, VTCP_name(s, a, sizeof a, p, sizeof p), a[0] != 0);
}

static void call_VTCP_filter_http(payload in) {
    (void)in;
    if (tcp_listen < 0) return;
    REPORT(VTCP_filter_http, int rc = VTCP_filter_http(tcp_listen), rc == 0);
}

static void call_VTCP_fastopen(payload in) {
    if (tcp_listen < 0) return;
    REPORT(VTCP_fastopen, int rc = VTCP_fastopen(tcp_listen, 1 + byte(in, 0) % 64), rc == 0);
}

/* vsha256 */

static VSHA256_CTX sha;
/* ltl: vsha256_context */
static void call_VSHA256_Init(payload in) {
    (void)in;
    REPORT_VOID(VSHA256_Init, VSHA256_Init(&sha));
}
/* ltl: vsha256_context */
static void call_VSHA256_Update(payload in) {
    REPORT_VOID(VSHA256_Update, VSHA256_Update(&sha, in.p, in.n));
}
/* ltl: vsha256_context */
static void call_VSHA256_Final(payload in) {
    (void)in;
    unsigned char digest[VSHA256_LEN];
    REPORT_VOID(VSHA256_Final, VSHA256_Final(digest, &sha));
}

static void call_VSHA256_Test(payload in) {
    (void)in;
    REPORT_VOID(VSHA256_Test, VSHA256_Test());
}

/* vte: text tables */

static struct vte *vte;

static int vte_sink(void *priv, const char *fmt, ...) {
    char buf[512];
    va_list ap;
    (void)priv;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    return 0;
}
/* ltl: vte_lifecycle */
static void call_VTE_new(payload in) {
    if (vte) return;
    if (!preqed_call("VTE_new")) return;
    vte = VTE_new(1 + byte(in, 0) % 16, 1 + byte(in, 1) % 200);  /* vte.c: assert(maxfields > 0), assert(width > 0) */
    preqed_result("VTE_new", vte != NULL);
}
/* ltl: vte_lifecycle */
static void call_VTE_putc(payload in) {
    if (!vte) return;
    if (!byte(in, 0)) return;  /* vte.c VTE_putc: AN(c) */
    REPORT(VTE_putc, int rc = VTE_putc(vte, (char)byte(in, 0)), rc == 0);
}
/* ltl: vte_lifecycle */
static void call_VTE_cat(payload in) {
    if (!vte) return;
    as_text(in);
    REPORT(VTE_cat, int rc = VTE_cat(vte, text), rc == 0);
}
/* ltl: vte_lifecycle */
static void call_VTE_printf(payload in) {
    if (!vte) return;
    as_text(in);
    REPORT(VTE_printf, int rc = VTE_printf(vte, "%s\t%u\n", text, (unsigned)in.n), rc == 0);
}
/* ltl: vte_lifecycle */
static void call_VTE_finish(payload in) {
    (void)in;
    if (!vte) return;
    REPORT(VTE_finish, int rc = VTE_finish(vte), rc == 0);
}
/* ltl: vte_lifecycle */
static void call_VTE_format(payload in) {
    (void)in;
    if (!vte) return;
    REPORT(VTE_format, int rc = VTE_format(vte, vte_sink, NULL), rc == 0);
}
/* ltl: vte_lifecycle */
static void call_VTE_dump(payload in) {
    (void)in;
    if (!vte) return;
    REPORT(VTE_dump, int rc = VTE_dump(vte, vte_sink, NULL), rc == 0);
}
/* ltl: vte_lifecycle */
static void call_VTE_destroy(payload in) {
    (void)in;
    if (!vte) return;
    REPORT(VTE_destroy, VTE_destroy(&vte), vte == NULL);
}

/* vtim: time */

static void call_VTIM_format(payload in) {
    char buf[VTIM_FORMAT_SIZE];
    double t = byte(in, 0) & 1 ? VTIM_real() : real_of(tail(in, 1));
    if (t >= 253402300800.0) return;  /* year 10000+: asserts in vtim.c:257 instead of returning "", see repro_vtim_format.c */
    REPORT(VTIM_format, VTIM_format(t, buf), buf[0] != 0 || t < 0);
}

static void call_VTIM_parse(payload in) {
    as_text(in);
    REPORT(VTIM_parse, vtim_real t = VTIM_parse(text), t != 0);
}

static void call_VTIM_mono(payload in) {
    (void)in;
    REPORT(VTIM_mono, vtim_mono t = VTIM_mono(), t > 0);
}

static void call_VTIM_real(payload in) {
    (void)in;
    REPORT(VTIM_real, vtim_real t = VTIM_real(), t > 0);
}

static void call_VTIM_sleep(payload in) {
    REPORT_VOID(VTIM_sleep, VTIM_sleep(byte(in, 0) / 512000.0));  /* at most 0.5 ms */
}

static void call_VTIM_timespec(payload in) {
    double t = real_of(in);
    REPORT(VTIM_timespec, struct timespec ts = VTIM_timespec(t), ts.tv_sec == (time_t)trunc(t));
}

static void call_VTIM_timeval(payload in) {
    double t = real_of(in);
    REPORT(VTIM_timeval, struct timeval tv = VTIM_timeval(t), tv.tv_sec == (time_t)trunc(t));
}

static void call_VTIM_timeval_sock(payload in) {
    double t = byte(in, 0) == 0xff ? INFINITY : real_of(tail(in, 1));
    REPORT(VTIM_timeval_sock, struct timeval tv = VTIM_timeval_sock(t), tv.tv_sec >= 0 || t < 0);
}

static void call_VTIM_poll_tmo(payload in) {
    double t = byte(in, 0) == 0xff ? INFINITY : fmod(real_of(tail(in, 1)), 1e6);  /* the result is an int of ms */
    REPORT(VTIM_poll_tmo, int ms = VTIM_poll_tmo(t), ms >= -1);
}

/* vcs: version strings */

static void call_VCS_String(payload in) {
    static const char which[][2] = { "T", "P", "B", "R", "V", "M" };  /* version.c VCS_String switch */
    REPORT(VCS_String, const char *s = VCS_String(which[byte(in, 0) % 6]), s != NULL && s[0] != 0);
}

static void call_VCS_Message(payload in) {
    (void)in;
    REPORT_VOID(VCS_Message, VCS_Message("fuzzer"));
}

/* vcli: CLI protocol over a pipe */

static void call_VCLI_WriteResult(payload in) {
    static const unsigned st[] = { CLIS_SYNTAX, CLIS_UNKNOWN, CLIS_UNIMPL, CLIS_TOOFEW, CLIS_TOOMANY, CLIS_PARAM,
                                   CLIS_AUTH, CLIS_OK, CLIS_TRUNCATED, CLIS_CANT, CLIS_COMMS, CLIS_CLOSE };
    int p[2];
    if (pipe(p)) return;
    as_text(tail(in, 1));
    REPORT(VCLI_WriteResult, int rc = VCLI_WriteResult(p[1], st[byte(in, 0) % 12], text), rc == 0);
    close(p[0]);
    close(p[1]);
}

static void call_VCLI_ReadResult(payload in) {
    int p[2];
    if (pipe(p)) return;
    size_t n = in.n < 32768 ? in.n : 32768;
    int bad = n && write(p[1], in.p, n) != (ssize_t)n;
    close(p[1]);
    unsigned status;
    char *res = NULL;
    if (!bad) REPORT(VCLI_ReadResult, int rc = VCLI_ReadResult(p[0], &status, &res, 0.01), rc == 0 && res != NULL);
    free(res);
    close(p[0]);
}

static void call_VCLI_AuthResponse(payload in) {
    char challenge[33], resp[CLI_AUTH_RESPONSE_LEN + 1];
    for (size_t i = 0; i < 32; i++) challenge[i] = i < in.n ? (char)in.p[i] : 'x';  /* 32 bytes are hashed */
    challenge[32] = 0;
    int p[2];
    if (pipe(p)) return;
    payload secret = tail(in, 32);
    size_t n = secret.n < 32768 ? secret.n : 32768;
    int bad = n && write(p[1], secret.p, n) != (ssize_t)n;
    close(p[1]);  /* VCLI_AuthResponse reads the secret until EOF */
    if (!bad) REPORT(VCLI_AuthResponse, VCLI_AuthResponse(p[0], challenge, resp), strlen(resp) == CLI_AUTH_RESPONSE_LEN);
    close(p[0]);
}

/* vsig: signal flags; handlers installed by VSIG_Arm_* / VUT_* are restored afterwards so libFuzzer's stay */

static const int vsig_nums[] = { SIGHUP, SIGINT, SIGTERM, SIGUSR1 };
static void signals_save(struct sigaction old[4]) {
    for (int i = 0; i < 4; i++) sigaction(vsig_nums[i], NULL, &old[i]);
}
static void signals_restore(const struct sigaction old[4]) {
    for (int i = 0; i < 4; i++) sigaction(vsig_nums[i], &old[i], NULL);
}
static int handler_is(int sig, void (*h)(int)) {
    struct sigaction sa;
    return sigaction(sig, NULL, &sa) == 0 && sa.sa_handler == h;
}

#define VSIG_WRAP(UPPER, lower) \
    static void call_VSIG_Got_##lower(payload in) { \
        (void)in; \
        REPORT_VOID(VSIG_Got_##lower, VSIG_Got_##lower(SIG##UPPER)); \
    } \
    static void call_VSIG_Arm_##lower(payload in) { \
        struct sigaction old[4]; \
        (void)in; \
        signals_save(old); \
        REPORT(VSIG_Arm_##lower, VSIG_Arm_##lower(), handler_is(SIG##UPPER, VSIG_Got_##lower)); \
        signals_restore(old); \
    }
VSIG_WRAP(HUP, hup)
VSIG_WRAP(INT, int)
VSIG_WRAP(TERM, term)
VSIG_WRAP(USR1, usr1)

/* vsl: log records from in-process VSL files */

static struct vsm *vsm;  /* defined with the vsm wrappers below */
static int vsm_attached;
static struct VSL_data *vsl;
static struct VSL_cursor *vslc;  /* owned by the harness until VSL_DeleteCursor / VSLQ_New / VSLQ_SetCursor */
static int vslc_rec;             /* the last VSL_Next returned vsl_more: vslc->rec is a whole record */
/* a read on the cursor returned vsl_e_io: the mmap cursor then reads past its map on every further read
 * (vsl_cursor.c vslc_mmap_next, repro_vsl_mmap_next_oob.c), so it, or the query / VUT holding it, only gets
 * deleted */
static int vslc_broken, vslq_broken;
static struct VSLQ *vslq;
static FILE *vsl_out;            /* VSL_WriteOpen result */
static char good_query[256];     /* last query VSLQ_New accepted, and its grouping */
static int good_query_grouping = -1;

static FILE *vsl_fo(void) { return vsl_out ? vsl_out : devnull_file(); }

static void vsl_tag_cb(int tag, void *priv) {
    (void)tag;
    ++*(unsigned *)priv;
}
static int vslq_count_cb(struct VSL_data *d, struct VSL_transaction *const trans[], void *priv) {
    (void)d;
    for (; *trans; trans++) ++*(unsigned *)priv;
    return 0;
}
static VSLQ_dispatch_f *dispatch_pick(uint8_t b, void **priv) {
    static unsigned count;
    switch (b % 4) {
    case 1: *priv = vsl_fo(); return VSL_PrintTransactions;
    case 2: *priv = vsl_fo(); return VSL_WriteTransactions;
    case 3: *priv = &count; return vslq_count_cb;
    default: *priv = NULL; return NULL;  /* vsl.h VSLQ_Dispatch: "Can be NULL to ignore records" */
    }
}
/* ltl: vsl_data_lifecycle */
static void call_VSL_New(payload in) {
    (void)in;
    if (vsl) return;
    if (!preqed_call("VSL_New")) return;
    vsl = VSL_New();
    preqed_result("VSL_New", vsl != NULL);
}
/* ltl: vsl_data_lifecycle */
static void call_VSL_Arg(payload in) {
    static const char opts[] = "bcCEixIXLRTvZ";  /* vapi_options.h VSL_OPT_*; Z is not one */
    if (!vsl) return;
    as_text(tail(in, 1));
    REPORT(VSL_Arg, int rc = VSL_Arg(vsl, opts[byte(in, 0) % (sizeof opts - 1)], text), rc == 1);
}
/* ltl: vsl_data_lifecycle */
static void call_VSL_Error(payload in) {
    (void)in;
    if (!vsl) return;
    REPORT_VOID(VSL_Error, (void)VSL_Error(vsl));
}
/* ltl: vsl_data_lifecycle */
static void call_VSL_ResetError(payload in) {
    (void)in;
    if (!vsl) return;
    REPORT(VSL_ResetError, VSL_ResetError(vsl), VSL_Error(vsl) == NULL);
}

static void call_VSL_Name2Tag(payload in) {
    const char *end = as_text(tail(in, 1));
    REPORT(VSL_Name2Tag, int t = VSL_Name2Tag(text, byte(in, 0) & 1 ? -1 : (int)(end - text)), t >= 0);
}

static void call_VSL_Glob2Tags(payload in) {
    const char *end = as_text(tail(in, 1));
    unsigned n = 0;
    REPORT(VSL_Glob2Tags, int rc = VSL_Glob2Tags(text, byte(in, 0) & 1 ? -1 : (int)(end - text), vsl_tag_cb, &n),
           rc > 0 && n == (unsigned)rc);
}

static void call_VSL_List2Tags(payload in) {
    const char *end = as_text(tail(in, 1));
    unsigned n = 0;
    REPORT(VSL_List2Tags, int rc = VSL_List2Tags(text, byte(in, 0) & 1 ? -1 : (int)(end - text), vsl_tag_cb, &n), rc > 0);
}

static void call_VSLQ_Name2Grouping(payload in) {
    const char *end = as_text(tail(in, 1));
    REPORT(VSLQ_Name2Grouping, int g = VSLQ_Name2Grouping(text, byte(in, 0) & 1 ? -1 : (int)(end - text)), g >= 0);
}
/* ltl: vsl_data_lifecycle, vsl_cursor_ownership, vsl_cursor_record */
static void call_VSL_CursorFile(payload in) {
    if (!vsl || vslc) return;
    char path[64];
    int fd = vsl_input(tail(in, 1), byte(in, 0) & 1, path, sizeof path);
    if (fd < 0) return;
    if (preqed_call("VSL_CursorFile")) {
        vslc = VSL_CursorFile(vsl, path, 0);
        preqed_result("VSL_CursorFile", vslc != NULL);
        vslc_rec = vslc_broken = 0;
    }
    close(fd);  /* the cursor opened its own descriptor */
}
/* ltl: vsl_data_lifecycle, vsl_cursor_ownership, vsl_cursor_record, vsm_lifecycle, vsm_attach */
static void call_VSL_CursorVSM(payload in) {
    if (!vsl || vslc || !vsm || !vsm_attached) return;  /* VSM_Get inside: AN(vd->attached) */
    static const unsigned opts[] = { 0, VSL_COPT_TAIL, VSL_COPT_BATCH, VSL_COPT_TAILSTOP };
    if (!preqed_call("VSL_CursorVSM")) return;
    vslc = VSL_CursorVSM(vsl, vsm, opts[byte(in, 0) % 4]);
    preqed_result("VSL_CursorVSM", vslc != NULL);
    vslc_rec = vslc_broken = 0;
}
/* ltl: vsl_cursor_ownership, vsl_cursor_record */
static void call_VSL_Next(payload in) {
    (void)in;
    if (!vslc || vslc_broken) return;
    /* ok: the cursor points to a record (vsl.h vsl_more); end, eof and errors leave no record to read */
    REPORT(VSL_Next, enum vsl_status s = VSL_Next(vslc); vslc_rec = s == vsl_more; vslc_broken = s == vsl_e_io,
           s == vsl_more);
}
/* ltl: vsl_cursor_ownership, vsl_cursor_record */
static void call_VSL_Check(payload in) {
    (void)in;
    if (!vslc || !vslc_rec) return;  /* vsl_cursor.c vslc_mmap_check: AN(ptr->ptr), inside the cursor's map */
    REPORT(VSL_Check, enum vsl_check c = VSL_Check(vslc, &vslc->rec), c != vsl_check_e_inval);
}
/* ltl: vsl_cursor_ownership, vsl_cursor_record */
static void call_VSL_ResetCursor(payload in) {
    (void)in;
    if (!vslc) return;
    REPORT(VSL_ResetCursor, enum vsl_status s = VSL_ResetCursor(vslc); vslc_rec = 0, s >= vsl_e_eof);
}
/* ltl: vsl_cursor_ownership */
static void call_VSL_DeleteCursor(payload in) {
    (void)in;
    if (!vslc) return;
    REPORT_VOID(VSL_DeleteCursor, VSL_DeleteCursor(vslc); vslc = NULL);
}
/* ltl: vsl_data_lifecycle, vsl_cursor_ownership, vsl_cursor_record */
static void call_VSL_Match(payload in) {
    (void)in;
    if (!vsl || !vslc || !vslc_rec) return;  /* reads vslc->rec */
    REPORT_VOID(VSL_Match, (void)VSL_Match(vsl, vslc));
}
/* ltl: vsl_data_lifecycle, vsl_cursor_ownership, vsl_cursor_record */
static void call_VSL_Print(payload in) {
    (void)in;
    if (!vsl || !vslc || !vslc_rec) return;  /* reads vslc->rec */
    REPORT(VSL_Print, int rc = VSL_Print(vsl, vslc, vsl_fo()), rc == 0);
}
/* ltl: vsl_data_lifecycle, vsl_cursor_ownership, vsl_cursor_record */
static void call_VSL_PrintTerse(payload in) {
    (void)in;
    if (!vsl || !vslc || !vslc_rec) return;  /* reads vslc->rec */
    REPORT(VSL_PrintTerse, int rc = VSL_PrintTerse(vsl, vslc, vsl_fo()), rc == 0);
}
/* ltl: vsl_data_lifecycle, vsl_cursor_ownership, vsl_cursor_record */
static void call_VSL_PrintAll(payload in) {
    (void)in;
    if (!vsl || !vslc || vslc_broken) return;
    REPORT(VSL_PrintAll, int rc = VSL_PrintAll(vsl, vslc, vsl_fo()); vslc_rec = 0; vslc_broken = rc == vsl_e_io,
           rc == vsl_end || rc == vsl_e_eof);  /* runs the cursor to its end */
}
/* ltl: vsl_data_lifecycle, vsl_cursor_ownership, vsl_cursor_record */
static void call_VSL_Write(payload in) {
    (void)in;
    if (!vsl || !vslc || !vslc_rec) return;  /* reads vslc->rec */
    REPORT(VSL_Write, int rc = VSL_Write(vsl, vslc, vsl_fo()), rc == 0);
}
/* ltl: vsl_data_lifecycle, vsl_cursor_ownership, vsl_cursor_record */
static void call_VSL_WriteAll(payload in) {
    (void)in;
    if (!vsl || !vslc || vslc_broken) return;
    REPORT(VSL_WriteAll, int rc = VSL_WriteAll(vsl, vslc, vsl_fo()); vslc_rec = 0; vslc_broken = rc == vsl_e_io,
           rc == vsl_end || rc == vsl_e_eof);  /* runs the cursor to its end */
}
/* a transaction over the harness cursor (vsl.h struct VSL_transaction) */
static struct VSL_transaction vsl_trans_of(payload in) {
    return (struct VSL_transaction){ .level = byte(in, 0) % 3, .vxid = byte(in, 1), .vxid_parent = 0,
                                     .type = (enum VSL_transaction_e)(byte(in, 2) % VSL_t__MAX),
                                     .reason = (enum VSL_reason_e)(byte(in, 3) % VSL_r__MAX), .c = vslc };
}
/* ltl: vsl_data_lifecycle, vsl_cursor_ownership, vsl_cursor_record */
static void call_VSL_PrintTransactions(payload in) {
    if (!vsl || !vslc || vslc_broken) return;
    struct VSL_transaction t = vsl_trans_of(in), *pt[2] = { &t, NULL };
    REPORT(VSL_PrintTransactions, int rc = VSL_PrintTransactions(vsl, pt, vsl_fo()); vslc_rec = 0; vslc_broken = rc == vsl_e_io,
           rc == vsl_end || rc == vsl_e_eof);
}
/* ltl: vsl_data_lifecycle, vsl_cursor_ownership, vsl_cursor_record */
static void call_VSL_WriteTransactions(payload in) {
    if (!vsl || !vslc || vslc_broken) return;
    struct VSL_transaction t = vsl_trans_of(in), *pt[2] = { &t, NULL };
    REPORT(VSL_WriteTransactions, int rc = VSL_WriteTransactions(vsl, pt, vsl_fo()); vslc_rec = 0; vslc_broken = rc == vsl_e_io,
           rc == vsl_end || rc == vsl_e_eof);
}
/* ltl: vsl_data_lifecycle */
static void call_VSL_WriteOpen(payload in) {
    if (!vsl || vsl_out) return;
    char path[64] = "/dev/null";
    int fd = -1;
    if (byte(in, 0) & 1) {  /* a fresh memfd instead of /dev/null; never a payload-chosen file name */
        fd = memfd_create("vslout", 0);
        if (fd < 0) return;
        snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
    }
    if (preqed_call("VSL_WriteOpen")) {
        vsl_out = VSL_WriteOpen(vsl, path, byte(in, 0) & 2, byte(in, 0) & 4);
        preqed_result("VSL_WriteOpen", vsl_out != NULL);
    }
    if (fd >= 0) close(fd);
}
/* ltl: vsl_data_lifecycle, vsl_cursor_ownership, vslq_lifecycle */
static void call_VSLQ_New(payload in) {
    if (!vsl || vslq) return;
    enum VSL_grouping_e g = (enum VSL_grouping_e)(byte(in, 0) % VSL_g__MAX);
    const char *q = NULL;
    if (byte(in, 1) & 1) {
        as_text(tail(in, 2));
        /* one query line: a bad later line leaks the parsed tree (vxp_parse.c vxp_expr), repro_vslq_query_leak.c */
        char *nl = strchr(text, '\n');
        if (nl) *nl = 0;
        q = text;
    }
    if (!preqed_call("VSLQ_New")) return;
    int broken = vslc && vslc_broken;
    vslq = VSLQ_New(vsl, vslc ? &vslc : NULL, g, q);  /* on success the cursor moves into the query */
    preqed_result("VSLQ_New", vslq != NULL);
    if (vslq) vslq_broken = broken;
    if (vslq && q && strlen(q) < sizeof good_query) {
        strcpy(good_query, q);
        good_query_grouping = (int)g;
    }
}
/* ltl: vsl_cursor_ownership, vslq_lifecycle */
static void call_VSLQ_SetCursor(payload in) {
    (void)in;
    if (!vslq) return;
    REPORT(VSLQ_SetCursor, vslq_broken = vslc && vslc_broken; VSLQ_SetCursor(vslq, vslc ? &vslc : NULL), vslc == NULL);
}
/* ltl: vslq_lifecycle */
static void call_VSLQ_Dispatch(payload in) {
    if (!vslq || vslq_broken) return;
    void *priv;
    VSLQ_dispatch_f *f = dispatch_pick(byte(in, 0), &priv);
    REPORT(VSLQ_Dispatch, int rc = VSLQ_Dispatch(vslq, f, priv); vslq_broken = rc == vsl_e_io, rc >= vsl_e_eof);
}
/* ltl: vslq_lifecycle */
static void call_VSLQ_Flush(payload in) {
    if (!vslq) return;
    void *priv;
    VSLQ_dispatch_f *f = dispatch_pick(byte(in, 0), &priv);
    REPORT(VSLQ_Flush, int rc = VSLQ_Flush(vslq, f, priv), rc == 0);
}
/* ltl: vslq_lifecycle */
static void call_VSLQ_Delete(payload in) {
    (void)in;
    if (!vslq) return;
    REPORT(VSLQ_Delete, VSLQ_Delete(&vslq), vslq == NULL);
}
/* ltl: vsl_data_lifecycle, vslq_lifecycle */
static void call_VSL_Delete(payload in) {
    (void)in;
    if (!vsl) return;
    REPORT_VOID(VSL_Delete, VSL_Delete(vsl); vsl = NULL);
}

/* vsm + vsc: shared memory. The writer side is vinyld's own VSMW (bin/vinyld/common/common_vsmw.c), run in this
 * process on a work directory below the cwd with the mgt and child segment sets, as mgt_shmem.c and
 * cache_shmlog.c set them up; VRT_VSC_* (common_vsc.c) allocate counters in the child set. */

struct heritage heritage;  /* heritage.h; vinyld defines it in mgt_main.c, common_vsc.c uses proc_vsmw */
static struct vsmw *vsmw_mgt;
static void *vsmw_mgt_seg;
static char vsm_wd[512];

static void vsm_writer_fini(void) {
    char p[600];
    if (heritage.proc_vsmw) VSMW_Destroy(&heritage.proc_vsmw);
    if (vsmw_mgt_seg) VSMW_Free(vsmw_mgt, &vsmw_mgt_seg);  /* VSMW_Destroy drops segments, not their clusters */
    if (vsmw_mgt) VSMW_Destroy(&vsmw_mgt);
    snprintf(p, sizeof p, "%s/_.vsm_child", vsm_wd);
    rmdir(p);
    snprintf(p, sizeof p, "%s/_.vsm_mgt", vsm_wd);
    rmdir(p);
    rmdir(vsm_wd);
}
static int vsm_writer(void) {
    char cwd[400], p[600];
    if (vsmw_mgt) return 1;
    if (!getcwd(cwd, sizeof cwd)) return 0;
    snprintf(vsm_wd, sizeof vsm_wd, "%s/vsm.%d", cwd, (int)getpid());
    (void)mkdir(vsm_wd, 0755);
    snprintf(p, sizeof p, "%s/_.vsm_mgt", vsm_wd);
    (void)mkdir(p, 0755);
    int mfd = open(p, O_RDONLY | O_DIRECTORY);
    snprintf(p, sizeof p, "%s/_.vsm_child", vsm_wd);
    (void)mkdir(p, 0755);
    int cfd = open(p, O_RDONLY | O_DIRECTORY);
    if (mfd <= 0 || cfd <= 0) {
        if (mfd >= 0) close(mfd);
        if (cfd >= 0) close(cfd);
        return 0;
    }
    vsmw_mgt = VSMW_New(mfd, 0640, "_.index");
    /* a mgt segment as mgt_shmem.c mgt_SHM_ChildNew allocates: vsm.c VSM__itern stops when the mgt set is empty */
    vsmw_mgt_seg = VSMW_Allocf(vsmw_mgt, NULL, "Panic", 64, "");
    heritage.proc_vsmw = VSMW_New(cfd, 0640, "_.index");
    atexit(vsm_writer_fini);
    return 1;
}

static struct vsm *vsm;
static int vsm_attached, vsm_wd_set, vsm_wd_ours, vsm_patient;
static struct vsm_fantom fantom;
static int fantom_ok;  /* fantom came from VSM_Get / VSM__itern on this vsm */

static void fantom_reset(void) {
    memset(&fantom, 0, sizeof fantom);
    fantom_ok = 0;
}
/* ltl: vsm_lifecycle, vsm_attach, vsm_fantom */
static void call_VSM_New(payload in) {
    (void)in;
    if (vsm) return;
    if (!preqed_call("VSM_New")) return;
    vsm = VSM_New();
    preqed_result("VSM_New", vsm != NULL);
    vsm_attached = vsm_wd_set = vsm_wd_ours = vsm_patient = 0;
    fantom_reset();
}
/* ltl: vsm_lifecycle */
static void call_VSM_Arg(payload in) {
    if (!vsm) return;
    char flag = "ntx"[byte(in, 0) % 3];  /* vsm.h: 'n' instance, 't' patience; others are rejected */
    int ours = flag == 'n' && (byte(in, 1) & 1) && vsm_writer();
    as_text(tail(in, 2));
    if (flag == 'n' && text[0] == '/') text[0] = '_';  /* a relative name stays below VINYL_STATE_DIR */
    const char *arg = ours ? vsm_wd : text;
    if (!preqed_call("VSM_Arg")) return;
    int rc = VSM_Arg(vsm, flag, arg);
    preqed_result("VSM_Arg", rc == 1);
    if (rc == 1 && flag == 'n') {
        vsm_wd_set = 1;
        vsm_wd_ours = ours;
    }
    if (rc == 1 && flag == 't') vsm_patient = strcasecmp(arg, "off") != 0 && strtod(arg, NULL) <= 1.0;
}
/* ltl: vsm_lifecycle, vsm_attach */
static void call_VSM_Attach(payload in) {
    (void)in;
    /* vsm.c VSM_Attach polls until the patience (-t, default 5 s, "off" forever) runs out: only attach to
     * this process's work directory, or with at most 1 s patience */
    if (!vsm || vsm_attached || !(vsm_wd_ours || vsm_patient)) return;
    if (!preqed_call("VSM_Attach")) return;
    int rc = VSM_Attach(vsm, -1);
    preqed_result("VSM_Attach", rc == 0);
    vsm_attached = rc == 0;
    vsm_wd_set = 1;  /* VSM_Attach sets the default instance */
}
/* ltl: vsm_lifecycle */
static void call_VSM_Status(payload in) {
    (void)in;
    if (!vsm || !vsm_wd_set) return;  /* vsm.c VSM_Status opens vd->wdname */
    REPORT_VOID(VSM_Status, (void)VSM_Status(vsm));
}
/* ltl: vsm_lifecycle */
static void call_VSM_Error(payload in) {
    (void)in;
    if (!vsm) return;
    REPORT_VOID(VSM_Error, (void)VSM_Error(vsm));
}
/* ltl: vsm_lifecycle */
static void call_VSM_ResetError(payload in) {
    (void)in;
    if (!vsm) return;
    REPORT(VSM_ResetError, VSM_ResetError(vsm), VSM_Error(vsm) == NULL);
}
/* ltl: vsm_lifecycle, vsm_attach, vsm_fantom */
static void call_VSM__iter0(payload in) {
    (void)in;
    if (!vsm || !vsm_attached || fantom.b) return;  /* a mapped fantom is kept until VSM_Unmap */
    REPORT_VOID(VSM__iter0, VSM__iter0(vsm, &fantom));
    fantom_ok = 0;
}
/* ltl: vsm_lifecycle, vsm_attach, vsm_fantom */
static void call_VSM__itern(payload in) {
    (void)in;
    if (!vsm || !vsm_attached || fantom.b) return;
    if (!fantom_ok && fantom.priv) return;  /* continue from VSM__iter0 or a looked-up fantom */
    if (!preqed_call("VSM__itern")) return;
    int rc = VSM__itern(vsm, &fantom);
    preqed_result("VSM__itern", rc == 1);
    fantom_ok = rc == 1;
    if (!fantom_ok) fantom_reset();
}
static const char *vsm_category(payload in) {
    static const char *const cats[] = { "Stat", "StatDoc", VSL_CLASS };  /* vsc_priv.h VSC_CLASS, VSC_DOC_CLASS */
    if (byte(in, 0) % 4 < 3) return cats[byte(in, 0) % 4];
    as_text(tail(in, 2));
    return text;
}
/* ltl: vsm_lifecycle, vsm_attach, vsm_fantom */
static void call_VSM_Get(payload in) {
    if (!vsm || !vsm_attached || fantom.b) return;
    const char *cat = vsm_category(in);
    if (!preqed_call("VSM_Get")) return;
    int rc = VSM_Get(vsm, &fantom, cat, byte(in, 1) & 1 ? "" : NULL);
    preqed_result("VSM_Get", rc == 1);
    fantom_ok = rc == 1;
}
/* ltl: vsm_lifecycle, vsm_attach */
static void call_VSM_Dup(payload in) {
    if (!vsm || !vsm_attached) return;
    const char *cat = vsm_category(in);
    char *d = NULL;
    REPORT(VSM_Dup, d = VSM_Dup(vsm, cat, byte(in, 1) & 1 ? "" : NULL), d != NULL);
    free(d);
}
/* ltl: vsm_lifecycle, vsm_attach, vsm_fantom */
static void call_VSM_Map(payload in) {
    (void)in;
    if (!vsm || !vsm_attached || !fantom_ok || fantom.b) return;
    REPORT(VSM_Map, int rc = VSM_Map(vsm, &fantom), rc == 0 && fantom.b != NULL);
}
/* ltl: vsm_lifecycle, vsm_attach, vsm_fantom */
static void call_VSM_Unmap(payload in) {
    (void)in;
    if (!vsm || !vsm_attached || !fantom.b) return;  /* vsm.c VSM_Unmap: AN(vf->b) */
    REPORT(VSM_Unmap, int rc = VSM_Unmap(vsm, &fantom), rc == 0);
}
/* ltl: vsm_lifecycle, vsm_fantom */
static void call_VSM_StillValid(payload in) {
    (void)in;
    if (!vsm || !fantom_ok) return;  /* vsm.h: "a previously looked up vsm_fantom" */
    REPORT(VSM_StillValid, const struct vsm_valid *v = VSM_StillValid(vsm, &fantom), v == VSM_valid);
}

static struct vsc *vsc;
static const struct VSC_point *vsc_pt;  /* vsc.h: points are valid until the next VSC_Iter */
static const struct VSC_level_desc *vsc_level;

static void *vsc_new_cb(void *priv, const struct VSC_point *const pt) {
    (void)priv;
    return TRUST_ME(pt);
}
static void vsc_destroy_cb(void *priv, const struct VSC_point *const pt) {
    (void)priv;
    (void)pt;
}
static int vsc_iter_cb(void *priv, const struct VSC_point *const pt) {
    ++*(unsigned *)priv;
    vsc_pt = pt;
    return 0;
}
/* ltl: vsm_lifecycle, vsc_lifecycle */
static void call_VSM_Destroy(payload in) {
    (void)in;
    if (!vsm) return;
    if (!preqed_call("VSM_Destroy")) return;
    VSM_Destroy(&vsm);
    preqed_result("VSM_Destroy", vsm == NULL);
    fantom_reset();
    vsm_attached = 0;
    vsc_pt = NULL;
}
/* ltl: vsc_lifecycle */
static void call_VSC_New(payload in) {
    (void)in;
    if (vsc) return;
    if (!preqed_call("VSC_New")) return;
    vsc = VSC_New();
    preqed_result("VSC_New", vsc != NULL);
    vsc_pt = NULL;
}
/* ltl: vsc_lifecycle */
static void call_VSC_Arg(payload in) {
    static const char args[] = "IXRfrq";  /* vsc.h VSC_Arg; q is not handled (returns 0) */
    if (!vsc) return;
    as_text(tail(in, 1));
    REPORT(VSC_Arg, int rc = VSC_Arg(vsc, args[byte(in, 0) % 6], text), rc == 1);
}
/* ltl: vsc_lifecycle */
static void call_VSC_State(payload in) {
    if (!vsc) return;
    int on = byte(in, 0) & 1;  /* vsc.c VSC_State: both functions or neither */
    /* removing the functions destroys the exposed points */
    REPORT_VOID(VSC_State, VSC_State(vsc, on ? vsc_new_cb : NULL, on ? vsc_destroy_cb : NULL, NULL); vsc_pt = NULL);
}
/* ltl: vsm_lifecycle, vsm_attach, vsc_lifecycle */
static void call_VSC_Iter(payload in) {
    (void)in;
    if (!vsc || !vsm || !vsm_attached) return;  /* VSC_Iter walks VSM_FOREACH: needs an attached vsm */
    unsigned n = 0;
    vsc_pt = NULL;
    REPORT(VSC_Iter, int rc = VSC_Iter(vsc, vsm, vsc_iter_cb, &n), rc == 0);
}

static void call_VSC_Value(payload in) {
    (void)in;
    if (!vsc_pt) return;
    REPORT_VOID(VSC_Value, (void)VSC_Value(vsc_pt));
}
/* ltl: vsc_lifecycle */
static void call_VSC_IsRaw(payload in) {
    (void)in;
    if (!vsc) return;
    REPORT_VOID(VSC_IsRaw, (void)VSC_IsRaw(vsc));
}

static void call_VSC_ChangeLevel(payload in) {
    REPORT(VSC_ChangeLevel, vsc_level = VSC_ChangeLevel(vsc_level, (int)(byte(in, 0) % 5) - 2), vsc_level != NULL);
}
/* ltl: vsc_lifecycle */
static void call_VSC_Destroy(payload in) {
    (void)in;
    if (!vsc) return;
    /* the vsm VSC_Iter mapped the segments with (vsc_lifecycle keeps it alive until here) */
    REPORT(VSC_Destroy, VSC_Destroy(&vsc, vsm); vsc_pt = NULL, vsc == NULL);
}

static struct vsc_seg *vrt_seg;

static void *vrt_vsc_allocv(struct vsc_seg **sg, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    void *r = VRT_VSC_Allocv(NULL, sg, vsc_debug_name, VSC_debug_size, vsc_debug_json, sizeof vsc_debug_json, fmt, ap);
    va_end(ap);
    return r;
}
/* ltl: vrt_vsc_segment */
static void call_VRT_VSC_Alloc(payload in) {
    if (vrt_seg || !vsm_writer()) return;
    char id[32];
    ident_of(tail(in, 1), id, sizeof id);
    if (!preqed_call("VRT_VSC_Alloc")) return;
    /* as the generated VSC_debug_New does; common_vsmw.c VSMW_Allocv: a non-empty fmt must print something */
    struct VSC_debug *c = VRT_VSC_Alloc(NULL, &vrt_seg, vsc_debug_name, VSC_debug_size, vsc_debug_json,
                                        sizeof vsc_debug_json, id[0] ? "%s" : "", id);
    preqed_result("VRT_VSC_Alloc", c != NULL && vrt_seg != NULL);
    if (c) c->count = byte(in, 0);
}
/* ltl: vrt_vsc_segment */
static void call_VRT_VSC_Allocv(payload in) {
    if (vrt_seg || !vsm_writer()) return;
    char id[32];
    ident_of(tail(in, 1), id, sizeof id);
    if (!preqed_call("VRT_VSC_Allocv")) return;
    struct VSC_debug *c = vrt_vsc_allocv(&vrt_seg, "%s.%u", id, byte(in, 0));
    preqed_result("VRT_VSC_Allocv", c != NULL && vrt_seg != NULL);
    if (c) c->count = UINT64_MAX - byte(in, 0);  /* above INT64_MAX: VSC_Value's gauge clamp */
}
/* ltl: vrt_vsc_segment */
static void call_VRT_VSC_Hide(payload in) {
    (void)in;
    if (!vrt_seg) return;
    REPORT_VOID(VRT_VSC_Hide, VRT_VSC_Hide(vrt_seg));
}
/* ltl: vrt_vsc_segment */
static void call_VRT_VSC_Reveal(payload in) {
    (void)in;
    if (!vrt_seg) return;
    REPORT_VOID(VRT_VSC_Reveal, VRT_VSC_Reveal(vrt_seg));
}
/* ltl: vrt_vsc_segment */
static void call_VRT_VSC_Destroy(payload in) {
    (void)in;
    if (!vrt_seg) return;
    /* common_vsc.c: assert(vsg->nm == nm), the name pointer given to the Alloc */
    REPORT_VOID(VRT_VSC_Destroy, VRT_VSC_Destroy(vsc_debug_name, vrt_seg); vrt_seg = NULL);
}

static void call_VRT_VSC_Overhead(payload in) {
    size_t n = u16_of(in, 0);
    REPORT(VRT_VSC_Overhead, size_t z = VRT_VSC_Overhead(n), z >= n);
}

/* vut: the log-utility driver, on in-process VSL files (-r) or this process's VSM work directory (-n) */

static struct VUT *vut;
static int vut_rfd = -1;  /* backs the -r file name */
static int vut_is_setup;
static int vut_broken;    /* VUT_Main's cursor returned vsl_e_io: see vslc_broken */
static char vut_rpath[64];

static const char *vut_usage[] = { "[-d]", "Process old log entries", NULL, NULL };
static const struct vopt_list vut_optlist[] = { { "d", "[-d]", "Process old log entries", "" } };
static const struct vopt_spec vut_spec = { vut_optlist, 1, "d", " [-d]", vut_usage };
static char *const vut_argv[] = { "fuzzer", NULL };

static void vut_sig_cb(int sig) { (void)sig; }
/* ltl: vut_lifecycle */
static void call_VUT_Init(payload in) {
    (void)in;
    if (vut) return;
    struct sigaction old[4];
    signals_save(old);  /* VUT_Init arms the VSIG handlers */
    if (preqed_call("VUT_Init")) {
        vut = VUT_Init("fuzzer", 1, vut_argv, &vut_spec);
        preqed_result("VUT_Init", vut != NULL);
    }
    signals_restore(old);
    vut_is_setup = 0;
}
/* ltl: vut_lifecycle */
static void call_VUT_Arg(payload in) {
    if (!vut) return;
    /* VUT_Arg and VUT_Setup call VUT_Error, i.e. exit(3), on a bad argument: only arguments they accept, no
     * -D (daemon), -P (pid file), -V / -Q (exit, file) */
    char arg[64] = "";
    int opt;
    switch (byte(in, 0) % 12) {
    case 0: opt = '0'; break;
    case 1: opt = 'd'; break;
    case 2:
        if (vut->q_arg) return;  /* the accepted query was checked under its grouping */
        opt = 'g';
        snprintf(arg, sizeof arg, "%s", VSLQ_grouping[byte(in, 1) % VSL_g__MAX]);
        break;
    case 3: opt = 'k'; snprintf(arg, sizeof arg, "%u", 1 + byte(in, 1)); break;
    case 4:
        if (vut->r_arg || !vsm_writer()) return;  /* vut.c VUT_Setup: only one of -n and -r */
        opt = 'n';
        snprintf(arg, sizeof arg, "%s", vsm_wd);
        if (strlen(vsm_wd) >= sizeof arg) return;
        break;
    case 5:
        if (vut->q_arg || good_query_grouping != vut->g_arg || !good_query[0] || strlen(good_query) >= sizeof arg) return;
        opt = 'q';
        strcpy(arg, good_query);
        break;
    case 6: {
        if (vut->n_arg) return;
        if (vut_rfd >= 0) close(vut_rfd);
        vut_rfd = vsl_input(tail(in, 2), byte(in, 1) & 1, vut_rpath, sizeof vut_rpath);
        if (vut_rfd < 0) return;
        opt = 'r';
        snprintf(arg, sizeof arg, "%s", vut_rpath);
        break;
    }
    case 7: opt = 't'; snprintf(arg, sizeof arg, "%u", byte(in, 1) % 2); break;
    case 8: opt = "bcCEv"[byte(in, 1) % 5]; break;
    case 9: opt = 'L'; snprintf(arg, sizeof arg, "%u", 1 + byte(in, 1)); break;
    case 10: opt = 'T'; snprintf(arg, sizeof arg, "%u.%u", byte(in, 1), byte(in, 2) % 10); break;
    default: opt = 'x'; snprintf(arg, sizeof arg, "%s", "Begin,End"); break;  /* a tag list VSL_Arg accepts */
    }
    REPORT(VUT_Arg, int rc = VUT_Arg(vut, opt, arg), rc == 1);
}
/* ltl: vut_lifecycle */
static void call_VUT_Setup(payload in) {
    (void)in;
    /* input from -r or this process's -n directory (attaches at once); -0 (dry run) stops before the input */
    if (!vut || !(vut->r_arg || vut->n_arg || vut->dryrun_opt)) return;
    /* vsm.c VSM_Attach gives up once VSIG_int / VSIG_term are raised, and VUT_Setup then exits */
    if (vut->n_arg && !vut->dryrun_opt && (VSIG_int || VSIG_term)) return;
    REPORT(VUT_Setup, VUT_Setup(vut); vut_is_setup = 1; vut_broken = 0, vut->vslq != NULL);
}
/* ltl: vut_lifecycle */
static void call_VUT_Main(payload in) {
    (void)in;
    /* with VSM input VUT_Main loops until a signal (no shmlog here): only -r input or a dry run */
    if (!vut || !vut_is_setup || vut_broken || (vut->vsm && !vut->dryrun_opt)) return;
    vut->dispatch_f = VSL_PrintTransactions;  /* vut.h struct VUT callback fields */
    vut->dispatch_priv = devnull_file();
    REPORT(VUT_Main, int rc = VUT_Main(vut); vut_broken = rc == vsl_e_io, rc >= vsl_e_eof);
}
/* ltl: vut_lifecycle */
static void call_VUT_Signaled(payload in) {
    if (!vut) return;
    static const int sigs[] = { SIGHUP, SIGINT, SIGTERM, SIGUSR1, SIGUSR2 };
    REPORT_VOID(VUT_Signaled, VUT_Signaled(vut, sigs[byte(in, 0) % 5]));
}

static void call_VUT_Signal(payload in) {
    (void)in;
    struct sigaction old[4];
    signals_save(old);
    REPORT(VUT_Signal, VUT_Signal(vut_sig_cb), handler_is(SIGHUP, vut_sig_cb) && handler_is(SIGUSR1, vut_sig_cb));
    signals_restore(old);
}
/* ltl: vut_lifecycle */
static void call_VUT_Fini(payload in) {
    (void)in;
    if (!vut) return;
    REPORT(VUT_Fini, VUT_Fini(&vut); vut_is_setup = 0, vut == NULL);
}

/* dispatch */

static void (*const api[])(payload) = {
    call_VAV_Parse, call_VAV_ParseTxt, call_VAV_Free, call_VAV_BackSlash, call_VAV_BackSlashDecode,
    call_VNUM, call_VNUM_duration, call_VNUM_duration_unit, call_VNUM_bytes_unit, call_VNUM_2bytes,
    call_VNUM_uint, call_VNUM_hex, call_SF_Parse_Integer, call_SF_Parse_Decimal, call_SF_Parse_Number,
    call_VCT_invalid_name,
    call_vct_isows, call_vct_issp, call_vct_ishex, call_vct_islws, call_vct_isctl, call_vct_isspace,
    call_vct_isdigit, call_vct_isalpha, call_vct_islower, call_vct_isupper, call_vct_isalnum, call_vct_isbase64,
    call_vct_issep, call_vct_issepctl, call_vct_isident1, call_vct_isident, call_vct_isxmlnamestart,
    call_vct_isxmlname, call_vct_istchar, call_vct_ishdrval, call_vct_is,
    call_vct_iscrlf, call_vct_skipcrlf, call_vct_casecmp, call_vct_caselencmp,
    call_VAS_errtxt, call_VBT_dump,
    call_VSB_new_auto, call_VSB_init, call_VSB_clear, call_VSB_bcat, call_VSB_cat, call_VSB_putc,
    call_VSB_printf, call_VSB_vprintf, call_VSB_quote, call_VSB_quote_pfx, call_VSB_indent, call_VBT_format,
    call_VSB_finish, call_VSB_data, call_VSB_tofile, call_VSB_len, call_VSB_error, call_VSB_destroy, call_VSB_fini,
    call_VBH_new, call_VBH_insert, call_VBH_reorder, call_VBH_delete, call_VBH_root, call_VBH_destroy, call_vbit_new,
    call_vbit_init, call_vbit_set, call_vbit_clr, call_vbit_test, call_vbit_expand, call_vbit_destroy,
    call_vbit_rndup, call_VRE_compile, call_VRE_match, call_VRE_capture, call_VRE_sub, call_VRE_export,
    call_VRE_unpack, call_VRE_free, call_VRE_error, call_VRE_quote, call_VRND_SeedTestable, call_VRND_RandomTestable,
    call_VRND_RandomTestableDouble, call_VRND_RandomCrypto, call_VRND_SeedAll, call_VSA_Init, call_VSA_Malloc,
    call_VSA_Build, call_VSA_BuildFAP, call_VSA_Clone, call_VSA_free, call_VSA_Sane, call_VSA_Port, call_VSA_Compare,
    call_VSA_Compare_IP, call_VSA_Get_Sockaddr, call_VSA_Get_Proto, call_VSA_GetPtr, call_VTCP_Check,
    call_VTCP_listen, call_VTCP_bind, call_VTCP_listen_on, call_VTCP_connect, call_VTCP_open, call_VTCP_connected,
    call_VTCP_close, call_VTCP_blocking, call_VTCP_nonblocking, call_VTCP_linger, call_VTCP_check_hup,
    call_VTCP_set_read_timeout, call_VTCP_read, call_VTCP_myname, call_VTCP_hisname, call_VTCP_my_suckaddr,
    call_VSA_getsockname, call_VSA_getpeername, call_VTCP_name, call_VTCP_filter_http, call_VTCP_fastopen,
    call_VSHA256_Init, call_VSHA256_Update, call_VSHA256_Final, call_VSHA256_Test, call_VTE_new, call_VTE_putc,
    call_VTE_cat, call_VTE_printf, call_VTE_finish, call_VTE_format, call_VTE_dump, call_VTE_destroy,
    call_VTIM_format, call_VTIM_parse, call_VTIM_mono, call_VTIM_real, call_VTIM_sleep, call_VTIM_timespec,
    call_VTIM_timeval, call_VTIM_timeval_sock, call_VTIM_poll_tmo, call_VCS_String, call_VCS_Message,
    call_VCLI_WriteResult, call_VCLI_ReadResult, call_VCLI_AuthResponse, call_VSIG_Got_hup, call_VSIG_Arm_hup,
    call_VSIG_Got_int, call_VSIG_Arm_int, call_VSIG_Got_term, call_VSIG_Arm_term, call_VSIG_Got_usr1,
    call_VSIG_Arm_usr1, call_VSL_New, call_VSL_Arg, call_VSL_Error, call_VSL_ResetError, call_VSL_Name2Tag,
    call_VSL_Glob2Tags, call_VSL_List2Tags, call_VSLQ_Name2Grouping, call_VSL_CursorFile, call_VSL_CursorVSM,
    call_VSL_Next, call_VSL_Check, call_VSL_ResetCursor, call_VSL_DeleteCursor, call_VSL_Match, call_VSL_Print,
    call_VSL_PrintTerse, call_VSL_PrintAll, call_VSL_Write, call_VSL_WriteAll, call_VSL_PrintTransactions,
    call_VSL_WriteTransactions, call_VSL_WriteOpen, call_VSLQ_New, call_VSLQ_SetCursor, call_VSLQ_Dispatch,
    call_VSLQ_Flush, call_VSLQ_Delete, call_VSL_Delete, call_VSM_New, call_VSM_Arg, call_VSM_Attach, call_VSM_Status,
    call_VSM_Error, call_VSM_ResetError, call_VSM__iter0, call_VSM__itern, call_VSM_Get, call_VSM_Dup, call_VSM_Map,
    call_VSM_Unmap, call_VSM_StillValid, call_VSM_Destroy, call_VSC_New, call_VSC_Arg, call_VSC_State, call_VSC_Iter,
    call_VSC_Value, call_VSC_IsRaw, call_VSC_ChangeLevel, call_VSC_Destroy, call_VRT_VSC_Alloc, call_VRT_VSC_Allocv,
    call_VRT_VSC_Hide, call_VRT_VSC_Reveal, call_VRT_VSC_Destroy, call_VRT_VSC_Overhead, call_VUT_Init, call_VUT_Arg,
    call_VUT_Setup, call_VUT_Main, call_VUT_Signaled, call_VUT_Signal, call_VUT_Fini,
};

#define API_COUNT (sizeof api / sizeof api[0])

static void cleanup(void) {
    if (argv_held) VAV_Free(argv_held);
    free(decoded);
    if (vsb && vsb_dynamic) VSB_destroy(&vsb);
    if (vsb && !vsb_dynamic) VSB_fini(vsb);
    argv_held = NULL;
    decoded = NULL;
    vsb = NULL;

    /* users before what they use: VUT, query, cursor, VSL data; VSC before the vsm it mapped with */
    if (vut) VUT_Fini(&vut);
    vut_is_setup = 0;
    if (vut_rfd >= 0) close(vut_rfd);
    vut_rfd = -1;
    if (vslq) VSLQ_Delete(&vslq);
    if (vslc) VSL_DeleteCursor(vslc);
    vslc = NULL;
    vslc_broken = vslq_broken = vut_broken = 0;
    if (vsl) VSL_Delete(vsl);
    vsl = NULL;
    if (vsl_out) fclose(vsl_out);
    vsl_out = NULL;
    if (vsc) VSC_Destroy(&vsc, vsm);
    vsc_pt = NULL;
    vsc_level = NULL;
    if (vsm) VSM_Destroy(&vsm);
    vsm_attached = 0;
    fantom_reset();
    if (vrt_seg) VRT_VSC_Destroy(vsc_debug_name, vrt_seg);
    vrt_seg = NULL;
    if (vte) VTE_destroy(&vte);
    if (heap) {
        for (unsigned k = 0; k < HEAP_SLOTS; k++)
            if (heap_items[k].in) VBH_delete(heap, heap_items[k].idx);
        VBH_destroy(&heap);
    }
    heap_n = 0;
    memset(heap_items, 0, sizeof heap_items);
    if (vb) vbit_destroy(vb);
    vb = NULL;
    if (re) VRE_free(&re);
    if (sua_owned) VSA_free(&sua_owned);
    sua_built = NULL;
    vsa_inited = 0;
    if (tcp_client >= 0) close(tcp_client);
    if (tcp_listen >= 0) close(tcp_listen);
    tcp_client_gone();
    tcp_listen = -1;
    /* the vsig.h flags are process-wide; a raised VSIG_int / VSIG_term would stop VUT_Main and VSM_Attach */
    VSIG_hup = VSIG_int = VSIG_term = VSIG_usr1 = 0;
    good_query[0] = 0;
    good_query_grouping = -1;
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
