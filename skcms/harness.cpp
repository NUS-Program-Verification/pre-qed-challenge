#include "skcms.h"
#include "preqed_ltl.h"

#include <cstdint>
#include <cstring>

struct payload {
    const uint8_t *p;
    size_t n;
};

/* skcms_Transform converts 1..256 pixels per call */
#define MAX_PIXELS 256
/* ICC profile bytes kept per slot: 64 KiB covers every profile in the upstream corpus */
#define ICC_CAP (1 << 16)

struct profile_slot {
    skcms_ICCProfile profile;
    uint8_t icc[ICC_CAP + 4];   /* backing store: skcms_Parse keeps pointers into it */
    bool valid;
};

static profile_slot src, dst;
static skcms_TransferFunction tf;
static bool tf_valid;
static skcms_Matrix3x3 matrix;
static bool matrix_valid;
/* 16 bytes per pixel = the widest format (RGBA_ffff) */
alignas(4) static uint8_t pixels_in[MAX_PIXELS * 16];
alignas(4) static uint8_t pixels_out[MAX_PIXELS * 16];

static uint8_t byte(payload in, size_t i) { return i < in.n ? in.p[i] : 0; }
static payload rest(payload in, size_t skip) {
    return { in.p + (skip < in.n ? skip : in.n), in.n > skip ? in.n - skip : 0 };
}
static float number(payload in, size_t i) {
    float f = 0;
    if (i + sizeof f <= in.n) std::memcpy(&f, in.p + i, sizeof f);
    return f == f && f - f == 0 ? f : 0;
}
static profile_slot &slot(uint8_t b) { return b & 1 ? dst : src; }
static skcms_PixelFormat pixel_format(uint8_t b) {
    return static_cast<skcms_PixelFormat>(b % (skcms_PixelFormat_BGRA_10101010_XR + 1));
}
static skcms_AlphaFormat alpha_format(uint8_t b) {
    return static_cast<skcms_AlphaFormat>(b % 3);
}
/* A transfer function or matrix is either the one the harness holds or a raw struct from payload bytes. */
static const skcms_TransferFunction *tf_arg(payload in, skcms_TransferFunction &raw) {
    if (byte(in, 0) & 1 || !tf_valid) {
        /* g, a, b, c, d, e, f from consecutive 4-byte floats */
        raw = { number(in, 1), number(in, 5), number(in, 9), number(in, 13), number(in, 17), number(in, 21), number(in, 25) };
        return &raw;
    }
    return &tf;
}
static const skcms_Matrix3x3 *matrix_arg(payload in, skcms_Matrix3x3 &raw) {
    if (byte(in, 0) & 1 || !matrix_valid) {
        for (int r = 0; r < 3; r++)
            for (int c = 0; c < 3; c++) raw.vals[r][c] = number(in, 1 + (r * 3 + c) * 4);
        return &raw;
    }
    return &matrix;
}
static const skcms_Curve *curve_of(const profile_slot &s, uint8_t b) {
    if (!s.valid) return nullptr;
    if (s.profile.has_trc) return &s.profile.trc[b % 3];
    if (s.profile.has_A2B) return &s.profile.A2B.input_curves[b % 4];
    return nullptr;
}

#define REPORT(api, stmt, ok_cond) \
    do { if (preqed_call(#api)) { stmt; preqed_result(#api, (ok_cond)); } } while (0)
#define REPORT_VOID(api, stmt) REPORT(api, stmt, true)

/* profiles */
/* ltl: profile_initialised_before_use */
static void call_skcms_Parse(payload in) {
    profile_slot &s = slot(byte(in, 0));
    payload icc = rest(in, 1);
    size_t n = icc.n < ICC_CAP ? icc.n : ICC_CAP;
    std::memcpy(s.icc, icc.p, n);
    if (!preqed_call("skcms_Parse")) return;
    s.valid = skcms_Parse(s.icc, n, &s.profile);
    preqed_result("skcms_Parse", s.valid);
}
/* ltl: profile_initialised_before_use */
static void call_skcms_ParseWithA2BPriority(payload in) {
    profile_slot &s = slot(byte(in, 0));
    /* A2B0/A2B1/A2B2 preference order, 1..3 entries (skcms_public.h) */
    int priority[3] = { byte(in, 1) % 3, byte(in, 2) % 3, byte(in, 3) % 3 };
    payload icc = rest(in, 4);
    size_t n = icc.n < ICC_CAP ? icc.n : ICC_CAP;
    std::memcpy(s.icc, icc.p, n);
    if (!preqed_call("skcms_ParseWithA2BPriority")) return;
    s.valid = skcms_ParseWithA2BPriority(s.icc, n, priority, 1 + byte(in, 1) % 3, &s.profile);
    preqed_result("skcms_ParseWithA2BPriority", s.valid);
}
/* ltl: profile_initialised_before_use */
static void call_skcms_sRGB_profile(payload in) {
    profile_slot &s = slot(byte(in, 0));
    if (!preqed_call("skcms_sRGB_profile")) return;
    s.profile = *skcms_sRGB_profile();
    s.valid = true;
    preqed_result("skcms_sRGB_profile", true);
}
/* ltl: profile_initialised_before_use */
static void call_skcms_XYZD50_profile(payload in) {
    profile_slot &s = slot(byte(in, 0));
    if (!preqed_call("skcms_XYZD50_profile")) return;
    s.profile = *skcms_XYZD50_profile();
    s.valid = true;
    preqed_result("skcms_XYZD50_profile", true);
}
/* ltl: profile_initialised_before_use */
static void call_skcms_Init(payload in) {
    profile_slot &s = slot(byte(in, 0));
    REPORT_VOID(skcms_Init, skcms_Init(&s.profile));
    s.valid = true;
}
/* ltl: profile_initialised_before_use, transfer_function_initialised_before_use */
static void call_skcms_SetTransferFunction(payload in) {
    profile_slot &s = slot(byte(in, 0));
    if (!s.valid || !tf_valid || skcms_TransferFunction_getType(&tf) != skcms_TFType_sRGBish) return;
    REPORT_VOID(skcms_SetTransferFunction, skcms_SetTransferFunction(&s.profile, &tf));
}
/* ltl: profile_initialised_before_use */
static void call_skcms_SetXYZD50(payload in) {
    profile_slot &s = slot(byte(in, 0));
    if (!s.valid || !matrix_valid) return;
    REPORT_VOID(skcms_SetXYZD50, skcms_SetXYZD50(&s.profile, &matrix));
}
/* ltl: profile_initialised_before_use */
static void call_skcms_ApproximatelyEqualProfiles(payload) {
    if (!src.valid || !dst.valid) return;
    REPORT_VOID(skcms_ApproximatelyEqualProfiles, skcms_ApproximatelyEqualProfiles(&src.profile, &dst.profile));
}
/* ltl: profile_initialised_before_use, transfer_function_initialised_before_use */
static void call_skcms_TRCs_AreApproximateInverse(payload in) {
    profile_slot &s = slot(byte(in, 0));
    if (!s.valid || !tf_valid) return;
    REPORT_VOID(skcms_TRCs_AreApproximateInverse, skcms_TRCs_AreApproximateInverse(&s.profile, &tf));
}
/* ltl: profile_initialised_before_use */
static void call_skcms_GetCHAD(payload in) {
    profile_slot &s = slot(byte(in, 0));
    if (!s.valid) return;
    skcms_Matrix3x3 m;
    REPORT(skcms_GetCHAD, bool ok = skcms_GetCHAD(&s.profile, &m), ok);
}
/* ltl: profile_initialised_before_use */
static void call_skcms_GetWTPT(payload in) {
    profile_slot &s = slot(byte(in, 0));
    if (!s.valid) return;
    float xyz[3];
    REPORT(skcms_GetWTPT, bool ok = skcms_GetWTPT(&s.profile, xyz), ok);
}
/* ltl: profile_initialised_before_use */
static void call_skcms_GetInputChannelCount(payload in) {
    profile_slot &s = slot(byte(in, 0));
    if (!s.valid) return;
    REPORT(skcms_GetInputChannelCount, int n = skcms_GetInputChannelCount(&s.profile), n > 0);
}
/* ltl: profile_initialised_before_use */
static void call_skcms_MakeUsableAsDestination(payload in) {
    profile_slot &s = slot(byte(in, 0));
    if (!s.valid) return;
    REPORT(skcms_MakeUsableAsDestination, bool ok = skcms_MakeUsableAsDestination(&s.profile), ok);
}
/* ltl: profile_initialised_before_use */
static void call_skcms_MakeUsableAsDestinationWithSingleCurve(payload in) {
    profile_slot &s = slot(byte(in, 0));
    if (!s.valid) return;
    REPORT(skcms_MakeUsableAsDestinationWithSingleCurve, bool ok = skcms_MakeUsableAsDestinationWithSingleCurve(&s.profile), ok);
}

/* curves */
/* ltl: profile_initialised_before_use, transfer_function_initialised_before_use */
static void call_skcms_ApproximateCurve(payload in) {
    const skcms_Curve *c = curve_of(slot(byte(in, 0)), byte(in, 1));
    if (!c) return;
    skcms_TransferFunction approx;
    float max_error;
    if (!preqed_call("skcms_ApproximateCurve")) return;
    bool ok = skcms_ApproximateCurve(c, &approx, &max_error);
    preqed_result("skcms_ApproximateCurve", ok);
    if (ok) {
        tf = approx;
        tf_valid = true;
    }
}
/* ltl: profile_initialised_before_use, transfer_function_initialised_before_use */
static void call_skcms_AreApproximateInverses(payload in) {
    const skcms_Curve *c = curve_of(slot(byte(in, 0)), byte(in, 1));
    if (!c || !tf_valid) return;
    REPORT_VOID(skcms_AreApproximateInverses, skcms_AreApproximateInverses(c, &tf));
}

/* transfer functions */
/* ltl: transfer_function_initialised_before_use */
static void call_skcms_sRGB_TransferFunction(payload) {
    REPORT_VOID(skcms_sRGB_TransferFunction, tf = *skcms_sRGB_TransferFunction());
    tf_valid = true;
}
/* ltl: transfer_function_initialised_before_use */
static void call_skcms_sRGB_Inverse_TransferFunction(payload) {
    REPORT_VOID(skcms_sRGB_Inverse_TransferFunction, tf = *skcms_sRGB_Inverse_TransferFunction());
    tf_valid = true;
}
/* ltl: transfer_function_initialised_before_use */
static void call_skcms_Identity_TransferFunction(payload) {
    REPORT_VOID(skcms_Identity_TransferFunction, tf = *skcms_Identity_TransferFunction());
    tf_valid = true;
}

static void call_skcms_TransferFunction_eval(payload in) {
    skcms_TransferFunction raw;
    const skcms_TransferFunction *f = tf_arg(in, raw);
    REPORT_VOID(skcms_TransferFunction_eval, skcms_TransferFunction_eval(f, number(in, 29)));
}
/* ltl: transfer_function_initialised_before_use */
static void call_skcms_TransferFunction_invert(payload in) {
    skcms_TransferFunction raw, inv;
    const skcms_TransferFunction *f = tf_arg(in, raw);
    if (!preqed_call("skcms_TransferFunction_invert")) return;
    bool ok = skcms_TransferFunction_invert(f, &inv);
    preqed_result("skcms_TransferFunction_invert", ok);
    if (ok) {
        tf = inv;
        tf_valid = true;
    }
}

static void call_skcms_TransferFunction_getType(payload in) {
    skcms_TransferFunction raw;
    REPORT_VOID(skcms_TransferFunction_getType, skcms_TransferFunction_getType(tf_arg(in, raw)));
}
/* ltl: transfer_function_initialised_before_use */
static void call_skcms_TransferFunction_makePQish(payload in) {
    if (!preqed_call("skcms_TransferFunction_makePQish")) return;
    /* A, B, C, D, E, F from six 4-byte floats */
    bool ok = skcms_TransferFunction_makePQish(&tf, number(in, 0), number(in, 4), number(in, 8),
                                               number(in, 12), number(in, 16), number(in, 20));
    preqed_result("skcms_TransferFunction_makePQish", ok);
    tf_valid = tf_valid || ok;
}
/* ltl: transfer_function_initialised_before_use */
static void call_skcms_TransferFunction_makeScaledHLGish(payload in) {
    if (!preqed_call("skcms_TransferFunction_makeScaledHLGish")) return;
    /* K, R, G, a, b, c */
    bool ok = skcms_TransferFunction_makeScaledHLGish(&tf, number(in, 0), number(in, 4), number(in, 8),
                                                      number(in, 12), number(in, 16), number(in, 20));
    preqed_result("skcms_TransferFunction_makeScaledHLGish", ok);
    tf_valid = tf_valid || ok;
}
/* ltl: transfer_function_initialised_before_use */
static void call_skcms_TransferFunction_makeHLGish(payload in) {
    if (!preqed_call("skcms_TransferFunction_makeHLGish")) return;
    /* R, G, a, b, c */
    bool ok = skcms_TransferFunction_makeHLGish(&tf, number(in, 0), number(in, 4), number(in, 8),
                                                number(in, 12), number(in, 16));
    preqed_result("skcms_TransferFunction_makeHLGish", ok);
    tf_valid = tf_valid || ok;
}
/* ltl: transfer_function_initialised_before_use */
static void call_skcms_TransferFunction_makePQ(payload in) {
    REPORT_VOID(skcms_TransferFunction_makePQ, skcms_TransferFunction_makePQ(&tf, number(in, 0)));
    tf_valid = true;
}
/* ltl: transfer_function_initialised_before_use */
static void call_skcms_TransferFunction_makeHLG(payload in) {
    /* hdr_reference_white, peak luminance, system gamma (defaults 203, 1000, 1.2) */
    REPORT_VOID(skcms_TransferFunction_makeHLG, skcms_TransferFunction_makeHLG(&tf, number(in, 0), number(in, 4), number(in, 8)));
    tf_valid = true;
}

#define TF_PREDICATE(api) \
    static void call_##api(payload in) { \
        skcms_TransferFunction raw; \
        REPORT_VOID(api, api(tf_arg(in, raw))); \
    }
TF_PREDICATE(skcms_TransferFunction_isSRGBish)
TF_PREDICATE(skcms_TransferFunction_isPQish)
TF_PREDICATE(skcms_TransferFunction_isHLGish)
TF_PREDICATE(skcms_TransferFunction_isPQ)
TF_PREDICATE(skcms_TransferFunction_isHLG)

/* matrices */

static void call_skcms_Matrix3x3_invert(payload in) {
    skcms_Matrix3x3 raw, inv;
    const skcms_Matrix3x3 *m = matrix_arg(in, raw);
    if (!preqed_call("skcms_Matrix3x3_invert")) return;
    bool ok = skcms_Matrix3x3_invert(m, &inv);
    preqed_result("skcms_Matrix3x3_invert", ok);
    if (ok) {
        matrix = inv;
        matrix_valid = true;
    }
}

static void call_skcms_Matrix3x3_concat(payload in) {
    skcms_Matrix3x3 raw;
    const skcms_Matrix3x3 *m = matrix_arg(in, raw);
    const skcms_Matrix3x3 *other = byte(in, 0) & 2 && dst.valid && dst.profile.has_toXYZD50 ? &dst.profile.toXYZD50 : m;
    REPORT_VOID(skcms_Matrix3x3_concat, matrix = skcms_Matrix3x3_concat(m, other));
    matrix_valid = true;
}

static void call_skcms_AdaptToXYZD50(payload in) {
    if (!preqed_call("skcms_AdaptToXYZD50")) return;
    bool ok = skcms_AdaptToXYZD50(number(in, 0), number(in, 4), &matrix);  /* white point x, y */
    preqed_result("skcms_AdaptToXYZD50", ok);
    matrix_valid = matrix_valid || ok;
}

static void call_skcms_PrimariesToXYZD50(payload in) {
    if (!preqed_call("skcms_PrimariesToXYZD50")) return;
    /* rx, ry, gx, gy, bx, by, wx, wy chromaticities */
    bool ok = skcms_PrimariesToXYZD50(number(in, 0), number(in, 4), number(in, 8), number(in, 12),
                                      number(in, 16), number(in, 20), number(in, 24), number(in, 28), &matrix);
    preqed_result("skcms_PrimariesToXYZD50", ok);
    matrix_valid = matrix_valid || ok;
}

/* transform */

static void call_skcms_DisableRuntimeCPUDetection(payload) {
    REPORT_VOID(skcms_DisableRuntimeCPUDetection, skcms_DisableRuntimeCPUDetection());
}
/* ltl: profile_initialised_before_use */
static void call_skcms_Transform(payload in) {
    if (!src.valid || !dst.valid) return;
    size_t npixels = 1 + byte(in, 3) % MAX_PIXELS;
    payload body = rest(in, 4);
    for (size_t i = 0; i < sizeof pixels_in; i++) pixels_in[i] = body.n ? body.p[i % body.n] : 0;
    REPORT(skcms_Transform,
           bool ok = skcms_Transform(pixels_in, pixel_format(byte(in, 0)), alpha_format(byte(in, 1)), &src.profile,
                                     pixels_out, pixel_format(byte(in, 2)), alpha_format(byte(in, 1) >> 2), &dst.profile,
                                     npixels),
           ok);
}

/* dispatch */

static void (*const api[])(payload) = {
    call_skcms_Parse, call_skcms_ParseWithA2BPriority, call_skcms_sRGB_profile, call_skcms_XYZD50_profile,
    call_skcms_Init, call_skcms_SetTransferFunction, call_skcms_SetXYZD50,
    call_skcms_ApproximatelyEqualProfiles, call_skcms_TRCs_AreApproximateInverse,
    call_skcms_GetCHAD, call_skcms_GetWTPT, call_skcms_GetInputChannelCount,
    call_skcms_MakeUsableAsDestination, call_skcms_MakeUsableAsDestinationWithSingleCurve,
    call_skcms_ApproximateCurve, call_skcms_AreApproximateInverses,
    call_skcms_sRGB_TransferFunction, call_skcms_sRGB_Inverse_TransferFunction, call_skcms_Identity_TransferFunction,
    call_skcms_TransferFunction_eval, call_skcms_TransferFunction_invert,
    call_skcms_TransferFunction_getType, call_skcms_TransferFunction_makePQish,
    call_skcms_TransferFunction_makeScaledHLGish, call_skcms_TransferFunction_makeHLGish,
    call_skcms_TransferFunction_makePQ, call_skcms_TransferFunction_makeHLG,
    call_skcms_TransferFunction_isSRGBish, call_skcms_TransferFunction_isPQish, call_skcms_TransferFunction_isHLGish,
    call_skcms_TransferFunction_isPQ, call_skcms_TransferFunction_isHLG,
    call_skcms_Matrix3x3_invert, call_skcms_Matrix3x3_concat,
    call_skcms_AdaptToXYZD50, call_skcms_PrimariesToXYZD50,
    call_skcms_DisableRuntimeCPUDetection, call_skcms_Transform,
};

static const size_t API_COUNT = sizeof api / sizeof api[0];

static void cleanup() {
    src.valid = dst.valid = false;
    tf_valid = matrix_valid = false;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    preqed_reset();
    size_t off = 0;
    while (size - off >= 3) {
        uint8_t op = data[off];
        size_t len = static_cast<size_t>(data[off + 1]) | static_cast<size_t>(data[off + 2]) << 8;
        off += 3;
        if (len > size - off) break;
        api[op % API_COUNT]({ data + off, len });
        off += len;
    }
    cleanup();
    return 0;
}
