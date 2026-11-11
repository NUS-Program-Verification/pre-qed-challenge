#include <double-conversion/double-conversion.h>
#include "preqed_ltl.h"

#include <cmath>
#include <cstdint>
#include <cstring>
#include <string>

using namespace double_conversion;

struct payload {
    const uint8_t *p;
    size_t n;
};

/* Output needs documented in double-to-string.h: fixed <= 60 + 100 + 2, exponential/precision <= 120 + 7,
 * plus symbols and the trailing NUL. 512 covers every mode. */
static const int kRoom = 512;

static DoubleToStringConverter *d2s;
static StringToDoubleConverter *s2d;
static StringBuilder *builder;
static bool builder_finalized;
/* StringBuilder target: kRoom (512) + up to 2040 more bytes chosen by the payload */
static char out[4096];
/* custom "Infinity"/"NaN" spellings, up to 8 payload bytes each */
static char infinity_symbol[16], nan_symbol[16];
static char text[1024];
static uc16 wide[1024];

static uint8_t byte(payload in, size_t i) { return i < in.n ? in.p[i] : 0; }
static payload rest(payload in, size_t skip) {
    return { in.p + (skip < in.n ? skip : in.n), in.n > skip ? in.n - skip : 0 };
}
static double number(payload in) {
    double d = 0;
    std::memcpy(&d, in.p, in.n < sizeof d ? in.n : sizeof d);
    return d;
}
static float single(payload in) {
    float f = 0;
    std::memcpy(&f, in.p, in.n < sizeof f ? in.n : sizeof f);
    return f;
}
static const char *cstr(char *dst, size_t cap, payload in) {
    size_t n = in.n < cap - 1 ? in.n : cap - 1;
    std::memcpy(dst, in.p, n);
    dst[n] = 0;
    return dst;
}
static int room() { return builder ? builder->size() - builder->position() : 0; }
static bool builder_ready() { return builder && !builder_finalized && room() >= kRoom; }

#define REPORT(api, stmt, ok_cond) \
    do { if (preqed_call(#api)) { stmt; preqed_result(#api, (ok_cond)); } } while (0)
#define REPORT_VOID(api, stmt) REPORT(api, stmt, true)

/* DoubleToStringConverter */
/* ltl: d2s_converter_lifecycle */
static void call_DoubleToStringConverter_ctor(payload in) {
    if (d2s) return;
    int flags = byte(in, 0) & 0x7f;
    if ((flags & DoubleToStringConverter::EMIT_TRAILING_ZERO_AFTER_POINT) &&
        !(flags & DoubleToStringConverter::EMIT_TRAILING_DECIMAL_POINT))
        return;
    /* A trailing zero requires a decimal point, including in exponential notation. */
    if ((flags & DoubleToStringConverter::EMIT_TRAILING_ZERO_AFTER_POINT_IN_EXPONENTIAL) &&
        !(flags & DoubleToStringConverter::EMIT_TRAILING_DECIMAL_POINT_IN_EXPONENTIAL))
        return;
    /* payload bytes 6..13 and 14..21 are the infinity and NaN symbols */
    cstr(infinity_symbol, sizeof infinity_symbol, { in.p + 6, in.n > 6 ? (in.n - 6 < 8 ? in.n - 6 : 8) : 0 });
    cstr(nan_symbol, sizeof nan_symbol, { in.p + 14, in.n > 14 ? (in.n - 14 < 8 ? in.n - 14 : 8) : 0 });
    if (!preqed_call("DoubleToStringConverter::DoubleToStringConverter")) return;
    d2s = new DoubleToStringConverter(flags, byte(in, 0) & 0x80 ? infinity_symbol : nullptr,
                                      byte(in, 1) & 0x80 ? nan_symbol : nullptr,
                                      static_cast<char>('A' + byte(in, 1) % 58),  /* exponent character 'A'..'z' */
                                      -(int)(byte(in, 2) % 21), byte(in, 3) % 22,  /* decimal_in_shortest_low -20..0, _high 0..21 */
                                      byte(in, 4) % 20, byte(in, 5) % 20,  /* max leading/trailing padding zeroes in precision mode */
                                      byte(in, 1) % 5);  /* min_exponent_width 0..4 */
    preqed_result("DoubleToStringConverter::DoubleToStringConverter", true);
}
/* ltl: d2s_converter_lifecycle */
static void call_DoubleToStringConverter_dtor(payload) {
    if (!d2s || d2s == &DoubleToStringConverter::EcmaScriptConverter()) {
        d2s = nullptr;
        return;
    }
    REPORT_VOID(DoubleToStringConverter::~DoubleToStringConverter, delete d2s);
    d2s = nullptr;
}
/* ltl: d2s_converter_lifecycle */
static void call_EcmaScriptConverter(payload) {
    if (d2s) return;
    if (!preqed_call("DoubleToStringConverter::EcmaScriptConverter")) return;
    d2s = const_cast<DoubleToStringConverter *>(&DoubleToStringConverter::EcmaScriptConverter());
    preqed_result("DoubleToStringConverter::EcmaScriptConverter", true);
}
/* ltl: d2s_converter_lifecycle, string_builder_lifecycle_and_finalize */
static void call_ToShortest(payload in) {
    if (!d2s || !builder_ready()) return;
    REPORT(DoubleToStringConverter::ToShortest, bool ok = d2s->ToShortest(number(in), builder), ok);
}
/* ltl: d2s_converter_lifecycle, string_builder_lifecycle_and_finalize */
static void call_ToShortestSingle(payload in) {
    if (!d2s || !builder_ready()) return;
    REPORT(DoubleToStringConverter::ToShortestSingle, bool ok = d2s->ToShortestSingle(single(in), builder), ok);
}
/* ltl: d2s_converter_lifecycle, string_builder_lifecycle_and_finalize */
static void call_ToFixed(payload in) {
    if (!d2s || !builder_ready()) return;
    /* 0..109 digits: the limit is kMaxFixedDigitsAfterPoint (100), larger values must return false */
    REPORT(DoubleToStringConverter::ToFixed, bool ok = d2s->ToFixed(number(rest(in, 1)), byte(in, 0) % 110, builder), ok);
}
/* ltl: d2s_converter_lifecycle, string_builder_lifecycle_and_finalize */
static void call_ToExponential(payload in) {
    if (!d2s || !builder_ready()) return;
    REPORT(DoubleToStringConverter::ToExponential,
           bool ok = d2s->ToExponential(number(rest(in, 1)), (int)byte(in, 0) % 130 - 2, builder), ok);  /* -2..127: -1 = shortest, > 120 rejected */
}
/* ltl: d2s_converter_lifecycle, string_builder_lifecycle_and_finalize */
static void call_ToPrecision(payload in) {
    if (!d2s || !builder_ready()) return;
    /* 0..129: the valid range is kMinPrecisionDigits..kMaxPrecisionDigits (1..120) */
    REPORT(DoubleToStringConverter::ToPrecision, bool ok = d2s->ToPrecision(number(rest(in, 1)), byte(in, 0) % 130, builder), ok);
}

static void call_DoubleToAscii(payload in) {
    static const DoubleToStringConverter::DtoaMode modes[] = {
        DoubleToStringConverter::SHORTEST, DoubleToStringConverter::SHORTEST_SINGLE,
        DoubleToStringConverter::FIXED, DoubleToStringConverter::PRECISION,
    };
    DoubleToStringConverter::DtoaMode mode = modes[byte(in, 0) % 4];
    double v = number(rest(in, 2));
    if (mode == DoubleToStringConverter::SHORTEST_SINGLE) v = static_cast<float>(v);
    if (std::isnan(v) || std::isinf(v)) return;
    /* DoubleToAscii asserts on out-of-range digits: FIXED 0..20 for |v| < 1e21, PRECISION 1..120 */
    int digits = mode == DoubleToStringConverter::FIXED ? byte(in, 1) % 21
               : mode == DoubleToStringConverter::PRECISION ? 1 + byte(in, 1) % 120 : 0;
    if (mode == DoubleToStringConverter::FIXED && std::fabs(v) >= 1e21) return;
    char buffer[kRoom];
    bool sign;
    int length, point;
    REPORT_VOID(DoubleToStringConverter::DoubleToAscii,
                DoubleToStringConverter::DoubleToAscii(v, mode, digits, buffer, sizeof buffer, &sign, &length, &point));
}

/* StringToDoubleConverter */
/* ltl: s2d_converter_lifecycle */
static void call_StringToDoubleConverter_ctor(payload in) {
    if (s2d) return;
    int flags = byte(in, 0);
    double empty = byte(in, 2) & 1 ? 0.0 : std::nan("");
    double junk = byte(in, 2) & 2 ? 0.0 : std::nan("");
    /* flags: the 8 StringToDoubleConverter::Flags bits; empty/junk values 0.0 or NaN; bytes 3..10 and 11..18 are the symbols */
    cstr(infinity_symbol, sizeof infinity_symbol, { in.p + 3, in.n > 3 ? (in.n - 3 < 8 ? in.n - 3 : 8) : 0 });
    cstr(nan_symbol, sizeof nan_symbol, { in.p + 11, in.n > 11 ? (in.n - 11 < 8 ? in.n - 11 : 8) : 0 });
    /* digit separator: none, or a printable character 0x20..0x3f */
    uc16 separator = byte(in, 2) & 4 ? StringToDoubleConverter::kNoSeparator : static_cast<uc16>(byte(in, 2) >> 3 | 0x20);
    /* Symbols must start with distinct characters, neither a sign nor a digit. */
    auto symbol_ok = [](const char *s) { return s[0] && s[0] != '+' && s[0] != '-' && !(s[0] >= '0' && s[0] <= '9'); };
    const char *inf_sym = byte(in, 1) & 2 && symbol_ok(infinity_symbol) ? infinity_symbol : nullptr;
    const char *nan_sym = byte(in, 1) & 4 && symbol_ok(nan_symbol) && !(inf_sym && inf_sym[0] == nan_symbol[0]) ? nan_symbol : nullptr;
    if (!preqed_call("StringToDoubleConverter::StringToDoubleConverter")) return;
    s2d = new StringToDoubleConverter(flags, empty, junk, inf_sym, nan_sym, separator);
    preqed_result("StringToDoubleConverter::StringToDoubleConverter", true);
}
/* ltl: s2d_converter_lifecycle */
static void call_StringToDoubleConverter_dtor(payload) {
    if (!s2d) return;
    REPORT_VOID(StringToDoubleConverter::~StringToDoubleConverter, delete s2d);
    s2d = nullptr;
}
/* ltl: s2d_converter_lifecycle */
static void call_StringToDouble(payload in) {
    if (!s2d) return;
    int consumed = 0;
    int len = (int)(in.n < sizeof text ? in.n : sizeof text);
    std::memcpy(text, in.p, len);
    REPORT_VOID(StringToDoubleConverter::StringToDouble, s2d->StringToDouble(text, len, &consumed));
}
/* ltl: s2d_converter_lifecycle */
static void call_StringToDouble_uc16(payload in) {
    if (!s2d) return;
    int consumed = 0;
    int len = (int)(in.n / 2 < sizeof wide / sizeof wide[0] ? in.n / 2 : sizeof wide / sizeof wide[0]);
    std::memcpy(wide, in.p, len * 2);
    REPORT_VOID(StringToDoubleConverter::StringToDouble(uc16), s2d->StringToDouble(wide, len, &consumed));
}
/* ltl: s2d_converter_lifecycle */
static void call_StringToFloat(payload in) {
    if (!s2d) return;
    int consumed = 0;
    int len = (int)(in.n < sizeof text ? in.n : sizeof text);
    std::memcpy(text, in.p, len);
    REPORT_VOID(StringToDoubleConverter::StringToFloat, s2d->StringToFloat(text, len, &consumed));
}
/* ltl: s2d_converter_lifecycle */
static void call_StringToFloat_uc16(payload in) {
    if (!s2d) return;
    int consumed = 0;
    int len = (int)(in.n / 2 < sizeof wide / sizeof wide[0] ? in.n / 2 : sizeof wide / sizeof wide[0]);
    std::memcpy(wide, in.p, len * 2);
    REPORT_VOID(StringToDoubleConverter::StringToFloat(uc16), s2d->StringToFloat(wide, len, &consumed));
}
/* StringTo<T> (string-to-double.h): "Same as StringToDouble for T = double, and StringToFloat for T = float" */
/* ltl: s2d_converter_lifecycle */
static void call_StringTo_double(payload in) {
    if (!s2d) return;
    int consumed = 0;
    int len = (int)(in.n < sizeof text ? in.n : sizeof text);
    std::memcpy(text, in.p, len);
    REPORT_VOID(StringToDoubleConverter::StringTo<double>, s2d->StringTo<double>(text, len, &consumed));
}
/* ltl: s2d_converter_lifecycle */
static void call_StringTo_float(payload in) {
    if (!s2d) return;
    int consumed = 0;
    int len = (int)(in.n < sizeof text ? in.n : sizeof text);
    std::memcpy(text, in.p, len);
    REPORT_VOID(StringToDoubleConverter::StringTo<float>, s2d->StringTo<float>(text, len, &consumed));
}
/* ltl: s2d_converter_lifecycle */
static void call_StringTo_double_uc16(payload in) {
    if (!s2d) return;
    int consumed = 0;
    int len = (int)(in.n / 2 < sizeof wide / sizeof wide[0] ? in.n / 2 : sizeof wide / sizeof wide[0]);
    std::memcpy(wide, in.p, len * 2);
    REPORT_VOID(StringToDoubleConverter::StringTo<double>(uc16), s2d->StringTo<double>(wide, len, &consumed));
}
/* ltl: s2d_converter_lifecycle */
static void call_StringTo_float_uc16(payload in) {
    if (!s2d) return;
    int consumed = 0;
    int len = (int)(in.n / 2 < sizeof wide / sizeof wide[0] ? in.n / 2 : sizeof wide / sizeof wide[0]);
    std::memcpy(wide, in.p, len * 2);
    REPORT_VOID(StringToDoubleConverter::StringTo<float>(uc16), s2d->StringTo<float>(wide, len, &consumed));
}

/* Vector (utils.h): a view over a caller buffer, here the payload copied into text. first/last/pop_back index
 * the buffer (pop_back asserts !is_empty()), so they run on a non-empty view only. */
static Vector<char> view(payload in) {
    int len = (int)(in.n < sizeof text ? in.n : sizeof text);
    std::memcpy(text, in.p, len);
    return Vector<char>(text, len);
}
static void call_Vector_is_empty(payload in) {
    Vector<char> v = view(in);
    REPORT(Vector::is_empty, bool e = v.is_empty(), e == (v.length() == 0));
}
static void call_Vector_first(payload in) {
    Vector<char> v = view(in);
    if (v.is_empty()) return;
    REPORT(Vector::first, char &c = v.first(), &c == text);
}
static void call_Vector_last(payload in) {
    Vector<char> v = view(in);
    if (v.is_empty()) return;
    REPORT(Vector::last, char &c = v.last(), &c == text + v.length() - 1);
}
static void call_Vector_pop_back(payload in) {
    Vector<char> v = view(in);
    if (v.is_empty()) return;
    int before = v.length();
    REPORT(Vector::pop_back, v.pop_back(), v.length() == before - 1);
}

/* StringBuilder */
/* ltl: string_builder_lifecycle_and_finalize */
static void call_StringBuilder_ctor(payload in) {
    if (builder) return;
    if (!preqed_call("StringBuilder::StringBuilder")) return;
    builder = new StringBuilder(out, kRoom + byte(in, 0) * 8);  /* 512..2552 bytes, within sizeof out */
    preqed_result("StringBuilder::StringBuilder", true);
    builder_finalized = false;
}
/* ltl: string_builder_lifecycle_and_finalize */
static void call_StringBuilder_dtor(payload) {
    if (!builder) return;
    REPORT_VOID(StringBuilder::~StringBuilder, delete builder);
    builder = nullptr;
}
/* ltl: string_builder_lifecycle_and_finalize */
static void call_StringBuilder_size(payload) {
    if (!builder) return;
    REPORT_VOID(StringBuilder::size, builder->size());
}
/* ltl: string_builder_lifecycle_and_finalize */
static void call_StringBuilder_position(payload) {
    if (!builder || builder_finalized) return;
    REPORT_VOID(StringBuilder::position, builder->position());
}
/* ltl: string_builder_lifecycle_and_finalize */
static void call_StringBuilder_Reset(payload) {
    if (!builder || builder_finalized) return;
    REPORT_VOID(StringBuilder::Reset, builder->Reset());
}
/* ltl: string_builder_lifecycle_and_finalize */
static void call_StringBuilder_AddCharacter(payload in) {
    if (!builder || builder_finalized || room() < 2 || !byte(in, 0)) return;
    REPORT_VOID(StringBuilder::AddCharacter, builder->AddCharacter(static_cast<char>(byte(in, 0))));
}
/* ltl: string_builder_lifecycle_and_finalize */
static void call_StringBuilder_AddString(payload in) {
    if (!builder || builder_finalized) return;
    cstr(text, sizeof text, in);
    if (room() < (int)std::strlen(text) + 1) return;
    REPORT_VOID(StringBuilder::AddString, builder->AddString(text));
}
/* ltl: string_builder_lifecycle_and_finalize */
static void call_StringBuilder_AddSubstring(payload in) {
    if (!builder || builder_finalized) return;
    cstr(text, sizeof text, in);
    int n = (int)std::strlen(text);
    if (room() < n + 1) return;
    REPORT_VOID(StringBuilder::AddSubstring, builder->AddSubstring(text, n));
}
/* ltl: string_builder_lifecycle_and_finalize */
static void call_StringBuilder_AddPadding(payload in) {
    if (!builder || builder_finalized || !byte(in, 0) || room() < (int)byte(in, 1) + 1) return;
    REPORT_VOID(StringBuilder::AddPadding, builder->AddPadding(static_cast<char>(byte(in, 0)), byte(in, 1)));
}
/* ltl: string_builder_lifecycle_and_finalize */
static void call_StringBuilder_Finalize(payload) {
    if (!builder || builder_finalized) return;
    REPORT(StringBuilder::Finalize, char *s = builder->Finalize(), s != nullptr);
    builder_finalized = true;
}

/* dispatch */

static void (*const api[])(payload) = {
    call_DoubleToStringConverter_ctor, call_DoubleToStringConverter_dtor, call_EcmaScriptConverter,
    call_ToShortest, call_ToShortestSingle, call_ToFixed, call_ToExponential, call_ToPrecision, call_DoubleToAscii,
    call_StringToDoubleConverter_ctor, call_StringToDoubleConverter_dtor,
    call_StringToDouble, call_StringToDouble_uc16, call_StringToFloat, call_StringToFloat_uc16,
    call_StringTo_double, call_StringTo_float, call_StringTo_double_uc16, call_StringTo_float_uc16,
    call_Vector_is_empty, call_Vector_first, call_Vector_last, call_Vector_pop_back,
    call_StringBuilder_ctor, call_StringBuilder_dtor, call_StringBuilder_size, call_StringBuilder_position,
    call_StringBuilder_Reset, call_StringBuilder_AddCharacter, call_StringBuilder_AddString,
    call_StringBuilder_AddSubstring, call_StringBuilder_AddPadding, call_StringBuilder_Finalize,
};

static const size_t API_COUNT = sizeof api / sizeof api[0];

static void cleanup() {
    if (d2s && d2s != &DoubleToStringConverter::EcmaScriptConverter()) delete d2s;
    delete s2d;
    delete builder;
    d2s = nullptr;
    s2d = nullptr;
    builder = nullptr;
    builder_finalized = false;
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
