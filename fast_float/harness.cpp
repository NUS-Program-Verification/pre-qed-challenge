#include <fast_float/fast_float.h>
#include "preqed_ltl.h"

#include <cstdint>
#include <cstring>

struct payload {
    const uint8_t *p;
    size_t n;
};

static uint8_t byte(payload in, size_t i) { return i < in.n ? in.p[i] : 0; }
static payload rest(payload in, size_t skip) {
    return { in.p + (skip < in.n ? skip : in.n), in.n > skip ? in.n - skip : 0 };
}

static fast_float::chars_format format(uint8_t b) {
    using fast_float::chars_format;
    /* every chars_format base value, then optional modifier bits from the high payload bits */
    static const chars_format base[] = {
        chars_format::general, chars_format::scientific, chars_format::fixed, chars_format::hex,
        chars_format::json, chars_format::json_or_infnan, chars_format::fortran,
    };
    uint64_t f = uint64_t(base[b % 7]);
    if (b & 0x10) f |= uint64_t(chars_format::no_infnan);
    if (b & 0x20) f |= uint64_t(chars_format::allow_leading_plus);
    if (b & 0x40) f |= uint64_t(chars_format::skip_white_space);
    return chars_format(f);
}

/* 64 KiB, aligned for char16_t/char32_t input (see as_chars) */
alignas(char32_t) static uint8_t aligned[1 << 16];
template <typename UC> static const UC *as_chars(payload in, size_t &count) {
    count = in.n / sizeof(UC);
    if (count * sizeof(UC) > sizeof aligned) count = sizeof aligned / sizeof(UC);
    std::memcpy(aligned, in.p, count * sizeof(UC));
    return reinterpret_cast<const UC *>(aligned);
}

#define REPORT(api, stmt, ok_cond) \
    do { if (preqed_call(#api)) { stmt; preqed_result(#api, (ok_cond)); } } while (0)

/* from_chars(first, last, T&, chars_format) for floating point, one wrapper per (T, UC) */

#define FLOAT_FROM_CHARS(ident, api, T, UC) \
    static void call_##ident(payload in) { \
        payload body = rest(in, 1); \
        size_t count; \
        const UC *first = as_chars<UC>(body, count); \
        T value; \
        REPORT(api, auto r = fast_float::from_chars(first, first + count, value, format(byte(in, 0))), r.ec == std::errc()); \
    }
FLOAT_FROM_CHARS(from_chars_float, from_chars<float>, float, char)
FLOAT_FROM_CHARS(from_chars_double, from_chars<double>, double, char)
FLOAT_FROM_CHARS(from_chars_float_char16_t, from_chars<float/char16_t>, float, char16_t)
FLOAT_FROM_CHARS(from_chars_double_char16_t, from_chars<double/char16_t>, double, char16_t)
FLOAT_FROM_CHARS(from_chars_float_char32_t, from_chars<float/char32_t>, float, char32_t)
FLOAT_FROM_CHARS(from_chars_double_char32_t, from_chars<double/char32_t>, double, char32_t)
FLOAT_FROM_CHARS(from_chars_float_wchar_t, from_chars<float/wchar_t>, float, wchar_t)
FLOAT_FROM_CHARS(from_chars_double_wchar_t, from_chars<double/wchar_t>, double, wchar_t)

/* from_chars(first, last, T&, base) for integers */

#define INT_FROM_CHARS(ident, api, T, UC) \
    static void call_##ident(payload in) { \
        payload body = rest(in, 1); \
        size_t count; \
        const UC *first = as_chars<UC>(body, count); \
        T value; \
        int base = 2 + byte(in, 0) % 35;  /* every base from_chars accepts: 2..36 */ \
        REPORT(api, auto r = fast_float::from_chars(first, first + count, value, base), r.ec == std::errc()); \
    }
INT_FROM_CHARS(from_chars_int8_t, from_chars<int8_t>, int8_t, char)
INT_FROM_CHARS(from_chars_uint8_t, from_chars<uint8_t>, uint8_t, char)
INT_FROM_CHARS(from_chars_int16_t, from_chars<int16_t>, int16_t, char)
INT_FROM_CHARS(from_chars_uint16_t, from_chars<uint16_t>, uint16_t, char)
INT_FROM_CHARS(from_chars_int32_t, from_chars<int32_t>, int32_t, char)
INT_FROM_CHARS(from_chars_uint32_t, from_chars<uint32_t>, uint32_t, char)
INT_FROM_CHARS(from_chars_int64_t, from_chars<int64_t>, int64_t, char)
INT_FROM_CHARS(from_chars_uint64_t, from_chars<uint64_t>, uint64_t, char)
INT_FROM_CHARS(from_chars_int32_t_char16_t, from_chars<int32_t/char16_t>, int32_t, char16_t)
INT_FROM_CHARS(from_chars_uint64_t_char32_t, from_chars<uint64_t/char32_t>, uint64_t, char32_t)

/* from_chars_advanced(first, last, T&, parse_options) */

#define ADVANCED(ident, api, T, UC) \
    static void call_##ident(payload in) { \
        payload body = rest(in, 3); \
        size_t count; \
        const UC *first = as_chars<UC>(body, count); \
        /* format, decimal point (payload byte, '.' when 0), base 2..36 */ \
        fast_float::parse_options_t<UC> options(format(byte(in, 0)), UC(byte(in, 1) ? byte(in, 1) : '.'), 2 + byte(in, 2) % 35); \
        T value; \
        REPORT(api, auto r = fast_float::from_chars_advanced(first, first + count, value, options), r.ec == std::errc()); \
    }
ADVANCED(from_chars_advanced_float, from_chars_advanced<float>, float, char)
ADVANCED(from_chars_advanced_double, from_chars_advanced<double>, double, char)
ADVANCED(from_chars_advanced_double_char16_t, from_chars_advanced<double/char16_t>, double, char16_t)
ADVANCED(from_chars_advanced_double_char32_t, from_chars_advanced<double/char32_t>, double, char32_t)
ADVANCED(from_chars_advanced_int64_t, from_chars_advanced<int64_t>, int64_t, char)
ADVANCED(from_chars_advanced_uint32_t, from_chars_advanced<uint32_t>, uint32_t, char)

/* integer_times_pow10(mantissa, decimal_exponent): uint64_t and int64_t mantissa, double result or an explicit T */

static uint64_t u64(payload in) {
    uint64_t v = 0;
    std::memcpy(&v, in.p, in.n < sizeof v ? in.n : sizeof v);
    return v;
}
/* decimal exponent -512..511 (payload bytes 0-1): wider than the double range (about 1e-324..1e308), so the
   documented "on overflow infinity is returned, on underflow 0 is returned" cases occur */
static int exponent10(payload in) { return int((byte(in, 0) | byte(in, 1) << 8) % 1024) - 512; }

#define TIMES_POW10(ident, api, expr) \
    static void call_##ident(payload in) { \
        int e = exponent10(in); \
        uint64_t m = u64(rest(in, 2)); \
        REPORT(api, auto v = expr, v == v);  /* never NaN: a number, 0 or infinity */ \
    }
TIMES_POW10(integer_times_pow10_uint64_t, integer_times_pow10(uint64_t), fast_float::integer_times_pow10(m, e))
TIMES_POW10(integer_times_pow10_int64_t, integer_times_pow10(int64_t), fast_float::integer_times_pow10(int64_t(m), e))
TIMES_POW10(integer_times_pow10_float, integer_times_pow10<float>, fast_float::integer_times_pow10<float>(m, e))
TIMES_POW10(integer_times_pow10_double_int64_t, integer_times_pow10<double>(int64_t), fast_float::integer_times_pow10<double>(int64_t(m), e))

/* chars_format bit operators (float_common.h): pure functions on the enum's uint64_t value */

#define FORMAT_BINARY(ident, api, op) \
    static void call_##ident(payload in) { \
        fast_float::chars_format a = format(byte(in, 0)), b = format(byte(in, 1)); \
        REPORT(api, auto r = a op b, uint64_t(r) == (uint64_t(a) op uint64_t(b))); \
    }
FORMAT_BINARY(chars_format_and, operator&, &)
FORMAT_BINARY(chars_format_or, operator|, |)
FORMAT_BINARY(chars_format_xor, operator^, ^)

#define FORMAT_ASSIGN(ident, api, assign, op) \
    static void call_##ident(payload in) { \
        fast_float::chars_format a = format(byte(in, 0)), b = format(byte(in, 1)); \
        uint64_t want = uint64_t(a) op uint64_t(b); \
        REPORT(api, a assign b, uint64_t(a) == want); \
    }
FORMAT_ASSIGN(chars_format_and_assign, operator&=, &=, &)
FORMAT_ASSIGN(chars_format_or_assign, operator|=, |=, |)
FORMAT_ASSIGN(chars_format_xor_assign, operator^=, ^=, ^)

static void call_chars_format_not(payload in) {
    fast_float::chars_format a = format(byte(in, 0));
    REPORT(operator~, auto r = ~a, uint64_t(r) == ~uint64_t(a));
}

/* from_chars_result_t::operator bool (float_common.h, P2497): true exactly when ec == std::errc() */
static void call_from_chars_result_bool(payload in) {
    size_t count;
    const char *first = as_chars<char>(in, count);
    double value;
    if (!preqed_call("from_chars<double>")) return;
    auto r = fast_float::from_chars(first, first + count, value);
    preqed_result("from_chars<double>", r.ec == std::errc());
    REPORT(from_chars_result_t::operator bool, bool ok = static_cast<bool>(r), ok == (r.ec == std::errc()));
}

/* dispatch */

static void (*const api[])(payload) = {
    call_from_chars_float, call_from_chars_double, call_from_chars_float_char16_t, call_from_chars_double_char16_t, call_from_chars_float_char32_t, call_from_chars_double_char32_t, call_from_chars_float_wchar_t, call_from_chars_double_wchar_t,
    call_from_chars_int8_t, call_from_chars_uint8_t, call_from_chars_int16_t, call_from_chars_uint16_t, call_from_chars_int32_t, call_from_chars_uint32_t, call_from_chars_int64_t, call_from_chars_uint64_t, call_from_chars_int32_t_char16_t, call_from_chars_uint64_t_char32_t,
    call_from_chars_advanced_float, call_from_chars_advanced_double, call_from_chars_advanced_double_char16_t, call_from_chars_advanced_double_char32_t, call_from_chars_advanced_int64_t, call_from_chars_advanced_uint32_t,
    call_integer_times_pow10_uint64_t, call_integer_times_pow10_int64_t, call_integer_times_pow10_float, call_integer_times_pow10_double_int64_t,
    call_chars_format_and, call_chars_format_or, call_chars_format_xor, call_chars_format_and_assign, call_chars_format_or_assign, call_chars_format_xor_assign, call_chars_format_not,
    call_from_chars_result_bool,
};

static const size_t API_COUNT = sizeof api / sizeof api[0];

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
    return 0;
}
