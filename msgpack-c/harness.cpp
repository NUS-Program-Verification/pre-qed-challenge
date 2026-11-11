#define MSGPACK_NO_BOOST
#include <msgpack.hpp>
#include "preqed_ltl.h"

#include <cstdint>
#include <cstring>
#include <map>
#include <sstream>
#include <string>
#include <vector>

struct payload {
    const uint8_t *p;
    size_t n;
};

static msgpack::sbuffer sbuf;                 /* pack target, also the unpack source */
static msgpack::packer<msgpack::sbuffer> packer(sbuf);
static uint32_t pending_body;                 /* bytes promised by the last pack_str/bin/ext/v4raw header */

static msgpack::vrefbuffer *vref;
static msgpack::zone *zone;
static msgpack::unpacker *unpacker;
static msgpack::object_handle handle;         /* result of unpack / unpacker::next */
static bool handle_valid;
static std::string vref_backing;              /* keeps append_ref targets alive */

static uint8_t byte(payload in, size_t i) { return i < in.n ? in.p[i] : 0; }
static payload rest(payload in, size_t skip) {
    return { in.p + (skip < in.n ? skip : in.n), in.n > skip ? in.n - skip : 0 };
}
template <typename T> static T scalar(payload in) {
    T v{};
    std::memcpy(&v, in.p, in.n < sizeof v ? in.n : sizeof v);
    return v;
}
static payload unpack_source(payload in) {
    if (byte(in, 0) & 1) return { reinterpret_cast<const uint8_t *>(sbuf.data()), sbuf.size() };
    return rest(in, 1);
}
static msgpack::unpack_limit limit(payload in) {
    /* unpack_limit(array, map, str, bin, ext, depth): element/byte limits 1..65536, depth 1..64;
       bounds the up-front allocation for array32/map32 headers (NOTES.md msgpack-c) */
    uint32_t n = 1u << (byte(in, 1) % 17);
    return msgpack::unpack_limit(n, n, n, n, n, 1 + byte(in, 1) % 64);
}

/* Empty STR/BIN/EXT parsed from input carry a null pointer; clone and == pass it to memcpy/memcmp. */
static bool has_null_raw(const msgpack::object &o) {
    switch (o.type) {
    case msgpack::type::STR: return o.via.str.ptr == nullptr;
    case msgpack::type::BIN: return o.via.bin.ptr == nullptr;
    case msgpack::type::EXT: return o.via.ext.ptr == nullptr;
    case msgpack::type::ARRAY:
        for (uint32_t i = 0; i < o.via.array.size; i++) if (has_null_raw(o.via.array.ptr[i])) return true;
        return false;
    case msgpack::type::MAP:
        for (uint32_t i = 0; i < o.via.map.size; i++)
            if (has_null_raw(o.via.map.ptr[i].key) || has_null_raw(o.via.map.ptr[i].val)) return true;
        return false;
    default: return false;
    }
}

#define REPORT(api, stmt, ok_cond) \
    do { if (preqed_call(#api)) { stmt; preqed_result(#api, (ok_cond)); } } while (0)
#define REPORT_VOID(api, stmt) REPORT(api, stmt, true)

/* Any library call that may throw msgpack exceptions (documented error reporting) */
static bool attempted;
#define TRY(api, stmt) \
    do { \
        if (!preqed_call(#api)) return; \
        attempted = true; \
        try { stmt; } catch (const msgpack::unpack_error &) { attempted = false; } catch (const msgpack::type_error &) { attempted = false; } \
        preqed_result(#api, attempted); \
    } while (0)

/* packer: scalars */

#define PACK_SCALAR(name, type) \
    static void call_pack_##name(payload in) { \
        if (pending_body) return; \
        REPORT_VOID(packer::pack_##name, packer.pack_##name(scalar<type>(in))); \
    }
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_SCALAR(uint8, uint8_t)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_SCALAR(uint16, uint16_t)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_SCALAR(uint32, uint32_t)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_SCALAR(uint64, uint64_t)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_SCALAR(int8, int8_t)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_SCALAR(int16, int16_t)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_SCALAR(int32, int32_t)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_SCALAR(int64, int64_t)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_SCALAR(fix_uint8, uint8_t)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_SCALAR(fix_uint16, uint16_t)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_SCALAR(fix_uint32, uint32_t)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_SCALAR(fix_uint64, uint64_t)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_SCALAR(fix_int8, int8_t)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_SCALAR(fix_int16, int16_t)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_SCALAR(fix_int32, int32_t)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_SCALAR(fix_int64, int64_t)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_SCALAR(char, char)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_SCALAR(signed_char, signed char)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_SCALAR(short, short)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_SCALAR(int, int)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_SCALAR(long, long)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_SCALAR(long_long, long long)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_SCALAR(unsigned_char, unsigned char)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_SCALAR(unsigned_short, unsigned short)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_SCALAR(unsigned_int, unsigned int)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_SCALAR(unsigned_long, unsigned long)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_SCALAR(unsigned_long_long, unsigned long long)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_SCALAR(float, float)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_SCALAR(double, double)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_SCALAR(wchar, wchar_t)

#define PACK_CONST(name) \
    static void call_pack_##name(payload) { \
        if (pending_body) return; \
        REPORT_VOID(packer::pack_##name, packer.pack_##name()); \
    }
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_CONST(nil)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_CONST(true)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_CONST(false)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
static void call_pack_array(payload in) {
    if (pending_body) return;
    REPORT_VOID(packer::pack_array, packer.pack_array(byte(in, 0)));
}
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
static void call_pack_map(payload in) {
    if (pending_body) return;
    REPORT_VOID(packer::pack_map, packer.pack_map(byte(in, 0)));
}

/* packer: raw headers and bodies. A header promises exactly N body bytes. */

#define PACK_HEADER(name) \
    static void call_pack_##name(payload in) { \
        if (pending_body) return; \
        uint32_t len = byte(in, 0) | byte(in, 1) << 8; \
        REPORT_VOID(packer::pack_##name, packer.pack_##name(len)); \
        pending_body = len; \
    }
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_HEADER(str)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_HEADER(v4raw)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_HEADER(bin)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
static void call_pack_ext(payload in) {
    if (pending_body) return;
    uint32_t len = byte(in, 0) | byte(in, 1) << 8;
    REPORT_VOID(packer::pack_ext, packer.pack_ext(len, static_cast<int8_t>(byte(in, 2))));
    pending_body = len;
}

static std::vector<char> body_bytes(payload in) {
    std::vector<char> body(pending_body);
    for (size_t i = 0; i < body.size(); i++) body[i] = in.n ? static_cast<char>(in.p[i % in.n]) : 0;
    return body;
}

#define PACK_BODY(name) \
    static void call_pack_##name##_body(payload in) { \
        if (!pending_body) return; \
        std::vector<char> body = body_bytes(in); \
        REPORT_VOID(packer::pack_##name##_body, packer.pack_##name##_body(body.data(), pending_body)); \
        pending_body = 0; \
    }
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_BODY(str)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_BODY(v4raw)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_BODY(bin)
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
PACK_BODY(ext)

/* packer: adaptor-based pack(T) and pack(object) */
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
static void call_pack_string(payload in) {
    if (pending_body) return;
    std::string s(reinterpret_cast<const char *>(in.p), in.n);
    REPORT_VOID(packer::pack<std::string>, packer.pack(s));
}
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
static void call_pack_vector(payload in) {
    if (pending_body) return;
    std::vector<int> v(in.p, in.p + in.n);
    REPORT_VOID(packer::pack<std::vector>, packer.pack(v));
}
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
static void call_pack_map_container(payload in) {
    if (pending_body) return;
    std::map<std::string, uint8_t> m;
    for (size_t i = 0; i + 1 < in.n; i += 2) m[std::string(1, static_cast<char>(in.p[i]))] = in.p[i + 1];
    REPORT_VOID(packer::pack<std::map>, packer.pack(m));
}
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body, object_handle_validity */
static void call_pack_object(payload) {
    if (pending_body || !handle_valid || has_null_raw(handle.get())) return;
    REPORT_VOID(packer::pack<object>, packer.pack(handle.get()));
}
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
static void call_msgpack_pack(payload in) {
    if (pending_body) return;
    REPORT_VOID(msgpack::pack, msgpack::pack(sbuf, scalar<int64_t>(in)));
}

/* adaptor value types (adaptor/*.hpp): construct, compare, pack */

static std::string payload_string(payload in) { return std::string(reinterpret_cast<const char *>(in.p), in.n); }
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
static void call_type_ext(payload in) {
    if (pending_body) return;
    payload body = rest(in, 1);
    msgpack::type::ext e(static_cast<int8_t>(byte(in, 0)), reinterpret_cast<const char *>(body.p), body.n);
    REPORT(type::ext, msgpack::type::ext_ref r(e); msgpack::type::ext copy(r),
           copy == e && !(copy != e) && !(copy < e) && !(copy > e) && copy.type() == e.type() && copy.size() == body.n
           && std::memcmp(copy.data(), body.p, body.n) == 0);
    REPORT_VOID(packer::pack<type::ext>, packer.pack(e));
}
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
static void call_type_ext_ref(payload in) {
    if (pending_body || !in.n) return;
    /* ext_ref(p, s): p[0] is the type byte, p[1..s-1] the data (ext.hpp:126-130) */
    msgpack::type::ext_ref a(reinterpret_cast<const char *>(in.p), in.n);
    msgpack::type::ext own(a);
    msgpack::type::ext_ref b(own);
    REPORT(type::ext_ref, bool eq = a == b,
           eq && !(a != b) && !(a < b) && !(a > b) && a.type() == static_cast<int8_t>(in.p[0]) && a.size() == in.n - 1
           && a.str() == std::string(b.data(), b.size()));
    REPORT_VOID(packer::pack<type::ext_ref>, packer.pack(a));
}
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
static void call_type_raw_ref(payload in) {
    if (pending_body) return;
    const char *p = reinterpret_cast<const char *>(in.p);
    uint32_t half = static_cast<uint32_t>(in.n / 2);
    msgpack::type::raw_ref a(p, half), b(p + half, static_cast<uint32_t>(in.n - half));
    REPORT(type::raw_ref, int order = (a > b) - (a < b), (a == b) != (a != b) && (order == 0) == (a == b) && a.str().size() == half);
    REPORT_VOID(packer::pack<type::raw_ref>, packer.pack(a));
}
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
static void call_type_v4raw_ref(payload in) {
    if (pending_body) return;
    const char *p = reinterpret_cast<const char *>(in.p);
    uint32_t half = static_cast<uint32_t>(in.n / 2);
    msgpack::type::v4raw_ref a(p, half), b(p + half, static_cast<uint32_t>(in.n - half));
    REPORT(type::v4raw_ref, int order = (a > b) - (a < b), (a == b) != (a != b) && (order == 0) == (a == b) && a.str().size() == half);
    REPORT_VOID(packer::pack<type::v4raw_ref>, packer.pack(a));
}
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
static void call_type_array_ref(payload in) {
    if (pending_body) return;
    std::vector<int> va(in.p, in.p + in.n / 2), vb(in.p + in.n / 2, in.p + in.n);
    msgpack::type::array_ref<std::vector<int>> a(va);
    msgpack::type::array_ref<std::vector<int>> b = msgpack::type::make_array_ref(vb);
    REPORT(type::array_ref, bool lt = a < b,
           a.size() == va.size() && (a == b) != (a != b) && lt == !(a >= b) && (a > b) == !(a <= b));
    REPORT_VOID(packer::pack<type::array_ref>, packer.pack(a));
}
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
static void call_type_fix_int(payload in) {
    if (pending_body) return;
    int32_t v = scalar<int32_t>(in);
    msgpack::type::fix_int32 f(v);
    REPORT(type::fix_int, int32_t back = f, back == v && f.get() == v);
    REPORT_VOID(packer::pack<type::fix_int>, packer.pack(f));
}
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
static void call_type_tuple(payload in) {
    if (pending_body) return;
    int64_t i = scalar<int64_t>(in);
    std::string s = payload_string(rest(in, 8));
    msgpack::type::tuple<int64_t, std::string> t(i, s);
    msgpack::type::tuple<int64_t, std::string> made = msgpack::type::make_tuple(i, s);
    int64_t i2 = 0;
    std::string s2;
    REPORT(type::tuple,
           msgpack::type::tie(i2, s2) = made; t = made;
           auto fwd = msgpack::type::forward_as_tuple(i, s);
           auto cat = msgpack::type::tuple_cat(msgpack::type::make_tuple(i), msgpack::type::make_tuple(s)),
           i2 == i && s2 == s && t.get<0>() == i && t.get<1>() == s && t.size() == 2 && &fwd.get<1>() == &s
           && std::get<1>(cat) == s);
    REPORT_VOID(packer::pack<type::tuple>, packer.pack(t));
}
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
static void call_type_define_array_pack(payload in) {
    if (pending_body) return;
    int64_t i = scalar<int64_t>(in);
    std::string s = payload_string(rest(in, 8));
    msgpack::type::define_array<int64_t, std::string> d = msgpack::type::make_define_array(i, s);
    REPORT_VOID(define_array::msgpack_pack, d.msgpack_pack(packer));
}
/* ltl: str_header_then_body, v4raw_header_then_body, bin_header_then_body, ext_header_then_body */
static void call_type_define_map_pack(payload in) {
    if (pending_body) return;
    std::string ki = "i", ks = "s";
    int64_t i = scalar<int64_t>(in);
    std::string s = payload_string(rest(in, 8));
    msgpack::type::define_map<std::string, int64_t, std::string, std::string> d = msgpack::type::make_define_map(ki, i, ks, s);
    REPORT_VOID(define_map::msgpack_pack, d.msgpack_pack(packer));
}

static void call_type_nil(payload) {
    msgpack::type::nil_t a, b;
    REPORT(type::nil_t::operator==, bool eq = a == b, eq && !(a < b));
}

static void call_version(payload) {
    REPORT(msgpack_version, const char *v = msgpack_version(),
           v != nullptr && std::to_string(msgpack_version_major()) + "." + std::to_string(msgpack_version_minor()) + "."
           + std::to_string(msgpack_version_revision()) == v);
}

/* sbuffer */

static void call_sbuffer_write(payload in) {
    if (!in.n) return;
    REPORT_VOID(sbuffer::write, sbuf.write(reinterpret_cast<const char *>(in.p), in.n));
}

static void call_sbuffer_data(payload) {
    REPORT(sbuffer::data, const char *d = sbuf.data(), d != nullptr || sbuf.size() == 0);
}

static void call_sbuffer_size(payload) {
    REPORT_VOID(sbuffer::size, sbuf.size());
}

static void call_sbuffer_clear(payload) {
    REPORT_VOID(sbuffer::clear, sbuf.clear());
    pending_body = 0;
}

static void call_sbuffer_move_assign(payload in) {
    msgpack::sbuffer other;
    if (in.n) other.write(reinterpret_cast<const char *>(in.p), in.n);
    REPORT(sbuffer::operator=, sbuf = std::move(other), sbuf.size() == in.n && other.size() == 0);
    pending_body = 0;
}

static void call_sbuffer_release(payload) {
    if (!preqed_call("sbuffer::release")) return;
    char *buf = sbuf.release();
    preqed_result("sbuffer::release", true);
    std::free(buf);
    pending_body = 0;
}

/* vrefbuffer */
/* ltl: vrefbuffer_lifecycle */
static void call_vrefbuffer_construct(payload in) {
    if (vref) return;
    if (!preqed_call("vrefbuffer::vrefbuffer")) return;
    vref = new msgpack::vrefbuffer(byte(in, 0) * 4, 1 + byte(in, 1) * 64);  /* ref_size 0..1020, chunk_size 1..16321 */
    preqed_result("vrefbuffer::vrefbuffer", true);
}
/* ltl: vrefbuffer_lifecycle */
static void call_vrefbuffer_write(payload in) {
    if (!vref) return;
    REPORT_VOID(vrefbuffer::write, vref->write(reinterpret_cast<const char *>(in.p), in.n));
}
/* ltl: vrefbuffer_lifecycle */
static void call_vrefbuffer_append_copy(payload in) {
    if (!vref) return;
    REPORT_VOID(vrefbuffer::append_copy, vref->append_copy(reinterpret_cast<const char *>(in.p), in.n));
}
/* ltl: vrefbuffer_lifecycle */
static void call_vrefbuffer_append_ref(payload in) {
    if (!vref) return;
    size_t offset = vref_backing.size();
    vref_backing.append(reinterpret_cast<const char *>(in.p), in.n);
    REPORT_VOID(vrefbuffer::append_ref, vref->append_ref(vref_backing.data() + offset, in.n));
}
/* ltl: vrefbuffer_lifecycle */
static void call_vrefbuffer_vector(payload) {
    if (!vref) return;
    REPORT(vrefbuffer::vector, const msgpack::iovec *v = vref->vector(), v != nullptr || vref->vector_size() == 0);
}
/* ltl: vrefbuffer_lifecycle */
static void call_vrefbuffer_vector_size(payload) {
    if (!vref) return;
    REPORT_VOID(vrefbuffer::vector_size, vref->vector_size());
}
/* ltl: vrefbuffer_lifecycle */
static void call_vrefbuffer_clear(payload) {
    if (!vref) return;
    REPORT_VOID(vrefbuffer::clear, vref->clear());
}
/* ltl: vrefbuffer_lifecycle */
static void call_vrefbuffer_migrate(payload) {
    if (!vref) return;
    msgpack::vrefbuffer to;
    size_t n = vref->vector_size();
    REPORT(vrefbuffer::migrate, vref->migrate(&to), to.vector_size() == n && vref->vector_size() == 0);
}
/* ltl: vrefbuffer_lifecycle */
static void call_vrefbuffer_destroy(payload) {
    if (!vref) return;
    REPORT_VOID(vrefbuffer::~vrefbuffer, delete vref);
    vref = nullptr;
    vref_backing.clear();
}

/* zone */

static void finalizer_noop(void *) {}
/* ltl: zone_lifecycle */
static void call_zone_construct(payload in) {
    if (zone) return;
    if (!preqed_call("zone::zone")) return;
    zone = new msgpack::zone(byte(in, 0) ? byte(in, 0) * 64 : MSGPACK_ZONE_CHUNK_SIZE);  /* chunk 64..16320 bytes or the default */
    preqed_result("zone::zone", true);
}
/* ltl: zone_lifecycle */
static void call_zone_allocate_align(payload in) {
    if (!zone) return;
    REPORT(zone::allocate_align, void *p = zone->allocate_align(byte(in, 0) * 16, 1u << (byte(in, 1) % 5)), p != nullptr);  /* alignment 1..16 */
}
/* ltl: zone_lifecycle */
static void call_zone_allocate_no_align(payload in) {
    if (!zone) return;
    REPORT(zone::allocate_no_align, void *p = zone->allocate_no_align(byte(in, 0) * 16), p != nullptr);
}
/* ltl: zone_lifecycle */
static void call_zone_push_finalizer(payload) {
    if (!zone) return;
    REPORT_VOID(zone::push_finalizer, zone->push_finalizer(finalizer_noop, nullptr));
}
/* ltl: zone_lifecycle */
static void call_zone_clear(payload) {
    if (!zone) return;
    REPORT_VOID(zone::clear, zone->clear());
}
/* ltl: zone_lifecycle */
static void call_zone_swap(payload) {
    if (!zone) return;
    msgpack::zone other;
    REPORT_VOID(zone::swap, zone->swap(other));
}
/* ltl: zone_lifecycle */
static void call_zone_allocate(payload in) {
    if (!zone) return;
    /* allocate<T> constructs T in the zone and registers its destructor as a finalizer (cpp11_zone.hpp:339-355) */
    REPORT(zone::allocate, std::string *s = zone->allocate<std::string>(payload_string(in)), s != nullptr && s->size() == in.n);
}
/* ltl: zone_lifecycle */
static void call_zone_move_assign(payload in) {
    if (!zone) return;
    msgpack::zone fresh(byte(in, 0) ? byte(in, 0) * 64 : MSGPACK_ZONE_CHUNK_SIZE);
    REPORT_VOID(zone::operator=, *zone = std::move(fresh));
}
/* ltl: zone_lifecycle */
static void call_define_array_object(payload in) {
    if (!zone) return;
    int64_t i = scalar<int64_t>(in);
    std::string s = payload_string(rest(in, 8));
    msgpack::object o;
    REPORT(define_array::msgpack_object, msgpack::type::make_define_array(i, s).msgpack_object(&o, *zone),
           o.type == msgpack::type::ARRAY && o.via.array.size == 2);
}
/* ltl: zone_lifecycle */
static void call_define_map_object(payload in) {
    if (!zone) return;
    std::string ki = "i", ks = "s";
    int64_t i = scalar<int64_t>(in);
    std::string s = payload_string(rest(in, 8));
    msgpack::object o;
    REPORT(define_map::msgpack_object, msgpack::type::make_define_map(ki, i, ks, s).msgpack_object(&o, *zone),
           o.type == msgpack::type::MAP && o.via.map.size == 2);
}
/* ltl: zone_lifecycle */
static void call_zone_destroy(payload) {
    if (!zone) return;
    REPORT_VOID(zone::~zone, delete zone);
    zone = nullptr;
}

/* unpack: produces handle */
/* ltl: object_handle_validity */
static void call_unpack(payload in) {
    payload src = unpack_source(in);
    TRY(msgpack::unpack, handle = msgpack::unpack(reinterpret_cast<const char *>(src.p), src.n, nullptr, nullptr, limit(in)));
    handle_valid = attempted;
}
/* ltl: object_handle_validity */
static void call_unpack_offset(payload in) {
    payload src = unpack_source(in);
    size_t off = 0;
    TRY(msgpack::unpack(off), handle = msgpack::unpack(reinterpret_cast<const char *>(src.p), src.n, off, nullptr, nullptr, limit(in)));
    handle_valid = attempted;
}
/* ltl: object_handle_validity */
static void call_unpack_referenced(payload in) {
    payload src = unpack_source(in);
    size_t off = 0;
    bool referenced = false;
    TRY(msgpack::unpack(referenced), handle = msgpack::unpack(reinterpret_cast<const char *>(src.p), src.n, off, referenced, nullptr, nullptr, limit(in)));
    handle_valid = attempted;
}
/* ltl: object_handle_validity */
static void call_unpack_v1(payload in) {
    payload src = unpack_source(in);
    size_t off = 0;
    TRY(msgpack::v1::unpack, handle = msgpack::v1::unpack(reinterpret_cast<const char *>(src.p), src.n, off, nullptr, nullptr, limit(in)));
    handle_valid = attempted;
}
/* ltl: object_handle_validity */
static void call_unpack_v2(payload in) {
    payload src = unpack_source(in);
    size_t off = 0;
    TRY(msgpack::v2::unpack, handle = msgpack::v2::unpack(reinterpret_cast<const char *>(src.p), src.n, off, nullptr, nullptr, limit(in)));
    handle_valid = attempted;
}
/* ltl: zone_lifecycle */
static void call_unpack_into_zone(payload in) {
    if (!zone) return;
    payload src = unpack_source(in);
    TRY(msgpack::unpack(zone), msgpack::object o = msgpack::unpack(*zone, reinterpret_cast<const char *>(src.p), src.n); (void)o);
}

/* streaming unpacker */
/* ltl: unpacker_lifecycle */
static void call_unpacker_construct(payload in) {
    if (unpacker) return;
    if (!preqed_call("unpacker::unpacker")) return;
    /* initial buffer 16..4080 bytes or the default; small buffers force expand_buffer */
    unpacker = new msgpack::unpacker(nullptr, nullptr, byte(in, 0) ? byte(in, 0) * 16 : MSGPACK_UNPACKER_INIT_BUFFER_SIZE, limit(rest(in, 1)));
    preqed_result("unpacker::unpacker", true);
}
/* ltl: unpacker_lifecycle, unpacker_feed_protocol */
static void call_unpacker_reserve_buffer(payload in) {
    if (!unpacker) return;
    REPORT_VOID(unpacker::reserve_buffer, unpacker->reserve_buffer(1 + byte(in, 0) * 64));  /* 1..16321 bytes */
}
/* ltl: unpacker_lifecycle */
static void call_unpacker_buffer_capacity(payload) {
    if (!unpacker) return;
    REPORT_VOID(unpacker::buffer_capacity, unpacker->buffer_capacity());
}
/* ltl: unpacker_lifecycle, unpacker_feed_protocol */
static void call_unpacker_feed(payload in) {
    if (!unpacker) return;
    payload src = unpack_source(in);
    size_t n = src.n < unpacker->buffer_capacity() ? src.n : unpacker->buffer_capacity();
    if (!preqed_call("unpacker::buffer")) return;
    char *dst = unpacker->buffer();
    if (n) std::memcpy(dst, src.p, n);  /* src.p is null when sbuf is empty */
    preqed_result("unpacker::buffer", true);
    REPORT_VOID(unpacker::buffer_consumed, unpacker->buffer_consumed(n));
}
/* ltl: unpacker_lifecycle, unpacker_feed_protocol, object_handle_validity */
static void call_unpacker_next(payload) {
    if (!unpacker) return;
    bool got = false;
    TRY(unpacker::next, got = unpacker->next(handle));
    handle_valid = attempted && got;
}
/* ltl: unpacker_lifecycle */
static void call_unpacker_message_size(payload) {
    if (!unpacker) return;
    REPORT_VOID(unpacker::message_size, unpacker->message_size());
}
/* ltl: unpacker_lifecycle */
static void call_unpacker_parsed_size(payload) {
    if (!unpacker) return;
    REPORT_VOID(unpacker::parsed_size, unpacker->parsed_size());
}
/* ltl: unpacker_lifecycle */
static void call_unpacker_nonparsed_size(payload) {
    if (!unpacker) return;
    REPORT_VOID(unpacker::nonparsed_size, unpacker->nonparsed_size());
}
/* ltl: unpacker_lifecycle */
static void call_unpacker_nonparsed_buffer(payload) {
    if (!unpacker) return;
    REPORT_VOID(unpacker::nonparsed_buffer, unpacker->nonparsed_buffer());
}
/* ltl: unpacker_lifecycle */
static void call_unpacker_skip_nonparsed_buffer(payload in) {
    if (!unpacker) return;
    size_t n = byte(in, 0);
    if (n > unpacker->nonparsed_size()) n = unpacker->nonparsed_size();
    REPORT_VOID(unpacker::skip_nonparsed_buffer, unpacker->skip_nonparsed_buffer(n));
}
/* ltl: unpacker_lifecycle */
static void call_unpacker_remove_nonparsed_buffer(payload) {
    if (!unpacker) return;
    REPORT_VOID(unpacker::remove_nonparsed_buffer, unpacker->remove_nonparsed_buffer());
}
/* ltl: unpacker_lifecycle */
static void call_unpacker_reset(payload) {
    if (!unpacker) return;
    REPORT_VOID(unpacker::reset, unpacker->reset());
}
/* ltl: unpacker_lifecycle */
static void call_unpacker_reset_zone(payload) {
    if (!unpacker) return;
    REPORT_VOID(unpacker::reset_zone, unpacker->reset_zone());
}
/* ltl: unpacker_lifecycle */
static void call_unpacker_release_zone(payload) {
    if (!unpacker) return;
    if (!preqed_call("unpacker::release_zone")) return;
    msgpack::zone *z = unpacker->release_zone();
    preqed_result("unpacker::release_zone", z != nullptr);
    delete z;
}
/* ltl: unpacker_lifecycle */
static void call_unpacker_flush_zone(payload) {
    if (!unpacker) return;
    REPORT(unpacker::flush_zone, bool ok = unpacker->flush_zone(), ok);
}
/* ltl: unpacker_lifecycle */
static void call_unpacker_destroy(payload) {
    if (!unpacker) return;
    REPORT_VOID(unpacker::~unpacker, delete unpacker);
    unpacker = nullptr;
}

/* v1 streaming unpacker (v1/unpack.hpp:866-1060): a separate implementation from the default v2 unpacker */

static msgpack::v1::unpacker *v1unpacker;
/* ltl: v1_unpacker_lifecycle */
static void call_v1unpacker_construct(payload in) {
    if (v1unpacker) return;
    if (!preqed_call("v1::unpacker::unpacker")) return;
    v1unpacker = new msgpack::v1::unpacker(nullptr, nullptr, byte(in, 0) ? byte(in, 0) * 16 : MSGPACK_UNPACKER_INIT_BUFFER_SIZE, limit(rest(in, 1)));
    preqed_result("v1::unpacker::unpacker", true);
}
/* ltl: v1_unpacker_lifecycle */
static void call_v1unpacker_move_assign(payload in) {
    if (!v1unpacker) return;
    REPORT_VOID(v1::unpacker::operator=,
                *v1unpacker = msgpack::v1::unpacker(nullptr, nullptr, byte(in, 0) ? byte(in, 0) * 16 : MSGPACK_UNPACKER_INIT_BUFFER_SIZE, limit(rest(in, 1))));
}
/* ltl: v1_unpacker_lifecycle, v1_unpacker_feed_protocol */
static void call_v1unpacker_reserve_buffer(payload in) {
    if (!v1unpacker) return;
    REPORT_VOID(v1::unpacker::reserve_buffer, v1unpacker->reserve_buffer(1 + byte(in, 0) * 64));
}
/* ltl: v1_unpacker_lifecycle */
static void call_v1unpacker_buffer_capacity(payload) {
    if (!v1unpacker) return;
    REPORT_VOID(v1::unpacker::buffer_capacity, v1unpacker->buffer_capacity());
}
/* ltl: v1_unpacker_lifecycle, v1_unpacker_feed_protocol */
static void call_v1unpacker_feed(payload in) {
    if (!v1unpacker) return;
    payload src = unpack_source(in);
    size_t n = src.n < v1unpacker->buffer_capacity() ? src.n : v1unpacker->buffer_capacity();
    if (!preqed_call("v1::unpacker::buffer")) return;
    char *dst = v1unpacker->buffer();
    if (n) std::memcpy(dst, src.p, n);
    preqed_result("v1::unpacker::buffer", true);
    REPORT_VOID(v1::unpacker::buffer_consumed, v1unpacker->buffer_consumed(n));
}
/* ltl: object_handle_validity, v1_unpacker_lifecycle, v1_unpacker_feed_protocol */
static void call_v1unpacker_next(payload) {
    if (!v1unpacker) return;
    bool got = false;
    TRY(v1::unpacker::next, got = v1unpacker->next(handle));
    handle_valid = attempted && got;
}
/* ltl: v1_unpacker_lifecycle, v1_unpacker_feed_protocol */
static void call_v1unpacker_execute(payload) {
    if (!v1unpacker) return;
    /* backward-compatible loop (v1/unpack.hpp:976-989): execute(), then data() while the zone is alive, then reset() */
    bool done = false;
    TRY(v1::unpacker::execute, done = v1unpacker->execute());
    if (!done) return;
    REPORT(v1::unpacker::data, msgpack::type::object_type t = v1unpacker->data().type, t <= msgpack::type::EXT);
    REPORT_VOID(v1::unpacker::reset, v1unpacker->reset());
}
/* ltl: v1_unpacker_lifecycle */
static void call_v1unpacker_message_size(payload) {
    if (!v1unpacker) return;
    REPORT_VOID(v1::unpacker::message_size, v1unpacker->message_size());
}
/* ltl: v1_unpacker_lifecycle */
static void call_v1unpacker_parsed_size(payload) {
    if (!v1unpacker) return;
    REPORT_VOID(v1::unpacker::parsed_size, v1unpacker->parsed_size());
}
/* ltl: v1_unpacker_lifecycle */
static void call_v1unpacker_nonparsed_size(payload) {
    if (!v1unpacker) return;
    REPORT_VOID(v1::unpacker::nonparsed_size, v1unpacker->nonparsed_size());
}
/* ltl: v1_unpacker_lifecycle */
static void call_v1unpacker_nonparsed_buffer(payload) {
    if (!v1unpacker) return;
    REPORT_VOID(v1::unpacker::nonparsed_buffer, v1unpacker->nonparsed_buffer());
}
/* ltl: v1_unpacker_lifecycle */
static void call_v1unpacker_skip_nonparsed_buffer(payload in) {
    if (!v1unpacker) return;
    size_t n = byte(in, 0);
    if (n > v1unpacker->nonparsed_size()) n = v1unpacker->nonparsed_size();
    REPORT_VOID(v1::unpacker::skip_nonparsed_buffer, v1unpacker->skip_nonparsed_buffer(n));
}
/* ltl: v1_unpacker_lifecycle */
static void call_v1unpacker_remove_nonparsed_buffer(payload) {
    if (!v1unpacker) return;
    REPORT_VOID(v1::unpacker::remove_nonparsed_buffer, v1unpacker->remove_nonparsed_buffer());
}
/* ltl: v1_unpacker_lifecycle */
static void call_v1unpacker_reset(payload) {
    if (!v1unpacker) return;
    REPORT_VOID(v1::unpacker::reset, v1unpacker->reset());
}
/* ltl: v1_unpacker_lifecycle */
static void call_v1unpacker_reset_zone(payload) {
    if (!v1unpacker) return;
    REPORT_VOID(v1::unpacker::reset_zone, v1unpacker->reset_zone());
}
/* ltl: v1_unpacker_lifecycle */
static void call_v1unpacker_release_zone(payload) {
    if (!v1unpacker) return;
    if (!preqed_call("v1::unpacker::release_zone")) return;
    msgpack::zone *z = v1unpacker->release_zone();
    preqed_result("v1::unpacker::release_zone", z != nullptr);
    delete z;
}
/* ltl: v1_unpacker_lifecycle */
static void call_v1unpacker_destroy(payload) {
    if (!v1unpacker) return;
    REPORT_VOID(v1::unpacker::~unpacker, delete v1unpacker);
    v1unpacker = nullptr;
}

/* object: inspection and conversion on handle */
/* ltl: object_handle_validity */
static void call_object_type(payload) {
    if (!handle_valid) return;
    REPORT_VOID(object::type, (void)handle.get().type);
}
/* ltl: object_handle_validity */
static void call_object_is_nil(payload) {
    if (!handle_valid) return;
    REPORT_VOID(object::is_nil, handle.get().is_nil());
}
/* ltl: object_handle_validity */
static void call_object_as_int(payload) {
    if (!handle_valid) return;
    TRY(object::as<int64_t>, handle.get().as<int64_t>());
}
/* ltl: object_handle_validity */
static void call_object_as_double(payload) {
    if (!handle_valid) return;
    TRY(object::as<double>, handle.get().as<double>());
}
/* ltl: object_handle_validity */
static void call_object_as_string(payload) {
    if (!handle_valid) return;
    TRY(object::as<std::string>, handle.get().as<std::string>());
}
/* ltl: object_handle_validity */
static void call_object_as_vector(payload) {
    if (!handle_valid) return;
    TRY(object::as<std::vector>, handle.get().as<std::vector<msgpack::object>>());
}
/* ltl: object_handle_validity */
static void call_object_as_map(payload) {
    if (!handle_valid) return;
    using string_map = std::map<std::string, msgpack::object>;
    TRY(object::as<std::map>, handle.get().as<string_map>());
}
/* ltl: object_handle_validity */
static void call_object_convert(payload) {
    if (!handle_valid) return;
    bool b;
    TRY(object::convert, handle.get().convert(b));
}
/* ltl: object_handle_validity */
static void call_object_convert_if_not_nil(payload) {
    if (!handle_valid) return;
    uint64_t v;
    TRY(object::convert_if_not_nil, handle.get().convert_if_not_nil(v));
}
/* ltl: object_handle_validity */
static void call_object_equal(payload) {
    if (!handle_valid || has_null_raw(handle.get())) return;
    REPORT(object::operator==, bool eq = handle.get() == handle.get(), eq);
}
/* ltl: object_handle_validity */
static void call_object_stream(payload) {
    if (!handle_valid) return;
    std::ostringstream os;
    REPORT_VOID(object::operator<<, os << handle.get());
}
/* ltl: zone_lifecycle */
static void call_object_construct_with_zone(payload in) {
    if (!zone) return;
    std::string s(reinterpret_cast<const char *>(in.p), in.n);
    REPORT_VOID(object::object(T,zone), msgpack::object o(s, *zone); (void)o);
}
/* ltl: object_handle_validity */
static void call_clone(payload) {
    if (!handle_valid || has_null_raw(handle.get())) return;
    REPORT_VOID(msgpack::clone, msgpack::object_handle c = msgpack::clone(handle.get()); (void)c);
}
/* ltl: object_handle_validity */
static void call_aligned_zone_size(payload) {
    if (!handle_valid) return;
    REPORT_VOID(msgpack::aligned_zone_size, msgpack::aligned_zone_size(handle.get()));
}
/* ltl: object_handle_validity */
static void call_object_handle_deref(payload) {
    if (!handle_valid) return;
    REPORT(object_handle::operator*, const msgpack::object &o = *handle, &o == &handle.get());
}
/* ltl: object_handle_validity */
static void call_object_handle_arrow(payload) {
    if (!handle_valid) return;
    REPORT(object_handle::operator->, msgpack::type::object_type t = handle->type, t == handle.get().type);
}
/* ltl: object_handle_validity */
static void call_object_not_equal(payload) {
    if (!handle_valid || has_null_raw(handle.get())) return;
    REPORT(object::operator!=, bool ne = handle.get() != handle.get(), !ne);
}
/* ltl: object_handle_validity */
static void call_object_implicit_convert(payload) {
    if (!handle_valid) return;
    TRY(object::convert(), int64_t v = handle.get().convert(); (void)v);
}
/* ltl: object_handle_validity */
static void call_object_iterate(payload) {
    if (!handle_valid) return;
    const msgpack::object &o = handle.get();
    if (o.type == msgpack::type::ARRAY)
        REPORT(msgpack::begin(array), size_t n = msgpack::end(o.via.array) - msgpack::begin(o.via.array), n == o.via.array.size);
    else if (o.type == msgpack::type::MAP)
        REPORT(msgpack::begin(map), size_t n = msgpack::end(o.via.map) - msgpack::begin(o.via.map), n == o.via.map.size);
}
/* ltl: object_handle_validity */
static void call_object_as_ext(payload) {
    if (!handle_valid || has_null_raw(handle.get())) return;
    TRY(object::as<type::ext>, msgpack::type::ext e = handle.get().as<msgpack::type::ext>(); (void)e);
}
/* ltl: object_handle_validity */
static void call_object_as_array_ref(payload) {
    if (!handle_valid) return;
    std::vector<int64_t> v;
    msgpack::type::array_ref<std::vector<int64_t>> r(v);
    TRY(object::convert<type::array_ref>, handle.get().convert(r));
}
/* ltl: object_handle_validity */
static void call_object_as_size_equal_only(payload) {
    if (!handle_valid) return;
    const msgpack::object &o = handle.get();
    std::vector<int64_t> v(o.type == msgpack::type::ARRAY ? o.via.array.size : 0);
    msgpack::type::size_equal_only<std::vector<int64_t>> s = msgpack::type::make_size_equal_only(v);
    TRY(object::convert<type::size_equal_only>, o.convert(s));
}
/* ltl: object_handle_validity */
static void call_define_array_unpack(payload) {
    if (!handle_valid) return;
    int64_t i = 0;
    std::string s;
    TRY(define_array::msgpack_unpack, msgpack::type::make_define_array(i, s).msgpack_unpack(handle.get()));
}
/* ltl: object_handle_validity */
static void call_define_map_unpack(payload) {
    if (!handle_valid) return;
    std::string ki = "i", ks = "s";
    int64_t i = 0;
    std::string s;
    TRY(define_map::msgpack_unpack, msgpack::type::make_define_map(ki, i, ks, s).msgpack_unpack(handle.get()));
}

/* visitor-based parse */

struct counting_visitor : msgpack::null_visitor {
    unsigned depth = 0;
    /* stop the visitor below 64 levels so deeply nested input cannot exhaust the stack */
    bool start_array(uint32_t) { return ++depth < 64; }
    bool start_map(uint32_t) { return ++depth < 64; }
    bool end_array() { depth--; return true; }
    bool end_map() { depth--; return true; }
};

static void call_parse(payload in) {
    payload src = unpack_source(in);
    counting_visitor v;
    /* parse returns false on error (v2/parse_decl.hpp:55); null_visitor does not throw */
    TRY(msgpack::parse, if (!msgpack::parse(reinterpret_cast<const char *>(src.p), src.n, v)) attempted = false);
}

static void call_parse_offset(payload in) {
    payload src = unpack_source(in);
    size_t off = 0;
    counting_visitor v;
    TRY(msgpack::parse(off), if (!msgpack::parse(reinterpret_cast<const char *>(src.p), src.n, off, v)) attempted = false);
}
/* ltl: object_handle_validity */
static void call_object_parser(payload) {
    if (!handle_valid) return;
    counting_visitor v;
    REPORT_VOID(object_parser::parse, msgpack::object_parser(handle.get()).parse(v));
}

/* v2::parser with the library's null_visitor (v2/parse.hpp:626-781, v2/null_visitor.hpp). parser requires
   holder.visitor().init() (parse.hpp:48) and holder.referenced()/set_referenced() (parse.hpp:907-915). */
struct init_null_visitor : msgpack::null_visitor {
    void init() {}
    /* parser::next documents msgpack::parse_error for invalid data (v2/parse.hpp:692-696); raise it like
       the library's create_object_visitor does (v2/create_object_visitor.hpp:255-257). next() returning
       false otherwise means 'need more data', a normal result. */
    void parse_error(size_t, size_t) { throw msgpack::parse_error("parse error"); }
};
struct noop_hook {
    void operator()(char *) {}
};
static noop_hook parser_hook;
struct null_parser : msgpack::v2::parser<null_parser, noop_hook> {
    typedef msgpack::v2::parser<null_parser, noop_hook> base;
    explicit null_parser(size_t n) : base(parser_hook, n) {}
    init_null_visitor &visitor() { return v; }
    bool referenced() const { return v.referenced(); }
    void set_referenced(bool r) { v.set_referenced(r); }
    init_null_visitor v;
};

static void call_parser_null_visitor(payload in) {
    payload src = unpack_source(in);
    null_parser a(1 + byte(in, 0) * 16), b(MSGPACK_UNPACKER_INIT_BUFFER_SIZE);
    a.reserve_buffer(src.n);
    if (src.n) std::memcpy(a.buffer(), src.p, src.n);
    a.buffer_consumed(src.n);
    /* the move leaves `a` empty (parse.hpp:817-834); b continues a's parse */
    REPORT_VOID(parser::operator=, static_cast<null_parser::base &>(b) = std::move(static_cast<null_parser::base &>(a)));
    TRY(parser::next, b.next());
}

/* dispatch */

static void (*const api[])(payload) = {
    call_pack_uint8, call_pack_uint16, call_pack_uint32, call_pack_uint64,
    call_pack_int8, call_pack_int16, call_pack_int32, call_pack_int64,
    call_pack_fix_uint8, call_pack_fix_uint16, call_pack_fix_uint32, call_pack_fix_uint64,
    call_pack_fix_int8, call_pack_fix_int16, call_pack_fix_int32, call_pack_fix_int64,
    call_pack_char, call_pack_signed_char, call_pack_short, call_pack_int, call_pack_long, call_pack_long_long,
    call_pack_unsigned_char, call_pack_unsigned_short, call_pack_unsigned_int, call_pack_unsigned_long,
    call_pack_unsigned_long_long, call_pack_float, call_pack_double,
    call_pack_nil, call_pack_true, call_pack_false, call_pack_array, call_pack_map,
    call_pack_str, call_pack_str_body, call_pack_v4raw, call_pack_v4raw_body,
    call_pack_bin, call_pack_bin_body, call_pack_ext, call_pack_ext_body,
    call_pack_string, call_pack_vector, call_pack_map_container, call_pack_object, call_msgpack_pack,
    call_sbuffer_write, call_sbuffer_data, call_sbuffer_size, call_sbuffer_clear, call_sbuffer_release,
    call_vrefbuffer_construct, call_vrefbuffer_write, call_vrefbuffer_append_copy, call_vrefbuffer_append_ref,
    call_vrefbuffer_vector, call_vrefbuffer_vector_size, call_vrefbuffer_clear, call_vrefbuffer_destroy,
    call_zone_construct, call_zone_allocate_align, call_zone_allocate_no_align, call_zone_push_finalizer,
    call_zone_clear, call_zone_swap, call_zone_destroy,
    call_unpack, call_unpack_offset, call_unpack_referenced, call_unpack_into_zone,
    call_unpacker_construct, call_unpacker_reserve_buffer, call_unpacker_buffer_capacity, call_unpacker_feed,
    call_unpacker_next, call_unpacker_message_size, call_unpacker_parsed_size, call_unpacker_nonparsed_size,
    call_unpacker_nonparsed_buffer, call_unpacker_skip_nonparsed_buffer, call_unpacker_remove_nonparsed_buffer,
    call_unpacker_reset, call_unpacker_reset_zone, call_unpacker_release_zone, call_unpacker_flush_zone,
    call_unpacker_destroy,
    call_object_type, call_object_is_nil, call_object_as_int, call_object_as_double, call_object_as_string,
    call_object_as_vector, call_object_as_map, call_object_convert, call_object_convert_if_not_nil,
    call_object_equal, call_object_stream, call_object_construct_with_zone, call_clone, call_aligned_zone_size,
    call_parse, call_parse_offset, call_object_parser,
    call_pack_wchar, call_type_ext, call_type_ext_ref, call_type_raw_ref, call_type_v4raw_ref, call_type_array_ref,
    call_type_fix_int, call_type_tuple, call_type_define_array_pack, call_type_define_map_pack, call_type_nil, call_version,
    call_sbuffer_move_assign, call_vrefbuffer_migrate,
    call_zone_allocate, call_zone_move_assign, call_define_array_object, call_define_map_object,
    call_unpack_v1, call_unpack_v2,
    call_v1unpacker_construct, call_v1unpacker_move_assign, call_v1unpacker_reserve_buffer, call_v1unpacker_buffer_capacity,
    call_v1unpacker_feed, call_v1unpacker_next, call_v1unpacker_execute, call_v1unpacker_message_size,
    call_v1unpacker_parsed_size, call_v1unpacker_nonparsed_size, call_v1unpacker_nonparsed_buffer,
    call_v1unpacker_skip_nonparsed_buffer, call_v1unpacker_remove_nonparsed_buffer, call_v1unpacker_reset,
    call_v1unpacker_reset_zone, call_v1unpacker_release_zone, call_v1unpacker_destroy,
    call_object_handle_deref, call_object_handle_arrow, call_object_not_equal, call_object_implicit_convert,
    call_object_iterate, call_object_as_ext, call_object_as_array_ref, call_object_as_size_equal_only,
    call_define_array_unpack, call_define_map_unpack,
    call_parser_null_visitor,
};

static const size_t API_COUNT = sizeof api / sizeof api[0];

static void cleanup() {
    handle = msgpack::object_handle();
    handle_valid = false;
    delete unpacker;
    unpacker = nullptr;
    delete v1unpacker;
    v1unpacker = nullptr;
    delete zone;
    zone = nullptr;
    delete vref;
    vref = nullptr;
    vref_backing.clear();
    sbuf.clear();
    pending_body = 0;
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
