#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/zlib.hpp>
#include <boost/beast/_experimental/test/stream.hpp>
#include <boost/asio/cancel_after.hpp>
#include <boost/asio/local/connect_pair.hpp>
#include <boost/asio/local/stream_protocol.hpp>
#include <boost/asio/post.hpp>
#include "preqed_ltl.h"

#include <sys/mman.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <vector>

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace zlib = beast::zlib;
namespace net = boost::asio;

/* Conventions: `% (N + 1)` picks every enumerator plus one out-of-range value; byte 0 of a payload usually
 * selects variants, the rest is text. beast::test::stream (_experimental/test/stream.hpp) is the in-memory
 * transport, as in Beast's own fuzzers; its sync read blocks on an empty open input, so every input stream is
 * closed after its bytes are appended. */

struct payload {
    const uint8_t *p;
    size_t n;
};

static uint8_t byte(payload in, size_t i) { return i < in.n ? in.p[i] : 0; }
static uint16_t u16(payload in, size_t i) { return (uint16_t)(byte(in, i) | byte(in, i + 1) << 8); }
static uint32_t u32(payload in, size_t i) { return (uint32_t)u16(in, i) | (uint32_t)u16(in, i + 2) << 16; }

/* Empty views still point at a valid "": chunk_extensions::insert memcpys from an empty name's data()
 * (impl/chunk_encode.hpp:654,677,680), which is UB for a null pointer; recorded in BUGS.md. */
static beast::string_view text(payload in, size_t skip) {
    if (skip >= in.n) return {"", 0};
    return {reinterpret_cast<const char *>(in.p + skip), in.n - skip};
}

/* byte `skip` is k, then a k-byte first string, then the rest */
static void split(payload in, size_t skip, beast::string_view &a, beast::string_view &b) {
    beast::string_view s = text(in, skip + 1);
    size_t k = std::min<size_t>(byte(in, skip), s.size());
    a = s.substr(0, k);
    b = s.substr(k);
}

/* field::unknown is excluded: every field-enum overload asserts name != field::unknown (impl/fields.hpp:477) */
static http::field field_of(payload in, size_t i) {
    unsigned last = static_cast<unsigned>(http::field::x_xss_protection);  /* last enumerator, field.hpp */
    return static_cast<http::field>(1 + u16(in, i) % last);
}

/* unknown..unlink, the whole enum (verb.hpp); method(verb::unknown) throws invalid_argument (message.hpp) */
static http::verb verb_of(payload in, size_t i) {
    return static_cast<http::verb>(byte(in, i) % (static_cast<unsigned>(http::verb::unlink) + 1));
}

/* every value 0..999 is accepted by result(unsigned); 1000..1023 exercises its documented throw */
static unsigned status_code(payload in, size_t i) { return u16(in, i) % 1024; }

/* 0 = no limit, otherwise 1..65535 */
static boost::optional<std::uint64_t> limit_of(payload in, size_t i) {
    uint16_t v = u16(in, i);
    if (v == 0) return boost::none;
    return std::uint64_t(v);
}

#define REPORT(api, stmt, ok_cond) \
    do { if (preqed_call(api)) { stmt; preqed_result(api, (ok_cond)); } } while (0)

/* Beast reports invalid arguments by throwing (length_error, invalid_argument, out_of_range, system_error) */
#define TRY(api, stmt, ok_cond) \
    do { \
        if (!preqed_call(api)) return; \
        bool ok_ = false; \
        try { stmt; ok_ = (ok_cond); } catch (const std::exception &) {} \
        preqed_result(api, ok_); \
    } while (0)

static net::io_context ioc;

/* Async operations complete through `ioc`: a wrapper starts one, runs the ready handlers and reports whether it
 * finished without error. The handler owns its completion record, so an operation still pending when its objects go
 * away completes harmlessly later. On the in-memory transports (closed input, connected peer) it finishes in one poll. */
struct completion {
    bool done = false;
    beast::error_code ec;
};

static void poll() {
    ioc.restart();
    ioc.poll();
}

static auto on_done(const std::shared_ptr<completion> &c) {
    return [c](beast::error_code ec, auto &&...) { c->done = true; c->ec = ec; };
}

/* The cancel_after token (asio/cancel_after.hpp:50) gives an operation a deadline it never reaches here; it asks the
 * operation's initiation for its executor. The websocket and stream wrappers use it for one overload each. */
template <class Handler> static auto bounded(Handler h) { return net::cancel_after(std::chrono::seconds(10), std::move(h)); }

/* `start` uses the completion handler `h`; `abandon` cancels or destroys what a still-pending operation uses */
#define ASYNC(api, start, abandon) \
    do { \
        if (!preqed_call(api)) return; \
        auto c_ = std::make_shared<completion>(); \
        auto h = on_done(c_); \
        start; \
        poll(); \
        bool ok_ = c_->done && !c_->ec; \
        if (!c_->done) { abandon; poll(); } \
        preqed_result(api, ok_); \
    } while (0)

/* ---------- core: strings and dynamic buffers ---------- */

static void call_iequals(payload in) {
    beast::string_view a, b;
    split(in, 0, a, b);
    REPORT("iequals", bool r = beast::iequals(a, b); (void)r, 1);
}

static void call_iless(payload in) {
    beast::string_view a, b;
    split(in, 0, a, b);
    REPORT("iless", bool r = beast::iless{}(a, b); (void)r, 1);
}

static beast::flat_buffer fb;
static beast::multi_buffer mb;
static beast::static_buffer<1024> sb;                   /* fixed capacity small enough to overflow */
static beast::flat_static_buffer<1024> fsb;

/* Library bug (NOTES.md, boost-beast): multi_buffer::prepare asserts total <= max_ (impl/multi_buffer.hpp:909) once
 * max_size(n) has lowered the limit below the memory it already holds. */
static bool prepare_asserts(beast::multi_buffer &b) { return b.capacity() > b.max_size(); }
template <class B> static bool prepare_asserts(B &) { return false; }

/* prepare(n) then copy the payload into the writable area; commit is a separate record */
#define DYNBUF_COMMON(NAME, B) \
    static void call_##B##_prepare(payload in) { \
        if (prepare_asserts(B)) return; \
        TRY(NAME "::prepare", auto w = B.prepare(u16(in, 0)); net::buffer_copy(w, net::buffer(text(in, 2).data(), text(in, 2).size())), 1); \
    } \
    static void call_##B##_commit(payload in) { REPORT(NAME "::commit", B.commit(u16(in, 0)), 1); } \
    static void call_##B##_consume(payload in) { REPORT(NAME "::consume", B.consume(u16(in, 0)), 1); } \
    static void call_##B##_size(payload) { REPORT(NAME "::size", size_t r = B.size(); (void)r, 1); } \
    static void call_##B##_capacity(payload) { REPORT(NAME "::capacity", size_t r = B.capacity(); (void)r, 1); } \
    static void call_##B##_max_size(payload) { REPORT(NAME "::max_size", size_t r = B.max_size(); (void)r, 1); } \
    static void call_##B##_clear(payload) { REPORT(NAME "::clear", B.clear(), 1); } \
    static void call_##B##_data(payload) { REPORT(NAME "::data", size_t r = beast::buffer_bytes(B.data()); (void)r, 1); } \
    static void call_##B##_cdata(payload) { REPORT(NAME "::cdata", size_t r = beast::buffer_bytes(B.cdata()); (void)r, 1); }

#define DYNBUF_GROWABLE(NAME, B) \
    static void call_##B##_reserve(payload in) { TRY(NAME "::reserve", B.reserve(u16(in, 0)), 1); } \
    static void call_##B##_shrink_to_fit(payload) { REPORT(NAME "::shrink_to_fit", B.shrink_to_fit(), 1); } \
    static void call_##B##_set_max_size(payload in) { REPORT(NAME "::max_size(n)", B.max_size(u16(in, 0)), 1); } \
    static void call_##B##_get_allocator(payload) { REPORT(NAME "::get_allocator", auto a = B.get_allocator(); (void)a, 1); } \
    /* swaps with a new buffer holding the payload */ \
    static void call_##B##_swap(payload in) { \
        std::remove_reference_t<decltype(B)> t; \
        beast::ostream(t) << text(in, 0); \
        REPORT("swap(" NAME ")", beast::swap(B, t), 1); \
    }

DYNBUF_COMMON("flat_buffer", fb)
DYNBUF_GROWABLE("flat_buffer", fb)
DYNBUF_COMMON("multi_buffer", mb)
DYNBUF_GROWABLE("multi_buffer", mb)
DYNBUF_COMMON("static_buffer", sb)
DYNBUF_COMMON("flat_static_buffer", fsb)

static void call_sb_base(payload) {
    REPORT("static_buffer::base", beast::static_buffer_base &b = sb.base(); size_t r = b.capacity() + b.max_size(); (void)r, 1);
}

static void call_fsb_base(payload) {
    REPORT("flat_static_buffer::base", beast::flat_static_buffer_base &b = fsb.base(); size_t r = b.capacity() + b.max_size(); (void)r, 1);
}

static void call_sb_assign(payload) {
    beast::static_buffer<1024> t;
    REPORT("static_buffer::operator=", t = sb, 1);
}

static void call_fsb_assign(payload) {
    beast::flat_static_buffer<1024> t;
    REPORT("flat_static_buffer::operator=", t = fsb, 1);
}

/* a const view assigned from the mutable one, walked backwards */
static void call_mb_subrange_assign(payload) {
    REPORT("multi_buffer::const_buffers_type::operator=", beast::multi_buffer::const_buffers_type c = mb.cdata(); c = mb.data();
           size_t r = c.buffer_bytes(); for (auto it = c.end(); it != c.begin();) r += (*--it).size(); (void)r, 1);
}

static void call_buffers_to_string(payload) {
    REPORT("buffers_to_string", std::string s = beast::buffers_to_string(mb.data()), 1);
}

static void call_buffer_bytes(payload) {
    REPORT("buffer_bytes", size_t r = beast::buffer_bytes(mb.data()); (void)r, 1);
}

static void call_buffers_prefix(payload in) {
    REPORT("buffers_prefix", std::string s = beast::buffers_to_string(beast::buffers_prefix(u16(in, 0), mb.data())), 1);
}

static void call_buffers_suffix(payload in) {
    REPORT("buffers_suffix", beast::buffers_suffix<beast::multi_buffer::const_buffers_type> s(mb.data());
           s.consume(u16(in, 0)); size_t r = beast::buffer_bytes(s); (void)r, 1);
}

static void call_buffers_cat(payload) {
    REPORT("buffers_cat", std::string s = beast::buffers_to_string(beast::buffers_cat(fb.data(), mb.data())), 1);
}

/* view and iterator copies, walked backwards */
static void call_buffers_prefix_assign(payload in) {
    REPORT("buffers_prefix_view::operator=", auto v = beast::buffers_prefix(u16(in, 0), mb.data()); auto w = v; w = v;
           size_t r = w.buffer_bytes_impl(); auto it = w.begin(); it = w.end(); while (it != w.begin()) r += (*--it).size(); (void)r, 1);
}

static void call_buffers_suffix_assign(payload in) {
    REPORT("buffers_suffix::operator=", beast::buffers_suffix<beast::multi_buffer::const_buffers_type> s(mb.data());
           s.consume(u16(in, 0)); auto t = s; t = s; size_t r = 0; auto it = t.begin(); it = t.end();
           while (it != t.begin()) r += (*--it).size(); (void)r, 1);
}

static void call_buffers_cat_assign(payload) {
    REPORT("buffers_cat_view::operator=", auto v = beast::buffers_cat(fb.data(), mb.data()); auto w = v; w = v;
           size_t r = 0; auto it = w.begin(); it = w.end(); while (it != w.begin()) r += (*--it).size(); (void)r, 1);
}

static void call_buffers_front(payload) {
    REPORT("buffers_front", size_t r = beast::buffers_front(mb.data()).size(); (void)r, 1);
}

static void call_buffers_range(payload) {
    REPORT("buffers_range", size_t r = 0; for (auto b : beast::buffers_range(mb.data())) r += b.size(); (void)r, 1);
}

static void call_ostream(payload in) {
    TRY("ostream", beast::ostream(fb) << text(in, 0), 1);
}

static void call_make_printable(payload) {
    REPORT("make_printable", std::ostringstream os; os << beast::make_printable(mb.data()), 1);
}

static void call_read_size(payload in) {
    REPORT("read_size", size_t r = beast::read_size(fb, 1 + u16(in, 0)); (void)r, 1);
}

static void call_read_size_or_throw(payload in) {
    TRY("read_size_or_throw", size_t r = beast::read_size_or_throw(fsb, 1 + u16(in, 0)); (void)r, 1);
}

static void call_iequal(payload in) {
    beast::string_view a, b;
    split(in, 0, a, b);
    REPORT("iequal", bool r = beast::iequal{}(a, b), r);
}

static void call_make_error_condition(payload) {
    REPORT("make_error_condition", auto c = beast::make_error_condition(beast::condition::timeout); std::string s = c.message(), 1);
}

/* handshake_failed and protocol_violation, websocket/error.hpp:229 */
static void call_ws_make_error_condition(payload in) {
    auto v = static_cast<websocket::condition>(1 + byte(in, 0) % 2);
    REPORT("websocket::make_error_condition", auto c = websocket::make_error_condition(v); std::string s = c.message(), 1);
}

/* ---------- core: buffers_adaptor over caller memory ---------- */

static char ba_mem[1024];
static std::optional<beast::buffers_adaptor<net::mutable_buffer>> ba;
static void call_ba_ctor(payload in) {
    REPORT("buffers_adaptor", ba.emplace(net::buffer(ba_mem, 1 + u16(in, 0) % sizeof ba_mem)), 1);
}

/* prepare throws length_error beyond max_size (buffers_adaptor.hpp:171) */
static void call_ba_prepare(payload in) {
    if (!ba) return;
    TRY("buffers_adaptor::prepare", auto w = ba->prepare(u16(in, 0)); net::buffer_copy(w, net::buffer(text(in, 2).data(), text(in, 2).size())), 1);
}
static void call_ba_commit(payload in) { if (ba) REPORT("buffers_adaptor::commit", ba->commit(u16(in, 0)), 1); }
static void call_ba_consume(payload in) { if (ba) REPORT("buffers_adaptor::consume", ba->consume(u16(in, 0)), 1); }
static void call_ba_size(payload) { if (ba) REPORT("buffers_adaptor::size", size_t r = ba->size(); (void)r, 1); }
static void call_ba_max_size(payload) { if (ba) REPORT("buffers_adaptor::max_size", size_t r = ba->max_size(); (void)r, 1); }
static void call_ba_capacity(payload) { if (ba) REPORT("buffers_adaptor::capacity", size_t r = ba->capacity(); (void)r, 1); }
static void call_ba_value(payload) { if (ba) REPORT("buffers_adaptor::value", size_t r = ba->value().size(); (void)r, 1); }

/* the readable bytes, forwards then backwards */
static void call_ba_data(payload) {
    if (ba) REPORT("buffers_adaptor::data", auto d = ba->data(); auto e = d; e = d; size_t r = beast::buffers_to_string(e).size();
                   for (auto it = d.end(); it != d.begin();) r += (*--it).size(); (void)r, 1);
}
static void call_ba_cdata(payload) {
    if (ba) REPORT("buffers_adaptor::cdata", auto d = ba->cdata(); size_t r = beast::buffers_to_string(d).size();
                   for (auto it = d.end(); it != d.begin();) r += (*--it).size(); (void)r, 1);
}

/* a copy refers to the same memory (buffers_adaptor.hpp:90) */
static void call_ba_assign(payload) {
    if (!ba) return;
    beast::buffers_adaptor<net::mutable_buffer> t(*ba);
    REPORT("buffers_adaptor::operator=", *ba = t, 1);
}

static void call_detect_ssl(payload in) {
    beast::test::stream s{ioc, text(in, 0)};
    s.close_remote();
    beast::flat_buffer b;
    beast::error_code ec;
    REPORT("detect_ssl", bool r = beast::detect_ssl(s, b, ec); (void)r, !ec);
}

static void call_async_detect_ssl(payload in) {
    beast::test::stream s{ioc, text(in, 0)};
    s.close_remote();
    beast::flat_buffer b;
    ASYNC("async_detect_ssl", beast::async_detect_ssl(s, b, h), s.close());
}

/* ---------- http: verbs, status codes, field names, rfc7230 lists ---------- */

static void call_string_to_verb(payload in) {
    REPORT("string_to_verb", http::verb v = http::string_to_verb(text(in, 0)), v != http::verb::unknown);
}

static void call_to_string_verb(payload in) {
    REPORT("to_string(verb)", beast::string_view s = http::to_string(verb_of(in, 0)); (void)s, 1);
}

static void call_int_to_status(payload in) {
    REPORT("int_to_status", http::status s = http::int_to_status(status_code(in, 0)), s != http::status::unknown);
}

static void call_to_status_class_int(payload in) {
    REPORT("to_status_class(unsigned)", http::status_class c = http::to_status_class(status_code(in, 0)),
           c != http::status_class::unknown);
}

static void call_to_status_class(payload in) {
    REPORT("to_status_class(status)", http::status_class c = http::to_status_class(http::int_to_status(status_code(in, 0))),
           c != http::status_class::unknown);
}

static void call_obsolete_reason(payload in) {
    REPORT("obsolete_reason", beast::string_view s = http::obsolete_reason(http::int_to_status(status_code(in, 0))); (void)s, 1);
}

static void call_string_to_field(payload in) {
    REPORT("string_to_field", http::field f = http::string_to_field(text(in, 0)), f != http::field::unknown);
}

static void call_to_string_field(payload in) {
    REPORT("to_string(field)", beast::string_view s = http::to_string(field_of(in, 0)); (void)s, 1);
}

static void call_param_list(payload in) {
    REPORT("param_list", size_t r = 0; for (auto const &p : http::param_list(text(in, 0))) r += p.first.size() + p.second.size(); (void)r, 1);
}

static void call_ext_list(payload in) {
    REPORT("ext_list", size_t r = 0;
           for (auto const &e : http::ext_list(text(in, 0))) for (auto const &p : e.second) r += p.first.size(); (void)r, 1);
}

static void call_ext_list_find(payload in) {
    beast::string_view key, list;
    split(in, 0, key, list);
    REPORT("ext_list::find", http::ext_list l(list); bool r = l.find(key) != l.end(), r);
}

static void call_ext_list_exists(payload in) {
    beast::string_view key, list;
    split(in, 0, key, list);
    REPORT("ext_list::exists", bool r = http::ext_list(list).exists(key), r);
}

static void call_param_list_cbegin(payload in) {
    REPORT("param_list::cbegin", http::param_list l(text(in, 0)); size_t r = 0;
           for (auto it = l.cbegin(); it != l.cend(); ++it) r += it->first.size() + it->second.size(); (void)r, 1);
}

static void call_ext_list_cbegin(payload in) {
    REPORT("ext_list::cbegin", http::ext_list l(text(in, 0)); size_t r = 0;
           for (auto it = l.cbegin(); it != l.cend(); ++it) r += it->first.size(); (void)r, 1);
}

static void call_token_list_cbegin(payload in) {
    REPORT("token_list::cbegin", http::token_list l(text(in, 0)); size_t r = 0;
           for (auto it = l.cbegin(); it != l.cend(); ++it) r += it->size(); (void)r, 1);
}

static void call_token_list(payload in) {
    REPORT("token_list", size_t r = 0; for (auto const &t : http::token_list(text(in, 0))) r += t.size(); (void)r, 1);
}

static void call_token_list_exists(payload in) {
    beast::string_view key, list;
    split(in, 0, key, list);
    REPORT("token_list::exists", bool r = http::token_list(list).exists(key), r);
}

static void call_opt_token_list(payload in) {
    REPORT("opt_token_list", size_t r = 0; for (auto const &t : http::opt_token_list(text(in, 0))) r += t.size(); (void)r, 1);
}

static void call_validate_list(payload in) {
    REPORT("validate_list", bool r = http::validate_list(http::opt_token_list(text(in, 0))), r);
}

/* ---------- http: chunked-encoding buffers ---------- */

static http::chunk_extensions exts;
/* Library bug (NOTES.md, boost-beast): a failed parse leaves a partial entry in the iteration index, and only a
 * successful parse rebuilds it (clear() does not); iterating it reads past the end of the heap buffer. */
static bool exts_partial;

static void call_chunk_extensions_parse(payload in) {
    beast::error_code ec;
    REPORT("chunk_extensions::parse", exts.parse(text(in, 0), ec); exts_partial = (bool)ec, !ec);
}

static void call_chunk_extensions_insert(payload in) {
    TRY("chunk_extensions::insert(name)", exts.insert(text(in, 0)), 1);
}

static void call_chunk_extensions_insert_value(payload in) {
    beast::string_view name, value;
    split(in, 0, name, value);
    TRY("chunk_extensions::insert(name,value)", exts.insert(name, value), 1);
}

static void call_chunk_extensions_str(payload) {
    REPORT("chunk_extensions::str", beast::string_view s = exts.str(); (void)s, 1);
}

static void call_chunk_extensions_clear(payload) { REPORT("chunk_extensions::clear", exts.clear(), 1); }

static void call_chunk_extensions_begin(payload) {
    if (exts_partial) return;
    REPORT("chunk_extensions::begin", size_t r = 0; for (auto const &e : exts) r += e.first.size() + e.second.size(); (void)r, 1);
}

/* iterator access and assignment */
static void call_chunk_extensions_iterator(payload) {
    if (exts_partial) return;
    REPORT("chunk_extensions::const_iterator", size_t r = 0; auto it = exts.begin();
           for (; it != exts.end(); ++it) r += it->first.size() + it->second.size(); it = exts.begin(); (void)r, 1);
}

/* the chunk size "must be greater than zero" (chunk_encode.hpp:125) */
static void call_chunk_header(payload in) {
    REPORT("chunk_header", std::string s = beast::buffers_to_string(http::chunk_header(1 + (size_t)u32(in, 0))), 1);
}

static void call_chunk_header_ext(payload in) {
    REPORT("chunk_header(ext)", std::string s = beast::buffers_to_string(http::chunk_header(1 + (size_t)u32(in, 0), text(in, 4))), 1);
}

static void call_chunk_body(payload in) {
    net::const_buffer b(text(in, 0).data(), text(in, 0).size());
    REPORT("chunk_body", std::string s = beast::buffers_to_string(http::chunk_body<net::const_buffer>(b)), 1);
}

static void call_chunk_body_ext(payload in) {
    beast::string_view ext, data;
    split(in, 0, ext, data);
    net::const_buffer b(data.data(), data.size());
    REPORT("chunk_body(ext)", std::string s = beast::buffers_to_string(http::chunk_body<net::const_buffer>(b, ext)), 1);
}

static void call_chunk_crlf(payload) {
    http::chunk_crlf c;
    REPORT("chunk_crlf", std::string s = beast::buffers_to_string(c), 1);
}

static void call_make_chunk(payload in) {
    net::const_buffer b(text(in, 0).data(), text(in, 0).size());
    REPORT("make_chunk", std::string s = beast::buffers_to_string(http::make_chunk(b)), 1);
}

static void call_make_chunk_last(payload) {
    REPORT("make_chunk_last", std::string s = beast::buffers_to_string(http::make_chunk_last()), 1);
}

/* ---------- http: messages and fields ---------- */

static http::request<http::string_body> req;
static http::response<http::string_body> res;

/* HTTP version = major*10 + minor; version() asserts 0 < value < 100 (message.hpp:337), so 1..99 = 0.1 through 9.9 */
static unsigned version_of(payload in, size_t i) { return 1 + byte(in, i) % 99; }

static void call_request(payload in) {
    TRY("request", req = http::request<http::string_body>(verb_of(in, 0), text(in, 2), version_of(in, 1)), 1);
}

static void call_response(payload in) {
    TRY("response", res = http::response<http::string_body>(http::int_to_status(status_code(in, 0)), version_of(in, 2)), 1);
}

static void call_request_method(payload in) { TRY("request::method(verb)", req.method(verb_of(in, 0)), 1); }
static void call_request_method_get(payload) { REPORT("request::method", http::verb v = req.method(); (void)v, 1); }
static void call_request_method_string(payload in) { TRY("request::method_string(s)", req.method_string(text(in, 0)), 1); }
static void call_request_method_string_get(payload) {
    REPORT("request::method_string", beast::string_view s = req.method_string(); (void)s, 1);
}
static void call_request_target(payload in) { TRY("request::target(s)", req.target(text(in, 0)), 1); }
static void call_request_target_get(payload) { REPORT("request::target", beast::string_view s = req.target(); (void)s, 1); }

static void call_response_result(payload in) { TRY("response::result(status)", res.result(http::int_to_status(status_code(in, 0))), 1); }
static void call_response_result_int(payload in) { TRY("response::result(unsigned)", res.result(status_code(in, 0)), 1); }
static void call_response_result_get(payload) { REPORT("response::result", http::status s = res.result(); (void)s, 1); }
static void call_response_result_int_get(payload) { REPORT("response::result_int", unsigned r = res.result_int(); (void)r, 1); }
static void call_response_reason(payload in) { TRY("response::reason(s)", res.reason(text(in, 0)), 1); }
static void call_response_reason_get(payload) { REPORT("response::reason", beast::string_view s = res.reason(); (void)s, 1); }

#define MESSAGE_API(NAME, M) \
    static void call_##M##_version(payload in) { REPORT(NAME "::version(v)", M.version(version_of(in, 0)), 1); } \
    static void call_##M##_version_get(payload) { REPORT(NAME "::version", unsigned r = M.version(); (void)r, 1); } \
    static void call_##M##_chunked(payload in) { TRY(NAME "::chunked(b)", M.chunked(byte(in, 0) & 1), 1); } \
    static void call_##M##_chunked_get(payload) { REPORT(NAME "::chunked", bool r = M.chunked(); (void)r, 1); } \
    static void call_##M##_keep_alive(payload in) { TRY(NAME "::keep_alive(b)", M.keep_alive(byte(in, 0) & 1), 1); } \
    static void call_##M##_keep_alive_get(payload) { REPORT(NAME "::keep_alive", bool r = M.keep_alive(); (void)r, 1); } \
    static void call_##M##_content_length(payload in) { TRY(NAME "::content_length", M.content_length(limit_of(in, 0)), 1); } \
    static void call_##M##_has_content_length(payload) { REPORT(NAME "::has_content_length", bool r = M.has_content_length(), r); } \
    static void call_##M##_need_eof(payload) { REPORT(NAME "::need_eof", bool r = M.need_eof(), r); } \
    static void call_##M##_payload_size(payload) { REPORT(NAME "::payload_size", auto r = M.payload_size(), r.has_value()); } \
    static void call_##M##_prepare_payload(payload) { TRY(NAME "::prepare_payload", M.prepare_payload(), 1); } \
    static void call_##M##_body(payload in) { REPORT(NAME "::body", M.body().assign(text(in, 0).data(), text(in, 0).size()), 1); }

MESSAGE_API("request", req)
MESSAGE_API("response", res)

/* the fields of the request (bit 0 clear) or of the response (bit 0 set); the rest of the payload follows byte 0 */
static http::fields &fields_of(payload in) {
    if (byte(in, 0) & 1) return res;
    return req;
}

static void call_fields_at(payload in) {
    http::fields &f = fields_of(in);
    TRY("fields::at(field)", beast::string_view s = f.at(field_of(in, 1)); (void)s, 1);
}

static void call_fields_at_name(payload in) {
    http::fields &f = fields_of(in);
    TRY("fields::at(name)", beast::string_view s = f.at(text(in, 1)); (void)s, 1);
}

static void call_fields_index(payload in) {
    http::fields &f = fields_of(in);
    REPORT("fields::operator[](field)", beast::string_view s = f[field_of(in, 1)], !s.empty());
}

static void call_fields_index_name(payload in) {
    http::fields &f = fields_of(in);
    REPORT("fields::operator[](name)", beast::string_view s = f[text(in, 1)], !s.empty());
}

static void call_fields_insert(payload in) {
    http::fields &f = fields_of(in);
    TRY("fields::insert(field)", f.insert(field_of(in, 1), text(in, 3)), 1);
}

static void call_fields_insert_name(payload in) {
    http::fields &f = fields_of(in);
    beast::string_view name, value;
    split(in, 1, name, value);
    TRY("fields::insert(name)", f.insert(name, value), 1);
}

/* name_string must equal to_string(name) unless name is field::unknown (fields.hpp:520) */
static void call_fields_insert_ec(payload in) {
    http::fields &f = fields_of(in);
    beast::error_code ec;
    if (byte(in, 1) & 1) {
        beast::string_view name, value;
        split(in, 2, name, value);
        REPORT("fields::insert(field,name,value,ec)", f.insert(http::field::unknown, name, value, ec), !ec);
    } else {
        http::field name = field_of(in, 2);
        REPORT("fields::insert(field,name,value,ec)", f.insert(name, http::to_string(name), text(in, 4), ec), !ec);
    }
}

static void call_fields_set(payload in) {
    http::fields &f = fields_of(in);
    TRY("fields::set(field)", f.set(field_of(in, 1), text(in, 3)), 1);
}

static void call_fields_set_name(payload in) {
    http::fields &f = fields_of(in);
    beast::string_view name, value;
    split(in, 1, name, value);
    TRY("fields::set(name)", f.set(name, value), 1);
}

static void call_fields_erase(payload in) {
    http::fields &f = fields_of(in);
    REPORT("fields::erase(field)", size_t r = f.erase(field_of(in, 1)), r != 0);
}

static void call_fields_erase_name(payload in) {
    http::fields &f = fields_of(in);
    REPORT("fields::erase(name)", size_t r = f.erase(text(in, 1)), r != 0);
}

/* erases the k-th field */
static void call_fields_erase_iterator(payload in) {
    http::fields &f = fields_of(in);
    auto it = f.begin();
    for (unsigned k = byte(in, 1); k && it != f.end(); --k) ++it;
    if (it == f.end()) return;
    REPORT("fields::erase(iterator)", f.erase(it), 1);
}

static void call_fields_clear(payload in) {
    http::fields &f = fields_of(in);
    REPORT("fields::clear", f.clear(), 1);
}

static void call_fields_contains(payload in) {
    http::fields &f = fields_of(in);
    REPORT("fields::contains(field)", bool r = f.contains(field_of(in, 1)), r);
}

static void call_fields_contains_name(payload in) {
    http::fields &f = fields_of(in);
    REPORT("fields::contains(name)", bool r = f.contains(text(in, 1)), r);
}

static void call_fields_count(payload in) {
    http::fields &f = fields_of(in);
    REPORT("fields::count(field)", size_t r = f.count(field_of(in, 1)), r != 0);
}

static void call_fields_count_name(payload in) {
    http::fields &f = fields_of(in);
    REPORT("fields::count(name)", size_t r = f.count(text(in, 1)), r != 0);
}

static void call_fields_find(payload in) {
    http::fields &f = fields_of(in);
    REPORT("fields::find(field)", bool r = f.find(field_of(in, 1)) != f.end(), r);
}

static void call_fields_find_name(payload in) {
    http::fields &f = fields_of(in);
    REPORT("fields::find(name)", bool r = f.find(text(in, 1)) != f.end(), r);
}

static void call_fields_equal_range(payload in) {
    http::fields &f = fields_of(in);
    REPORT("fields::equal_range(field)", auto r = f.equal_range(field_of(in, 1)), r.first != r.second);
}

static void call_fields_equal_range_name(payload in) {
    http::fields &f = fields_of(in);
    REPORT("fields::equal_range(name)", auto r = f.equal_range(text(in, 1)), r.first != r.second);
}

static void call_fields_begin(payload in) {
    http::fields &f = fields_of(in);
    REPORT("fields::begin", size_t r = 0;
           for (auto const &e : f) r += e.name_string().size() + e.value().size() + (e.name() == http::field::unknown); (void)r, 1);
}

static void call_fields_cbegin(payload in) {
    http::fields &f = fields_of(in);
    REPORT("fields::cbegin", size_t r = 0; for (auto it = f.cbegin(); it != f.cend(); ++it) r += it->value().size(); (void)r, 1);
}

/* compares a name with the first field (key_compare, fields.hpp:124) */
static void call_fields_key_comp(payload in) {
    http::fields &f = fields_of(in);
    if (f.begin() == f.end()) return;
    REPORT("fields::key_comp", bool r = f.key_comp()(text(in, 1), *f.begin()), r);
}

static void call_fields_get_allocator(payload in) {
    http::fields &f = fields_of(in);
    REPORT("fields::get_allocator", auto a = f.get_allocator(); (void)a, 1);
}

/* swaps the request with a new one built from the payload */
static void call_http_swap(payload in) {
    http::request<http::string_body> t;
    try { t = http::request<http::string_body>(verb_of(in, 0), text(in, 2), version_of(in, 1)); } catch (const std::exception &) { return; }
    REPORT("http::swap", http::swap(req, t), 1);
}

static void call_fields_swap(payload) {
    http::fields &a = req, &b = res;
    REPORT("fields::swap", a.swap(b), 1);
}

static void call_ostream_request(payload) { REPORT("operator<<(request)", std::ostringstream os; os << req, 1); }
static void call_ostream_response(payload) { REPORT("operator<<(response)", std::ostringstream os; os << res, 1); }

static void call_is_upgrade(payload) { REPORT("websocket::is_upgrade", bool r = websocket::is_upgrade(req), r); }

static void call_make_chunk_last_trailer(payload in) {
    REPORT("make_chunk_last(trailer)", std::string s = beast::buffers_to_string(http::make_chunk_last(fields_of(in))), 1);
}

/* ---------- http: parsers ---------- */

static std::optional<http::request_parser<http::string_body>> rqp;
static std::optional<http::response_parser<http::string_body>> rsp;
static beast::flat_buffer io_buf;                        /* leftover octets between http::read* calls */

/* the parser keeps references to these callbacks (parser.hpp:235, 283), so they live as long as the program */
static std::function<void(std::uint64_t, beast::string_view, beast::error_code &)> on_chunk_header_cb =
    [](std::uint64_t, beast::string_view ext, beast::error_code &) {
        http::chunk_extensions ce;
        beast::error_code e;
        ce.parse(ext, e);
    };
static std::function<std::size_t(std::uint64_t, beast::string_view, beast::error_code &)> on_chunk_body_cb =
    [](std::uint64_t, beast::string_view body, beast::error_code &) { return body.size(); };

/* Guards:
 * - put/put_eof/read on a finished parser asserts !is_done() (impl/basic_parser.ipp:90); the message can finish
 *   inside any put, where the LTL cannot see it, so the parser is asked first.
 * - put_eof asserts got_some() (impl/basic_parser.ipp:205), which also depends on what put consumed. */
#define PARSER_API(NAME, P, MSG) \
    static void call_##P##_ctor(payload) { REPORT(NAME, P.emplace(), 1); } \
    static void call_##P##_put(payload in) { \
        if (!P || P->is_done()) return; \
        beast::error_code ec; \
        REPORT(NAME "::put", P->put(net::buffer(text(in, 0).data(), text(in, 0).size()), ec), !ec); \
    } \
    static void call_##P##_put_eof(payload) { \
        if (!P || P->is_done() || !P->got_some()) return; \
        beast::error_code ec; \
        REPORT(NAME "::put_eof", P->put_eof(ec), !ec); \
    } \
    static void call_##P##_is_done(payload) { if (P) REPORT(NAME "::is_done", bool r = P->is_done(), r); } \
    static void call_##P##_is_header_done(payload) { if (P) REPORT(NAME "::is_header_done", bool r = P->is_header_done(), r); } \
    static void call_##P##_got_some(payload) { if (P) REPORT(NAME "::got_some", bool r = P->got_some(), r); } \
    static void call_##P##_upgrade(payload) { if (P) REPORT(NAME "::upgrade", bool r = P->upgrade(), r); } \
    static void call_##P##_chunked(payload) { if (P) REPORT(NAME "::chunked", bool r = P->chunked(), r); } \
    static void call_##P##_keep_alive(payload) { if (P) REPORT(NAME "::keep_alive", bool r = P->keep_alive(), r); } \
    static void call_##P##_content_length(payload) { if (P) REPORT(NAME "::content_length", auto r = P->content_length(), r.has_value()); } \
    static void call_##P##_content_length_remaining(payload) { \
        if (P) REPORT(NAME "::content_length_remaining", auto r = P->content_length_remaining(), r.has_value()); \
    } \
    static void call_##P##_need_eof(payload) { if (P) REPORT(NAME "::need_eof", bool r = P->need_eof(), r); } \
    static void call_##P##_body_limit(payload in) { if (P) REPORT(NAME "::body_limit", P->body_limit(limit_of(in, 0)), 1); } \
    static void call_##P##_header_limit(payload in) { if (P) REPORT(NAME "::header_limit", P->header_limit(u32(in, 0)), 1); } \
    static void call_##P##_eager(payload in) { if (P) REPORT(NAME "::eager(b)", P->eager(byte(in, 0) & 1), 1); } \
    static void call_##P##_eager_get(payload) { if (P) REPORT(NAME "::eager", bool r = P->eager(), r); } \
    static void call_##P##_skip(payload in) { if (P) REPORT(NAME "::skip(b)", P->skip(byte(in, 0) & 1), 1); } \
    static void call_##P##_skip_get(payload) { if (P) REPORT(NAME "::skip", bool r = P->skip(), r); } \
    static void call_##P##_get(payload) { if (P) REPORT(NAME "::get", size_t r = P->get().body().size(); (void)r, 1); } \
    static void call_##P##_release(payload) { if (P) REPORT(NAME "::release", MSG = P->release(), 1); } \
    static void call_##P##_on_chunk_header(payload) { if (P) REPORT(NAME "::on_chunk_header", P->on_chunk_header(on_chunk_header_cb), 1); } \
    static void call_##P##_on_chunk_body(payload) { if (P) REPORT(NAME "::on_chunk_body", P->on_chunk_body(on_chunk_body_cb), 1); } \
    static void call_##P##_merge_all_trailers(payload in) { \
        if (P) REPORT(NAME "::merge_all_trailers(b)", P->merge_all_trailers(byte(in, 0) & 1), 1); \
    } \
    static void call_##P##_merge_all_trailers_get(payload) { \
        if (P) REPORT(NAME "::merge_all_trailers", bool r = P->merge_all_trailers(), r); \
    } \
    static void call_##P##_read(payload in) { \
        if (!P || P->is_done()) return; \
        beast::test::stream s{ioc, text(in, 0)}; \
        s.close_remote(); \
        beast::error_code ec; \
        REPORT("http::read(" NAME ")", http::read(s, io_buf, *P, ec), !ec); \
    } \
    static void call_##P##_read_header(payload in) { \
        if (!P || P->is_done()) return; \
        beast::test::stream s{ioc, text(in, 0)}; \
        s.close_remote(); \
        beast::error_code ec; \
        REPORT("http::read_header(" NAME ")", http::read_header(s, io_buf, *P, ec), !ec); \
    } \
    static void call_##P##_read_some(payload in) { \
        if (!P || P->is_done()) return; \
        beast::test::stream s{ioc, text(in, 0)}; \
        s.close_remote(); \
        beast::error_code ec; \
        REPORT("http::read_some(" NAME ")", http::read_some(s, io_buf, *P, ec), !ec); \
    } \
    static void call_##P##_async_read(payload in) { \
        if (!P || P->is_done()) return; \
        beast::test::stream s{ioc, text(in, 0)}; \
        s.close_remote(); \
        ASYNC("http::async_read(" NAME ")", http::async_read(s, io_buf, *P, h), s.close()); \
    } \
    static void call_##P##_async_read_header(payload in) { \
        if (!P || P->is_done()) return; \
        beast::test::stream s{ioc, text(in, 0)}; \
        s.close_remote(); \
        ASYNC("http::async_read_header(" NAME ")", http::async_read_header(s, io_buf, *P, h), s.close()); \
    } \
    static void call_##P##_async_read_some(payload in) { \
        if (!P || P->is_done()) return; \
        beast::test::stream s{ioc, text(in, 0)}; \
        s.close_remote(); \
        ASYNC("http::async_read_some(" NAME ")", http::async_read_some(s, io_buf, *P, h), s.close()); \
    }
/* ltl: request_parser_configure_before_parsing, request_parser_done_is_final, request_parser_header_queries */
PARSER_API("request_parser", rqp, req)
/* ltl: response_parser_configure_before_parsing, response_parser_done_is_final, response_parser_header_queries */
PARSER_API("response_parser", rsp, res)

static void call_read_request(payload in) {
    beast::test::stream s{ioc, text(in, 0)};
    s.close_remote();
    beast::error_code ec;
    REPORT("http::read(request)", http::read(s, io_buf, req, ec), !ec);
}

static void call_async_read_request(payload in) {
    beast::test::stream s{ioc, text(in, 0)};
    s.close_remote();
    ASYNC("http::async_read(request)", http::async_read(s, io_buf, req, h), s.close());
}

static void call_async_read_response(payload in) {
    beast::test::stream s{ioc, text(in, 0)};
    s.close_remote();
    ASYNC("http::async_read(response)", http::async_read(s, io_buf, res, h), s.close());
}

static void call_read_response(payload in) {
    beast::test::stream s{ioc, text(in, 0)};
    s.close_remote();
    beast::error_code ec;
    REPORT("http::read(response)", http::read(s, io_buf, res, ec), !ec);
}

/* ---------- http: serializers, writes, message_generator ---------- */

/* the serializer refers to its message (serializer.hpp:226), so each one owns a copy taken at construction */
template <bool isRequest> struct serializer_box {
    http::message<isRequest, http::string_body> msg;
    http::serializer<isRequest, http::string_body> sr{msg};
    size_t pending = 0;                                  /* octets offered by the last next() */
    explicit serializer_box(const http::message<isRequest, http::string_body> &m) : msg(m) {}
};

static std::unique_ptr<serializer_box<true>> rqs;
static std::unique_ptr<serializer_box<false>> rss;

/* writes go to a connected peer whose input is discarded */
struct sink {
    beast::test::stream out{ioc}, peer{ioc};
    sink() { out.connect(peer); }
};

/* Guard: next() after is_done() hits the serializer's done state (impl/serializer.hpp:277); completion happens
 * inside consume or http::write, where the LTL cannot see it. consume(n) takes at most what next() offered
 * (serializer.hpp:359). */
#define SERIALIZER_API(NAME, S, MSG) \
    static void call_##S##_ctor(payload) { REPORT(NAME, S.reset(new std::remove_reference_t<decltype(*S)>(MSG)), 1); } \
    static void call_##S##_next(payload) { \
        if (!S || S->sr.is_done()) return; \
        beast::error_code ec; \
        REPORT(NAME "::next", S->sr.next(ec, [&](beast::error_code &, auto const &b) { S->pending = beast::buffer_bytes(b); }), !ec); \
    } \
    static void call_##S##_consume(payload in) { \
        if (!S) return; \
        size_t n = std::min<size_t>(u16(in, 0), S->pending); \
        REPORT(NAME "::consume", S->sr.consume(n); S->pending = 0, 1); \
    } \
    static void call_##S##_is_done(payload) { if (S) REPORT(NAME "::is_done", bool r = S->sr.is_done(), r); } \
    static void call_##S##_is_header_done(payload) { if (S) REPORT(NAME "::is_header_done", bool r = S->sr.is_header_done(), r); } \
    static void call_##S##_split(payload in) { if (S) REPORT(NAME "::split(b)", S->sr.split(byte(in, 0) & 1), 1); } \
    static void call_##S##_split_get(payload) { if (S) REPORT(NAME "::split", bool r = S->sr.split(), r); } \
    static void call_##S##_limit(payload in) { if (S) REPORT(NAME "::limit(n)", S->sr.limit(u16(in, 0)), 1); } \
    static void call_##S##_limit_get(payload) { if (S) REPORT(NAME "::limit", size_t r = S->sr.limit(); (void)r, 1); } \
    static void call_##S##_get(payload) { if (S) REPORT(NAME "::get", size_t r = S->sr.get().body().size(); (void)r, 1); } \
    static void call_##S##_write(payload) { \
        if (!S) return; \
        sink k; \
        beast::error_code ec; \
        REPORT("http::write(" NAME ")", http::write(k.out, S->sr, ec); S->pending = 0, !ec); \
    } \
    static void call_##S##_write_header(payload) { \
        if (!S) return; \
        sink k; \
        beast::error_code ec; \
        REPORT("http::write_header(" NAME ")", http::write_header(k.out, S->sr, ec); S->pending = 0, !ec); \
    } \
    static void call_##S##_write_some(payload) { \
        if (!S || S->sr.is_done()) return; \
        sink k; \
        beast::error_code ec; \
        REPORT("http::write_some(" NAME ")", http::write_some(k.out, S->sr, ec); S->pending = 0, !ec); \
    } \
    static void call_##S##_async_write(payload) { \
        if (!S) return; \
        sink k; \
        S->pending = 0; \
        ASYNC("http::async_write(" NAME ")", http::async_write(k.out, S->sr, h), k.out.close()); \
    } \
    static void call_##S##_async_write_header(payload) { \
        if (!S) return; \
        sink k; \
        S->pending = 0; \
        ASYNC("http::async_write_header(" NAME ")", http::async_write_header(k.out, S->sr, h), k.out.close()); \
    } \
    static void call_##S##_async_write_some(payload) { \
        if (!S || S->sr.is_done()) return; \
        sink k; \
        S->pending = 0; \
        ASYNC("http::async_write_some(" NAME ")", http::async_write_some(k.out, S->sr, h), k.out.close()); \
    }
/* ltl: request_serializer_consume_after_next */
SERIALIZER_API("request_serializer", rqs, req)
/* ltl: response_serializer_consume_after_next */
SERIALIZER_API("response_serializer", rss, res)

static void call_write_request(payload) {
    sink k;
    beast::error_code ec;
    REPORT("http::write(request)", http::write(k.out, req, ec), !ec);
}

static void call_write_response(payload) {
    sink k;
    beast::error_code ec;
    REPORT("http::write(response)", http::write(k.out, res, ec), !ec);
}

static void call_async_write_request(payload) {
    sink k;
    ASYNC("http::async_write(request)", http::async_write(k.out, req, h), k.out.close());
}

static void call_async_write_response(payload) {
    sink k;
    ASYNC("http::async_write(response)", http::async_write(k.out, res, h), k.out.close());
}

/* ---------- http: the other body types ---------- */

/* One in-memory file per process for file_posix, file_stdio and file_body, reached by path through /proc. */
static int memfd() {
    static int fd = memfd_create("beast-fuzz", 0);
    return fd;
}

static std::string mem_path() { return "/proc/self/fd/" + std::to_string(memfd()); }

/* read, scan, write, write_new, write_existing, append, append_existing (file_base.hpp:43) */
static beast::file_mode file_mode_of(payload in, size_t i) {
    return static_cast<beast::file_mode>(byte(in, i) % 7);
}

/* reads one request from the payload into p */
template <class Parser> static bool read_into(Parser &p, payload in) {
    beast::test::stream s{ioc, text(in, 0)};
    s.close_remote();
    beast::flat_buffer b;
    beast::error_code ec;
    http::read(s, b, p, ec);
    return !ec;
}

template <class Message> static bool write_out(Message &m) {
    sink k;
    beast::error_code ec;
    http::write(k.out, m, ec);
    return !ec;
}

/* a 200 response whose payload_size the body reports (prepare_payload calls Body::size) */
template <class Body> static http::response<Body> response_of() {
    http::response<Body> m{http::status::ok, 11};
    return m;
}

static void call_read_vector_body(payload in) {
    http::request_parser<http::vector_body<char>> p;
    REPORT("http::read(vector_body)", bool ok = read_into(p, in), ok);
}

static void call_write_vector_body(payload in) {
    auto m = response_of<http::vector_body<char>>();
    m.body().assign(text(in, 0).begin(), text(in, 0).end());
    m.prepare_payload();
    REPORT("http::write(vector_body)", bool ok = write_out(m), ok);
}

/* the body is a caller span of 1..4096 bytes (byte 0-1); the request follows */
static void call_read_span_body(payload in) {
    static char mem[4096];
    http::request_parser<http::span_body<char>> p;
    p.get().body() = beast::span<char>(mem, 1 + u16(in, 0) % sizeof mem);
    REPORT("http::read(span_body)", bool ok = read_into(p, payload{in.p + std::min<size_t>(2, in.n), in.n - std::min<size_t>(2, in.n)}), ok);
}

static void call_write_span_body(payload in) {
    std::string d(text(in, 0));
    auto m = response_of<http::span_body<char>>();
    m.body() = beast::span<char>(&d[0], d.size());
    m.prepare_payload();
    REPORT("http::write(span_body)", bool ok = write_out(m), ok);
}

/* the buffer_body read loop of buffer_body.hpp:30-60: refill the caller buffer while the parser asks for one */
static void call_read_buffer_body(payload in) {
    char mem[512];
    http::request_parser<http::buffer_body> p;
    beast::test::stream s{ioc, text(in, 0)};
    s.close_remote();
    beast::flat_buffer b;
    beast::error_code ec;
    REPORT("http::read(buffer_body)",
           for (size_t k = 0; k <= in.n && !p.is_done(); ++k) {
               p.get().body().data = mem;
               p.get().body().size = sizeof mem;
               http::read(s, b, p, ec);
               if (ec == http::error::need_buffer) ec = {};
               if (ec) break;
           },
           !ec);
}

static void call_write_buffer_body(payload in) {
    std::string d(text(in, 0));
    auto m = response_of<http::buffer_body>();
    m.body().data = d.empty() ? nullptr : &d[0];
    m.body().size = d.size();
    m.body().more = false;
    m.prepare_payload();
    REPORT("http::write(buffer_body)", bool ok = write_out(m), ok);
}

static void call_read_empty_body(payload in) {
    http::request_parser<http::empty_body> p;
    REPORT("http::read(empty_body)", bool ok = read_into(p, in), ok);
}

static void call_write_empty_body(payload) {
    auto m = response_of<http::empty_body>();
    m.prepare_payload();
    REPORT("http::write(empty_body)", bool ok = write_out(m), ok);
}

static void call_read_dynamic_body(payload in) {
    http::request_parser<http::dynamic_body> p;
    REPORT("http::read(dynamic_body)", bool ok = read_into(p, in), ok);
}

static void call_write_dynamic_body(payload in) {
    auto m = response_of<http::dynamic_body>();
    beast::ostream(m.body()) << text(in, 0);
    m.prepare_payload();
    REPORT("http::write(dynamic_body)", bool ok = write_out(m), ok);
}

/* the body file is the in-memory file opened for writing; the reader asserts it is open (basic_file_body.hpp:514) */
static void call_read_file_body(payload in) {
    http::request_parser<http::file_body> p;
    beast::error_code ec;
    p.get().body().open(mem_path().c_str(), beast::file_mode::write, ec);
    if (ec) return;
    REPORT("http::read(file_body)", bool ok = read_into(p, in), ok);
}

/* sends the in-memory file after storing the payload in it; the writer asserts it is open (basic_file_body.hpp:347) */
static void call_write_file_body(payload in) {
    if (ftruncate(memfd(), 0) != 0 || pwrite(memfd(), text(in, 0).data(), text(in, 0).size(), 0) != (ssize_t)text(in, 0).size()) return;
    auto m = response_of<http::file_body>();
    beast::error_code ec;
    m.body().open(mem_path().c_str(), beast::file_mode::scan, ec);
    if (ec) return;
    m.prepare_payload();
    REPORT("http::write(file_body)", bool ok = write_out(m), ok);
}

/* ---------- core: files ---------- */

static beast::file_posix fposix;
static beast::file_stdio fstdio;
static char file_buf[4096];

/* errors on a closed file are reported through ec (impl/file_posix.ipp:211, impl/file_stdio.ipp:217) */
#define FILE_API(NAME, F, T) \
    static void call_##F##_open(payload in) { \
        beast::error_code ec; \
        REPORT(NAME "::open", F.open(mem_path().c_str(), file_mode_of(in, 0), ec), !ec); \
    } \
    static void call_##F##_close(payload) { beast::error_code ec; REPORT(NAME "::close", F.close(ec), !ec); } \
    static void call_##F##_is_open(payload) { REPORT(NAME "::is_open", bool r = F.is_open(), r); } \
    static void call_##F##_size(payload) { beast::error_code ec; REPORT(NAME "::size", auto r = F.size(ec); (void)r, !ec); } \
    static void call_##F##_pos(payload) { beast::error_code ec; REPORT(NAME "::pos", auto r = F.pos(ec); (void)r, !ec); } \
    static void call_##F##_seek(payload in) { beast::error_code ec; REPORT(NAME "::seek", F.seek(u32(in, 0), ec), !ec); } \
    static void call_##F##_read(payload in) { \
        beast::error_code ec; \
        REPORT(NAME "::read", size_t r = F.read(file_buf, 1 + u16(in, 0) % sizeof file_buf, ec); (void)r, !ec); \
    } \
    static void call_##F##_write(payload in) { \
        beast::error_code ec; \
        REPORT(NAME "::write", size_t r = F.write(text(in, 0).data(), text(in, 0).size(), ec); (void)r, !ec); \
    } \
    static void call_##F##_native_handle(payload) { REPORT(NAME "::native_handle", auto r = F.native_handle(); (void)r, 1); } \
    /* moves the file into a temporary, which closes it */ \
    static void call_##F##_move(payload) { REPORT(NAME, T t(std::move(F)), 1); } \
    /* takes over a newly opened file */ \
    static void call_##F##_assign(payload in) { \
        T t; \
        beast::error_code ec; \
        t.open(mem_path().c_str(), file_mode_of(in, 0), ec); \
        REPORT(NAME "::operator=", F = std::move(t), 1); \
    }

FILE_API("file_posix", fposix, beast::file_posix)
FILE_API("file_stdio", fstdio, beast::file_stdio)

/* a descriptor of its own for the in-memory file */
static void call_fposix_set_native_handle(payload) {
    int fd = dup(memfd());
    if (fd < 0) return;
    REPORT("file_posix::native_handle(fd)", fposix.native_handle(fd), 1);
}

static void call_fstdio_set_native_handle(payload) {
    int fd = dup(memfd());
    if (fd < 0) return;
    std::FILE *f = fdopen(fd, "r+");
    if (!f) { close(fd); return; }
    REPORT("file_stdio::native_handle(FILE*)", fstdio.native_handle(f), 1);
}

static http::file_body::value_type fbody;

static void call_fbody_open(payload in) {
    beast::error_code ec;
    REPORT("file_body::value_type::open", fbody.open(mem_path().c_str(), file_mode_of(in, 0), ec), !ec);
}

static void call_fbody_close(payload) { REPORT("file_body::value_type::close", fbody.close(), 1); }
static void call_fbody_is_open(payload) { REPORT("file_body::value_type::is_open", bool r = fbody.is_open(), r); }
static void call_fbody_size(payload) { REPORT("file_body::value_type::size", auto r = fbody.size(); (void)r, 1); }
static void call_fbody_file(payload) { REPORT("file_body::value_type::file", bool r = fbody.file().is_open(), r); }

/* "The file must be open or else an error occurs" (basic_file_body.hpp:158) */
static void call_fbody_reset(payload in) {
    beast::file_posix f;
    beast::error_code ec;
    f.open(mem_path().c_str(), file_mode_of(in, 0), ec);
    REPORT("file_body::value_type::reset", fbody.reset(std::move(f), ec), !ec);
}

/* takes over a newly opened file body */
static void call_fbody_assign(payload in) {
    http::file_body::value_type t;
    beast::error_code ec;
    t.open(mem_path().c_str(), file_mode_of(in, 0), ec);
    REPORT("file_body::value_type::operator=", fbody = std::move(t), 1);
}

static void call_fbody_seek(payload in) {
    beast::error_code ec;
    REPORT("file_body::value_type::seek", fbody.seek(u32(in, 0), ec), !ec);
}

static std::optional<http::message_generator> gen;
static size_t gen_pending;                               /* octets offered by the last prepare() */

/* bit 0 picks a copy of the request (clear) or of the response (set) */
/* ltl: message_generator_consume_after_prepare */
static void call_message_generator(payload in) {
    if (byte(in, 0) & 1)
        REPORT("message_generator", gen.emplace(http::response<http::string_body>(res)); gen_pending = 0, 1);
    else
        REPORT("message_generator", gen.emplace(http::request<http::string_body>(req)); gen_pending = 0, 1);
}
/* ltl: message_generator_consume_after_prepare */
static void call_message_generator_prepare(payload) {
    if (!gen || gen->is_done()) return;
    beast::error_code ec;
    REPORT("message_generator::prepare", gen_pending = beast::buffer_bytes(gen->prepare(ec)), !ec);
}
/* ltl: message_generator_consume_after_prepare */
static void call_message_generator_consume(payload in) {
    if (!gen) return;
    size_t n = std::min<size_t>(u16(in, 0), gen_pending);
    REPORT("message_generator::consume", gen->consume(n); gen_pending = 0, 1);
}

static void call_message_generator_is_done(payload) {
    if (gen) REPORT("message_generator::is_done", bool r = gen->is_done(), r);
}

static void call_message_generator_keep_alive(payload) {
    if (gen) REPORT("message_generator::keep_alive", bool r = gen->keep_alive(), r);
}
/* ltl: message_generator_consume_after_prepare */
static void call_write_generator(payload) {
    if (!gen) return;
    sink k;
    beast::error_code ec;
    REPORT("write(message_generator)", beast::write(k.out, *gen, ec); gen_pending = 0, !ec);
}

/* async_write takes the generator by value (buffers_generator.hpp:189), so the slot is emptied */
/* ltl: message_generator_consume_after_prepare */
static void call_async_write_generator(payload) {
    if (!gen) return;
    sink k;
    http::message_generator g = std::move(*gen);
    gen.reset();
    gen_pending = 0;
    ASYNC("async_write(message_generator)", beast::async_write(k.out, std::move(g), h), k.out.close());
}

/* ---------- zlib ---------- */

static zlib::deflate_stream deflater;
static zlib::inflate_stream inflater;
static zlib::z_params dz, iz;
static std::vector<uint8_t> zout(1 << 16);

static zlib::Flush flush_of(payload in, size_t i) {
    return static_cast<zlib::Flush>(byte(in, i) % 7);  /* none, block, partial, sync, full, finish, trees */
}

static zlib::Strategy strategy_of(payload in, size_t i) {
    return static_cast<zlib::Strategy>(byte(in, i) % 5);  /* normal, filtered, huffman, rle, fixed */
}

/* avail_out is 1..65536 (bytes 1-2), input is the rest */
static void z_setup(zlib::z_params &z, payload in) {
    beast::string_view s = text(in, 3);
    z.next_in = s.data();
    z.avail_in = s.size();
    z.next_out = zout.data();
    z.avail_out = 1 + u16(in, 1);
}

/* level -1..9 (-1 = default), windowBits 8..15 (8 is raised to 9), memLevel 1..9: deflate_stream.hpp:94,
 * plus one invalid value each, which reset rejects by throwing */
static void call_deflate_reset_params(payload in) {
    int level = (int)(byte(in, 0) % 12) - 1, wbits = 8 + byte(in, 1) % 9, mem = 1 + byte(in, 2) % 10;
    TRY("deflate_stream::reset(level,windowBits,memLevel,strategy)", deflater.reset(level, wbits, mem, strategy_of(in, 3)), 1);
}

static void call_deflate_reset(payload) { REPORT("deflate_stream::reset", deflater.reset(), 1); }
static void call_deflate_clear(payload) { REPORT("deflate_stream::clear", deflater.clear(), 1); }

static void call_deflate_upper_bound(payload in) {
    REPORT("deflate_stream::upper_bound", size_t r = deflater.upper_bound(u32(in, 0)); (void)r, 1);
}

static void call_deflate_upper_bound_free(payload in) {
    REPORT("deflate_upper_bound", size_t r = zlib::deflate_upper_bound(u32(in, 0)); (void)r, 1);
}

/* good_length, max_lazy, nice_length, max_chain: 0..258 (zlib's MAX_MATCH) */
static void call_deflate_tune(payload in) {
    REPORT("deflate_stream::tune", deflater.tune(byte(in, 0), u16(in, 1) % 259, u16(in, 3) % 259, u16(in, 5)), 1);
}

static void call_deflate_write(payload in) {
    z_setup(dz, in);
    beast::error_code ec;
    TRY("deflate_stream::write", deflater.write(dz, flush_of(in, 0), ec), !ec);
}

static void call_deflate_params(payload in) {
    z_setup(dz, in);
    beast::error_code ec;
    TRY("deflate_stream::params", deflater.params(dz, (int)(byte(in, 0) % 12) - 1, strategy_of(in, 3), ec), !ec);
}

static void call_deflate_pending(payload) {
    unsigned value = 0;
    int bits = 0;
    REPORT("deflate_stream::pending", deflater.pending(&value, &bits), 1);
}

/* bits 0..16 (zlib deflatePrime accepts at most 16) plus one invalid value */
static void call_deflate_prime(payload in) {
    beast::error_code ec;
    REPORT("deflate_stream::prime", deflater.prime(byte(in, 0) % 18, u16(in, 1), ec), !ec);
}

/* windowBits 8..15 plus one value that throws domain_error (detail/inflate_stream.ipp:59) */
static void call_inflate_reset_bits(payload in) {
    TRY("inflate_stream::reset(windowBits)", inflater.reset(8 + byte(in, 0) % 9), 1);
}

static void call_inflate_reset(payload) { REPORT("inflate_stream::reset", inflater.reset(), 1); }
static void call_inflate_clear(payload) { REPORT("inflate_stream::clear", inflater.clear(), 1); }

static void call_inflate_write(payload in) {
    z_setup(iz, in);
    beast::error_code ec;
    TRY("inflate_stream::write", inflater.write(iz, flush_of(in, 0), ec), !ec);
}

/* ---------- websocket ---------- */

/* The stream's next layer reads the record's payload and then end-of-file; writes go to `peer`. */
struct ws_box {
    beast::test::stream peer{ioc};
    websocket::stream<beast::test::stream> ws;
    explicit ws_box(beast::string_view input) : ws(ioc, input) {
        ws.next_layer().connect(peer);
        ws.next_layer().close_remote();
    }
};

static std::unique_ptr<ws_box> wsb;
static beast::flat_buffer ws_buf;
static size_t control_frames;
/* ltl: websocket_handshake_before_messages, websocket_write_buffer_before_handshake, websocket_frame_before_message_type, websocket_status_after_handshake */
static void call_ws_stream(payload in) { REPORT("websocket::stream", wsb.reset(new ws_box(text(in, 0))), 1); }

/* permessage_deflate fields (option.hpp): window bits 8..16 and levels -1..10 include values set_option rejects
 * by throwing invalid_argument (detail/impl_base.hpp:231) */
static void call_ws_set_option_pmd(payload in) {
    if (!wsb) return;
    websocket::permessage_deflate o;
    uint8_t f = byte(in, 0);
    o.server_enable = f & 1;
    o.client_enable = f & 2;
    o.server_no_context_takeover = f & 4;
    o.client_no_context_takeover = f & 8;
    o.server_max_window_bits = 8 + byte(in, 1) % 9;
    o.client_max_window_bits = 8 + byte(in, 2) % 9;
    o.compLevel = (int)(byte(in, 3) % 12) - 1;
    o.memLevel = byte(in, 4) % 11;
    o.msg_size_threshold = u16(in, 5);
    TRY("websocket::stream::set_option(permessage_deflate)", wsb->ws.set_option(o), 1);
}

static void call_ws_get_option_pmd(payload) {
    if (!wsb) return;
    websocket::permessage_deflate o;
    REPORT("websocket::stream::get_option(permessage_deflate)", wsb->ws.get_option(o), 1);
}
/* ltl: websocket_status_after_handshake */
static void call_ws_get_status(payload) {
    if (!wsb) return;
    websocket::permessage_deflate_status s;
    REPORT("websocket::stream::get_status", wsb->ws.get_status(s), s.active);
}

/* bit 0 clear: decorate the handshake request's User-Agent; set: the accept response's Server; value = the rest */
static void call_ws_set_option_decorator(payload in) {
    if (!wsb) return;
    std::string v(text(in, 1));
    if (byte(in, 0) & 1)
        TRY("websocket::stream::set_option(decorator)", wsb->ws.set_option(websocket::stream_base::decorator(
                [v](websocket::response_type &r) { r.set(http::field::server, v); })), 1);
    else
        TRY("websocket::stream::set_option(decorator)", wsb->ws.set_option(websocket::stream_base::decorator(
                [v](websocket::request_type &r) { r.set(http::field::user_agent, v); })), 1);
}

#define WS_FLAG(NAME, FN) \
    static void call_ws_##FN(payload in) { if (wsb) REPORT("websocket::stream::" NAME "(b)", wsb->ws.FN(byte(in, 0) & 1), 1); } \
    static void call_ws_##FN##_get(payload) { if (wsb) REPORT("websocket::stream::" NAME, bool r = wsb->ws.FN(), r); }

WS_FLAG("auto_fragment", auto_fragment)
WS_FLAG("binary", binary)
WS_FLAG("text", text)
WS_FLAG("compress", compress)

static void call_ws_read_message_max(payload in) {
    if (wsb) REPORT("websocket::stream::read_message_max(n)", wsb->ws.read_message_max(u32(in, 0)), 1);
}

static void call_ws_read_message_max_get(payload) {
    if (wsb) REPORT("websocket::stream::read_message_max", size_t r = wsb->ws.read_message_max(); (void)r, 1);
}

/* the minimum is 8 (stream.hpp:620); smaller values throw invalid_argument */
/* ltl: websocket_write_buffer_before_handshake */
static void call_ws_write_buffer_bytes(payload in) {
    if (wsb) TRY("websocket::stream::write_buffer_bytes(n)", wsb->ws.write_buffer_bytes(u16(in, 0)), 1);
}

static void call_ws_write_buffer_bytes_get(payload) {
    if (wsb) REPORT("websocket::stream::write_buffer_bytes", size_t r = wsb->ws.write_buffer_bytes(); (void)r, 1);
}

static void call_ws_secure_prng(payload in) {
    if (wsb) REPORT("websocket::stream::secure_prng", wsb->ws.secure_prng(byte(in, 0) & 1), 1);
}

static void call_ws_is_open(payload) { if (wsb) REPORT("websocket::stream::is_open", bool r = wsb->ws.is_open(), r); }
/* ltl: websocket_frame_before_message_type */
static void call_ws_got_text(payload) { if (wsb) REPORT("websocket::stream::got_text", bool r = wsb->ws.got_text(), r); }
/* ltl: websocket_frame_before_message_type */
static void call_ws_got_binary(payload) { if (wsb) REPORT("websocket::stream::got_binary", bool r = wsb->ws.got_binary(), r); }
static void call_ws_is_message_done(payload) {
    if (wsb) REPORT("websocket::stream::is_message_done", bool r = wsb->ws.is_message_done(), r);
}
static void call_ws_reason(payload) {
    if (wsb) REPORT("websocket::stream::reason", websocket::close_reason const &r = wsb->ws.reason(), r.code != websocket::close_code::none);
}

/* initial_size is "a non-zero size" (stream.hpp:352) */
static void call_ws_read_size_hint(payload in) {
    if (wsb) REPORT("websocket::stream::read_size_hint(n)", size_t r = wsb->ws.read_size_hint(1 + (size_t)u16(in, 0)); (void)r, 1);
}

static void call_ws_read_size_hint_buffer(payload) {
    if (wsb) REPORT("websocket::stream::read_size_hint(buffer)", size_t r = wsb->ws.read_size_hint(ws_buf); (void)r, 1);
}

static void call_ws_control_callback(payload) {
    if (wsb) REPORT("websocket::stream::control_callback(cb)",
                    wsb->ws.control_callback([](websocket::frame_type, beast::string_view) { ++control_frames; }), 1);
}

static void call_ws_control_callback_reset(payload) {
    if (wsb) REPORT("websocket::stream::control_callback", wsb->ws.control_callback(), 1);
}
/* ltl: websocket_handshake_before_messages, websocket_write_buffer_before_handshake, websocket_status_after_handshake */
static void call_ws_accept(payload) {
    if (!wsb) return;
    beast::error_code ec;
    REPORT("websocket::stream::accept", wsb->ws.accept(ec), !ec);
}
/* ltl: websocket_handshake_before_messages, websocket_write_buffer_before_handshake, websocket_status_after_handshake */
static void call_ws_accept_buffers(payload in) {
    if (!wsb) return;
    beast::error_code ec;
    REPORT("websocket::stream::accept(buffers)", wsb->ws.accept(net::buffer(text(in, 0).data(), text(in, 0).size()), ec), !ec);
}
/* ltl: websocket_handshake_before_messages, websocket_write_buffer_before_handshake, websocket_status_after_handshake */
static void call_ws_accept_request(payload) {
    if (!wsb) return;
    beast::error_code ec;
    REPORT("websocket::stream::accept(request)", wsb->ws.accept(req, ec), !ec);
}
/* ltl: websocket_handshake_before_messages, websocket_write_buffer_before_handshake, websocket_status_after_handshake */
static void call_ws_handshake(payload in) {
    if (!wsb) return;
    beast::string_view host, target;
    split(in, 0, host, target);
    beast::error_code ec;
    REPORT("websocket::stream::handshake", wsb->ws.handshake(host, target, ec), !ec);
}
/* ltl: websocket_handshake_before_messages, websocket_write_buffer_before_handshake, websocket_status_after_handshake */
static void call_ws_handshake_response(payload in) {
    if (!wsb) return;
    beast::string_view host, target;
    split(in, 0, host, target);
    beast::error_code ec;
    REPORT("websocket::stream::handshake(response)", wsb->ws.handshake(res, host, target, ec), !ec);
}
/* ltl: websocket_handshake_before_messages, websocket_frame_before_message_type */
static void call_ws_read(payload) {
    if (!wsb) return;
    beast::error_code ec;
    REPORT("websocket::stream::read", wsb->ws.read(ws_buf, ec), !ec);
}

/* limit 0 means no limit (impl/read.hpp:1000) */
/* ltl: websocket_handshake_before_messages, websocket_frame_before_message_type */
static void call_ws_read_some(payload in) {
    if (!wsb) return;
    beast::error_code ec;
    REPORT("websocket::stream::read_some(buffer,limit)", wsb->ws.read_some(ws_buf, u16(in, 0), ec), !ec);
}

/* reads into a caller buffer of 1..4096 bytes */
/* ltl: websocket_handshake_before_messages, websocket_frame_before_message_type */
static void call_ws_read_some_buffers(payload in) {
    if (!wsb) return;
    static char out[4096];
    beast::error_code ec;
    REPORT("websocket::stream::read_some(buffers)", wsb->ws.read_some(net::buffer(out, 1 + u16(in, 0) % sizeof out), ec), !ec);
}
/* ltl: websocket_handshake_before_messages */
static void call_ws_write(payload in) {
    if (!wsb) return;
    beast::error_code ec;
    REPORT("websocket::stream::write", wsb->ws.write(net::buffer(text(in, 0).data(), text(in, 0).size()), ec), !ec);
}
/* ltl: websocket_handshake_before_messages */
static void call_ws_write_some(payload in) {
    if (!wsb) return;
    beast::error_code ec;
    REPORT("websocket::stream::write_some",
           wsb->ws.write_some(byte(in, 0) & 1, net::buffer(text(in, 1).data(), text(in, 1).size()), ec), !ec);
}

/* control-frame payloads are at most 125 bytes (rfc6455.hpp ping_data), close reasons at most 123 (reason_string) */
/* ltl: websocket_handshake_before_messages */
static void call_ws_ping(payload in) {
    if (!wsb) return;
    beast::error_code ec;
    beast::string_view s = text(in, 0).substr(0, 125);
    websocket::ping_data pd;
    pd.assign(s.data(), s.size());
    REPORT("websocket::stream::ping", wsb->ws.ping(pd, ec), !ec);
}
/* ltl: websocket_handshake_before_messages */
static void call_ws_pong(payload in) {
    if (!wsb) return;
    beast::error_code ec;
    beast::string_view s = text(in, 0).substr(0, 125);
    websocket::ping_data pd;
    pd.assign(s.data(), s.size());
    REPORT("websocket::stream::pong", wsb->ws.pong(pd, ec), !ec);
}
/* ltl: websocket_handshake_before_messages */
static void call_ws_close(payload in) {
    if (!wsb) return;
    websocket::close_reason cr;
    cr.code = u16(in, 0);
    beast::string_view s = text(in, 2).substr(0, 123);
    cr.reason.assign(s.data(), s.size());
    beast::error_code ec;
    REPORT("websocket::stream::close", wsb->ws.close(cr, ec), !ec);
}

/* timeouts apply to asynchronous operations only (stream_base.hpp:86); each duration is the suggested value, none(),
 * 0 ms (expires at once) or 1 ms */
static websocket::stream_base::duration duration_of(payload in, size_t i, websocket::stream_base::duration suggested) {
    switch (byte(in, i) % 4) {
    case 0: return suggested;
    case 1: return websocket::stream_base::none();
    case 2: return std::chrono::milliseconds(0);
    default: return std::chrono::milliseconds(1);
    }
}

static void call_ws_set_option_timeout(payload in) {
    if (!wsb) return;
    auto t = websocket::stream_base::timeout::suggested(byte(in, 0) & 1 ? beast::role_type::server : beast::role_type::client);
    t.handshake_timeout = duration_of(in, 1, t.handshake_timeout);
    t.idle_timeout = duration_of(in, 2, t.idle_timeout);
    t.keep_alive_pings = byte(in, 3) & 1;
    REPORT("websocket::stream::set_option(timeout)", wsb->ws.set_option(t), 1);
}

static void call_ws_get_option_timeout(payload) {
    if (!wsb) return;
    websocket::stream_base::timeout t;
    REPORT("websocket::stream::get_option(timeout)", wsb->ws.get_option(t), 1);
}

static void call_ws_get_executor(payload) {
    if (wsb) REPORT("websocket::stream::get_executor", auto e = wsb->ws.get_executor(); (void)e, 1);
}

static void call_get_lowest_layer(payload) {
    if (wsb) REPORT("get_lowest_layer", beast::test::stream &l = beast::get_lowest_layer(wsb->ws); (void)l, 1);
}

static void call_close_reason_bool(payload in) {
    websocket::close_reason cr(u16(in, 0));
    REPORT("websocket::close_reason::operator bool", bool r = static_cast<bool>(cr), r);
}

/* Asynchronous counterparts of the operations above; an operation still pending after the poll is abandoned by
 * destroying the stream, which cancels it. */
/* ltl: websocket_handshake_before_messages, websocket_write_buffer_before_handshake, websocket_status_after_handshake */
static void call_ws_async_accept(payload) {
    if (!wsb) return;
    ASYNC("websocket::stream::async_accept", wsb->ws.async_accept(bounded(h)), wsb.reset());
}
/* ltl: websocket_handshake_before_messages, websocket_write_buffer_before_handshake, websocket_status_after_handshake */
static void call_ws_async_accept_buffers(payload in) {
    if (!wsb) return;
    ASYNC("websocket::stream::async_accept(buffers)",
          wsb->ws.async_accept(net::buffer(text(in, 0).data(), text(in, 0).size()), h), wsb.reset());
}
/* ltl: websocket_handshake_before_messages, websocket_write_buffer_before_handshake, websocket_status_after_handshake */
static void call_ws_async_accept_request(payload) {
    if (!wsb) return;
    ASYNC("websocket::stream::async_accept(request)", wsb->ws.async_accept(req, bounded(h)), wsb.reset());
}
/* ltl: websocket_handshake_before_messages, websocket_write_buffer_before_handshake, websocket_status_after_handshake */
static void call_ws_async_handshake(payload in) {
    if (!wsb) return;
    beast::string_view host, target;
    split(in, 0, host, target);
    ASYNC("websocket::stream::async_handshake", wsb->ws.async_handshake(host, target, bounded(h)), wsb.reset());
}
/* ltl: websocket_handshake_before_messages, websocket_write_buffer_before_handshake, websocket_status_after_handshake */
static void call_ws_async_handshake_response(payload in) {
    if (!wsb) return;
    beast::string_view host, target;
    split(in, 0, host, target);
    ASYNC("websocket::stream::async_handshake(response)", wsb->ws.async_handshake(res, host, target, h), wsb.reset());
}
/* ltl: websocket_handshake_before_messages, websocket_frame_before_message_type */
static void call_ws_async_read(payload) {
    if (!wsb) return;
    ASYNC("websocket::stream::async_read", wsb->ws.async_read(ws_buf, bounded(h)), wsb.reset());
}
/* ltl: websocket_handshake_before_messages, websocket_frame_before_message_type */
static void call_ws_async_read_some(payload in) {
    if (!wsb) return;
    ASYNC("websocket::stream::async_read_some(buffer,limit)", wsb->ws.async_read_some(ws_buf, u16(in, 0), bounded(h)), wsb.reset());
}
/* ltl: websocket_handshake_before_messages, websocket_frame_before_message_type */
static void call_ws_async_read_some_buffers(payload in) {
    if (!wsb) return;
    static char out[4096];
    ASYNC("websocket::stream::async_read_some(buffers)",
          wsb->ws.async_read_some(net::buffer(out, 1 + u16(in, 0) % sizeof out), bounded(h)), wsb.reset());
}
/* ltl: websocket_handshake_before_messages */
static void call_ws_async_write(payload in) {
    if (!wsb) return;
    ASYNC("websocket::stream::async_write", wsb->ws.async_write(net::buffer(text(in, 0).data(), text(in, 0).size()), bounded(h)), wsb.reset());
}
/* ltl: websocket_handshake_before_messages */
static void call_ws_async_write_some(payload in) {
    if (!wsb) return;
    ASYNC("websocket::stream::async_write_some",
          wsb->ws.async_write_some(byte(in, 0) & 1, net::buffer(text(in, 1).data(), text(in, 1).size()), h), wsb.reset());
}
/* ltl: websocket_handshake_before_messages */
static void call_ws_async_ping(payload in) {
    if (!wsb) return;
    beast::string_view s = text(in, 0).substr(0, 125);
    websocket::ping_data pd;
    pd.assign(s.data(), s.size());
    ASYNC("websocket::stream::async_ping", wsb->ws.async_ping(pd, bounded(h)), wsb.reset());
}
/* ltl: websocket_handshake_before_messages */
static void call_ws_async_pong(payload in) {
    if (!wsb) return;
    beast::string_view s = text(in, 0).substr(0, 125);
    websocket::ping_data pd;
    pd.assign(s.data(), s.size());
    ASYNC("websocket::stream::async_pong", wsb->ws.async_pong(pd, h), wsb.reset());
}
/* ltl: websocket_handshake_before_messages */
static void call_ws_async_close(payload in) {
    if (!wsb) return;
    websocket::close_reason cr;
    cr.code = u16(in, 0);
    beast::string_view s = text(in, 2).substr(0, 123);
    cr.reason.assign(s.data(), s.size());
    ASYNC("websocket::stream::async_close", wsb->ws.async_close(cr, bounded(h)), wsb.reset());
}

/* ---------- core: stream layers over the in-memory transport ---------- */

static char stream_buf[4096];

/* the payload is the input, then end-of-file; writes go to `peer` */
struct brs_box {
    beast::test::stream peer{ioc};
    beast::buffered_read_stream<beast::test::stream, beast::flat_buffer> s;
    explicit brs_box(beast::string_view input) : s(ioc, input) {
        s.next_layer().connect(peer);
        s.next_layer().close_remote();
    }
};

static std::unique_ptr<brs_box> brs;

static void call_brs_ctor(payload in) { REPORT("buffered_read_stream", brs.reset(new brs_box(text(in, 0))), 1); }

/* octets placed in the read buffer are returned before the next layer is read */
static void call_brs_buffer(payload in) {
    if (brs) REPORT("buffered_read_stream::buffer", beast::ostream(brs->s.buffer()) << text(in, 0), 1);
}

static void call_brs_capacity(payload in) { if (brs) REPORT("buffered_read_stream::capacity", brs->s.capacity(u16(in, 0)), 1); }
static void call_brs_next_layer(payload) {
    if (brs) REPORT("buffered_read_stream::next_layer", size_t r = brs->s.next_layer().nread(); (void)r, 1);
}
static void call_brs_get_executor(payload) { if (brs) REPORT("buffered_read_stream::get_executor", auto e = brs->s.get_executor(); (void)e, 1); }

static void call_brs_read_some(payload in) {
    if (!brs) return;
    beast::error_code ec;
    REPORT("buffered_read_stream::read_some",
           size_t r = brs->s.read_some(net::buffer(stream_buf, 1 + u16(in, 0) % sizeof stream_buf), ec); (void)r, !ec);
}

static void call_brs_write_some(payload in) {
    if (!brs) return;
    beast::error_code ec;
    REPORT("buffered_read_stream::write_some",
           size_t r = brs->s.write_some(net::buffer(text(in, 0).data(), text(in, 0).size()), ec); (void)r, !ec);
}

static void call_brs_async_read_some(payload in) {
    if (!brs) return;
    ASYNC("buffered_read_stream::async_read_some",
          brs->s.async_read_some(net::buffer(stream_buf, 1 + u16(in, 0) % sizeof stream_buf), bounded(h)), brs.reset());
}

static void call_brs_async_write_some(payload in) {
    if (!brs) return;
    ASYNC("buffered_read_stream::async_write_some",
          brs->s.async_write_some(net::buffer(text(in, 0).data(), text(in, 0).size()), h), brs.reset());
}

/* takes over a new stream (unconnected, so its writes fail) holding the payload */
static void call_brs_assign(payload in) {
    if (!brs) return;
    beast::buffered_read_stream<beast::test::stream, beast::flat_buffer> t(ioc, text(in, 0));
    t.next_layer().close_remote();
    REPORT("buffered_read_stream::operator=", brs->s = std::move(t), 1);
}

struct fls_box {
    beast::test::stream peer{ioc};
    beast::flat_stream<beast::test::stream> s;
    explicit fls_box(beast::string_view input) : s(ioc, input) {
        s.next_layer().connect(peer);
        s.next_layer().close_remote();
    }
};

static std::unique_ptr<fls_box> fls;

/* two buffers (split at byte 0), so the flat_stream has a sequence to flatten */
static std::array<net::const_buffer, 2> two_buffers(payload in) {
    beast::string_view a, b;
    split(in, 0, a, b);
    return {{net::const_buffer(a.data(), a.size()), net::const_buffer(b.data(), b.size())}};
}

static void call_fls_ctor(payload in) { REPORT("flat_stream", fls.reset(new fls_box(text(in, 0))), 1); }
static void call_fls_next_layer(payload) { if (fls) REPORT("flat_stream::next_layer", size_t r = fls->s.next_layer().nwrite(); (void)r, 1); }
static void call_fls_get_executor(payload) { if (fls) REPORT("flat_stream::get_executor", auto e = fls->s.get_executor(); (void)e, 1); }

static void call_fls_read_some(payload in) {
    if (!fls) return;
    beast::error_code ec;
    REPORT("flat_stream::read_some",
           size_t r = fls->s.read_some(net::buffer(stream_buf, 1 + u16(in, 0) % sizeof stream_buf), ec); (void)r, !ec);
}

static void call_fls_write_some(payload in) {
    if (!fls) return;
    beast::error_code ec;
    REPORT("flat_stream::write_some", size_t r = fls->s.write_some(two_buffers(in), ec); (void)r, !ec);
}

static void call_fls_async_read_some(payload in) {
    if (!fls) return;
    ASYNC("flat_stream::async_read_some",
          fls->s.async_read_some(net::buffer(stream_buf, 1 + u16(in, 0) % sizeof stream_buf), h), fls.reset());
}

static void call_fls_async_write_some(payload in) {
    if (!fls) return;
    auto b = two_buffers(in);
    ASYNC("flat_stream::async_write_some", fls->s.async_write_some(b, bounded(h)), fls.reset());
}

static void call_fls_assign(payload in) {
    if (!fls) return;
    beast::flat_stream<beast::test::stream> t(ioc, text(in, 0));
    t.next_layer().close_remote();
    REPORT("flat_stream::operator=", fls->s = std::move(t), 1);
}

static beast::role_type role_of(payload in, size_t i) { return byte(in, i) & 1 ? beast::role_type::server : beast::role_type::client; }

/* teardown(flat_stream) tears down the next layer (impl/flat_stream.hpp:269) */
static void call_fls_teardown(payload in) {
    if (!fls) return;
    beast::error_code ec;
    REPORT("teardown(flat_stream)", beast::teardown(role_of(in, 0), fls->s, ec), !ec);
}

static void call_fls_async_teardown(payload in) {
    if (!fls) return;
    ASYNC("async_teardown(flat_stream)", beast::async_teardown(role_of(in, 0), fls->s, h), fls.reset());
}

/* ---------- core: completion handler utilities ---------- */

static size_t handler_calls;

/* a saved_handler completes a cancelled handler with operation_aborted (impl/saved_handler.hpp:180) */
struct count_handler {
    void operator()() const { ++handler_calls; }
    void operator()(beast::error_code) const { ++handler_calls; }
};

struct result_handler {
    void operator()(beast::error_code, std::size_t) const { ++handler_calls; }
};

/* cancellation_type is a bit mask of terminal, partial and total (asio/cancellation_type.hpp) */
static net::cancellation_type cancel_of(payload in, size_t i) { return static_cast<net::cancellation_type>(byte(in, i) % 8); }

/* post() asks the bound handler for its executor (associator specialization, detail/bind_handler.hpp:256) */
static void call_bind_handler(payload in) {
    REPORT("bind_handler", net::post(ioc, beast::bind_handler(result_handler{}, beast::error_code{}, (size_t)u16(in, 0))); poll(), 1);
}

static void call_bind_front_handler(payload in) {
    REPORT("bind_front_handler", net::post(ioc, beast::bind_front_handler(result_handler{}, beast::error_code{}, (size_t)u16(in, 0))); poll(), 1);
}

static beast::saved_handler sh;
/* ltl: saved_handler_value */
static void call_sh_emplace(payload in) { REPORT("saved_handler::emplace", sh.emplace(count_handler{}, cancel_of(in, 0)), 1); }
/* ltl: saved_handler_value */
static void call_sh_emplace_alloc(payload in) {
    REPORT("saved_handler::emplace(alloc)", sh.emplace(count_handler{}, std::allocator<char>{}, cancel_of(in, 0)), 1);
}
static void call_sh_has_value(payload) { REPORT("saved_handler::has_value", bool r = sh.has_value(), r); }
/* ltl: saved_handler_value */
static void call_sh_reset(payload) { REPORT("saved_handler::reset", bool r = sh.reset(), r); }
/* ltl: saved_handler_value */
static void call_sh_invoke(payload) { REPORT("saved_handler::invoke", sh.invoke(), 1); }
/* ltl: saved_handler_value */
static void call_sh_maybe_invoke(payload) { REPORT("saved_handler::maybe_invoke", bool r = sh.maybe_invoke(), r); }

/* moves the handler out into a temporary, which destroys it */
/* ltl: saved_handler_value */
static void call_sh_move(payload) { REPORT("saved_handler::saved_handler", beast::saved_handler t(std::move(sh)), 1); }

/* takes over a newly stored handler */
/* ltl: saved_handler_value */
static void call_sh_assign(payload in) {
    beast::saved_handler t;
    t.emplace(count_handler{}, cancel_of(in, 0));
    REPORT("saved_handler::operator=", sh = std::move(t), 1);
}

using ab_type = beast::async_base<count_handler, net::io_context::executor_type>;
using sab_type = beast::stable_async_base<count_handler, net::io_context::executor_type>;
static std::optional<ab_type> ab;
static std::optional<sab_type> sab;
/* ltl: async_base_complete_once */
static void call_ab_ctor(payload) { REPORT("async_base", ab.emplace(count_handler{}, ioc.get_executor()), 1); }
/* ltl: async_base_complete_once */
static void call_ab_get_allocator(payload) { if (ab) REPORT("async_base::get_allocator", auto a = ab->get_allocator(); (void)a, 1); }
/* ltl: async_base_complete_once */
static void call_ab_get_executor(payload) { if (ab) REPORT("async_base::get_executor", auto e = ab->get_executor(); (void)e, 1); }
/* ltl: async_base_complete_once */
static void call_ab_get_immediate_executor(payload) {
    if (ab) REPORT("async_base::get_immediate_executor", auto e = ab->get_immediate_executor(); (void)e, 1);
}
/* ltl: async_base_complete_once */
static void call_ab_get_cancellation_slot(payload) {
    if (ab) REPORT("async_base::get_cancellation_slot", auto s = ab->get_cancellation_slot(); bool r = s.is_connected(), r);
}
/* ltl: async_base_complete_once */
static void call_ab_set_allowed_cancellation(payload in) {
    if (ab) REPORT("async_base::set_allowed_cancellation", ab->set_allowed_cancellation(cancel_of(in, 0)), 1);
}
/* ltl: async_base_complete_once */
static void call_ab_handler(payload) { if (ab) REPORT("async_base::handler", count_handler const &r = ab->handler(); (void)r, 1); }
/* ltl: async_base_complete_once */
static void call_ab_is_continuation(payload) {
    if (ab) REPORT("asio_handler_is_continuation", bool r = beast::asio_handler_is_continuation(&*ab), r);
}
/* ltl: async_base_complete_once */
static void call_ab_release_handler(payload) { if (ab) REPORT("async_base::release_handler", count_handler r = ab->release_handler(); r(), 1); }
/* complete(false) dispatches to the executor, so the poll runs the handler */
/* ltl: async_base_complete_once */
static void call_ab_complete(payload in) { if (ab) REPORT("async_base::complete", ab->complete(byte(in, 0) & 1); poll(), 1); }
/* ltl: async_base_complete_once */
static void call_ab_complete_now(payload) { if (ab) REPORT("async_base::complete_now", ab->complete_now(), 1); }
/* ltl: stable_async_base_complete_once */
static void call_sab_ctor(payload) { REPORT("stable_async_base", sab.emplace(count_handler{}, ioc.get_executor()), 1); }
/* the state lives until the handler is invoked (async_base.hpp:740) */
static void call_sab_allocate_stable(payload in) {
    if (sab) REPORT("allocate_stable", std::string &s = beast::allocate_stable<std::string>(*sab, text(in, 0)); (void)s, 1);
}
/* ltl: stable_async_base_complete_once */
static void call_sab_complete(payload in) { if (sab) REPORT("stable_async_base::complete", sab->complete(byte(in, 0) & 1); poll(), 1); }
/* ltl: stable_async_base_complete_once */
static void call_sab_complete_now(payload) { if (sab) REPORT("stable_async_base::complete_now", sab->complete_now(), 1); }

/* ---------- core: basic_stream over a connected local socket pair ---------- */

using local = net::local::stream_protocol;
using bstream = beast::basic_stream<local, net::any_io_executor, beast::simple_rate_policy>;

/* What the pending operations use lives here, held by the box and by their handlers. One read and one write may be
 * pending at a time (basic_stream.hpp, "no other calls to async_read_some"); connect uses both. */
struct bs_shared {
    bool reading = false, writing = false;
    std::string wdata;
    char rdata[4096];
};

/* the stream's peer sent the payload and then shut down its sending side, so reads end with eof and never block;
 * the peer is drained after each write */
struct bs_box {
    local::socket peer{ioc};
    std::optional<bstream> s;
    std::shared_ptr<bs_shared> st = std::make_shared<bs_shared>();
    bs_box(beast::string_view input, bool with_policy) {
        local::socket a{ioc};
        net::local::connect_pair(a, peer);
        if (with_policy)
            s.emplace(beast::simple_rate_policy{}, std::move(a));
        else
            s.emplace(std::move(a));
        net::write(peer, net::buffer(input.data(), input.size()));
        attach(std::move(peer));
    }
    void attach(local::socket p) {
        peer = std::move(p);
        peer.shutdown(local::socket::shutdown_send);
        peer.non_blocking(true);
    }
    void drain() {
        beast::error_code ec;
        while (peer.is_open() && peer.read_some(net::buffer(stream_buf), ec) > 0) {}
    }
    bool idle() const { return !st->reading && !st->writing; }
};

static std::unique_ptr<bs_box> bs;

/* an abstract-namespace listener (no file system entry) for connect; one per process */
static local::acceptor *listener() {
    static std::unique_ptr<local::acceptor> a;
    if (!a) {
        try {
            a.reset(new local::acceptor(ioc, local::endpoint(std::string(1, '\0') + "beast-fuzz-" + std::to_string(getpid()))));
        } catch (const std::exception &) { return nullptr; }
    }
    return a.get();
}

/* after a successful connect the accepted socket becomes the peer; without one a read could block, so the stream
 * is closed */
static void accept_peer() {
    beast::error_code ec;
    local::socket p{ioc};
    listener()->accept(p, ec);
    if (!ec)
        bs->attach(std::move(p));
    else
        bs->s->close();
}

static void call_bs_ctor(payload in) { TRY("basic_stream", bs.reset(new bs_box(text(in, 1), byte(in, 0) & 1)), 1); }
static void call_bs_socket(payload) { if (bs) REPORT("basic_stream::socket", bool r = bs->s->socket().is_open(), r); }
/* outstanding operations are canceled (basic_stream.hpp:429); the stream is left without a socket */
static void call_bs_release_socket(payload) { if (bs) REPORT("basic_stream::release_socket", local::socket so = bs->s->release_socket(); poll(), 1); }
static void call_bs_rate_policy(payload) { if (bs) REPORT("basic_stream::rate_policy", beast::simple_rate_policy &p = bs->s->rate_policy(); (void)p, 1); }
static void call_bs_read_limit(payload in) { if (bs) REPORT("simple_rate_policy::read_limit", bs->s->rate_policy().read_limit(1 + u16(in, 0)), 1); }
static void call_bs_write_limit(payload in) { if (bs) REPORT("simple_rate_policy::write_limit", bs->s->rate_policy().write_limit(1 + u16(in, 0)), 1); }
static void call_bs_expires_after(payload in) {
    if (bs) REPORT("basic_stream::expires_after", bs->s->expires_after(std::chrono::milliseconds(byte(in, 0) % 3)), 1);
}
static void call_bs_expires_at(payload in) {
    if (bs) REPORT("basic_stream::expires_at",
                   bs->s->expires_at(net::steady_timer::clock_type::now() + std::chrono::milliseconds(byte(in, 0) % 3)), 1);
}
static void call_bs_expires_never(payload) { if (bs) REPORT("basic_stream::expires_never", bs->s->expires_never(), 1); }
static void call_bs_cancel(payload) { if (bs) REPORT("basic_stream::cancel", bs->s->cancel(); poll(), 1); }
static void call_bs_close(payload) { if (bs) REPORT("basic_stream::close", bs->s->close(); poll(), 1); }
static void call_bs_get_executor(payload) { if (bs) REPORT("basic_stream::get_executor", auto e = bs->s->get_executor(); (void)e, 1); }
static void call_bs_close_socket(payload) { if (bs) REPORT("beast_close_socket", beast::beast_close_socket(*bs->s); poll(), 1); }

static void call_bs_read_some(payload in) {
    if (!bs || bs->st->reading) return;
    beast::error_code ec;
    REPORT("basic_stream::read_some", size_t r = bs->s->read_some(net::buffer(stream_buf, 1 + u16(in, 0) % sizeof stream_buf), ec); (void)r, !ec);
}

static void call_bs_write_some(payload in) {
    if (!bs || bs->st->writing) return;
    beast::error_code ec;
    REPORT("basic_stream::write_some", size_t r = bs->s->write_some(net::buffer(text(in, 0).data(), text(in, 0).size()), ec); bs->drain(), !ec);
}

/* a rate-limited or timed operation may still be pending; it stays with the stream and its flag clears on completion */
static void call_bs_async_read_some(payload in) {
    if (!bs || bs->st->reading || !preqed_call("basic_stream::async_read_some")) return;
    auto st = bs->st;
    auto c = std::make_shared<completion>();
    st->reading = true;
    bs->s->async_read_some(net::buffer(st->rdata, 1 + u16(in, 0) % sizeof st->rdata),
                           bounded([st, c](beast::error_code ec, size_t) { st->reading = false; c->done = true; c->ec = ec; }));
    poll();
    preqed_result("basic_stream::async_read_some", c->done && !c->ec);
}

static void call_bs_async_write_some(payload in) {
    if (!bs || bs->st->writing || !preqed_call("basic_stream::async_write_some")) return;
    auto st = bs->st;
    auto c = std::make_shared<completion>();
    st->writing = true;
    st->wdata.assign(text(in, 0).data(), text(in, 0).size());
    bs->s->async_write_some(net::buffer(st->wdata),
                            bounded([st, c](beast::error_code ec, size_t) { st->writing = false; c->done = true; c->ec = ec; }));
    poll();
    bs->drain();
    preqed_result("basic_stream::async_write_some", c->done && !c->ec);
}

/* connect needs no pending operation (it uses both); bit 0-1 of byte 0 pick endpoint, endpoint sequence or iterators */
static void call_bs_connect(payload in) {
    if (!bs || !bs->idle() || !listener()) return;
    std::vector<local::endpoint> eps{listener()->local_endpoint()};
    beast::error_code ec;
    bool ran = false;
    switch (byte(in, 0) % 3) {
    case 0: REPORT("basic_stream::connect", bs->s->connect(eps[0], ec); ran = true, !ec); break;
    case 1: REPORT("basic_stream::connect(endpoints)", bs->s->connect(eps, ec); ran = true, !ec); break;
    default: REPORT("basic_stream::connect(iterators)", bs->s->connect(eps.begin(), eps.end(), ec); ran = true, !ec); break;
    }
    if (ran && !ec) accept_peer();
}

static void call_bs_async_connect(payload in) {
    if (!bs || !bs->idle() || !listener()) return;
    const char *api = byte(in, 0) % 3 == 0 ? "basic_stream::async_connect" :
                      byte(in, 0) % 3 == 1 ? "basic_stream::async_connect(endpoints)" : "basic_stream::async_connect(iterators)";
    if (!preqed_call(api)) return;
    auto eps = std::make_shared<std::vector<local::endpoint>>(1, listener()->local_endpoint());
    auto st = bs->st;
    auto c = std::make_shared<completion>();
    auto h = [st, c, eps](beast::error_code ec, auto &&...) { st->reading = st->writing = false; c->done = true; c->ec = ec; };
    st->reading = st->writing = true;
    switch (byte(in, 0) % 3) {
    case 0: bs->s->async_connect((*eps)[0], bounded(h)); break;
    case 1: bs->s->async_connect(*eps, bounded(h)); break;
    default: bs->s->async_connect(eps->begin(), eps->end(), bounded(h)); break;
    }
    poll();
    if (c->done && !c->ec) accept_peer();
    preqed_result(api, c->done && !c->ec);
}

/* teardown(basic_stream) shuts the socket down and reads to end-of-file (websocket::teardown, impl/basic_stream.hpp:1095) */
static void call_bs_teardown(payload in) {
    if (!bs || !bs->idle()) return;
    beast::error_code ec;
    REPORT("teardown(basic_stream)", beast::teardown(role_of(in, 0), *bs->s, ec), !ec);
}

static void call_bs_async_teardown(payload in) {
    if (!bs || !bs->idle()) return;
    ASYNC("async_teardown(basic_stream)", beast::async_teardown(role_of(in, 0), *bs->s, h), bs->s->close());
}

static void call_ws_seed_prng(payload in) {
    std::vector<uint32_t> words;
    for (size_t i = 0; i + 4 <= in.n; i += 4) words.push_back(u32(in, i));
    std::seed_seq ss(words.begin(), words.end());
    REPORT("websocket::seed_prng", websocket::seed_prng(ss), 1);
}

/* ---------- dispatch ---------- */

#define DYNBUF_ENTRIES(B) call_##B##_prepare, call_##B##_commit, call_##B##_consume, call_##B##_size, \
    call_##B##_capacity, call_##B##_max_size, call_##B##_clear, call_##B##_data, call_##B##_cdata
#define GROWABLE_ENTRIES(B) call_##B##_reserve, call_##B##_shrink_to_fit, call_##B##_set_max_size, \
    call_##B##_get_allocator, call_##B##_swap
#define MESSAGE_ENTRIES(M) call_##M##_version, call_##M##_version_get, call_##M##_chunked, call_##M##_chunked_get, \
    call_##M##_keep_alive, call_##M##_keep_alive_get, call_##M##_content_length, call_##M##_has_content_length, \
    call_##M##_need_eof, call_##M##_payload_size, call_##M##_prepare_payload, call_##M##_body
#define PARSER_ENTRIES(P) call_##P##_ctor, call_##P##_put, call_##P##_put_eof, call_##P##_is_done, \
    call_##P##_is_header_done, call_##P##_got_some, call_##P##_upgrade, call_##P##_chunked, call_##P##_keep_alive, \
    call_##P##_content_length, call_##P##_content_length_remaining, call_##P##_need_eof, call_##P##_body_limit, \
    call_##P##_header_limit, call_##P##_eager, call_##P##_eager_get, call_##P##_skip, call_##P##_skip_get, \
    call_##P##_get, call_##P##_release, call_##P##_on_chunk_header, call_##P##_on_chunk_body, \
    call_##P##_merge_all_trailers, call_##P##_merge_all_trailers_get, call_##P##_read, call_##P##_read_header, \
    call_##P##_read_some, call_##P##_async_read, call_##P##_async_read_header, call_##P##_async_read_some
#define SERIALIZER_ENTRIES(S) call_##S##_ctor, call_##S##_next, call_##S##_consume, call_##S##_is_done, \
    call_##S##_is_header_done, call_##S##_split, call_##S##_split_get, call_##S##_limit, call_##S##_limit_get, \
    call_##S##_get, call_##S##_write, call_##S##_write_header, call_##S##_write_some, call_##S##_async_write, \
    call_##S##_async_write_header, call_##S##_async_write_some
#define FILE_ENTRIES(F) call_##F##_open, call_##F##_close, call_##F##_is_open, call_##F##_size, call_##F##_pos, \
    call_##F##_seek, call_##F##_read, call_##F##_write, call_##F##_native_handle, call_##F##_move, call_##F##_assign
#define WS_FLAG_ENTRIES(FN) call_ws_##FN, call_ws_##FN##_get

static void (*const api[])(payload) = {
    call_iequals, call_iless,
    DYNBUF_ENTRIES(fb), GROWABLE_ENTRIES(fb), DYNBUF_ENTRIES(mb), GROWABLE_ENTRIES(mb), DYNBUF_ENTRIES(sb), DYNBUF_ENTRIES(fsb),
    call_buffers_to_string, call_buffer_bytes, call_buffers_prefix, call_buffers_suffix, call_buffers_cat,
    call_buffers_front, call_buffers_range, call_ostream, call_make_printable, call_read_size, call_read_size_or_throw,
    call_detect_ssl,
    call_string_to_verb, call_to_string_verb, call_int_to_status, call_to_status_class_int, call_to_status_class,
    call_obsolete_reason, call_string_to_field, call_to_string_field,
    call_param_list, call_ext_list, call_ext_list_find, call_ext_list_exists, call_token_list, call_token_list_exists,
    call_opt_token_list, call_validate_list,
    call_chunk_extensions_parse, call_chunk_extensions_insert, call_chunk_extensions_insert_value,
    call_chunk_extensions_str, call_chunk_extensions_clear, call_chunk_extensions_begin,
    call_chunk_header, call_chunk_header_ext, call_chunk_body, call_chunk_body_ext, call_chunk_crlf, call_make_chunk,
    call_make_chunk_last, call_make_chunk_last_trailer,
    call_request, call_response,
    call_request_method, call_request_method_get, call_request_method_string, call_request_method_string_get,
    call_request_target, call_request_target_get,
    call_response_result, call_response_result_int, call_response_result_get, call_response_result_int_get,
    call_response_reason, call_response_reason_get,
    MESSAGE_ENTRIES(req), MESSAGE_ENTRIES(res),
    call_fields_at, call_fields_at_name, call_fields_index, call_fields_index_name, call_fields_insert,
    call_fields_insert_name, call_fields_insert_ec, call_fields_set, call_fields_set_name, call_fields_erase,
    call_fields_erase_name, call_fields_erase_iterator, call_fields_clear, call_fields_contains,
    call_fields_contains_name, call_fields_count, call_fields_count_name, call_fields_find, call_fields_find_name,
    call_fields_equal_range, call_fields_equal_range_name, call_fields_begin, call_fields_swap,
    call_ostream_request, call_ostream_response, call_is_upgrade,
    PARSER_ENTRIES(rqp), PARSER_ENTRIES(rsp), call_read_request, call_read_response,
    SERIALIZER_ENTRIES(rqs), SERIALIZER_ENTRIES(rss), call_write_request, call_write_response,
    call_message_generator, call_message_generator_prepare, call_message_generator_consume,
    call_message_generator_is_done, call_message_generator_keep_alive, call_write_generator,
    call_deflate_reset_params, call_deflate_reset, call_deflate_clear, call_deflate_upper_bound,
    call_deflate_upper_bound_free, call_deflate_tune, call_deflate_write, call_deflate_params, call_deflate_pending,
    call_deflate_prime, call_inflate_reset_bits, call_inflate_reset, call_inflate_clear, call_inflate_write,
    call_ws_stream, call_ws_set_option_pmd, call_ws_get_option_pmd, call_ws_get_status, call_ws_set_option_decorator,
    WS_FLAG_ENTRIES(auto_fragment), WS_FLAG_ENTRIES(binary), WS_FLAG_ENTRIES(text), WS_FLAG_ENTRIES(compress),
    call_ws_read_message_max, call_ws_read_message_max_get, call_ws_write_buffer_bytes, call_ws_write_buffer_bytes_get,
    call_ws_secure_prng, call_ws_is_open, call_ws_got_text, call_ws_got_binary, call_ws_is_message_done,
    call_ws_reason, call_ws_read_size_hint, call_ws_read_size_hint_buffer, call_ws_control_callback,
    call_ws_control_callback_reset, call_ws_accept, call_ws_accept_buffers, call_ws_accept_request, call_ws_handshake,
    call_ws_handshake_response, call_ws_read, call_ws_read_some, call_ws_read_some_buffers, call_ws_write,
    call_ws_write_some, call_ws_ping, call_ws_pong, call_ws_close, call_ws_seed_prng,
    call_sb_base, call_fsb_base, call_sb_assign, call_fsb_assign, call_mb_subrange_assign, call_buffers_prefix_assign,
    call_buffers_suffix_assign, call_buffers_cat_assign, call_iequal, call_make_error_condition,
    call_ws_make_error_condition,
    call_ba_ctor, call_ba_prepare, call_ba_commit, call_ba_consume, call_ba_size, call_ba_max_size, call_ba_capacity,
    call_ba_value, call_ba_data, call_ba_cdata, call_ba_assign,
    call_async_detect_ssl, call_param_list_cbegin, call_ext_list_cbegin, call_token_list_cbegin,
    call_chunk_extensions_iterator, call_fields_cbegin, call_fields_key_comp, call_fields_get_allocator, call_http_swap,
    call_async_read_request, call_async_read_response, call_async_write_request, call_async_write_response,
    call_read_vector_body, call_write_vector_body, call_read_span_body, call_write_span_body, call_read_buffer_body,
    call_write_buffer_body, call_read_empty_body, call_write_empty_body, call_read_dynamic_body,
    call_write_dynamic_body, call_read_file_body, call_write_file_body,
    FILE_ENTRIES(fposix), FILE_ENTRIES(fstdio), call_fposix_set_native_handle, call_fstdio_set_native_handle,
    call_fbody_open, call_fbody_close, call_fbody_is_open, call_fbody_size, call_fbody_file, call_fbody_reset,
    call_fbody_seek, call_fbody_assign, call_async_write_generator,
    call_ws_set_option_timeout, call_ws_get_option_timeout, call_ws_get_executor, call_get_lowest_layer,
    call_close_reason_bool, call_ws_async_accept, call_ws_async_accept_buffers, call_ws_async_accept_request,
    call_ws_async_handshake, call_ws_async_handshake_response, call_ws_async_read, call_ws_async_read_some,
    call_ws_async_read_some_buffers, call_ws_async_write, call_ws_async_write_some, call_ws_async_ping,
    call_ws_async_pong, call_ws_async_close,
    call_brs_ctor, call_brs_buffer, call_brs_capacity, call_brs_next_layer, call_brs_get_executor, call_brs_read_some,
    call_brs_write_some, call_brs_async_read_some, call_brs_async_write_some, call_brs_assign,
    call_fls_ctor, call_fls_next_layer, call_fls_get_executor, call_fls_read_some, call_fls_write_some,
    call_fls_async_read_some, call_fls_async_write_some, call_fls_assign, call_fls_teardown, call_fls_async_teardown,
    call_bind_handler, call_bind_front_handler,
    call_sh_emplace, call_sh_emplace_alloc, call_sh_has_value, call_sh_reset, call_sh_invoke, call_sh_maybe_invoke,
    call_sh_move, call_sh_assign,
    call_ab_ctor, call_ab_get_allocator, call_ab_get_executor, call_ab_get_immediate_executor,
    call_ab_get_cancellation_slot, call_ab_set_allowed_cancellation, call_ab_handler, call_ab_is_continuation,
    call_ab_release_handler, call_ab_complete, call_ab_complete_now,
    call_sab_ctor, call_sab_allocate_stable, call_sab_complete, call_sab_complete_now,
    call_bs_ctor, call_bs_socket, call_bs_release_socket, call_bs_rate_policy, call_bs_read_limit, call_bs_write_limit,
    call_bs_expires_after, call_bs_expires_at, call_bs_expires_never, call_bs_cancel, call_bs_close,
    call_bs_get_executor, call_bs_close_socket, call_bs_read_some, call_bs_write_some, call_bs_async_read_some,
    call_bs_async_write_some, call_bs_connect, call_bs_async_connect, call_bs_teardown, call_bs_async_teardown,
};
#define API_COUNT (sizeof api / sizeof api[0])

/* objects that pending operations use go first; the poll then completes those operations as cancelled */
static void cleanup() {
    bs.reset();
    brs.reset();
    fls.reset();
    ab.reset();
    sab.reset();
    sh.reset();
    ba.reset();
    beast::error_code fec;
    fposix.close(fec);
    fstdio.close(fec);
    fbody.close();
    if (ftruncate(memfd(), 0) != 0) { /* no in-memory file */ }
    wsb.reset();
    ws_buf.clear();
    gen.reset();
    rqs.reset();
    rss.reset();
    rqp.reset();
    rsp.reset();
    io_buf = beast::flat_buffer();
    req = {};
    res = {};
    beast::error_code ec;
    exts.parse("", ec);                                 /* clear() keeps the iteration index (see exts_partial) */
    exts_partial = false;
    fb = beast::flat_buffer();
    mb = beast::multi_buffer();
    sb.clear();
    fsb.clear();
    deflater.reset(6, 15, 8, zlib::Strategy::normal);    /* the default constructor's settings (deflate_stream.hpp:82) */
    deflater.clear();
    inflater.clear();
    dz = {};
    iz = {};
    poll();
}

/* record: u16 opcode (more than 256 wrappers), u16 payload length, payload; all little-endian */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    preqed_reset();
    size_t off = 0;
    while (size - off >= 4) {
        size_t op = (size_t)data[off] | (size_t)data[off + 1] << 8;
        size_t len = (size_t)data[off + 2] | (size_t)data[off + 3] << 8;
        off += 4;
        if (len > size - off) break;
        api[op % API_COUNT](payload{data + off, len});
        off += len;
    }
    cleanup();
    return 0;
}
