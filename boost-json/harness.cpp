#include <boost/json.hpp>
#include <boost/json/src.hpp>
#include <boost/json/basic_parser_impl.hpp>
#include "preqed_ltl.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iterator>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <system_error>
#include <tuple>
#include <vector>

namespace json = boost::json;

/* Boost.JSON's own SAX handler from the project fuzzer: it accepts every event. */
struct event_handler {
    static constexpr std::size_t max_object_size = std::size_t(-1);
    static constexpr std::size_t max_array_size = std::size_t(-1);
    static constexpr std::size_t max_key_size = std::size_t(-1);
    static constexpr std::size_t max_string_size = std::size_t(-1);
    std::size_t events = 0;
    bool on_document_begin(boost::system::error_code &) { ++events; return true; }
    bool on_document_end(boost::system::error_code &) { ++events; return true; }
    bool on_object_begin(boost::system::error_code &) { ++events; return true; }
    bool on_object_end(std::size_t, boost::system::error_code &) { ++events; return true; }
    bool on_array_begin(boost::system::error_code &) { ++events; return true; }
    bool on_array_end(std::size_t, boost::system::error_code &) { ++events; return true; }
    bool on_key_part(json::string_view, std::size_t, boost::system::error_code &) { ++events; return true; }
    bool on_key(json::string_view, std::size_t, boost::system::error_code &) { ++events; return true; }
    bool on_string_part(json::string_view, std::size_t, boost::system::error_code &) { ++events; return true; }
    bool on_string(json::string_view, std::size_t, boost::system::error_code &) { ++events; return true; }
    bool on_number_part(json::string_view, boost::system::error_code &) { ++events; return true; }
    bool on_int64(std::int64_t, json::string_view, boost::system::error_code &) { ++events; return true; }
    bool on_uint64(std::uint64_t, json::string_view, boost::system::error_code &) { ++events; return true; }
    bool on_double(double, json::string_view, boost::system::error_code &) { ++events; return true; }
    bool on_bool(bool, boost::system::error_code &) { ++events; return true; }
    bool on_null(boost::system::error_code &) { ++events; return true; }
    bool on_comment_part(json::string_view, boost::system::error_code &) { ++events; return true; }
    bool on_comment(json::string_view, boost::system::error_code &) { ++events; return true; }
};

struct payload {
    const uint8_t *p;
    size_t n;
};

/* one live instance per stateful object, created and reset by records */
static json::value current;                             /* the document most calls read or rewrite */
static bool have;
static json::value spare;                               /* the previous document: second operand of swap and ==, != */
static std::string text_out;                            /* last serialize / serializer output */
static std::vector<std::int64_t> numbers;               /* last typed vector */
static std::unique_ptr<json::stream_parser> stream;
static bool stream_seen;                                /* input consumed since ctor/reset */
static bool stream_released;                            /* value taken; reset() is required next */
static bool stream_comment_tail;                        /* last buffer ended where a comment can end */
static std::unique_ptr<json::parser> buffer;
static bool buffer_complete;                            /* last write parsed a whole text */
static std::unique_ptr<json::serializer> writer;
static bool writer_bound;                               /* serializer holds a pointer into current */
static std::unique_ptr<json::basic_parser<event_handler>> events;
static bool events_done;
static std::unique_ptr<json::monotonic_resource> monotonic;
static std::unique_ptr<json::static_resource> fixed;
static std::vector<unsigned char> fixed_buf;

static uint8_t byte(payload in, size_t i) { return i < in.n ? in.p[i] : 0; }

static json::string_view text(payload in, size_t skip) {
    if (skip >= in.n) return json::string_view();
    return json::string_view(reinterpret_cast<const char *>(in.p + skip), in.n - skip);
}

static std::string string_of(payload in, size_t skip) {
    json::string_view s = text(in, skip);
    return s.empty() ? std::string() : std::string(s.data(), s.size());
}

/* first byte k, then a key of k bytes, then the rest */
static bool split(payload in, json::string_view &key, json::string_view &rest) {
    size_t k = byte(in, 0);
    if (in.n < 1 || k > in.n - 1) return false;
    key = json::string_view(reinterpret_cast<const char *>(in.p + 1), k);
    rest = json::string_view(reinterpret_cast<const char *>(in.p + 1 + k), in.n - 1 - k);
    return true;
}

/* one payload bit per parse_options switch (boost/json/parse_options.hpp); max_depth 1..256 */
static json::parse_options options(uint8_t flags, uint8_t depth) {
    json::parse_options o;
    o.allow_comments = (flags & 1) != 0;
    o.allow_trailing_commas = (flags & 2) != 0;
    o.allow_invalid_utf8 = (flags & 4) != 0;
    o.allow_invalid_utf16 = (flags & 8) != 0;
    o.allow_infinity_and_nan = (flags & 16) != 0;
    o.numbers = static_cast<json::number_precision>((flags >> 5) % 2);  /* none needs a custom handler */
    o.max_depth = 1 + depth;
    return o;
}

/* memory resources: the value is copied out to the default resource before the next record */
static json::storage_ptr storage(uint8_t flags, size_t n) {
    switch (flags % 4) {
    case 1:
        monotonic.reset(new json::monotonic_resource(256 + n * 16));  /* initial block grows with the input */
        return json::storage_ptr(monotonic.get());
    case 2:
        fixed.reset();
        fixed_buf.resize(256 + n * 16);  /* may be too small: static_resource then throws bad_alloc, a documented error */
        fixed.reset(new json::static_resource(fixed_buf.data(), fixed_buf.size()));
        return json::storage_ptr(fixed.get());
    case 3:
        return json::storage_ptr(json::get_null_resource());
    default:
        return json::storage_ptr();
    }
}

#define REPORT(api, stmt, ok_cond) \
    do { if (preqed_call(api)) { stmt; preqed_result(api, (ok_cond)); } } while (0)

/* Boost.JSON reports malformed input by throwing system_error; a throw is a failed call */
#define TRY(api, stmt, ok_cond) \
    do { \
        if (!preqed_call(api)) return; \
        bool ok_ = false; \
        try { stmt; ok_ = (ok_cond); } catch (const std::exception &) {} \
        preqed_result(api, ok_); \
    } while (0)

/* serializer::reset points at &current and keeps sub-element pointers in its own stack, so the value
 * must outlive the walk (serializer.hpp:157); only done() ends the walk */
static bool can_replace() { return !writer || !writer_bound || writer->done(); }

static void take(json::value v) {
    spare = std::move(current);
    current = json::value(std::move(v), {});
    have = true;
}

/* parsing */
/* ltl: serializer_value_lifetime */
static void call_parse(payload in) {
    if (!can_replace()) return;
    json::string_view s = (byte(in, 0) & 1) && !text_out.empty() ? json::string_view(text_out) : text(in, 2);
    std::error_code ec;
    TRY("parse", json::value v = json::parse(s, ec, json::storage_ptr(), options(byte(in, 0), byte(in, 1)));
        if (!ec) take(std::move(v)), !ec);
}
/* ltl: serializer_value_lifetime */
static void call_parse_istream(payload in) {
    if (!can_replace()) return;
    std::istringstream is((byte(in, 0) & 1) && !text_out.empty() ? text_out : string_of(in, 0));
    std::error_code ec;
    TRY("parse(istream)", json::value v = json::parse(is, ec); if (!ec) take(std::move(v)), !ec);
}
/* ltl: serializer_value_lifetime */
static void call_parse_storage(payload in) {
    if (!can_replace()) return;
    json::string_view s = text(in, 2);
    std::error_code ec;
    TRY("parse(storage_ptr)",
        json::value v = json::parse(s, ec, storage(byte(in, 0), in.n), options(byte(in, 1), 0));
        if (!ec) take(std::move(v)), !ec);
}

/* stream_parser */
/* ltl: stream_parser_release_lifecycle */
static void call_stream_parser(payload in) {
    json::parse_options opt = options(byte(in, 0), byte(in, 1));
    if (!preqed_call("stream_parser")) return;
    stream.reset(new json::stream_parser({}, opt));
    stream_seen = false;
    stream_released = false;
    stream_comment_tail = false;
    preqed_result("stream_parser", true);
}
/* ltl: stream_parser_release_lifecycle */
static void call_stream_parser_reset(payload) {
    if (!stream) return;
    TRY("stream_parser::reset", stream->reset(), true);
    stream_seen = false;
    stream_released = false;
    stream_comment_tail = false;
}

/* basic_parser_impl.hpp:782 resumes a comment that ended exactly at the end of the previous buffer and
 * calls parse_value() on the empty segment, dereferencing the null data pointer (:632); so no empty
 * segment reaches a streaming parser, and finish() is skipped when a comment can just have ended. */
/* ltl: stream_parser_release_lifecycle */
static void call_stream_parser_write(payload in) {
    if (!stream || stream_released || stream->done() || in.n == 0) return;
    std::error_code ec;
    TRY("stream_parser::write", std::size_t n = stream->write(text(in, 0), ec); if (n) { stream_seen = true; }, !ec);
    stream_comment_tail = in.p[in.n - 1] == '\n' || in.p[in.n - 1] == '/';
}
/* ltl: stream_parser_release_lifecycle */
static void call_stream_parser_write_some(payload in) {
    if (!stream || stream_released || stream->done() || in.n == 0) return;
    std::error_code ec;
    TRY("stream_parser::write_some", std::size_t n = stream->write_some(text(in, 0), ec); if (n) { stream_seen = true; }, !ec);
    stream_comment_tail = in.p[in.n - 1] == '\n' || in.p[in.n - 1] == '/';
}
/* ltl: stream_parser_release_lifecycle */
static void call_stream_parser_finish(payload) {
    if (!stream || stream_released || stream->done() || stream_comment_tail) return;
    std::error_code ec;
    TRY("stream_parser::finish", stream->finish(ec), !ec);
}
/* ltl: stream_parser_release_lifecycle */
static void call_stream_parser_done(payload) {
    if (!stream) return;
    if (!preqed_call("stream_parser::done")) return;
    bool done = stream->done();
    preqed_result("stream_parser::done", done);
}
/* ltl: stream_parser_release_lifecycle, serializer_value_lifetime */
static void call_stream_parser_release(payload) {
    if (!stream || stream_released || !stream_seen || !can_replace()) return;
    if (!preqed_call("stream_parser::done")) return;
    bool done = stream->done();
    preqed_result("stream_parser::done", done);
    if (!done) return;
    /* release() consumes the value; a second call without reset() trips value_stack.ipp:348
     * (stream_parser.hpp:622: "necessary to call reset after calling this function") */
    if (!preqed_call("stream_parser::release")) return;
    bool ok = true;
    try { take(stream->release()); } catch (const std::exception &) { ok = false; }
    preqed_result("stream_parser::release", ok);
    stream_released = true;
    stream_seen = false;
}

/* parser */
/* ltl: parser_release_lifecycle */
static void call_parser(payload in) {
    json::parse_options opt = options(byte(in, 0), byte(in, 1));
    if (!preqed_call("parser")) return;
    buffer.reset(new json::parser({}, opt));
    buffer_complete = false;
    preqed_result("parser", true);
}
/* ltl: parser_release_lifecycle */
static void call_parser_reset(payload) {
    if (!buffer) return;
    TRY("parser::reset", buffer->reset(), true);
    buffer_complete = false;
}
/* ltl: parser_release_lifecycle */
static void call_parser_write(payload in) {
    if (!buffer || buffer_complete) return;
    std::error_code ec;
    TRY("parser::write", buffer->write(text(in, 0), ec), !ec);
    buffer_complete = !ec;
}
/* ltl: parser_release_lifecycle, serializer_value_lifetime */
static void call_parser_release(payload) {
    if (!buffer || !buffer_complete || !can_replace()) return;
    /* release() consumes the parse; a second call without reset() trips value_stack.ipp:348
     * (parser.hpp:525: "necessary to call reset after calling this function") */
    if (!preqed_call("parser::release")) return;
    bool ok = true;
    try { take(buffer->release()); } catch (const std::exception &) { ok = false; }
    preqed_result("parser::release", ok);
    buffer_complete = false;
}

/* serialization */

static void call_serialize(payload in) {
    if (!have) return;
    json::serialize_options opt;
    opt.allow_infinity_and_nan = (byte(in, 0) & 1) != 0;
    TRY("serialize", text_out = json::serialize(current, opt), true);
}
/* ltl: serializer_read_after_reset, serializer_value_lifetime */
static void call_serializer(payload in) {
    if (!can_replace()) return;
    json::serialize_options opt;
    opt.allow_infinity_and_nan = (byte(in, 0) & 1) != 0;
    if (!preqed_call("serializer")) return;
    writer.reset(new json::serializer(opt));
    writer_bound = false;
    preqed_result("serializer", true);
}
/* ltl: serializer_read_after_reset, serializer_value_lifetime */
static void call_serializer_reset(payload) {
    if (!writer || !have) return;
    TRY("serializer::reset", writer->reset(&current), true);
    writer_bound = true;
}
/* ltl: serializer_read_after_reset, serializer_value_lifetime */
static void call_serializer_done(payload) {
    if (!writer) return;
    if (!preqed_call("serializer::done")) return;
    bool done = writer->done();
    preqed_result("serializer::done", done);
    if (done) writer_bound = false;
}
/* ltl: serializer_read_after_reset, serializer_value_lifetime */
static void call_serializer_read(payload in) {
    if (!writer || !writer_bound) return;
    /* read() has @pre done() == false (serializer.hpp:230) */
    if (!preqed_call("serializer::done")) return;
    bool done = writer->done();
    preqed_result("serializer::done", done);
    if (done) { writer_bound = false; return; }
    if (!preqed_call("serializer::read")) return;
    char buf[512];
    json::string_view out = writer->read(buf, std::min<size_t>(sizeof buf, 1 + in.n));
    text_out.append(out.data(), out.size());
    preqed_result("serializer::read", !out.empty());
    if (!preqed_call("serializer::done")) return;
    done = writer->done();
    preqed_result("serializer::done", done);
    if (done) writer_bound = false;
}

/* array, object, pointer */

static void call_value_is_array(payload) {
    if (!have) return;
    if (!preqed_call("value::is_array")) return;
    preqed_result("value::is_array", current.is_array());
}

static void call_value_as_array(payload) {
    if (!have || !current.is_array()) return;
    REPORT("value::as_array", (void)current.as_array(), true);
}

static void call_array_size(payload) {
    if (!have || !current.is_array()) return;
    REPORT("array::size", (void)current.as_array().size(), true);
}
/* ltl: serializer_value_lifetime */
static void call_array_emplace_back(payload in) {
    if (!have || !current.is_array() || !can_replace()) return;
    if (!preqed_call("array::emplace_back")) return;
    bool ok = true;
    try { current.as_array().emplace_back(text(in, 0)); } catch (const std::exception &) { ok = false; }
    preqed_result("array::emplace_back", ok);
}
/* ltl: serializer_value_lifetime */
static void call_array_erase(payload in) {
    if (!have || !current.is_array() || !can_replace()) return;
    json::array &a = current.as_array();
    if (a.empty()) return;
    if (!preqed_call("array::erase")) return;
    bool ok = true;
    try { a.erase(a.begin() + byte(in, 0) % a.size()); } catch (const std::exception &) { ok = false; }
    preqed_result("array::erase", ok);
}
/* ltl: serializer_value_lifetime */
static void call_array_resize(payload in) {
    if (!have || !current.is_array() || !can_replace()) return;
    if (!preqed_call("array::resize")) return;
    bool ok = true;
    try { current.as_array().resize(byte(in, 0) % 65, json::value(text(in, 1))); } catch (const std::exception &) { ok = false; }
    preqed_result("array::resize", ok);
}

static void call_value_is_object(payload) {
    if (!have) return;
    if (!preqed_call("value::is_object")) return;
    preqed_result("value::is_object", current.is_object());
}

static void call_value_as_object(payload) {
    if (!have || !current.is_object()) return;
    REPORT("value::as_object", (void)current.as_object(), true);
}
/* ltl: serializer_value_lifetime */
static void call_object_insert_or_assign(payload in) {
    if (!have || !current.is_object() || !can_replace()) return;
    json::string_view key, val;
    if (!split(in, key, val)) return;
    if (!preqed_call("object::insert_or_assign")) return;
    bool ok = true;
    try { current.as_object().insert_or_assign(key, val); } catch (const std::exception &) { ok = false; }
    preqed_result("object::insert_or_assign", ok);
}
/* ltl: serializer_value_lifetime */
static void call_object_stable_erase(payload in) {
    if (!have || !current.is_object() || !can_replace()) return;
    if (!preqed_call("object::stable_erase")) return;
    bool ok = true;
    try { ok = current.as_object().stable_erase(text(in, 0)) != 0; } catch (const std::exception &) { ok = false; }
    preqed_result("object::stable_erase", ok);
}

static void call_value_find_pointer(payload in) {
    if (!have) return;
    if (!preqed_call("value::find_pointer")) return;
    std::error_code ec;
    bool ok = false;
    try { ok = current.find_pointer(text(in, 0), ec) != nullptr && !ec; } catch (const std::exception &) {}
    preqed_result("value::find_pointer", ok);
}
/* ltl: serializer_value_lifetime */
static void call_value_set_at_pointer(payload in) {
    if (!have || !can_replace()) return;
    json::string_view ptr, val;
    if (!split(in, ptr, val)) return;
    if (!preqed_call("value::set_at_pointer")) return;
    std::error_code ec;
    bool ok = false;
    try { ok = current.set_at_pointer(ptr, val, ec) != nullptr && !ec; } catch (const std::exception &) {}
    preqed_result("value::set_at_pointer", ok);
}
/* ltl: serializer_value_lifetime */
static void call_value_set_at_pointer_options(payload in) {
    if (!have || !can_replace() || in.n < 3) return;
    json::string_view ptr, val;
    if (!split(in, ptr, val)) return;
    json::set_pointer_options opts;
    opts.create_arrays = (byte(in, 0) & 1) != 0;
    opts.create_objects = (byte(in, 0) & 2) != 0;
    opts.replace_any_scalar = (byte(in, 0) & 4) != 0;
    opts.max_created_elements = 1 + (byte(in, 0) >> 4);  /* 1..16 */
    if (!preqed_call("value::set_at_pointer(options)")) return;
    std::error_code ec;
    bool ok = false;
    try { ok = current.set_at_pointer(ptr, val, ec, opts) != nullptr && !ec; } catch (const std::exception &) {}
    preqed_result("value::set_at_pointer(options)", ok);
}

/* conversions */

static void call_parse_into_vector(payload in) {
    json::string_view s = text(in, 0);
    std::error_code ec;
    if (!preqed_call("parse_into(vector)")) return;
    std::vector<std::int64_t> out;
    bool ok = false;
    try { json::parse_into(out, s, ec); ok = !ec; } catch (const std::exception &) {}
    preqed_result("parse_into(vector)", ok);
    if (ok) numbers = std::move(out);
}

static void call_parse_into_tuple(payload in) {
    json::string_view s = text(in, 0);
    std::error_code ec;
    if (!preqed_call("parse_into(tuple)")) return;
    std::tuple<std::string, std::int64_t> out;
    bool ok = false;
    try { json::parse_into(out, s, ec); ok = !ec; } catch (const std::exception &) {}
    preqed_result("parse_into(tuple)", ok);
    if (ok) numbers.push_back(std::get<1>(out));
}

static void call_parse_into_double(payload in) {
    json::string_view s = text(in, 0);
    std::error_code ec;
    if (!preqed_call("parse_into(double)")) return;
    double out = 0;
    bool ok = false;
    try { json::parse_into(out, s, ec); ok = !ec; } catch (const std::exception &) {}
    preqed_result("parse_into(double)", ok);
    if (ok) numbers.push_back(std::isfinite(out) && std::fabs(out) < 1e12 ? static_cast<std::int64_t>(out) : 0);
}

static void call_parse_into_bool(payload in) {
    json::string_view s = text(in, 0);
    std::error_code ec;
    if (!preqed_call("parse_into(bool)")) return;
    bool out = false;
    bool ok = false;
    try { json::parse_into(out, s, ec); ok = !ec; } catch (const std::exception &) {}
    preqed_result("parse_into(bool)", ok);
    if (ok) numbers.push_back(out);
}
/* ltl: serializer_value_lifetime */
static void call_value_from(payload in) {
    if (!can_replace() || in.n < 1) return;
    if ((in.n & 1) != 0) {
        std::string s = string_of(in, 0);
        TRY("value_from", take(json::value_from(s)), true);
    } else {
        std::vector<std::int64_t> typed = numbers;
        for (size_t i = 0; i < in.n; i++) typed.push_back(static_cast<std::int64_t>(in.p[i]));
        TRY("value_from", take(json::value_from(typed)), true);
    }
}

static void call_try_value_to_string(payload) {
    if (!have) return;
    if (!preqed_call("try_value_to(string)")) return;
    bool ok = false;
    try {
        auto r = json::try_value_to<std::string>(current);
        ok = r.has_value();
        if (ok) text_out = *r;
    } catch (const std::exception &) {}
    preqed_result("try_value_to(string)", ok);
}

/* std::nullopt_t is a supported conversion target; the library implements it as its tag_invoke overload
   (detail/value_to.hpp:835): succeeds only for null */
static void call_try_value_to_nullopt(payload) {
    if (!have) return;
    if (!preqed_call("try_value_to(nullopt_t)")) return;
    bool ok = false;
    try { ok = json::try_value_to<std::nullopt_t>(current).has_value(); } catch (const std::exception &) {}
    preqed_result("try_value_to(nullopt_t)", ok);
}

static void call_try_value_to_vector(payload) {
    if (!have) return;
    if (!preqed_call("try_value_to(vector)")) return;
    bool ok = false;
    try {
        auto r = json::try_value_to<std::vector<std::int64_t>>(current);
        ok = r.has_value();
        if (ok) numbers = std::move(*r);
    } catch (const std::exception &) {}
    preqed_result("try_value_to(vector)", ok);
}

static void call_visit(payload in) {
    if (!have) return;
    if (!preqed_call("visit")) return;
    bool ok = true;
    try {
        (void)json::visit([&in](auto const &x) -> std::size_t {
            std::size_t r = sizeof(x);
            for (size_t i = 0; i < in.n; i++) r = r * 33u ^ in.p[i];
            return r;
        }, current);
    } catch (const std::exception &) { ok = false; }
    preqed_result("visit", ok);
}

/* basic_parser with the project's event handler */

static void call_basic_parser(payload in) {
    json::parse_options opt = options(byte(in, 0), byte(in, 1));
    if (!preqed_call("basic_parser")) return;
    events.reset(new json::basic_parser<event_handler>(opt));
    events_done = false;
    preqed_result("basic_parser", true);
}

static void call_basic_parser_write_some(payload in) {
    if (!events || events_done || in.n < 2) return;
    if (!preqed_call("basic_parser::write_some")) return;
    std::error_code ec;
    bool ok = false;
    try { events->write_some((byte(in, 0) & 1) != 0, reinterpret_cast<const char *>(in.p + 1), in.n - 1, ec); ok = !ec; }
    catch (const std::exception &) {}
    preqed_result("basic_parser::write_some", ok);
}

static void call_basic_parser_done(payload) {
    if (!events) return;
    if (!preqed_call("basic_parser::done")) return;
    bool done = events->done();
    preqed_result("basic_parser::done", done);
    if (done) events_done = true;
}

/* value accessors: as_* throw system_error on a kind mismatch (value.hpp), a documented failure */

static void call_value_as_bool(payload) {
    if (!have) return;
    TRY("value::as_bool", (void)current.as_bool(), true);
}
static void call_value_as_double(payload) {
    if (!have) return;
    TRY("value::as_double", (void)current.as_double(), true);
}
static void call_value_as_int64(payload) {
    if (!have) return;
    TRY("value::as_int64", (void)current.as_int64(), true);
}
static void call_value_as_uint64(payload) {
    if (!have) return;
    TRY("value::as_uint64", (void)current.as_uint64(), true);
}
static void call_value_as_string(payload) {
    if (!have) return;
    TRY("value::as_string", (void)current.as_string(), true);
}
/* at(key) on objects, at(pos) otherwise; out-of-range and wrong kind throw */
static void call_value_at(payload in) {
    if (!have) return;
    if (current.is_object()) TRY("value::at", (void)current.at(text(in, 0)), true);
    else TRY("value::at", (void)current.at(byte(in, 0)), true);
}
static void call_value_try_at(payload in) {
    if (!have) return;
    if (current.is_object()) REPORT("value::try_at", bool ok = current.try_at(text(in, 0)).has_value(), ok);
    else REPORT("value::try_at", bool ok = current.try_at(byte(in, 0)).has_value(), ok);
}
static void call_value_at_pointer(payload in) {
    if (!have) return;
    TRY("value::at_pointer", (void)current.at_pointer(text(in, 0)), true);
}
static void call_value_try_at_pointer(payload in) {
    if (!have) return;
    REPORT("value::try_at_pointer", bool ok = current.try_at_pointer(text(in, 0)).has_value(), ok);
}
static void call_value_get_allocator(payload) {
    if (!have) return;
    REPORT("value::get_allocator", (void)current.get_allocator(), true);
}
static void call_value_if_bool(payload) {
    if (!have) return;
    REPORT("value::if_bool", bool ok = current.if_bool() != nullptr, ok);
}
static void call_value_if_double(payload) {
    if (!have) return;
    REPORT("value::if_double", bool ok = current.if_double() != nullptr, ok);
}
static void call_value_if_int64(payload) {
    if (!have) return;
    REPORT("value::if_int64", bool ok = current.if_int64() != nullptr, ok);
}
static void call_value_if_uint64(payload) {
    if (!have) return;
    REPORT("value::if_uint64", bool ok = current.if_uint64() != nullptr, ok);
}
static void call_value_if_object(payload) {
    if (!have) return;
    REPORT("value::if_object", bool ok = current.if_object() != nullptr, ok);
}
static void call_value_is_number(payload) {
    if (!have) return;
    REPORT("value::is_number", bool ok = current.is_number(), ok);
}
static void call_value_is_primitive(payload) {
    if (!have) return;
    REPORT("value::is_primitive", bool ok = current.is_primitive(), ok);
}
static void call_value_is_structured(payload) {
    if (!have) return;
    REPORT("value::is_structured", bool ok = current.is_structured(), ok);
}
static void call_value_try_as_bool(payload) {
    if (!have) return;
    REPORT("value::try_as_bool", bool ok = current.try_as_bool().has_value(), ok);
}
static void call_value_try_as_double(payload) {
    if (!have) return;
    REPORT("value::try_as_double", bool ok = current.try_as_double().has_value(), ok);
}
static void call_value_try_as_int64(payload) {
    if (!have) return;
    REPORT("value::try_as_int64", bool ok = current.try_as_int64().has_value(), ok);
}
static void call_value_try_as_uint64(payload) {
    if (!have) return;
    REPORT("value::try_as_uint64", bool ok = current.try_as_uint64().has_value(), ok);
}
static void call_value_try_as_null(payload) {
    if (!have) return;
    REPORT("value::try_as_null", bool ok = current.try_as_null().has_value(), ok);
}
static void call_value_try_as_string(payload) {
    if (!have) return;
    REPORT("value::try_as_string", bool ok = current.try_as_string().has_value(), ok);
}
/* integral targets fail on loss of precision, double always converts a number (value.hpp to_number) */
static void call_value_try_to_number(payload in) {
    if (!have) return;
    if (byte(in, 0) & 1) REPORT("value::try_to_number", bool ok = current.try_to_number<std::int64_t>().has_value(), ok);
    else REPORT("value::try_to_number", bool ok = current.try_to_number<double>().has_value(), ok);
}

/* value mutators: kind changes in place */
/* ltl: serializer_value_lifetime */
static void call_value_emplace_bool(payload in) {
    if (!have || !can_replace()) return;
    REPORT("value::emplace_bool", current.emplace_bool() = (byte(in, 0) & 1) != 0, true);
}
/* ltl: serializer_value_lifetime */
static void call_value_emplace_double(payload in) {
    if (!have || !can_replace()) return;
    double d = 0;
    std::memcpy(&d, in.p, std::min(in.n, sizeof d));
    REPORT("value::emplace_double", current.emplace_double() = d, true);
}
/* ltl: serializer_value_lifetime */
static void call_value_emplace_int64(payload in) {
    if (!have || !can_replace()) return;
    std::int64_t i = 0;
    std::memcpy(&i, in.p, std::min(in.n, sizeof i));
    REPORT("value::emplace_int64", current.emplace_int64() = i, true);
}
/* ltl: serializer_value_lifetime */
static void call_value_emplace_uint64(payload in) {
    if (!have || !can_replace()) return;
    std::uint64_t u = 0;
    std::memcpy(&u, in.p, std::min(in.n, sizeof u));
    REPORT("value::emplace_uint64", current.emplace_uint64() = u, true);
}
/* ltl: serializer_value_lifetime */
static void call_value_emplace_null(payload) {
    if (!have || !can_replace()) return;
    REPORT("value::emplace_null", current.emplace_null(), true);
}
/* ltl: serializer_value_lifetime */
static void call_value_emplace_object(payload) {
    if (!have || !can_replace()) return;
    REPORT("value::emplace_object", (void)current.emplace_object(), true);
}

/* array members (current must be an array) */

static void call_array_at(payload in) {
    if (!have || !current.is_array()) return;
    TRY("array::at", (void)current.as_array().at(byte(in, 0)), true);
}
static void call_array_try_at(payload in) {
    if (!have || !current.is_array()) return;
    REPORT("array::try_at", bool ok = current.as_array().try_at(byte(in, 0)).has_value(), ok);
}
/* operator[], front and back have @pre pos < size() / ! empty() (array.hpp) */
static void call_array_index(payload in) {
    if (!have || !current.is_array() || current.as_array().empty()) return;
    json::array &a = current.as_array();
    REPORT("array::operator[]", (void)a[byte(in, 0) % a.size()], true);
}
static void call_array_front(payload) {
    if (!have || !current.is_array() || current.as_array().empty()) return;
    REPORT("array::front", (void)current.as_array().front(), true);
}
static void call_array_back(payload) {
    if (!have || !current.is_array() || current.as_array().empty()) return;
    REPORT("array::back", (void)current.as_array().back(), true);
}
static void call_array_cbegin(payload) {
    if (!have || !current.is_array()) return;
    json::array const &a = current.as_array();
    REPORT("array::cbegin", bool ok = a.cbegin() == a.data(), ok);
}
static void call_array_cend(payload) {
    if (!have || !current.is_array()) return;
    json::array const &a = current.as_array();
    REPORT("array::cend", bool ok = a.cend() == a.data() + a.size(), ok);
}
static void call_array_rbegin(payload) {
    if (!have || !current.is_array()) return;
    json::array &a = current.as_array();
    REPORT("array::rbegin", bool ok = a.rbegin().base() == a.data() + a.size(), ok);
}
static void call_array_rend(payload) {
    if (!have || !current.is_array()) return;
    json::array &a = current.as_array();
    REPORT("array::rend", bool ok = a.rend().base() == a.data(), ok);
}
static void call_array_crbegin(payload) {
    if (!have || !current.is_array()) return;
    json::array const &a = current.as_array();
    REPORT("array::crbegin", bool ok = a.crbegin().base() == a.data() + a.size(), ok);
}
static void call_array_crend(payload) {
    if (!have || !current.is_array()) return;
    json::array const &a = current.as_array();
    REPORT("array::crend", bool ok = a.crend().base() == a.data(), ok);
}
static void call_array_get_allocator(payload) {
    if (!have || !current.is_array()) return;
    REPORT("array::get_allocator", (void)current.as_array().get_allocator(), true);
}
/* ltl: serializer_value_lifetime */
static void call_array_clear(payload) {
    if (!have || !current.is_array() || !can_replace()) return;
    REPORT("array::clear", current.as_array().clear(), true);
}
/* ltl: serializer_value_lifetime */
static void call_array_pop_back(payload) {
    if (!have || !current.is_array() || current.as_array().empty() || !can_replace()) return;
    REPORT("array::pop_back", current.as_array().pop_back(), true);
}
/* ltl: serializer_value_lifetime */
static void call_array_insert(payload in) {
    if (!have || !current.is_array() || !can_replace()) return;
    json::array &a = current.as_array();
    TRY("array::insert", a.insert(a.begin() + byte(in, 0) % (a.size() + 1), json::value(text(in, 1))), true);
}
/* ltl: serializer_value_lifetime */
static void call_array_emplace(payload in) {
    if (!have || !current.is_array() || !can_replace()) return;
    json::array &a = current.as_array();
    TRY("array::emplace", a.emplace(a.begin() + byte(in, 0) % (a.size() + 1), text(in, 1)), true);
}
/* ltl: serializer_value_lifetime */
static void call_array_assign(payload in) {
    if (!have || !current.is_array() || !can_replace()) return;
    TRY("array::operator=", (current.as_array() = { text(in, 1), static_cast<int>(byte(in, 0)) }), true);
}
/* ltl: serializer_value_lifetime */
static void call_array_shrink_to_fit(payload) {
    if (!have || !current.is_array() || !can_replace()) return;
    TRY("array::shrink_to_fit", current.as_array().shrink_to_fit(), true);
}
/* swaps with the previous document's array */
/* ltl: serializer_value_lifetime */
static void call_array_swap(payload) {
    if (!have || !current.is_array() || !spare.is_array() || !can_replace()) return;
    TRY("array::swap", current.as_array().swap(spare.as_array()), true);
}

/* object members (current must be an object) */

static void call_object_at(payload in) {
    if (!have || !current.is_object()) return;
    TRY("object::at", (void)current.as_object().at(text(in, 0)), true);
}
static void call_object_try_at(payload in) {
    if (!have || !current.is_object()) return;
    REPORT("object::try_at", bool ok = current.as_object().try_at(text(in, 0)).has_value(), ok);
}
static void call_object_contains(payload in) {
    if (!have || !current.is_object()) return;
    REPORT("object::contains", bool ok = current.as_object().contains(text(in, 0)), ok);
}
static void call_object_count(payload in) {
    if (!have || !current.is_object()) return;
    REPORT("object::count", bool ok = current.as_object().count(text(in, 0)) != 0, ok);
}
static void call_object_if_contains(payload in) {
    if (!have || !current.is_object()) return;
    REPORT("object::if_contains", bool ok = current.as_object().if_contains(text(in, 0)) != nullptr, ok);
}
static void call_object_cbegin(payload) {
    if (!have || !current.is_object()) return;
    json::object const &o = current.as_object();
    REPORT("object::cbegin", bool ok = static_cast<std::size_t>(std::distance(o.cbegin(), o.end())) == o.size(), ok);
}
static void call_object_cend(payload) {
    if (!have || !current.is_object()) return;
    json::object const &o = current.as_object();
    REPORT("object::cend", bool ok = static_cast<std::size_t>(std::distance(o.begin(), o.cend())) == o.size(), ok);
}
static void call_object_rbegin(payload) {
    if (!have || !current.is_object()) return;
    json::object &o = current.as_object();
    REPORT("object::rbegin", bool ok = o.rbegin().base() == o.end(), ok);
}
static void call_object_rend(payload) {
    if (!have || !current.is_object()) return;
    json::object &o = current.as_object();
    REPORT("object::rend", bool ok = o.rend().base() == o.begin(), ok);
}
static void call_object_crbegin(payload) {
    if (!have || !current.is_object()) return;
    json::object const &o = current.as_object();
    REPORT("object::crbegin", bool ok = o.crbegin().base() == o.end(), ok);
}
static void call_object_crend(payload) {
    if (!have || !current.is_object()) return;
    json::object const &o = current.as_object();
    REPORT("object::crend", bool ok = o.crend().base() == o.begin(), ok);
}
static void call_object_get_allocator(payload) {
    if (!have || !current.is_object()) return;
    REPORT("object::get_allocator", (void)current.as_object().get_allocator(), true);
}
/* ltl: serializer_value_lifetime */
static void call_object_clear(payload) {
    if (!have || !current.is_object() || !can_replace()) return;
    REPORT("object::clear", current.as_object().clear(), true);
}
/* ltl: serializer_value_lifetime */
static void call_object_erase(payload in) {
    if (!have || !current.is_object() || !can_replace()) return;
    REPORT("object::erase", bool ok = current.as_object().erase(text(in, 0)) != 0, ok);
}
/* operator[] inserts a null for a missing key */
/* ltl: serializer_value_lifetime */
static void call_object_index(payload in) {
    if (!have || !current.is_object() || !can_replace()) return;
    TRY("object::operator[]", (void)current.as_object()[text(in, 0)], true);
}
/* ltl: serializer_value_lifetime */
static void call_object_assign(payload in) {
    if (!have || !current.is_object() || !can_replace()) return;
    json::string_view key, val;
    if (!split(in, key, val)) return;
    TRY("object::operator=", (current.as_object() = { { key, val } }), true);
}

/* key_value_pair: the first member of an object */

static void call_key_value_pair_key_c_str(payload) {
    if (!have || !current.is_object() || current.as_object().empty()) return;
    json::key_value_pair const &kv = *current.as_object().begin();
    REPORT("key_value_pair::key_c_str", bool ok = kv.key_c_str()[kv.key().size()] == '\0', ok);
}
static void call_get(payload) {
    if (!have || !current.is_object() || current.as_object().empty()) return;
    json::key_value_pair const &kv = *current.as_object().begin();
    REPORT("get", bool ok = json::get<0>(kv) == kv.key() && &json::get<1>(kv) == &kv.value(), ok);
}

/* string members (current must be a string) */

static void call_string_at(payload in) {
    if (!have || !current.is_string()) return;
    TRY("string::at", (void)current.as_string().at(byte(in, 0)), true);
}
static void call_string_try_at(payload in) {
    if (!have || !current.is_string()) return;
    REPORT("string::try_at", bool ok = current.as_string().try_at(byte(in, 0)).has_value(), ok);
}
/* operator[], front, back and pop_back have @pre pos < size() / ! empty() (string.hpp) */
static void call_string_index(payload in) {
    if (!have || !current.is_string() || current.as_string().empty()) return;
    json::string &s = current.as_string();
    REPORT("string::operator[]", (void)s[byte(in, 0) % s.size()], true);
}
static void call_string_front(payload) {
    if (!have || !current.is_string() || current.as_string().empty()) return;
    REPORT("string::front", (void)current.as_string().front(), true);
}
static void call_string_back(payload) {
    if (!have || !current.is_string() || current.as_string().empty()) return;
    REPORT("string::back", (void)current.as_string().back(), true);
}
static void call_string_begin(payload) {
    if (!have || !current.is_string()) return;
    json::string &s = current.as_string();
    REPORT("string::begin", bool ok = s.begin() == s.data(), ok);
}
static void call_string_end(payload) {
    if (!have || !current.is_string()) return;
    json::string &s = current.as_string();
    REPORT("string::end", bool ok = s.end() == s.data() + s.size(), ok);
}
static void call_string_cbegin(payload) {
    if (!have || !current.is_string()) return;
    json::string const &s = current.as_string();
    REPORT("string::cbegin", bool ok = s.cbegin() == s.data(), ok);
}
static void call_string_cend(payload) {
    if (!have || !current.is_string()) return;
    json::string const &s = current.as_string();
    REPORT("string::cend", bool ok = s.cend() == s.data() + s.size(), ok);
}
static void call_string_rbegin(payload) {
    if (!have || !current.is_string()) return;
    json::string &s = current.as_string();
    REPORT("string::rbegin", bool ok = s.rbegin().base() == s.data() + s.size(), ok);
}
static void call_string_rend(payload) {
    if (!have || !current.is_string()) return;
    json::string &s = current.as_string();
    REPORT("string::rend", bool ok = s.rend().base() == s.data(), ok);
}
static void call_string_crbegin(payload) {
    if (!have || !current.is_string()) return;
    json::string const &s = current.as_string();
    REPORT("string::crbegin", bool ok = s.crbegin().base() == s.data() + s.size(), ok);
}
static void call_string_crend(payload) {
    if (!have || !current.is_string()) return;
    json::string const &s = current.as_string();
    REPORT("string::crend", bool ok = s.crend().base() == s.data(), ok);
}
static void call_string_c_str(payload) {
    if (!have || !current.is_string()) return;
    json::string const &s = current.as_string();
    REPORT("string::c_str", bool ok = s.c_str()[s.size()] == '\0', ok);
}
static void call_string_capacity(payload) {
    if (!have || !current.is_string()) return;
    json::string const &s = current.as_string();
    REPORT("string::capacity", bool ok = s.capacity() >= s.size(), ok);
}
static void call_string_empty(payload) {
    if (!have || !current.is_string()) return;
    REPORT("string::empty", bool ok = current.as_string().empty(), ok);
}
static void call_string_get_allocator(payload) {
    if (!have || !current.is_string()) return;
    REPORT("string::get_allocator", (void)current.as_string().get_allocator(), true);
}
static void call_string_compare(payload in) {
    if (!have || !current.is_string()) return;
    REPORT("string::compare", bool ok = current.as_string().compare(text(in, 0)) == 0, ok);
}
static void call_string_starts_with(payload in) {
    if (!have || !current.is_string()) return;
    REPORT("string::starts_with", bool ok = current.as_string().starts_with(text(in, 0)), ok);
}
static void call_string_ends_with(payload in) {
    if (!have || !current.is_string()) return;
    REPORT("string::ends_with", bool ok = current.as_string().ends_with(text(in, 0)), ok);
}
/* copy throws out_of_range when pos > size() (string.hpp) */
static void call_string_copy(payload in) {
    if (!have || !current.is_string()) return;
    char buf[64];
    TRY("string::copy", (void)current.as_string().copy(buf, byte(in, 0) % sizeof buf, byte(in, 1)), true);
}
static void call_string_find(payload in) {
    if (!have || !current.is_string()) return;
    REPORT("string::find", bool ok = current.as_string().find(text(in, 1), byte(in, 0)) != json::string::npos, ok);
}
static void call_string_rfind(payload in) {
    if (!have || !current.is_string()) return;
    REPORT("string::rfind", bool ok = current.as_string().rfind(text(in, 1), byte(in, 0)) != json::string::npos, ok);
}
static void call_string_find_first_of(payload in) {
    if (!have || !current.is_string()) return;
    REPORT("string::find_first_of",
           bool ok = current.as_string().find_first_of(text(in, 1), byte(in, 0)) != json::string::npos, ok);
}
static void call_string_find_first_not_of(payload in) {
    if (!have || !current.is_string()) return;
    REPORT("string::find_first_not_of",
           bool ok = current.as_string().find_first_not_of(text(in, 1), byte(in, 0)) != json::string::npos, ok);
}
static void call_string_find_last_of(payload in) {
    if (!have || !current.is_string()) return;
    REPORT("string::find_last_of",
           bool ok = current.as_string().find_last_of(text(in, 1), byte(in, 0)) != json::string::npos, ok);
}
static void call_string_find_last_not_of(payload in) {
    if (!have || !current.is_string()) return;
    REPORT("string::find_last_not_of",
           bool ok = current.as_string().find_last_not_of(text(in, 1), byte(in, 0)) != json::string::npos, ok);
}
/* string mutators: the serializer keeps a pointer into the characters (serializer.ipp:471) */
/* ltl: serializer_value_lifetime */
static void call_string_append(payload in) {
    if (!have || !current.is_string() || !can_replace()) return;
    TRY("string::append", current.as_string().append(text(in, 0)), true);
}
/* ltl: serializer_value_lifetime */
static void call_string_append_assign(payload in) {
    if (!have || !current.is_string() || !can_replace()) return;
    TRY("string::operator+=", current.as_string() += text(in, 0), true);
}
/* ltl: serializer_value_lifetime */
static void call_string_assign(payload in) {
    if (!have || !current.is_string() || !can_replace()) return;
    TRY("string::operator=", current.as_string() = text(in, 0), true);
}
/* ltl: serializer_value_lifetime */
static void call_string_push_back(payload in) {
    if (!have || !current.is_string() || !can_replace()) return;
    TRY("string::push_back", current.as_string().push_back(static_cast<char>(byte(in, 0))), true);
}
/* ltl: serializer_value_lifetime */
static void call_string_pop_back(payload) {
    if (!have || !current.is_string() || current.as_string().empty() || !can_replace()) return;
    REPORT("string::pop_back", current.as_string().pop_back(), true);
}
/* ltl: serializer_value_lifetime */
static void call_string_clear(payload) {
    if (!have || !current.is_string() || !can_replace()) return;
    REPORT("string::clear", current.as_string().clear(), true);
}
/* erase, insert and replace throw out_of_range when pos > size() (string.hpp) */
/* ltl: serializer_value_lifetime */
static void call_string_erase(payload in) {
    if (!have || !current.is_string() || !can_replace()) return;
    TRY("string::erase", current.as_string().erase(byte(in, 0), byte(in, 1)), true);
}
/* ltl: serializer_value_lifetime */
static void call_string_insert(payload in) {
    if (!have || !current.is_string() || !can_replace()) return;
    TRY("string::insert", current.as_string().insert(byte(in, 0), text(in, 1)), true);
}
/* ltl: serializer_value_lifetime */
static void call_string_replace(payload in) {
    if (!have || !current.is_string() || !can_replace()) return;
    TRY("string::replace", current.as_string().replace(byte(in, 0), byte(in, 1), text(in, 2)), true);
}
/* ltl: serializer_value_lifetime */
static void call_string_resize(payload in) {
    if (!have || !current.is_string() || !can_replace()) return;
    TRY("string::resize", current.as_string().resize(byte(in, 0), static_cast<char>(byte(in, 1))), true);
}
/* ltl: serializer_value_lifetime */
static void call_string_reserve(payload in) {
    if (!have || !current.is_string() || !can_replace()) return;
    TRY("string::reserve", current.as_string().reserve(std::size_t(byte(in, 0)) * 16), true);
}
/* ltl: serializer_value_lifetime */
static void call_string_shrink_to_fit(payload) {
    if (!have || !current.is_string() || !can_replace()) return;
    TRY("string::shrink_to_fit", current.as_string().shrink_to_fit(), true);
}
/* swaps with the previous document's string */
/* ltl: serializer_value_lifetime */
static void call_string_swap(payload) {
    if (!have || !current.is_string() || !spare.is_string() || !can_replace()) return;
    TRY("string::swap", current.as_string().swap(spare.as_string()), true);
}

/* free functions: the second operand is the previous document */

static void call_operator_eq(payload) {
    if (!have) return;
    REPORT("operator==", bool ok = current == spare, ok);
}
static void call_operator_ne(payload) {
    if (!have) return;
    REPORT("operator!=", bool ok = current != spare, ok);
}
/* relational operators exist for string only (string.hpp) */
static void call_operator_lt(payload in) {
    if (!have || !current.is_string()) return;
    REPORT("operator<", bool ok = current.as_string() < text(in, 0), ok);
}
static void call_operator_le(payload in) {
    if (!have || !current.is_string()) return;
    REPORT("operator<=", bool ok = current.as_string() <= text(in, 0), ok);
}
static void call_operator_gt(payload in) {
    if (!have || !current.is_string()) return;
    REPORT("operator>", bool ok = current.as_string() > text(in, 0), ok);
}
static void call_operator_ge(payload in) {
    if (!have || !current.is_string()) return;
    REPORT("operator>=", bool ok = current.as_string() >= text(in, 0), ok);
}
static void call_operator_shl(payload) {
    if (!have) return;
    std::ostringstream os;
    TRY("operator<<", os << current; text_out = os.str(), !os.fail());
}
/* operator>> parses one value from the stream (value.hpp) */
/* ltl: serializer_value_lifetime */
static void call_operator_shr(payload in) {
    if (!can_replace()) return;
    std::istringstream is(string_of(in, 0));
    json::value v;
    TRY("operator>>", is >> v; if (!is.fail()) take(std::move(v)), !is.fail());
}
static void call_hash_value(payload) {
    if (!have) return;
    REPORT("hash_value", (void)hash_value(current), true);  /* hidden friend: ADL */
}
static void call_std_hash(payload) {
    if (!have) return;
    REPORT("std::hash", (void)std::hash<json::value>()(current), true);
}
/* ltl: serializer_value_lifetime */
static void call_swap(payload) {
    if (!have || !can_replace()) return;
    TRY("swap", swap(current, spare), true);  /* hidden friend: ADL */
}
static void call_to_string(payload) {
    if (!have) return;
    REPORT("to_string", bool ok = !json::to_string(current.kind()).empty(), ok);
}
/* value_to throws system_error when the value does not convert */
static void call_value_to(payload in) {
    if (!have) return;
    if (byte(in, 0) & 1) TRY("value_to", numbers = json::value_to<std::vector<std::int64_t>>(current), true);
    else TRY("value_to", text_out = json::value_to<std::string>(current), true);
}

/* errors */

static void call_make_error_condition(payload in) {
    json::condition c = static_cast<json::condition>(1 + byte(in, 0) % 4);
    REPORT("make_error_condition", bool ok = json::make_error_condition(c).failed(), ok);
}
/* returns a result holding the error (result_for.hpp) */
static void call_result_from_errno(payload in) {
    int e = 1 + byte(in, 0) % 133;
    REPORT("result_from_errno", bool ok = json::result_from_errno<json::value>(e, nullptr).has_error(), ok);
}

/* memory resources */

static void call_make_shared_resource(payload in) {
    if (!preqed_call("make_shared_resource")) return;
    bool ok = false;
    try {
        json::storage_ptr sp = json::make_shared_resource<json::monotonic_resource>();
        ok = json::value(text(in, 0), sp).storage() == sp;
    } catch (const std::exception &) {}
    preqed_result("make_shared_resource", ok);
}
static void call_storage_ptr_is_deallocate_trivial(payload in) {
    json::storage_ptr sp = storage(byte(in, 0), in.n);
    REPORT("storage_ptr::is_deallocate_trivial", bool ok = sp.is_deallocate_trivial(), ok);
}
/* no value keeps memory from a resource: parse(storage_ptr) copies its result out (take) */
static void call_monotonic_resource_release(payload) {
    if (!monotonic) return;
    REPORT("monotonic_resource::release", monotonic->release(), true);
}
static void call_static_resource_release(payload) {
    if (!fixed) return;
    REPORT("static_resource::release", fixed->release(), true);
}

/* dispatch */

static void (*const api[])(payload) = {
    call_parse, call_parse_istream, call_parse_storage,
    call_stream_parser, call_stream_parser_reset, call_stream_parser_write,
    call_stream_parser_write_some, call_stream_parser_finish, call_stream_parser_done,
    call_stream_parser_release,
    call_parser, call_parser_reset, call_parser_write, call_parser_release,
    call_serialize, call_serializer, call_serializer_reset, call_serializer_done, call_serializer_read,
    call_value_is_array, call_value_as_array, call_array_size, call_array_emplace_back,
    call_array_erase, call_array_resize,
    call_value_is_object, call_value_as_object, call_object_insert_or_assign, call_object_stable_erase,
    call_value_find_pointer, call_value_set_at_pointer, call_value_set_at_pointer_options,
    call_parse_into_vector, call_parse_into_tuple, call_parse_into_double, call_parse_into_bool,
    call_value_from, call_try_value_to_string, call_try_value_to_nullopt, call_try_value_to_vector, call_visit,
    call_basic_parser, call_basic_parser_write_some, call_basic_parser_done,
    call_value_as_bool, call_value_as_double, call_value_as_int64, call_value_as_uint64, call_value_as_string,
    call_value_at, call_value_try_at, call_value_at_pointer, call_value_try_at_pointer, call_value_get_allocator,
    call_value_if_bool, call_value_if_double, call_value_if_int64, call_value_if_uint64, call_value_if_object,
    call_value_is_number, call_value_is_primitive, call_value_is_structured, call_value_try_as_bool,
    call_value_try_as_double, call_value_try_as_int64, call_value_try_as_uint64, call_value_try_as_null,
    call_value_try_as_string, call_value_try_to_number, call_value_emplace_bool, call_value_emplace_double,
    call_value_emplace_int64, call_value_emplace_uint64, call_value_emplace_null, call_value_emplace_object,
    call_array_at, call_array_try_at, call_array_index, call_array_front, call_array_back, call_array_cbegin,
    call_array_cend, call_array_rbegin, call_array_rend, call_array_crbegin, call_array_crend,
    call_array_get_allocator, call_array_clear, call_array_pop_back, call_array_insert, call_array_emplace,
    call_array_assign, call_array_shrink_to_fit, call_array_swap, call_object_at, call_object_try_at,
    call_object_contains, call_object_count, call_object_if_contains, call_object_cbegin, call_object_cend,
    call_object_rbegin, call_object_rend, call_object_crbegin, call_object_crend, call_object_get_allocator,
    call_object_clear, call_object_erase, call_object_index, call_object_assign, call_key_value_pair_key_c_str,
    call_get, call_string_at, call_string_try_at, call_string_index, call_string_front, call_string_back,
    call_string_begin, call_string_end, call_string_cbegin, call_string_cend, call_string_rbegin, call_string_rend,
    call_string_crbegin, call_string_crend, call_string_c_str, call_string_capacity, call_string_empty,
    call_string_get_allocator, call_string_compare, call_string_starts_with, call_string_ends_with,
    call_string_copy, call_string_find, call_string_rfind, call_string_find_first_of, call_string_find_first_not_of,
    call_string_find_last_of, call_string_find_last_not_of, call_string_append, call_string_append_assign,
    call_string_assign, call_string_push_back, call_string_pop_back, call_string_clear, call_string_erase,
    call_string_insert, call_string_replace, call_string_resize, call_string_reserve, call_string_shrink_to_fit,
    call_string_swap, call_operator_eq, call_operator_ne, call_operator_lt, call_operator_le, call_operator_gt,
    call_operator_ge, call_operator_shl, call_operator_shr, call_hash_value, call_std_hash, call_swap,
    call_to_string, call_value_to,
    call_make_error_condition, call_result_from_errno, call_make_shared_resource,
    call_storage_ptr_is_deallocate_trivial, call_monotonic_resource_release, call_static_resource_release,
};

static const size_t API_COUNT = sizeof api / sizeof api[0];

static void cleanup() {
    writer.reset();
    events.reset();
    buffer.reset();
    stream.reset();
    fixed.reset();
    monotonic.reset();
    current = json::value();
    spare = json::value();
    have = false;
    text_out.clear();
    numbers.clear();
    fixed_buf.clear();
    stream_seen = false;
    stream_released = false;
    stream_comment_tail = false;
    buffer_complete = false;
    writer_bound = false;
    events_done = false;
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
