#include "simdjson.h"
#include "preqed_ltl.h"

#include <sys/mman.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace sj = simdjson;

struct payload {
    const uint8_t *p;
    size_t n;
};

static uint8_t byte(payload in, size_t i) { return i < in.n ? in.p[i] : 0; }
static payload rest(payload in, size_t skip) {
    return { in.p + (skip < in.n ? skip : in.n), in.n > skip ? in.n - skip : 0 };
}
static std::string_view view(payload in) { return { reinterpret_cast<const char *>(in.p), in.n }; }

#define REPORT(api, stmt, ok_cond) \
    do { if (preqed_call(api)) { stmt; preqed_result(api, (ok_cond)); } } while (0)

/* conversion operators, begin()/end() on elements and value() throw simdjson_error on failure (SIMDJSON_EXCEPTIONS) */
#define THROWING(api, stmt) \
    do { if (preqed_call(api)) { bool ok_ = true; try { stmt; } catch (const sj::simdjson_error &) { ok_ = false; } preqed_result(api, ok_); } } while (0)

/* the load / memory-map APIs read a file: hand them the payload as an anonymous in-memory file */
struct memfile {
    int fd;
    std::string path;
    explicit memfile(payload in) : fd(memfd_create("simdjson-fuzz", MFD_CLOEXEC)) {
        for (size_t off = 0; fd >= 0 && off < in.n;) {
            ssize_t w = write(fd, in.p + off, in.n - off);
            if (w <= 0) { close(fd); fd = -1; }
            else off += size_t(w);
        }
        if (fd >= 0) path = "/proc/self/fd/" + std::to_string(fd);
    }
    ~memfile() { if (fd >= 0) close(fd); }
};

/* DOM: one parser, one current element, one array and one object iteration, one document stream */

static sj::dom::parser *dom_parser;
static sj::dom::document *dom_document;      /* target of parse_into_document */
static sj::padded_string *dom_stream_input;  /* parse_many keeps pointers into it */
static sj::padded_string *padded_buf;        /* built by padded_string::append, read by parse(padded_string) */
static sj::dom::element dom_current;
static bool dom_valid;
static sj::dom::array dom_array;
static sj::dom::array::iterator dom_ait, dom_aend;
static bool dom_array_valid;
static sj::dom::object dom_object;
static sj::dom::object::iterator dom_oit, dom_oend;
static bool dom_object_valid;
static sj::dom::document_stream *dom_stream;
static sj::dom::document_stream::iterator dom_sit, dom_send;
static bool dom_stream_valid;
static sj::simdjson_result<sj::dom::element> dom_res;   /* last successful navigation result, for chained calls */
static bool dom_res_valid;
static sj::dom::element dom_prev;                       /* element replaced by the last navigation (same document) */
static bool dom_prev_valid;
static sj::simdjson_result<sj::dom::array> dom_ares;    /* the get_array result behind dom_array */

/* elements, arrays and objects of the current document are gone */
static void dom_elements_gone() {
    dom_valid = dom_array_valid = dom_object_valid = dom_res_valid = dom_prev_valid = false;
}

/* "at most one parsed document in play per parser instance" (doc/dom.md). The stream's stage-1 worker thread
 * may still read its input (the parse_many buffer, or the parser's loaded bytes that every parse reuses), so
 * the stream is destroyed (~document_stream stops the thread first, simdjson.h:10510) before any reuse. */
static void dom_reused() {
    dom_elements_gone();
    dom_stream_valid = false;
    delete dom_stream;   /* not move-assignment: that races with the worker (repro_stream_move_assign.cpp) */
    dom_stream = new sj::dom::document_stream();
}

static void dom_take(const char *api, sj::simdjson_result<sj::dom::element> r) {
    sj::dom::element e;
    bool ok = !r.get(e);
    preqed_result(api, ok);
    if (ok) {
        if (dom_valid) { dom_prev = dom_current; dom_prev_valid = true; }
        dom_current = e;
        dom_valid = true;
        dom_res = r;
        dom_res_valid = true;
    }
}
/* ltl: dom_one_document_per_parser, dom_array_view, dom_object_view, dom_stream_from_parse_many */
static void call_dom_parser_parse(payload in) {
    dom_reused();
    if (!preqed_call("dom::parser::parse")) return;
    dom_take("dom::parser::parse", dom_parser->parse(in.p, in.n));
}
/* ltl: dom_one_document_per_parser, dom_array_view, dom_object_view, dom_stream_from_parse_many */
static void call_dom_parser_parse_padded(payload in) {
    if (byte(in, 0) & 1) *padded_buf = sj::padded_string(view(rest(in, 1)));
    if (!padded_buf->data()) return;
    dom_reused();
    if (!preqed_call("dom::parser::parse(padded_string)")) return;
    dom_take("dom::parser::parse(padded_string)", dom_parser->parse(*padded_buf));
}
/* ltl: dom_one_document_per_parser, dom_array_view, dom_object_view, dom_stream_from_parse_many */
static void call_dom_parser_parse_unpadded(payload in) {
    dom_reused();
    if (!preqed_call("dom::parser::parse_unpadded")) return;
    dom_take("dom::parser::parse_unpadded", dom_parser->parse_unpadded(view(in)));
}
/* ltl: dom_one_document_per_parser, dom_array_view, dom_object_view, dom_stream_from_parse_many */
static void call_dom_parser_parse_into_document(payload in) {
    dom_reused();
    if (!preqed_call("dom::parser::parse_into_document")) return;
    dom_take("dom::parser::parse_into_document", dom_parser->parse_into_document(*dom_document, in.p, in.n));
}
/* ltl: dom_one_document_per_parser, dom_array_view, dom_object_view, dom_stream_from_parse_many */
static void call_dom_parser_parse_many(payload in) {
    dom_reused();
    *dom_stream_input = sj::padded_string(view(rest(in, 1)));
    /* batch size: the 1 MB default, or 8 KiB so documents straddle batch boundaries */
    size_t batch = byte(in, 0) & 1 ? sj::dom::DEFAULT_BATCH_SIZE : 8192;
    auto format = byte(in, 0) & 2 ? sj::stream_format::comma_delimited : sj::stream_format::whitespace_delimited;
    if (!preqed_call("dom::parser::parse_many")) return;
    bool ok = !dom_parser->parse_many(*dom_stream_input, batch, format).get(*dom_stream);
    preqed_result("dom::parser::parse_many", ok);
    if (!ok) return;
    dom_sit = dom_stream->begin();
    dom_send = dom_stream->end();
    dom_stream_valid = true;
}
/* ltl: dom_one_document_per_parser, dom_array_view, dom_object_view, dom_stream_from_parse_many */
static void call_dom_parser_allocate(payload in) {
    size_t capacity = (size_t(byte(in, 0)) | size_t(byte(in, 1)) << 8) * 64;  /* 0..4 MiB in 64-byte steps; max depth 1..256 below */
    dom_reused();
    REPORT("dom::parser::allocate", auto ec = dom_parser->allocate(capacity, 1 + byte(in, 2)), ec == sj::SUCCESS);
}

static void call_dom_parser_number_as_string(payload in) {
    REPORT("dom::parser::number_as_string", dom_parser->number_as_string(byte(in, 0) & 1), true);
}

/* document stream */
/* ltl: dom_one_document_per_parser, dom_stream_from_parse_many */
static void call_dom_document_stream_next(payload) {
    if (!dom_stream_valid || !(dom_sit != dom_send)) return;
    if (!preqed_call("dom::document_stream::iterator::operator*")) return;
    sj::dom::element e;
    bool ok = !(*dom_sit).get(e);
    preqed_result("dom::document_stream::iterator::operator*", ok);
    if (ok) {
        dom_current = e;
        dom_valid = true;
        dom_array_valid = dom_object_valid = dom_res_valid = dom_prev_valid = false;
    }
}
/* ltl: dom_one_document_per_parser, dom_array_view, dom_object_view, dom_stream_from_parse_many */
static void call_dom_document_stream_advance(payload) {
    if (!dom_stream_valid || !(dom_sit != dom_send)) return;
    dom_elements_gone();
    REPORT("dom::document_stream::iterator::operator++", ++dom_sit, true);
}

/* element navigation: success replaces the current element */
/* ltl: dom_one_document_per_parser */
static void call_dom_element_at_pointer(payload in) {
    if (!dom_valid) return;
    if (!preqed_call("dom::element::at_pointer")) return;
    dom_take("dom::element::at_pointer", dom_current.at_pointer(view(in)));
}
/* ltl: dom_one_document_per_parser */
static void call_dom_element_at_key(payload in) {
    if (!dom_valid) return;
    if (!preqed_call("dom::element::at_key")) return;
    dom_take("dom::element::at_key", dom_current.at_key(view(in)));
}
/* ltl: dom_one_document_per_parser */
static void call_dom_element_at_key_case_insensitive(payload in) {
    if (!dom_valid) return;
    if (!preqed_call("dom::element::at_key_case_insensitive")) return;
    dom_take("dom::element::at_key_case_insensitive", dom_current.at_key_case_insensitive(view(in)));
}
/* ltl: dom_one_document_per_parser */
static void call_dom_element_at(payload in) {
    if (!dom_valid) return;
    if (!preqed_call("dom::element::at")) return;
    dom_take("dom::element::at", dom_current.at(byte(in, 0)));
}

/* element inspection */

#define DOM_GET(api, method) \
    static void call_dom_element_##method(payload) { \
        if (!dom_valid) return; \
        REPORT(api, auto r = dom_current.method(), !r.error()); \
    }
/* ltl: dom_one_document_per_parser */
DOM_GET("dom::element::get_string", get_string)
/* ltl: dom_one_document_per_parser */
DOM_GET("dom::element::get_c_str", get_c_str)
/* ltl: dom_one_document_per_parser */
DOM_GET("dom::element::get_string_length", get_string_length)
/* ltl: dom_one_document_per_parser */
DOM_GET("dom::element::get_int64", get_int64)
/* ltl: dom_one_document_per_parser */
DOM_GET("dom::element::get_uint64", get_uint64)
/* ltl: dom_one_document_per_parser */
DOM_GET("dom::element::get_double", get_double)
/* ltl: dom_one_document_per_parser */
DOM_GET("dom::element::get_bool", get_bool)
/* ltl: dom_one_document_per_parser */
DOM_GET("dom::element::get_bigint", get_bigint)
/* ltl: dom_one_document_per_parser */
static void call_dom_element_type(payload) {
    if (!dom_valid) return;
    REPORT("dom::element::type", (void)dom_current.type(), true);
}
/* ltl: dom_one_document_per_parser */
static void call_dom_element_is_number(payload) {
    if (!dom_valid) return;
    REPORT("dom::element::is_number", (void)dom_current.is_number(), true);
}
/* ltl: dom_one_document_per_parser */
static void call_dom_element_dump_raw_tape(payload) {
    if (!dom_valid) return;
    std::ostringstream os;
    REPORT("dom::element::dump_raw_tape", bool ok = dom_current.dump_raw_tape(os), ok);
}
/* ltl: dom_one_document_per_parser */
static void call_dom_operator_stream(payload) {
    if (!dom_valid) return;
    std::ostringstream os;
    REPORT("dom::operator<<", os << dom_current, bool(os));
}

/* arrays */
/* ltl: dom_one_document_per_parser, dom_array_view */
static void call_dom_element_get_array(payload) {
    if (!dom_valid) return;
    if (!preqed_call("dom::element::get_array")) return;
    dom_ares = dom_current.get_array();
    bool ok = !sj::simdjson_result<sj::dom::array>(dom_ares).get(dom_array);
    preqed_result("dom::element::get_array", ok);
    if (!ok) return;
    dom_ait = dom_array.begin();
    dom_aend = dom_array.end();
    dom_array_valid = true;
}
/* ltl: dom_array_view */
static void call_dom_array_size(payload) {
    if (!dom_array_valid) return;
    REPORT("dom::array::size", (void)dom_array.size(), true);
}
/* ltl: dom_array_view */
static void call_dom_array_at(payload in) {
    if (!dom_array_valid) return;
    if (!preqed_call("dom::array::at")) return;
    dom_take("dom::array::at", dom_array.at(byte(in, 0)));
}
/* ltl: dom_array_view */
static void call_dom_array_at_pointer(payload in) {
    if (!dom_array_valid) return;
    if (!preqed_call("dom::array::at_pointer")) return;
    dom_take("dom::array::at_pointer", dom_array.at_pointer(view(in)));
}
/* ltl: dom_array_view */
static void call_dom_array_iterator_deref(payload) {
    if (!dom_array_valid || !(dom_ait != dom_aend)) return;
    if (!preqed_call("dom::array::iterator::operator*")) return;
    dom_current = *dom_ait;
    preqed_result("dom::array::iterator::operator*", true);
    dom_valid = true;
}
/* ltl: dom_array_view */
static void call_dom_array_iterator_advance(payload) {
    if (!dom_array_valid || !(dom_ait != dom_aend)) return;
    REPORT("dom::array::iterator::operator++", ++dom_ait, true);
}

/* objects */
/* ltl: dom_one_document_per_parser, dom_object_view */
static void call_dom_element_get_object(payload) {
    if (!dom_valid) return;
    if (!preqed_call("dom::element::get_object")) return;
    bool ok = !dom_current.get_object().get(dom_object);
    preqed_result("dom::element::get_object", ok);
    if (!ok) return;
    dom_oit = dom_object.begin();
    dom_oend = dom_object.end();
    dom_object_valid = true;
}
/* ltl: dom_object_view */
static void call_dom_object_size(payload) {
    if (!dom_object_valid) return;
    REPORT("dom::object::size", (void)dom_object.size(), true);
}
/* ltl: dom_object_view */
static void call_dom_object_at_key(payload in) {
    if (!dom_object_valid) return;
    if (!preqed_call("dom::object::at_key")) return;
    dom_take("dom::object::at_key", dom_object.at_key(view(in)));
}
/* ltl: dom_object_view */
static void call_dom_object_at_key_case_insensitive(payload in) {
    if (!dom_object_valid) return;
    if (!preqed_call("dom::object::at_key_case_insensitive")) return;
    dom_take("dom::object::at_key_case_insensitive", dom_object.at_key_case_insensitive(view(in)));
}
/* ltl: dom_object_view */
static void call_dom_object_iterator_deref(payload) {
    if (!dom_object_valid || !(dom_oit != dom_oend)) return;
    if (!preqed_call("dom::object::iterator::operator*")) return;
    dom_current = (*dom_oit).value;
    preqed_result("dom::object::iterator::operator*", true);
    dom_valid = true;
}
/* ltl: dom_object_view */
static void call_dom_object_iterator_advance(payload) {
    if (!dom_object_valid || !(dom_oit != dom_oend)) return;
    REPORT("dom::object::iterator::operator++", ++dom_oit, true);
}

/* DOM: files, parser and document assignment, stream statistics */
/* ltl: dom_one_document_per_parser, dom_array_view, dom_object_view, dom_stream_from_parse_many */
static void call_dom_parser_load(payload in) {
    memfile f(in);
    if (f.fd < 0) return;
    dom_reused();
    if (!preqed_call("dom::parser::load")) return;
    dom_take("dom::parser::load", dom_parser->load(f.path));
}
/* ltl: dom_one_document_per_parser, dom_array_view, dom_object_view, dom_stream_from_parse_many */
static void call_dom_parser_load_into_document(payload in) {
    memfile f(in);
    if (f.fd < 0) return;
    dom_reused();
    if (!preqed_call("dom::parser::load_into_document")) return;
    dom_take("dom::parser::load_into_document", dom_parser->load_into_document(*dom_document, f.path));
}
/* ltl: dom_one_document_per_parser, dom_array_view, dom_object_view, dom_stream_from_parse_many */
static void call_dom_parser_load_many(payload in) {
    memfile f(rest(in, 1));
    if (f.fd < 0) return;
    dom_reused();
    size_t batch = byte(in, 0) & 1 ? sj::dom::DEFAULT_BATCH_SIZE : 8192;
    if (!preqed_call("dom::parser::load_many")) return;
    bool ok = !dom_parser->load_many(f.path, batch).get(*dom_stream);
    preqed_result("dom::parser::load_many", ok);
    if (!ok) return;
    dom_sit = dom_stream->begin();
    dom_send = dom_stream->end();
    dom_stream_valid = true;
}

/* move-assigning a fresh parser frees the old one's document and loaded bytes */
/* ltl: dom_one_document_per_parser, dom_array_view, dom_object_view, dom_stream_from_parse_many */
static void call_dom_parser_operator_assign(payload) {
    dom_reused();
    REPORT("dom::parser::operator=", *dom_parser = sj::dom::parser(), true);
}

static void call_dom_parser_set_max_capacity(payload in) {
    size_t cap = (size_t(byte(in, 0)) | size_t(byte(in, 1)) << 8) * 64;  /* "will not allocate or deallocate" (simdjson.h:6675) */
    REPORT("dom::parser::set_max_capacity", dom_parser->set_max_capacity(cap), true);
}

/* replaces the parse_into_document / load_into_document target */
/* ltl: dom_one_document_per_parser, dom_array_view, dom_object_view */
static void call_dom_document_operator_assign(payload) {
    dom_elements_gone();
    REPORT("dom::document::operator=", *dom_document = sj::dom::document(), true);
}
/* the defaulted move-assignment (simdjson.h:6880) overwrites the stream while its stage-1 worker thread still
 * reads it (repro_stream_move_assign.cpp): only a stream that never started is assigned */
/* ltl: dom_stream_from_parse_many */
static void call_dom_document_stream_operator_assign(payload) {
    if (dom_stream_valid) return;
    REPORT("dom::document_stream::operator=", *dom_stream = sj::dom::document_stream(), true);
}
/* ltl: dom_stream_from_parse_many */
static void call_dom_document_stream_size_in_bytes(payload) {
    if (!dom_stream_valid) return;
    REPORT("dom::document_stream::size_in_bytes", (void)dom_stream->size_in_bytes(), true);
}
/* ltl: dom_stream_from_parse_many */
static void call_dom_document_stream_truncated_bytes(payload) {
    if (!dom_stream_valid) return;
    REPORT("dom::document_stream::truncated_bytes", (void)dom_stream->truncated_bytes(), true);
}
/* ltl: dom_stream_from_parse_many */
static void call_dom_document_stream_iterator_current_index(payload) {
    if (!dom_stream_valid || !(dom_sit != dom_send)) return;
    REPORT("dom::document_stream::iterator::current_index", (void)dom_sit.current_index(), true);
}
/* ltl: dom_stream_from_parse_many */
static void call_dom_document_stream_iterator_source(payload) {
    if (!dom_stream_valid || !(dom_sit != dom_send)) return;
    REPORT("dom::document_stream::iterator::source", (void)dom_sit.source(), true);
}

/* DOM: more element routines */

#define DOM_IS(api, method) \
    static void call_dom_element_##method(payload) { \
        if (!dom_valid) return; \
        REPORT(api, (void)dom_current.method(), true); \
    }
/* ltl: dom_one_document_per_parser */
DOM_IS("dom::element::is_array", is_array)
/* ltl: dom_one_document_per_parser */
DOM_IS("dom::element::is_object", is_object)
/* ltl: dom_one_document_per_parser */
DOM_IS("dom::element::is_string", is_string)
/* ltl: dom_one_document_per_parser */
DOM_IS("dom::element::is_bool", is_bool)
/* ltl: dom_one_document_per_parser */
DOM_IS("dom::element::is_null", is_null)
/* ltl: dom_one_document_per_parser */
DOM_IS("dom::element::is_bigint", is_bigint)
/* ltl: dom_one_document_per_parser */
static void call_dom_element_at_path(payload in) {
    if (!dom_valid) return;
    if (!preqed_call("dom::element::at_path")) return;
    dom_take("dom::element::at_path", dom_current.at_path(view(in)));
}
/* ltl: dom_one_document_per_parser */
static void call_dom_element_at_path_with_wildcard(payload in) {
    if (!dom_valid) return;
    REPORT("dom::element::at_path_with_wildcard", auto r = dom_current.at_path_with_wildcard(view(in)), !r.error());
}
/* ltl: dom_one_document_per_parser */
static void call_dom_element_subscript(payload in) {
    if (!dom_valid) return;
    if (!preqed_call("dom::element::operator[]")) return;
    dom_take("dom::element::operator[]", dom_current[view(in)]);
}

#define DOM_CONVERT(name, api, T) \
    static void call_dom_element_to_##name(payload) { \
        if (!dom_valid) return; \
        THROWING(api, T v = dom_current.operator T(); (void)v); \
    }
/* ltl: dom_one_document_per_parser */
DOM_CONVERT(bool, "dom::element::operator(bool)", bool)
/* ltl: dom_one_document_per_parser */
DOM_CONVERT(c_str, "dom::element::operator(const_char_*)", const char *)
/* ltl: dom_one_document_per_parser */
DOM_CONVERT(string_view, "dom::element::operator(string_view)", std::string_view)
/* ltl: dom_one_document_per_parser */
DOM_CONVERT(uint64, "dom::element::operator(uint64_t)", uint64_t)
/* ltl: dom_one_document_per_parser */
DOM_CONVERT(int64, "dom::element::operator(int64_t)", int64_t)
/* ltl: dom_one_document_per_parser */
DOM_CONVERT(double, "dom::element::operator(double)", double)
/* ltl: dom_one_document_per_parser */
DOM_CONVERT(array, "dom::element::operator(array)", sj::dom::array)
/* ltl: dom_one_document_per_parser */
DOM_CONVERT(object, "dom::element::operator(object)", sj::dom::object)
/* ltl: dom_one_document_per_parser */
static void call_dom_element_begin(payload) {
    if (!dom_valid) return;
    THROWING("dom::element::begin", (void)dom_current.begin());
}
/* ltl: dom_one_document_per_parser */
static void call_dom_element_end(payload) {
    if (!dom_valid) return;
    THROWING("dom::element::end", (void)dom_current.end());
}
/* ltl: dom_one_document_per_parser */
static void call_dom_element_less(payload) {
    if (!dom_valid || !dom_prev_valid) return;
    REPORT("dom::element::operator<", (void)(dom_current < dom_prev), true);
}
/* ltl: dom_one_document_per_parser */
static void call_dom_element_equal(payload) {
    if (!dom_valid || !dom_prev_valid) return;
    REPORT("dom::element::operator==", (void)(dom_current == dom_prev), true);
}
/* ltl: dom_one_document_per_parser */
static void call_dom_element_tie(payload) {
    if (!dom_valid) return;
    int64_t v;
    sj::error_code ec;
    REPORT("dom::element::tie", sj::dom::element(dom_current).tie(v, ec), ec == sj::SUCCESS);
}

/* serialisation of the current element */
/* ltl: dom_one_document_per_parser */
static void call_to_string(payload) {
    if (!dom_valid) return;
    REPORT("to_string", (void)sj::to_string(dom_current), true);
}
/* ltl: dom_one_document_per_parser */
static void call_prettify(payload) {
    if (!dom_valid) return;
    REPORT("prettify", (void)sj::prettify(dom_current), true);
}
/* ltl: dom_one_document_per_parser */
static void call_fractured_json(payload) {
    if (!dom_valid) return;
    REPORT("fractured_json", (void)sj::fractured_json(dom_current), true);
}

/* DOM: more array and object routines */
/* ltl: dom_array_view */
static void call_dom_array_at_path(payload in) {
    if (!dom_array_valid) return;
    if (!preqed_call("dom::array::at_path")) return;
    dom_take("dom::array::at_path", dom_array.at_path(view(in)));
}
/* ltl: dom_array_view */
static void call_dom_array_at_path_with_wildcard(payload in) {
    if (!dom_array_valid) return;
    REPORT("dom::array::at_path_with_wildcard", auto r = dom_array.at_path_with_wildcard(view(in)), !r.error());
}
/* ltl: dom_array_view */
static void call_dom_array_get_values(payload) {
    if (!dom_array_valid) return;
    std::vector<sj::dom::element> out;
    REPORT("dom::array::get_values", dom_array.get_values(out), true);
}
/* ltl: dom_array_view */
static void call_dom_array_number_of_slots(payload) {
    if (!dom_array_valid) return;
    REPORT("dom::array::number_of_slots", (void)dom_array.number_of_slots(), true);
}
/* ltl: dom_array_view */
static void call_dom_array_to_element(payload) {
    if (!dom_array_valid) return;
    REPORT("dom::array::operator(element)", dom_current = dom_array.operator sj::dom::element(), true);
    dom_valid = true;
}

#define DOM_ITER_CMP(name, api, valid, it, end, op) \
    static void call_##name(payload) { \
        if (!(valid)) return; \
        REPORT(api, (void)(it op end), true); \
    }
/* ltl: dom_array_view */
DOM_ITER_CMP(dom_array_iterator_eq, "dom::array::iterator::operator==", dom_array_valid, dom_ait, dom_aend, ==)
/* ltl: dom_array_view */
DOM_ITER_CMP(dom_array_iterator_lt, "dom::array::iterator::operator<", dom_array_valid, dom_ait, dom_aend, <)
/* ltl: dom_array_view */
DOM_ITER_CMP(dom_array_iterator_le, "dom::array::iterator::operator<=", dom_array_valid, dom_ait, dom_aend, <=)
/* ltl: dom_array_view */
DOM_ITER_CMP(dom_array_iterator_gt, "dom::array::iterator::operator>", dom_array_valid, dom_ait, dom_aend, >)
/* ltl: dom_array_view */
DOM_ITER_CMP(dom_array_iterator_ge, "dom::array::iterator::operator>=", dom_array_valid, dom_ait, dom_aend, >=)
/* ltl: dom_object_view */
DOM_ITER_CMP(dom_object_iterator_eq, "dom::object::iterator::operator==", dom_object_valid, dom_oit, dom_oend, ==)
/* ltl: dom_object_view */
DOM_ITER_CMP(dom_object_iterator_lt, "dom::object::iterator::operator<", dom_object_valid, dom_oit, dom_oend, <)
/* ltl: dom_object_view */
DOM_ITER_CMP(dom_object_iterator_le, "dom::object::iterator::operator<=", dom_object_valid, dom_oit, dom_oend, <=)
/* ltl: dom_object_view */
DOM_ITER_CMP(dom_object_iterator_gt, "dom::object::iterator::operator>", dom_object_valid, dom_oit, dom_oend, >)
/* ltl: dom_object_view */
DOM_ITER_CMP(dom_object_iterator_ge, "dom::object::iterator::operator>=", dom_object_valid, dom_oit, dom_oend, >=)
/* ltl: dom_object_view */
static void call_dom_object_at_path(payload in) {
    if (!dom_object_valid) return;
    if (!preqed_call("dom::object::at_path")) return;
    dom_take("dom::object::at_path", dom_object.at_path(view(in)));
}
/* ltl: dom_object_view */
static void call_dom_object_at_path_with_wildcard(payload in) {
    if (!dom_object_valid) return;
    REPORT("dom::object::at_path_with_wildcard", auto r = dom_object.at_path_with_wildcard(view(in)), !r.error());
}
/* ltl: dom_object_view */
static void call_dom_object_get_values(payload) {
    if (!dom_object_valid) return;
    std::vector<sj::dom::element> out;
    REPORT("dom::object::get_values", dom_object.get_values(out), true);
}
/* ltl: dom_object_view */
static void call_dom_object_subscript(payload in) {
    if (!dom_object_valid) return;
    if (!preqed_call("dom::object::operator[]")) return;
    dom_take("dom::object::operator[]", dom_object[view(in)]);
}
/* ltl: dom_object_view */
static void call_dom_object_to_element(payload) {
    if (!dom_object_valid) return;
    REPORT("dom::object::operator(element)", dom_current = dom_object.operator sj::dom::element(), true);
    dom_valid = true;
}

/* DOM results: the simdjson_result<element> of the last navigation, chained as in doc/basics.md */

#define DOM_RES_GET(api, method) \
    static void call_dom_res_##method(payload) { \
        if (!dom_res_valid) return; \
        REPORT(api, auto r = dom_res.method(), !r.error()); \
    }
/* ltl: dom_one_document_per_parser */
DOM_RES_GET("simdjson_result<dom::element>::type", type)
/* ltl: dom_one_document_per_parser */
DOM_RES_GET("simdjson_result<dom::element>::get_array", get_array)
/* ltl: dom_one_document_per_parser */
DOM_RES_GET("simdjson_result<dom::element>::get_object", get_object)
/* ltl: dom_one_document_per_parser */
DOM_RES_GET("simdjson_result<dom::element>::get_c_str", get_c_str)
/* ltl: dom_one_document_per_parser */
DOM_RES_GET("simdjson_result<dom::element>::get_string_length", get_string_length)
/* ltl: dom_one_document_per_parser */
DOM_RES_GET("simdjson_result<dom::element>::get_string", get_string)
/* ltl: dom_one_document_per_parser */
DOM_RES_GET("simdjson_result<dom::element>::get_int64", get_int64)
/* ltl: dom_one_document_per_parser */
DOM_RES_GET("simdjson_result<dom::element>::get_uint64", get_uint64)
/* ltl: dom_one_document_per_parser */
DOM_RES_GET("simdjson_result<dom::element>::get_double", get_double)
/* ltl: dom_one_document_per_parser */
DOM_RES_GET("simdjson_result<dom::element>::get_bool", get_bool)
/* ltl: dom_one_document_per_parser */
DOM_RES_GET("simdjson_result<dom::element>::get_bigint", get_bigint)
/* the is_* checks answer false on an error result */
#define DOM_RES_IS(api, method) \
    static void call_dom_res_##method(payload) { \
        if (!dom_res_valid) return; \
        REPORT(api, (void)dom_res.method(), true); \
    }
/* ltl: dom_one_document_per_parser */
DOM_RES_IS("simdjson_result<dom::element>::is_array", is_array)
/* ltl: dom_one_document_per_parser */
DOM_RES_IS("simdjson_result<dom::element>::is_object", is_object)
/* ltl: dom_one_document_per_parser */
DOM_RES_IS("simdjson_result<dom::element>::is_string", is_string)
/* ltl: dom_one_document_per_parser */
DOM_RES_IS("simdjson_result<dom::element>::is_int64", is_int64)
/* ltl: dom_one_document_per_parser */
DOM_RES_IS("simdjson_result<dom::element>::is_uint64", is_uint64)
/* ltl: dom_one_document_per_parser */
DOM_RES_IS("simdjson_result<dom::element>::is_double", is_double)
/* ltl: dom_one_document_per_parser */
DOM_RES_IS("simdjson_result<dom::element>::is_number", is_number)
/* ltl: dom_one_document_per_parser */
DOM_RES_IS("simdjson_result<dom::element>::is_bool", is_bool)
/* ltl: dom_one_document_per_parser */
DOM_RES_IS("simdjson_result<dom::element>::is_null", is_null)
/* ltl: dom_one_document_per_parser */
DOM_RES_IS("simdjson_result<dom::element>::is_bigint", is_bigint)
/* ltl: dom_one_document_per_parser */
static void call_dom_res_is(payload) {
    if (!dom_res_valid) return;
    REPORT("simdjson_result<dom::element>::is", (void)dom_res.is<int64_t>(), true);
}
/* ltl: dom_one_document_per_parser */
static void call_dom_res_subscript(payload in) {
    if (!dom_res_valid) return;
    if (!preqed_call("simdjson_result<dom::element>::operator[]")) return;
    dom_take("simdjson_result<dom::element>::operator[]", dom_res[view(in)]);
}
/* ltl: dom_one_document_per_parser */
static void call_dom_res_at_path(payload in) {
    if (!dom_res_valid) return;
    if (!preqed_call("simdjson_result<dom::element>::at_path")) return;
    dom_take("simdjson_result<dom::element>::at_path", dom_res.at_path(view(in)));
}
/* ltl: dom_one_document_per_parser */
static void call_dom_res_at_path_with_wildcard(payload in) {
    if (!dom_res_valid) return;
    REPORT("simdjson_result<dom::element>::at_path_with_wildcard", auto r = dom_res.at_path_with_wildcard(view(in)), !r.error());
}

#define DOM_RES_CONVERT(name, api, T) \
    static void call_dom_res_to_##name(payload) { \
        if (!dom_res_valid) return; \
        THROWING(api, T v = dom_res.operator T(); (void)v); \
    }
/* ltl: dom_one_document_per_parser */
DOM_RES_CONVERT(bool, "simdjson_result<dom::element>::operator(bool)", bool)
/* ltl: dom_one_document_per_parser */
DOM_RES_CONVERT(c_str, "simdjson_result<dom::element>::operator(const_char_*)", const char *)
/* ltl: dom_one_document_per_parser */
DOM_RES_CONVERT(string_view, "simdjson_result<dom::element>::operator(string_view)", std::string_view)
/* ltl: dom_one_document_per_parser */
DOM_RES_CONVERT(uint64, "simdjson_result<dom::element>::operator(uint64_t)", uint64_t)
/* ltl: dom_one_document_per_parser */
DOM_RES_CONVERT(int64, "simdjson_result<dom::element>::operator(int64_t)", int64_t)
/* ltl: dom_one_document_per_parser */
DOM_RES_CONVERT(double, "simdjson_result<dom::element>::operator(double)", double)
/* ltl: dom_one_document_per_parser */
DOM_RES_CONVERT(array, "simdjson_result<dom::element>::operator(array)", sj::dom::array)
/* ltl: dom_one_document_per_parser */
DOM_RES_CONVERT(object, "simdjson_result<dom::element>::operator(object)", sj::dom::object)
/* ltl: dom_one_document_per_parser */
static void call_dom_res_begin(payload) {
    if (!dom_res_valid) return;
    THROWING("simdjson_result<dom::element>::begin", (void)dom_res.begin());
}
/* ltl: dom_one_document_per_parser */
static void call_dom_res_end(payload) {
    if (!dom_res_valid) return;
    THROWING("simdjson_result<dom::element>::end", (void)dom_res.end());
}
/* ltl: dom_array_view */
static void call_dom_ares_size(payload) {
    if (!dom_array_valid) return;
    THROWING("simdjson_result<dom::array>::size", (void)dom_ares.size());
}
/* ltl: dom_array_view */
static void call_dom_ares_get_values(payload) {
    if (!dom_array_valid) return;
    std::vector<sj::dom::element> out;
    THROWING("simdjson_result<dom::array>::get_values", dom_ares.get_values(out));
}

/* plain simdjson_result<T> (here the int64_t of get_int64): value(), take_value(), operator T&&, tie */
/* ltl: dom_one_document_per_parser */
static void call_result_value(payload) {
    if (!dom_valid) return;
    auto r = dom_current.get_int64();
    THROWING("simdjson_result<int64_t>::value", (void)r.value());
}
/* ltl: dom_one_document_per_parser */
static void call_result_take_value(payload) {
    if (!dom_valid) return;
    auto r = dom_current.get_int64();
    THROWING("simdjson_result<int64_t>::take_value", (void)std::move(r).take_value());
}
/* ltl: dom_one_document_per_parser */
static void call_result_operator_rvalue(payload) {
    if (!dom_valid) return;
    auto r = dom_current.get_int64();
    THROWING("simdjson_result<int64_t>::operator(int64_t&&)", int64_t v = std::move(r); (void)v);
}
/* ltl: dom_one_document_per_parser */
static void call_result_tie(payload) {
    if (!dom_valid) return;
    int64_t v;
    sj::error_code ec;
    REPORT("simdjson_result<int64_t>::tie", dom_current.get_int64().tie(v, ec), ec == sj::SUCCESS);
}

/* On-Demand: one parser, one document, and one live value / array / object / field / stream */

static sj::ondemand::parser *od_parser;
static sj::padded_string *od_input;            /* the document iterates over this buffer */
static sj::ondemand::document *od_doc;
static bool od_doc_valid, od_doc_consumed;
static sj::ondemand::value od_value;
static bool od_value_valid;
static sj::ondemand::array od_array;
static sj::ondemand::array_iterator od_ait, od_aend;
static bool od_array_valid;
static sj::ondemand::object od_object;
static sj::ondemand::object_iterator od_oit, od_oend;
static bool od_object_valid;
static sj::ondemand::field od_field;
static bool od_field_valid;
static sj::ondemand::document_stream *od_stream;
static sj::ondemand::document_stream::iterator od_sit, od_send;
static bool od_stream_valid, od_stream_started;   /* started: its stage-1 worker may run */
static sj::ondemand::document_reference od_ref;   /* valid until the stream iterator advances */
static bool od_ref_valid, od_ref_consumed;
static sj::simdjson_result<sj::ondemand::document_reference> od_rres;  /* the stream dereference behind od_ref */
static sj::simdjson_result<sj::ondemand::value> od_vres;      /* a lookup result, chained as in doc/basics.md */
static bool od_vres_valid;
static sj::simdjson_result<sj::ondemand::array_iterator> od_rit, od_rend;  /* begin()/end() of a document or value */
static bool od_riter_valid, od_rit_deref, od_rend_set;
static sj::simdjson_result<sj::ondemand::array> od_arres;     /* the get_array result behind od_array */
static sj::simdjson_result<sj::ondemand::object> od_ores;     /* the get_object result behind od_object */
static bool od_array_fresh, od_object_fresh;   /* created and not yet accessed */
static bool od_ait_deref, od_oit_deref;        /* operator* "MUST ONLY BE CALLED ONCE PER ITERATION" (simdjson.h:87207, 90950) */
static sj::simdjson_result<sj::ondemand::field> od_fres;      /* the dereference behind od_field */
static bool od_key_used;                       /* unescaped_key() consumed the key */
static sj::ondemand::number od_number;
static bool od_number_valid;
static sj::ondemand::raw_json_string od_raw;   /* points into od_input */
static bool od_raw_valid;

/* rewind() and at_pointer "invalidate all values, objects and arrays" (doc/basics.md, Rewinding) */
static void od_views_reset() {
    od_value_valid = od_array_valid = od_object_valid = od_field_valid = od_vres_valid = od_riter_valid = false;
}

/* "A parser instance can only be used for one document at a time" */
static void od_parser_reused() {
    od_views_reset();
    od_doc_valid = od_stream_valid = od_ref_valid = od_raw_valid = false;
}

static bool od_ref_ready() { return od_ref_valid && !od_ref_consumed; }

/* as for parse_many: the stream's stage-1 worker thread may still read od_input, so destroy the stream (which
 * stops the thread) before od_input is replaced or the parser is reassigned */
static void od_stream_close() {
    od_stream_valid = od_stream_started = od_ref_valid = false;
    delete od_stream;    /* not move-assignment: that races with the worker (repro_stream_move_assign.cpp) */
    od_stream = new sj::ondemand::document_stream();
}

static bool od_doc_ready() { return od_doc_valid && !od_doc_consumed; }

/* INCOMPLETE_ARRAY_OR_OBJECT / TAPE_ERROR are fatal: "the document instance cannot be used" and
 * doc.is_alive() turns false (doc/basics.md, error handling). Check after every failed operation. */
/* ltl: ondemand_one_document_per_parser, ondemand_value_consumed_once, ondemand_array_view, ondemand_object_view, ondemand_stream_from_iterate_many, ondemand_value_result_consumed_once, ondemand_array_iterator_result */
static void od_after(bool ok) {
    if (ok || !(od_doc_valid || od_ref_valid)) return;
    if (!preqed_call("ondemand::document::is_alive")) return;
    /* a stream document is reached through its document_reference */
    bool alive;
    if (od_doc_valid) alive = od_doc->is_alive();
    else { sj::ondemand::document &d = od_ref; alive = d.is_alive(); }
    preqed_result("ondemand::document::is_alive", alive);
    if (!alive) od_parser_reused();
}

/* conversion operators of On-Demand values throw instead of returning an error */
#define OD_THROWING(api, stmt) \
    do { if (preqed_call(api)) { bool ok_ = true; try { stmt; } catch (const sj::simdjson_error &) { ok_ = false; } preqed_result(api, ok_); od_after(ok_); } } while (0)

#define OD_REPORT(api, expr) \
    do { if (preqed_call(api)) { bool ok_ = !(expr).error(); preqed_result(api, ok_); od_after(ok_); } } while (0)
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once, ondemand_value_consumed_once, ondemand_array_view, ondemand_object_view, ondemand_stream_from_iterate_many, ondemand_value_result_consumed_once, ondemand_array_iterator_result, ondemand_raw_json_string_input */
static void call_ondemand_parser_iterate(payload in) {
    od_parser_reused();
    od_stream_close();
    *od_input = sj::padded_string(view(in));
    if (!preqed_call("ondemand::parser::iterate")) return;
    bool ok = !od_parser->iterate(*od_input).get(*od_doc);
    preqed_result("ondemand::parser::iterate", ok);
    od_doc_valid = ok;
    od_doc_consumed = false;
}
/* ltl: ondemand_one_document_per_parser, ondemand_value_consumed_once, ondemand_array_view, ondemand_object_view, ondemand_stream_from_iterate_many, ondemand_value_result_consumed_once, ondemand_document_reference_read_once, ondemand_array_iterator_result, ondemand_raw_json_string_input */
static void call_ondemand_parser_iterate_many(payload in) {
    od_parser_reused();
    od_stream_close();
    *od_input = sj::padded_string(view(rest(in, 1)));
    auto format = byte(in, 0) & 1 ? sj::stream_format::comma_delimited : sj::stream_format::whitespace_delimited;
    if (!preqed_call("ondemand::parser::iterate_many")) return;
    bool ok = !od_parser->iterate_many(*od_input, 8192, format).get(*od_stream);  /* 8 KiB batches, as in parse_many */
    preqed_result("ondemand::parser::iterate_many", ok);
    if (!ok) return;
    od_sit = od_stream->begin();
    od_send = od_stream->end();
    od_stream_valid = od_stream_started = true;
    od_ref_consumed = false;
}
/* ltl: ondemand_stream_from_iterate_many */
static void call_ondemand_document_stream_next(payload) {
    if (!od_stream_valid || !(od_sit != od_send)) return;
    if (!preqed_call("ondemand::document_stream::iterator::operator*")) return;
    od_rres = *od_sit;
    bool ok = !sj::simdjson_result<sj::ondemand::document_reference>(od_rres).get(od_ref);
    preqed_result("ondemand::document_stream::iterator::operator*", ok);
    od_ref_valid = ok;
}
/* ltl: ondemand_stream_from_iterate_many */
static void call_ondemand_document_reference_type(payload) {
    if (!od_ref_valid) return;
    REPORT("ondemand::document_reference::type", auto t = od_ref.type(), !t.error());
}
/* ltl: ondemand_value_consumed_once, ondemand_array_view, ondemand_object_view, ondemand_stream_from_iterate_many, ondemand_value_result_consumed_once, ondemand_document_reference_read_once, ondemand_array_iterator_result */
static void call_ondemand_document_stream_advance(payload) {
    if (!od_stream_valid || !(od_sit != od_send)) return;
    od_ref_valid = od_ref_consumed = false;
    od_views_reset();   /* values of the previous document go with it */
    REPORT("ondemand::document_stream::iterator::operator++", ++od_sit, true);
}
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once, ondemand_value_consumed_once, ondemand_array_view, ondemand_object_view, ondemand_value_result_consumed_once, ondemand_array_iterator_result */
static void call_ondemand_document_rewind(payload) {
    if (!od_doc_valid) return;
    od_views_reset();
    REPORT("ondemand::document::rewind", od_doc->rewind(), true);
    od_doc_consumed = false;
}

/* document scalar accessors consume the document */

#define OD_DOC_GET(api, method) \
    static void call_od_doc_##method(payload) { \
        if (!od_doc_ready()) return; \
        od_doc_consumed = true; \
        OD_REPORT(api, od_doc->method()); \
    }
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once */
OD_DOC_GET("ondemand::document::get_int64", get_int64)
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once */
OD_DOC_GET("ondemand::document::get_uint64", get_uint64)
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once */
OD_DOC_GET("ondemand::document::get_double", get_double)
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once */
OD_DOC_GET("ondemand::document::get_bool", get_bool)
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once */
OD_DOC_GET("ondemand::document::get_string", get_string)
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once */
OD_DOC_GET("ondemand::document::get_raw_json_string", get_raw_json_string)
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once */
OD_DOC_GET("ondemand::document::get_number", get_number)
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once */
OD_DOC_GET("ondemand::document::is_null", is_null)
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once */
OD_DOC_GET("ondemand::document::raw_json", raw_json)
/* ltl: ondemand_one_document_per_parser */
static void call_od_doc_type(payload) {
    if (!od_doc_ready()) return;
    OD_REPORT("ondemand::document::type", od_doc->type());
}

/* document accessors that produce a view */
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once, ondemand_value_consumed_once */
static void call_od_doc_get_value(payload) {
    if (!od_doc_ready()) return;
    od_doc_consumed = true;
    if (!preqed_call("ondemand::document::get_value")) return;
    bool ok = !od_doc->get_value().get(od_value);
    preqed_result("ondemand::document::get_value", ok);
    od_after(ok);
    od_value_valid = ok;
}
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once, ondemand_value_consumed_once */
static void call_od_doc_find_field(payload in) {
    if (!od_doc_ready()) return;
    od_doc_consumed = true;
    if (!preqed_call("ondemand::document::find_field")) return;
    bool ok = !od_doc->find_field(view(in)).get(od_value);
    preqed_result("ondemand::document::find_field", ok);
    od_after(ok);
    od_value_valid = ok;
}

/* at_pointer rewinds the document first, so it is legal at any point while the document lives */
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once, ondemand_value_consumed_once, ondemand_array_view, ondemand_object_view, ondemand_value_result_consumed_once, ondemand_array_iterator_result */
static void call_od_doc_at_pointer(payload in) {
    if (!od_doc_valid) return;
    od_views_reset();
    od_doc_consumed = true;
    if (!preqed_call("ondemand::document::at_pointer")) return;
    bool ok = !od_doc->at_pointer(view(in)).get(od_value);
    preqed_result("ondemand::document::at_pointer", ok);
    od_after(ok);
    od_value_valid = ok;
}

static void od_begin_array(const char *api, sj::simdjson_result<sj::ondemand::array> r) {
    od_arres = r;
    bool ok = !std::move(r).get(od_array);
    if (ok) ok = !od_array.begin().get(od_ait) && !od_array.end().get(od_aend);
    preqed_result(api, ok);
    od_array_valid = od_array_fresh = ok;
    od_ait_deref = false;
    od_after(ok);
}

static void od_begin_object(const char *api, sj::simdjson_result<sj::ondemand::object> r) {
    od_ores = r;
    bool ok = !std::move(r).get(od_object);
    if (ok) ok = !od_object.begin().get(od_oit) && !od_object.end().get(od_oend);
    preqed_result(api, ok);
    od_object_valid = od_object_fresh = ok;
    od_oit_deref = false;
    od_after(ok);
}
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once, ondemand_array_view */
static void call_od_doc_get_array(payload) {
    if (!od_doc_ready()) return;
    od_doc_consumed = true;
    if (!preqed_call("ondemand::document::get_array")) return;
    od_begin_array("ondemand::document::get_array", od_doc->get_array());
}
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once, ondemand_object_view */
static void call_od_doc_get_object(payload) {
    if (!od_doc_ready()) return;
    od_doc_consumed = true;
    if (!preqed_call("ondemand::document::get_object")) return;
    od_begin_object("ondemand::document::get_object", od_doc->get_object());
}

/* values: consumed once (doc/basics.md rule 3); type() only peeks */
/* ltl: ondemand_value_consumed_once */
static void call_od_value_type(payload) {
    if (!od_value_valid) return;
    OD_REPORT("ondemand::value::type", od_value.type());
}

#define OD_VALUE_GET(api, method) \
    static void call_od_value_##method(payload) { \
        if (!od_value_valid) return; \
        od_value_valid = false; \
        OD_REPORT(api, od_value.method()); \
    }
/* ltl: ondemand_value_consumed_once */
OD_VALUE_GET("ondemand::value::get_int64", get_int64)
/* ltl: ondemand_value_consumed_once */
OD_VALUE_GET("ondemand::value::get_uint64", get_uint64)
/* ltl: ondemand_value_consumed_once */
OD_VALUE_GET("ondemand::value::get_double", get_double)
/* ltl: ondemand_value_consumed_once */
OD_VALUE_GET("ondemand::value::get_bool", get_bool)
/* ltl: ondemand_value_consumed_once */
OD_VALUE_GET("ondemand::value::get_string", get_string)
/* ltl: ondemand_value_consumed_once */
OD_VALUE_GET("ondemand::value::get_number", get_number)
/* ltl: ondemand_value_consumed_once */
OD_VALUE_GET("ondemand::value::is_null", is_null)
/* ltl: ondemand_value_consumed_once */
OD_VALUE_GET("ondemand::value::raw_json", raw_json)
/* ltl: ondemand_value_consumed_once, ondemand_array_view */
static void call_od_value_get_array(payload) {
    if (!od_value_valid) return;
    od_value_valid = false;
    if (!preqed_call("ondemand::value::get_array")) return;
    od_begin_array("ondemand::value::get_array", od_value.get_array());
}
/* ltl: ondemand_value_consumed_once, ondemand_object_view */
static void call_od_value_get_object(payload) {
    if (!od_value_valid) return;
    od_value_valid = false;
    if (!preqed_call("ondemand::value::get_object")) return;
    od_begin_object("ondemand::value::get_object", od_value.get_object());
}

/* array iteration: deref yields the child value, ++ skips it if unused */
/* ltl: ondemand_value_consumed_once, ondemand_array_view */
static void call_od_array_iterator_deref(payload) {
    if (!od_array_valid || !(od_ait != od_aend) || od_ait_deref) return;
    od_ait_deref = true;
    od_array_fresh = od_vres_valid = false;
    if (!preqed_call("ondemand::array_iterator::operator*")) return;
    bool ok = !(*od_ait).get(od_value);
    preqed_result("ondemand::array_iterator::operator*", ok);
    od_after(ok);
    od_value_valid = ok;
    if (!ok) od_array_valid = false;
}
/* ltl: ondemand_value_consumed_once, ondemand_array_view, ondemand_array_iterator_result */
static void call_od_array_iterator_advance(payload) {
    if (!od_array_valid || !(od_ait != od_aend)) return;
    od_value_valid = od_vres_valid = od_riter_valid = od_array_fresh = od_ait_deref = false;
    REPORT("ondemand::array_iterator::operator++", ++od_ait, true);
}

/* object iteration */
/* ltl: ondemand_object_view, ondemand_field_key_once */
static void call_od_object_iterator_deref(payload) {
    if (!od_object_valid || !(od_oit != od_oend) || od_oit_deref) return;
    od_oit_deref = true;
    od_object_fresh = false;
    if (!preqed_call("ondemand::object_iterator::operator*")) return;
    od_fres = *od_oit;
    od_key_used = false;
    bool ok = !sj::simdjson_result<sj::ondemand::field>(od_fres).get(od_field);
    preqed_result("ondemand::object_iterator::operator*", ok);
    od_after(ok);
    od_field_valid = ok;
    if (!ok) od_object_valid = false;
}
/* ltl: ondemand_value_consumed_once, ondemand_object_view, ondemand_array_iterator_result */
static void call_od_object_iterator_advance(payload) {
    if (!od_object_valid || !(od_oit != od_oend)) return;
    od_field_valid = od_value_valid = od_vres_valid = od_riter_valid = od_object_fresh = od_oit_deref = false;
    REPORT("ondemand::object_iterator::operator++", ++od_oit, true);
}

/* "This consumes the key: once you have called unescaped_key(), you cannot call it again nor can you call
 * key()" (simdjson.h:88860) */
/* ltl: ondemand_field_key_once */
static void call_od_field_unescaped_key(payload) {
    if (!od_field_valid || od_key_used) return;
    od_key_used = true;
    OD_REPORT("ondemand::field::unescaped_key", od_field.unescaped_key());
}
/* ltl: ondemand_value_consumed_once */
static void call_od_field_value(payload) {
    if (!od_field_valid) return;
    od_field_valid = od_vres_valid = false;
    REPORT("ondemand::field::value", od_value = od_field.value(), true);
    od_value_valid = true;
}
/* ltl: ondemand_value_consumed_once, ondemand_object_view */
static void call_od_object_find_field(payload in) {
    if (!od_object_valid) return;
    od_field_valid = od_vres_valid = od_object_fresh = false;
    if (!preqed_call("ondemand::object::find_field")) return;
    bool ok = !od_object.find_field(view(in)).get(od_value);
    preqed_result("ondemand::object::find_field", ok);
    od_after(ok);
    od_value_valid = ok;
}

/* On-Demand: lookup results (simdjson_result<value>) and begin()/end() iterator results */

/* one value view at a time: a new result replaces the current value and field */
static void od_take_vres(const char *api, sj::simdjson_result<sj::ondemand::value> r) {
    bool ok = !r.error();
    preqed_result(api, ok);
    od_after(ok);
    od_value_valid = od_field_valid = false;
    od_vres = r;
    od_vres_valid = ok;
}

static void od_take_riter(const char *api, sj::simdjson_result<sj::ondemand::array_iterator> r) {
    bool ok = !r.error();
    preqed_result(api, ok);
    od_after(ok);
    od_rit = r;
    od_riter_valid = ok;
    od_rit_deref = false;
}

static void od_noop(sj::ondemand::value) {}

/* On-Demand: more document routines */
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once */
OD_DOC_GET("ondemand::document::get_int32", get_int32)
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once */
OD_DOC_GET("ondemand::document::get_uint32", get_uint32)
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once */
OD_DOC_GET("ondemand::document::get_int64_in_string", get_int64_in_string)
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once */
OD_DOC_GET("ondemand::document::get_uint64_in_string", get_uint64_in_string)
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once */
OD_DOC_GET("ondemand::document::get_double_in_string", get_double_in_string)
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once */
OD_DOC_GET("ondemand::document::get_wobbly_string", get_wobbly_string)
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once */
static void call_od_doc_get(payload) {
    if (!od_doc_ready()) return;
    od_doc_consumed = true;
    OD_REPORT("ondemand::document::get", od_doc->get<double>());
}

/* type inspection does not consume the document */
#define OD_DOC_PEEK(api, method) \
    static void call_od_doc_##method(payload) { \
        if (!od_doc_ready()) return; \
        OD_REPORT(api, od_doc->method()); \
    }
/* ltl: ondemand_one_document_per_parser */
OD_DOC_PEEK("ondemand::document::is_integer", is_integer)
/* ltl: ondemand_one_document_per_parser */
OD_DOC_PEEK("ondemand::document::is_string", is_string)
/* ltl: ondemand_one_document_per_parser */
OD_DOC_PEEK("ondemand::document::get_number_type", get_number_type)
/* ltl: ondemand_one_document_per_parser */
OD_DOC_PEEK("ondemand::document::raw_json_token", raw_json_token)
/* ltl: ondemand_one_document_per_parser */
static void call_od_doc_is_negative(payload) {
    if (!od_doc_ready()) return;
    REPORT("ondemand::document::is_negative", (void)od_doc->is_negative(), true);
}
/* ltl: ondemand_one_document_per_parser */
static void call_od_doc_current_location(payload) {
    if (!od_doc_valid) return;
    REPORT("ondemand::document::current_location", (void)od_doc->current_location(), true);
}
/* ltl: ondemand_one_document_per_parser */
static void call_od_doc_current_depth(payload) {
    if (!od_doc_valid) return;
    REPORT("ondemand::document::current_depth", (void)od_doc->current_depth(), true);
}
/* ltl: ondemand_one_document_per_parser */
static void call_od_doc_at_end(payload) {
    if (!od_doc_valid) return;
    REPORT("ondemand::document::at_end", (void)od_doc->at_end(), true);
}

/* count_elements / count_fields read the root container and rewind on success (simdjson.h:93314) */
#define OD_DOC_COUNT(api, method) \
    static void call_od_doc_##method(payload) { \
        if (!od_doc_ready()) return; \
        od_doc_consumed = true; \
        if (!preqed_call(api)) return; \
        bool ok = !od_doc->method().error(); \
        preqed_result(api, ok); \
        od_after(ok); \
        if (ok) od_doc_consumed = false; \
    }
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once */
OD_DOC_COUNT("ondemand::document::count_elements", count_elements)
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once */
OD_DOC_COUNT("ondemand::document::count_fields", count_fields)
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once, ondemand_value_result_consumed_once */
static void call_od_doc_find_field_unordered(payload in) {
    if (!od_doc_ready()) return;
    od_doc_consumed = true;
    if (!preqed_call("ondemand::document::find_field_unordered")) return;
    od_take_vres("ondemand::document::find_field_unordered", od_doc->find_field_unordered(view(in)));
}
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once, ondemand_value_result_consumed_once */
static void call_od_doc_subscript(payload in) {
    if (!od_doc_ready()) return;
    od_doc_consumed = true;
    if (!preqed_call("ondemand::document::operator[]")) return;
    od_take_vres("ondemand::document::operator[]", (*od_doc)[view(in)]);
}

/* at_path and for_each_at_path_with_wildcard rewind the document first, as at_pointer does */
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once, ondemand_value_consumed_once, ondemand_array_view, ondemand_object_view, ondemand_value_result_consumed_once, ondemand_array_iterator_result */
static void call_od_doc_at_path(payload in) {
    if (!od_doc_valid) return;
    od_views_reset();
    od_doc_consumed = true;
    if (!preqed_call("ondemand::document::at_path")) return;
    od_take_vres("ondemand::document::at_path", od_doc->at_path(view(in)));
}
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once, ondemand_value_consumed_once, ondemand_array_view, ondemand_object_view, ondemand_value_result_consumed_once, ondemand_array_iterator_result */
static void call_od_doc_for_each_at_path_with_wildcard(payload in) {
    if (!od_doc_valid) return;
    od_views_reset();
    od_doc_consumed = true;
    REPORT("ondemand::document::for_each_at_path_with_wildcard",
           auto ec = od_doc->for_each_at_path_with_wildcard(view(in), od_noop), ec == sj::SUCCESS);
    od_after(true);
}
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once, ondemand_array_iterator_result */
static void call_od_doc_begin(payload) {
    if (!od_doc_ready()) return;
    od_doc_consumed = true;
    if (!preqed_call("ondemand::document::begin")) return;
    od_take_riter("ondemand::document::begin", od_doc->begin());
}
/* ltl: ondemand_one_document_per_parser */
static void call_od_doc_end(payload) {
    if (!od_doc_valid) return;
    REPORT("ondemand::document::end", od_rend = od_doc->end(), true);
    od_rend_set = true;
}

#define OD_DOC_CONVERT(name, api, T) \
    static void call_od_doc_to_##name(payload) { \
        if (!od_doc_ready()) return; \
        od_doc_consumed = true; \
        OD_THROWING(api, T v = od_doc->operator T(); (void)v); \
    }
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once */
OD_DOC_CONVERT(array, "ondemand::document::operator(array)", sj::ondemand::array)
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once */
OD_DOC_CONVERT(object, "ondemand::document::operator(object)", sj::ondemand::object)
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once */
OD_DOC_CONVERT(uint64, "ondemand::document::operator(uint64_t)", uint64_t)
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once */
OD_DOC_CONVERT(int64, "ondemand::document::operator(int64_t)", int64_t)
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once */
OD_DOC_CONVERT(double, "ondemand::document::operator(double)", double)
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once */
OD_DOC_CONVERT(string_view, "ondemand::document::operator(string_view)", std::string_view)
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once */
OD_DOC_CONVERT(raw_json_string, "ondemand::document::operator(raw_json_string)", sj::ondemand::raw_json_string)
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once */
OD_DOC_CONVERT(bool, "ondemand::document::operator(bool)", bool)
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once */
OD_DOC_CONVERT(value, "ondemand::document::operator(value)", sj::ondemand::value)
/* ltl: ondemand_one_document_per_parser, ondemand_document_read_once */
OD_DOC_CONVERT(T, "ondemand::document::operator(T)", int32_t)

/* On-Demand: documents of a stream, reached through a document_reference (read once, like a document) */

#define OD_REF_GET(api, method) \
    static void call_od_ref_##method(payload) { \
        if (!od_ref_ready()) return; \
        od_ref_consumed = true; \
        OD_REPORT(api, od_ref.method()); \
    }
/* ltl: ondemand_stream_from_iterate_many, ondemand_document_reference_read_once */
OD_REF_GET("ondemand::document_reference::get_bool", get_bool)
/* ltl: ondemand_stream_from_iterate_many, ondemand_document_reference_read_once */
OD_REF_GET("ondemand::document_reference::get_double", get_double)
/* ltl: ondemand_stream_from_iterate_many, ondemand_document_reference_read_once */
OD_REF_GET("ondemand::document_reference::get_double_in_string", get_double_in_string)
/* ltl: ondemand_stream_from_iterate_many, ondemand_document_reference_read_once */
OD_REF_GET("ondemand::document_reference::get_int32", get_int32)
/* ltl: ondemand_stream_from_iterate_many, ondemand_document_reference_read_once */
OD_REF_GET("ondemand::document_reference::get_int64", get_int64)
/* ltl: ondemand_stream_from_iterate_many, ondemand_document_reference_read_once */
OD_REF_GET("ondemand::document_reference::get_int64_in_string", get_int64_in_string)
/* ltl: ondemand_stream_from_iterate_many, ondemand_document_reference_read_once */
OD_REF_GET("ondemand::document_reference::get_number", get_number)
/* ltl: ondemand_stream_from_iterate_many, ondemand_document_reference_read_once */
OD_REF_GET("ondemand::document_reference::get_raw_json_string", get_raw_json_string)
/* ltl: ondemand_stream_from_iterate_many, ondemand_document_reference_read_once */
OD_REF_GET("ondemand::document_reference::get_string", get_string)
/* ltl: ondemand_stream_from_iterate_many, ondemand_document_reference_read_once */
OD_REF_GET("ondemand::document_reference::get_uint32", get_uint32)
/* ltl: ondemand_stream_from_iterate_many, ondemand_document_reference_read_once */
OD_REF_GET("ondemand::document_reference::get_uint64", get_uint64)
/* ltl: ondemand_stream_from_iterate_many, ondemand_document_reference_read_once */
OD_REF_GET("ondemand::document_reference::get_uint64_in_string", get_uint64_in_string)
/* ltl: ondemand_stream_from_iterate_many, ondemand_document_reference_read_once */
OD_REF_GET("ondemand::document_reference::get_wobbly_string", get_wobbly_string)
/* ltl: ondemand_stream_from_iterate_many, ondemand_document_reference_read_once */
OD_REF_GET("ondemand::document_reference::is_null", is_null)
/* ltl: ondemand_stream_from_iterate_many, ondemand_document_reference_read_once */
OD_REF_GET("ondemand::document_reference::raw_json", raw_json)
/* ltl: ondemand_stream_from_iterate_many, ondemand_document_reference_read_once */
static void call_od_ref_get(payload) {
    if (!od_ref_ready()) return;
    od_ref_consumed = true;
    OD_REPORT("ondemand::document_reference::get", od_ref.get<double>());
}
/* ltl: ondemand_value_consumed_once, ondemand_stream_from_iterate_many, ondemand_document_reference_read_once */
static void call_od_ref_get_value(payload) {
    if (!od_ref_ready()) return;
    od_ref_consumed = true;
    if (!preqed_call("ondemand::document_reference::get_value")) return;
    bool ok = !od_ref.get_value().get(od_value);
    preqed_result("ondemand::document_reference::get_value", ok);
    od_after(ok);
    od_value_valid = ok;
    od_vres_valid = false;
}
/* ltl: ondemand_array_view, ondemand_stream_from_iterate_many, ondemand_document_reference_read_once */
static void call_od_ref_get_array(payload) {
    if (!od_ref_ready()) return;
    od_ref_consumed = true;
    if (!preqed_call("ondemand::document_reference::get_array")) return;
    od_begin_array("ondemand::document_reference::get_array", od_ref.get_array());
}
/* ltl: ondemand_object_view, ondemand_stream_from_iterate_many, ondemand_document_reference_read_once */
static void call_od_ref_get_object(payload) {
    if (!od_ref_ready()) return;
    od_ref_consumed = true;
    if (!preqed_call("ondemand::document_reference::get_object")) return;
    od_begin_object("ondemand::document_reference::get_object", od_ref.get_object());
}

#define OD_REF_PEEK(api, method) \
    static void call_od_ref_##method(payload) { \
        if (!od_ref_ready()) return; \
        OD_REPORT(api, od_ref.method()); \
    }
/* ltl: ondemand_stream_from_iterate_many */
OD_REF_PEEK("ondemand::document_reference::is_integer", is_integer)
/* ltl: ondemand_stream_from_iterate_many */
OD_REF_PEEK("ondemand::document_reference::is_scalar", is_scalar)
/* ltl: ondemand_stream_from_iterate_many */
OD_REF_PEEK("ondemand::document_reference::is_string", is_string)
/* ltl: ondemand_stream_from_iterate_many */
OD_REF_PEEK("ondemand::document_reference::get_number_type", get_number_type)
/* ltl: ondemand_stream_from_iterate_many */
OD_REF_PEEK("ondemand::document_reference::raw_json_token", raw_json_token)
/* ltl: ondemand_stream_from_iterate_many */
static void call_od_ref_is_negative(payload) {
    if (!od_ref_ready()) return;
    REPORT("ondemand::document_reference::is_negative", (void)od_ref.is_negative(), true);
}
/* ltl: ondemand_stream_from_iterate_many */
static void call_od_ref_current_location(payload) {
    if (!od_ref_valid) return;
    REPORT("ondemand::document_reference::current_location", (void)od_ref.current_location(), true);
}
/* ltl: ondemand_stream_from_iterate_many */
static void call_od_ref_current_depth(payload) {
    if (!od_ref_valid) return;
    REPORT("ondemand::document_reference::current_depth", (void)od_ref.current_depth(), true);
}
/* ltl: ondemand_stream_from_iterate_many */
static void call_od_ref_to_document(payload) {
    if (!od_ref_valid) return;
    REPORT("ondemand::document_reference::operator(document&)", sj::ondemand::document &d = od_ref; (void)d, true);
}

#define OD_REF_COUNT(api, method) \
    static void call_od_ref_##method(payload) { \
        if (!od_ref_ready()) return; \
        od_ref_consumed = true; \
        if (!preqed_call(api)) return; \
        bool ok = !od_ref.method().error(); \
        preqed_result(api, ok); \
        od_after(ok); \
        if (ok) od_ref_consumed = false; \
    }
/* ltl: ondemand_stream_from_iterate_many, ondemand_document_reference_read_once */
OD_REF_COUNT("ondemand::document_reference::count_elements", count_elements)
/* ltl: ondemand_stream_from_iterate_many, ondemand_document_reference_read_once */
OD_REF_COUNT("ondemand::document_reference::count_fields", count_fields)
/* ltl: ondemand_stream_from_iterate_many, ondemand_value_result_consumed_once, ondemand_document_reference_read_once */
static void call_od_ref_find_field_unordered(payload in) {
    if (!od_ref_ready()) return;
    od_ref_consumed = true;
    if (!preqed_call("ondemand::document_reference::find_field_unordered")) return;
    od_take_vres("ondemand::document_reference::find_field_unordered", od_ref.find_field_unordered(view(in)));
}
/* ltl: ondemand_stream_from_iterate_many, ondemand_value_result_consumed_once, ondemand_document_reference_read_once */
static void call_od_ref_subscript(payload in) {
    if (!od_ref_ready()) return;
    od_ref_consumed = true;
    if (!preqed_call("ondemand::document_reference::operator[]")) return;
    od_take_vres("ondemand::document_reference::operator[]", od_ref[view(in)]);
}
/* ltl: ondemand_value_consumed_once, ondemand_array_view, ondemand_object_view, ondemand_stream_from_iterate_many, ondemand_value_result_consumed_once, ondemand_document_reference_read_once, ondemand_array_iterator_result */
static void call_od_ref_at_path(payload in) {
    if (!od_ref_valid) return;
    od_views_reset();
    od_ref_consumed = true;
    if (!preqed_call("ondemand::document_reference::at_path")) return;
    od_take_vres("ondemand::document_reference::at_path", od_ref.at_path(view(in)));
}
/* ltl: ondemand_value_consumed_once, ondemand_array_view, ondemand_object_view, ondemand_stream_from_iterate_many, ondemand_value_result_consumed_once, ondemand_document_reference_read_once, ondemand_array_iterator_result */
static void call_od_ref_for_each_at_path_with_wildcard(payload in) {
    if (!od_ref_valid) return;
    od_views_reset();
    od_ref_consumed = true;
    REPORT("ondemand::document_reference::for_each_at_path_with_wildcard",
           auto ec = od_ref.for_each_at_path_with_wildcard(view(in), od_noop), ec == sj::SUCCESS);
    od_after(true);
}
/* ltl: ondemand_stream_from_iterate_many, ondemand_document_reference_read_once, ondemand_array_iterator_result */
static void call_od_ref_begin(payload) {
    if (!od_ref_ready()) return;
    od_ref_consumed = true;
    if (!preqed_call("ondemand::document_reference::begin")) return;
    od_take_riter("ondemand::document_reference::begin", od_ref.begin());
}
/* ltl: ondemand_stream_from_iterate_many */
static void call_od_ref_end(payload) {
    if (!od_ref_valid) return;
    REPORT("ondemand::document_reference::end", od_rend = od_ref.end(), true);
    od_rend_set = true;
}
/* ltl: ondemand_value_consumed_once, ondemand_array_view, ondemand_object_view, ondemand_stream_from_iterate_many, ondemand_value_result_consumed_once, ondemand_document_reference_read_once, ondemand_array_iterator_result */
static void call_od_ref_rewind(payload) {
    if (!od_ref_valid) return;
    od_views_reset();
    REPORT("ondemand::document_reference::rewind", od_ref.rewind(), true);
    od_ref_consumed = false;
}

#define OD_REF_CONVERT(name, api, T) \
    static void call_od_ref_to_##name(payload) { \
        if (!od_ref_ready()) return; \
        od_ref_consumed = true; \
        OD_THROWING(api, T v = od_ref.operator T(); (void)v); \
    }
/* ltl: ondemand_stream_from_iterate_many, ondemand_document_reference_read_once */
OD_REF_CONVERT(array, "ondemand::document_reference::operator(array)", sj::ondemand::array)
/* ltl: ondemand_stream_from_iterate_many, ondemand_document_reference_read_once */
OD_REF_CONVERT(object, "ondemand::document_reference::operator(object)", sj::ondemand::object)
/* ltl: ondemand_stream_from_iterate_many, ondemand_document_reference_read_once */
OD_REF_CONVERT(uint64, "ondemand::document_reference::operator(uint64_t)", uint64_t)
/* ltl: ondemand_stream_from_iterate_many, ondemand_document_reference_read_once */
OD_REF_CONVERT(int64, "ondemand::document_reference::operator(int64_t)", int64_t)
/* ltl: ondemand_stream_from_iterate_many, ondemand_document_reference_read_once */
OD_REF_CONVERT(double, "ondemand::document_reference::operator(double)", double)
/* ltl: ondemand_stream_from_iterate_many, ondemand_document_reference_read_once */
OD_REF_CONVERT(string_view, "ondemand::document_reference::operator(string_view)", std::string_view)
/* ltl: ondemand_stream_from_iterate_many, ondemand_document_reference_read_once */
OD_REF_CONVERT(raw_json_string, "ondemand::document_reference::operator(raw_json_string)", sj::ondemand::raw_json_string)
/* ltl: ondemand_stream_from_iterate_many, ondemand_document_reference_read_once */
OD_REF_CONVERT(bool, "ondemand::document_reference::operator(bool)", bool)
/* ltl: ondemand_stream_from_iterate_many, ondemand_document_reference_read_once */
OD_REF_CONVERT(value, "ondemand::document_reference::operator(value)", sj::ondemand::value)
/* ltl: ondemand_stream_from_iterate_many, ondemand_document_reference_read_once */
OD_REF_CONVERT(T, "ondemand::document_reference::operator(T)", int32_t)

/* the simdjson_result<document_reference> of the stream dereference */
/* ltl: ondemand_value_consumed_once, ondemand_array_view, ondemand_object_view, ondemand_stream_from_iterate_many, ondemand_value_result_consumed_once, ondemand_document_reference_read_once, ondemand_array_iterator_result */
static void call_od_rres_rewind(payload) {
    if (!od_ref_valid) return;
    od_views_reset();
    REPORT("simdjson_result<ondemand::document_reference>::rewind", auto ec = od_rres.rewind(), ec == sj::SUCCESS);
    od_ref_consumed = false;
}
/* ltl: ondemand_stream_from_iterate_many, ondemand_value_result_consumed_once, ondemand_document_reference_read_once */
static void call_od_rres_get_value(payload) {
    if (!od_ref_ready()) return;
    od_ref_consumed = true;
    if (!preqed_call("simdjson_result<ondemand::document_reference>::get_value")) return;
    od_take_vres("simdjson_result<ondemand::document_reference>::get_value", od_rres.get_value());
}
/* ltl: ondemand_stream_from_iterate_many, ondemand_document_reference_read_once */
static void call_od_rres_to_value(payload) {
    if (!od_ref_ready()) return;
    od_ref_consumed = true;
    OD_THROWING("simdjson_result<ondemand::document_reference>::operator(value)",
                sj::ondemand::value v = od_rres.operator sj::ondemand::value(); (void)v);
}

/* On-Demand: document streams */
/* ltl: ondemand_stream_from_iterate_many */
static void call_od_stream_size_in_bytes(payload) {
    if (!od_stream_valid) return;
    REPORT("ondemand::document_stream::size_in_bytes", (void)od_stream->size_in_bytes(), true);
}
/* ltl: ondemand_stream_from_iterate_many */
static void call_od_stream_truncated_bytes(payload) {
    if (!od_stream_valid) return;
    REPORT("ondemand::document_stream::truncated_bytes", (void)od_stream->truncated_bytes(), true);
}
/* ltl: ondemand_stream_from_iterate_many */
static void call_od_stream_iterator_current_index(payload) {
    if (!od_stream_valid || !(od_sit != od_send)) return;
    REPORT("ondemand::document_stream::iterator::current_index", (void)od_sit.current_index(), true);
}

/* source() maps the current document as iterated so far: used before the document is read and only when
 * "!i.error()" (doc/iterate_many.md:338). Unchecked it dereferences null after a failed batch
 * (repro_stream_source_null.cpp), although doc/iterate_many.md:375 calls it unchecked. */
/* ltl: ondemand_stream_from_iterate_many */
static void call_od_stream_iterator_source(payload) {
    if (!od_stream_valid || !(od_sit != od_send) || od_ref_consumed || od_sit.error()) return;
    REPORT("ondemand::document_stream::iterator::source", (void)od_sit.source(), true);
}
/* ltl: ondemand_stream_from_iterate_many */
static void call_od_stream_iterator_error(payload) {
    if (!od_stream_valid || !(od_sit != od_send)) return;
    REPORT("ondemand::document_stream::iterator::error", (void)od_sit.error(), true);
}
/* ltl: ondemand_stream_from_iterate_many */
static void call_od_stream_iterator_equal(payload) {
    if (!od_stream_valid) return;
    REPORT("ondemand::document_stream::iterator::operator==", (void)(od_sit == od_send), true);
}
/* as for DOM (simdjson.h:88565): only a stream that never started (none since the last close) is assigned */
/* ltl: ondemand_value_consumed_once, ondemand_array_view, ondemand_object_view, ondemand_stream_from_iterate_many, ondemand_value_result_consumed_once, ondemand_array_iterator_result */
static void call_od_stream_operator_assign(payload) {
    if (od_stream_started) return;
    od_views_reset();
    od_ref_valid = false;
    REPORT("ondemand::document_stream::operator=", *od_stream = sj::ondemand::document_stream(), true);
}

/* On-Demand: parser */
/* ltl: ondemand_one_document_per_parser, ondemand_value_consumed_once, ondemand_array_view, ondemand_object_view, ondemand_stream_from_iterate_many, ondemand_value_result_consumed_once, ondemand_array_iterator_result, ondemand_raw_json_string_input */
static void call_od_parser_operator_assign(payload) {
    od_parser_reused();
    od_stream_close();
    REPORT("ondemand::parser::operator=", *od_parser = sj::ondemand::parser(), true);
}

static void call_od_parser_set_max_capacity(payload in) {
    size_t cap = (size_t(byte(in, 0)) | size_t(byte(in, 1)) << 8) * 64;
    REPORT("ondemand::parser::set_max_capacity", od_parser->set_max_capacity(cap), true);
}

/* the thread-local parser of simdjson::from (simdjson.h:86815) */
static void call_od_parser_get_parser(payload) {
    REPORT("ondemand::parser::get_parser", sj::ondemand::parser &p = sj::ondemand::parser::get_parser(); (void)p, true);
}

static void call_od_parser_release_parser(payload) {
    REPORT("ondemand::parser::release_parser", (void)sj::ondemand::parser::release_parser(), true);
}

/* On-Demand: more value routines */
/* ltl: ondemand_value_consumed_once */
OD_VALUE_GET("ondemand::value::get_int32", get_int32)
/* ltl: ondemand_value_consumed_once */
OD_VALUE_GET("ondemand::value::get_uint32", get_uint32)
/* ltl: ondemand_value_consumed_once */
OD_VALUE_GET("ondemand::value::get_int64_in_string", get_int64_in_string)
/* ltl: ondemand_value_consumed_once */
OD_VALUE_GET("ondemand::value::get_uint64_in_string", get_uint64_in_string)
/* ltl: ondemand_value_consumed_once */
OD_VALUE_GET("ondemand::value::get_double_in_string", get_double_in_string)
/* ltl: ondemand_value_consumed_once */
OD_VALUE_GET("ondemand::value::get_wobbly_string", get_wobbly_string)
/* ltl: ondemand_value_consumed_once */
static void call_od_value_get(payload) {
    if (!od_value_valid) return;
    od_value_valid = false;
    OD_REPORT("ondemand::value::get", od_value.get<double>());
}
/* ltl: ondemand_value_consumed_once, ondemand_raw_json_string_input */
static void call_od_value_get_raw_json_string(payload) {
    if (!od_value_valid) return;
    od_value_valid = false;
    if (!preqed_call("ondemand::value::get_raw_json_string")) return;
    bool ok = !od_value.get_raw_json_string().get(od_raw);
    preqed_result("ondemand::value::get_raw_json_string", ok);
    od_after(ok);
    od_raw_valid = ok;
}

#define OD_VALUE_PEEK(api, method) \
    static void call_od_value_##method(payload) { \
        if (!od_value_valid) return; \
        OD_REPORT(api, od_value.method()); \
    }
/* ltl: ondemand_value_consumed_once */
OD_VALUE_PEEK("ondemand::value::is_scalar", is_scalar)
/* ltl: ondemand_value_consumed_once */
OD_VALUE_PEEK("ondemand::value::is_string", is_string)
/* ltl: ondemand_value_consumed_once */
OD_VALUE_PEEK("ondemand::value::is_integer", is_integer)
/* ltl: ondemand_value_consumed_once */
OD_VALUE_PEEK("ondemand::value::get_number_type", get_number_type)
/* ltl: ondemand_value_consumed_once */
OD_VALUE_PEEK("ondemand::value::current_location", current_location)
/* "if successful, the array is 'rewinded' at its beginning as if it had never been accessed"; on failure
 * "it is no longer safe to continue" (simdjson.h:84900) */
#define OD_VALUE_COUNT(api, method) \
    static void call_od_value_##method(payload) { \
        if (!od_value_valid) return; \
        if (!preqed_call(api)) return; \
        bool ok = !od_value.method().error(); \
        preqed_result(api, ok); \
        od_after(ok); \
        if (!ok) od_value_valid = false; \
    }
/* ltl: ondemand_value_consumed_once */
OD_VALUE_COUNT("ondemand::value::count_elements", count_elements)
/* ltl: ondemand_value_consumed_once */
OD_VALUE_COUNT("ondemand::value::count_fields", count_fields)
/* ltl: ondemand_value_consumed_once */
static void call_od_value_is_negative(payload) {
    if (!od_value_valid) return;
    REPORT("ondemand::value::is_negative", (void)od_value.is_negative(), true);
}
/* ltl: ondemand_value_consumed_once */
static void call_od_value_raw_json_token(payload) {
    if (!od_value_valid) return;
    REPORT("ondemand::value::raw_json_token", (void)od_value.raw_json_token(), true);
}
/* ltl: ondemand_value_consumed_once */
static void call_od_value_current_depth(payload) {
    if (!od_value_valid) return;
    REPORT("ondemand::value::current_depth", (void)od_value.current_depth(), true);
}

#define OD_VALUE_LOOKUP(name, api, expr) \
    static void call_od_value_##name(payload in) { \
        if (!od_value_valid) return; \
        od_value_valid = false; \
        if (!preqed_call(api)) return; \
        od_take_vres(api, expr); \
    }
/* ltl: ondemand_value_consumed_once, ondemand_value_result_consumed_once */
OD_VALUE_LOOKUP(find_field_unordered, "ondemand::value::find_field_unordered", od_value.find_field_unordered(view(in)))
/* ltl: ondemand_value_consumed_once, ondemand_value_result_consumed_once */
OD_VALUE_LOOKUP(subscript, "ondemand::value::operator[]", od_value[view(in)])
/* ltl: ondemand_value_consumed_once, ondemand_value_result_consumed_once */
OD_VALUE_LOOKUP(at_path, "ondemand::value::at_path", od_value.at_path(view(in)))
/* ltl: ondemand_value_consumed_once */
static void call_od_value_for_each_at_path_with_wildcard(payload in) {
    if (!od_value_valid) return;
    od_value_valid = false;
    REPORT("ondemand::value::for_each_at_path_with_wildcard",
           auto ec = od_value.for_each_at_path_with_wildcard(view(in), od_noop), ec == sj::SUCCESS);
    od_after(true);
}
/* ltl: ondemand_value_consumed_once, ondemand_array_iterator_result */
static void call_od_value_begin(payload) {
    if (!od_value_valid) return;
    od_value_valid = false;
    if (!preqed_call("ondemand::value::begin")) return;
    od_take_riter("ondemand::value::begin", od_value.begin());
}
/* ltl: ondemand_value_consumed_once */
static void call_od_value_end(payload) {
    if (!od_value_valid) return;
    REPORT("ondemand::value::end", od_rend = od_value.end(), true);
    od_rend_set = true;
}

#define OD_VALUE_CONVERT(name, api, T) \
    static void call_od_value_to_##name(payload) { \
        if (!od_value_valid) return; \
        od_value_valid = false; \
        OD_THROWING(api, T v = od_value.operator T(); (void)v); \
    }
/* ltl: ondemand_value_consumed_once */
OD_VALUE_CONVERT(array, "ondemand::value::operator(array)", sj::ondemand::array)
/* ltl: ondemand_value_consumed_once */
OD_VALUE_CONVERT(object, "ondemand::value::operator(object)", sj::ondemand::object)
/* ltl: ondemand_value_consumed_once */
OD_VALUE_CONVERT(uint64, "ondemand::value::operator(uint64_t)", uint64_t)
/* ltl: ondemand_value_consumed_once */
OD_VALUE_CONVERT(int64, "ondemand::value::operator(int64_t)", int64_t)
/* ltl: ondemand_value_consumed_once */
OD_VALUE_CONVERT(double, "ondemand::value::operator(double)", double)
/* ltl: ondemand_value_consumed_once */
OD_VALUE_CONVERT(string_view, "ondemand::value::operator(string_view)", std::string_view)
/* ltl: ondemand_value_consumed_once */
OD_VALUE_CONVERT(raw_json_string, "ondemand::value::operator(raw_json_string)", sj::ondemand::raw_json_string)
/* ltl: ondemand_value_consumed_once */
OD_VALUE_CONVERT(bool, "ondemand::value::operator(bool)", bool)
/* ltl: ondemand_value_consumed_once */
OD_VALUE_CONVERT(T, "ondemand::value::operator(T)", int32_t)

/* "The value must not have been accessed previously" (simdjson.h:91213) */
/* ltl: ondemand_value_consumed_once */
static void call_to_json_string(payload) {
    if (!od_value_valid) return;
    od_value_valid = false;
    OD_REPORT("to_json_string", sj::to_json_string(od_value));
}

/* On-Demand: simdjson_result<value> (consumed once, like a value) */

#define OD_VRES_GET(api, method) \
    static void call_od_vres_##method(payload) { \
        if (!od_vres_valid) return; \
        od_vres_valid = false; \
        OD_REPORT(api, od_vres.method()); \
    }
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_GET("simdjson_result<ondemand::value>::get_uint64", get_uint64)
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_GET("simdjson_result<ondemand::value>::get_int64", get_int64)
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_GET("simdjson_result<ondemand::value>::get_uint32", get_uint32)
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_GET("simdjson_result<ondemand::value>::get_int32", get_int32)
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_GET("simdjson_result<ondemand::value>::get_uint64_in_string", get_uint64_in_string)
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_GET("simdjson_result<ondemand::value>::get_int64_in_string", get_int64_in_string)
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_GET("simdjson_result<ondemand::value>::get_double", get_double)
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_GET("simdjson_result<ondemand::value>::get_double_in_string", get_double_in_string)
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_GET("simdjson_result<ondemand::value>::get_string", get_string)
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_GET("simdjson_result<ondemand::value>::get_wobbly_string", get_wobbly_string)
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_GET("simdjson_result<ondemand::value>::get_bool", get_bool)
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_GET("simdjson_result<ondemand::value>::is_null", is_null)
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_GET("simdjson_result<ondemand::value>::raw_json", raw_json)
/* ltl: ondemand_value_result_consumed_once, ondemand_raw_json_string_input */
static void call_od_vres_get_raw_json_string(payload) {
    if (!od_vres_valid) return;
    od_vres_valid = false;
    if (!preqed_call("simdjson_result<ondemand::value>::get_raw_json_string")) return;
    bool ok = !od_vres.get_raw_json_string().get(od_raw);
    preqed_result("simdjson_result<ondemand::value>::get_raw_json_string", ok);
    od_after(ok);
    od_raw_valid = ok;
}
/* ltl: ondemand_value_result_consumed_once */
static void call_od_vres_get_number(payload) {
    if (!od_vres_valid) return;
    od_vres_valid = false;
    if (!preqed_call("simdjson_result<ondemand::value>::get_number")) return;
    bool ok = !od_vres.get_number().get(od_number);
    preqed_result("simdjson_result<ondemand::value>::get_number", ok);
    od_after(ok);
    od_number_valid = ok;
}
/* ltl: ondemand_array_view, ondemand_value_result_consumed_once */
static void call_od_vres_get_array(payload) {
    if (!od_vres_valid) return;
    od_vres_valid = false;
    if (!preqed_call("simdjson_result<ondemand::value>::get_array")) return;
    od_begin_array("simdjson_result<ondemand::value>::get_array", od_vres.get_array());
}
/* ltl: ondemand_object_view, ondemand_value_result_consumed_once */
static void call_od_vres_get_object(payload) {
    if (!od_vres_valid) return;
    od_vres_valid = false;
    if (!preqed_call("simdjson_result<ondemand::value>::get_object")) return;
    od_begin_object("simdjson_result<ondemand::value>::get_object", od_vres.get_object());
}

#define OD_VRES_PEEK(api, method) \
    static void call_od_vres_##method(payload) { \
        if (!od_vres_valid) return; \
        OD_REPORT(api, od_vres.method()); \
    }
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_PEEK("simdjson_result<ondemand::value>::type", type)
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_PEEK("simdjson_result<ondemand::value>::is_scalar", is_scalar)
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_PEEK("simdjson_result<ondemand::value>::is_string", is_string)
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_PEEK("simdjson_result<ondemand::value>::is_negative", is_negative)
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_PEEK("simdjson_result<ondemand::value>::is_integer", is_integer)
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_PEEK("simdjson_result<ondemand::value>::get_number_type", get_number_type)
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_PEEK("simdjson_result<ondemand::value>::current_location", current_location)
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_PEEK("simdjson_result<ondemand::value>::current_depth", current_depth)
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_PEEK("simdjson_result<ondemand::value>::raw_json_token", raw_json_token)

#define OD_VRES_COUNT(api, method) \
    static void call_od_vres_##method(payload) { \
        if (!od_vres_valid) return; \
        if (!preqed_call(api)) return; \
        bool ok = !od_vres.method().error(); \
        preqed_result(api, ok); \
        od_after(ok); \
        if (!ok) od_vres_valid = false; \
    }
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_COUNT("simdjson_result<ondemand::value>::count_elements", count_elements)
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_COUNT("simdjson_result<ondemand::value>::count_fields", count_fields)
/* ltl: ondemand_value_result_consumed_once */
static void call_od_vres_has_value(payload) {
    if (!od_vres_valid) return;
    REPORT("simdjson_result<ondemand::value>::has_value", bool h = od_vres.has_value(), h);
}
/* ltl: ondemand_value_result_consumed_once */
static void call_od_vres_arrow(payload) {
    if (!od_vres_valid) return;
    THROWING("simdjson_result<ondemand::value>::operator->", (void)od_vres.operator->());
}

#define OD_VRES_LOOKUP(name, api, expr) \
    static void call_od_vres_##name(payload in) { \
        if (!od_vres_valid) return; \
        od_vres_valid = false; \
        if (!preqed_call(api)) return; \
        od_take_vres(api, expr); \
    }
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_LOOKUP(find_field_unordered, "simdjson_result<ondemand::value>::find_field_unordered", od_vres.find_field_unordered(view(in)))
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_LOOKUP(subscript, "simdjson_result<ondemand::value>::operator[]", od_vres[view(in)])
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_LOOKUP(at_path, "simdjson_result<ondemand::value>::at_path", od_vres.at_path(view(in)))
/* ltl: ondemand_value_result_consumed_once */
static void call_od_vres_for_each_at_path_with_wildcard(payload in) {
    if (!od_vres_valid) return;
    od_vres_valid = false;
    REPORT("simdjson_result<ondemand::value>::for_each_at_path_with_wildcard",
           auto ec = od_vres.for_each_at_path_with_wildcard(view(in), od_noop), ec == sj::SUCCESS);
    od_after(true);
}
/* ltl: ondemand_value_result_consumed_once, ondemand_array_iterator_result */
static void call_od_vres_begin(payload) {
    if (!od_vres_valid) return;
    od_vres_valid = false;
    if (!preqed_call("simdjson_result<ondemand::value>::begin")) return;
    od_take_riter("simdjson_result<ondemand::value>::begin", od_vres.begin());
}
/* ltl: ondemand_value_result_consumed_once */
static void call_od_vres_end(payload) {
    if (!od_vres_valid) return;
    REPORT("simdjson_result<ondemand::value>::end", od_rend = od_vres.end(), true);
    od_rend_set = true;
}

#define OD_VRES_CONVERT(name, api, T) \
    static void call_od_vres_to_##name(payload) { \
        if (!od_vres_valid) return; \
        od_vres_valid = false; \
        OD_THROWING(api, T v = od_vres.operator T(); (void)v); \
    }
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_CONVERT(array, "simdjson_result<ondemand::value>::operator(array)", sj::ondemand::array)
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_CONVERT(object, "simdjson_result<ondemand::value>::operator(object)", sj::ondemand::object)
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_CONVERT(uint64, "simdjson_result<ondemand::value>::operator(uint64_t)", uint64_t)
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_CONVERT(int64, "simdjson_result<ondemand::value>::operator(int64_t)", int64_t)
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_CONVERT(double, "simdjson_result<ondemand::value>::operator(double)", double)
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_CONVERT(string_view, "simdjson_result<ondemand::value>::operator(string_view)", std::string_view)
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_CONVERT(raw_json_string, "simdjson_result<ondemand::value>::operator(raw_json_string)", sj::ondemand::raw_json_string)
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_CONVERT(bool, "simdjson_result<ondemand::value>::operator(bool)", bool)
/* ltl: ondemand_value_result_consumed_once */
OD_VRES_CONVERT(T, "simdjson_result<ondemand::value>::operator(T)", int32_t)

/* taking the value out of a successful result: it becomes the current value */
#define OD_VRES_TAKE(name, api, expr) \
    static void call_od_vres_##name(payload) { \
        if (!od_vres_valid) return; \
        od_vres_valid = false; \
        if (!preqed_call(api)) return; \
        bool ok = true; \
        try { od_value = expr; } catch (const sj::simdjson_error &) { ok = false; } \
        preqed_result(api, ok); \
        od_value_valid = ok; \
        od_field_valid = false; \
    }
/* ltl: ondemand_value_consumed_once, ondemand_value_result_consumed_once */
OD_VRES_TAKE(deref, "simdjson_result<ondemand::value>::operator*", *od_vres)
/* ltl: ondemand_value_consumed_once, ondemand_value_result_consumed_once */
OD_VRES_TAKE(value, "simdjson_result<ondemand::value>::value", od_vres.value())
/* ltl: ondemand_value_consumed_once, ondemand_value_result_consumed_once */
OD_VRES_TAKE(take_value, "simdjson_result<ondemand::value>::take_value", std::move(od_vres).take_value())
/* ltl: ondemand_value_consumed_once, ondemand_value_result_consumed_once */
OD_VRES_TAKE(value_unsafe, "simdjson_result<ondemand::value>::value_unsafe", od_vres.value_unsafe())
using od_value_result_base = sj::fallback::implementation_simdjson_result_base<sj::ondemand::value>;
/* ltl: ondemand_value_consumed_once, ondemand_value_result_consumed_once */
OD_VRES_TAKE(rvalue, "simdjson_result<ondemand::value>::operator(value&&)", std::move(od_vres).od_value_result_base::operator sj::ondemand::value &&())

/* On-Demand: begin()/end() results, iterated as in a range-for loop */

static bool od_riter_ready() { return od_riter_valid && od_rend_set; }
/* ltl: ondemand_array_iterator_result */
static void call_od_riter_not_equal(payload) {
    if (!od_riter_ready()) return;
    REPORT("simdjson_result<ondemand::array_iterator>::operator!=", (void)(od_rit != od_rend), true);
}
/* ltl: ondemand_array_iterator_result */
static void call_od_riter_equal(payload) {
    if (!od_riter_ready()) return;
    REPORT("simdjson_result<ondemand::array_iterator>::operator==", (void)(od_rit == od_rend), true);
}
/* ltl: ondemand_array_iterator_result */
static void call_od_riter_at_end(payload) {
    if (!od_riter_valid) return;
    REPORT("simdjson_result<ondemand::array_iterator>::at_end", (void)od_rit.at_end(), true);
}

/* "MUST ONLY BE CALLED ONCE PER ITERATION" (simdjson.h:87267); children of the previous element are gone */
/* ltl: ondemand_value_result_consumed_once, ondemand_array_iterator_result */
static void call_od_riter_deref(payload) {
    if (!od_riter_ready() || od_rit_deref || !(od_rit != od_rend)) return;
    od_rit_deref = true;
    od_array_valid = od_object_valid = false;
    if (!preqed_call("simdjson_result<ondemand::array_iterator>::operator*")) return;
    od_take_vres("simdjson_result<ondemand::array_iterator>::operator*", *od_rit);
}
/* ltl: ondemand_array_iterator_result */
static void call_od_riter_advance(payload) {
    if (!od_riter_ready() || !(od_rit != od_rend)) return;
    od_value_valid = od_vres_valid = od_field_valid = od_array_valid = od_object_valid = od_rit_deref = false;
    REPORT("simdjson_result<ondemand::array_iterator>::operator++", ++od_rit, true);
}

/* On-Demand: fields */
/* ltl: ondemand_field_key_once, ondemand_raw_json_string_input */
static void call_od_field_key(payload) {
    if (!od_field_valid || od_key_used) return;
    REPORT("ondemand::field::key", od_raw = od_field.key(), true);
    od_raw_valid = true;
}

static void call_od_field_key_raw_json_token(payload) {
    if (!od_field_valid) return;
    REPORT("ondemand::field::key_raw_json_token", (void)od_field.key_raw_json_token(), true);
}

static void call_od_field_escaped_key(payload) {
    if (!od_field_valid) return;
    REPORT("ondemand::field::escaped_key", (void)od_field.escaped_key(), true);
}
/* ltl: ondemand_field_key_once */
static void call_od_fres_key(payload) {
    if (!od_field_valid || od_key_used) return;
    OD_REPORT("simdjson_result<ondemand::field>::key", od_fres.key());
}

static void call_od_fres_key_raw_json_token(payload) {
    if (!od_field_valid) return;
    OD_REPORT("simdjson_result<ondemand::field>::key_raw_json_token", od_fres.key_raw_json_token());
}

static void call_od_fres_escaped_key(payload) {
    if (!od_field_valid) return;
    OD_REPORT("simdjson_result<ondemand::field>::escaped_key", od_fres.escaped_key());
}
/* ltl: ondemand_field_key_once */
static void call_od_fres_unescaped_key(payload) {
    if (!od_field_valid || od_key_used) return;
    od_key_used = true;
    OD_REPORT("simdjson_result<ondemand::field>::unescaped_key", od_fres.unescaped_key());
}
/* ltl: ondemand_value_result_consumed_once */
static void call_od_fres_value(payload) {
    if (!od_field_valid) return;
    od_field_valid = false;
    if (!preqed_call("simdjson_result<ondemand::field>::value")) return;
    od_take_vres("simdjson_result<ondemand::field>::value", od_fres.value());
}

/* raw_json_string comparisons: "the user is responsible for providing a string with no unescaped quote"
 * (simdjson.h:86365) */
static bool quote_free(std::string_view s) { return s.find('"') == std::string_view::npos; }
/* ltl: ondemand_raw_json_string_input */
static void call_od_raw_equal(payload in) {
    if (!od_raw_valid || !quote_free(view(in))) return;
    REPORT("ondemand::operator==(raw_json_string)", (void)(od_raw == view(in)), true);
}
/* ltl: ondemand_raw_json_string_input */
static void call_od_raw_not_equal(payload in) {
    if (!od_raw_valid || !quote_free(view(in))) return;
    REPORT("ondemand::operator!=(raw_json_string)", (void)(view(in) != od_raw), true);
}

/* On-Demand: numbers ("only valid if is_int64() is true" etc., simdjson.h:86070-86100) */

static void call_od_number_get_number_type(payload) {
    if (!od_number_valid) return;
    REPORT("ondemand::number::get_number_type", (void)od_number.get_number_type(), true);
}

#define OD_NUMBER_IS(api, method) \
    static void call_od_number_##method(payload) { \
        if (!od_number_valid) return; \
        REPORT(api, (void)od_number.method(), true); \
    }
OD_NUMBER_IS("ondemand::number::is_uint64", is_uint64)
OD_NUMBER_IS("ondemand::number::is_int64", is_int64)
OD_NUMBER_IS("ondemand::number::is_double", is_double)
OD_NUMBER_IS("ondemand::number::as_double", as_double)

#define OD_NUMBER_GET(name, api, is, expr) \
    static void call_od_number_##name(payload) { \
        if (!od_number_valid || !od_number.is()) return; \
        REPORT(api, (void)(expr), true); \
    }
OD_NUMBER_GET(get_uint64, "ondemand::number::get_uint64", is_uint64, od_number.get_uint64())
OD_NUMBER_GET(get_int64, "ondemand::number::get_int64", is_int64, od_number.get_int64())
OD_NUMBER_GET(get_double, "ondemand::number::get_double", is_double, od_number.get_double())
OD_NUMBER_GET(to_uint64, "ondemand::number::operator(uint64_t)", is_uint64, od_number.operator uint64_t())
OD_NUMBER_GET(to_int64, "ondemand::number::operator(int64_t)", is_int64, od_number.operator int64_t())
OD_NUMBER_GET(to_double, "ondemand::number::operator(double)", is_double, od_number.operator double())

static void call_od_number_type_stream(payload) {
    if (!od_number_valid) return;
    std::ostringstream os;
    REPORT("operator<<(number_type)", os << od_number.get_number_type(), bool(os));
}

static void call_od_json_type_stream(payload in) {
    std::ostringstream os;
    REPORT("ondemand::operator<<(json_type)", os << sj::ondemand::json_type(1 + byte(in, 0) % 6), bool(os));
}

/* On-Demand: more array and object routines. count / is_empty / reset rewind the container: used only
 * before it is first accessed, so no value is read twice ("You should still consume values only once") */
/* ltl: ondemand_array_view */
static void call_od_array_iterator_equal(payload) {
    if (!od_array_valid) return;
    REPORT("ondemand::array_iterator::operator==", (void)(od_ait == od_aend), true);
}
/* ltl: ondemand_object_view */
static void call_od_object_iterator_equal(payload) {
    if (!od_object_valid) return;
    REPORT("ondemand::object_iterator::operator==", (void)(od_oit == od_oend), true);
}

/* on failure "it is no longer safe to continue" with the container (simdjson.h:86915) */
#define OD_FRESH(name, api, valid, fresh, expr) \
    static void call_##name(payload) { \
        if (!(valid) || !(fresh)) return; \
        if (!preqed_call(api)) return; \
        bool ok = !(expr).error(); \
        preqed_result(api, ok); \
        od_after(ok); \
        if (!ok) valid = false; \
    }
/* ltl: ondemand_array_view */
OD_FRESH(od_array_count_elements, "ondemand::array::count_elements", od_array_valid, od_array_fresh, od_array.count_elements())
/* ltl: ondemand_array_view */
OD_FRESH(od_array_is_empty, "ondemand::array::is_empty", od_array_valid, od_array_fresh, od_array.is_empty())
/* ltl: ondemand_array_view */
OD_FRESH(od_array_reset, "ondemand::array::reset", od_array_valid, od_array_fresh, od_array.reset())
/* ltl: ondemand_array_view */
OD_FRESH(od_arres_count_elements, "simdjson_result<ondemand::array>::count_elements", od_array_valid, od_array_fresh, od_arres.count_elements())
/* ltl: ondemand_array_view */
OD_FRESH(od_arres_is_empty, "simdjson_result<ondemand::array>::is_empty", od_array_valid, od_array_fresh, od_arres.is_empty())
/* simdjson_result<array>::reset() is declared but never defined (repro_result_array_reset.cpp): the object one is used */
/* ltl: ondemand_object_view */
OD_FRESH(od_ores_reset, "simdjson_result<ondemand::object>::reset", od_object_valid, od_object_fresh, od_ores.reset())
/* ltl: ondemand_object_view */
OD_FRESH(od_object_count_fields, "ondemand::object::count_fields", od_object_valid, od_object_fresh, od_object.count_fields())
/* ltl: ondemand_object_view */
OD_FRESH(od_object_is_empty, "ondemand::object::is_empty", od_object_valid, od_object_fresh, od_object.is_empty())
/* ltl: ondemand_object_view */
OD_FRESH(od_object_reset, "ondemand::object::reset", od_object_valid, od_object_fresh, od_object.reset())
/* ltl: ondemand_object_view */
OD_FRESH(od_ores_count_fields, "simdjson_result<ondemand::object>::count_fields", od_object_valid, od_object_fresh, od_ores.count_fields())

/* "You may only call at_pointer on an array after it has been created, but before it has been first
 * accessed ... It is no longer possible to call at_pointer on the same array" (simdjson.h:84960): the
 * array is done after a path query, a wildcard walk, or raw_json (which consumes it) */
/* ltl: ondemand_array_view, ondemand_value_result_consumed_once */
static void call_od_array_at_path(payload in) {
    if (!od_array_valid || !od_array_fresh) return;
    od_array_valid = false;
    if (!preqed_call("ondemand::array::at_path")) return;
    od_take_vres("ondemand::array::at_path", od_array.at_path(view(in)));
}
/* ltl: ondemand_array_view */
static void call_od_array_for_each_at_path_with_wildcard(payload in) {
    if (!od_array_valid || !od_array_fresh) return;
    od_array_valid = false;
    REPORT("ondemand::array::for_each_at_path_with_wildcard",
           auto ec = od_array.for_each_at_path_with_wildcard(view(in), od_noop), ec == sj::SUCCESS);
    od_after(true);
}
/* ltl: ondemand_array_view */
static void call_od_arres_for_each_at_path_with_wildcard(payload in) {
    if (!od_array_valid || !od_array_fresh) return;
    od_array_valid = false;
    REPORT("simdjson_result<ondemand::array>::for_each_at_path_with_wildcard",
           auto ec = od_arres.for_each_at_path_with_wildcard(view(in), od_noop), ec == sj::SUCCESS);
    od_after(true);
}
/* ltl: ondemand_array_view */
static void call_od_arres_raw_json(payload) {
    if (!od_array_valid || !od_array_fresh) return;
    od_array_valid = false;
    OD_REPORT("simdjson_result<ondemand::array>::raw_json", od_arres.raw_json());
}

#define OD_OBJECT_LOOKUP(name, api, expr) \
    static void call_od_object_##name(payload in) { \
        if (!od_object_valid) return; \
        od_object_fresh = false; \
        if (!preqed_call(api)) return; \
        od_take_vres(api, expr); \
    }
/* ltl: ondemand_object_view, ondemand_value_result_consumed_once */
OD_OBJECT_LOOKUP(find_field_unordered, "ondemand::object::find_field_unordered", od_object.find_field_unordered(view(in)))
/* ltl: ondemand_object_view, ondemand_value_result_consumed_once */
OD_OBJECT_LOOKUP(subscript, "ondemand::object::operator[]", od_object[view(in)])
/* ltl: ondemand_object_view, ondemand_value_result_consumed_once */
OD_OBJECT_LOOKUP(at_path, "ondemand::object::at_path", od_object.at_path(view(in)))
/* ltl: ondemand_object_view */
static void call_od_object_for_each_at_path_with_wildcard(payload in) {
    if (!od_object_valid) return;
    od_object_fresh = od_field_valid = od_value_valid = od_vres_valid = false;
    REPORT("ondemand::object::for_each_at_path_with_wildcard",
           auto ec = od_object.for_each_at_path_with_wildcard(view(in), od_noop), ec == sj::SUCCESS);
    od_after(true);
}

/* stateless utilities */

static void call_minify(payload in) {
    std::vector<char> out(in.n + 1);
    size_t written = 0;
    REPORT("minify", auto ec = sj::minify(reinterpret_cast<const char *>(in.p), in.n, out.data(), written), ec == sj::SUCCESS);
}

static void call_validate_utf8(payload in) {
    REPORT("validate_utf8", (void)sj::validate_utf8(reinterpret_cast<const char *>(in.p), in.n), true);
}

static void call_padded_string_append(payload in) {
    REPORT("padded_string::append", bool ok = padded_buf->append(reinterpret_cast<const char *>(in.p), in.n), ok);
}

static const sj::implementation *pick_implementation(uint8_t b) {
    std::vector<const sj::implementation *> supported;
    for (const sj::implementation *impl : sj::get_available_implementations())
        if (impl->supported_by_runtime_system()) supported.push_back(impl);
    return supported.empty() ? nullptr : supported[b % supported.size()];
}

static void call_implementation_validate_utf8(payload in) {
    const sj::implementation *impl = pick_implementation(byte(in, 0));
    if (!impl) return;
    payload body = rest(in, 1);
    REPORT("implementation::validate_utf8", (void)impl->validate_utf8(reinterpret_cast<const char *>(body.p), body.n), true);
}

static void call_implementation_minify(payload in) {
    const sj::implementation *impl = pick_implementation(byte(in, 0));
    if (!impl) return;
    payload body = rest(in, 1);
    std::vector<uint8_t> out(body.n + sj::SIMDJSON_PADDING);
    size_t written = 0;
    REPORT("implementation::minify", auto ec = impl->minify(body.p, body.n, out.data(), written), ec == sj::SUCCESS);
}

static void call_builtin_implementation(payload) {
    REPORT("builtin_implementation", auto *impl = sj::builtin_implementation(), impl != nullptr);
}

static void call_implementation_name(payload in) {
    const sj::implementation *impl = pick_implementation(byte(in, 0));
    if (!impl) return;
    REPORT("implementation::name", (void)impl->name(), true);
}

static void call_implementation_description(payload in) {
    const sj::implementation *impl = pick_implementation(byte(in, 0));
    if (!impl) return;
    REPORT("implementation::description", (void)impl->description(), true);
}

/* error codes: any value below NUM_ERROR_CODES (simdjson.h:2746) */
static sj::error_code error_of(payload in) { return sj::error_code(byte(in, 0) % sj::NUM_ERROR_CODES); }

static void call_error_message(payload in) {
    REPORT("error_message", const char *m = sj::error_message(error_of(in)), m != nullptr);
}

static void call_is_fatal(payload in) {
    REPORT("is_fatal", (void)sj::is_fatal(error_of(in)), true);
}

static void call_error_code_stream(payload in) {
    std::ostringstream os;
    REPORT("operator<<(error_code)", os << error_of(in), bool(os));
}

static void call_simdjson_error_what(payload in) {
    sj::simdjson_error e(error_of(in));
    REPORT("simdjson_error::what", const char *w = e.what(), w != nullptr);
}

static void call_simdjson_error_error(payload in) {
    sj::simdjson_error e(error_of(in));
    REPORT("simdjson_error::error", (void)e.error(), true);
}

/* "If parsing fails, return the original string" (simdjson.h:13035) */
static void call_fractured_json_string(payload in) {
    REPORT("fractured_json_string", (void)sj::fractured_json_string(view(in)), true);
}

static void call_to_json(payload in) {
    int64_t v = 0;
    std::memcpy(&v, in.p, in.n < sizeof v ? in.n : sizeof v);
    REPORT("to_json", auto r = sj::to_json(v), !r.error());
}

/* padded strings: _padded, file load, swap and accessors on the parse(padded_string) buffer */

static void call_operator_padded(payload in) {
    REPORT("_padded", *padded_buf = operator""_padded(reinterpret_cast<const char *>(in.p), in.n), true);
}

static void call_padded_string_load(payload in) {
    memfile f(in);
    if (f.fd < 0) return;
    if (!preqed_call("padded_string::load")) return;
    auto r = sj::padded_string::load(f.path);
    bool ok = !r.error();
    preqed_result("padded_string::load", ok);
    if (ok) *padded_buf = std::move(r).value_unsafe();
}

static void call_padded_string_swap(payload in) {
    sj::padded_string other(view(in));
    REPORT("padded_string::swap", padded_buf->swap(other), true);
}

static void call_padded_string_size(payload) {
    REPORT("padded_string::size", (void)padded_buf->size(), true);
}

static void call_padded_string_u8data(payload) {
    REPORT("padded_string::u8data", (void)padded_buf->u8data(), true);
}

static void call_padded_string_to_string_view(payload) {
    REPORT("padded_string::operator(string_view)", std::string_view v = *padded_buf; (void)v, true);
}

/* padded_string_builder: append, then build (copy) or convert (move) into the parse(padded_string) buffer */

static sj::padded_string_builder *psb;

static void call_padded_string_builder_ctor(payload in) {
    size_t cap = size_t(byte(in, 0)) * 64;
    REPORT("padded_string_builder::padded_string_builder", sj::padded_string_builder b(cap); (void)b.length(), true);
}

static void call_padded_string_builder_operator_assign(payload in) {
    size_t cap = size_t(byte(in, 0)) * 64;
    REPORT("padded_string_builder::operator=", *psb = sj::padded_string_builder(cap), true);
}

static void call_padded_string_builder_append(payload in) {
    payload body = rest(in, 1);
    REPORT("padded_string_builder::append",
           bool ok = byte(in, 0) & 1 ? psb->append(view(body)) : psb->append(reinterpret_cast<const char *>(body.p), body.n), ok);
}

static void call_padded_string_builder_length(payload) {
    REPORT("padded_string_builder::length", (void)psb->length(), true);
}

static void call_padded_string_builder_build(payload) {
    REPORT("padded_string_builder::build", *padded_buf = psb->build(), true);
}

static void call_padded_string_builder_convert(payload) {
    REPORT("padded_string_builder::convert", *padded_buf = psb->convert(), true);
}

/* padded_input may point into its source when the padding stays inside the page (simdjson.h:4735): the
 * source keeps SIMDJSON_PADDING bytes of capacity, so reads through the view stay inside its allocation */

static std::string *padded_in_src;
static sj::padded_input *padded_in;

static void call_padded_input_ctor(payload in) {
    delete padded_in;
    padded_in = nullptr;
    padded_in_src->clear();
    padded_in_src->reserve(in.n + sj::SIMDJSON_PADDING);
    padded_in_src->assign(reinterpret_cast<const char *>(in.p), in.n);
    const std::string &s = *padded_in_src;
    switch (byte(in, 0) % 3) {
    case 0: REPORT("padded_input::padded_input", padded_in = new sj::padded_input(std::string_view(s)), true); break;
    case 1: REPORT("padded_input::padded_input", padded_in = new sj::padded_input(s.data(), s.size()), true); break;
    default: REPORT("padded_input::padded_input", padded_in = new sj::padded_input(s), true); break;
    }
}

static void call_padded_input_is_view(payload) {
    if (!padded_in) return;
    REPORT("padded_input::is_view", (void)padded_in->is_view(), true);
}

static void call_padded_input_to_view(payload) {
    if (!padded_in) return;
    REPORT("padded_input::operator(padded_string_view)", sj::padded_string_view v = *padded_in, v.length() == padded_in_src->size());
}

/* padded_memory_map: "In case of error ... view() will return an empty view" (simdjson.h:4541) */

static sj::padded_memory_map *pmm;

static void call_padded_memory_map_ctor(payload in) {
    memfile f(in);
    if (f.fd < 0) return;
    delete pmm;
    REPORT("padded_memory_map::padded_memory_map", pmm = new sj::padded_memory_map(f.path.c_str()), true);
}

static void call_padded_memory_map_is_valid(payload) {
    if (!pmm) return;
    REPORT("padded_memory_map::is_valid", bool v = pmm->is_valid(), v);
}

static void call_padded_memory_map_view(payload) {
    if (!pmm) return;
    REPORT("padded_memory_map::view", sj::padded_string_view v = pmm->view(); (void)v, true);
}

/* builder::string_builder: one builder, content need not be valid JSON (no UTF-8 validation, builder.md) */

static sj::builder::string_builder *sb;
static std::string cstr(payload in) { return std::string(view(in)); }  /* NUL-terminated copy for const char * overloads */

static void call_string_builder_ctor(payload in) {
    REPORT("builder::string_builder::string_builder", *sb = sj::builder::string_builder(1 + size_t(byte(in, 0)) * 16), true);
}

static void call_string_builder_append(payload in) {
    payload body = rest(in, 1);
    int64_t i = 0;
    double d = 0;
    std::memcpy(&i, body.p, body.n < sizeof i ? body.n : sizeof i);
    std::memcpy(&d, body.p, body.n < sizeof d ? body.n : sizeof d);
    switch (byte(in, 0) % 4) {
    case 0: REPORT("builder::string_builder::append", sb->append(i), true); break;
    case 1: REPORT("builder::string_builder::append", sb->append(d), true); break;
    case 2: REPORT("builder::string_builder::append", sb->append(bool(i & 1)), true); break;
    default: REPORT("builder::string_builder::append", sb->append(char(byte(body, 0))), true); break;
    }
}

#define SB_PLAIN(method) \
    static void call_string_builder_##method(payload) { \
        REPORT("builder::string_builder::" #method, sb->method(), true); \
    }
SB_PLAIN(append_null)
SB_PLAIN(clear)
SB_PLAIN(start_object)
SB_PLAIN(end_object)
SB_PLAIN(start_array)
SB_PLAIN(end_array)
SB_PLAIN(append_comma)
SB_PLAIN(append_colon)

static void call_string_builder_escape_and_append(payload in) {
    REPORT("builder::string_builder::escape_and_append", sb->escape_and_append(view(in)), true);
}

static void call_string_builder_escape_and_append_with_quotes(payload in) {
    payload body = rest(in, 1);
    switch (byte(in, 0) % 3) {
    case 0: REPORT("builder::string_builder::escape_and_append_with_quotes", sb->escape_and_append_with_quotes(view(body)), true); break;
    case 1: REPORT("builder::string_builder::escape_and_append_with_quotes", sb->escape_and_append_with_quotes(char(byte(body, 0))), true); break;
    default: { std::string s = cstr(body); REPORT("builder::string_builder::escape_and_append_with_quotes", sb->escape_and_append_with_quotes(s.c_str()), true); break; }
    }
}

static void call_string_builder_append_raw(payload in) {
    payload body = rest(in, 1);
    switch (byte(in, 0) % 3) {
    case 0: { std::string s = cstr(body); REPORT("builder::string_builder::append_raw", sb->append_raw(s.c_str()), true); break; }
    case 1: REPORT("builder::string_builder::append_raw", sb->append_raw(view(body)), true); break;
    default: REPORT("builder::string_builder::append_raw", sb->append_raw(reinterpret_cast<const char *>(body.p), body.n), true); break;
    }
}

/* "Append exactly N characters from str" */
static void call_string_builder_append_raw_n(payload in) {
    if (in.n < 8) return;
    REPORT("builder::string_builder::append_raw_n", sb->append_raw_n<8>(reinterpret_cast<const char *>(in.p)), true);
}

static void call_string_builder_append_key_value(payload in) {
    int64_t v = 0;
    std::memcpy(&v, in.p, in.n < sizeof v ? in.n : sizeof v);
    REPORT("builder::string_builder::append_key_value", sb->append_key_value(view(rest(in, 8)), v), true);
}

static void call_string_builder_to_string(payload) {
    THROWING("builder::string_builder::operator(string)", std::string s = sb->operator std::string(); (void)s);
}

static void call_string_builder_to_string_view(payload) {
    THROWING("builder::string_builder::operator(string_view)", std::string_view s = sb->operator std::string_view(); (void)s);
}

static void call_string_builder_view(payload) {
    REPORT("builder::string_builder::view", auto r = sb->view(), !r.error());
}

static void call_string_builder_c_str(payload) {
    REPORT("builder::string_builder::c_str", auto r = sb->c_str(), !r.error());
}

static void call_string_builder_size(payload) {
    REPORT("builder::string_builder::size", (void)sb->size(), true);
}

static void call_string_builder_validate_unicode(payload) {
    REPORT("builder::string_builder::validate_unicode", (void)sb->validate_unicode(), true);
}

/* dispatch */

static void (*const api[])(payload) = {
    call_dom_parser_parse, call_dom_parser_parse_padded, call_dom_parser_parse_unpadded,
    call_dom_parser_parse_into_document, call_dom_parser_parse_many, call_dom_parser_allocate,
    call_dom_parser_number_as_string, call_dom_document_stream_next, call_dom_document_stream_advance,
    call_dom_element_at_pointer, call_dom_element_at_key, call_dom_element_at_key_case_insensitive, call_dom_element_at,
    call_dom_element_get_string, call_dom_element_get_c_str, call_dom_element_get_string_length,
    call_dom_element_get_int64, call_dom_element_get_uint64, call_dom_element_get_double, call_dom_element_get_bool,
    call_dom_element_get_bigint, call_dom_element_type, call_dom_element_is_number, call_dom_element_dump_raw_tape,
    call_dom_operator_stream,
    call_dom_element_get_array, call_dom_array_size, call_dom_array_at, call_dom_array_at_pointer,
    call_dom_array_iterator_deref, call_dom_array_iterator_advance,
    call_dom_element_get_object, call_dom_object_size, call_dom_object_at_key, call_dom_object_at_key_case_insensitive,
    call_dom_object_iterator_deref, call_dom_object_iterator_advance,
    call_ondemand_parser_iterate, call_ondemand_parser_iterate_many, call_ondemand_document_stream_next,
    call_ondemand_document_reference_type,
    call_ondemand_document_stream_advance, call_ondemand_document_rewind,
    call_od_doc_get_int64, call_od_doc_get_uint64, call_od_doc_get_double, call_od_doc_get_bool,
    call_od_doc_get_string, call_od_doc_get_raw_json_string, call_od_doc_get_number, call_od_doc_is_null,
    call_od_doc_raw_json, call_od_doc_type, call_od_doc_get_value, call_od_doc_find_field, call_od_doc_at_pointer,
    call_od_doc_get_array, call_od_doc_get_object,
    call_od_value_type, call_od_value_get_int64, call_od_value_get_uint64, call_od_value_get_double,
    call_od_value_get_bool, call_od_value_get_string, call_od_value_get_number, call_od_value_is_null,
    call_od_value_raw_json, call_od_value_get_array, call_od_value_get_object,
    call_od_array_iterator_deref, call_od_array_iterator_advance,
    call_od_object_iterator_deref, call_od_object_iterator_advance, call_od_field_unescaped_key, call_od_field_value,
    call_od_object_find_field,
    call_minify, call_validate_utf8, call_padded_string_append,
    call_implementation_validate_utf8, call_implementation_minify,
    call_dom_parser_load, call_dom_parser_load_into_document, call_dom_parser_load_many,
    call_dom_parser_operator_assign, call_dom_parser_set_max_capacity, call_dom_document_operator_assign,
    call_dom_document_stream_operator_assign, call_dom_document_stream_size_in_bytes,
    call_dom_document_stream_truncated_bytes, call_dom_document_stream_iterator_current_index,
    call_dom_document_stream_iterator_source, call_dom_element_is_array, call_dom_element_is_object,
    call_dom_element_is_string, call_dom_element_is_bool, call_dom_element_is_null, call_dom_element_is_bigint,
    call_dom_element_at_path, call_dom_element_at_path_with_wildcard, call_dom_element_subscript,
    call_dom_element_to_bool, call_dom_element_to_c_str, call_dom_element_to_string_view, call_dom_element_to_uint64,
    call_dom_element_to_int64, call_dom_element_to_double, call_dom_element_to_array, call_dom_element_to_object,
    call_dom_element_begin, call_dom_element_end, call_dom_element_less, call_dom_element_equal, call_dom_element_tie,
    call_to_string, call_prettify, call_fractured_json, call_dom_array_at_path, call_dom_array_at_path_with_wildcard,
    call_dom_array_get_values, call_dom_array_number_of_slots, call_dom_array_to_element, call_dom_array_iterator_eq,
    call_dom_array_iterator_lt, call_dom_array_iterator_le, call_dom_array_iterator_gt, call_dom_array_iterator_ge,
    call_dom_object_iterator_eq, call_dom_object_iterator_lt, call_dom_object_iterator_le,
    call_dom_object_iterator_gt, call_dom_object_iterator_ge, call_dom_object_at_path,
    call_dom_object_at_path_with_wildcard, call_dom_object_get_values, call_dom_object_subscript,
    call_dom_object_to_element, call_dom_res_type, call_dom_res_get_array, call_dom_res_get_object,
    call_dom_res_get_c_str, call_dom_res_get_string_length, call_dom_res_get_string, call_dom_res_get_int64,
    call_dom_res_get_uint64, call_dom_res_get_double, call_dom_res_get_bool, call_dom_res_get_bigint,
    call_dom_res_is_array, call_dom_res_is_object, call_dom_res_is_string, call_dom_res_is_int64,
    call_dom_res_is_uint64, call_dom_res_is_double, call_dom_res_is_number, call_dom_res_is_bool,
    call_dom_res_is_null, call_dom_res_is_bigint, call_dom_res_is, call_dom_res_subscript, call_dom_res_at_path,
    call_dom_res_at_path_with_wildcard, call_dom_res_to_bool, call_dom_res_to_c_str, call_dom_res_to_string_view,
    call_dom_res_to_uint64, call_dom_res_to_int64, call_dom_res_to_double, call_dom_res_to_array,
    call_dom_res_to_object, call_dom_res_begin, call_dom_res_end, call_dom_ares_size, call_dom_ares_get_values,
    call_result_value, call_result_take_value, call_result_operator_rvalue, call_result_tie, call_od_doc_get_int32,
    call_od_doc_get_uint32, call_od_doc_get_int64_in_string, call_od_doc_get_uint64_in_string,
    call_od_doc_get_double_in_string, call_od_doc_get_wobbly_string, call_od_doc_get, call_od_doc_is_integer,
    call_od_doc_is_string, call_od_doc_get_number_type, call_od_doc_raw_json_token, call_od_doc_is_negative,
    call_od_doc_current_location, call_od_doc_current_depth, call_od_doc_at_end, call_od_doc_count_elements,
    call_od_doc_count_fields, call_od_doc_find_field_unordered, call_od_doc_subscript, call_od_doc_at_path,
    call_od_doc_for_each_at_path_with_wildcard, call_od_doc_begin, call_od_doc_end, call_od_doc_to_array,
    call_od_doc_to_object, call_od_doc_to_uint64, call_od_doc_to_int64, call_od_doc_to_double,
    call_od_doc_to_string_view, call_od_doc_to_raw_json_string, call_od_doc_to_bool, call_od_doc_to_value,
    call_od_doc_to_T, call_od_ref_get_bool, call_od_ref_get_double, call_od_ref_get_double_in_string,
    call_od_ref_get_int32, call_od_ref_get_int64, call_od_ref_get_int64_in_string, call_od_ref_get_number,
    call_od_ref_get_raw_json_string, call_od_ref_get_string, call_od_ref_get_uint32, call_od_ref_get_uint64,
    call_od_ref_get_uint64_in_string, call_od_ref_get_wobbly_string, call_od_ref_is_null, call_od_ref_raw_json,
    call_od_ref_get, call_od_ref_get_value, call_od_ref_get_array, call_od_ref_get_object, call_od_ref_is_integer,
    call_od_ref_is_scalar, call_od_ref_is_string, call_od_ref_get_number_type, call_od_ref_raw_json_token,
    call_od_ref_is_negative, call_od_ref_current_location, call_od_ref_current_depth, call_od_ref_to_document,
    call_od_ref_count_elements, call_od_ref_count_fields, call_od_ref_find_field_unordered, call_od_ref_subscript,
    call_od_ref_at_path, call_od_ref_for_each_at_path_with_wildcard, call_od_ref_begin, call_od_ref_end,
    call_od_ref_rewind, call_od_ref_to_array, call_od_ref_to_object, call_od_ref_to_uint64, call_od_ref_to_int64,
    call_od_ref_to_double, call_od_ref_to_string_view, call_od_ref_to_raw_json_string, call_od_ref_to_bool,
    call_od_ref_to_value, call_od_ref_to_T, call_od_rres_rewind, call_od_rres_get_value, call_od_rres_to_value,
    call_od_stream_size_in_bytes, call_od_stream_truncated_bytes, call_od_stream_iterator_current_index,
    call_od_stream_iterator_source, call_od_stream_iterator_error, call_od_stream_iterator_equal,
    call_od_stream_operator_assign, call_od_parser_operator_assign, call_od_parser_set_max_capacity,
    call_od_parser_get_parser, call_od_parser_release_parser, call_od_value_get_int32, call_od_value_get_uint32,
    call_od_value_get_int64_in_string, call_od_value_get_uint64_in_string, call_od_value_get_double_in_string,
    call_od_value_get_wobbly_string, call_od_value_get, call_od_value_get_raw_json_string, call_od_value_is_scalar,
    call_od_value_is_string, call_od_value_is_integer, call_od_value_get_number_type, call_od_value_current_location,
    call_od_value_count_elements, call_od_value_count_fields, call_od_value_is_negative, call_od_value_raw_json_token,
    call_od_value_current_depth, call_od_value_find_field_unordered, call_od_value_subscript, call_od_value_at_path,
    call_od_value_for_each_at_path_with_wildcard, call_od_value_begin, call_od_value_end, call_od_value_to_array,
    call_od_value_to_object, call_od_value_to_uint64, call_od_value_to_int64, call_od_value_to_double,
    call_od_value_to_string_view, call_od_value_to_raw_json_string, call_od_value_to_bool, call_od_value_to_T,
    call_to_json_string, call_od_vres_get_uint64, call_od_vres_get_int64, call_od_vres_get_uint32,
    call_od_vres_get_int32, call_od_vres_get_uint64_in_string, call_od_vres_get_int64_in_string,
    call_od_vres_get_double, call_od_vres_get_double_in_string, call_od_vres_get_string,
    call_od_vres_get_wobbly_string, call_od_vres_get_bool, call_od_vres_is_null, call_od_vres_raw_json,
    call_od_vres_get_raw_json_string, call_od_vres_get_number, call_od_vres_get_array, call_od_vres_get_object,
    call_od_vres_type, call_od_vres_is_scalar, call_od_vres_is_string, call_od_vres_is_negative,
    call_od_vres_is_integer, call_od_vres_get_number_type, call_od_vres_current_location, call_od_vres_current_depth,
    call_od_vres_raw_json_token, call_od_vres_count_elements, call_od_vres_count_fields, call_od_vres_has_value,
    call_od_vres_arrow, call_od_vres_find_field_unordered, call_od_vres_subscript, call_od_vres_at_path,
    call_od_vres_for_each_at_path_with_wildcard, call_od_vres_begin, call_od_vres_end, call_od_vres_to_array,
    call_od_vres_to_object, call_od_vres_to_uint64, call_od_vres_to_int64, call_od_vres_to_double,
    call_od_vres_to_string_view, call_od_vres_to_raw_json_string, call_od_vres_to_bool, call_od_vres_to_T,
    call_od_vres_deref, call_od_vres_value, call_od_vres_take_value, call_od_vres_value_unsafe, call_od_vres_rvalue,
    call_od_riter_not_equal, call_od_riter_equal, call_od_riter_at_end, call_od_riter_deref, call_od_riter_advance,
    call_od_field_key, call_od_field_key_raw_json_token, call_od_field_escaped_key, call_od_fres_key,
    call_od_fres_key_raw_json_token, call_od_fres_escaped_key, call_od_fres_unescaped_key, call_od_fres_value,
    call_od_raw_equal, call_od_raw_not_equal, call_od_number_get_number_type, call_od_number_is_uint64,
    call_od_number_is_int64, call_od_number_is_double, call_od_number_as_double, call_od_number_get_uint64,
    call_od_number_get_int64, call_od_number_get_double, call_od_number_to_uint64, call_od_number_to_int64,
    call_od_number_to_double, call_od_number_type_stream, call_od_json_type_stream, call_od_array_iterator_equal,
    call_od_object_iterator_equal, call_od_array_count_elements, call_od_array_is_empty, call_od_array_reset,
    call_od_arres_count_elements, call_od_arres_is_empty, call_od_ores_reset, call_od_object_count_fields,
    call_od_object_is_empty, call_od_object_reset, call_od_ores_count_fields, call_od_array_at_path,
    call_od_array_for_each_at_path_with_wildcard, call_od_arres_for_each_at_path_with_wildcard,
    call_od_arres_raw_json, call_od_object_find_field_unordered, call_od_object_subscript, call_od_object_at_path,
    call_od_object_for_each_at_path_with_wildcard, call_builtin_implementation, call_implementation_name,
    call_implementation_description, call_error_message, call_is_fatal, call_error_code_stream,
    call_simdjson_error_what, call_simdjson_error_error, call_fractured_json_string, call_to_json,
    call_operator_padded, call_padded_string_load, call_padded_string_swap, call_padded_string_size,
    call_padded_string_u8data, call_padded_string_to_string_view, call_padded_string_builder_ctor,
    call_padded_string_builder_operator_assign, call_padded_string_builder_append, call_padded_string_builder_length,
    call_padded_string_builder_build, call_padded_string_builder_convert, call_padded_input_ctor,
    call_padded_input_is_view, call_padded_input_to_view, call_padded_memory_map_ctor,
    call_padded_memory_map_is_valid, call_padded_memory_map_view, call_string_builder_ctor,
    call_string_builder_append, call_string_builder_append_null, call_string_builder_clear,
    call_string_builder_start_object, call_string_builder_end_object, call_string_builder_start_array,
    call_string_builder_end_array, call_string_builder_append_comma, call_string_builder_append_colon,
    call_string_builder_escape_and_append, call_string_builder_escape_and_append_with_quotes,
    call_string_builder_append_raw, call_string_builder_append_raw_n, call_string_builder_append_key_value,
    call_string_builder_to_string, call_string_builder_to_string_view, call_string_builder_view,
    call_string_builder_c_str, call_string_builder_size, call_string_builder_validate_unicode,
};

static const size_t API_COUNT = sizeof api / sizeof api[0];

static void setup() {
    dom_parser = new sj::dom::parser();
    dom_document = new sj::dom::document();
    dom_stream_input = new sj::padded_string();
    padded_buf = new sj::padded_string();
    dom_stream = new sj::dom::document_stream();
    od_parser = new sj::ondemand::parser();
    od_input = new sj::padded_string();
    od_doc = new sj::ondemand::document();
    od_stream = new sj::ondemand::document_stream();
    psb = new sj::padded_string_builder();
    padded_in_src = new std::string();
    sb = new sj::builder::string_builder();
}

static void cleanup() {
    delete sb;
    delete pmm;
    pmm = nullptr;
    delete padded_in;
    padded_in = nullptr;
    delete padded_in_src;
    delete psb;
    od_number_valid = od_rend_set = od_stream_started = false;
    delete od_stream;
    delete od_doc;
    delete od_input;
    delete od_parser;
    delete dom_stream;
    delete dom_stream_input;
    delete padded_buf;
    delete dom_document;
    delete dom_parser;
    dom_elements_gone();
    dom_stream_valid = false;
    od_parser_reused();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    preqed_reset();
    setup();
    size_t off = 0;
    while (size - off >= 4) {
        size_t op = static_cast<size_t>(data[off]) | static_cast<size_t>(data[off + 1]) << 8;  /* more than 256 wrappers */
        size_t len = static_cast<size_t>(data[off + 2]) | static_cast<size_t>(data[off + 3]) << 8;
        off += 4;
        if (len > size - off) break;
        api[op % API_COUNT]({ data + off, len });
        off += len;
    }
    cleanup();
    return 0;
}
