#include <jsoncons/json.hpp>
#include <jsoncons/json_cursor.hpp>
#include <jsoncons/json_parser.hpp>
#include <jsoncons/json_reader.hpp>
#include <jsoncons/json_filter.hpp>
#include <jsoncons/staj_iterator.hpp>
#include <jsoncons/sink.hpp>
#include <jsoncons/utility/bigint.hpp>
#include <jsoncons/utility/uri.hpp>
#include <jsoncons_ext/bson/bson.hpp>
#include <jsoncons_ext/cbor/cbor.hpp>
#include <jsoncons_ext/csv/csv.hpp>
#include <jsoncons_ext/jmespath/jmespath.hpp>
#include <jsoncons_ext/jsonpatch/jsonpatch.hpp>
#include <jsoncons_ext/jsonpath/jsonpath.hpp>
#include <jsoncons_ext/jsonpointer/jsonpointer.hpp>
#include <jsoncons_ext/jsonschema/jsonschema.hpp>
#include <jsoncons_ext/mergepatch/mergepatch.hpp>
#include <jsoncons_ext/msgpack/msgpack.hpp>
#include <jsoncons_ext/toon/decode_toon.hpp>
#include <jsoncons_ext/toon/toon.hpp>
#include <jsoncons_ext/toon/toon_reader.hpp>
#include <jsoncons_ext/ubjson/ubjson.hpp>
#include "preqed_ltl.h"

#include <cstdint>
#include <cstring>
#include <memory>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>

using jsoncons::json;

struct payload {
    const uint8_t *p;
    size_t n;
};

static json current;                        /* the document most calls read or rewrite */
static bool have;
static std::string text_out;                /* last dump / encode_csv / encode_toon output */
static std::vector<uint8_t> bytes_out;      /* last binary encoding */
static std::unique_ptr<jsoncons::jsonschema::json_schema<json>> schema;
static std::unique_ptr<jsoncons::bigint> number, previous_number;
static std::unique_ptr<std::istringstream> cursor_input;   /* the cursor reads from it */
static std::unique_ptr<jsoncons::json_stream_cursor> cursor;

/* options every decode/encode wrapper of the format uses; the setter wrappers change them */
static jsoncons::json_options json_opts;
static jsoncons::csv::csv_options csv_opts;
static jsoncons::toon::toon_options toon_opts;
static jsoncons::cbor::cbor_options cbor_opts;
static jsoncons::bson::bson_options bson_opts;
static jsoncons::msgpack::msgpack_options msgpack_opts;
static jsoncons::ubjson::ubjson_options ubjson_opts;
static jsoncons::jsonschema::evaluation_options schema_opts;

/* last error objects the library threw or returned */
static std::unique_ptr<jsoncons::ser_error> parse_err;
static std::unique_ptr<jsoncons::read_error> read_err;
static std::unique_ptr<jsoncons::conv_error> conv_err;
static std::unique_ptr<jsoncons::conversion_error> conversion_err;
static std::unique_ptr<jsoncons::jsonpatch::jsonpatch_error> patch_err;
static std::unique_ptr<jsoncons::jsonpointer::jsonpointer_error> pointer_err;
static std::unique_ptr<jsoncons::jsonpath::jsonpath_error> jsonpath_err;
static std::unique_ptr<jsoncons::jmespath::jmespath_error> jmespath_err;
static std::unique_ptr<jsoncons::jsonschema::schema_error> schema_err;
static std::unique_ptr<jsoncons::jsonschema::validation_error> validation_err;
static std::vector<jsoncons::jsonschema::validation_message> messages;

static jsoncons::byte_string bytes;                       /* byte_string wrappers work on it */
static jsoncons::jsonpath::json_location location;        /* json_location wrappers work on it */
static jsoncons::jsonpath::path_element element{std::size_t(0)};
static std::unique_ptr<jsoncons::jsonpath::jsonpath_expression<json>> jsonpath_expr;
static jsoncons::jsonpath::custom_functions<json> jsonpath_functions;
static std::unique_ptr<jsoncons::jmespath::jmespath_expression<json>> jmespath_expr;
static jsoncons::jmespath::custom_functions<json> jmespath_functions;

/* binary and CSV cursors, each over its own input */
static std::vector<uint8_t> cbor_cursor_input, bson_cursor_input, msgpack_cursor_input, ubjson_cursor_input;
static std::string csv_cursor_input;
static std::unique_ptr<jsoncons::cbor::cbor_bytes_cursor> cbor_cursor;
static std::unique_ptr<jsoncons::bson::bson_bytes_cursor> bson_cursor;
static std::unique_ptr<jsoncons::msgpack::msgpack_bytes_cursor> msgpack_cursor;
static std::unique_ptr<jsoncons::ubjson::ubjson_bytes_cursor> ubjson_cursor;
static std::unique_ptr<jsoncons::csv::csv_string_cursor> csv_cursor;

static uint8_t byte(payload in, size_t i) { return i < in.n ? in.p[i] : 0; }
static payload rest(payload in, size_t skip) {
    return { in.p + (skip < in.n ? skip : in.n), in.n > skip ? in.n - skip : 0 };
}
static std::string text(payload in) { return std::string(reinterpret_cast<const char *>(in.p), in.n); }
static bool flag(payload in) { return byte(in, 0) & 1; }
static char ch(payload in) { return static_cast<char>(byte(in, 0)); }
/* two arguments: the first byte gives the length of the first one */
static void split(payload in, payload &a, payload &b) {
    size_t k = in.n ? byte(in, 0) % in.n : 0;
    a = { in.p + (in.n ? 1 : 0), in.n ? k : 0 };
    b = rest(in, 1 + k);
}
static std::wstring wide(payload in) { return std::wstring(in.p, in.p + in.n); }

/* jsoncons reports malformed input by throwing (ser_error, jsonpath_error, ...) */
#define TRY(api, stmt, ok_cond) \
    do { \
        if (!preqed_call(api)) return; \
        bool ok_ = false; \
        try { stmt; ok_ = (ok_cond); } catch (const std::exception &) {} \
        preqed_result(api, ok_); \
    } while (0)

/* as TRY, and keeps a copy of the documented exception type in slot */
#define TRY_KEEP(api, stmt, ok_cond, error_type, slot) \
    do { \
        if (!preqed_call(api)) return; \
        bool ok_ = false; \
        try { stmt; ok_ = (ok_cond); } \
        catch (const error_type &e) { slot.reset(new error_type(e)); } \
        catch (const std::exception &) {} \
        preqed_result(api, ok_); \
    } while (0)

static void take(json value) {
    current = std::move(value);
    have = true;
}

/* first byte bit 0: operate on the current document, else on a JSON string built from the rest */
static bool select(payload in, json &out) {
    if (byte(in, 0) & 1) {
        if (!have) return false;
        out = current;
    } else {
        out = json(text(rest(in, 1)));
    }
    return true;
}

/* a nested JSON argument parsed from the payload; failures are reported as json::parse */
static bool argument(payload in, json &out) {
    bool ok = false;
    if (!preqed_call("json::parse")) return false;
    try { out = json::parse(text(in)); ok = true; } catch (const std::exception &) {}
    preqed_result("json::parse", ok);
    return ok;
}

/* binary decoder input: the last encoding, or the payload. chars_source::read does memcpy(p, data(), 0) on an
 * empty buffer, and an empty std::vector has data() == nullptr (source.hpp:598), so empty input is skipped. */
static bool binary_input(payload in, std::vector<uint8_t> &out) {
    if ((byte(in, 0) & 1) && !bytes_out.empty()) out = bytes_out;
    else out.assign(in.p + (in.n ? 1 : 0), in.p + in.n);
    return !out.empty();
}

/* JSON text */

static void call_json_parse(payload in) {
    std::string s = byte(in, 0) & 1 ? text_out : text(rest(in, 1));
    TRY_KEEP("json::parse", take(json::parse(s, json_opts)), true, jsoncons::ser_error, parse_err);
}

static void call_json_parse_stream(payload in) {
    std::istringstream is(text(in));
    TRY("json::parse(istream)", take(json::parse(is, json_opts)), true);
}

static void call_json_dump(payload in) {
    json value;
    if (!select(in, value)) return;
    TRY("json::dump", text_out.clear(); value.dump(text_out, json_opts), true);
}

static void call_json_dump_pretty(payload in) {
    json value;
    if (!select(in, value)) return;
    TRY("json::dump_pretty", text_out.clear(); value.dump_pretty(text_out, json_opts), true);
}

static void call_json_dump_encoder(payload in) {
    json value;
    if (!select(in, value)) return;
    TRY("json::dump(json_string_encoder)", text_out.clear(); jsoncons::json_string_encoder encoder(text_out);
        value.dump(encoder), true);
}

static void call_json_stream_reader_read(payload in) {
    std::istringstream is(text(in));
    jsoncons::json_decoder<json> decoder;
    std::error_code ec;
    TRY("json_stream_reader::read", jsoncons::json_stream_reader reader(is, decoder); reader.read(ec);
        if (!ec && decoder.is_valid()) take(decoder.get_result()), !ec && have);
}

static void call_json_stream_reader_read_to_encoder(payload in) {
    std::istringstream is(text(in));
    std::string encoded;
    std::error_code ec;
    TRY("json_stream_reader::read(encoder)", jsoncons::json_string_encoder encoder(encoded);
        jsoncons::json_stream_reader reader(is, encoder); reader.read(ec); if (!ec) text_out = encoded, !ec);
}

static void call_json_parser_update_finish(payload in) {
    std::string s = text(in);
    jsoncons::json_parser parser;
    jsoncons::json_decoder<json> decoder;
    TRY("json_parser::update", parser.update(s.data(), s.size()), true);
    std::error_code ec;
    TRY("json_parser::finish_parse", parser.finish_parse(decoder, ec);
        if (!ec && decoder.is_valid()) take(decoder.get_result()), !ec && decoder.is_valid());
}

/* stream cursor: one live cursor over its own input, advanced one event per record */
/* ltl: cursor_lifecycle */
static void call_json_stream_cursor_ctor(payload in) {
    cursor.reset();
    cursor_input.reset(new std::istringstream(text(in)));
    std::error_code ec;
    TRY("json_stream_cursor::json_stream_cursor", cursor.reset(new jsoncons::json_stream_cursor(*cursor_input, ec)), !ec);
    if (ec) cursor.reset();
}
/* ltl: cursor_lifecycle */
static void call_json_stream_cursor_current(payload) {
    if (!cursor || cursor->done()) return;
    TRY("json_stream_cursor::current", (void)cursor->current(), true);
}
/* ltl: cursor_lifecycle */
static void call_json_stream_cursor_next(payload) {
    if (!cursor || cursor->done()) return;
    std::error_code ec;
    TRY("json_stream_cursor::next", cursor->next(ec), !ec);
    if (ec) cursor.reset();
}

/* document edits */

static void call_json_insert_or_assign(payload in) {
    if (!have || !current.is_object()) return;
    std::string s = text(in);
    TRY("json::insert_or_assign", current.insert_or_assign(s, json(s)), true);
}

static void call_json_push_back(payload in) {
    if (!have || !current.is_array()) return;
    TRY("json::push_back", current.push_back(json(text(in))), true);
}

/* CSV and TOON */

static void call_decode_csv(payload in) {
    jsoncons::csv::csv_options options = csv_opts;
    options.assume_header(byte(in, 0) & 1);
    TRY("csv::decode_csv", take(jsoncons::csv::decode_csv<json>(text(rest(in, 1)), options)), true);
}

static void call_encode_csv(payload in) {
    if (!have) return;
    jsoncons::csv::csv_options options = csv_opts;
    options.field_delimiter(byte(in, 0) & 1 ? ';' : ',');
    TRY("csv::encode_csv", text_out.clear(); jsoncons::csv::encode_csv(current, text_out, options), true);
}

static void call_decode_toon(payload in) {
    TRY("toon::decode_toon", take(jsoncons::toon::decode_toon<json>(text(in), toon_opts)), true);
}

static void call_encode_toon(payload in) {
    json value;
    if (!select(in, value)) return;
    TRY("toon::encode_toon", text_out.clear(); jsoncons::toon::encode_toon(value, text_out, toon_opts), true);
}

/* binary formats */

static void call_decode_cbor(payload in) {
    std::vector<uint8_t> input;
    if (!binary_input(in, input)) return;
    TRY("cbor::decode_cbor", take(jsoncons::cbor::decode_cbor<json>(input, cbor_opts)), true);
}

static void call_decode_bson(payload in) {
    std::vector<uint8_t> input;
    if (!binary_input(in, input)) return;
    TRY("bson::decode_bson", take(jsoncons::bson::decode_bson<json>(input, bson_opts)), true);
}

static void call_decode_msgpack(payload in) {
    std::vector<uint8_t> input;
    if (!binary_input(in, input)) return;
    TRY("msgpack::decode_msgpack", take(jsoncons::msgpack::decode_msgpack<json>(input.begin(), input.end(), msgpack_opts)), true);
}

static void call_decode_msgpack_stream(payload in) {
    std::istringstream is(text(in));
    TRY("msgpack::decode_msgpack(istream)", take(jsoncons::msgpack::decode_msgpack<json>(is, msgpack_opts)), true);
}

static void call_decode_ubjson(payload in) {
    std::vector<uint8_t> input;
    if (!binary_input(in, input)) return;
    TRY("ubjson::decode_ubjson", take(jsoncons::ubjson::decode_ubjson<json>(input, ubjson_opts)), true);
}

#define ENCODE(api, fn, opts) \
    static void call_##fn(payload in) { \
        json value; \
        if (!select(in, value)) return; \
        TRY(api, bytes_out.clear(); fn(value, bytes_out, opts), true); \
    }
using jsoncons::bson::encode_bson;
using jsoncons::cbor::encode_cbor;
using jsoncons::msgpack::encode_msgpack;
using jsoncons::ubjson::encode_ubjson;
ENCODE("cbor::encode_cbor", encode_cbor, cbor_opts)
ENCODE("bson::encode_bson", encode_bson, bson_opts)
ENCODE("msgpack::encode_msgpack", encode_msgpack, msgpack_opts)
ENCODE("ubjson::encode_ubjson", encode_ubjson, ubjson_opts)

static void call_encode_msgpack_stream(payload in) {
    json value;
    if (!select(in, value)) return;
    std::ostringstream os;
    TRY("msgpack::encode_msgpack(ostream)", encode_msgpack(value, os, msgpack_opts); text_out = os.str(), true);
}

/* JSON Pointer, Patch, Merge Patch */

static bool pointer(payload in, jsoncons::jsonpointer::json_pointer &out) {
    std::error_code ec;
    if (!preqed_call("jsonpointer::json_pointer::parse")) return false;
    bool ok = false;
    try { out = jsoncons::jsonpointer::json_pointer::parse(text(in), ec); ok = !ec; } catch (const std::exception &) {}
    preqed_result("jsonpointer::json_pointer::parse", ok);
    return ok;
}

static void call_jsonpointer_get(payload in) {
    jsoncons::jsonpointer::json_pointer ptr;
    if (!have || !pointer(in, ptr)) return;
    std::error_code ec;
    TRY("jsonpointer::get", const json &r = jsoncons::jsonpointer::get(current, ptr, ec); if (!ec) text_out = r.to_string(), !ec);
}

static void call_jsonpointer_add(payload in) {
    jsoncons::jsonpointer::json_pointer ptr;
    if (!have || !pointer(in, ptr)) return;
    std::error_code ec;
    TRY("jsonpointer::add", jsoncons::jsonpointer::add(current, ptr, json(text(in)), ec), !ec);
}

static void call_jsonpointer_remove(payload in) {
    jsoncons::jsonpointer::json_pointer ptr;
    if (!have || !pointer(in, ptr)) return;
    std::error_code ec;
    TRY("jsonpointer::remove", jsoncons::jsonpointer::remove(current, ptr, ec), !ec);
}

static void call_jsonpointer_replace(payload in) {
    jsoncons::jsonpointer::json_pointer ptr;
    if (!have || !pointer(in, ptr)) return;
    std::error_code ec;
    TRY("jsonpointer::replace", jsoncons::jsonpointer::replace(current, ptr, json(text(in)), ec), !ec);
}

static void call_jsonpointer_flatten(payload in) {
    json value;
    if (byte(in, 0) & 1) {
        if (!have) return;
        value = current;
    } else if (!argument(rest(in, 1), value)) {
        return;
    }
    TRY("jsonpointer::flatten", take(jsoncons::jsonpointer::flatten(value)), true);
}

static void call_jsonpointer_unflatten(payload in) {
    json value;
    if (byte(in, 0) & 1) {
        if (!have) return;
        value = current;
    } else if (!argument(rest(in, 1), value)) {
        return;
    }
    TRY("jsonpointer::unflatten", take(jsoncons::jsonpointer::unflatten(value)), true);
}

static void call_jsonpatch_apply_patch(payload in) {
    json patch;
    if (!have || !argument(in, patch)) return;
    std::error_code ec;
    TRY("jsonpatch::apply_patch", jsoncons::jsonpatch::apply_patch(current, patch, ec), !ec);
}

static void call_jsonpatch_from_diff(payload in) {
    json target;
    if (!have || !argument(in, target)) return;
    TRY("jsonpatch::from_diff", take(jsoncons::jsonpatch::from_diff(current, target)), true);
}

static void call_mergepatch_apply_merge_patch(payload in) {
    json patch;
    if (!have || !argument(in, patch)) return;
    TRY("mergepatch::apply_merge_patch", jsoncons::mergepatch::apply_merge_patch(current, patch), true);
}

static void call_mergepatch_from_diff(payload in) {
    json target;
    if (!have || !argument(in, target)) return;
    TRY("mergepatch::from_diff", take(jsoncons::mergepatch::from_diff(current, target)), true);
}

/* JSONPath, JMESPath */

static void call_jsonpath_json_query(payload in) {
    if (!have) return;
    TRY_KEEP("jsonpath::json_query", take(jsoncons::jsonpath::json_query(current, text(in))), true,
             jsoncons::jsonpath::jsonpath_error, jsonpath_err);
}

static void call_jsonpath_json_replace(payload in) {
    if (!have) return;
    std::string s = text(in);
    TRY("jsonpath::json_replace", jsoncons::jsonpath::json_replace(current, s, json(s)), true);
}

/* jmespath.hpp:3699 pops the state stack on ')' without a size check; an unmatched ')' underflows it */
static bool parens_balanced(const std::string &expr) {
    int depth = 0;
    for (char c : expr) {
        depth += c == '(';
        if (c == ')' && --depth < 0) return false;
    }
    return true;
}

/* jmespath.hpp:4584: in state multi_select_hash the characters * ] ? : - and digits neither advance nor change
 * state, so compile() loops forever on '{' followed by one of them */
static bool hash_key_loops(const std::string &expr) {
    for (size_t i = 0; i + 1 < expr.size(); i++)
        if (expr[i] == '\x7b' /* { */ && std::strchr("*]?:-0123456789", expr[i + 1]) && expr[i + 1]) return true;
    return false;
}

static void call_jmespath_search(payload in) {
    std::string expr = text(in);
    if (!have || hash_key_loops(expr) || !parens_balanced(expr)) return;
    TRY_KEEP("jmespath::search", take(jsoncons::jmespath::search(current, expr)), true, jsoncons::jmespath::jmespath_error,
             jmespath_err);
}

/* JSON Schema */
/* ltl: schema_before_validate */
static void call_jsonschema_make_json_schema(payload in) {
    json source;
    if (!argument(in, source)) return;
    schema.reset();
    TRY_KEEP("jsonschema::make_json_schema",
        schema.reset(new jsoncons::jsonschema::json_schema<json>(jsoncons::jsonschema::make_json_schema(source, schema_opts))), true,
        jsoncons::jsonschema::schema_error, schema_err);
}
/* ltl: schema_before_validate */
static void call_json_schema_is_valid(payload in) {
    if (!schema) return;
    json instance;
    if (byte(in, 0) & 1) {
        if (!have) return;
        instance = current;
    } else if (!argument(rest(in, 1), instance)) {
        return;
    }
    TRY("json_schema::is_valid", (void)schema->is_valid(instance), true);
}

/* bigint */
/* ltl: bigint_operands_exist */
static void call_bigint_ctor(payload in) {
    if (!in.n || in.n > 4096) return;  /* bigint text up to 4096 digits: larger ones make operator% quadratic-slow */
    std::string s = text(in);
    std::unique_ptr<jsoncons::bigint> created;
    TRY("bigint::bigint", created.reset(new jsoncons::bigint(s)), true);
    if (created) {
        previous_number = std::move(number);
        number = std::move(created);
    }
}
/* ltl: bigint_operands_exist */
static void call_bigint_modulo(payload in) {
    if (!number || !previous_number) return;
    const jsoncons::bigint &denominator = byte(in, 0) & 1 ? *number : *previous_number;
    const jsoncons::bigint &numerator = byte(in, 0) & 1 ? *previous_number : *number;
    if (denominator == 0) return;
    TRY("bigint::operator%", jsoncons::bigint r = numerator % denominator; (void)r, true);
}
/* ltl: bigint_operands_exist */
static void call_bigint_to_string(payload) {
    if (!number) return;
    TRY("bigint::to_string", text_out = number->to_string(), true);
}

/* options setters and getters: they only change the options slot the format's wrappers use */
#define SET(fn, api, stmt) \
    static void fn(payload in) { \
        (void)in; \
        TRY(api, stmt, true); \
    }

template <typename E> static E pick(payload in, int n) { return static_cast<E>(byte(in, 0) % n); }

/* JSON options (json_options.hpp) */

using line_split = jsoncons::line_split_kind;
using json_encode_view = const jsoncons::basic_json_encode_options<char> &;
SET(call_json_options_assign, "json_options::operator=", json_opts = jsoncons::json_options())
SET(call_json_options_allow_comments, "json_options::allow_comments", json_opts.allow_comments(flag(in)))
SET(call_json_options_allow_trailing_comma, "json_options::allow_trailing_comma", json_opts.allow_trailing_comma(flag(in)))
SET(call_json_options_lossless_number, "json_options::lossless_number", json_opts.lossless_number(flag(in)))
SET(call_json_options_lossless_bignum, "json_options::lossless_bignum", json_opts.lossless_bignum(flag(in)))
SET(call_json_options_max_nesting_depth, "json_options::max_nesting_depth", json_opts.max_nesting_depth(1 + byte(in, 0)))
SET(call_json_options_nan_to_num, "json_options::nan_to_num", json_opts.nan_to_num(text(in)))
SET(call_json_options_inf_to_num, "json_options::inf_to_num", json_opts.inf_to_num(text(in)))
SET(call_json_options_neginf_to_num, "json_options::neginf_to_num", json_opts.neginf_to_num(text(in)))
SET(call_json_options_nan_to_str, "json_options::nan_to_str", json_opts.nan_to_str(text(rest(in, 1)), flag(in)))
SET(call_json_options_inf_to_str, "json_options::inf_to_str", json_opts.inf_to_str(text(rest(in, 1)), flag(in)))
SET(call_json_options_neginf_to_str, "json_options::neginf_to_str", json_opts.neginf_to_str(text(rest(in, 1)), flag(in)))
SET(call_json_options_byte_string_format, "json_options::byte_string_format",
    json_opts.byte_string_format(pick<jsoncons::byte_string_chars_format>(in, 4)))
SET(call_json_options_bigint_format, "json_options::bigint_format", json_opts.bigint_format(pick<jsoncons::bignum_format_kind>(in, 4)))
SET(call_json_options_bignum_format, "json_options::bignum_format", json_opts.bignum_format(pick<jsoncons::bignum_format_kind>(in, 4)))
SET(call_json_options_line_splits, "json_options::line_splits", json_opts.line_splits(pick<line_split>(in, 3)))
SET(call_json_options_root_line_splits, "json_options::root_line_splits", json_opts.root_line_splits(pick<line_split>(in, 3)))
SET(call_json_options_object_object_line_splits, "json_options::object_object_line_splits",
    json_opts.object_object_line_splits(pick<line_split>(in, 3)))
SET(call_json_options_object_array_line_splits, "json_options::object_array_line_splits",
    json_opts.object_array_line_splits(pick<line_split>(in, 3)))
SET(call_json_options_array_object_line_splits, "json_options::array_object_line_splits",
    json_opts.array_object_line_splits(pick<line_split>(in, 3)))
SET(call_json_options_array_array_line_splits, "json_options::array_array_line_splits",
    json_opts.array_array_line_splits(pick<line_split>(in, 3)))
SET(call_json_options_indent_size, "json_options::indent_size", json_opts.indent_size(byte(in, 0) % 16))
SET(call_json_options_indent_char, "json_options::indent_char", json_opts.indent_char(ch(in)))
SET(call_json_options_spaces_around_colon, "json_options::spaces_around_colon",
    json_opts.spaces_around_colon(pick<jsoncons::spaces_option>(in, 4)))
SET(call_json_options_spaces_around_comma, "json_options::spaces_around_comma",
    json_opts.spaces_around_comma(pick<jsoncons::spaces_option>(in, 4)))
SET(call_json_options_pad_inside_object_braces, "json_options::pad_inside_object_braces", json_opts.pad_inside_object_braces(flag(in)))
SET(call_json_options_pad_inside_array_brackets, "json_options::pad_inside_array_brackets",
    json_opts.pad_inside_array_brackets(flag(in)))
SET(call_json_options_new_line_chars, "json_options::new_line_chars", json_opts.new_line_chars(text(in)))
SET(call_json_options_line_length_limit, "json_options::line_length_limit", json_opts.line_length_limit(byte(in, 0)))
SET(call_json_options_float_format, "json_options::float_format", json_opts.float_format(pick<jsoncons::float_chars_format>(in, 4)))
/* precision: digits of a double, 0 = shortest round-trip (basic_json_options.md) */
SET(call_json_options_precision, "json_options::precision", json_opts.precision(static_cast<int8_t>(byte(in, 0) % 18)))
SET(call_json_options_escape_all_non_ascii, "json_options::escape_all_non_ascii", json_opts.escape_all_non_ascii(flag(in)))
SET(call_json_options_escape_solidus, "json_options::escape_solidus", json_opts.escape_solidus(flag(in)))
SET(call_json_encode_options_bigint_format, "json_encode_options::bigint_format",
    (void)static_cast<json_encode_view>(json_opts).bigint_format())
SET(call_json_encode_options_line_splits, "json_encode_options::line_splits",
    (void)static_cast<json_encode_view>(json_opts).line_splits())

static void call_json_options_err_handler(payload in) {
    TRY("json_options::err_handler", switch (byte(in, 0) % 3) {
        case 0: json_opts.err_handler(jsoncons::default_json_parsing()); break;
        case 1: json_opts.err_handler(jsoncons::strict_json_parsing()); break;
        default: json_opts.err_handler(jsoncons::allow_trailing_commas()); break;
    }, true);
}

/* decode_json / encode_json / print (decode_json.hpp, encode_json.hpp, basic_json.hpp) */

static void call_decode_json(payload in) {
    TRY("decode_json", take(jsoncons::decode_json<json>(text(in), json_opts)), true);
}

static void call_try_decode_json(payload in) {
    TRY("try_decode_json", auto r = jsoncons::try_decode_json<json>(text(in), json_opts);
        if (r) take(*r); else read_err.reset(new jsoncons::read_error(r.error())), static_cast<bool>(r));
}

static void call_read_error_message(payload) {
    if (!read_err) return;
    TRY("read_error::message", text_out = read_err->message(), true);
}

static void call_read_error_assign(payload in) {
    if (!read_err) return;
    std::error_code ec = jsoncons::json_errc::unexpected_eof;
    TRY("read_error::operator=", *read_err = jsoncons::read_error(ec, text(rest(in, 2)), byte(in, 0), byte(in, 1)), true);
}

static void call_encode_json(payload in) {
    json value;
    if (!select(in, value)) return;
    TRY("encode_json", text_out.clear(); jsoncons::encode_json(value, text_out, json_opts), true);
}

static void call_encode_json_pretty(payload in) {
    json value;
    if (!select(in, value)) return;
    TRY("encode_json_pretty", text_out.clear(); jsoncons::encode_json_pretty(value, text_out, json_opts), true);
}

static void call_try_encode_json(payload in) {
    json value;
    if (!select(in, value)) return;
    TRY("try_encode_json", text_out.clear(); auto r = jsoncons::try_encode_json(value, text_out, json_opts), static_cast<bool>(r));
}

static void call_try_encode_json_pretty(payload in) {
    json value;
    if (!select(in, value)) return;
    TRY("try_encode_json_pretty", text_out.clear(); auto r = jsoncons::try_encode_json_pretty(value, text_out, json_opts),
        static_cast<bool>(r));
}

static void call_print(payload in) {
    json value;
    if (!select(in, value)) return;
    std::ostringstream os;
    TRY("print", os << jsoncons::print(value, json_opts); text_out = os.str(), true);
}

static void call_pretty_print(payload in) {
    json value;
    if (!select(in, value)) return;
    std::ostringstream os;
    TRY("pretty_print", os << jsoncons::pretty_print(value, json_opts); text_out = os.str(), true);
}

static void call_json_operator_insert(payload in) {
    json value;
    if (!select(in, value)) return;
    std::ostringstream os;
    TRY("operator<<(json)", os << value; text_out = os.str(), true);
}

static void call_json_operator_extract(payload in) {
    std::istringstream is(text(in));
    json value;
    TRY("operator>>(json)", is >> value; take(value), true);
}

static void call_combine_allocators(payload in) {
    TRY("combine_allocators", take(json::parse(jsoncons::combine_allocators(), text(in), json_opts)), true);
}

static void call_temp_allocator_only(payload in) {
    TRY("temp_allocator_only", take(json::parse(jsoncons::temp_allocator_only(std::allocator<char>()), text(in), json_opts)), true);
}

/* errors (json_exception.hpp, conv_error.hpp, conversion_result.hpp) */

static void call_ser_error_code(payload) {
    if (!parse_err) return;
    TRY("ser_error::code", (void)parse_err->code(), true);
}
static void call_ser_error_line(payload) {
    if (!parse_err) return;
    TRY("ser_error::line", (void)parse_err->line(), true);
}
static void call_ser_error_column(payload) {
    if (!parse_err) return;
    TRY("ser_error::column", (void)parse_err->column(), true);
}
static void call_ser_error_what(payload) {
    if (!parse_err) return;
    TRY("ser_error::what", text_out = parse_err->what(), true);
}
static void call_ser_error_assign(payload in) {
    if (!parse_err) return;
    std::error_code ec = jsoncons::json_errc::syntax_error;
    TRY("ser_error::operator=", *parse_err = jsoncons::ser_error(ec, byte(in, 0), byte(in, 1)), true);
}

/* as<T> throws conv_error when the value does not convert (basic_json.hpp:1547) */
static void call_json_as(payload in) {
    if (!have) return;
    TRY_KEEP("json::as", if (flag(in)) (void)current.as<uint64_t>(); else text_out = current.as<std::string>(), true,
             jsoncons::conv_error, conv_err);
}
static void call_conv_error_what(payload) {
    if (!conv_err) return;
    TRY("conv_error::what", text_out = conv_err->what(), true);
}

static void call_json_try_as(payload) {
    if (!have) return;
    TRY("json::try_as", auto r = current.try_as<int64_t>();
        if (!r) conversion_err.reset(new jsoncons::conversion_error(r.error())), static_cast<bool>(r));
}
static void call_conversion_error_message(payload) {
    if (!conversion_err) return;
    TRY("conversion_error::message", text_out = conversion_err->message(), true);
}
static void call_conversion_error_assign(payload) {
    if (!conversion_err || !have) return;
    TRY("conversion_error::operator=", auto r = current.try_as<std::string>(); if (!r) *conversion_err = r.error(), true);
}

/* basic_json members (basic_json.hpp) */

static void call_json_as_byte_string(payload) {
    if (!have) return;
    TRY("json::as_byte_string", bytes = current.as_byte_string(), true);
}

static void call_json_try_as_byte_string(payload) {
    if (!have) return;
    TRY("json::try_as_byte_string", auto r = current.try_as_byte_string<jsoncons::byte_string>(jsoncons::make_alloc_set());
        if (r) bytes = *r, static_cast<bool>(r));
}

static void call_json_at_or_null(payload in) {
    if (!have) return;
    TRY("json::at_or_null", text_out = current.at_or_null(text(in)).to_string(), true);
}

static void call_json_capacity(payload) {
    if (!have) return;
    TRY("json::capacity", (void)current.capacity(), true);
}

static void call_json_count(payload in) {
    if (!have) return;
    TRY("json::count", (void)current.count(text(in)), true);
}

static void call_json_emplace(payload in) {
    if (!have || !current.is_array()) return;
    size_t pos = byte(in, 0) % (current.size() + 1);
    TRY("json::emplace", current.emplace(current.array_range().cbegin() + pos, text(rest(in, 1))), true);
}

static void call_json_get_value_or(payload in) {
    if (!have) return;
    TRY("json::get_value_or", text_out = current.get_value_or<std::string>(text(in), std::string("-")), true);
}

static void call_json_is_bignum(payload) {
    if (!have) return;
    TRY("json::is_bignum", (void)current.is_bignum(), true);
}
static void call_json_is_byte_string(payload) {
    if (!have) return;
    TRY("json::is_byte_string", (void)current.is_byte_string(), true);
}
static void call_json_is_byte_string_view(payload) {
    if (!have) return;
    TRY("json::is_byte_string_view", (void)current.is_byte_string_view(), true);
}
static void call_json_is_half(payload) {
    if (!have) return;
    TRY("json::is_half", (void)current.is_half(), true);
}

static void call_json_make_array(payload in) {
    TRY("json::make_array", take(json::make_array(byte(in, 0) % 16, json(text(rest(in, 1))))), true);
}

static void call_json_merge(payload in) {
    json source;
    if (!have || !argument(in, source)) return;
    TRY("json::merge", current.merge(source), true);
}

static void call_json_merge_or_update(payload in) {
    json source;
    if (!have || !argument(in, source)) return;
    TRY("json::merge_or_update", current.merge_or_update(source), true);
}

static void call_json_resize(payload in) {
    if (!have) return;
    TRY("json::resize", current.resize(byte(in, 0)), true);
}

static void call_json_shrink_to_fit(payload) {
    if (!have) return;
    TRY("json::shrink_to_fit", current.shrink_to_fit(), true);
}

static void call_json_byte_string_arg(payload) {
    TRY("json(byte_string_arg_t)", take(json(jsoncons::byte_string_arg_t(), bytes)), true);
}

static void call_json_half_arg(payload in) {
    TRY("json(half_arg_t)", take(json(jsoncons::half_arg_t(), static_cast<uint16_t>(byte(in, 0) | byte(in, 1) << 8))), true);
}

/* range (json/range.hpp): every wrapper walks the whole range and checks it saw size() elements */
static void call_range_rbegin(payload) {
    if (!have || !current.is_array()) return;
    TRY("range::rbegin", auto r = current.array_range(); size_t n = 0;
        for (auto it = r.rbegin(); it != r.rend(); ++it) n++, n == current.size());
}
static void call_range_cbegin(payload) {
    if (!have || !current.is_object()) return;
    TRY("range::cbegin", auto r = current.object_range(); size_t n = 0;
        for (auto it = r.cbegin(); it != r.cend(); ++it) n++, n == current.size());
}
static void call_range_crbegin(payload) {
    if (!have || !current.is_object()) return;
    TRY("range::crbegin", auto r = current.object_range(); size_t n = 0;
        for (auto it = r.crbegin(); it != r.crend(); ++it) n++, n == current.size());
}

/* key_value (json/key_value.hpp) */
static void call_key_value_shrink_to_fit(payload) {
    if (!have || !current.is_object()) return;
    TRY("key_value::shrink_to_fit", for (auto &member : current.object_range()) member.shrink_to_fit(), true);
}
/* swap with a member of the same key: object members stay sorted by key */
static void call_key_value_swap(payload in) {
    if (!have || !current.is_object() || current.empty()) return;
    TRY("key_value::swap", auto &member = *current.object_range().begin();
        json::key_value_type other(std::string(member.key()), json(text(in))); member.swap(other), true);
}

/* byte_string and byte_string_view (utility/byte_string.hpp) */

static void call_byte_string_assign(payload in) { TRY("byte_string::assign", bytes.assign(in.p, in.n), true); }
static void call_byte_string_append(payload in) { TRY("byte_string::append", bytes.append(in.p, in.n), true); }
static void call_byte_string_push_back(payload in) { TRY("byte_string::push_back", bytes.push_back(byte(in, 0)), true); }
static void call_byte_string_clear(payload) { TRY("byte_string::clear", bytes.clear(), true); }
static void call_byte_string_reserve(payload in) { TRY("byte_string::reserve", bytes.reserve(byte(in, 0) * 16), true); }
static void call_byte_string_get_allocator(payload) { TRY("byte_string::get_allocator", (void)bytes.get_allocator(), true); }
static void call_byte_string_operator_assign(payload in) {
    TRY("byte_string::operator=", bytes = jsoncons::byte_string(jsoncons::byte_string_view(in.p, in.n)), bytes.size() == in.n);
}
static void call_byte_string_index(payload in) {
    if (bytes.size() == 0) return;
    TRY("byte_string::operator[]", (void)bytes[byte(in, 0) % bytes.size()], true);
}
static void call_byte_string_begin(payload) {
    TRY("byte_string::begin", size_t n = 0; for (auto it = bytes.begin(); it != bytes.end(); ++it) n++, n == bytes.size());
}

static void call_byte_string_view_cbegin(payload) {
    jsoncons::byte_string_view view(bytes);
    TRY("byte_string_view::cbegin", size_t n = 0; for (auto it = view.cbegin(); it != view.cend(); ++it) n++, n == view.size());
}
static void call_byte_string_view_index(payload in) {
    jsoncons::byte_string_view view(bytes);
    if (view.size() == 0) return;
    TRY("byte_string_view::operator[]", (void)view[byte(in, 0) % view.size()], true);
}
static void call_byte_string_view_assign(payload in) {
    jsoncons::byte_string_view view;
    TRY("byte_string_view::operator=", view = jsoncons::byte_string_view(in.p, in.n), view.size() == in.n);
}
/* byte_string.hpp:446: pos + n overflows for n close to SIZE_MAX (std::string_view::npos style), so n is not
 * clamped and the view runs past the buffer (repro.cpp case 5); n is kept <= size() */
static void call_byte_string_view_substr(payload in) {
    jsoncons::byte_string_view view(bytes);
    size_t pos = byte(in, 0) % (view.size() + 2), n = byte(in, 1);
    if (pos > view.size()) {
        TRY("byte_string_view::substr", (void)view.substr(pos, n), false);  /* documented: throws out_of_range */
        return;
    }
    TRY("byte_string_view::substr", auto sub = view.substr(pos, n); size_t sum = 0; for (uint8_t b : sub) sum += b; (void)sum,
        sub.size() <= view.size() - pos);
}

/* sinks (sink.hpp) */

/* stream_sink(os, buflen): buflen 0 makes push_back write through the empty buffer's data() (sink.hpp:107-115,
 * repro.cpp case 6), so buflen >= 1 */
static void call_stream_sink_ctor(payload in) {
    std::ostringstream os;
    TRY("stream_sink::stream_sink", { jsoncons::stream_sink<char> sink(os, 1 + byte(in, 0));
        sink.append(reinterpret_cast<const char *>(in.p), in.n); } text_out = os.str(), text_out.size() == in.n);
}
static void call_stream_sink_append(payload in) {
    std::ostringstream os;
    TRY("stream_sink::append", { jsoncons::stream_sink<char> sink(os); sink.append(reinterpret_cast<const char *>(in.p), in.n);
        sink.append(byte(in, 0) % 8, 'x'); } text_out = os.str(), text_out.size() == in.n + byte(in, 0) % 8);
}
static void call_stream_sink_push_back(payload in) {
    std::ostringstream os;
    TRY("stream_sink::push_back", { jsoncons::stream_sink<char> sink(os, 1 + byte(in, 0) % 4);
        for (size_t i = 0; i < in.n; i++) sink.push_back(static_cast<char>(in.p[i])); } text_out = os.str(), text_out.size() == in.n);
}
static void call_stream_sink_flush(payload in) {
    std::ostringstream os;
    TRY("stream_sink::flush", jsoncons::stream_sink<char> sink(os); sink.append(reinterpret_cast<const char *>(in.p), in.n);
        sink.flush(), os.str().size() == in.n);
}
/* move assignment; the moved-from sink is destroyed first (sink.hpp:62 = default keeps its raw buffer pointers,
 * repro.cpp case 7 shows the use-after-free when it outlives the target) */
static void call_stream_sink_assign(payload in) {
    std::ostringstream os, other;
    TRY("stream_sink::operator=", { jsoncons::stream_sink<char> sink(os); { jsoncons::stream_sink<char> source(other);
        sink = std::move(source); } sink.append(reinterpret_cast<const char *>(in.p), in.n); } (void)0, true);
}

static void call_binary_stream_sink_append(payload in) {
    std::ostringstream os;
    TRY("binary_stream_sink::append", { jsoncons::binary_stream_sink sink(os); sink.append(in.p, in.n); }
        text_out = os.str(), text_out.size() == in.n);
}
static void call_binary_stream_sink_assign(payload in) {
    std::ostringstream os, other;
    TRY("binary_stream_sink::operator=", { jsoncons::binary_stream_sink sink(os); { jsoncons::binary_stream_sink source(other);
        sink = std::move(source); } sink.append(in.p, in.n); } (void)0, true);
}
static void call_bytes_sink_assign(payload in) {
    std::vector<uint8_t> a, b;
    TRY("bytes_sink::operator=", jsoncons::bytes_sink<std::vector<uint8_t>> sink(a);
        sink = jsoncons::bytes_sink<std::vector<uint8_t>>(b); sink.append(in.p, in.n), b.size() == in.n);
}
static void call_string_sink_assign(payload in) {
    std::string a, b;
    TRY("string_sink::operator=", jsoncons::string_sink<std::string> sink(a);
        sink = jsoncons::string_sink<std::string>(b); sink.append(reinterpret_cast<const char *>(in.p), in.n), true);
}

/* uri (utility/uri.hpp) */

static bool uri_arg(payload in, jsoncons::uri &out) {
    std::error_code ec;
    if (!preqed_call("uri::parse")) return false;
    bool ok = false;
    try { out = jsoncons::uri::parse(text(in), ec); ok = !ec; } catch (const std::exception &) {}
    preqed_result("uri::parse", ok);
    return ok;
}

#define URI_GET(fn, api, member) \
    static void fn(payload in) { \
        jsoncons::uri u; \
        if (!uri_arg(in, u)) return; \
        TRY(api, (void)u.member(), true); \
    }
URI_GET(call_uri_authority, "uri::authority", authority)
URI_GET(call_uri_userinfo, "uri::userinfo", userinfo)
URI_GET(call_uri_path, "uri::path", path)
URI_GET(call_uri_query, "uri::query", query)
URI_GET(call_uri_has_scheme, "uri::has_scheme", has_scheme)

/* uri(other, uri_fragment_part, fragment): other with its fragment replaced (uri.hpp:141) */
static void call_uri_with_fragment(payload in) {
    payload base, fragment;
    split(in, base, fragment);
    jsoncons::uri u;
    if (!uri_arg(base, u)) return;
    TRY("uri::uri(uri_fragment_part_t)", jsoncons::uri v(u, jsoncons::uri_fragment_part_t(), text(fragment)); text_out = v.string(), true);
}

/* JSON parser, reader, decoder, encoders, filters (json_parser.hpp, json_reader.hpp, json_decoder.hpp, json_encoder.hpp,
 * json_filter.hpp) */

#define PARSER_GET(fn, api, member) \
    static void fn(payload in) { \
        std::string s = text(in); \
        jsoncons::json_parser parser(json_opts); \
        jsoncons::json_decoder<json> decoder; \
        std::error_code ec; \
        TRY(api, parser.update(s.data(), s.size()); parser.parse_some(decoder, ec); (void)parser.member(), true); \
    }
PARSER_GET(call_json_parser_position, "json_parser::position", position)
PARSER_GET(call_json_parser_begin_position, "json_parser::begin_position", begin_position)
PARSER_GET(call_json_parser_end_position, "json_parser::end_position", end_position)

static void call_json_stream_reader_line(payload in) {
    std::istringstream is(text(in));
    jsoncons::json_decoder<json> decoder;
    std::error_code ec;
    TRY("json_stream_reader::line", jsoncons::json_stream_reader reader(is, decoder, json_opts); reader.read(ec); (void)reader.line(), true);
}

static void call_json_stream_reader_column(payload in) {
    std::istringstream is(text(in));
    jsoncons::json_decoder<json> decoder;
    std::error_code ec;
    TRY("json_stream_reader::column", jsoncons::json_stream_reader reader(is, decoder, json_opts); reader.read(ec); (void)reader.column(),
        true);
}

static void call_json_decoder_reset(payload in) {
    std::istringstream is(text(in));
    jsoncons::json_decoder<json> decoder;
    std::error_code ec;
    TRY("json_decoder::reset", jsoncons::json_stream_reader reader(is, decoder, json_opts); reader.read(ec); decoder.reset(),
        !decoder.is_valid());
}

/* reset() clears the encoder state, so the second dump starts a new document */
static void call_json_encoder_reset(payload in) {
    json value;
    if (!select(in, value)) return;
    TRY("json_string_encoder::reset", text_out.clear(); jsoncons::json_string_encoder encoder(text_out, json_opts); value.dump(encoder);
        encoder.reset(); value.dump(encoder), true);
}

static void call_compact_json_encoder_reset(payload in) {
    json value;
    if (!select(in, value)) return;
    TRY("compact_json_string_encoder::reset", text_out.clear(); jsoncons::compact_json_string_encoder encoder(text_out, json_opts);
        value.dump(encoder); encoder.reset(); value.dump(encoder), true);
}

static void call_compact_json_encoder_ctor(payload in) {
    json value;
    if (!select(in, value)) return;
    TRY("compact_json_string_encoder::compact_json_string_encoder", text_out.clear();
        jsoncons::compact_json_string_encoder encoder(text_out, json_opts); value.dump(encoder), true);
}

static void call_json_filter(payload in) {
    json value;
    if (!select(in, value)) return;
    TRY("json_filter::json_filter", text_out.clear(); jsoncons::json_string_encoder encoder(text_out, json_opts);
        jsoncons::json_filter filter(encoder); value.dump(filter), true);
}

static void call_json_filter_destination(payload in) {
    json value;
    if (!select(in, value)) return;
    TRY("json_filter::destination", text_out.clear(); jsoncons::json_string_encoder encoder(text_out, json_opts);
        jsoncons::json_filter filter(encoder); value.dump(filter.destination()), true);
}

static void call_rename_object_key_filter(payload in) {
    if (!have) return;
    payload name, new_name;
    split(in, name, new_name);
    TRY("rename_object_key_filter::rename_object_key_filter", text_out.clear(); jsoncons::json_string_encoder encoder(text_out, json_opts);
        jsoncons::rename_object_key_filter filter(text(name), text(new_name), encoder); current.dump(filter), true);
}

/* JSON stream cursor (json_cursor.hpp), through its own type, its staj_cursor base (staj_cursor.hpp) and its
 * ser_context (ser_context.hpp). current/next/read_to need an event: !done(). */

static void cursor_failed() {
    cursor.reset();
}
/* ltl: cursor_lifecycle */
static void call_json_stream_cursor_check_done(payload) {
    if (!cursor) return;
    std::error_code ec;
    TRY("json_stream_cursor::check_done", cursor->check_done(ec), !ec);
    if (ec) cursor_failed();
}
/* ltl: cursor_lifecycle */
static void call_json_stream_cursor_line(payload) {
    if (!cursor) return;
    TRY("json_stream_cursor::line", (void)cursor->line(), true);
}
/* ltl: cursor_lifecycle */
static void call_json_stream_cursor_column(payload) {
    if (!cursor) return;
    TRY("json_stream_cursor::column", (void)cursor->column(), true);
}
/* ltl: cursor_lifecycle */
static void call_json_stream_cursor_context(payload) {
    if (!cursor) return;
    TRY("json_stream_cursor::context", (void)&cursor->context(), true);
}
/* ltl: cursor_lifecycle */
static void call_json_stream_cursor_eof(payload) {
    if (!cursor) return;
    TRY("json_stream_cursor::eof", (void)cursor->eof(), true);
}
/* ltl: cursor_lifecycle */
static void call_json_stream_cursor_read_to(payload) {
    if (!cursor || cursor->done()) return;
    jsoncons::json_decoder<json> decoder;
    std::error_code ec;
    TRY("json_stream_cursor::read_to", cursor->read_to(decoder, ec); if (!ec && decoder.is_valid()) take(decoder.get_result()), !ec);
    if (ec) cursor_failed();
}
/* ltl: cursor_lifecycle */
static void call_json_stream_cursor_reset(payload in) {
    if (!cursor) return;
    std::unique_ptr<std::istringstream> input(new std::istringstream(text(in)));
    std::error_code ec;
    TRY("json_stream_cursor::reset", cursor->reset(*input, ec), !ec);
    cursor_input = std::move(input);  /* the cursor reads from the new stream now */
    if (ec) cursor_failed();
}

#define CONTEXT_GET(fn, api, member) \
    static void fn(payload) { \
        if (!cursor) return; \
        const jsoncons::ser_context &context = cursor->context(); \
        TRY(api, (void)context.member(), true); \
    }
/* ltl: cursor_lifecycle */
CONTEXT_GET(call_ser_context_line, "ser_context::line", line)
/* ltl: cursor_lifecycle */
CONTEXT_GET(call_ser_context_column, "ser_context::column", column)
/* ltl: cursor_lifecycle */
CONTEXT_GET(call_ser_context_position, "ser_context::position", position)
/* ltl: cursor_lifecycle */
CONTEXT_GET(call_ser_context_begin_position, "ser_context::begin_position", begin_position)
/* ltl: cursor_lifecycle */
CONTEXT_GET(call_ser_context_end_position, "ser_context::end_position", end_position)

#define STAJ_GET(fn, api, expr) \
    static void fn(payload) { \
        if (!cursor) return; \
        jsoncons::staj_cursor &base = *cursor; \
        TRY(api, (void)(expr), true); \
    }
/* ltl: cursor_lifecycle */
STAJ_GET(call_staj_cursor_done, "staj_cursor::done", base.done())
/* ltl: cursor_lifecycle */
STAJ_GET(call_staj_cursor_line, "staj_cursor::line", base.line())
/* ltl: cursor_lifecycle */
STAJ_GET(call_staj_cursor_column, "staj_cursor::column", base.column())
/* ltl: cursor_lifecycle */
STAJ_GET(call_staj_cursor_context, "staj_cursor::context", &base.context())
/* ltl: cursor_lifecycle */
STAJ_GET(call_staj_cursor_is_multi_dim, "staj_cursor::is_multi_dim", base.is_multi_dim())
/* ltl: cursor_lifecycle */
STAJ_GET(call_staj_cursor_extents, "staj_cursor::extents", base.extents().size())
/* ltl: cursor_lifecycle */
STAJ_GET(call_staj_cursor_order, "staj_cursor::order", base.order())
/* ltl: cursor_lifecycle */
STAJ_GET(call_staj_cursor_is_typed_array, "staj_cursor::is_typed_array", base.is_typed_array())
/* ltl: cursor_lifecycle */
STAJ_GET(call_staj_cursor_array_tag, "staj_cursor::array_tag", base.array_tag())
/* ltl: cursor_lifecycle */
STAJ_GET(call_staj_cursor_array_buffer, "staj_cursor::array_buffer", base.array_buffer().size())
/* ltl: cursor_lifecycle */
STAJ_GET(call_staj_cursor_to_end_array, "staj_cursor::to_end_array", (base.to_end_array(), 0))
/* ltl: cursor_lifecycle */
static void call_staj_cursor_current(payload) {
    if (!cursor || cursor->done()) return;
    jsoncons::staj_cursor &base = *cursor;
    TRY("staj_cursor::current", (void)base.current().event_type(), true);
}
/* ltl: cursor_lifecycle */
static void call_staj_cursor_next(payload) {
    if (!cursor || cursor->done()) return;
    jsoncons::staj_cursor &base = *cursor;
    std::error_code ec;
    TRY("staj_cursor::next", base.next(ec), !ec);
    if (ec) cursor_failed();
}
/* ltl: cursor_lifecycle */
static void call_staj_cursor_read_to(payload) {
    if (!cursor || cursor->done()) return;
    jsoncons::staj_cursor &base = *cursor;
    jsoncons::json_decoder<json> decoder;
    std::error_code ec;
    TRY("staj_cursor::read_to", base.read_to(decoder, ec); if (!ec && decoder.is_valid()) take(decoder.get_result()), !ec);
    if (ec) cursor_failed();
}
/* ltl: cursor_lifecycle */
static void call_staj_cursor_array_expected(payload) {
    if (!cursor || cursor->done()) return;
    jsoncons::staj_cursor &base = *cursor;
    std::error_code ec;
    TRY("staj_cursor::array_expected", base.array_expected(ec), !ec);
}

/* the event the cursor is positioned on (staj_event.hpp) */
/* ltl: cursor_lifecycle */
static void call_staj_event_size(payload) {
    if (!cursor || cursor->done()) return;
    TRY("staj_event::size", (void)cursor->current().size(), true);
}
/* ltl: cursor_lifecycle */
static void call_staj_event_ext_tag(payload) {
    if (!cursor || cursor->done()) return;
    TRY("staj_event::ext_tag", (void)cursor->current().ext_tag(), true);
}
/* ltl: cursor_lifecycle */
static void call_staj_event_get(payload) {
    if (!cursor || cursor->done()) return;
    std::error_code ec;
    TRY("staj_event::get", text_out = cursor->current().get<std::string>(ec), !ec);
}

/* staj_array_iterator / staj_object_iterator (staj_iterator.hpp) over the cursor: an iterator positioned on
 * begin_array / begin_object reads one element per step; dereferencing needs it != end. The cursor errored when
 * the iterator reports an error. */
using array_iterator = jsoncons::staj_array_iterator<json>;
using object_iterator = jsoncons::staj_object_iterator<std::string, json>;
/* ltl: cursor_lifecycle */
static void call_staj_array_iterator_ctor(payload) {
    if (!cursor || cursor->done()) return;
    std::error_code ec;
    TRY("staj_array_iterator::staj_array_iterator", array_iterator it(*cursor, ec), !ec);
    if (ec) cursor_failed();
}
/* ltl: cursor_lifecycle */
static void call_staj_array_iterator_deref(payload) {
    if (!cursor || cursor->done()) return;
    std::error_code ec;
    TRY("staj_array_iterator::operator*", array_iterator it(*cursor, ec);
        if (!ec && it != jsoncons::end(it)) text_out = (*it).to_string(), !ec);
    if (ec) cursor_failed();
}
/* ltl: cursor_lifecycle */
static void call_staj_array_iterator_arrow(payload) {
    if (!cursor || cursor->done()) return;
    std::error_code ec;
    TRY("staj_array_iterator::operator->", array_iterator it(*cursor, ec);
        if (!ec && it != jsoncons::end(it)) (void)it->size(), !ec);
    if (ec) cursor_failed();
}
/* ltl: cursor_lifecycle */
static void call_staj_array_iterator_increment(payload) {
    if (!cursor || cursor->done()) return;
    std::error_code ec;
    TRY("staj_array_iterator::increment", array_iterator it(*cursor, ec);
        for (auto e = jsoncons::end(it); !ec && it != e;) it.increment(ec), !ec);
    if (ec) cursor_failed();
}
/* ltl: cursor_lifecycle */
static void call_staj_array_iterator_preincrement(payload) {
    if (!cursor || cursor->done()) return;
    if (!preqed_call("staj_array_iterator::operator++")) return;
    bool ok = false;
    try {
        auto it = jsoncons::begin(array_iterator(*cursor));
        if (it != jsoncons::end(it)) ++it;
        ok = true;
    } catch (const std::exception &) {}
    preqed_result("staj_array_iterator::operator++", ok);
    if (!ok) cursor_failed();
}
/* ltl: cursor_lifecycle */
static void call_staj_array_iterator_assign(payload) {
    if (!cursor || cursor->done()) return;
    std::error_code ec;
    TRY("staj_array_iterator::operator=", array_iterator it(*cursor, ec); array_iterator copy; copy = it, !ec);
    if (ec) cursor_failed();
}
/* ltl: cursor_lifecycle */
static void call_staj_object_iterator_ctor(payload) {
    if (!cursor || cursor->done()) return;
    std::error_code ec;
    TRY("staj_object_iterator::staj_object_iterator", object_iterator it(*cursor, ec), !ec);
    if (ec) cursor_failed();
}
/* ltl: cursor_lifecycle */
static void call_staj_object_iterator_deref(payload) {
    if (!cursor || cursor->done()) return;
    std::error_code ec;
    TRY("staj_object_iterator::operator*", object_iterator it(*cursor, ec);
        if (!ec && it != jsoncons::end(it)) text_out = (*it).first, !ec);
    if (ec) cursor_failed();
}
/* ltl: cursor_lifecycle */
static void call_staj_object_iterator_arrow(payload) {
    if (!cursor || cursor->done()) return;
    std::error_code ec;
    TRY("staj_object_iterator::operator->", object_iterator it(*cursor, ec);
        if (!ec && it != jsoncons::end(it)) text_out = it->second.to_string(), !ec);
    if (ec) cursor_failed();
}
/* ltl: cursor_lifecycle */
static void call_staj_object_iterator_increment(payload) {
    if (!cursor || cursor->done()) return;
    std::error_code ec;
    TRY("staj_object_iterator::increment", object_iterator it(*cursor, ec);
        for (auto e = jsoncons::end(it); !ec && it != e;) it.increment(ec), !ec);
    if (ec) cursor_failed();
}
/* ltl: cursor_lifecycle */
static void call_staj_object_iterator_preincrement(payload) {
    if (!cursor || cursor->done()) return;
    if (!preqed_call("staj_object_iterator::operator++")) return;
    bool ok = false;
    try {
        auto it = jsoncons::begin(object_iterator(*cursor));
        if (it != jsoncons::end(it)) ++it;
        ok = true;
    } catch (const std::exception &) {}
    preqed_result("staj_object_iterator::operator++", ok);
    if (!ok) cursor_failed();
}
/* ltl: cursor_lifecycle */
static void call_staj_object_iterator_assign(payload) {
    if (!cursor || cursor->done()) return;
    std::error_code ec;
    TRY("staj_object_iterator::operator=", object_iterator it(*cursor, ec); object_iterator copy; copy = it, !ec);
    if (ec) cursor_failed();
}

/* bigint (utility/bigint.hpp): unary operations on the last bigint, binary ones on the last two. Results of
 * growing operations are discarded so operand sizes stay bounded by bigint::bigint's 4096 digits. */

#define BIG_UNARY(fn, api, stmt) \
    static void fn(payload in) { \
        (void)in; \
        if (!number) return; \
        jsoncons::bigint &x = *number; \
        TRY(api, stmt, true); \
    }
/* ltl: bigint_operands_exist */
BIG_UNARY(call_bigint_operator_bool, "bigint::operator(bool)", (void)static_cast<bool>(x))
/* ltl: bigint_operands_exist */
BIG_UNARY(call_bigint_operator_double, "bigint::operator(double)", (void)static_cast<double>(x))
/* ltl: bigint_operands_exist */
BIG_UNARY(call_bigint_operator_long_double, "bigint::operator(long_double)", (void)static_cast<long double>(x))
/* ltl: bigint_operands_exist */
BIG_UNARY(call_bigint_operator_integer, "bigint::operator(int64_t)", (void)static_cast<int64_t>(x))
/* ltl: bigint_operands_exist */
BIG_UNARY(call_bigint_operator_not, "bigint::operator!", (void)!x)
/* ltl: bigint_operands_exist */
BIG_UNARY(call_bigint_increment, "bigint::operator++", ++x)
/* ltl: bigint_operands_exist */
BIG_UNARY(call_bigint_decrement, "bigint::operator--", --x)
/* ltl: bigint_operands_exist */
BIG_UNARY(call_bigint_to_string_hex, "bigint::to_string_hex", text_out = x.to_string_hex())
/* ltl: bigint_operands_exist */
BIG_UNARY(call_bigint_babs, "babs", jsoncons::bigint r = jsoncons::babs(x); (void)r)
/* ltl: bigint_operands_exist */
BIG_UNARY(call_bigint_bpow, "bpow", jsoncons::bigint r = jsoncons::bpow(x, byte(in, 0) % 8); (void)r)
/* ltl: bigint_operands_exist */
BIG_UNARY(call_bigint_shift_left, "bigint::operator<<", jsoncons::bigint r = x << static_cast<unsigned>(byte(in, 0) * 8); (void)r)
/* ltl: bigint_operands_exist */
BIG_UNARY(call_bigint_shift_right, "bigint::operator>>", jsoncons::bigint r = x >> static_cast<unsigned>(byte(in, 0) * 8); (void)r)

/* square root of a negative number is outside bsqrt's domain (bigint.md: sqrt) */
/* ltl: bigint_operands_exist */
static void call_bigint_bsqrt(payload) {
    if (!number || *number < 0) return;
    TRY("bsqrt", jsoncons::bigint r = jsoncons::bsqrt(*number); (void)r, true);
}

#define BIG_BINARY(fn, api, stmt) \
    static void fn(payload in) { \
        if (!number || !previous_number) return; \
        jsoncons::bigint &x = byte(in, 0) & 1 ? *number : *previous_number; \
        const jsoncons::bigint &y = byte(in, 0) & 1 ? *previous_number : *number; \
        TRY(api, stmt, true); \
    }
/* ltl: bigint_operands_exist */
BIG_BINARY(call_bigint_and_assign, "bigint::operator&=", x &= y)
/* ltl: bigint_operands_exist */
BIG_BINARY(call_bigint_or_assign, "bigint::operator|=", x |= y)
/* ltl: bigint_operands_exist */
BIG_BINARY(call_bigint_xor_assign, "bigint::operator^=", x ^= y)
/* ltl: bigint_operands_exist */
BIG_BINARY(call_bigint_plus, "bigint::operator+", jsoncons::bigint r = x + y; (void)r)
/* ltl: bigint_operands_exist */
BIG_BINARY(call_bigint_times, "bigint::operator*", jsoncons::bigint r = x * y; (void)r)
/* ltl: bigint_operands_exist */
BIG_BINARY(call_bigint_xor, "bigint::operator^", jsoncons::bigint r = x ^ y; (void)r)
/* ltl: bigint_operands_exist */
static void call_bigint_divide(payload in) {
    if (!number || !previous_number) return;
    const jsoncons::bigint &denominator = byte(in, 0) & 1 ? *number : *previous_number;
    const jsoncons::bigint &numerator = byte(in, 0) & 1 ? *previous_number : *number;
    if (denominator == 0) return;
    TRY("bigint::operator/", jsoncons::bigint r = numerator / denominator; (void)r, true);
}

/* cursors of the other formats (cbor/bson/msgpack/ubjson/csv *_cursor.hpp): same contract as the JSON cursor;
 * each reads from its own input slot, which is only replaced while the cursor is gone or being reset */

static bool csv_input(payload in, std::string &out) {
    out = text(in);
    return true;
}

static bool keep_event(const jsoncons::staj_event &event, const jsoncons::ser_context &) {
    return event.event_type() != jsoncons::staj_events::key;
}

#define CURSOR_WRAPPERS(slot, name, ctor_name, type, input, opts, load) \
    static void call_##slot##_ctor(payload in) { \
        slot.reset(); \
        if (!load(in, input)) return; \
        std::error_code ec; \
        TRY(name "::" ctor_name, slot.reset(new type(input, opts, ec)), !ec); \
        if (ec) slot.reset(); \
    } \
    static void call_##slot##_current(payload) { \
        if (!slot || slot->done()) return; \
        TRY(name "::current", (void)slot->current().event_type(), true); \
    } \
    static void call_##slot##_next(payload) { \
        if (!slot || slot->done()) return; \
        std::error_code ec; \
        TRY(name "::next", slot->next(ec), !ec); \
        if (ec) slot.reset(); \
    } \
    static void call_##slot##_done(payload) { \
        if (!slot) return; \
        TRY(name "::done", (void)slot->done(), true); \
    } \
    static void call_##slot##_eof(payload) { \
        if (!slot) return; \
        TRY(name "::eof", (void)slot->eof(), true); \
    } \
    static void call_##slot##_line(payload) { \
        if (!slot) return; \
        TRY(name "::line", (void)slot->line(), true); \
    } \
    static void call_##slot##_column(payload) { \
        if (!slot) return; \
        TRY(name "::column", (void)slot->column(), true); \
    } \
    static void call_##slot##_context(payload) { \
        if (!slot) return; \
        TRY(name "::context", (void)slot->context().line(), true); \
    } \
    static void call_##slot##_read_to(payload) { \
        if (!slot || slot->done()) return; \
        jsoncons::json_decoder<json> decoder; \
        std::error_code ec; \
        TRY(name "::read_to", slot->read_to(decoder, ec); if (!ec && decoder.is_valid()) take(decoder.get_result()), !ec); \
        if (ec) slot.reset(); \
    } \
    static void call_##slot##_reset(payload in) { \
        if (!slot || !load(in, input)) return; \
        std::error_code ec; \
        TRY(name "::reset", slot->reset(input, ec), !ec); \
        if (ec) slot.reset(); \
    } \
    static void call_##slot##_filter(payload) { \
        if (!slot) return; \
        bool ok_ = false; \
        if (!preqed_call(name "::operator|")) return; \
        try { \
            auto view = *slot | keep_event; \
            (void)view.done(); \
            ok_ = true; \
        } catch (const std::exception &) {} \
        preqed_result(name "::operator|", ok_); \
        if (!ok_) slot.reset(); \
    }

/* CSV (csv_options.hpp, csv_cursor.hpp, csv_reader.hpp, csv_encoder.hpp) */

using csv_decode_view = const jsoncons::csv::basic_csv_decode_options<char> &;
SET(call_csv_options_assign, "csv::csv_options::operator=", csv_opts = jsoncons::csv::csv_options())
SET(call_csv_options_float_format, "csv::csv_options::float_format", csv_opts.float_format(pick<jsoncons::float_chars_format>(in, 4)))
SET(call_csv_options_precision, "csv::csv_options::precision", csv_opts.precision(static_cast<int8_t>(byte(in, 0) % 18)))
SET(call_csv_options_header_lines, "csv::csv_options::header_lines", csv_opts.header_lines(byte(in, 0) % 4))
SET(call_csv_options_ignore_empty_values, "csv::csv_options::ignore_empty_values", csv_opts.ignore_empty_values(flag(in)))
SET(call_csv_options_ignore_empty_lines, "csv::csv_options::ignore_empty_lines", csv_opts.ignore_empty_lines(flag(in)))
SET(call_csv_options_trim_leading, "csv::csv_options::trim_leading", csv_opts.trim_leading(flag(in)))
SET(call_csv_options_trim_trailing, "csv::csv_options::trim_trailing", csv_opts.trim_trailing(flag(in)))
SET(call_csv_options_trim_leading_inside_quotes, "csv::csv_options::trim_leading_inside_quotes",
    csv_opts.trim_leading_inside_quotes(flag(in)))
SET(call_csv_options_trim_trailing_inside_quotes, "csv::csv_options::trim_trailing_inside_quotes",
    csv_opts.trim_trailing_inside_quotes(flag(in)))
SET(call_csv_options_trim, "csv::csv_options::trim", csv_opts.trim(flag(in)))
SET(call_csv_options_trim_inside_quotes, "csv::csv_options::trim_inside_quotes", csv_opts.trim_inside_quotes(flag(in)))
SET(call_csv_options_unquoted_empty_value_is_null, "csv::csv_options::unquoted_empty_value_is_null",
    csv_opts.unquoted_empty_value_is_null(flag(in)))
SET(call_csv_options_column_names, "csv::csv_options::column_names", csv_opts.column_names(text(in)))
SET(call_csv_options_column_types, "csv::csv_options::column_types", csv_opts.column_types(text(in)))
SET(call_csv_options_column_defaults, "csv::csv_options::column_defaults", csv_opts.column_defaults(text(in)))
SET(call_csv_options_flat, "csv::csv_options::flat", csv_opts.flat(flag(in)))
SET(call_csv_options_max_nesting_depth, "csv::csv_options::max_nesting_depth", csv_opts.max_nesting_depth(1 + byte(in, 0)))
SET(call_csv_options_subfield_delimiter, "csv::csv_options::subfield_delimiter", csv_opts.subfield_delimiter(ch(in)))
SET(call_csv_options_line_delimiter, "csv::csv_options::line_delimiter", csv_opts.line_delimiter(text(in)))
SET(call_csv_options_quote_char, "csv::csv_options::quote_char", csv_opts.quote_char(ch(in)))
SET(call_csv_options_quote_escape_char, "csv::csv_options::quote_escape_char", csv_opts.quote_escape_char(ch(in)))
SET(call_csv_options_comment_starter, "csv::csv_options::comment_starter", csv_opts.comment_starter(ch(in)))
SET(call_csv_options_infer_types, "csv::csv_options::infer_types", csv_opts.infer_types(flag(in)))
SET(call_csv_options_lossless_number, "csv::csv_options::lossless_number", csv_opts.lossless_number(flag(in)))
SET(call_csv_options_quote_style, "csv::csv_options::quote_style", csv_opts.quote_style(pick<jsoncons::csv::quote_style_kind>(in, 4)))
SET(call_csv_options_mapping_kind, "csv::csv_options::mapping_kind",
    csv_opts.mapping_kind(static_cast<jsoncons::csv::csv_mapping_kind>(1 + byte(in, 0) % 3)))
SET(call_csv_options_max_lines, "csv::csv_options::max_lines", csv_opts.max_lines(byte(in, 0)))
SET(call_csv_options_nan_to_num, "csv::csv_options::nan_to_num", csv_opts.nan_to_num(text(in)))
SET(call_csv_options_inf_to_num, "csv::csv_options::inf_to_num", csv_opts.inf_to_num(text(in)))
SET(call_csv_options_neginf_to_num, "csv::csv_options::neginf_to_num", csv_opts.neginf_to_num(text(in)))
SET(call_csv_options_nan_to_str, "csv::csv_options::nan_to_str", csv_opts.nan_to_str(text(rest(in, 1)), flag(in)))
SET(call_csv_options_inf_to_str, "csv::csv_options::inf_to_str", csv_opts.inf_to_str(text(rest(in, 1)), flag(in)))
SET(call_csv_options_neginf_to_str, "csv::csv_options::neginf_to_str", csv_opts.neginf_to_str(text(rest(in, 1)), flag(in)))
SET(call_csv_decode_options_trim, "csv::csv_decode_options::trim", (void)static_cast<csv_decode_view>(csv_opts).trim())
SET(call_csv_decode_options_trim_inside_quotes, "csv::csv_decode_options::trim_inside_quotes",
    (void)static_cast<csv_decode_view>(csv_opts).trim_inside_quotes())

static void call_csv_options_column_mapping(payload in) {
    payload from, to;
    split(in, from, to);
    std::vector<std::pair<std::string, std::string>> mapping{{text(from), text(to)}};
    TRY("csv::csv_options::column_mapping", csv_opts.column_mapping(mapping), true);
}
/* ltl: csv_cursor_lifecycle */
CURSOR_WRAPPERS(csv_cursor, "csv::csv_string_cursor", "csv_string_cursor", jsoncons::csv::csv_string_cursor, csv_cursor_input, csv_opts, csv_input)

static void call_csv_reader_eof(payload in) {
    std::string s = text(in);
    jsoncons::json_decoder<json> decoder;
    std::error_code ec;
    TRY("csv::csv_string_reader::eof", jsoncons::csv::csv_string_reader reader(s, decoder, csv_opts); reader.read(ec);
        (void)reader.eof(), !ec);
}

static void call_csv_encoder_reset(payload) {
    if (!have) return;
    TRY("csv::csv_string_encoder::reset", text_out.clear(); jsoncons::csv::csv_string_encoder encoder(text_out, csv_opts);
        current.dump(encoder); encoder.reset(); current.dump(encoder), true);
}

/* TOON (toon_options.hpp, toon_reader.hpp) */

using toon_key_folding = jsoncons::toon::key_folding_kind;
SET(call_toon_options_assign, "toon::toon_options::operator=", toon_opts = jsoncons::toon::toon_options())
/* indent: spaces per nesting level (toon_options.md) */
SET(call_toon_options_indent, "toon::toon_options::indent", toon_opts.indent(1 + byte(in, 0) % 8))
SET(call_toon_options_strict, "toon::toon_options::strict", toon_opts.strict(flag(in)))
SET(call_toon_options_delimiter, "toon::toon_options::delimiter",
    toon_opts.delimiter(byte(in, 0) % 3 == 0 ? jsoncons::toon::toon_delimiter_kind::comma
                        : byte(in, 0) % 3 == 1 ? jsoncons::toon::toon_delimiter_kind::tab : jsoncons::toon::toon_delimiter_kind::pipe))
SET(call_toon_options_length_marker, "toon::toon_options::length_marker",
    toon_opts.length_marker(flag(in) ? jsoncons::optional<char>(ch(rest(in, 1))) : jsoncons::optional<char>()))
SET(call_toon_options_key_folding, "toon::toon_options::key_folding", toon_opts.key_folding(pick<toon_key_folding>(in, 2)))
SET(call_toon_options_flatten_depth, "toon::toon_options::flatten_depth", toon_opts.flatten_depth(byte(in, 0)))
SET(call_toon_options_expand_paths, "toon::toon_options::expand_paths", toon_opts.expand_paths(pick<toon_key_folding>(in, 2)))
SET(call_toon_options_max_nesting_depth, "toon::toon_options::max_nesting_depth", toon_opts.max_nesting_depth(1 + byte(in, 0)))
SET(call_toon_decode_options_expand_paths, "toon::toon_decode_options::expand_paths",
    (void)static_cast<const jsoncons::toon::toon_decode_options &>(toon_opts).expand_paths())
SET(call_toon_encode_options_key_folding, "toon::toon_encode_options::key_folding",
    (void)static_cast<const jsoncons::toon::toon_encode_options &>(toon_opts).key_folding())
SET(call_toon_encode_options_flatten_depth, "toon::toon_encode_options::flatten_depth",
    (void)static_cast<const jsoncons::toon::toon_encode_options &>(toon_opts).flatten_depth())
SET(call_toon_options_common_max_nesting_depth, "toon::toon_options_common::max_nesting_depth",
    (void)static_cast<const jsoncons::toon::toon_options_common &>(toon_opts).max_nesting_depth())

static void call_toon_reader_read(payload in) {
    std::string s = text(in);
    jsoncons::json_decoder<json> decoder;
    TRY("toon::toon_string_reader::read", jsoncons::toon::toon_string_reader reader(s, decoder, toon_opts); reader.read();
        if (decoder.is_valid()) take(decoder.get_result()), true);
}

/* CBOR (cbor_options.hpp, cbor_cursor.hpp, cbor_encoder.hpp) */

SET(call_cbor_options_assign, "cbor::cbor_options::operator=", cbor_opts = jsoncons::cbor::cbor_options())
SET(call_cbor_options_max_nesting_depth, "cbor::cbor_options::max_nesting_depth", cbor_opts.max_nesting_depth(1 + byte(in, 0)))
SET(call_cbor_options_pack_strings, "cbor::cbor_options::pack_strings", cbor_opts.pack_strings(flag(in)))
SET(call_cbor_options_use_typed_arrays, "cbor::cbor_options::use_typed_arrays", cbor_opts.use_typed_arrays(flag(in)))
/* ltl: cbor_cursor_lifecycle */
CURSOR_WRAPPERS(cbor_cursor, "cbor::cbor_bytes_cursor", "cbor_bytes_cursor", jsoncons::cbor::cbor_bytes_cursor, cbor_cursor_input, cbor_opts, binary_input)

#define CBOR_CURSOR_GET(fn, api, expr) \
    static void fn(payload) { \
        if (!cbor_cursor) return; \
        TRY(api, (void)(expr), true); \
    }
/* ltl: cbor_cursor_lifecycle */
CBOR_CURSOR_GET(call_cbor_cursor_raw_tag, "cbor::cbor_bytes_cursor::raw_tag", cbor_cursor->raw_tag())
/* ltl: cbor_cursor_lifecycle */
CBOR_CURSOR_GET(call_cbor_cursor_is_typed_array, "cbor::cbor_bytes_cursor::is_typed_array", cbor_cursor->is_typed_array())
/* ltl: cbor_cursor_lifecycle */
CBOR_CURSOR_GET(call_cbor_cursor_is_multi_dim, "cbor::cbor_bytes_cursor::is_multi_dim", cbor_cursor->is_multi_dim())
/* ltl: cbor_cursor_lifecycle */
CBOR_CURSOR_GET(call_cbor_cursor_order, "cbor::cbor_bytes_cursor::order", cbor_cursor->order())

/* array_tag/array_buffer/extents/to_end_array describe the typed array the cursor is on: is_typed_array()
 * (cbor_parser.hpp:277-287 assert a typed array, :341 pops the parse state unconditionally) */
#define CBOR_TYPED(fn, api, stmt) \
    static void fn(payload) { \
        if (!cbor_cursor || cbor_cursor->done() || !cbor_cursor->is_typed_array()) return; \
        TRY(api, stmt, true); \
    }
/* ltl: cbor_cursor_lifecycle */
CBOR_TYPED(call_cbor_cursor_array_tag, "cbor::cbor_bytes_cursor::array_tag", (void)cbor_cursor->array_tag())
/* ltl: cbor_cursor_lifecycle */
CBOR_TYPED(call_cbor_cursor_array_buffer, "cbor::cbor_bytes_cursor::array_buffer", (void)cbor_cursor->array_buffer().size())
/* ltl: cbor_cursor_lifecycle */
CBOR_TYPED(call_cbor_cursor_extents, "cbor::cbor_bytes_cursor::extents", (void)cbor_cursor->extents().size())
/* ltl: cbor_cursor_lifecycle */
CBOR_TYPED(call_cbor_cursor_to_end_array, "cbor::cbor_bytes_cursor::to_end_array", cbor_cursor->to_end_array())
/* ltl: cbor_cursor_lifecycle */
CBOR_TYPED(call_cbor_cursor_read_typed_array, "staj_cursor::read_typed_array", std::vector<double> values; cbor_cursor->read_typed_array(values))

/* one tagged item per call into bytes_out; containers get one null member */
#define CBOR_TAGGED(fn, api, stmt) \
    static void fn(payload in) { \
        uint64_t tag = byte(in, 0) | static_cast<uint64_t>(byte(in, 1)) << 8; \
        payload value = rest(in, 2); \
        (void)value; \
        TRY(api, bytes_out.clear(); jsoncons::cbor::cbor_bytes_encoder encoder(bytes_out, cbor_opts); stmt; encoder.flush(), true); \
    }
CBOR_TAGGED(call_cbor_encoder_null_value_with_tag, "cbor::cbor_bytes_encoder::null_value_with_tag", encoder.null_value_with_tag(tag))
CBOR_TAGGED(call_cbor_encoder_bool_value_with_tag, "cbor::cbor_bytes_encoder::bool_value_with_tag",
            encoder.bool_value_with_tag(flag(value), tag))
CBOR_TAGGED(call_cbor_encoder_string_value_with_tag, "cbor::cbor_bytes_encoder::string_value_with_tag",
            encoder.string_value_with_tag(text(value), tag))
CBOR_TAGGED(call_cbor_encoder_byte_string_value_with_tag, "cbor::cbor_bytes_encoder::byte_string_value_with_tag",
            encoder.byte_string_value_with_tag(jsoncons::byte_string_view(value.p, value.n), tag))
CBOR_TAGGED(call_cbor_encoder_double_value_with_tag, "cbor::cbor_bytes_encoder::double_value_with_tag",
            double d = 0; std::memcpy(&d, value.p, value.n < sizeof d ? value.n : sizeof d); encoder.double_value_with_tag(d, tag))
CBOR_TAGGED(call_cbor_encoder_uint64_value_with_tag, "cbor::cbor_bytes_encoder::uint64_value_with_tag",
            uint64_t u = 0; std::memcpy(&u, value.p, value.n < sizeof u ? value.n : sizeof u); encoder.uint64_value_with_tag(u, tag))
CBOR_TAGGED(call_cbor_encoder_int64_value_with_tag, "cbor::cbor_bytes_encoder::int64_value_with_tag",
            int64_t i = 0; std::memcpy(&i, value.p, value.n < sizeof i ? value.n : sizeof i); encoder.int64_value_with_tag(i, tag))
CBOR_TAGGED(call_cbor_encoder_begin_array_with_tag, "cbor::cbor_bytes_encoder::begin_array_with_tag",
            if (flag(value)) encoder.begin_array_with_tag(1, tag); else encoder.begin_array_with_tag(tag);
            encoder.null_value(); encoder.end_array())
CBOR_TAGGED(call_cbor_encoder_begin_object_with_tag, "cbor::cbor_bytes_encoder::begin_object_with_tag",
            if (flag(value)) encoder.begin_object_with_tag(1, tag); else encoder.begin_object_with_tag(tag);
            encoder.key("k"); encoder.null_value(); encoder.end_object())

/* reset() clears the encoder state, so the second dump starts a new item */
#define ENCODER_RESET(fn, api, type, opts) \
    static void fn(payload in) { \
        json value; \
        if (!select(in, value)) return; \
        TRY(api, bytes_out.clear(); type encoder(bytes_out, opts); value.dump(encoder); encoder.reset(); value.dump(encoder), true); \
    }
ENCODER_RESET(call_cbor_encoder_reset, "cbor::cbor_bytes_encoder::reset", jsoncons::cbor::cbor_bytes_encoder, cbor_opts)

/* BSON (bson_options.hpp, bson_cursor.hpp, bson_encoder.hpp) */

SET(call_bson_options_assign, "bson::bson_options::operator=", bson_opts = jsoncons::bson::bson_options())
SET(call_bson_options_max_nesting_depth, "bson::bson_options::max_nesting_depth", bson_opts.max_nesting_depth(1 + byte(in, 0)))
/* ltl: bson_cursor_lifecycle */
CURSOR_WRAPPERS(bson_cursor, "bson::bson_bytes_cursor", "bson_bytes_cursor", jsoncons::bson::bson_bytes_cursor, bson_cursor_input, bson_opts, binary_input)
/* ltl: bson_cursor_lifecycle */
static void call_bson_cursor_array_expected(payload) {
    if (!bson_cursor || bson_cursor->done()) return;
    std::error_code ec;
    TRY("bson::bson_bytes_cursor::array_expected", bson_cursor->array_expected(ec), !ec);
    if (ec) bson_cursor.reset();
}
ENCODER_RESET(call_bson_encoder_reset, "bson::bson_bytes_encoder::reset", jsoncons::bson::bson_bytes_encoder, bson_opts)

/* MessagePack (msgpack_options.hpp, msgpack_cursor.hpp, msgpack_encoder.hpp) */

SET(call_msgpack_options_assign, "msgpack::msgpack_options::operator=", msgpack_opts = jsoncons::msgpack::msgpack_options())
SET(call_msgpack_options_max_nesting_depth, "msgpack::msgpack_options::max_nesting_depth",
    msgpack_opts.max_nesting_depth(1 + byte(in, 0)))
/* ltl: msgpack_cursor_lifecycle */
CURSOR_WRAPPERS(msgpack_cursor, "msgpack::msgpack_bytes_cursor", "msgpack_bytes_cursor", jsoncons::msgpack::msgpack_bytes_cursor, msgpack_cursor_input, msgpack_opts, binary_input)
ENCODER_RESET(call_msgpack_encoder_reset, "msgpack::msgpack_bytes_encoder::reset", jsoncons::msgpack::msgpack_bytes_encoder,
              msgpack_opts)

/* UBJSON (ubjson_options.hpp, ubjson_cursor.hpp, ubjson_encoder.hpp) */

SET(call_ubjson_options_assign, "ubjson::ubjson_options::operator=", ubjson_opts = jsoncons::ubjson::ubjson_options())
SET(call_ubjson_options_max_nesting_depth, "ubjson::ubjson_options::max_nesting_depth", ubjson_opts.max_nesting_depth(1 + byte(in, 0)))
SET(call_ubjson_options_max_items, "ubjson::ubjson_options::max_items", ubjson_opts.max_items(byte(in, 0) * 64))
/* ltl: ubjson_cursor_lifecycle */
CURSOR_WRAPPERS(ubjson_cursor, "ubjson::ubjson_bytes_cursor", "ubjson_bytes_cursor", jsoncons::ubjson::ubjson_bytes_cursor, ubjson_cursor_input, ubjson_opts, binary_input)
ENCODER_RESET(call_ubjson_encoder_reset, "ubjson::ubjson_bytes_encoder::reset", jsoncons::ubjson::ubjson_bytes_encoder, ubjson_opts)

/* JSON Pointer (jsonpointer.hpp) */

static bool pointers(payload in, jsoncons::jsonpointer::json_pointer &a, jsoncons::jsonpointer::json_pointer &b) {
    payload first, second;
    split(in, first, second);
    return pointer(first, a) && pointer(second, b);
}

static void call_jsonpointer_back(payload in) {
    jsoncons::jsonpointer::json_pointer ptr;
    if (!pointer(in, ptr) || ptr.empty()) return;  /* back(): the last token, needs one */
    TRY("jsonpointer::json_pointer::back", text_out = ptr.back(), true);
}

static void call_jsonpointer_clear(payload in) {
    jsoncons::jsonpointer::json_pointer ptr;
    if (!pointer(in, ptr)) return;
    TRY("jsonpointer::json_pointer::clear", ptr.clear(), ptr.empty());
}

static void call_jsonpointer_append_pointer(payload in) {
    jsoncons::jsonpointer::json_pointer a, b;
    if (!pointers(in, a, b)) return;
    TRY("jsonpointer::json_pointer::operator+=", size_t n = a.tokens().size(); a += b, a.tokens().size() == n + b.tokens().size());
}

static void call_jsonpointer_plus(payload in) {
    jsoncons::jsonpointer::json_pointer a, b;
    if (!pointers(in, a, b)) return;
    TRY("jsonpointer::operator+", text_out = (a + b).to_string(), true);
}

#define POINTER_COMPARE(fn, api, op) \
    static void fn(payload in) { \
        jsoncons::jsonpointer::json_pointer a, b; \
        if (!pointers(in, a, b)) return; \
        TRY(api, (void)(a op b), true); \
    }
POINTER_COMPARE(call_jsonpointer_equal, "jsonpointer::operator==", ==)
POINTER_COMPARE(call_jsonpointer_not_equal, "jsonpointer::operator!=", !=)
POINTER_COMPARE(call_jsonpointer_less_equal, "jsonpointer::operator<=", <=)
POINTER_COMPARE(call_jsonpointer_greater, "jsonpointer::operator>", >)
POINTER_COMPARE(call_jsonpointer_greater_equal, "jsonpointer::operator>=", >=)

static void call_jsonpointer_insert(payload in) {
    jsoncons::jsonpointer::json_pointer ptr;
    if (!pointer(in, ptr)) return;
    std::ostringstream os;
    TRY("jsonpointer::operator<<", os << ptr; text_out = os.str(), text_out == ptr.to_string());
}

static void call_jsonpointer_to_string(payload in) {
    jsoncons::jsonpointer::json_pointer ptr;
    if (!pointer(in, ptr)) return;
    TRY("jsonpointer::to_string", text_out = jsoncons::jsonpointer::to_string(ptr), true);
}

static void call_jsonpointer_to_wstring(payload in) {
    std::error_code ec;
    TRY("jsonpointer::to_wstring", auto ptr = jsoncons::jsonpointer::wjson_pointer::parse(wide(in), ec);
        if (!ec) (void)jsoncons::jsonpointer::to_wstring(ptr), !ec);
}

/* get without error_code throws jsonpointer_error (jsonpointer.hpp:654) */
static void call_jsonpointer_get_throwing(payload in) {
    jsoncons::jsonpointer::json_pointer ptr;
    if (!have || !pointer(in, ptr)) return;
    TRY_KEEP("jsonpointer::get(throw)", text_out = jsoncons::jsonpointer::get(current, ptr).to_string(), true,
             jsoncons::jsonpointer::jsonpointer_error, pointer_err);
}
static void call_jsonpointer_error_what(payload) {
    if (!pointer_err) return;
    TRY("jsonpointer::jsonpointer_error::what", text_out = pointer_err->what(), true);
}

static void call_jsonpointer_contains(payload in) {
    jsoncons::jsonpointer::json_pointer ptr;
    if (!have || !pointer(in, ptr)) return;
    TRY("jsonpointer::contains", (void)jsoncons::jsonpointer::contains(current, ptr), true);
}

/* JSON Patch errors (jsonpatch.hpp:578 apply_patch throws jsonpatch_error) */

static void call_jsonpatch_apply_patch_throwing(payload in) {
    json patch;
    if (!have || !argument(in, patch)) return;
    TRY_KEEP("jsonpatch::apply_patch(throw)", jsoncons::jsonpatch::apply_patch(current, patch), true, jsoncons::jsonpatch::jsonpatch_error,
             patch_err);
}
static void call_jsonpatch_error_what(payload) {
    if (!patch_err) return;
    TRY("jsonpatch::jsonpatch_error::what", text_out = patch_err->what(), true);
}
static void call_jsonpatch_error_assign(payload) {
    if (!patch_err) return;
    TRY("jsonpatch::jsonpatch_error::operator=",
        *patch_err = jsoncons::jsonpatch::jsonpatch_error(jsoncons::jsonpatch::jsonpatch_errc::test_failed), true);
}

/* JSONPath (jsonpath_expression.hpp, json_location.hpp, path_node.hpp, flatten.hpp, jsonpath_error.hpp) */

static void call_jsonpath_error_line(payload) {
    if (!jsonpath_err) return;
    TRY("jsonpath::jsonpath_error::line", (void)jsonpath_err->line(), true);
}
static void call_jsonpath_error_column(payload) {
    if (!jsonpath_err) return;
    TRY("jsonpath::jsonpath_error::column", (void)jsonpath_err->column(), true);
}
static void call_jsonpath_error_what(payload) {
    if (!jsonpath_err) return;
    TRY("jsonpath::jsonpath_error::what", text_out = jsonpath_err->what(), true);
}

/* custom function: returns its first argument; a second registration of a name is allowed (jsonpath.md) */
static void call_jsonpath_register_function(payload in) {
    std::string name = text(rest(in, 1));
    if (name.empty()) return;
    jsoncons::optional<std::size_t> arity(byte(in, 0) % 3);
    TRY("jsonpath::custom_functions::register_function", jsonpath_functions.register_function(name, arity,
        [](jsoncons::span<const jsoncons::jsonpath::parameter<json>> params, std::error_code &) -> json {
            return params.empty() ? json::null() : params[0].value();
        }), true);
}

static void call_jsonpath_custom_function_assign(payload in) {
    TRY("jsonpath::custom_function::operator=", jsoncons::jsonpath::custom_function<json> f(text(in), 0,
        [](jsoncons::span<const jsoncons::jsonpath::parameter<json>>, std::error_code &) -> json { return json::null(); });
        jsoncons::jsonpath::custom_function<json> g(f); g = f, g.name() == f.name());
}
/* ltl: jsonpath_expression_before_use */
static void call_jsonpath_make_expression(payload in) {
    jsonpath_expr.reset();
    TRY_KEEP("jsonpath::make_expression", jsonpath_expr.reset(new jsoncons::jsonpath::jsonpath_expression<json>(
        jsoncons::jsonpath::make_expression<json>(text(in), jsonpath_functions))), true, jsoncons::jsonpath::jsonpath_error, jsonpath_err);
}
/* ltl: jsonpath_expression_before_use */
static void call_jsonpath_expression_assign(payload in) {
    if (!jsonpath_expr) return;
    TRY_KEEP("jsonpath::jsonpath_expression::operator=", *jsonpath_expr = jsoncons::jsonpath::make_expression<json>(text(in)), true,
             jsoncons::jsonpath::jsonpath_error, jsonpath_err);
}
/* ltl: jsonpath_expression_before_use */
static void call_jsonpath_expression_select(payload in) {
    if (!jsonpath_expr || !have) return;
    TRY("jsonpath::jsonpath_expression::select",
        take(jsonpath_expr->select(current, flag(in) ? jsoncons::jsonpath::result_options::path : jsoncons::jsonpath::result_options())),
        true);
}
/* ltl: jsonpath_expression_before_use */
static void call_jsonpath_expression_select_paths(payload) {
    if (!jsonpath_expr || !have) return;
    TRY("jsonpath::jsonpath_expression::select_paths", auto paths = jsonpath_expr->select_paths(current);
        if (!paths.empty()) location = paths.front(), true);
}
/* the callback replaces each selected value by its normalized path */
/* ltl: jsonpath_expression_before_use */
static void call_jsonpath_expression_update(payload) {
    if (!jsonpath_expr || !have) return;
    TRY("jsonpath::jsonpath_expression::update", jsonpath_expr->update(current,
        [](const jsoncons::jsonpath::path_node &path, json &value) { value = json(jsoncons::jsonpath::to_string(path)); }), true);
}

static void call_json_location_parse(payload in) {
    TRY("jsonpath::json_location::parse", location = jsoncons::jsonpath::json_location::parse(text(in)), true);
}
static void call_json_location_ctor(payload) {
    TRY("jsonpath::json_location::json_location", jsoncons::jsonpath::path_node root; jsoncons::jsonpath::path_node child(&root, std::size_t(1));
        location = jsoncons::jsonpath::json_location(child), location.size() == 1);
}
static void call_json_location_append(payload in) {
    TRY("jsonpath::json_location::append", size_t n = location.size();
        if (flag(in)) location.append(text(rest(in, 1))); else location.append(byte(in, 1)), location.size() == n + 1);
}
static void call_json_location_slash_assign(payload in) {
    TRY("jsonpath::json_location::operator/=", size_t n = location.size();
        if (flag(in)) location /= text(rest(in, 1)); else location /= byte(in, 1), location.size() == n + 1);
}
static void call_json_location_clear(payload) { TRY("jsonpath::json_location::clear", location.clear(), location.empty()); }
static void call_json_location_empty(payload) { TRY("jsonpath::json_location::empty", (void)location.empty(), true); }
static void call_json_location_size(payload) { TRY("jsonpath::json_location::size", (void)location.size(), true); }
static void call_json_location_index(payload in) {
    if (location.empty()) return;
    TRY("jsonpath::json_location::operator[]", element = location[byte(in, 0) % location.size()], true);
}
static void call_json_location_begin(payload) {
    TRY("jsonpath::json_location::begin", size_t n = 0; for (auto it = location.begin(); it != location.end(); ++it) n++,
        n == location.size());
}
static void call_json_location_compare(payload in) {
    TRY("jsonpath::json_location::compare", auto other = jsoncons::jsonpath::json_location::parse(text(in));
        (void)location.compare(other), true);
}
static void call_json_location_not_equal(payload in) {
    TRY("jsonpath::operator!=", auto other = jsoncons::jsonpath::json_location::parse(text(in)); (void)(location != other), true);
}
static void call_json_location_assign(payload) {
    TRY("jsonpath::json_location::operator=", jsoncons::jsonpath::json_location copy; copy = location, copy == location);
}
static void call_jsonpath_location_to_string(payload) {
    TRY("jsonpath::to_string", text_out = jsoncons::jsonpath::to_string(location), true);
}
static void call_jsonpath_location_to_wstring(payload in) {
    TRY("jsonpath::to_wstring", jsoncons::jsonpath::wjson_location w; w.append(wide(in)); (void)jsoncons::jsonpath::to_wstring(w), true);
}
static void call_jsonpath_get(payload) {
    if (!have) return;
    TRY("jsonpath::get", auto r = jsoncons::jsonpath::get(current, location); if (r.second) text_out = r.first->to_string(), true);
}
static void call_jsonpath_replace(payload in) {
    if (!have) return;
    TRY("jsonpath::replace", (void)jsoncons::jsonpath::replace(current, location, json(text(rest(in, 1))), flag(in)), true);
}
static void call_jsonpath_remove(payload in) {
    if (!have) return;
    TRY("jsonpath::remove", if (flag(in)) (void)jsoncons::jsonpath::remove(current, location);
        else (void)jsoncons::jsonpath::remove(current, jsoncons::string_view(text(rest(in, 1)))), true);
}
static void call_jsonpath_flatten(payload in) {
    json value;
    if (!select(in, value)) return;
    TRY("jsonpath::flatten", take(jsoncons::jsonpath::flatten(value)), true);
}
static void call_jsonpath_unflatten(payload) {
    if (!have) return;
    TRY("jsonpath::unflatten", take(jsoncons::jsonpath::unflatten(current)), true);
}

static void call_path_element_ctor(payload in) {
    TRY("jsonpath::path_element::path_element",
        if (flag(in)) element = jsoncons::jsonpath::path_element(text(rest(in, 1)));
        else element = jsoncons::jsonpath::path_element(static_cast<std::size_t>(byte(in, 1))), true);
}
static void call_path_element_has_name(payload) { TRY("jsonpath::path_element::has_name", (void)element.has_name(), true); }
static void call_path_element_has_index(payload) { TRY("jsonpath::path_element::has_index", (void)element.has_index(), true); }
static void call_path_element_name(payload) { TRY("jsonpath::path_element::name", text_out = element.name(), true); }
static void call_path_element_index(payload) { TRY("jsonpath::path_element::index", (void)element.index(), true); }
static void call_path_element_compare(payload in) {
    TRY("jsonpath::path_element::compare", jsoncons::jsonpath::path_element other(text(in)); (void)element.compare(other), true);
}
static void call_path_element_assign(payload) {
    TRY("jsonpath::path_element::operator=", jsoncons::jsonpath::path_element copy(std::size_t(0)); copy = element,
        copy.compare(element) == 0);
}

/* path_node: nodes of the same depth (siblings of one root). path_node.hpp:89 swap() exchanges parent, kind,
 * name and index but not size_, so swapping nodes of different depth makes to_string/select index their node
 * vector out of bounds (path_node.hpp:283-288, repro.cpp case 4). */
static void call_path_node_swap(payload in) {
    jsoncons::jsonpath::path_node root;
    std::string name = text(in);
    jsoncons::jsonpath::path_node a(&root, name), b(&root, static_cast<std::size_t>(byte(in, 0)));
    TRY("jsonpath::path_node::swap", a.swap(b); text_out = jsoncons::jsonpath::to_string(a) + jsoncons::jsonpath::to_string(b), true);
}
static void call_path_node_assign(payload in) {
    jsoncons::jsonpath::path_node root;
    std::string name = text(in);
    jsoncons::jsonpath::path_node a(&root, name), b(&a, static_cast<std::size_t>(byte(in, 0)));
    TRY("jsonpath::path_node::operator=", jsoncons::jsonpath::path_node copy; copy = b,
        jsoncons::jsonpath::to_string(copy) == jsoncons::jsonpath::to_string(b));
}

/* JMESPath (jmespath.hpp). make_expression compiles like search, so the same two parser bugs are avoided. */

static void call_jmespath_error_line(payload) {
    if (!jmespath_err) return;
    TRY("jmespath::jmespath_error::line", (void)jmespath_err->line(), true);
}
static void call_jmespath_error_column(payload) {
    if (!jmespath_err) return;
    TRY("jmespath::jmespath_error::column", (void)jmespath_err->column(), true);
}
static void call_jmespath_error_what(payload) {
    if (!jmespath_err) return;
    TRY("jmespath::jmespath_error::what", text_out = jmespath_err->what(), true);
}

/* custom function: returns its first value argument (jmespath.md custom_functions) */
static void call_jmespath_register_function(payload in) {
    std::string name = text(rest(in, 1));
    if (name.empty()) return;
    jsoncons::optional<std::size_t> arity(byte(in, 0) % 3);
    TRY("jmespath::custom_functions::register_function", jmespath_functions.register_function(name, arity,
        [](jsoncons::span<const jsoncons::jmespath::parameter<json>> params, jsoncons::jmespath::eval_context<json> &,
           std::error_code &) -> json {
            for (const auto &p : params)
                if (p.is_value()) return p.value();
            return json::null();
        }), true);
}

static void call_jmespath_parameter_assign(payload in) {
    json a(text(in)), b;
    TRY("jmespath::parameter::operator=", jsoncons::jmespath::parameter<json> p(a); jsoncons::jmespath::parameter<json> q(b); q = p,
        &q.value() == &a);
}
/* ltl: jmespath_expression_before_use */
static void call_jmespath_make_expression(payload in) {
    std::string expr = text(in);
    jmespath_expr.reset();
    if (hash_key_loops(expr) || !parens_balanced(expr)) return;
    TRY_KEEP("jmespath::make_expression", jmespath_expr.reset(new jsoncons::jmespath::jmespath_expression<json>(
        jsoncons::jmespath::make_expression<json>(expr, jmespath_functions))), true, jsoncons::jmespath::jmespath_error, jmespath_err);
}
/* ltl: jmespath_expression_before_use */
static void call_jmespath_expression_evaluate(payload) {
    if (!jmespath_expr || !have) return;
    std::error_code ec;
    TRY("jmespath::jmespath_expression::evaluate", json r = jmespath_expr->evaluate(current, ec); if (!ec) take(r), !ec);
}

/* JSON Schema (json_schema.hpp, evaluation_options.hpp, validation_message.hpp, jsonschema_error.hpp) */

static void call_jsonschema_evaluation_options_assign(payload in) {
    static const char *const versions[] = {"http://json-schema.org/draft-04/schema#", "http://json-schema.org/draft-06/schema#",
        "http://json-schema.org/draft-07/schema#", "https://json-schema.org/draft/2019-09/schema",
        "https://json-schema.org/draft/2020-12/schema"};
    TRY("jsonschema::evaluation_options::operator=",
        schema_opts = jsoncons::jsonschema::evaluation_options().default_version(versions[byte(in, 0) % 5]), true);
}

static void call_jsonschema_schema_error_what(payload) {
    if (!schema_err) return;
    TRY("jsonschema::schema_error::what", text_out = schema_err->what(), true);
}
/* ltl: schema_before_validate */
static void call_json_schema_validate(payload in) {
    if (!schema) return;
    json instance;
    if (byte(in, 0) & 1) {
        if (!have) return;
        instance = current;
    } else if (!argument(rest(in, 1), instance)) {
        return;
    }
    TRY("json_schema::validate", messages.clear(); schema->validate(instance,
        [](const jsoncons::jsonschema::validation_message &msg) -> jsoncons::jsonschema::walk_state {
            if (messages.size() < 16) messages.push_back(msg);
            return jsoncons::jsonschema::walk_state::advance;
        }), true);
}
/* validate(instance) throws validation_error on the first error (json_schema/validate.md (1)) */
/* ltl: schema_before_validate */
static void call_json_schema_validate_throwing(payload in) {
    if (!schema || !have) return;
    (void)in;
    TRY_KEEP("json_schema::validate(throw)", schema->validate(current), true, jsoncons::jsonschema::validation_error, validation_err);
}
/* ltl: schema_before_validate */
static void call_json_schema_walk(payload) {
    if (!schema || !have) return;
    TRY("json_schema::walk", size_t n = 0; schema->walk(current,
        [&n](const jsoncons::jsonschema::schema_property<json> &property, const json &, const jsoncons::jsonpointer::json_pointer &,
             jsoncons::optional<json> &) -> jsoncons::jsonschema::walk_state {
            n += property.keyword().size() + property.subschemas().size() + property.schema_location().string().size();
            return jsoncons::jsonschema::walk_state::advance;
        }); (void)n, true);
}
/* ltl: schema_before_validate */
static void call_json_schema_assign(payload in) {
    json source;
    if (!schema || !argument(in, source)) return;
    TRY_KEEP("json_schema::operator=", *schema = jsoncons::jsonschema::make_json_schema(source, schema_opts), true,
             jsoncons::jsonschema::schema_error, schema_err);
}

static void call_validation_error_what(payload) {
    if (!validation_err) return;
    TRY("jsonschema::validation_error::what", text_out = validation_err->what(), true);
}

#define MESSAGE_GET(fn, api, expr) \
    static void fn(payload) { \
        if (messages.empty()) return; \
        const jsoncons::jsonschema::validation_message &msg = messages.back(); \
        TRY(api, text_out = expr, true); \
    }
MESSAGE_GET(call_validation_message_message, "jsonschema::validation_message::message", msg.message())
MESSAGE_GET(call_validation_message_keyword, "jsonschema::validation_message::keyword", msg.keyword())
MESSAGE_GET(call_validation_message_instance_location, "jsonschema::validation_message::instance_location",
            msg.instance_location().to_string())
MESSAGE_GET(call_validation_message_eval_path, "jsonschema::validation_message::eval_path", msg.eval_path().to_string())
MESSAGE_GET(call_validation_message_schema_location, "jsonschema::validation_message::schema_location", msg.schema_location().string())

/* dispatch */

static void (*const api[])(payload) = {
    call_json_parse, call_json_parse_stream, call_json_dump, call_json_dump_pretty, call_json_dump_encoder,
    call_json_stream_reader_read, call_json_stream_reader_read_to_encoder, call_json_parser_update_finish,
    call_json_stream_cursor_ctor, call_json_stream_cursor_current, call_json_stream_cursor_next,
    call_json_insert_or_assign, call_json_push_back, call_decode_csv, call_encode_csv, call_decode_toon,
    call_encode_toon, call_decode_cbor, call_decode_bson, call_decode_msgpack, call_decode_msgpack_stream,
    call_decode_ubjson, call_encode_cbor, call_encode_bson, call_encode_msgpack, call_encode_ubjson,
    call_encode_msgpack_stream, call_jsonpointer_get, call_jsonpointer_add, call_jsonpointer_remove,
    call_jsonpointer_replace, call_jsonpointer_flatten, call_jsonpointer_unflatten, call_jsonpatch_apply_patch,
    call_jsonpatch_from_diff, call_mergepatch_apply_merge_patch, call_mergepatch_from_diff, call_jsonpath_json_query,
    call_jsonpath_json_replace, call_jmespath_search, call_jsonschema_make_json_schema, call_json_schema_is_valid,
    call_bigint_ctor, call_bigint_modulo, call_bigint_to_string, call_json_options_assign,
    call_json_options_allow_comments, call_json_options_allow_trailing_comma, call_json_options_lossless_number,
    call_json_options_lossless_bignum, call_json_options_max_nesting_depth, call_json_options_nan_to_num,
    call_json_options_inf_to_num, call_json_options_neginf_to_num, call_json_options_nan_to_str,
    call_json_options_inf_to_str, call_json_options_neginf_to_str, call_json_options_byte_string_format,
    call_json_options_bigint_format, call_json_options_bignum_format, call_json_options_line_splits,
    call_json_options_root_line_splits, call_json_options_object_object_line_splits,
    call_json_options_object_array_line_splits, call_json_options_array_object_line_splits,
    call_json_options_array_array_line_splits, call_json_options_indent_size, call_json_options_indent_char,
    call_json_options_spaces_around_colon, call_json_options_spaces_around_comma,
    call_json_options_pad_inside_object_braces, call_json_options_pad_inside_array_brackets,
    call_json_options_new_line_chars, call_json_options_line_length_limit, call_json_options_float_format,
    call_json_options_precision, call_json_options_escape_all_non_ascii, call_json_options_escape_solidus,
    call_json_encode_options_bigint_format, call_json_encode_options_line_splits, call_json_options_err_handler,
    call_decode_json, call_try_decode_json, call_read_error_message, call_read_error_assign, call_encode_json,
    call_encode_json_pretty, call_try_encode_json, call_try_encode_json_pretty, call_print, call_pretty_print,
    call_json_operator_insert, call_json_operator_extract, call_combine_allocators, call_temp_allocator_only,
    call_ser_error_code, call_ser_error_line, call_ser_error_column, call_ser_error_what, call_ser_error_assign,
    call_json_as, call_conv_error_what, call_json_try_as, call_conversion_error_message, call_conversion_error_assign,
    call_json_as_byte_string, call_json_try_as_byte_string, call_json_at_or_null, call_json_capacity, call_json_count,
    call_json_emplace, call_json_get_value_or, call_json_is_bignum, call_json_is_byte_string,
    call_json_is_byte_string_view, call_json_is_half, call_json_make_array, call_json_merge,
    call_json_merge_or_update, call_json_resize, call_json_shrink_to_fit, call_json_byte_string_arg,
    call_json_half_arg, call_range_rbegin, call_range_cbegin, call_range_crbegin, call_key_value_shrink_to_fit,
    call_key_value_swap, call_byte_string_assign, call_byte_string_append, call_byte_string_push_back,
    call_byte_string_clear, call_byte_string_reserve, call_byte_string_get_allocator,
    call_byte_string_operator_assign, call_byte_string_index, call_byte_string_begin, call_byte_string_view_cbegin,
    call_byte_string_view_index, call_byte_string_view_assign, call_byte_string_view_substr, call_stream_sink_ctor,
    call_stream_sink_append, call_stream_sink_push_back, call_stream_sink_flush, call_stream_sink_assign,
    call_binary_stream_sink_append, call_binary_stream_sink_assign, call_bytes_sink_assign, call_string_sink_assign,
    call_uri_authority, call_uri_userinfo, call_uri_path, call_uri_query, call_uri_has_scheme, call_uri_with_fragment,
    call_json_parser_position, call_json_parser_begin_position, call_json_parser_end_position,
    call_json_stream_reader_line, call_json_stream_reader_column, call_json_decoder_reset, call_json_encoder_reset,
    call_compact_json_encoder_reset, call_compact_json_encoder_ctor, call_json_filter, call_json_filter_destination,
    call_rename_object_key_filter, call_json_stream_cursor_check_done, call_json_stream_cursor_line,
    call_json_stream_cursor_column, call_json_stream_cursor_context, call_json_stream_cursor_eof,
    call_json_stream_cursor_read_to, call_json_stream_cursor_reset,
    call_ser_context_line, call_ser_context_column, call_ser_context_position, call_ser_context_begin_position,
    call_ser_context_end_position, call_staj_cursor_done, call_staj_cursor_line, call_staj_cursor_column,
    call_staj_cursor_context, call_staj_cursor_is_multi_dim, call_staj_cursor_extents, call_staj_cursor_order,
    call_staj_cursor_is_typed_array, call_staj_cursor_array_tag, call_staj_cursor_array_buffer,
    call_staj_cursor_to_end_array, call_staj_cursor_current, call_staj_cursor_next, call_staj_cursor_read_to,
    call_staj_cursor_array_expected, call_staj_event_size, call_staj_event_ext_tag, call_staj_event_get,
    call_staj_array_iterator_ctor, call_staj_array_iterator_deref, call_staj_array_iterator_arrow,
    call_staj_array_iterator_increment, call_staj_array_iterator_preincrement, call_staj_array_iterator_assign,
    call_staj_object_iterator_ctor, call_staj_object_iterator_deref, call_staj_object_iterator_arrow,
    call_staj_object_iterator_increment, call_staj_object_iterator_preincrement, call_staj_object_iterator_assign,
    call_bigint_operator_bool, call_bigint_operator_double, call_bigint_operator_long_double,
    call_bigint_operator_integer, call_bigint_operator_not, call_bigint_increment, call_bigint_decrement,
    call_bigint_to_string_hex, call_bigint_babs, call_bigint_bpow, call_bigint_shift_left, call_bigint_shift_right,
    call_bigint_bsqrt, call_bigint_and_assign, call_bigint_or_assign, call_bigint_xor_assign, call_bigint_plus,
    call_bigint_times, call_bigint_xor, call_bigint_divide, call_csv_options_assign, call_csv_options_float_format,
    call_csv_options_precision, call_csv_options_header_lines, call_csv_options_ignore_empty_values,
    call_csv_options_ignore_empty_lines, call_csv_options_trim_leading, call_csv_options_trim_trailing,
    call_csv_options_trim_leading_inside_quotes, call_csv_options_trim_trailing_inside_quotes, call_csv_options_trim,
    call_csv_options_trim_inside_quotes, call_csv_options_unquoted_empty_value_is_null, call_csv_options_column_names,
    call_csv_options_column_types, call_csv_options_column_defaults, call_csv_options_flat,
    call_csv_options_max_nesting_depth, call_csv_options_subfield_delimiter, call_csv_options_line_delimiter,
    call_csv_options_quote_char, call_csv_options_quote_escape_char, call_csv_options_comment_starter,
    call_csv_options_infer_types, call_csv_options_lossless_number, call_csv_options_quote_style,
    call_csv_options_mapping_kind, call_csv_options_max_lines, call_csv_options_nan_to_num,
    call_csv_options_inf_to_num, call_csv_options_neginf_to_num, call_csv_options_nan_to_str,
    call_csv_options_inf_to_str, call_csv_options_neginf_to_str, call_csv_decode_options_trim,
    call_csv_decode_options_trim_inside_quotes, call_csv_options_column_mapping, call_csv_cursor_ctor,
    call_csv_cursor_current, call_csv_cursor_next, call_csv_cursor_done, call_csv_cursor_eof, call_csv_cursor_line,
    call_csv_cursor_column, call_csv_cursor_context, call_csv_cursor_read_to, call_csv_cursor_reset,
    call_csv_cursor_filter, call_csv_reader_eof, call_csv_encoder_reset, call_toon_options_assign,
    call_toon_options_indent, call_toon_options_strict, call_toon_options_delimiter, call_toon_options_length_marker,
    call_toon_options_key_folding, call_toon_options_flatten_depth, call_toon_options_expand_paths,
    call_toon_options_max_nesting_depth, call_toon_decode_options_expand_paths, call_toon_encode_options_key_folding,
    call_toon_encode_options_flatten_depth, call_toon_options_common_max_nesting_depth, call_toon_reader_read,
    call_cbor_options_assign, call_cbor_options_max_nesting_depth, call_cbor_options_pack_strings,
    call_cbor_options_use_typed_arrays, call_cbor_cursor_ctor, call_cbor_cursor_current, call_cbor_cursor_next,
    call_cbor_cursor_done, call_cbor_cursor_eof, call_cbor_cursor_line, call_cbor_cursor_column,
    call_cbor_cursor_context, call_cbor_cursor_read_to, call_cbor_cursor_reset, call_cbor_cursor_filter,
    call_cbor_cursor_raw_tag, call_cbor_cursor_is_typed_array, call_cbor_cursor_is_multi_dim, call_cbor_cursor_order,
    call_cbor_cursor_array_tag, call_cbor_cursor_array_buffer, call_cbor_cursor_extents,
    call_cbor_cursor_to_end_array, call_cbor_cursor_read_typed_array, call_cbor_encoder_null_value_with_tag,
    call_cbor_encoder_bool_value_with_tag, call_cbor_encoder_string_value_with_tag,
    call_cbor_encoder_byte_string_value_with_tag, call_cbor_encoder_double_value_with_tag,
    call_cbor_encoder_uint64_value_with_tag, call_cbor_encoder_int64_value_with_tag,
    call_cbor_encoder_begin_array_with_tag, call_cbor_encoder_begin_object_with_tag, call_cbor_encoder_reset,
    call_bson_options_assign, call_bson_options_max_nesting_depth, call_bson_cursor_ctor, call_bson_cursor_current,
    call_bson_cursor_next, call_bson_cursor_done, call_bson_cursor_eof, call_bson_cursor_line,
    call_bson_cursor_column, call_bson_cursor_context, call_bson_cursor_read_to, call_bson_cursor_reset,
    call_bson_cursor_filter, call_bson_cursor_array_expected, call_bson_encoder_reset, call_msgpack_options_assign,
    call_msgpack_options_max_nesting_depth, call_msgpack_cursor_ctor, call_msgpack_cursor_current,
    call_msgpack_cursor_next, call_msgpack_cursor_done, call_msgpack_cursor_eof, call_msgpack_cursor_line,
    call_msgpack_cursor_column, call_msgpack_cursor_context, call_msgpack_cursor_read_to, call_msgpack_cursor_reset,
    call_msgpack_cursor_filter, call_msgpack_encoder_reset, call_ubjson_options_assign,
    call_ubjson_options_max_nesting_depth, call_ubjson_options_max_items, call_ubjson_cursor_ctor,
    call_ubjson_cursor_current, call_ubjson_cursor_next, call_ubjson_cursor_done, call_ubjson_cursor_eof,
    call_ubjson_cursor_line, call_ubjson_cursor_column, call_ubjson_cursor_context, call_ubjson_cursor_read_to,
    call_ubjson_cursor_reset, call_ubjson_cursor_filter, call_ubjson_encoder_reset, call_jsonpointer_back,
    call_jsonpointer_clear, call_jsonpointer_append_pointer, call_jsonpointer_plus, call_jsonpointer_equal,
    call_jsonpointer_not_equal, call_jsonpointer_less_equal, call_jsonpointer_greater, call_jsonpointer_greater_equal,
    call_jsonpointer_insert, call_jsonpointer_to_string, call_jsonpointer_to_wstring, call_jsonpointer_get_throwing,
    call_jsonpointer_error_what, call_jsonpointer_contains,
    call_jsonpatch_apply_patch_throwing, call_jsonpatch_error_what, call_jsonpatch_error_assign,
    call_jsonpath_error_line, call_jsonpath_error_column, call_jsonpath_error_what, call_jsonpath_register_function,
    call_jsonpath_custom_function_assign, call_jsonpath_make_expression, call_jsonpath_expression_assign,
    call_jsonpath_expression_select, call_jsonpath_expression_select_paths, call_jsonpath_expression_update,
    call_json_location_parse, call_json_location_ctor, call_json_location_append, call_json_location_slash_assign,
    call_json_location_clear, call_json_location_empty, call_json_location_size, call_json_location_index,
    call_json_location_begin, call_json_location_compare, call_json_location_not_equal, call_json_location_assign,
    call_jsonpath_location_to_string, call_jsonpath_location_to_wstring, call_jsonpath_get, call_jsonpath_replace,
    call_jsonpath_remove, call_jsonpath_flatten, call_jsonpath_unflatten, call_path_element_ctor,
    call_path_element_has_name, call_path_element_has_index, call_path_element_name, call_path_element_index,
    call_path_element_compare, call_path_element_assign, call_path_node_swap, call_path_node_assign,
    call_jmespath_error_line, call_jmespath_error_column, call_jmespath_error_what, call_jmespath_register_function,
    call_jmespath_parameter_assign, call_jmespath_make_expression, call_jmespath_expression_evaluate,
    call_jsonschema_evaluation_options_assign, call_jsonschema_schema_error_what, call_json_schema_validate,
    call_json_schema_validate_throwing, call_json_schema_walk, call_json_schema_assign, call_validation_error_what,
    call_validation_message_message, call_validation_message_keyword, call_validation_message_instance_location,
    call_validation_message_eval_path, call_validation_message_schema_location,
};

static const size_t API_COUNT = sizeof api / sizeof api[0];

static void cleanup() {
    current = json();
    have = false;
    text_out.clear();
    bytes_out.clear();
    schema.reset();
    number.reset();
    previous_number.reset();
    cursor.reset();
    cursor_input.reset();
    json_opts = jsoncons::json_options();
    csv_opts = jsoncons::csv::csv_options();
    toon_opts = jsoncons::toon::toon_options();
    cbor_opts = jsoncons::cbor::cbor_options();
    bson_opts = jsoncons::bson::bson_options();
    msgpack_opts = jsoncons::msgpack::msgpack_options();
    ubjson_opts = jsoncons::ubjson::ubjson_options();
    schema_opts = jsoncons::jsonschema::evaluation_options();
    parse_err.reset();
    read_err.reset();
    conv_err.reset();
    conversion_err.reset();
    patch_err.reset();
    pointer_err.reset();
    jsonpath_err.reset();
    jmespath_err.reset();
    schema_err.reset();
    validation_err.reset();
    messages.clear();
    bytes.clear();
    location.clear();
    element = jsoncons::jsonpath::path_element(std::size_t(0));
    jsonpath_expr.reset();
    jsonpath_functions = jsoncons::jsonpath::custom_functions<json>();
    jmespath_expr.reset();
    jmespath_functions = jsoncons::jmespath::custom_functions<json>();
    cbor_cursor.reset();
    bson_cursor.reset();
    msgpack_cursor.reset();
    ubjson_cursor.reset();
    csv_cursor.reset();
    cbor_cursor_input.clear();
    bson_cursor_input.clear();
    msgpack_cursor_input.clear();
    ubjson_cursor_input.clear();
    csv_cursor_input.clear();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    preqed_reset();
    size_t off = 0;
    /* record: 2-byte operation (there are more than 256 wrappers), 2-byte payload length, payload */
    while (size - off >= 4) {
        size_t op = static_cast<size_t>(data[off]) | static_cast<size_t>(data[off + 1]) << 8;
        size_t len = static_cast<size_t>(data[off + 2]) | static_cast<size_t>(data[off + 3]) << 8;
        off += 4;
        if (len > size - off) break;
        api[op % API_COUNT]({ data + off, len });
        off += len;
    }
    cleanup();
    return 0;
}
