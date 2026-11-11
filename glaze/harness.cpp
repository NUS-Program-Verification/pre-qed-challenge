#include <glaze/glaze.hpp>
#include <glaze/glaze_exceptions.hpp>
#include <glaze/bson.hpp>
#include <glaze/cbor.hpp>
#include <glaze/chrono.hpp>
#include <glaze/json/jmespath.hpp>
#include <glaze/json/patch.hpp>
#include <glaze/jsonb.hpp>
#include <glaze/msgpack.hpp>
#include <glaze/toml.hpp>
#include <glaze/yaml.hpp>
#include <glaze/thread/threadpool.hpp>
#include "preqed_ltl.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <filesystem>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

/* file APIs work on one file and one directory in the working directory, removed after every input */
#define FILE_PATH "glaze-harness.dat"
#define DIR_PATH "glaze-harness.d"

/* reflected types: the typed readers and writers need them */

struct fuzz_child {
    int n{};
    std::string label{};
    std::vector<double> data{};
};

/* reflected model for the typed read/write paths: one field of each kind glaze serializes differently
   (int, double, string, fixed array, optional, map, nested struct vector, variant) */
struct fuzz_model {
    int i{};
    double d{};
    std::string hello{};
    std::array<uint64_t, 3> arr{};
    std::optional<std::string> maybe{};
    std::map<std::string, int> dict{};
    std::vector<fuzz_child> kids{};
    std::variant<int, std::string, double> alt{};
};

/* CSV needs column-shaped data: vectors of numbers/bools and a vector of fixed arrays */
struct csv_model {
    std::vector<int> num1{};
    std::deque<float> num2{};
    std::vector<bool> maybe{};
    std::vector<std::array<int, 3>> v3s{};
};

/* types described by glz::meta wrappers instead of pure reflection: glz::flags (bools as a list of names),
   glz::array (members positionally), glz::object (named members), and the chrono field wrappers */
struct fuzz_perms {
    bool read{};
    bool write{};
    bool execute{};
};

struct fuzz_point {
    double x{};
    double y{};
    int id{};
};

struct fuzz_record {
    int id{};
    std::string name{};
    fuzz_perms perms{};
    fuzz_point at{};
};

struct fuzz_dated {
    std::chrono::system_clock::time_point start{};
    std::chrono::sys_days day{};
};

struct fuzz_counted {
    std::chrono::sys_time<std::chrono::milliseconds> logged{};
};

template <>
struct glz::meta<fuzz_perms> {
    using T = fuzz_perms;
    static constexpr auto value = glz::flags("read", &T::read, "write", &T::write, "execute", &T::execute);
};

template <>
struct glz::meta<fuzz_point> {
    using T = fuzz_point;
    static constexpr auto value = glz::array(&T::x, &T::y, &T::id);
};

template <>
struct glz::meta<fuzz_record> {
    using T = fuzz_record;
    static constexpr auto value = glz::object("id", &T::id, "name", &T::name, "perms", &T::perms, "at", &T::at);
};

template <>
struct glz::meta<fuzz_dated> {
    using T = fuzz_dated;
    static constexpr auto value = glz::object("start", glz::date_format(&T::start, "%Y-%m-%d %H:%M:%S"),
                                              "day", glz::date_format(&T::day, "%F"));
};

template <>
struct glz::meta<fuzz_counted> {
    using T = fuzz_counted;
    static constexpr auto value = glz::object("logged", glz::epoch_count<std::chrono::milliseconds>(&T::logged));
};

struct payload {
    const uint8_t *p;
    size_t n;
};

/* state: one typed document, one generic document, one second document for diff/merge, one converted sequence */

static fuzz_model model;
static bool have_model;
static glz::generic generic;
static bool have_generic;
static glz::generic target;
static bool have_target;
static csv_model csv;
static bool have_csv;
static std::vector<fuzz_model> sequence;
static glz::patch_document patches;
static bool have_patch;
static std::string text_out;                /* last text serialization */
static std::string bytes_out;               /* last binary serialization */
static std::string expression_path;         /* jmespath_expression::tokens are views into it, so it outlives the expression */
static std::unique_ptr<glz::jmespath_expression> expression;
static glz::generic_u64 wide;               /* integer-preserving generic: as_number/is_int64/is_uint64/is_double need it */
static bool have_wide;
static glz::error_ctx last_error;           /* result and input of the last read_json, for format_error */
static std::string last_input;
/* lazy documents keep pointers into their text and views keep a pointer to their document: the text, the
   document and the views derived from it are replaced together */
static std::string lazy_text;
static std::optional<glz::lazy_document<>> lazy_doc;
static std::optional<glz::lazy_json_view<>> lazy_view;
static std::optional<glz::indexed_lazy_view<glz::opts{}>> lazy_index;
static std::string beve_text;
static std::optional<glz::lazy_beve_document<>> beve_doc;
static std::optional<glz::lazy_beve_view<>> beve_view;
static std::optional<glz::indexed_lazy_beve_view<glz::opts{}>> beve_index;
/* json_stream_reader keeps a reference to its stream */
static std::unique_ptr<std::istringstream> stream_in;
static std::unique_ptr<glz::json_stream_reader<fuzz_model, std::istringstream>> stream_reader;
static std::unique_ptr<glz::pool> thread_pool;
static glz::epoch_time<std::chrono::milliseconds> stamp;
static glz::uuid id;
static bool have_file;
static bool have_dir;

static uint8_t byte(payload in, size_t i) { return i < in.n ? in.p[i] : 0; }
static payload rest(payload in, size_t skip) {
    return { in.p + (skip < in.n ? skip : in.n), in.n > skip ? in.n - skip : 0 };
}
static std::string text(payload in) { return std::string(reinterpret_cast<const char *>(in.p), in.n); }

/* first payload byte bit 0: feed the last serialization back in, else use the rest of the record. glaze pads a
 * resizable input buffer and reads up to its sentinel, so documents are handed over as owned std::strings */
static std::string text_in(payload in) {
    if ((byte(in, 0) & 1) && !text_out.empty()) return text_out;
    return text(rest(in, 1));
}
static std::string bytes_in(payload in) {
    if ((byte(in, 0) & 1) && !bytes_out.empty()) return bytes_out;
    return text(rest(in, 1));
}

/* writers get a variant of the current model whose fields come from the record bytes */
static fuzz_model selected_model(payload in) {
    fuzz_model chosen = model;
    if (!in.n) return chosen;
    chosen.i = byte(in, 0);
    chosen.hello = text(rest(in, 1));
    if (in.n > 1) chosen.arr[0] = byte(in, 1);
    if (in.n > 2) {
        chosen.maybe = text({ in.p + 2, std::min<size_t>(in.n - 2, 24) });  /* up to 24 bytes */
        chosen.alt = (byte(in, 0) & 1)
                        ? std::variant<int, std::string, double>{ text(rest(in, 2)) }
                        : std::variant<int, std::string, double>{ double(byte(in, 2)) / 3.0 };
        chosen.dict["k" + std::to_string(byte(in, 1))] = byte(in, 2);
        chosen.kids.clear();
        const size_t count = std::min<size_t>(in.n - 2, 12);  /* up to 12 children, one per payload byte */
        for (size_t j = 0; j < count; ++j) {
            chosen.kids.push_back({ int(byte(in, j + 2)), "k" + std::to_string(j), { double(byte(in, j + 2)) / 7.0 } });
        }
    }
    return chosen;
}

static glz::generic selected_generic(payload in) {
    glz::generic chosen = generic;
    if (in.n) {
        if (byte(in, 0) & 1) chosen.data = text(rest(in, 1));
        else chosen.data = static_cast<double>(byte(in, 0));
    }
    return chosen;
}

/* JSON text */

static void call_read(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("read")) return;
    const glz::error_ctx ec = glz::read<glz::opts{ .null_terminated = false }>(model, s);
    preqed_result("read", !ec);
    if (!ec) have_model = true;
}

static void call_read_generic(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("read")) return;
    const glz::error_ctx ec = glz::read<glz::opts{ .null_terminated = false }>(generic, s);
    preqed_result("read", !ec);
    if (!ec) have_generic = true;
}

static void call_read_target(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("read")) return;
    const glz::error_ctx ec = glz::read<glz::opts{ .null_terminated = false, .error_on_unknown_keys = false }>(
        target, s);
    preqed_result("read", !ec);
    if (!ec) have_target = true;
}

static void call_read_json(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("read_json")) return;
    const glz::error_ctx ec = glz::read_json(model, s);
    preqed_result("read_json", !ec);
    if (!ec) have_model = true;
    last_error = ec;
    last_input = std::move(s);
}

static void call_read_jsonc(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("read_jsonc")) return;
    const glz::error_ctx ec = glz::read_jsonc(model, s);
    preqed_result("read_jsonc", !ec);
    if (!ec) have_model = true;
}

static void call_write_json(payload in) {
    if (!have_model) return;
    if (!preqed_call("write_json")) return;
    auto r = glz::write_json(selected_model(in));
    preqed_result("write_json", bool(r));
    if (r) text_out = std::move(*r);
}

static void call_write_json_generic(payload) {
    if (!have_generic) return;
    if (!preqed_call("write_json")) return;
    auto r = glz::write_json(generic);
    preqed_result("write_json", bool(r));
    if (r) text_out = std::move(*r);
}

static void call_write_prettify(payload) {
    if (!have_generic) return;
    if (!preqed_call("write")) return;
    std::string out;
    const glz::error_ctx ec = glz::write<glz::opts{ .prettify = true }>(generic, out);
    preqed_result("write", !ec);
    if (!ec) text_out = std::move(out);
}

static void call_minify_json(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("minify_json")) return;
    text_out = glz::minify_json<glz::opts{ .null_terminated = false }>(s);
    preqed_result("minify_json", true);
}

static void call_prettify_json(payload in) {
    const std::string s = text_in(in);
    if (!preqed_call("prettify_json")) return;
    text_out = glz::prettify_json(s);
    preqed_result("prettify_json", true);
}

static void call_validate_json(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("validate_json")) return;
    const glz::error_ctx ec = glz::validate_json(s);
    preqed_result("validate_json", !ec);
}

static void call_validate_jsonc(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("validate_jsonc")) return;
    const glz::error_ctx ec = glz::validate_jsonc(s);
    preqed_result("validate_jsonc", !ec);
}

static void call_validate_utf8(payload in) {
    const std::string s = text_in(in);
    if (!preqed_call("validate_utf8")) return;
    preqed_result("validate_utf8", glz::validate_utf8(s.data(), s.size()));
}

static void call_write_json_schema(payload in) {
    if (!preqed_call("write_json_schema")) return;
    auto r = (byte(in, 0) & 1) ? glz::write_json_schema<fuzz_model>() : glz::write_json_schema<fuzz_child>();
    preqed_result("write_json_schema", bool(r));
    if (r) text_out = std::move(*r);
}

/* YAML, TOML, CSV, NDJSON */

static void call_read_yaml(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("read_yaml")) return;
    const glz::error_ctx ec = glz::read_yaml(generic, s);
    preqed_result("read_yaml", !ec);
    if (!ec) have_generic = true;
}

static void call_read_yaml_model(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("read_yaml")) return;
    const glz::error_ctx ec = glz::read_yaml(model, s);
    preqed_result("read_yaml", !ec);
    if (!ec) have_model = true;
}

static void call_write_yaml(payload in) {
    if (!have_model) return;
    if (!preqed_call("write_yaml")) return;
    auto r = glz::write_yaml(selected_model(in));
    preqed_result("write_yaml", bool(r));
    if (r) text_out = std::move(*r);
}

static void call_write_yaml_generic(payload) {
    if (!have_generic) return;
    if (!preqed_call("write_yaml")) return;
    auto r = glz::write_yaml(generic);
    preqed_result("write_yaml", bool(r));
    if (r) text_out = std::move(*r);
}

static void call_write_yaml_flow(payload in) {
    if (!have_model) return;
    if (!preqed_call("write")) return;
    std::string out;
    const glz::error_ctx ec = glz::write<glz::yaml::yaml_opts{ .flow_style = true }>(selected_model(in), out);
    preqed_result("write", !ec);
    if (!ec) text_out = std::move(out);
}

static void call_read_toml(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("read_toml")) return;
    const glz::error_ctx ec = glz::read_toml(model, s);
    preqed_result("read_toml", !ec);
    if (!ec) have_model = true;
}

static void call_read_toml_generic(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("read_toml")) return;
    const glz::error_ctx ec = glz::read_toml(generic, s);
    preqed_result("read_toml", !ec);
    if (!ec) have_generic = true;
}

static void call_write_toml(payload in) {
    if (!have_model) return;
    if (!preqed_call("write_toml")) return;
    auto r = glz::write_toml(selected_model(in));
    preqed_result("write_toml", bool(r));
    if (r) text_out = std::move(*r);
}

static void call_read_csv_rowwise(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("read_csv")) return;
    const glz::error_ctx ec = glz::read_csv<glz::rowwise>(csv, s);
    preqed_result("read_csv", !ec);
    if (!ec) have_csv = true;
}

static void call_read_csv_colwise(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("read_csv")) return;
    csv_model flat;
    const glz::error_ctx ec = glz::read_csv<glz::colwise>(flat, s);
    preqed_result("read_csv", !ec);
    if (!ec) {
        csv = std::move(flat);
        have_csv = true;
    }
}

static void call_write_csv(payload) {
    if (!have_csv) return;
    if (!preqed_call("write_csv")) return;
    auto r = glz::write_csv<glz::rowwise>(csv);
    preqed_result("write_csv", bool(r));
    if (r) text_out = std::move(*r);
}

static void call_read_ndjson(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("read_ndjson")) return;
    std::vector<fuzz_model> decoded;
    const glz::error_ctx ec = glz::read_ndjson(decoded, s);
    preqed_result("read_ndjson", !ec);
    if (!ec) {
        sequence = std::move(decoded);
        if (!sequence.empty()) {
            model = sequence.front();
            have_model = true;
        }
    }
}

static void call_write_ndjson(payload in) {
    if (!have_model) return;
    if (!preqed_call("write_ndjson")) return;
    const std::vector<fuzz_model> documents{ model, selected_model(in) };
    auto r = glz::write_ndjson(documents);
    preqed_result("write_ndjson", bool(r));
    if (r) text_out = std::move(*r);
}

/* CBOR, MessagePack, JSONB, BSON, BEVE */

static void call_read_cbor(payload in) {
    std::string b = bytes_in(in);
    if (!preqed_call("read_cbor")) return;
    auto r = glz::read_cbor<fuzz_model>(b);
    preqed_result("read_cbor", bool(r));
    if (r) {
        model = std::move(*r);
        have_model = true;
    }
}

static void call_write_cbor(payload in) {
    if (!have_model) return;
    if (!preqed_call("write_cbor")) return;
    auto r = glz::write_cbor(selected_model(in));
    preqed_result("write_cbor", bool(r));
    if (r) bytes_out = std::move(*r);
}

static void call_cbor_to_json(payload in) {
    std::string b = bytes_in(in);
    if (!preqed_call("cbor_to_json")) return;
    std::string out;
    const glz::error_ctx ec = glz::cbor_to_json(b, out);
    preqed_result("cbor_to_json", !ec);
    if (!ec) text_out = std::move(out);
}

static void call_read_cbor_sequence(payload in) {
    std::string b = bytes_in(in);
    if (!preqed_call("read_cbor")) return;
    auto r = glz::read_cbor<std::vector<fuzz_model>>(b);
    preqed_result("read_cbor", bool(r));
    if (r) {
        sequence = std::move(*r);
        if (!sequence.empty()) {
            model = sequence.front();
            have_model = true;
        }
    }
}

static void call_read_msgpack(payload in) {
    std::string b = bytes_in(in);
    if (!preqed_call("read_msgpack")) return;
    auto r = glz::read_msgpack<fuzz_model>(b);
    preqed_result("read_msgpack", bool(r));
    if (r) {
        model = std::move(*r);
        have_model = true;
    }
}

static void call_write_msgpack(payload in) {
    if (!have_model) return;
    if (!preqed_call("write_msgpack")) return;
    auto r = glz::write_msgpack(selected_model(in));
    preqed_result("write_msgpack", bool(r));
    if (r) bytes_out = std::move(*r);
}

static void call_read_msgpack_ext(payload in) {
    std::string b = bytes_in(in);
    if (!preqed_call("read_msgpack")) return;
    auto r = glz::read_msgpack<glz::msgpack::ext>(b);
    preqed_result("read_msgpack", bool(r));
    if (r) bytes_out.assign(reinterpret_cast<const char *>(r->data.data()), r->data.size());
}

static void call_read_msgpack_timestamp(payload in) {
    std::string b = bytes_in(in);
    if (!preqed_call("read_msgpack")) return;
    auto r = glz::read_msgpack<glz::msgpack::timestamp>(b);
    preqed_result("read_msgpack", bool(r));
}

static void call_read_msgpack_sequence(payload in) {
    std::string b = bytes_in(in);
    if (!preqed_call("read_msgpack")) return;
    auto r = glz::read_msgpack<std::vector<fuzz_model>>(b);
    preqed_result("read_msgpack", bool(r));
    if (r) {
        sequence = std::move(*r);
        if (!sequence.empty()) {
            model = sequence.front();
            have_model = true;
        }
    }
}

static void call_read_jsonb(payload in) {
    std::string b = bytes_in(in);
    if (!preqed_call("read_jsonb")) return;
    auto r = glz::read_jsonb<fuzz_model>(b);
    preqed_result("read_jsonb", bool(r));
    if (r) {
        model = std::move(*r);
        have_model = true;
    }
}

static void call_read_jsonb_generic(payload in) {
    std::string b = bytes_in(in);
    if (!preqed_call("read_jsonb")) return;
    auto r = glz::read_jsonb<glz::generic>(b);
    preqed_result("read_jsonb", bool(r));
    if (r) {
        generic = std::move(*r);
        have_generic = true;
    }
}

static void call_write_jsonb(payload in) {
    if (!have_model) return;
    if (!preqed_call("write_jsonb")) return;
    auto r = glz::write_jsonb(selected_model(in));
    preqed_result("write_jsonb", bool(r));
    if (r) bytes_out = std::move(*r);
}

static void call_jsonb_to_json(payload in) {
    std::string b = bytes_in(in);
    if (!preqed_call("jsonb_to_json")) return;
    std::string out;
    const glz::error_ctx ec = glz::jsonb_to_json(b, out);
    preqed_result("jsonb_to_json", !ec);
    if (!ec) text_out = std::move(out);
}

static void call_read_jsonb_sequence(payload in) {
    std::string b = bytes_in(in);
    if (!preqed_call("read_jsonb")) return;
    auto r = glz::read_jsonb<std::vector<fuzz_model>>(b);
    preqed_result("read_jsonb", bool(r));
    if (r) {
        sequence = std::move(*r);
        if (!sequence.empty()) {
            model = sequence.front();
            have_model = true;
        }
    }
}

static void call_read_bson(payload in) {
    std::string b = bytes_in(in);
    if (!preqed_call("read_bson")) return;
    auto r = glz::read_bson<fuzz_model>(b);
    preqed_result("read_bson", bool(r));
    if (r) {
        model = std::move(*r);
        have_model = true;
    }
}

static void call_write_bson(payload in) {
    if (!have_model) return;
    if (!preqed_call("write_bson")) return;
    auto r = glz::write_bson(selected_model(in));
    preqed_result("write_bson", bool(r));
    if (r) bytes_out = std::move(*r);
}

static void call_bson_to_json(payload in) {
    std::string b = bytes_in(in);
    if (!preqed_call("bson_to_json")) return;
    std::string out;
    const glz::error_ctx ec = glz::bson_to_json(b, out);
    preqed_result("bson_to_json", !ec);
    if (!ec) text_out = std::move(out);
}

static void call_read_beve(payload in) {
    std::string b = bytes_in(in);
    if (!preqed_call("read_beve")) return;
    auto r = glz::read_beve<fuzz_model>(b);
    preqed_result("read_beve", bool(r));
    if (r) {
        model = std::move(*r);
        have_model = true;
    }
}

static void call_write_beve(payload in) {
    if (!have_model) return;
    if (!preqed_call("write_beve")) return;
    auto r = glz::write_beve(selected_model(in));
    preqed_result("write_beve", bool(r));
    if (r) bytes_out = std::move(*r);
}

static void call_beve_to_json(payload in) {
    std::string b = bytes_in(in);
    if (!preqed_call("beve_to_json")) return;
    std::string out;
    const glz::error_ctx ec = glz::beve_to_json(b, out);
    preqed_result("beve_to_json", !ec);
    if (!ec) text_out = std::move(out);
}

static void call_read_beve_sequence(payload in) {
    std::string b = bytes_in(in);
    if (!preqed_call("read_beve")) return;
    auto r = glz::read_beve<std::vector<fuzz_model>>(b);
    preqed_result("read_beve", bool(r));
    if (r) {
        sequence = std::move(*r);
        if (!sequence.empty()) {
            model = sequence.front();
            have_model = true;
        }
    }
}

/* base64 */

static void call_read_base64(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("read_base64")) return;
    bytes_out = glz::read_base64(s);
    preqed_result("read_base64", true);
}

static void call_write_base64(payload in) {
    std::string b = bytes_in(in);
    if (!preqed_call("write_base64")) return;
    text_out = glz::write_base64(b);
    preqed_result("write_base64", true);
}

/* JSON pointer, JSON Patch, merge patch */

static void call_read_as_json(payload in) {
    if (!have_model) return;
    std::string s = text_in(in);
    const std::string path = (byte(in, 0) & 1) ? "/i" : "/hello";
    if (!preqed_call("read_as_json")) return;
    preqed_result("read_as_json", glz::read_as_json(model, path, s));
}

static void call_write_as_json(payload in) {
    if (!have_model) return;
    const std::string path = (byte(in, 0) & 1) ? "/i" : "/hello";
    if (!preqed_call("write_as_json")) return;
    std::string out;
    const bool ok = glz::write_as_json(selected_model(in), path, out);
    preqed_result("write_as_json", ok);
    if (ok) text_out = std::move(out);
}

static void call_read_as(payload in) {
    if (!have_model) return;
    std::string b = bytes_in(in);
    const std::string path = (byte(in, 0) & 1) ? "/i" : "/hello";
    if (!preqed_call("read_as")) return;
    const glz::error_ctx ec = glz::read_as<glz::opts{ .format = glz::BEVE }>(model, path, b);
    preqed_result("read_as", !ec);
}

static void call_write_as(payload in) {
    if (!have_model) return;
    const std::string path = (byte(in, 0) & 1) ? "/i" : "/hello";
    if (!preqed_call("write_as")) return;
    std::string out;
    const bool ok = glz::write_as<glz::opts{ .format = glz::BEVE }>(selected_model(in), path, out);
    preqed_result("write_as", ok);
    if (ok) bytes_out = std::move(out);
}

static void call_diff(payload in) {
    if (!have_generic || !have_target) return;
    const glz::diff_opts opts{ .detect_moves = bool(byte(in, 0) & 1),
                               .detect_copies = bool(byte(in, 0) & 2),
                               .array_lcs = bool(byte(in, 0) & 4) };
    if (!preqed_call("diff")) return;
    auto r = glz::diff(generic, target, opts);
    preqed_result("diff", bool(r));
    if (r) {
        patches = std::move(*r);
        have_patch = true;
    }
}

/* two independent documents split out of one record, so the diff input is not a replay of retained state */
static void call_diff_json(payload in) {
    if (in.n < 3) return;
    const size_t split = (size_t(byte(in, 0)) | size_t(byte(in, 1)) << 8) % (in.n - 2);
    std::string a = text({ in.p + 2, split });
    std::string b = text({ in.p + 2 + split, in.n - 2 - split });
    if (!preqed_call("diff")) return;
    auto r = glz::diff(std::string_view(a), std::string_view(b));
    preqed_result("diff", bool(r));
    if (r) {
        patches = std::move(*r);
        have_patch = true;
    }
}

static void call_patch(payload in) {
    if (!have_generic || !have_patch) return;
    const glz::patch_opts opts{ .create_intermediate = bool(byte(in, 0) & 1), .atomic = !(byte(in, 0) & 2) };
    if (!preqed_call("patch")) return;
    const glz::error_ctx ec = glz::patch(generic, patches, opts);
    preqed_result("patch", !ec);
}

/* the record bytes pick the operation type and the two paths; the value is the selected generic */
static void call_patch_op(payload in) {
    if (!have_generic) return;
    const unsigned selector = byte(in, 0);
    glz::patch_document ops;
    glz::patch_op operation{};
    operation.op = static_cast<glz::patch_op_type>(selector % 6);  /* add, remove, replace, move, copy, test */
    /* "/0" addresses an array element, "/hello" the fuzz_model field that typed writes produce */
    operation.path = (selector & 8) ? "/0" : "/hello";
    operation.value = selected_generic(in);
    operation.from = (selector & 16) ? "/0" : "/hello";
    ops.push_back(std::move(operation));
    if (!preqed_call("patch")) return;
    const glz::error_ctx ec = glz::patch(generic, ops,
                                        glz::patch_opts{ .create_intermediate = bool(selector & 32),
                                                         .atomic = bool(selector & 64) });
    preqed_result("patch", !ec);
}

static void call_patch_json(payload in) {
    if (text_out.empty()) return;
    std::string s = text_in(in);
    const glz::patch_opts opts{ .create_intermediate = bool(byte(in, 0) & 1), .atomic = true };
    if (!preqed_call("patch_json")) return;
    auto r = glz::patch_json(std::string_view(text_out), std::string_view(s), opts);
    preqed_result("patch_json", bool(r));
    if (r) text_out = std::move(*r);
}

static void call_merge_diff(payload) {
    if (!have_generic || !have_target) return;
    if (!preqed_call("merge_diff")) return;
    auto r = glz::merge_diff(generic, target);
    preqed_result("merge_diff", bool(r));
    if (r) {
        target = std::move(*r);
        have_target = true;
    }
}

static void call_merge_patch(payload) {
    if (!have_generic || !have_target) return;
    if (!preqed_call("merge_patch")) return;
    const glz::error_ctx ec = glz::merge_patch(generic, target);
    preqed_result("merge_patch", !ec);
}

static void call_merge_patch_json(payload in) {
    if (!have_generic) return;
    std::string s = text_in(in);
    if (!preqed_call("merge_patch")) return;
    const glz::error_ctx ec = glz::merge_patch(generic, std::string_view(s));
    preqed_result("merge_patch", !ec);
}

static void call_merge_patch_model(payload in) {
    if (!have_model) return;
    std::string s = text_in(in);
    if (!preqed_call("merge_patch")) return;
    const glz::error_ctx ec = glz::merge_patch(model, std::string_view(s));
    preqed_result("merge_patch", !ec);
}

/* JMESPath */
/* ltl: jmespath_expression_lifecycle */
static void call_jmespath_expression(payload in) {
    std::string path = text_in(in);
    if (!preqed_call("jmespath_expression::jmespath_expression")) return;
    expression.reset();
    expression_path = std::move(path);
    expression.reset(new glz::jmespath_expression(std::string_view(expression_path)));
    preqed_result("jmespath_expression::jmespath_expression", !bool(expression->error));
}
/* ltl: jmespath_expression_lifecycle */
static void call_read_jmespath(payload in) {
    if (!expression) return;
    std::string s = text_in(in);
    if (!preqed_call("read_jmespath")) return;
    const glz::error_ctx ec = glz::read_jmespath(*expression, model, s);
    preqed_result("read_jmespath", !ec);
    if (!ec) have_model = true;
}

/* numbers */

static void call_from_chars_double(payload in) {
    const std::string s = text_in(in);
    if (!preqed_call("from_chars")) return;
    double number{};
    const auto r = glz::fast_float::from_chars(s.data(), s.data() + s.size(), number);
    preqed_result("from_chars", r.ec == std::errc{});
    if (r.ec == std::errc{}) {
        model.d = number;
        have_model = true;
    }
}

static void call_from_chars_float(payload in) {
    const std::string s = text_in(in);
    if (!preqed_call("from_chars")) return;
    float number{};
    const auto r = glz::fast_float::from_chars(s.data(), s.data() + s.size(), number);
    preqed_result("from_chars", r.ec == std::errc{});
    if (r.ec == std::errc{}) {
        model.d = double(number);
        have_model = true;
    }
}

static void call_atoi_int64(payload in) {
    const std::string s = text_in(in);
    if (!preqed_call("atoi")) return;
    int64_t number{};
    const char *it = s.data();
    const bool ok = glz::atoi(number, it, s.data() + s.size());
    preqed_result("atoi", ok);
    if (ok) {
        model.i = static_cast<int>(number);
        have_model = true;
    }
}

static void call_atoi_uint64(payload in) {
    const std::string s = text_in(in);
    if (!preqed_call("atoi")) return;
    uint64_t number{};
    const char *it = s.data();
    const bool ok = glz::atoi(number, it, s.data() + s.size());
    preqed_result("atoi", ok);
    if (ok) {
        model.arr[0] = number;
        have_model = true;
    }
}

/* record helpers for the APIs below */

/* two strings split out of one record at the 16-bit offset in bytes 0-1 */
static std::pair<std::string, std::string> split(payload in) {
    if (in.n < 3) return {};
    const size_t at = (size_t(byte(in, 0)) | size_t(byte(in, 1)) << 8) % (in.n - 2);
    return { text({ in.p + 2, at }), text({ in.p + 2 + at, in.n - 2 - at }) };
}

static void put_file(const char *path, const std::string &s) {
    FILE *f = fopen(path, "wb");
    if (!f) return;
    fwrite(s.data(), 1, s.size(), f);
    fclose(f);
}

/* file readers: byte 0 bit 1 keeps the file the last write_file_* left, else the record (or the last
   serialization, bit 0) is written to it first */
static void fill_file(payload in, bool binary) {
    if (byte(in, 0) & 2) return;
    put_file(FILE_PATH, binary ? bytes_in(in) : text_in(in));
    have_file = true;
}

/* generic accessors */

static void call_read_wide(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("read")) return;
    const glz::error_ctx ec = glz::read<glz::opts{ .null_terminated = false }>(wide, s);
    preqed_result("read", !ec);
    if (!ec) have_wide = true;
}

/* operator[] descends: an array element (index checked: generic_fwd.hpp:207 indexes the vector unchecked) or an
   object member (inserted as null when missing; a null document becomes an object, generic_fwd.hpp:209-218) */
static void call_generic_operator_index(payload in) {
    if (!have_generic) return;
    if (generic.is_array()) {
        const size_t i = byte(in, 0);
        if (i >= generic.get_array().size()) return;
        if (!preqed_call("generic_json::operator[]")) return;
        glz::generic child = generic[static_cast<size_t>(i)];  /* operator[](std::integral auto&&) needs a prvalue */
        generic = std::move(child);
    } else {
        if (!generic.is_object() && !generic.is_null()) return;  /* std::get<object_t> otherwise */
        const std::string key = text(rest(in, 1));
        if (!preqed_call("generic_json::operator[]")) return;
        glz::generic child = generic[key];
        generic = std::move(child);
    }
    preqed_result("generic_json::operator[]", true);
}

/* at(key) is the object operator[] (generic_fwd.hpp:313); the record sets the member to the second document */
static void call_generic_at(payload in) {
    if (!have_generic || !(generic.is_object() || generic.is_null())) return;
    const std::string key = text(rest(in, 1));
    if (!preqed_call("generic_json::at")) return;
    generic.at(key) = have_target ? target : glz::generic(double(byte(in, 0)));
    preqed_result("generic_json::at", true);
}

static void call_generic_contains(payload in) {
    if (!have_generic) return;
    const std::string key = text(rest(in, 1));
    if (!preqed_call("generic_json::contains")) return;
    preqed_result("generic_json::contains", generic.contains(key));
}

static void call_generic_dump(payload) {
    if (!have_generic) return;
    if (!preqed_call("generic_json::dump")) return;
    auto r = generic.dump();
    preqed_result("generic_json::dump", bool(r));
    if (r) text_out = std::move(*r);
}

static void call_generic_empty(payload) {
    if (!have_generic) return;
    if (!preqed_call("generic_json::empty")) return;
    (void)generic.empty();
    preqed_result("generic_json::empty", true);
}

static void call_generic_size(payload) {
    if (!have_generic) return;
    if (!preqed_call("generic_json::size")) return;
    (void)generic.size();
    preqed_result("generic_json::size", true);
}

static void call_generic_get_if(payload in) {
    if (!have_generic) return;
    if (!preqed_call("generic_json::get_if")) return;
    bool found;
    switch (byte(in, 0) % 3) {
    case 0: {
        const std::string *s = generic.get_if<std::string>();
        found = s != nullptr;
        if (s) text_out = *s;
        break;
    }
    case 1: found = generic.get_if<double>() != nullptr; break;
    default: found = generic.get_if<bool>() != nullptr; break;
    }
    preqed_result("generic_json::get_if", found);
}

/* as<T>() reads the held alternative (generic_fwd.hpp:164-197): only called for the type the value holds.
   as<int>() is static_cast<int>(double) (generic_fwd.hpp:188): only for values that fit in int */
static void call_generic_as(payload) {
    if (!have_generic || !(generic.is_number() || generic.is_string())) return;
    if (generic.is_number()) {
        const double v = generic.get<double>();
        if (!(v > double(std::numeric_limits<int>::min()) - 1.0 && v < double(std::numeric_limits<int>::max()) + 1.0))
            return;
    }
    if (!preqed_call("generic_json::as")) return;
    if (generic.is_number()) model.i = generic.as<int>();
    else model.hello = generic.as<std::string>();
    have_model = true;
    preqed_result("generic_json::as", true);
}

static void call_generic_as_number(payload) {
    if (!have_wide || !wide.is_number()) return;
    if (!preqed_call("generic_json::as_number")) return;
    model.d = wide.as_number();
    have_model = true;
    preqed_result("generic_json::as_number", true);
}

static void call_generic_is_boolean(payload) {
    if (!have_generic) return;
    if (!preqed_call("generic_json::is_boolean")) return;
    (void)generic.is_boolean();
    preqed_result("generic_json::is_boolean", true);
}

static void call_generic_is_number(payload) {
    if (!have_generic) return;
    if (!preqed_call("generic_json::is_number")) return;
    (void)generic.is_number();
    preqed_result("generic_json::is_number", true);
}

static void call_generic_is_string(payload) {
    if (!have_generic) return;
    if (!preqed_call("generic_json::is_string")) return;
    (void)generic.is_string();
    preqed_result("generic_json::is_string", true);
}

static void call_generic_is_double(payload) {
    if (!have_wide) return;
    if (!preqed_call("generic_json::is_double")) return;
    (void)wide.is_double();
    preqed_result("generic_json::is_double", true);
}

static void call_generic_is_int64(payload) {
    if (!have_wide) return;
    if (!preqed_call("generic_json::is_int64")) return;
    (void)wide.is_int64();
    preqed_result("generic_json::is_int64", true);
}

static void call_generic_is_uint64(payload) {
    if (!have_wide) return;
    if (!preqed_call("generic_json::is_uint64")) return;
    (void)wide.is_uint64();
    preqed_result("generic_json::is_uint64", true);
}

static void call_generic_operator_arrow(payload) {
    if (!have_generic) return;
    if (!preqed_call("generic_json::operator->")) return;
    (void)generic->index();
    preqed_result("generic_json::operator->", true);
}

static void call_generic_reset(payload) {
    if (!have_generic) return;
    if (!preqed_call("generic_json::reset")) return;
    generic.reset();
    preqed_result("generic_json::reset", true);
}

static void call_is_object(payload) {
    if (!have_generic) return;
    if (!preqed_call("is_object")) return;
    (void)glz::is_object(generic);
    preqed_result("is_object", true);
}

static void call_is_array(payload) {
    if (!have_generic) return;
    if (!preqed_call("is_array")) return;
    (void)glz::is_array(generic);
    preqed_result("is_array", true);
}

static void call_is_string(payload) {
    if (!have_generic) return;
    if (!preqed_call("is_string")) return;
    (void)glz::is_string(generic);
    preqed_result("is_string", true);
}

static void call_is_number(payload) {
    if (!have_generic) return;
    if (!preqed_call("is_number")) return;
    (void)glz::is_number(generic);
    preqed_result("is_number", true);
}

static void call_is_boolean(payload) {
    if (!have_generic) return;
    if (!preqed_call("is_boolean")) return;
    (void)glz::is_boolean(generic);
    preqed_result("is_boolean", true);
}

static void call_is_null(payload) {
    if (!have_generic) return;
    if (!preqed_call("is_null")) return;
    (void)glz::is_null(generic);
    preqed_result("is_null", true);
}

/* defined for primitives, strings and containers, not reflected structs (generic.hpp:304-498, docs/generic-json.md:240);
   byte 0 bit 0 picks a map of numbers or a vector of strings */
static void call_convert_from_generic(payload in) {
    if (!have_generic) return;
    if (!preqed_call("convert_from_generic")) return;
    glz::error_ctx ec;
    if (byte(in, 0) & 1) {
        std::map<std::string, int> converted;
        ec = glz::convert_from_generic(converted, generic);
        if (!ec) model.dict = std::move(converted);
    } else {
        std::vector<std::string> converted;
        ec = glz::convert_from_generic(converted, generic);
        if (!ec && !converted.empty()) model.hello = converted.front();
    }
    preqed_result("convert_from_generic", !ec);
    if (!ec) have_model = true;
}

/* ordered_small_map: the object of the generic document (generic_fwd.hpp:117 object_t) */

static glz::generic::object_t *generic_object() {
    return have_generic && generic.is_object() ? &generic.get_object() : nullptr;
}

/* at() throws std::out_of_range for a missing key (ordered_small_map.hpp:953-959), so the key is looked up first;
   the member becomes the document */
static void call_ordered_small_map_at(payload in) {
    glz::generic::object_t *o = generic_object();
    if (!o) return;
    const std::string key = text(rest(in, 1));
    if (o->find(key) == o->end()) return;
    if (!preqed_call("ordered_small_map::at")) return;
    glz::generic child = o->at(key);
    generic = std::move(child);
    preqed_result("ordered_small_map::at", true);
}

static void call_ordered_small_map_clear(payload) {
    glz::generic::object_t *o = generic_object();
    if (!o) return;
    if (!preqed_call("ordered_small_map::clear")) return;
    o->clear();
    preqed_result("ordered_small_map::clear", true);
}

static void call_ordered_small_map_contains(payload in) {
    glz::generic::object_t *o = generic_object();
    if (!o) return;
    const std::string key = text(rest(in, 1));
    if (!preqed_call("ordered_small_map::contains")) return;
    preqed_result("ordered_small_map::contains", o->contains(key));
}

static void call_ordered_small_map_insert(payload in) {
    glz::generic::object_t *o = generic_object();
    if (!o) return;
    std::string key = text(rest(in, 1));
    glz::generic value = have_target ? target : glz::generic(double(byte(in, 0)));
    if (!preqed_call("ordered_small_map::insert")) return;
    (void)o->insert({ std::move(key), std::move(value) });
    preqed_result("ordered_small_map::insert", true);
}

static void call_ordered_small_map_insert_or_assign(payload in) {
    glz::generic::object_t *o = generic_object();
    if (!o) return;
    std::string key = text(rest(in, 1));
    glz::generic value = have_target ? target : glz::generic(double(byte(in, 0)));
    if (!preqed_call("ordered_small_map::insert_or_assign")) return;
    (void)o->insert_or_assign(std::move(key), std::move(value));
    preqed_result("ordered_small_map::insert_or_assign", true);
}

static void call_ordered_small_map_reserve(payload in) {
    glz::generic::object_t *o = generic_object();
    if (!o) return;
    if (!preqed_call("ordered_small_map::reserve")) return;
    o->reserve(byte(in, 0));
    preqed_result("ordered_small_map::reserve", true);
}

static void call_ordered_small_map_shrink_to_fit(payload) {
    glz::generic::object_t *o = generic_object();
    if (!o) return;
    if (!preqed_call("ordered_small_map::shrink_to_fit")) return;
    o->shrink_to_fit();
    preqed_result("ordered_small_map::shrink_to_fit", true);
}

/* lazy JSON: a view lives as long as the document and text it came from, so lazy_json replaces all of them */
/* ltl: lazy_json_lifecycle */
static void call_lazy_json(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("lazy_json")) return;
    lazy_index.reset();
    lazy_view.reset();
    lazy_doc.reset();
    lazy_text = std::move(s);
    auto r = glz::lazy_json(lazy_text);
    preqed_result("lazy_json", bool(r));
    if (r) lazy_doc.emplace(std::move(*r));
}
/* ltl: lazy_json_lifecycle */
static void call_lazy_document_root(payload) {
    if (!lazy_doc) return;
    if (!preqed_call("lazy_document::root")) return;
    lazy_view = lazy_doc->root();
    preqed_result("lazy_document::root", true);
}

/* byte 0 bit 0: index byte 1, else the key in the rest of the record */
/* ltl: lazy_json_lifecycle */
static void call_lazy_document_operator_index(payload in) {
    if (!lazy_doc) return;
    const std::string key = text(rest(in, 1));
    if (!preqed_call("lazy_document::operator[]")) return;
    lazy_view = (byte(in, 0) & 1) ? (*lazy_doc)[size_t(byte(in, 1))] : (*lazy_doc)[std::string_view(key)];
    preqed_result("lazy_document::operator[]", !lazy_view->has_error());
}
/* ltl: lazy_json_lifecycle */
static void call_lazy_document_reset_parse_pos(payload) {
    if (!lazy_doc) return;
    if (!preqed_call("lazy_document::reset_parse_pos")) return;
    lazy_doc->reset_parse_pos();
    preqed_result("lazy_document::reset_parse_pos", true);
}
/* ltl: lazy_json_lifecycle */
static void call_lazy_json_view_operator_index(payload in) {
    if (!lazy_view) return;
    const std::string key = text(rest(in, 1));
    if (!preqed_call("lazy_json_view::operator[]")) return;
    glz::lazy_json_view<> child =
        (byte(in, 0) & 1) ? (*lazy_view)[size_t(byte(in, 1))] : (*lazy_view)[std::string_view(key)];
    lazy_view = child;
    preqed_result("lazy_json_view::operator[]", !child.has_error());
}
/* ltl: lazy_json_lifecycle */
static void call_lazy_json_view_get(payload in) {
    if (!lazy_view) return;
    if (!preqed_call("lazy_json_view::get")) return;
    bool ok;
    switch (byte(in, 0) % 5) {
    case 0: {
        auto r = lazy_view->get<std::string>();
        ok = bool(r);
        if (r) text_out = std::move(*r);
        break;
    }
    case 1: {
        auto r = lazy_view->get<std::string_view>();
        ok = bool(r);
        if (r) text_out = std::string(*r);
        break;
    }
    case 2: ok = bool(lazy_view->get<int64_t>()); break;
    case 3: ok = bool(lazy_view->get<double>()); break;
    default: ok = bool(lazy_view->get<bool>()); break;
    }
    preqed_result("lazy_json_view::get", ok);
}
/* ltl: lazy_json_lifecycle */
static void call_lazy_json_view_key(payload) {
    if (!lazy_view) return;
    if (!preqed_call("lazy_json_view::key")) return;
    text_out = std::string(lazy_view->key());
    preqed_result("lazy_json_view::key", true);
}
/* ltl: lazy_json_lifecycle */
static void call_lazy_json_view_index(payload) {
    if (!lazy_view) return;
    if (!preqed_call("lazy_json_view::index")) return;
    lazy_index = lazy_view->index();
    preqed_result("lazy_json_view::index", true);
}
/* ltl: lazy_json_lifecycle */
static void call_lazy_json_view_is_object(payload) {
    if (!lazy_view) return;
    if (!preqed_call("lazy_json_view::is_object")) return;
    (void)lazy_view->is_object();
    preqed_result("lazy_json_view::is_object", true);
}
/* ltl: lazy_json_lifecycle */
static void call_lazy_json_view_is_array(payload) {
    if (!lazy_view) return;
    if (!preqed_call("lazy_json_view::is_array")) return;
    (void)lazy_view->is_array();
    preqed_result("lazy_json_view::is_array", true);
}
/* ltl: lazy_json_lifecycle */
static void call_lazy_json_view_is_string(payload) {
    if (!lazy_view) return;
    if (!preqed_call("lazy_json_view::is_string")) return;
    (void)lazy_view->is_string();
    preqed_result("lazy_json_view::is_string", true);
}
/* ltl: lazy_json_lifecycle */
static void call_lazy_json_view_is_number(payload) {
    if (!lazy_view) return;
    if (!preqed_call("lazy_json_view::is_number")) return;
    (void)lazy_view->is_number();
    preqed_result("lazy_json_view::is_number", true);
}
/* ltl: lazy_json_lifecycle */
static void call_lazy_json_view_is_boolean(payload) {
    if (!lazy_view) return;
    if (!preqed_call("lazy_json_view::is_boolean")) return;
    (void)lazy_view->is_boolean();
    preqed_result("lazy_json_view::is_boolean", true);
}
/* ltl: lazy_json_lifecycle */
static void call_lazy_json_view_is_null(payload) {
    if (!lazy_view) return;
    if (!preqed_call("lazy_json_view::is_null")) return;
    (void)lazy_view->is_null();
    preqed_result("lazy_json_view::is_null", true);
}
/* ltl: lazy_json_lifecycle */
static void call_lazy_json_view_has_error(payload) {
    if (!lazy_view) return;
    if (!preqed_call("lazy_json_view::has_error")) return;
    (void)lazy_view->has_error();
    preqed_result("lazy_json_view::has_error", true);
}
/* ltl: lazy_json_lifecycle */
static void call_lazy_json_view_error(payload) {
    if (!lazy_view) return;
    if (!preqed_call("lazy_json_view::error")) return;
    preqed_result("lazy_json_view::error", lazy_view->error() == glz::error_code::none);  /* ok = the view holds no error */
}
/* ltl: lazy_json_lifecycle */
static void call_lazy_json_view_empty(payload) {
    if (!lazy_view) return;
    if (!preqed_call("lazy_json_view::empty")) return;
    (void)lazy_view->empty();
    preqed_result("lazy_json_view::empty", true);
}
/* ltl: lazy_json_lifecycle */
static void call_lazy_json_view_size(payload) {
    if (!lazy_view) return;
    if (!preqed_call("lazy_json_view::size")) return;
    (void)lazy_view->size();
    preqed_result("lazy_json_view::size", true);
}
/* ltl: lazy_json_lifecycle */
static void call_lazy_json_view_contains(payload in) {
    if (!lazy_view) return;
    const std::string key = text(rest(in, 1));
    if (!preqed_call("lazy_json_view::contains")) return;
    preqed_result("lazy_json_view::contains", lazy_view->contains(key));
}
/* ltl: lazy_json_lifecycle */
static void call_lazy_json_view_read_into(payload) {
    if (!lazy_view) return;
    if (!preqed_call("lazy_json_view::read_into")) return;
    const glz::error_ctx ec = lazy_view->read_into(model);
    preqed_result("lazy_json_view::read_into", !ec);
    if (!ec) have_model = true;
}
/* ltl: lazy_json_lifecycle */
static void call_lazy_json_view_raw_json(payload) {
    if (!lazy_view) return;
    if (!preqed_call("lazy_json_view::raw_json")) return;
    text_out = std::string(lazy_view->raw_json());
    preqed_result("lazy_json_view::raw_json", true);
}

/* begin: the view descends to the first element or member */
/* ltl: lazy_json_lifecycle */
static void call_lazy_json_view_begin(payload) {
    if (!lazy_view) return;
    if (!preqed_call("lazy_json_view::begin")) return;
    auto it = lazy_view->begin();
    const bool any = it != lazy_view->end();
    if (any) lazy_view = glz::lazy_json_view<>(*it);
    preqed_result("lazy_json_view::begin", any);
}

/* end: a full range-for over the elements or members */
/* ltl: lazy_json_lifecycle */
static void call_lazy_json_view_end(payload) {
    if (!lazy_view) return;
    if (!preqed_call("lazy_json_view::end")) return;
    size_t errors = 0;
    for (auto it = lazy_view->begin(); it != lazy_view->end(); ++it) errors += (*it).has_error();
    preqed_result("lazy_json_view::end", errors == 0);
}
/* ltl: lazy_json_lifecycle */
static void call_indexed_lazy_view_size(payload) {
    if (!lazy_index) return;
    if (!preqed_call("indexed_lazy_view::size")) return;
    (void)lazy_index->size();
    preqed_result("indexed_lazy_view::size", true);
}
/* ltl: lazy_json_lifecycle */
static void call_indexed_lazy_view_empty(payload) {
    if (!lazy_index) return;
    if (!preqed_call("indexed_lazy_view::empty")) return;
    (void)lazy_index->empty();
    preqed_result("indexed_lazy_view::empty", true);
}
/* ltl: lazy_json_lifecycle */
static void call_indexed_lazy_view_contains(payload in) {
    if (!lazy_index) return;
    const std::string key = text(rest(in, 1));
    if (!preqed_call("indexed_lazy_view::contains")) return;
    preqed_result("indexed_lazy_view::contains", lazy_index->contains(key));
}
/* ltl: lazy_json_lifecycle */
static void call_indexed_lazy_view_operator_index(payload in) {
    if (!lazy_index) return;
    const std::string key = text(rest(in, 1));
    if (!preqed_call("indexed_lazy_view::operator[]")) return;
    lazy_view = (byte(in, 0) & 1) ? (*lazy_index)[size_t(byte(in, 1))] : (*lazy_index)[std::string_view(key)];
    preqed_result("indexed_lazy_view::operator[]", !lazy_view->has_error());
}
/* ltl: lazy_json_lifecycle */
static void call_indexed_lazy_view_begin(payload) {
    if (!lazy_index) return;
    if (!preqed_call("indexed_lazy_view::begin")) return;
    auto it = lazy_index->begin();
    const bool any = it != lazy_index->end();
    if (any) lazy_view = glz::lazy_json_view<>(*it);
    preqed_result("indexed_lazy_view::begin", any);
}
/* ltl: lazy_json_lifecycle */
static void call_indexed_lazy_view_end(payload) {
    if (!lazy_index) return;
    if (!preqed_call("indexed_lazy_view::end")) return;
    size_t errors = 0;
    for (auto it = lazy_index->begin(); it != lazy_index->end(); ++it) errors += (*it).has_error();
    preqed_result("indexed_lazy_view::end", errors == 0);
}

/* lazy BEVE: same ownership as lazy JSON */
/* ltl: lazy_beve_lifecycle */
static void call_lazy_beve(payload in) {
    std::string b = bytes_in(in);
    if (!preqed_call("lazy_beve")) return;
    beve_index.reset();
    beve_view.reset();
    beve_doc.reset();
    beve_text = std::move(b);
    auto r = glz::lazy_beve(beve_text);
    preqed_result("lazy_beve", bool(r));
    if (r) beve_doc.emplace(std::move(*r));
}
/* ltl: lazy_beve_lifecycle */
static void call_lazy_beve_document_root(payload) {
    if (!beve_doc) return;
    if (!preqed_call("lazy_beve_document::root")) return;
    beve_view = beve_doc->root();
    preqed_result("lazy_beve_document::root", true);
}
/* ltl: lazy_beve_lifecycle */
static void call_lazy_beve_document_operator_index(payload in) {
    if (!beve_doc) return;
    const std::string key = text(rest(in, 1));
    if (!preqed_call("lazy_beve_document::operator[]")) return;
    beve_view = (byte(in, 0) & 1) ? (*beve_doc)[size_t(byte(in, 1))] : (*beve_doc)[std::string_view(key)];
    preqed_result("lazy_beve_document::operator[]", !beve_view->has_error());
}
/* ltl: lazy_beve_lifecycle */
static void call_lazy_beve_document_reset_parse_pos(payload) {
    if (!beve_doc) return;
    if (!preqed_call("lazy_beve_document::reset_parse_pos")) return;
    beve_doc->reset_parse_pos();
    preqed_result("lazy_beve_document::reset_parse_pos", true);
}
/* ltl: lazy_beve_lifecycle */
static void call_lazy_beve_view_operator_index(payload in) {
    if (!beve_view) return;
    const std::string key = text(rest(in, 1));
    if (!preqed_call("lazy_beve_view::operator[]")) return;
    glz::lazy_beve_view<> child =
        (byte(in, 0) & 1) ? (*beve_view)[size_t(byte(in, 1))] : (*beve_view)[std::string_view(key)];
    beve_view = child;
    preqed_result("lazy_beve_view::operator[]", !child.has_error());
}
/* ltl: lazy_beve_lifecycle */
static void call_lazy_beve_view_get(payload in) {
    if (!beve_view) return;
    if (!preqed_call("lazy_beve_view::get")) return;
    bool ok;
    switch (byte(in, 0) % 5) {
    case 0: {
        auto r = beve_view->get<std::string>();
        ok = bool(r);
        if (r) text_out = std::move(*r);
        break;
    }
    case 1: {
        auto r = beve_view->get<std::string_view>();
        ok = bool(r);
        if (r) text_out = std::string(*r);
        break;
    }
    case 2: ok = bool(beve_view->get<int64_t>()); break;
    case 3: ok = bool(beve_view->get<double>()); break;
    default: ok = bool(beve_view->get<bool>()); break;
    }
    preqed_result("lazy_beve_view::get", ok);
}
/* ltl: lazy_beve_lifecycle */
static void call_lazy_beve_view_key(payload) {
    if (!beve_view) return;
    if (!preqed_call("lazy_beve_view::key")) return;
    text_out = std::string(beve_view->key());
    preqed_result("lazy_beve_view::key", true);
}
/* ltl: lazy_beve_lifecycle */
static void call_lazy_beve_view_index(payload) {
    if (!beve_view) return;
    if (!preqed_call("lazy_beve_view::index")) return;
    beve_index = beve_view->index();
    preqed_result("lazy_beve_view::index", true);
}
/* ltl: lazy_beve_lifecycle */
static void call_lazy_beve_view_is_object(payload) {
    if (!beve_view) return;
    if (!preqed_call("lazy_beve_view::is_object")) return;
    (void)beve_view->is_object();
    preqed_result("lazy_beve_view::is_object", true);
}
/* ltl: lazy_beve_lifecycle */
static void call_lazy_beve_view_is_array(payload) {
    if (!beve_view) return;
    if (!preqed_call("lazy_beve_view::is_array")) return;
    (void)beve_view->is_array();
    preqed_result("lazy_beve_view::is_array", true);
}
/* ltl: lazy_beve_lifecycle */
static void call_lazy_beve_view_is_typed_array(payload) {
    if (!beve_view) return;
    if (!preqed_call("lazy_beve_view::is_typed_array")) return;
    (void)beve_view->is_typed_array();
    preqed_result("lazy_beve_view::is_typed_array", true);
}
/* ltl: lazy_beve_lifecycle */
static void call_lazy_beve_view_is_generic_array(payload) {
    if (!beve_view) return;
    if (!preqed_call("lazy_beve_view::is_generic_array")) return;
    (void)beve_view->is_generic_array();
    preqed_result("lazy_beve_view::is_generic_array", true);
}
/* ltl: lazy_beve_lifecycle */
static void call_lazy_beve_view_is_string(payload) {
    if (!beve_view) return;
    if (!preqed_call("lazy_beve_view::is_string")) return;
    (void)beve_view->is_string();
    preqed_result("lazy_beve_view::is_string", true);
}
/* ltl: lazy_beve_lifecycle */
static void call_lazy_beve_view_is_number(payload) {
    if (!beve_view) return;
    if (!preqed_call("lazy_beve_view::is_number")) return;
    (void)beve_view->is_number();
    preqed_result("lazy_beve_view::is_number", true);
}
/* ltl: lazy_beve_lifecycle */
static void call_lazy_beve_view_is_boolean(payload) {
    if (!beve_view) return;
    if (!preqed_call("lazy_beve_view::is_boolean")) return;
    (void)beve_view->is_boolean();
    preqed_result("lazy_beve_view::is_boolean", true);
}
/* ltl: lazy_beve_lifecycle */
static void call_lazy_beve_view_is_null(payload) {
    if (!beve_view) return;
    if (!preqed_call("lazy_beve_view::is_null")) return;
    (void)beve_view->is_null();
    preqed_result("lazy_beve_view::is_null", true);
}
/* ltl: lazy_beve_lifecycle */
static void call_lazy_beve_view_has_error(payload) {
    if (!beve_view) return;
    if (!preqed_call("lazy_beve_view::has_error")) return;
    (void)beve_view->has_error();
    preqed_result("lazy_beve_view::has_error", true);
}
/* ltl: lazy_beve_lifecycle */
static void call_lazy_beve_view_error(payload) {
    if (!beve_view) return;
    if (!preqed_call("lazy_beve_view::error")) return;
    preqed_result("lazy_beve_view::error", beve_view->error() == glz::error_code::none);  /* ok = the view holds no error */
}
/* ltl: lazy_beve_lifecycle */
static void call_lazy_beve_view_empty(payload) {
    if (!beve_view) return;
    if (!preqed_call("lazy_beve_view::empty")) return;
    (void)beve_view->empty();
    preqed_result("lazy_beve_view::empty", true);
}
/* ltl: lazy_beve_lifecycle */
static void call_lazy_beve_view_size(payload) {
    if (!beve_view) return;
    if (!preqed_call("lazy_beve_view::size")) return;
    (void)beve_view->size();
    preqed_result("lazy_beve_view::size", true);
}
/* ltl: lazy_beve_lifecycle */
static void call_lazy_beve_view_contains(payload in) {
    if (!beve_view) return;
    const std::string key = text(rest(in, 1));
    if (!preqed_call("lazy_beve_view::contains")) return;
    preqed_result("lazy_beve_view::contains", beve_view->contains(key));
}
/* ltl: lazy_beve_lifecycle */
static void call_lazy_beve_view_read_into(payload) {
    if (!beve_view) return;
    if (!preqed_call("lazy_beve_view::read_into")) return;
    const glz::error_ctx ec = beve_view->read_into(model);
    preqed_result("lazy_beve_view::read_into", !ec);
    if (!ec) have_model = true;
}
/* ltl: lazy_beve_lifecycle */
static void call_lazy_beve_view_raw_beve(payload) {
    if (!beve_view) return;
    if (!preqed_call("lazy_beve_view::raw_beve")) return;
    bytes_out = std::string(beve_view->raw_beve());
    preqed_result("lazy_beve_view::raw_beve", true);
}
/* ltl: lazy_beve_lifecycle */
static void call_lazy_beve_view_begin(payload) {
    if (!beve_view) return;
    if (!preqed_call("lazy_beve_view::begin")) return;
    auto it = beve_view->begin();
    const bool any = it != beve_view->end();
    if (any) beve_view = glz::lazy_beve_view<>(*it);
    preqed_result("lazy_beve_view::begin", any);
}
/* ltl: lazy_beve_lifecycle */
static void call_lazy_beve_view_end(payload) {
    if (!beve_view) return;
    if (!preqed_call("lazy_beve_view::end")) return;
    size_t errors = 0;
    for (auto it = beve_view->begin(); it != beve_view->end(); ++it) errors += (*it).has_error();
    preqed_result("lazy_beve_view::end", errors == 0);
}
/* ltl: lazy_beve_lifecycle */
static void call_indexed_lazy_beve_view_size(payload) {
    if (!beve_index) return;
    if (!preqed_call("indexed_lazy_beve_view::size")) return;
    (void)beve_index->size();
    preqed_result("indexed_lazy_beve_view::size", true);
}
/* ltl: lazy_beve_lifecycle */
static void call_indexed_lazy_beve_view_empty(payload) {
    if (!beve_index) return;
    if (!preqed_call("indexed_lazy_beve_view::empty")) return;
    (void)beve_index->empty();
    preqed_result("indexed_lazy_beve_view::empty", true);
}
/* ltl: lazy_beve_lifecycle */
static void call_indexed_lazy_beve_view_contains(payload in) {
    if (!beve_index) return;
    const std::string key = text(rest(in, 1));
    if (!preqed_call("indexed_lazy_beve_view::contains")) return;
    preqed_result("indexed_lazy_beve_view::contains", beve_index->contains(key));
}
/* ltl: lazy_beve_lifecycle */
static void call_indexed_lazy_beve_view_operator_index(payload in) {
    if (!beve_index) return;
    const std::string key = text(rest(in, 1));
    if (!preqed_call("indexed_lazy_beve_view::operator[]")) return;
    beve_view = (byte(in, 0) & 1) ? (*beve_index)[size_t(byte(in, 1))] : (*beve_index)[std::string_view(key)];
    preqed_result("indexed_lazy_beve_view::operator[]", !beve_view->has_error());
}
/* ltl: lazy_beve_lifecycle */
static void call_indexed_lazy_beve_view_begin(payload) {
    if (!beve_index) return;
    if (!preqed_call("indexed_lazy_beve_view::begin")) return;
    auto it = beve_index->begin();
    const bool any = it != beve_index->end();
    if (any) beve_view = glz::lazy_beve_view<>(*it);
    preqed_result("indexed_lazy_beve_view::begin", any);
}
/* ltl: lazy_beve_lifecycle */
static void call_indexed_lazy_beve_view_end(payload) {
    if (!beve_index) return;
    if (!preqed_call("indexed_lazy_beve_view::end")) return;
    size_t errors = 0;
    for (auto it = beve_index->begin(); it != beve_index->end(); ++it) errors += (*it).has_error();
    preqed_result("indexed_lazy_beve_view::end", errors == 0);
}

/* streams */
/* ltl: json_stream_reader_lifecycle */
static void call_json_stream_reader(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("json_stream_reader::json_stream_reader")) return;
    stream_reader.reset();
    stream_in.reset(new std::istringstream(std::move(s)));
    stream_reader.reset(new glz::json_stream_reader<fuzz_model, std::istringstream>(*stream_in));
    preqed_result("json_stream_reader::json_stream_reader", true);
}
/* ltl: json_stream_reader_lifecycle */
static void call_json_stream_reader_read_next(payload) {
    if (!stream_reader) return;
    if (!preqed_call("json_stream_reader::read_next")) return;
    fuzz_model value;
    const glz::error_ctx ec = stream_reader->read_next(value);
    preqed_result("json_stream_reader::read_next", !ec);
    if (!ec) {
        model = std::move(value);
        have_model = true;
    }
}

/* begin reads the next value (json_stream.hpp:151, iterator constructor) */
/* ltl: json_stream_reader_lifecycle */
static void call_json_stream_reader_begin(payload) {
    if (!stream_reader) return;
    if (!preqed_call("json_stream_reader::begin")) return;
    auto it = stream_reader->begin();
    const bool any = it != stream_reader->end();
    if (any) {
        model = *it;
        have_model = true;
    }
    preqed_result("json_stream_reader::begin", any);
}

/* end: a range-for over the remaining values */
/* ltl: json_stream_reader_lifecycle */
static void call_json_stream_reader_end(payload) {
    if (!stream_reader) return;
    if (!preqed_call("json_stream_reader::end")) return;
    std::vector<fuzz_model> decoded;
    for (auto it = stream_reader->begin(); it != stream_reader->end(); ++it) decoded.push_back(*it);
    preqed_result("json_stream_reader::end", true);
    if (!decoded.empty()) {
        sequence = std::move(decoded);
        model = sequence.front();
        have_model = true;
    }
}

static void call_read_json_stream(payload in) {
    std::istringstream stream(text_in(in));
    std::vector<fuzz_model> decoded;
    if (!preqed_call("read_json_stream")) return;
    const glz::error_ctx ec = glz::read_json_stream(decoded, stream);
    preqed_result("read_json_stream", !ec);
    if (!ec && !decoded.empty()) {
        sequence = std::move(decoded);
        model = sequence.front();
        have_model = true;
    }
}

static void call_basic_istream_buffer(payload in) {
    std::istringstream stream(text_in(in));
    if (!preqed_call("basic_istream_buffer::basic_istream_buffer")) return;
    glz::basic_istream_buffer<std::istringstream> buffer(stream);
    const glz::error_ctx ec = glz::read_json(model, buffer);
    preqed_result("basic_istream_buffer::basic_istream_buffer", !ec);
    if (!ec) have_model = true;
}

static void call_basic_ostream_buffer(payload in) {
    if (!have_model) return;
    std::ostringstream stream;
    if (!preqed_call("basic_ostream_buffer::basic_ostream_buffer")) return;
    glz::basic_ostream_buffer<std::ostringstream> buffer(stream);
    const glz::error_ctx ec = glz::write_json(selected_model(in), buffer);
    preqed_result("basic_ostream_buffer::basic_ostream_buffer", !ec && stream.good());
    if (!ec) text_out = stream.str();
}

/* JSON pointer on text and on reflected values */

/* byte 0 bit 1 picks the path: "/i" (an int) or "/hello" (a string) */
static void call_get_as_json(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("get_as_json")) return;
    bool ok;
    if (byte(in, 0) & 2) {
        auto r = glz::get_as_json<int, "/i">(s);
        ok = bool(r);
        if (r) model.i = *r;
    } else {
        auto r = glz::get_as_json<std::string, "/hello">(s);
        ok = bool(r);
        if (r) model.hello = std::move(*r);
    }
    preqed_result("get_as_json", ok);
}

static void call_get_sv_json(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("get_sv_json")) return;
    auto r = glz::get_sv_json<"/kids/0/label">(s);
    preqed_result("get_sv_json", bool(r));
    if (r) text_out = std::string(*r);
}

static void call_get_view_json(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("get_view_json")) return;
    auto r = glz::get_view_json<"/dict">(s);
    preqed_result("get_view_json", bool(r));
    if (r) text_out = std::string(r->data(), r->size());
}

/* runtime pointer: the first part of the record is the pointer, the second the document */
static void call_get_view_json_runtime(payload in) {
    auto [ptr, doc] = split(in);
    if (!preqed_call("get_view_json")) return;
    auto r = glz::get_view_json(ptr, doc);
    preqed_result("get_view_json", bool(r));
    if (r) text_out = std::string(r->data(), r->size());
}

/* the first part of the record is the raw value, the second the document */
static void call_write_at(payload in) {
    auto [value, doc] = split(in);
    /* Skip out-of-buffer views returned for malformed JSON. */
    if (auto v = glz::get_view_json<"/hello">(doc); v && (v->data() < doc.data() || v->data() + v->size() > doc.data() + doc.size()))
        return;
    if (!preqed_call("write_at")) return;
    const glz::error_ctx ec = glz::write_at<"/hello">(value, doc);
    preqed_result("write_at", !ec);
    if (!ec) text_out = std::move(doc);
}

/* the first part is the pointer, the second the document; byte 2 is written as a number */
static void call_write_at_runtime(payload in) {
    auto [ptr, doc] = split(in);
    const std::string value = std::to_string(byte(in, 2));
    if (!preqed_call("write_at")) return;
    const glz::error_ctx ec = glz::write_at(ptr, value, doc);
    preqed_result("write_at", !ec);
    if (!ec) text_out = std::move(doc);
}

/* the rest of the record is the pointer; byte 0 bit 0 picks the value type (int for /i, string for /hello) */
static void call_get(payload in) {
    if (!have_model) return;
    const std::string ptr = text(rest(in, 1));
    if (!preqed_call("get")) return;
    bool ok;
    if (byte(in, 0) & 1) {
        auto r = glz::get<int>(model, ptr);
        ok = bool(r);
        if (r) r->get() = byte(in, 0);
    } else {
        auto r = glz::get<std::string>(model, ptr);
        ok = bool(r);
        if (r) text_out = r->get();
    }
    preqed_result("get", ok);
}

static void call_get_if(payload in) {
    if (!have_model) return;
    const std::string ptr = text(rest(in, 1));
    if (!preqed_call("get_if")) return;
    double *p = glz::get_if<double>(model, ptr);
    preqed_result("get_if", p != nullptr);
    if (p) *p = byte(in, 0);
}

static void call_get_value(payload in) {
    if (!have_model) return;
    const std::string ptr = text(rest(in, 1));
    if (!preqed_call("get_value")) return;
    auto r = glz::get_value<uint64_t>(model, ptr);
    preqed_result("get_value", bool(r));
}

static void call_set(payload in) {
    if (!have_model) return;
    const std::string ptr = text(rest(in, 1));
    if (!preqed_call("set")) return;
    const bool ok = (byte(in, 0) & 1) ? glz::set(model, ptr, int(byte(in, 0))) : glz::set(model, ptr, ptr);
    preqed_result("set", ok);
}

/* partial writes */

/* keys: the rest of the record split at ',' */
static std::vector<std::string> keys_of(payload in) {
    std::vector<std::string> keys;
    std::string s = text(rest(in, 1));
    size_t start = 0;
    for (size_t comma; (comma = s.find(',', start)) != std::string::npos; start = comma + 1)
        keys.push_back(s.substr(start, comma - start));
    keys.push_back(s.substr(start));
    return keys;
}

static void call_write_json_partial(payload in) {
    if (!have_model) return;
    const std::vector<std::string> keys = keys_of(in);
    if (!preqed_call("write_json_partial")) return;
    std::string out;
    const glz::error_ctx ec = glz::write_json_partial(model, keys, out);
    preqed_result("write_json_partial", !ec);
    if (!ec) text_out = std::move(out);
}

static void call_write_json_exclude(payload in) {
    if (!have_model) return;
    const std::vector<std::string> keys = keys_of(in);
    if (!preqed_call("write_json_exclude")) return;
    std::string out;
    const glz::error_ctx ec = glz::write_json_exclude(model, keys, out);
    preqed_result("write_json_exclude", !ec);
    if (!ec) text_out = std::move(out);
}

static constexpr auto partial_ptrs = glz::json_ptrs("/i", "/hello", "/dict", "/kids");

static void call_json_ptrs(payload in) {
    if (!have_model) return;
    if (!preqed_call("json_ptrs")) return;
    std::string out;
    const glz::error_ctx ec = glz::write_json<partial_ptrs>(selected_model(in), out);
    preqed_result("json_ptrs", !ec);
    if (!ec) text_out = std::move(out);
}

/* patch and merge-patch value variants */

static void call_patched(payload) {
    if (!have_generic || !have_patch) return;
    if (!preqed_call("patched")) return;
    auto r = glz::patched(generic, patches);
    preqed_result("patched", bool(r));
    if (r) {
        target = std::move(*r);
        have_target = true;
    }
}

static void call_merge_patched(payload) {
    if (!have_generic || !have_target) return;
    if (!preqed_call("merge_patched")) return;
    auto r = glz::merge_patched(generic, target);
    preqed_result("merge_patched", bool(r));
    if (r) target = std::move(*r);
}

static void call_merge_patch_json_text(payload in) {
    if (text_out.empty()) return;
    std::string s = text_in(in);
    if (!preqed_call("merge_patch_json")) return;
    auto r = glz::merge_patch_json(std::string_view(text_out), std::string_view(s));
    preqed_result("merge_patch_json", bool(r));
    if (r) text_out = std::move(*r);
}

static void call_merge_diff_json(payload in) {
    auto [a, b] = split(in);
    if (!preqed_call("merge_diff_json")) return;
    auto r = glz::merge_diff_json(std::string_view(a), std::string_view(b));
    preqed_result("merge_diff_json", bool(r));
    if (r) text_out = std::move(*r);
}

/* errors */

static void call_format_error(payload) {
    if (!last_error) return;
    if (!preqed_call("format_error")) return;
    text_out = glz::format_error(last_error, last_input);
    preqed_result("format_error", !text_out.empty());
}

/* reflection helpers, meta wrappers */

static void call_for_each_field(payload) {
    if (!have_model) return;
    if (!preqed_call("for_each_field")) return;
    size_t fields = 0;
    glz::for_each_field(model, [&](auto &) { ++fields; });
    preqed_result("for_each_field", fields == 8);  /* fuzz_model has 8 members */
}

static void call_object(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("object")) return;
    fuzz_record record;
    const glz::error_ctx ec = glz::read_json(record, s);
    preqed_result("object", !ec);
    if (!ec) {
        auto r = glz::write_json(record);
        if (r) text_out = std::move(*r);
    }
}

static void call_array(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("array")) return;
    fuzz_point point;
    const glz::error_ctx ec = glz::read_json(point, s);
    preqed_result("array", !ec);
    if (!ec) {
        auto r = glz::write_json(point);
        if (r) text_out = std::move(*r);
    }
}

static void call_flags(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("flags")) return;
    fuzz_perms perms;
    const glz::error_ctx ec = glz::read_json(perms, s);
    preqed_result("flags", !ec);
    if (!ec) {
        auto r = glz::write_json(perms);
        if (r) text_out = std::move(*r);
    }
}

static void call_date_format(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("date_format")) return;
    fuzz_dated dated;
    const glz::error_ctx ec = glz::read_json(dated, s);
    preqed_result("date_format", !ec);
    if (!ec) {
        auto r = glz::write_json(dated);
        if (r) text_out = std::move(*r);
    }
}

static void call_epoch_count(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("epoch_count")) return;
    fuzz_counted counted;
    const glz::error_ctx ec = glz::read_json(counted, s);
    preqed_result("epoch_count", !ec);
    if (!ec) {
        auto r = glz::write_json(counted);
        if (r) text_out = std::move(*r);
    }
}

/* the record's first 8 bytes are a millisecond count */
static std::chrono::system_clock::time_point time_of(payload in) {
    int64_t ms = 0;
    for (size_t i = 0; i < 8 && i < in.n; ++i) ms |= int64_t(in.p[i]) << (8 * i);
    /* the clock counts nanoseconds: |ms| < 2^42 keeps ms * 10^6 below 2^63 */
    return std::chrono::system_clock::time_point(std::chrono::milliseconds(ms % (int64_t(1) << 42)));
}

static void call_epoch_time(payload in) {
    const auto tp = time_of(in);
    if (!preqed_call("epoch_time::epoch_time")) return;
    stamp = glz::epoch_time<std::chrono::milliseconds>(tp);
    preqed_result("epoch_time::epoch_time", true);
}

static void call_epoch_time_operator_time_point(payload) {
    if (!preqed_call("epoch_time::operator time_point")) return;
    const std::chrono::system_clock::time_point tp = stamp;
    preqed_result("epoch_time::operator time_point", tp == stamp.value);
}

static void call_epoch_time_operator_eq(payload in) {
    const glz::epoch_time<std::chrono::milliseconds> other(time_of(in));
    if (!preqed_call("epoch_time::operator==")) return;
    (void)(stamp == other);
    preqed_result("epoch_time::operator==", true);
}

static void call_epoch_time_operator_cmp(payload in) {
    const glz::epoch_time<std::chrono::milliseconds> other(time_of(in));
    if (!preqed_call("epoch_time::operator<=>")) return;
    (void)(stamp <=> other);
    preqed_result("epoch_time::operator<=>", true);
}

static void call_toml_opts(payload in) {
    if (!have_model) return;
    if (!preqed_call("toml_opts::toml_opts")) return;
    std::string out;
    const glz::error_ctx ec = (byte(in, 0) & 1) ? glz::write<glz::toml_opts{ true }>(selected_model(in), out)
                                                 : glz::write<glz::toml_opts{}>(selected_model(in), out);
    preqed_result("toml_opts::toml_opts", !ec);
    if (!ec) text_out = std::move(out);
}

/* templating: the record is the layout */

static void call_stencil(payload in) {
    if (!have_model) return;
    const std::string layout = text(rest(in, 1));
    if (!preqed_call("stencil")) return;
    auto r = glz::stencil(layout, model);
    preqed_result("stencil", bool(r));
    if (r) text_out = std::move(*r);
}

static void call_mustache(payload in) {
    if (!have_model) return;
    const std::string layout = text(rest(in, 1));
    if (!preqed_call("mustache")) return;
    auto r = glz::mustache(layout, model);
    preqed_result("mustache", bool(r));
    if (r) text_out = std::move(*r);
}

/* key transformers: the record is the key */

static void call_to_camel_case(payload in) {
    const std::string s = text_in(in);
    if (!preqed_call("to_camel_case")) return;
    text_out = glz::to_camel_case(s);
    preqed_result("to_camel_case", true);
}

static void call_to_snake_case(payload in) {
    const std::string s = text_in(in);
    if (!preqed_call("to_snake_case")) return;
    text_out = glz::to_snake_case(s);
    preqed_result("to_snake_case", true);
}

static void call_to_kebab_case(payload in) {
    const std::string s = text_in(in);
    if (!preqed_call("to_kebab_case")) return;
    text_out = glz::to_kebab_case(s);
    preqed_result("to_kebab_case", true);
}

static void call_camel_case_rename_key(payload in) {
    const std::string s = text_in(in);
    if (!preqed_call("camel_case::rename_key")) return;
    text_out = glz::camel_case::rename_key(std::string_view(s));
    preqed_result("camel_case::rename_key", true);
}

static void call_pascal_case_rename_key(payload in) {
    const std::string s = text_in(in);
    if (!preqed_call("pascal_case::rename_key")) return;
    text_out = glz::pascal_case::rename_key(std::string_view(s));
    preqed_result("pascal_case::rename_key", true);
}

static void call_snake_case_rename_key(payload in) {
    const std::string s = text_in(in);
    if (!preqed_call("snake_case::rename_key")) return;
    text_out = glz::snake_case::rename_key(std::string_view(s));
    preqed_result("snake_case::rename_key", true);
}

static void call_screaming_snake_case_rename_key(payload in) {
    const std::string s = text_in(in);
    if (!preqed_call("screaming_snake_case::rename_key")) return;
    text_out = glz::screaming_snake_case::rename_key(std::string_view(s));
    preqed_result("screaming_snake_case::rename_key", true);
}

static void call_kebab_case_rename_key(payload in) {
    const std::string s = text_in(in);
    if (!preqed_call("kebab_case::rename_key")) return;
    text_out = glz::kebab_case::rename_key(std::string_view(s));
    preqed_result("kebab_case::rename_key", true);
}

static void call_screaming_kebab_case_rename_key(payload in) {
    const std::string s = text_in(in);
    if (!preqed_call("screaming_kebab_case::rename_key")) return;
    text_out = glz::screaming_kebab_case::rename_key(std::string_view(s));
    preqed_result("screaming_kebab_case::rename_key", true);
}

static void call_lower_case_rename_key(payload in) {
    const std::string s = text_in(in);
    if (!preqed_call("lower_case::rename_key")) return;
    text_out = glz::lower_case::rename_key(std::string_view(s));
    preqed_result("lower_case::rename_key", true);
}

static void call_upper_case_rename_key(payload in) {
    const std::string s = text_in(in);
    if (!preqed_call("upper_case::rename_key")) return;
    text_out = glz::upper_case::rename_key(std::string_view(s));
    preqed_result("upper_case::rename_key", true);
}

/* UUID text form */

static void call_parse_uuid(payload in) {
    const std::string s = text_in(in);
    if (!preqed_call("parse_uuid")) return;
    preqed_result("parse_uuid", glz::parse_uuid(s, id));
}

/* the text form parses back to the same value */
static void call_to_string(payload) {
    if (!preqed_call("to_string")) return;
    text_out = glz::to_string(id);
    glz::uuid back;
    preqed_result("to_string", glz::parse_uuid(text_out, back) && back == id);
}

/* BEVE sizes, untagged and delimited forms */

static void call_beve_size(payload in) {
    if (!have_model) return;
    const fuzz_model chosen = selected_model(in);
    if (!preqed_call("beve_size")) return;
    (void)glz::beve_size(chosen);
    preqed_result("beve_size", true);
}

static void call_beve_size_untagged(payload in) {
    if (!have_model) return;
    const fuzz_model chosen = selected_model(in);
    if (!preqed_call("beve_size_untagged")) return;
    (void)glz::beve_size_untagged(chosen);
    preqed_result("beve_size_untagged", true);
}

/* the first 8 record bytes are the integer */
static void call_compressed_int_size(payload in) {
    uint64_t v = 0;
    for (size_t i = 0; i < 8 && i < in.n; ++i) v |= uint64_t(in.p[i]) << (8 * i);
    if (!preqed_call("compressed_int_size")) return;
    (void)glz::compressed_int_size(v);
    preqed_result("compressed_int_size", true);
}

static void call_write_beve_untagged(payload in) {
    if (!have_model) return;
    if (!preqed_call("write_beve_untagged")) return;
    auto r = glz::write_beve_untagged(selected_model(in));
    preqed_result("write_beve_untagged", bool(r));
    if (r) bytes_out = std::move(*r);
}

static void call_read_beve_untagged(payload in) {
    std::string b = bytes_in(in);
    if (!preqed_call("read_beve_untagged")) return;
    const glz::error_ctx ec = glz::read_beve_untagged(model, b);
    preqed_result("read_beve_untagged", !ec);
    if (!ec) have_model = true;
}

/* the append writers extend the last binary serialization */
static void call_write_beve_append(payload in) {
    if (!have_model) return;
    if (!preqed_call("write_beve_append")) return;
    const glz::error_ctx ec = glz::write_beve_append(selected_model(in), bytes_out);
    preqed_result("write_beve_append", !ec);
}

static void call_write_beve_append_with_delimiter(payload in) {
    if (!have_model) return;
    if (!preqed_call("write_beve_append_with_delimiter")) return;
    const glz::error_ctx ec = glz::write_beve_append_with_delimiter(selected_model(in), bytes_out);
    preqed_result("write_beve_append_with_delimiter", !ec);
}

static void call_write_beve_delimiter(payload) {
    if (!preqed_call("write_beve_delimiter")) return;
    glz::write_beve_delimiter(bytes_out);
    preqed_result("write_beve_delimiter", true);
}

static void call_write_beve_delimited(payload in) {
    if (!have_model) return;
    const std::vector<fuzz_model> documents{ model, selected_model(in) };
    if (!preqed_call("write_beve_delimited")) return;
    auto r = glz::write_beve_delimited(documents);
    preqed_result("write_beve_delimited", bool(r));
    if (r) bytes_out = std::move(*r);
}

static void call_read_beve_delimited(payload in) {
    std::string b = bytes_in(in);
    if (!preqed_call("read_beve_delimited")) return;
    std::vector<fuzz_model> decoded;
    const glz::error_ctx ec = glz::read_beve_delimited(decoded, b);
    preqed_result("read_beve_delimited", !ec);
    if (!ec && !decoded.empty()) {
        sequence = std::move(decoded);
        model = sequence.front();
        have_model = true;
    }
}

/* byte 0 bits 2-7: the offset */
static void call_read_beve_at(payload in) {
    std::string b = bytes_in(in);
    if (!preqed_call("read_beve_at")) return;
    auto r = glz::read_beve_at(model, b, byte(in, 0) >> 2);
    preqed_result("read_beve_at", bool(r));
    if (r) have_model = true;
}

/* thread pool: each job validates its own copy of the record as JSON */
/* ltl: pool_lifecycle */
static void call_pool(payload in) {
    if (!preqed_call("pool::pool")) return;
    thread_pool.reset();
    thread_pool.reset(new glz::pool(1 + byte(in, 0) % 3));
    preqed_result("pool::pool", true);
}
/* ltl: pool_lifecycle */
static void call_pool_emplace_back(payload in) {
    if (!thread_pool) return;
    std::string s = text_in(in);
    if (!preqed_call("pool::emplace_back")) return;
    auto done = thread_pool->emplace_back([s = std::move(s)] { return !glz::validate_json(s); });
    preqed_result("pool::emplace_back", done.valid());
}
/* ltl: pool_lifecycle */
static void call_pool_wait(payload) {
    if (!thread_pool) return;
    if (!preqed_call("pool::wait")) return;
    thread_pool->wait();
    preqed_result("pool::wait", true);
}

/* files: FILE_PATH and DIR_PATH only, never a name from the record */

static void call_write_directory(payload in) {
    if (!have_model) return;
    const std::map<std::filesystem::path, fuzz_model> files{ { DIR_PATH "/a.json", model },
                                                             { DIR_PATH "/b.json", selected_model(in) } };
    if (!preqed_call("write_directory")) return;
    have_dir = true;
    const glz::error_ctx ec = glz::write_directory(files, DIR_PATH);
    preqed_result("write_directory", !ec);
}

/* byte 0 bit 1 keeps the directory as the last write_directory left it, else the record becomes one more file */
static void call_read_directory(payload in) {
    if (!(byte(in, 0) & 2)) {
        std::error_code err;
        std::filesystem::create_directory(DIR_PATH, err);
        have_dir = true;
        put_file(DIR_PATH "/c.json", text_in(in));
    }
    std::map<std::filesystem::path, fuzz_model> files;
    if (!preqed_call("read_directory")) return;
    const glz::error_ctx ec = glz::read_directory(files, DIR_PATH);
    preqed_result("read_directory", !ec);
    if (!ec && !files.empty()) {
        model = files.begin()->second;
        have_model = true;
    }
}

static void call_read_file_json(payload in) {
    fill_file(in, false);
    std::string buffer;
    if (!preqed_call("read_file_json")) return;
    const glz::error_ctx ec = glz::read_file_json(model, FILE_PATH, buffer);
    preqed_result("read_file_json", !ec);
    if (!ec) have_model = true;
}

static void call_write_file_json(payload in) {
    if (!have_model) return;
    std::string buffer;
    if (!preqed_call("write_file_json")) return;
    have_file = true;
    const glz::error_ctx ec = glz::write_file_json(selected_model(in), FILE_PATH, buffer);
    preqed_result("write_file_json", !ec);
}

static void call_read_file_jsonb(payload in) {
    fill_file(in, true);
    std::string buffer;
    if (!preqed_call("read_file_jsonb")) return;
    const glz::error_ctx ec = glz::read_file_jsonb(model, FILE_PATH, buffer);
    preqed_result("read_file_jsonb", !ec);
    if (!ec) have_model = true;
}

static void call_write_file_jsonb(payload in) {
    if (!have_model) return;
    std::string buffer;
    if (!preqed_call("write_file_jsonb")) return;
    have_file = true;
    const glz::error_code ec = glz::write_file_jsonb(selected_model(in), FILE_PATH, buffer);
    preqed_result("write_file_jsonb", ec == glz::error_code::none);
}

static void call_read_file_msgpack(payload in) {
    fill_file(in, true);
    std::string buffer;
    if (!preqed_call("read_file_msgpack")) return;
    const glz::error_ctx ec = glz::read_file_msgpack(model, FILE_PATH, buffer);
    preqed_result("read_file_msgpack", !ec);
    if (!ec) have_model = true;
}

static void call_write_file_msgpack(payload in) {
    if (!have_model) return;
    std::string buffer;
    if (!preqed_call("write_file_msgpack")) return;
    have_file = true;
    const glz::error_ctx ec = glz::write_file_msgpack(selected_model(in), FILE_PATH, buffer);
    preqed_result("write_file_msgpack", !ec);
}

static void call_read_file_bson(payload in) {
    fill_file(in, true);
    std::string buffer;
    if (!preqed_call("read_file_bson")) return;
    const glz::error_ctx ec = glz::read_file_bson(model, FILE_PATH, buffer);
    preqed_result("read_file_bson", !ec);
    if (!ec) have_model = true;
}

static void call_write_file_bson(payload in) {
    if (!have_model) return;
    std::string buffer;
    if (!preqed_call("write_file_bson")) return;
    have_file = true;
    const glz::error_code ec = glz::write_file_bson(selected_model(in), FILE_PATH, buffer);
    preqed_result("write_file_bson", ec == glz::error_code::none);
}

static void call_read_file_toml(payload in) {
    fill_file(in, false);
    std::string buffer;
    if (!preqed_call("read_file_toml")) return;
    const glz::error_ctx ec = glz::read_file_toml(model, FILE_PATH, buffer);
    preqed_result("read_file_toml", !ec);
    if (!ec) have_model = true;
}

static void call_write_file_toml(payload in) {
    if (!have_model) return;
    std::string buffer;
    if (!preqed_call("write_file_toml")) return;
    have_file = true;
    const glz::error_ctx ec = glz::write_file_toml(selected_model(in), FILE_PATH, buffer);
    preqed_result("write_file_toml", !ec);
}

static void call_read_file_yaml(payload in) {
    fill_file(in, false);
    std::string buffer;
    if (!preqed_call("read_file_yaml")) return;
    const glz::error_ctx ec = glz::read_file_yaml(model, FILE_PATH, buffer);
    preqed_result("read_file_yaml", !ec);
    if (!ec) have_model = true;
}

static void call_write_file_yaml(payload in) {
    if (!have_model) return;
    std::string buffer;
    if (!preqed_call("write_file_yaml")) return;
    have_file = true;
    const glz::error_ctx ec = glz::write_file_yaml(selected_model(in), FILE_PATH, buffer);
    preqed_result("write_file_yaml", !ec);
}

static void call_write_file_csv(payload) {
    if (!have_csv) return;
    std::string buffer;
    if (!preqed_call("write_file_csv")) return;
    have_file = true;
    const glz::error_ctx ec = glz::write_file_csv<glz::rowwise>(csv, FILE_PATH, buffer);
    preqed_result("write_file_csv", !ec);
}

/* throwing API (glz::ex): a std::exception is the failure result */

static void call_ex_read(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("ex::read")) return;
    bool ok = true;
    try {
        glz::ex::read<glz::opts{ .null_terminated = false }>(model, s);
    } catch (const std::exception &) {
        ok = false;
    }
    preqed_result("ex::read", ok);
    if (ok) have_model = true;
}

static void call_ex_write(payload in) {
    if (!have_model) return;
    if (!preqed_call("ex::write")) return;
    bool ok = true;
    try {
        text_out = glz::ex::write<glz::opts{}>(selected_model(in));
    } catch (const std::exception &) {
        ok = false;
    }
    preqed_result("ex::write", ok);
}

static void call_ex_read_json(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("ex::read_json")) return;
    bool ok = true;
    try {
        glz::ex::read_json(model, s);
    } catch (const std::exception &) {
        ok = false;
    }
    preqed_result("ex::read_json", ok);
    if (ok) have_model = true;
}

static void call_ex_read_jsonc(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("ex::read_jsonc")) return;
    bool ok = true;
    try {
        glz::ex::read_jsonc(model, s);
    } catch (const std::exception &) {
        ok = false;
    }
    preqed_result("ex::read_jsonc", ok);
    if (ok) have_model = true;
}

static void call_ex_read_ndjson(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("ex::read_ndjson")) return;
    std::vector<fuzz_model> decoded;
    bool ok = true;
    try {
        glz::ex::read_ndjson(decoded, s);
    } catch (const std::exception &) {
        ok = false;
    }
    preqed_result("ex::read_ndjson", ok);
    if (ok && !decoded.empty()) {
        sequence = std::move(decoded);
        model = sequence.front();
        have_model = true;
    }
}

static void call_ex_validate_json(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("ex::validate_json")) return;
    bool ok = true;
    try {
        glz::ex::validate_json(s);
    } catch (const std::exception &) {
        ok = false;
    }
    preqed_result("ex::validate_json", ok);
}

static void call_ex_validate_jsonc(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("ex::validate_jsonc")) return;
    bool ok = true;
    try {
        glz::ex::validate_jsonc(s);
    } catch (const std::exception &) {
        ok = false;
    }
    preqed_result("ex::validate_jsonc", ok);
}

static void call_ex_write_json(payload in) {
    if (!have_model) return;
    if (!preqed_call("ex::write_json")) return;
    bool ok = true;
    try {
        text_out = glz::ex::write_json(selected_model(in));
    } catch (const std::exception &) {
        ok = false;
    }
    preqed_result("ex::write_json", ok);
}

static void call_ex_write_jsonc(payload in) {
    if (!have_model) return;
    if (!preqed_call("ex::write_jsonc")) return;
    bool ok = true;
    try {
        glz::ex::write_jsonc(selected_model(in), text_out);
    } catch (const std::exception &) {
        ok = false;
    }
    preqed_result("ex::write_jsonc", ok);
}

static void call_ex_write_ndjson(payload in) {
    if (!have_model) return;
    const std::vector<fuzz_model> documents{ model, selected_model(in) };
    if (!preqed_call("ex::write_ndjson")) return;
    bool ok = true;
    try {
        glz::ex::write_ndjson(documents, text_out);
    } catch (const std::exception &) {
        ok = false;
    }
    preqed_result("ex::write_ndjson", ok);
}

static void call_ex_write_json_schema(payload in) {
    if (!preqed_call("ex::write_json_schema")) return;
    bool ok = true;
    try {
        text_out = (byte(in, 0) & 1) ? glz::ex::write_json_schema<fuzz_model>() : glz::ex::write_json_schema<fuzz_child>();
    } catch (const std::exception &) {
        ok = false;
    }
    preqed_result("ex::write_json_schema", ok);
}

static void call_ex_read_beve(payload in) {
    std::string b = bytes_in(in);
    if (!preqed_call("ex::read_beve")) return;
    bool ok = true;
    try {
        glz::ex::read_beve(model, b);
    } catch (const std::exception &) {
        ok = false;
    }
    preqed_result("ex::read_beve", ok);
    if (ok) have_model = true;
}

static void call_ex_write_beve(payload in) {
    if (!have_model) return;
    if (!preqed_call("ex::write_beve")) return;
    bool ok = true;
    try {
        glz::ex::write_beve(selected_model(in), bytes_out);
    } catch (const std::exception &) {
        ok = false;
    }
    preqed_result("ex::write_beve", ok);
}

static void call_ex_read_cbor(payload in) {
    std::string b = bytes_in(in);
    if (!preqed_call("ex::read_cbor")) return;
    bool ok = true;
    try {
        glz::ex::read_cbor(model, b);
    } catch (const std::exception &) {
        ok = false;
    }
    preqed_result("ex::read_cbor", ok);
    if (ok) have_model = true;
}

static void call_ex_write_cbor(payload in) {
    if (!have_model) return;
    if (!preqed_call("ex::write_cbor")) return;
    bool ok = true;
    try {
        bytes_out = glz::ex::write_cbor(selected_model(in));
    } catch (const std::exception &) {
        ok = false;
    }
    preqed_result("ex::write_cbor", ok);
}

static void call_ex_read_msgpack(payload in) {
    std::string b = bytes_in(in);
    if (!preqed_call("ex::read_msgpack")) return;
    bool ok = true;
    try {
        glz::ex::read_msgpack(model, b);
    } catch (const std::exception &) {
        ok = false;
    }
    preqed_result("ex::read_msgpack", ok);
    if (ok) have_model = true;
}

static void call_ex_write_msgpack(payload in) {
    if (!have_model) return;
    if (!preqed_call("ex::write_msgpack")) return;
    bool ok = true;
    try {
        bytes_out = glz::ex::write_msgpack(selected_model(in));
    } catch (const std::exception &) {
        ok = false;
    }
    preqed_result("ex::write_msgpack", ok);
}

static void call_ex_read_csv(payload in) {
    std::string s = text_in(in);
    if (!preqed_call("ex::read_csv")) return;
    csv_model flat;
    bool ok = true;
    try {
        glz::ex::read_csv<glz::rowwise>(flat, s);
    } catch (const std::exception &) {
        ok = false;
    }
    preqed_result("ex::read_csv", ok);
    if (ok) {
        csv = std::move(flat);
        have_csv = true;
    }
}

static void call_ex_read_file_json(payload in) {
    fill_file(in, false);
    std::string buffer;
    if (!preqed_call("ex::read_file_json")) return;
    bool ok = true;
    try {
        glz::ex::read_file_json(model, FILE_PATH, buffer);
    } catch (const std::exception &) {
        ok = false;
    }
    preqed_result("ex::read_file_json", ok);
    if (ok) have_model = true;
}

static void call_ex_read_file_jsonc(payload in) {
    fill_file(in, false);
    std::string buffer;
    if (!preqed_call("ex::read_file_jsonc")) return;
    bool ok = true;
    try {
        glz::ex::read_file_jsonc(model, FILE_PATH, buffer);
    } catch (const std::exception &) {
        ok = false;
    }
    preqed_result("ex::read_file_jsonc", ok);
    if (ok) have_model = true;
}

static void call_ex_read_file_beve(payload in) {
    fill_file(in, true);
    std::string buffer;
    if (!preqed_call("ex::read_file_beve")) return;
    bool ok = true;
    try {
        glz::ex::read_file_beve(model, FILE_PATH, buffer);
    } catch (const std::exception &) {
        ok = false;
    }
    preqed_result("ex::read_file_beve", ok);
    if (ok) have_model = true;
}

static void call_ex_read_file_msgpack(payload in) {
    fill_file(in, true);
    std::string buffer;
    if (!preqed_call("ex::read_file_msgpack")) return;
    bool ok = true;
    try {
        glz::ex::read_file_msgpack(model, FILE_PATH, buffer);
    } catch (const std::exception &) {
        ok = false;
    }
    preqed_result("ex::read_file_msgpack", ok);
    if (ok) have_model = true;
}

static void call_ex_write_file_json(payload in) {
    if (!have_model) return;
    std::string buffer;
    if (!preqed_call("ex::write_file_json")) return;
    have_file = true;
    bool ok = true;
    try {
        glz::ex::write_file_json(selected_model(in), FILE_PATH, buffer);
    } catch (const std::exception &) {
        ok = false;
    }
    preqed_result("ex::write_file_json", ok);
}

static void call_ex_write_file_ndjson(payload in) {
    if (!have_model) return;
    const std::vector<fuzz_model> documents{ model, selected_model(in) };
    std::string buffer;
    if (!preqed_call("ex::write_file_ndjson")) return;
    have_file = true;
    bool ok = true;
    try {
        glz::ex::write_file_ndjson(documents, FILE_PATH, buffer);
    } catch (const std::exception &) {
        ok = false;
    }
    preqed_result("ex::write_file_ndjson", ok);
}

static void call_ex_write_file_beve(payload in) {
    if (!have_model) return;
    std::string buffer;
    if (!preqed_call("ex::write_file_beve")) return;
    have_file = true;
    bool ok = true;
    try {
        glz::ex::write_file_beve(selected_model(in), FILE_PATH, buffer);
    } catch (const std::exception &) {
        ok = false;
    }
    preqed_result("ex::write_file_beve", ok);
}

static void call_ex_write_file_msgpack(payload in) {
    if (!have_model) return;
    std::string buffer;
    if (!preqed_call("ex::write_file_msgpack")) return;
    have_file = true;
    bool ok = true;
    try {
        glz::ex::write_file_msgpack(selected_model(in), FILE_PATH, buffer);
    } catch (const std::exception &) {
        ok = false;
    }
    preqed_result("ex::write_file_msgpack", ok);
}

/* dispatch */

static void (*const api[])(payload) = {
    call_read,
    call_read_generic,
    call_read_target,
    call_read_json,
    call_read_jsonc,
    call_write_json,
    call_write_json_generic,
    call_write_prettify,
    call_minify_json,
    call_prettify_json,
    call_validate_json,
    call_validate_jsonc,
    call_validate_utf8,
    call_write_json_schema,
    call_read_yaml,
    call_read_yaml_model,
    call_write_yaml,
    call_write_yaml_generic,
    call_write_yaml_flow,
    call_read_toml,
    call_read_toml_generic,
    call_write_toml,
    call_read_csv_rowwise,
    call_read_csv_colwise,
    call_write_csv,
    call_read_ndjson,
    call_write_ndjson,
    call_read_cbor,
    call_write_cbor,
    call_cbor_to_json,
    call_read_cbor_sequence,
    call_read_msgpack,
    call_write_msgpack,
    call_read_msgpack_ext,
    call_read_msgpack_timestamp,
    call_read_msgpack_sequence,
    call_read_jsonb,
    call_read_jsonb_generic,
    call_write_jsonb,
    call_jsonb_to_json,
    call_read_jsonb_sequence,
    call_read_bson,
    call_write_bson,
    call_bson_to_json,
    call_read_beve,
    call_write_beve,
    call_beve_to_json,
    call_read_beve_sequence,
    call_read_base64,
    call_write_base64,
    call_read_as_json,
    call_write_as_json,
    call_read_as,
    call_write_as,
    call_diff,
    call_diff_json,
    call_patch,
    call_patch_op,
    call_patch_json,
    call_merge_diff,
    call_merge_patch,
    call_merge_patch_json,
    call_merge_patch_model,
    call_jmespath_expression,
    call_read_jmespath,
    call_from_chars_double,
    call_from_chars_float,
    call_atoi_int64,
    call_atoi_uint64,
    call_read_wide,
    call_generic_operator_index,
    call_generic_at,
    call_generic_contains,
    call_generic_dump,
    call_generic_empty,
    call_generic_size,
    call_generic_get_if,
    call_generic_as,
    call_generic_as_number,
    call_generic_is_boolean,
    call_generic_is_number,
    call_generic_is_string,
    call_generic_is_double,
    call_generic_is_int64,
    call_generic_is_uint64,
    call_generic_operator_arrow,
    call_generic_reset,
    call_is_object,
    call_is_array,
    call_is_string,
    call_is_number,
    call_is_boolean,
    call_is_null,
    call_convert_from_generic,
    call_ordered_small_map_at,
    call_ordered_small_map_clear,
    call_ordered_small_map_contains,
    call_ordered_small_map_insert,
    call_ordered_small_map_insert_or_assign,
    call_ordered_small_map_reserve,
    call_ordered_small_map_shrink_to_fit,
    call_lazy_json,
    call_lazy_document_root,
    call_lazy_document_operator_index,
    call_lazy_document_reset_parse_pos,
    call_lazy_json_view_operator_index,
    call_lazy_json_view_get,
    call_lazy_json_view_key,
    call_lazy_json_view_index,
    call_lazy_json_view_is_object,
    call_lazy_json_view_is_array,
    call_lazy_json_view_is_string,
    call_lazy_json_view_is_number,
    call_lazy_json_view_is_boolean,
    call_lazy_json_view_is_null,
    call_lazy_json_view_has_error,
    call_lazy_json_view_error,
    call_lazy_json_view_empty,
    call_lazy_json_view_size,
    call_lazy_json_view_contains,
    call_lazy_json_view_read_into,
    call_lazy_json_view_raw_json,
    call_lazy_json_view_begin,
    call_lazy_json_view_end,
    call_indexed_lazy_view_size,
    call_indexed_lazy_view_empty,
    call_indexed_lazy_view_contains,
    call_indexed_lazy_view_operator_index,
    call_indexed_lazy_view_begin,
    call_indexed_lazy_view_end,
    call_lazy_beve,
    call_lazy_beve_document_root,
    call_lazy_beve_document_operator_index,
    call_lazy_beve_document_reset_parse_pos,
    call_lazy_beve_view_operator_index,
    call_lazy_beve_view_get,
    call_lazy_beve_view_key,
    call_lazy_beve_view_index,
    call_lazy_beve_view_is_object,
    call_lazy_beve_view_is_array,
    call_lazy_beve_view_is_typed_array,
    call_lazy_beve_view_is_generic_array,
    call_lazy_beve_view_is_string,
    call_lazy_beve_view_is_number,
    call_lazy_beve_view_is_boolean,
    call_lazy_beve_view_is_null,
    call_lazy_beve_view_has_error,
    call_lazy_beve_view_error,
    call_lazy_beve_view_empty,
    call_lazy_beve_view_size,
    call_lazy_beve_view_contains,
    call_lazy_beve_view_read_into,
    call_lazy_beve_view_raw_beve,
    call_lazy_beve_view_begin,
    call_lazy_beve_view_end,
    call_indexed_lazy_beve_view_size,
    call_indexed_lazy_beve_view_empty,
    call_indexed_lazy_beve_view_contains,
    call_indexed_lazy_beve_view_operator_index,
    call_indexed_lazy_beve_view_begin,
    call_indexed_lazy_beve_view_end,
    call_json_stream_reader,
    call_json_stream_reader_read_next,
    call_json_stream_reader_begin,
    call_json_stream_reader_end,
    call_read_json_stream,
    call_basic_istream_buffer,
    call_basic_ostream_buffer,
    call_get_as_json,
    call_get_sv_json,
    call_get_view_json,
    call_get_view_json_runtime,
    call_write_at,
    call_write_at_runtime,
    call_get,
    call_get_if,
    call_get_value,
    call_set,
    call_write_json_partial,
    call_write_json_exclude,
    call_json_ptrs,
    call_patched,
    call_merge_patched,
    call_merge_patch_json_text,
    call_merge_diff_json,
    call_format_error,
    call_for_each_field,
    call_object,
    call_array,
    call_flags,
    call_date_format,
    call_epoch_count,
    call_epoch_time,
    call_epoch_time_operator_time_point,
    call_epoch_time_operator_eq,
    call_epoch_time_operator_cmp,
    call_toml_opts,
    call_stencil,
    call_mustache,
    call_to_camel_case,
    call_to_snake_case,
    call_to_kebab_case,
    call_camel_case_rename_key,
    call_pascal_case_rename_key,
    call_snake_case_rename_key,
    call_screaming_snake_case_rename_key,
    call_kebab_case_rename_key,
    call_screaming_kebab_case_rename_key,
    call_lower_case_rename_key,
    call_upper_case_rename_key,
    call_parse_uuid,
    call_to_string,
    call_beve_size,
    call_beve_size_untagged,
    call_compressed_int_size,
    call_write_beve_untagged,
    call_read_beve_untagged,
    call_write_beve_append,
    call_write_beve_append_with_delimiter,
    call_write_beve_delimiter,
    call_write_beve_delimited,
    call_read_beve_delimited,
    call_read_beve_at,
    call_pool,
    call_pool_emplace_back,
    call_pool_wait,
    call_write_directory,
    call_read_directory,
    call_read_file_json,
    call_write_file_json,
    call_read_file_jsonb,
    call_write_file_jsonb,
    call_read_file_msgpack,
    call_write_file_msgpack,
    call_read_file_bson,
    call_write_file_bson,
    call_read_file_toml,
    call_write_file_toml,
    call_read_file_yaml,
    call_write_file_yaml,
    call_write_file_csv,
    call_ex_read,
    call_ex_write,
    call_ex_read_json,
    call_ex_read_jsonc,
    call_ex_read_ndjson,
    call_ex_validate_json,
    call_ex_validate_jsonc,
    call_ex_write_json,
    call_ex_write_jsonc,
    call_ex_write_ndjson,
    call_ex_write_json_schema,
    call_ex_read_beve,
    call_ex_write_beve,
    call_ex_read_cbor,
    call_ex_write_cbor,
    call_ex_read_msgpack,
    call_ex_write_msgpack,
    call_ex_read_csv,
    call_ex_read_file_json,
    call_ex_read_file_jsonc,
    call_ex_read_file_beve,
    call_ex_read_file_msgpack,
    call_ex_write_file_json,
    call_ex_write_file_ndjson,
    call_ex_write_file_beve,
    call_ex_write_file_msgpack,
};

static const size_t API_COUNT = sizeof api / sizeof api[0];

static void cleanup() {
    model = fuzz_model{};
    have_model = false;
    generic = glz::generic{};
    have_generic = false;
    target = glz::generic{};
    have_target = false;
    csv = csv_model{};
    have_csv = false;
    sequence.clear();
    patches.clear();
    have_patch = false;
    text_out.clear();
    bytes_out.clear();
    expression.reset();
    expression_path.clear();
    wide = glz::generic_u64{};
    have_wide = false;
    last_error = {};
    last_input.clear();
    lazy_index.reset();
    lazy_view.reset();
    lazy_doc.reset();
    lazy_text.clear();
    beve_index.reset();
    beve_view.reset();
    beve_doc.reset();
    beve_text.clear();
    stream_reader.reset();
    stream_in.reset();
    thread_pool.reset();  /* ~pool finishes the queued jobs (threadpool.hpp:167) */
    stamp = {};
    id = {};
    if (have_file) std::remove(FILE_PATH);
    have_file = false;
    if (have_dir) {
        std::error_code err;
        std::filesystem::remove_all(DIR_PATH, err);
    }
    have_dir = false;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    preqed_reset();
    size_t off = 0;
    /* record: 16-bit API index (more than 256 wrappers), 16-bit length, payload */
    while (size - off >= 4) {
        const size_t op = static_cast<size_t>(data[off]) | static_cast<size_t>(data[off + 1]) << 8;
        const size_t len = static_cast<size_t>(data[off + 2]) | static_cast<size_t>(data[off + 3]) << 8;
        off += 4;
        if (len > size - off) break;
        api[op % API_COUNT]({ data + off, len });
        off += len;
        /* a serialization can be larger than the record that produced it, so an oversized one is not fed back */
        if (text_out.size() > 8192) text_out.clear();
        if (bytes_out.size() > 8192) bytes_out.clear();
    }
    cleanup();
    return 0;
}
