#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <json.h>
#include <json_visit.h>
#include <json_patch.h>
#include "preqed_ltl.h"

#define FILE_PATH "json-c-harness.json"

typedef struct {
    const uint8_t *p;
    size_t n;
} payload;

static struct json_object *root;  /* owned tree */
static struct json_object *item;  /* owned loose object, waiting to be attached */
static struct json_object *child; /* borrowed pointer into root */
static int item_shared;           /* item is a reference to a node inside root */
static struct json_tokener *tok;
static int tok_failed; /* fatal parse error; reset before reuse */
static struct printbuf *pb;
static struct json_object_iterator iter, iter_end;
static int iter_valid;
static struct lh_table *table;   /* linkhash table with pointer keys */
static struct array_list *list;
static int debug_level;
/* lh_kptr_table_new hashes the key pointer itself: the 16 addresses in here are the keys */
static char ptr_keys[16];

/* NUL-terminated copies of payload bytes: keys (255 chars), strings (4095 chars) */
static char key[256];
static char str[4096];
/* stable address handed to json_object_set_userdata; never freed through the userdata callback */
static char str2[256];

static uint8_t byte(payload in, size_t i) { return i < in.n ? in.p[i] : 0; }
static payload rest(payload in, size_t skip) {
    payload r = { in.p + (skip < in.n ? skip : in.n), in.n > skip ? in.n - skip : 0 };
    return r;
}
static const char *cstr(char *dst, size_t cap, payload in) {
    size_t n = in.n < cap - 1 ? in.n : cap - 1;
    memcpy(dst, in.p, n);
    dst[n] = 0;
    return dst;
}
static int64_t integer(payload in) {
    int64_t v = 0;
    memcpy(&v, in.p, in.n < sizeof v ? in.n : sizeof v);
    return v;
}
static double number(payload in) {
    double d = 0;
    memcpy(&d, in.p, in.n < sizeof d ? in.n : sizeof d);
    return d;
}
/* each payload bit toggles one JSON_C_TO_STRING_* serialization flag (json_object.h) */
static int to_string_flags(uint8_t b) {
    return (b & 1 ? JSON_C_TO_STRING_SPACED : 0) | (b & 2 ? JSON_C_TO_STRING_PRETTY : 0) |
           (b & 4 ? JSON_C_TO_STRING_PRETTY_TAB : 0) | (b & 8 ? JSON_C_TO_STRING_NOZERO : 0) |
           (b & 16 ? JSON_C_TO_STRING_NOSLASHESCAPE : 0) | (b & 32 ? JSON_C_TO_STRING_COLOR : 0);
}
static int root_is(enum json_type t) { return root && json_object_get_type(root) == t; }

/* root changed shape: borrowed pointers and iterators into it are stale */
static void root_mutated(void) {
    child = NULL;
    iter_valid = 0;
}

#define REPORT(api, expr, ok_cond) \
    do { if (preqed_call(#api)) { int rc = (expr); preqed_result(#api, (ok_cond)); } } while (0)
#define REPORT_VOID(api, expr) \
    do { if (preqed_call(#api)) { expr; preqed_result(#api, 1); } } while (0)

static void take_root(const char *api, struct json_object *tree) {
    preqed_result(api, tree != NULL);
    root = tree;
}
static void take_item(const char *api, struct json_object *node) {
    preqed_result(api, node != NULL);
    item = node;
    item_shared = 0;
}
static void take_child(const char *api, struct json_object *node) {
    preqed_result(api, node != NULL);
    child = node;
}

/* version and globals */

static void call_json_c_version(payload in) {
    (void)in;
    if (!preqed_call("json_c_version")) return;
    preqed_result("json_c_version", json_c_version() != NULL);
}

static void call_json_c_version_num(payload in) {
    (void)in;
    REPORT_VOID(json_c_version_num, json_c_version_num());
}

static void call_json_c_set_serialization_double_format(payload in) {
    /* NULL restores the default; %.17g round-trips doubles; %f, %.3e, %g change the text form */
    static const char *const formats[] = { NULL, "%.17g", "%f", "%.3e", "%g" };
    REPORT(json_c_set_serialization_double_format,
           json_c_set_serialization_double_format(formats[byte(in, 0) % 5], JSON_C_OPTION_GLOBAL), rc == 0);
}

static void call_json_type_to_name(payload in) {
    if (!preqed_call("json_type_to_name")) return;
    preqed_result("json_type_to_name", json_type_to_name((enum json_type)(byte(in, 0) % 8)) != NULL);
}

/* parsing: produces root */
/* ltl: root_lifecycle */
static void call_json_tokener_parse(payload in) {
    if (root) return;
    if (!preqed_call("json_tokener_parse")) return;
    take_root("json_tokener_parse", json_tokener_parse(cstr(str, sizeof str, in)));
}
/* ltl: root_lifecycle */
static void call_json_tokener_parse_verbose(payload in) {
    if (root) return;
    enum json_tokener_error err;
    if (!preqed_call("json_tokener_parse_verbose")) return;
    take_root("json_tokener_parse_verbose", json_tokener_parse_verbose(cstr(str, sizeof str, in), &err));
}
/* ltl: tokener_lifecycle */
static void call_json_tokener_new(payload in) {
    (void)in;
    if (tok) return;
    if (!preqed_call("json_tokener_new")) return;
    tok = json_tokener_new();
    preqed_result("json_tokener_new", tok != NULL);
}
/* ltl: tokener_lifecycle */
static void call_json_tokener_new_ex(payload in) {
    if (tok) return;
    if (!preqed_call("json_tokener_new_ex")) return;
    tok = json_tokener_new_ex(1 + byte(in, 0) % 64);  /* max nesting depth 1..64 (default is 32) */
    preqed_result("json_tokener_new_ex", tok != NULL);
}

/* bit 0 strict, bit 1 UTF-8 validation, bit 2 allow trailing characters (json_tokener.h) */
/* ltl: tokener_lifecycle */
static void call_json_tokener_set_flags(payload in) {
    if (!tok) return;
    int flags = (byte(in, 0) & 1 ? JSON_TOKENER_STRICT : 0) | (byte(in, 0) & 2 ? JSON_TOKENER_VALIDATE_UTF8 : 0) |
                (byte(in, 0) & 4 ? JSON_TOKENER_ALLOW_TRAILING_CHARS : 0);
    REPORT_VOID(json_tokener_set_flags, json_tokener_set_flags(tok, flags));
}
/* ltl: root_lifecycle, tokener_lifecycle */
static void call_json_tokener_parse_ex(payload in) {
    if (!tok || root || tok_failed) return;
    if (!preqed_call("json_tokener_parse_ex")) return;
    struct json_object *parsed = json_tokener_parse_ex(tok, (const char *)in.p, (int)in.n);
    enum json_tokener_error err = json_tokener_get_error(tok);
    preqed_result("json_tokener_parse_ex", err == json_tokener_success);
    tok_failed = !parsed && err != json_tokener_continue;
    root = parsed;
}
/* ltl: tokener_lifecycle */
static void call_json_tokener_get_error(payload in) {
    (void)in;
    if (!tok) return;
    REPORT_VOID(json_tokener_get_error, json_tokener_get_error(tok));
}

static void call_json_tokener_error_desc(payload in) {
    if (!preqed_call("json_tokener_error_desc")) return;
    preqed_result("json_tokener_error_desc", json_tokener_error_desc((enum json_tokener_error)(byte(in, 0) % 24)) != NULL);
}
/* ltl: tokener_lifecycle */
static void call_json_tokener_get_parse_end(payload in) {
    (void)in;
    if (!tok) return;
    REPORT_VOID(json_tokener_get_parse_end, json_tokener_get_parse_end(tok));
}
/* ltl: tokener_lifecycle */
static void call_json_tokener_reset(payload in) {
    (void)in;
    if (!tok) return;
    REPORT_VOID(json_tokener_reset, json_tokener_reset(tok));
    tok_failed = 0;
}
/* ltl: tokener_lifecycle */
static void call_json_tokener_free(payload in) {
    (void)in;
    if (!tok) return;
    REPORT_VOID(json_tokener_free, json_tokener_free(tok));
    tok = NULL;
    tok_failed = 0;
}

/* files and descriptors */

static void write_file(payload in) {
    int fd = open(FILE_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return;
    ssize_t written = write(fd, in.p, in.n);
    (void)written;
    close(fd);
}
/* ltl: root_lifecycle */
static void call_json_object_from_file(payload in) {
    if (root) return;
    write_file(in);
    if (!preqed_call("json_object_from_file")) return;
    take_root("json_object_from_file", json_object_from_file(FILE_PATH));
}
/* ltl: root_lifecycle */
static void call_json_object_from_fd(payload in) {
    if (root) return;
    write_file(in);
    int fd = open(FILE_PATH, O_RDONLY);
    if (fd < 0) return;
    if (!preqed_call("json_object_from_fd")) {
        close(fd);
        return;
    }
    take_root("json_object_from_fd", json_object_from_fd(fd));
    close(fd);
}
/* ltl: root_lifecycle */
static void call_json_object_from_fd_ex(payload in) {
    if (root) return;
    write_file(rest(in, 1));
    int fd = open(FILE_PATH, O_RDONLY);
    if (fd < 0) return;
    if (!preqed_call("json_object_from_fd_ex")) {
        close(fd);
        return;
    }
    take_root("json_object_from_fd_ex", json_object_from_fd_ex(fd, 1 + byte(in, 0) % 64));  /* depth 1..64 */
    close(fd);
}
/* ltl: root_lifecycle */
static void call_json_object_to_file(payload in) {
    (void)in;
    if (!root) return;
    REPORT(json_object_to_file, json_object_to_file(FILE_PATH, root), rc == 0);
}
/* ltl: root_lifecycle */
static void call_json_object_to_file_ext(payload in) {
    if (!root) return;
    REPORT(json_object_to_file_ext, json_object_to_file_ext(FILE_PATH, root, to_string_flags(byte(in, 0))), rc == 0);
}
/* ltl: root_lifecycle */
static void call_json_object_to_fd(payload in) {
    if (!root) return;
    int fd = open(FILE_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return;
    if (!preqed_call("json_object_to_fd")) {
        close(fd);
        return;
    }
    int rc = json_object_to_fd(fd, root, to_string_flags(byte(in, 0)));
    preqed_result("json_object_to_fd", rc == 0);
    close(fd);
}

static void call_json_util_get_last_err(payload in) {
    (void)in;
    REPORT_VOID(json_util_get_last_err, json_util_get_last_err());
}

static void call_json_parse_int64(payload in) {
    int64_t v;
    REPORT(json_parse_int64, json_parse_int64(cstr(str, sizeof str, in), &v), rc == 0);
}

static void call_json_parse_uint64(payload in) {
    uint64_t v;
    REPORT(json_parse_uint64, json_parse_uint64(cstr(str, sizeof str, in), &v), rc == 0);
}

static void call_json_parse_double(payload in) {
    double v;
    REPORT(json_parse_double, json_parse_double(cstr(str, sizeof str, in), &v), rc == 0);
}

/* serialization */
/* ltl: root_lifecycle */
static void call_json_object_to_json_string(payload in) {
    (void)in;
    if (!root) return;
    if (!preqed_call("json_object_to_json_string")) return;
    preqed_result("json_object_to_json_string", json_object_to_json_string(root) != NULL);
}
/* ltl: root_lifecycle */
static void call_json_object_to_json_string_ext(payload in) {
    if (!root) return;
    if (!preqed_call("json_object_to_json_string_ext")) return;
    preqed_result("json_object_to_json_string_ext", json_object_to_json_string_ext(root, to_string_flags(byte(in, 0))) != NULL);
}
/* ltl: root_lifecycle */
static void call_json_object_to_json_string_length(payload in) {
    if (!root) return;
    size_t len = 0;
    if (!preqed_call("json_object_to_json_string_length")) return;
    const char *s = json_object_to_json_string_length(root, to_string_flags(byte(in, 0)), &len);
    preqed_result("json_object_to_json_string_length", s != NULL && strlen(s) == len);
}

static int custom_serializer(struct json_object *jso, struct printbuf *out, int level, int flags) {
    (void)jso;
    (void)level;
    (void)flags;
    /* replaces the value's JSON text with the 8-byte string "custom" (quotes included) */
    return printbuf_memappend(out, "\"custom\"", 8);
}
/* ltl: borrowed_child_validity */
static void call_json_object_set_serializer(payload in) {
    if (!child) return;
    REPORT_VOID(json_object_set_serializer, json_object_set_serializer(child, byte(in, 0) & 1 ? custom_serializer : NULL, NULL, NULL));
}
/* ltl: borrowed_child_validity */
static void call_json_object_set_userdata(payload in) {
    if (!child) return;
    REPORT_VOID(json_object_set_userdata, json_object_set_userdata(child, byte(in, 0) & 1 ? str2 : NULL, NULL));
}
/* ltl: borrowed_child_validity */
static void call_json_object_get_userdata(payload in) {
    (void)in;
    if (!child) return;
    REPORT_VOID(json_object_get_userdata, json_object_get_userdata(child));
}
/* ltl: borrowed_child_validity, printbuf_lifecycle */
static void call_json_object_double_to_json_string(payload in) {
    if (!child || !pb || !json_object_is_type(child, json_type_double)) return;
    REPORT(json_object_double_to_json_string,
           json_object_double_to_json_string(child, pb, byte(in, 0) % 4, to_string_flags(byte(in, 1))), rc >= 0);  /* level 0..3: nesting depth, only used for indentation */
}

/* reference counting on root */
/* ltl: root_lifecycle, borrowed_child_validity, iterator_validity */
static void call_json_object_put(payload in) {
    (void)in;
    if (!root) return;
    root_mutated();
    REPORT_VOID(json_object_put, json_object_put(root));
    root = NULL;
}
/* ltl: item_ownership, borrowed_child_validity */
static void call_json_object_get(payload in) {
    (void)in;
    if (!child || child == root || item) return;
    if (!preqed_call("json_object_get")) return;
    take_item("json_object_get", json_object_get(child));
    item_shared = 1;
}

/* constructors: produce item */

#define NEW(api, ...) \
    static void call_##api(payload in) { \
        (void)in; \
        if (item) return; \
        if (!preqed_call(#api)) return; \
        take_item(#api, api(__VA_ARGS__)); \
    }
/* ltl: item_ownership */
NEW(json_object_new_object)
/* ltl: item_ownership */
NEW(json_object_new_array)
/* ltl: item_ownership */
NEW(json_object_new_null)
/* ltl: item_ownership */
NEW(json_object_new_array_ext, byte(in, 0))
/* ltl: item_ownership */
NEW(json_object_new_boolean, byte(in, 0) & 1)
/* ltl: item_ownership */
NEW(json_object_new_int, (int32_t)integer(in))
/* ltl: item_ownership */
NEW(json_object_new_int64, integer(in))
/* ltl: item_ownership */
NEW(json_object_new_uint64, (uint64_t)integer(in))
/* ltl: item_ownership */
NEW(json_object_new_double, number(in))
/* ltl: item_ownership */
NEW(json_object_new_double_s, number(in), cstr(str, sizeof str, rest(in, 8)))
/* ltl: item_ownership */
NEW(json_object_new_string, cstr(str, sizeof str, in))
/* ltl: item_ownership */
NEW(json_object_new_string_len, (const char *)in.p, (int)in.n)
/* ltl: root_lifecycle, item_ownership */
static void call_json_object_deep_copy(payload in) {
    (void)in;
    if (item || !root) return;
    struct json_object *copy = NULL;
    if (!preqed_call("json_object_deep_copy")) return;
    int rc = json_object_deep_copy(root, &copy, NULL);
    preqed_result("json_object_deep_copy", rc == 0);
    item = copy;
    item_shared = 0;
}

/* attach item to root: ownership moves on success */

#define ATTACH(api, type, expr) \
    do { \
        if (!root_is(type) || !item) return; \
        root_mutated(); \
        if (!preqed_call(#api)) return; \
        int rc = (expr); \
        preqed_result(#api, rc == 0); \
        if (rc == 0) item = NULL; \
    } while (0)
/* ltl: root_lifecycle, item_ownership, borrowed_child_validity, iterator_validity */
static void call_json_object_object_add(payload in) {
    ATTACH(json_object_object_add, json_type_object, json_object_object_add(root, cstr(key, sizeof key, in), item));
}
/* ltl: root_lifecycle, item_ownership, borrowed_child_validity, iterator_validity */
static void call_json_object_object_add_ex(payload in) {
    if (!root_is(json_type_object)) return;
    cstr(key, sizeof key, rest(in, 1));
    unsigned opts = byte(in, 0) & 1 && !json_object_object_get_ex(root, key, NULL) ? JSON_C_OBJECT_ADD_KEY_IS_NEW : 0;
    ATTACH(json_object_object_add_ex, json_type_object, json_object_object_add_ex(root, key, item, opts));
}
/* ltl: root_lifecycle, item_ownership, borrowed_child_validity, iterator_validity */
static void call_json_object_array_add(payload in) {
    (void)in;
    ATTACH(json_object_array_add, json_type_array, json_object_array_add(root, item));
}
/* ltl: root_lifecycle, item_ownership, borrowed_child_validity, iterator_validity */
static void call_json_object_array_put_idx(payload in) {
    ATTACH(json_object_array_put_idx, json_type_array, json_object_array_put_idx(root, byte(in, 0), item));
}
/* ltl: root_lifecycle, item_ownership, borrowed_child_validity, iterator_validity */
static void call_json_object_array_insert_idx(payload in) {
    ATTACH(json_object_array_insert_idx, json_type_array, json_object_array_insert_idx(root, byte(in, 0), item));
}
/* ltl: root_lifecycle, item_ownership, borrowed_child_validity, iterator_validity */
static void call_json_object_array_put_with_idx_limit_cb(payload in) {
    size_t limit = byte(in, 1);
    ATTACH(json_object_array_put_with_idx_limit_cb, json_type_array,
           json_object_array_put_with_idx_limit_cb(root, NULL, byte(in, 0), item, &limit));
}

/* json pointers: set moves item (possibly replacing root), get produces child */

#define POINTER_SET(api, expr) \
    do { \
        if (!root || !item || item_shared) return; \
        root_mutated(); \
        if (!preqed_call(#api)) return; \
        int rc = (expr); \
        preqed_result(#api, rc == 0); \
        if (rc == 0) item = NULL; \
    } while (0)
/* ltl: root_lifecycle, item_ownership, borrowed_child_validity, iterator_validity */
static void call_json_pointer_set(payload in) {
    POINTER_SET(json_pointer_set, json_pointer_set(&root, cstr(str, sizeof str, in), item));
}
/* ltl: root_lifecycle, item_ownership, borrowed_child_validity, iterator_validity */
static void call_json_pointer_setf(payload in) {
    POINTER_SET(json_pointer_setf, json_pointer_setf(&root, item, "%s", cstr(str, sizeof str, in)));
}
/* ltl: root_lifecycle, item_ownership, borrowed_child_validity, iterator_validity */
static void call_json_pointer_set_with_limit_index(payload in) {
    POINTER_SET(json_pointer_set_with_limit_index,
                json_pointer_set_with_limit_index(&root, cstr(str, sizeof str, rest(in, 1)), item, byte(in, 0)));
}
/* ltl: root_lifecycle, item_ownership, borrowed_child_validity, iterator_validity */
static void call_json_pointer_set_with_cb(payload in) {
    size_t limit = byte(in, 0);
    POINTER_SET(json_pointer_set_with_cb,
                json_pointer_set_with_cb(&root, cstr(str, sizeof str, rest(in, 1)), item,
                                         json_object_array_put_with_idx_limit_cb, 0, &limit));
}
/* ltl: root_lifecycle, borrowed_child_validity */
static void call_json_pointer_get(payload in) {
    if (!root) return;
    struct json_object *res = NULL;
    if (!preqed_call("json_pointer_get")) return;
    int rc = json_pointer_get(root, cstr(str, sizeof str, in), &res);
    take_child("json_pointer_get", rc == 0 ? res : NULL);
}
/* ltl: root_lifecycle, borrowed_child_validity */
static void call_json_pointer_getf(payload in) {
    if (!root) return;
    struct json_object *res = NULL;
    if (!preqed_call("json_pointer_getf")) return;
    int rc = json_pointer_getf(root, &res, "%s", cstr(str, sizeof str, in));
    take_child("json_pointer_getf", rc == 0 ? res : NULL);
}

/* object access */
/* ltl: root_lifecycle, borrowed_child_validity */
static void call_json_object_object_get(payload in) {
    if (!root_is(json_type_object)) return;
    if (!preqed_call("json_object_object_get")) return;
    take_child("json_object_object_get", json_object_object_get(root, cstr(key, sizeof key, in)));
}
/* ltl: root_lifecycle, borrowed_child_validity */
static void call_json_object_object_get_ex(payload in) {
    if (!root_is(json_type_object)) return;
    struct json_object *res = NULL;
    if (!preqed_call("json_object_object_get_ex")) return;
    json_bool found = json_object_object_get_ex(root, cstr(key, sizeof key, in), &res);
    take_child("json_object_object_get_ex", found ? res : NULL);
}
/* ltl: root_lifecycle */
static void call_json_object_object_length(payload in) {
    (void)in;
    if (!root_is(json_type_object)) return;
    REPORT(json_object_object_length, json_object_object_length(root), rc >= 0);
}
/* ltl: root_lifecycle, borrowed_child_validity, iterator_validity */
static void call_json_object_object_del(payload in) {
    if (!root_is(json_type_object)) return;
    root_mutated();
    REPORT_VOID(json_object_object_del, json_object_object_del(root, cstr(key, sizeof key, in)));
}
/* ltl: root_lifecycle */
static void call_json_object_get_object(payload in) {
    (void)in;
    if (!root) return;
    if (!preqed_call("json_object_get_object")) return;
    preqed_result("json_object_get_object", json_object_get_object(root) != NULL);
}

/* array access */
/* ltl: root_lifecycle */
static void call_json_object_array_length(payload in) {
    (void)in;
    if (!root_is(json_type_array)) return;
    REPORT_VOID(json_object_array_length, json_object_array_length(root));
}
/* ltl: root_lifecycle, borrowed_child_validity */
static void call_json_object_array_get_idx(payload in) {
    if (!root_is(json_type_array)) return;
    if (!preqed_call("json_object_array_get_idx")) return;
    take_child("json_object_array_get_idx", json_object_array_get_idx(root, byte(in, 0)));
}
/* ltl: root_lifecycle, borrowed_child_validity, iterator_validity */
static void call_json_object_array_del_idx(payload in) {
    if (!root_is(json_type_array)) return;
    root_mutated();
    REPORT(json_object_array_del_idx, json_object_array_del_idx(root, byte(in, 0), 1 + byte(in, 1)), rc == 0);
}
/* ltl: root_lifecycle */
static void call_json_object_array_shrink(payload in) {
    if (!root_is(json_type_array)) return;
    REPORT(json_object_array_shrink, json_object_array_shrink(root, byte(in, 0)), rc == 0);
}

static int compare_int64(const void *a, const void *b) {
    struct json_object *const *x = a;
    struct json_object *const *y = b;
    int64_t u = json_object_get_int64(*x), v = json_object_get_int64(*y);
    return (u > v) - (u < v);
}
/* ltl: root_lifecycle, borrowed_child_validity, iterator_validity */
static void call_json_object_array_sort(payload in) {
    (void)in;
    if (!root_is(json_type_array)) return;
    root_mutated();
    REPORT_VOID(json_object_array_sort, json_object_array_sort(root, compare_int64));
}
/* ltl: root_lifecycle, item_ownership, borrowed_child_validity */
static void call_json_object_array_bsearch(payload in) {
    (void)in;
    if (!root_is(json_type_array) || !item) return;
    if (!preqed_call("json_object_array_bsearch")) return;
    take_child("json_object_array_bsearch", json_object_array_bsearch(item, root, compare_int64));
}
/* ltl: root_lifecycle */
static void call_json_object_get_array(payload in) {
    (void)in;
    if (!root) return;
    if (!preqed_call("json_object_get_array")) return;
    preqed_result("json_object_get_array", json_object_get_array(root) != NULL);
}

/* child inspection and mutation */
/* ltl: borrowed_child_validity */
static void call_json_object_get_type(payload in) {
    (void)in;
    if (!child) return;
    REPORT_VOID(json_object_get_type, json_object_get_type(child));
}
/* ltl: borrowed_child_validity */
static void call_json_object_is_type(payload in) {
    if (!child) return;
    REPORT_VOID(json_object_is_type, json_object_is_type(child, (enum json_type)(byte(in, 0) % 8)));  /* json_type_null..json_type_string, plus one out-of-range value */
}

#define GETTER(api) \
    static void call_##api(payload in) { \
        (void)in; \
        if (!child) return; \
        REPORT_VOID(api, api(child)); \
    }
/* ltl: borrowed_child_validity */
GETTER(json_object_get_boolean)
/* ltl: borrowed_child_validity */
GETTER(json_object_get_int)
/* ltl: borrowed_child_validity */
GETTER(json_object_get_int64)
/* ltl: borrowed_child_validity */
GETTER(json_object_get_uint64)
/* ltl: borrowed_child_validity */
GETTER(json_object_get_double)
/* ltl: borrowed_child_validity */
GETTER(json_object_get_string)
/* ltl: borrowed_child_validity */
GETTER(json_object_get_string_len)

#define SETTER(api, expr) \
    static void call_##api(payload in) { \
        if (!child) return; \
        REPORT(api, expr, rc == 1); \
    }
/* ltl: borrowed_child_validity */
SETTER(json_object_set_boolean, json_object_set_boolean(child, byte(in, 0) & 1))
/* ltl: borrowed_child_validity */
SETTER(json_object_set_int, json_object_set_int(child, (int32_t)integer(in)))
/* ltl: borrowed_child_validity */
SETTER(json_object_set_int64, json_object_set_int64(child, integer(in)))
/* ltl: borrowed_child_validity */
SETTER(json_object_set_uint64, json_object_set_uint64(child, (uint64_t)integer(in)))
/* ltl: borrowed_child_validity */
SETTER(json_object_set_double, json_object_set_double(child, number(in)))
/* ltl: borrowed_child_validity */
SETTER(json_object_set_string, json_object_set_string(child, cstr(str, sizeof str, in)))
/* ltl: borrowed_child_validity */
SETTER(json_object_set_string_len, json_object_set_string_len(child, (const char *)in.p, (int)in.n))
/* ltl: borrowed_child_validity */
SETTER(json_object_int_inc, json_object_int_inc(child, integer(in)))

/* whole-tree operations */
/* ltl: root_lifecycle, item_ownership */
static void call_json_object_equal(payload in) {
    (void)in;
    if (!root || !item) return;
    REPORT_VOID(json_object_equal, json_object_equal(root, item));
}

static int visitor(struct json_object *jso, int flags, struct json_object *parent, const char *key_name,
                   size_t *index, void *arg) {
    (void)jso;
    (void)flags;
    (void)parent;
    (void)key_name;
    (void)index;
    /* every return value json_c_visit's callback may give (json_visit.h); the payload picks one */
    static const int outcomes[] = { JSON_C_VISIT_RETURN_CONTINUE, JSON_C_VISIT_RETURN_SKIP,
                                    JSON_C_VISIT_RETURN_POP, JSON_C_VISIT_RETURN_STOP, JSON_C_VISIT_RETURN_ERROR };
    return outcomes[*(uint8_t *)arg % 5];
}
/* ltl: root_lifecycle */
static void call_json_c_visit(payload in) {
    if (!root) return;
    uint8_t choice = byte(in, 0);
    REPORT(json_c_visit, json_c_visit(root, 0, visitor, &choice), rc >= 0);
}
/* ltl: root_lifecycle, item_ownership, borrowed_child_validity, iterator_validity */
static void call_json_patch_apply(payload in) {
    (void)in;
    if (!root || !item || item_shared || !json_object_is_type(item, json_type_array)) return;
    struct json_patch_error err;
    root_mutated();
    REPORT(json_patch_apply, json_patch_apply(NULL, item, &root, &err), rc == 0);
}

/* iterator over root object */

static void call_json_object_iter_init_default(payload in) {
    (void)in;
    REPORT_VOID(json_object_iter_init_default, json_object_iter_init_default());
}
/* ltl: root_lifecycle, iterator_validity */
static void call_json_object_iter_begin(payload in) {
    (void)in;
    if (!root_is(json_type_object)) return;
    if (!preqed_call("json_object_iter_begin")) return;
    iter = json_object_iter_begin(root);
    iter_end = json_object_iter_end(root);
    preqed_result("json_object_iter_begin", 1);
    iter_valid = 1;
}
/* ltl: root_lifecycle */
static void call_json_object_iter_end(payload in) {
    (void)in;
    if (!root_is(json_type_object)) return;
    if (!preqed_call("json_object_iter_end")) return;
    iter_end = json_object_iter_end(root);
    preqed_result("json_object_iter_end", 1);
}
/* ltl: iterator_validity */
static void call_json_object_iter_equal(payload in) {
    (void)in;
    if (!iter_valid) return;
    REPORT_VOID(json_object_iter_equal, json_object_iter_equal(&iter, &iter_end));
}
/* ltl: iterator_validity */
static void call_json_object_iter_next(payload in) {
    (void)in;
    if (!iter_valid || json_object_iter_equal(&iter, &iter_end)) return;
    REPORT_VOID(json_object_iter_next, json_object_iter_next(&iter));
}
/* ltl: iterator_validity */
static void call_json_object_iter_peek_name(payload in) {
    (void)in;
    if (!iter_valid || json_object_iter_equal(&iter, &iter_end)) return;
    if (!preqed_call("json_object_iter_peek_name")) return;
    preqed_result("json_object_iter_peek_name", json_object_iter_peek_name(&iter) != NULL);
}
/* ltl: borrowed_child_validity, iterator_validity */
static void call_json_object_iter_peek_value(payload in) {
    (void)in;
    if (!iter_valid || json_object_iter_equal(&iter, &iter_end)) return;
    if (!preqed_call("json_object_iter_peek_value")) return;
    take_child("json_object_iter_peek_value", json_object_iter_peek_value(&iter));
}

/* printbuf */
/* ltl: printbuf_lifecycle */
static void call_printbuf_new(payload in) {
    (void)in;
    if (pb) return;
    if (!preqed_call("printbuf_new")) return;
    pb = printbuf_new();
    preqed_result("printbuf_new", pb != NULL);
}
/* ltl: printbuf_lifecycle */
static void call_printbuf_memappend(payload in) {
    if (!pb) return;
    REPORT(printbuf_memappend, printbuf_memappend(pb, (const char *)in.p, (int)in.n), rc >= 0);
}
/* ltl: printbuf_lifecycle */
static void call_printbuf_memset(payload in) {
    if (!pb) return;
    REPORT(printbuf_memset, printbuf_memset(pb, byte(in, 0) & 1 ? -1 : byte(in, 1), byte(in, 2), byte(in, 3)), rc >= 0);
}
/* ltl: printbuf_lifecycle */
static void call_sprintbuf(payload in) {
    if (!pb) return;
    REPORT(sprintbuf, sprintbuf(pb, "%s:%d", cstr(str, sizeof str, in), (int)in.n), rc >= 0);
}
/* ltl: printbuf_lifecycle */
static void call_printbuf_reset(payload in) {
    (void)in;
    if (!pb) return;
    REPORT_VOID(printbuf_reset, printbuf_reset(pb));
}
/* ltl: printbuf_lifecycle */
static void call_printbuf_free(payload in) {
    (void)in;
    if (!pb) return;
    REPORT_VOID(printbuf_free, printbuf_free(pb));
    pb = NULL;
}

/* linkhash table with pointer keys (linkhash.h) */
/* ltl: lh_table_lifecycle */
static void call_lh_kptr_table_new(payload in) {
    if (table) return;
    if (!preqed_call("lh_kptr_table_new")) return;
    table = lh_kptr_table_new(1 + byte(in, 0) % 64, NULL);  /* initial size 1..64; no free_fn: keys and values are static */
    preqed_result("lh_kptr_table_new", table != NULL);
}
/* ltl: lh_table_lifecycle */
static void call_lh_table_insert(payload in) {
    if (!table) return;
    REPORT(lh_table_insert, lh_table_insert(table, &ptr_keys[byte(in, 0) % 16], str2), rc == 0);
}
/* ltl: lh_table_lifecycle */
static void call_lh_entry_prev(payload in) {
    if (!table) return;
    struct lh_entry *e = lh_table_lookup_entry(table, &ptr_keys[byte(in, 0) % 16]);
    if (!e) return;
    REPORT_VOID(lh_entry_prev, lh_entry_prev(e));
}
/* ltl: lh_table_lifecycle */
static void call_lh_table_free(payload in) {
    (void)in;
    if (!table) return;
    REPORT_VOID(lh_table_free, lh_table_free(table));
    table = NULL;
}

/* array_list (arraylist.h) */

static void list_free_fn(void *data) { (void)data; }
/* ltl: array_list_lifecycle */
static void call_array_list_new(payload in) {
    (void)in;
    if (list) return;
    if (!preqed_call("array_list_new")) return;
    list = array_list_new(list_free_fn);
    preqed_result("array_list_new", list != NULL);
}
/* ltl: array_list_lifecycle */
static void call_array_list_free(payload in) {
    (void)in;
    if (!list) return;
    REPORT_VOID(array_list_free, array_list_free(list));
    list = NULL;
}

/* globals: struct size, string hash, debug switches and messages (json_object.h, linkhash.h, debug.h) */

static void call_json_c_object_sizeof(payload in) {
    (void)in;
    REPORT(json_c_object_sizeof, (int)json_c_object_sizeof(), rc > 0);
}
static void call_json_global_set_string_hash(payload in) {
    /* JSON_C_STR_HASH_DFLT 0, JSON_C_STR_HASH_PERLLIKE 1; 2 is the documented "-1 if parameter was invalid" case */
    REPORT(json_global_set_string_hash, json_global_set_string_hash(byte(in, 0) % 3), rc == 0);
}
static void call_mc_set_debug(payload in) {
    debug_level = byte(in, 0) & 1;
    REPORT_VOID(mc_set_debug, mc_set_debug(debug_level));
}
static void call_mc_get_debug(payload in) {
    (void)in;
    REPORT(mc_get_debug, mc_get_debug(), rc == debug_level);
}
static void call_mc_set_syslog(payload in) {
    REPORT_VOID(mc_set_syslog, mc_set_syslog(byte(in, 0) & 1));
}
/* mc_info/mc_error print to stderr (or syslog after mc_set_syslog(1)): the message is empty so the fuzzer log stays readable */
static void call_mc_info(payload in) {
    (void)in;
    REPORT_VOID(mc_info, mc_info("%s", ""));
}
static void call_mc_error(payload in) {
    (void)in;
    REPORT_VOID(mc_error, mc_error("%s", ""));
}

/* dispatch */

static void (*const api[])(payload) = {
    call_json_c_version, call_json_c_version_num, call_json_c_set_serialization_double_format, call_json_type_to_name,
    call_json_tokener_parse, call_json_tokener_parse_verbose, call_json_tokener_new, call_json_tokener_new_ex,
    call_json_tokener_set_flags, call_json_tokener_parse_ex, call_json_tokener_get_error, call_json_tokener_error_desc,
    call_json_tokener_get_parse_end, call_json_tokener_reset, call_json_tokener_free,
    call_json_object_from_file, call_json_object_from_fd, call_json_object_from_fd_ex, call_json_object_to_file,
    call_json_object_to_file_ext, call_json_object_to_fd, call_json_util_get_last_err,
    call_json_parse_int64, call_json_parse_uint64, call_json_parse_double,
    call_json_object_to_json_string, call_json_object_to_json_string_ext, call_json_object_to_json_string_length,
    call_json_object_set_serializer, call_json_object_set_userdata, call_json_object_get_userdata,
    call_json_object_double_to_json_string,
    call_json_object_put, call_json_object_get,
    call_json_object_new_object, call_json_object_new_array, call_json_object_new_null, call_json_object_new_array_ext,
    call_json_object_new_boolean, call_json_object_new_int, call_json_object_new_int64, call_json_object_new_uint64,
    call_json_object_new_double, call_json_object_new_double_s, call_json_object_new_string,
    call_json_object_new_string_len, call_json_object_deep_copy,
    call_json_object_object_add, call_json_object_object_add_ex, call_json_object_array_add,
    call_json_object_array_put_idx, call_json_object_array_insert_idx, call_json_object_array_put_with_idx_limit_cb,
    call_json_pointer_set, call_json_pointer_setf, call_json_pointer_set_with_limit_index, call_json_pointer_set_with_cb,
    call_json_pointer_get, call_json_pointer_getf,
    call_json_object_object_get, call_json_object_object_get_ex, call_json_object_object_length,
    call_json_object_object_del, call_json_object_get_object,
    call_json_object_array_length, call_json_object_array_get_idx, call_json_object_array_del_idx,
    call_json_object_array_shrink, call_json_object_array_sort, call_json_object_array_bsearch, call_json_object_get_array,
    call_json_object_get_type, call_json_object_is_type,
    call_json_object_get_boolean, call_json_object_get_int, call_json_object_get_int64, call_json_object_get_uint64,
    call_json_object_get_double, call_json_object_get_string, call_json_object_get_string_len,
    call_json_object_set_boolean, call_json_object_set_int, call_json_object_set_int64, call_json_object_set_uint64,
    call_json_object_set_double, call_json_object_set_string, call_json_object_set_string_len, call_json_object_int_inc,
    call_json_object_equal, call_json_c_visit, call_json_patch_apply,
    call_json_object_iter_init_default, call_json_object_iter_begin, call_json_object_iter_end,
    call_json_object_iter_equal, call_json_object_iter_next, call_json_object_iter_peek_name,
    call_json_object_iter_peek_value,
    call_printbuf_new, call_printbuf_memappend, call_printbuf_memset, call_sprintbuf, call_printbuf_reset,
    call_printbuf_free,
    call_lh_kptr_table_new, call_lh_table_insert, call_lh_entry_prev, call_lh_table_free,
    call_array_list_new, call_array_list_free,
    call_json_c_object_sizeof, call_json_global_set_string_hash,
    call_mc_set_debug, call_mc_get_debug, call_mc_set_syslog, call_mc_info, call_mc_error,
};

#define API_COUNT (sizeof api / sizeof api[0])

static void cleanup(void) {
    json_object_put(root);
    json_object_put(item);
    if (tok) json_tokener_free(tok);
    if (pb) printbuf_free(pb);
    if (table) lh_table_free(table);
    if (list) array_list_free(list);
    root = item = child = NULL;
    tok = NULL;
    tok_failed = 0;
    pb = NULL;
    table = NULL;
    list = NULL;
    item_shared = iter_valid = 0;
    json_c_set_serialization_double_format(NULL, JSON_C_OPTION_GLOBAL);
    json_global_set_string_hash(JSON_C_STR_HASH_DFLT);
    mc_set_debug(0);
    mc_set_syslog(0);
    debug_level = 0;
    unlink(FILE_PATH);
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
