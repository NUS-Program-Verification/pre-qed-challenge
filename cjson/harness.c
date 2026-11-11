#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <cJSON.h>
#include <cJSON_Utils.h>
#include "preqed_ltl.h"

typedef struct {
    const uint8_t *p;
    size_t n;
} payload;

static cJSON *root;   /* owned tree, produced by parsing */
static cJSON *item;   /* owned loose node, waiting to be attached */
static cJSON *patch;  /* owned patch document */
static cJSON *child;  /* borrowed pointer into root */
static int item_referenced; /* root holds a reference node pointing at item */
/* cJSON_Utils sorting (SortObject, and compare_json inside patch generation and
 * the patch "test" op) leaves child->prev NULL; add_item_to_array then reports
 * success without appending, so items would leak. No adds after a sort. */
static int sorted;
static char *text;    /* owned buffer from print or cJSON_malloc */

/* NUL-terminated copies of payload bytes: object keys (255 chars), string values (4095 chars) */
static char key[256];
static char str[4096];
/* backing store for cJSON_CreateStringReference: the item points into it, so it must outlive the item */
static char str2[4096];
/* 64 KiB: cJSON_PrintPreallocated target and the 16 x 256-byte strings of cJSON_CreateStringArray */
static char scratch[1 << 16];

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
static double number(payload in) {
    double d = 0;
    memcpy(&d, in.p, in.n < sizeof d ? in.n : sizeof d);
    return d;
}
static int is_reference(const cJSON *node) { return node && (node->type & cJSON_IsReference); }
static int is_container(const cJSON *node) { return cJSON_IsArray(node) || cJSON_IsObject(node); }
static int is_direct_child(const cJSON *node) {
    for (const cJSON *c = root ? root->child : NULL; c; c = c->next)
        if (c == node) return 1;
    return 0;
}

/* root is about to change: borrowed pointers into it and reference nodes onto it die */
static void root_mutated(void) {
    child = NULL;
    if (is_reference(item)) {
        cJSON_Delete(item);
        item = NULL;
    }
}

#define REPORT(api, expr, ok_cond) \
    do { if (preqed_call(#api)) { int rc = (expr); preqed_result(#api, (ok_cond)); } } while (0)
#define REPORT_VOID(api, expr) \
    do { if (preqed_call(#api)) { expr; preqed_result(#api, 1); } } while (0)

static void take_root(const char *api, cJSON *tree) {
    preqed_result(api, tree != NULL);
    root = tree;
}
static void take_item(const char *api, cJSON *node) {
    preqed_result(api, node != NULL);
    item = node;
}
static void take_patch(const char *api, cJSON *node) {
    preqed_result(api, node != NULL);
    patch = node;
}
static void take_child(const char *api, cJSON *node) {
    preqed_result(api, node != NULL);
    child = node;
}
static void take_text(const char *api, char *buf) {
    preqed_result(api, buf != NULL);
    text = buf;
}

/* hooks and version */

static void *hook_malloc(size_t n) { return malloc(n); }
static void hook_free(void *p) { free(p); }

static void call_cJSON_Version(payload in) {
    (void)in;
    if (!preqed_call("cJSON_Version")) return;
    preqed_result("cJSON_Version", cJSON_Version() != NULL);
}

static void call_cJSON_InitHooks(payload in) {
    cJSON_Hooks hooks = { hook_malloc, hook_free };
    REPORT_VOID(cJSON_InitHooks, cJSON_InitHooks(byte(in, 0) & 1 ? &hooks : NULL));
}

/* parse: produces root */
/* ltl: root_lifecycle */
static void call_cJSON_Parse(payload in) {
    if (root) return;
    if (!preqed_call("cJSON_Parse")) return;
    take_root("cJSON_Parse", cJSON_Parse(cstr(str, sizeof str, in)));
}
/* ltl: root_lifecycle */
static void call_cJSON_ParseWithLength(payload in) {
    if (root) return;
    if (!preqed_call("cJSON_ParseWithLength")) return;
    take_root("cJSON_ParseWithLength", cJSON_ParseWithLength((const char *)in.p, in.n));
}
/* ltl: root_lifecycle */
static void call_cJSON_ParseWithOpts(payload in) {
    if (root) return;
    const char *end = NULL;
    if (!preqed_call("cJSON_ParseWithOpts")) return;
    take_root("cJSON_ParseWithOpts",
              cJSON_ParseWithOpts(cstr(str, sizeof str, rest(in, 1)), byte(in, 0) & 2 ? &end : NULL, byte(in, 0) & 1));
}
/* ltl: root_lifecycle */
static void call_cJSON_ParseWithLengthOpts(payload in) {
    if (root) return;
    const char *end = NULL;
    payload body = rest(in, 1);
    if (!preqed_call("cJSON_ParseWithLengthOpts")) return;
    take_root("cJSON_ParseWithLengthOpts",
              cJSON_ParseWithLengthOpts((const char *)body.p, body.n, byte(in, 0) & 2 ? &end : NULL, byte(in, 0) & 1));
}

static void call_cJSON_GetErrorPtr(payload in) {
    (void)in;
    if (!preqed_call("cJSON_GetErrorPtr")) return;
    cJSON_GetErrorPtr();
    preqed_result("cJSON_GetErrorPtr", 1);
}

/* print: produces text */
/* ltl: root_lifecycle, print_buffer_free */
static void call_cJSON_Print(payload in) {
    (void)in;
    if (!root || text) return;
    if (!preqed_call("cJSON_Print")) return;
    take_text("cJSON_Print", cJSON_Print(root));
}
/* ltl: root_lifecycle, print_buffer_free */
static void call_cJSON_PrintUnformatted(payload in) {
    (void)in;
    if (!root || text) return;
    if (!preqed_call("cJSON_PrintUnformatted")) return;
    take_text("cJSON_PrintUnformatted", cJSON_PrintUnformatted(root));
}
/* ltl: root_lifecycle, print_buffer_free */
static void call_cJSON_PrintBuffered(payload in) {
    if (!root || text) return;
    if (!preqed_call("cJSON_PrintBuffered")) return;
    /* prebuffer 0..4080 bytes (0 and small values force the realloc path), fmt flag */
    take_text("cJSON_PrintBuffered", cJSON_PrintBuffered(root, byte(in, 0) * 16, byte(in, 1) & 1));
}
/* ltl: root_lifecycle */
static void call_cJSON_PrintPreallocated(payload in) {
    if (!root) return;
    /* 1..16321 bytes, always <= sizeof scratch; small lengths exercise the too-short failure */
    int length = 1 + byte(in, 0) * 64;
    REPORT(cJSON_PrintPreallocated, cJSON_PrintPreallocated(root, scratch, length, byte(in, 1) & 1), rc);
}

static void call_cJSON_Minify(payload in) {
    REPORT_VOID(cJSON_Minify, cJSON_Minify((char *)cstr(str, sizeof str, in)));
}

/* delete root */
/* ltl: root_lifecycle, borrowed_child_validity */
static void call_cJSON_Delete(payload in) {
    (void)in;
    if (!root) return;
    root_mutated();
    REPORT_VOID(cJSON_Delete, cJSON_Delete(root));
    root = NULL;
    item_referenced = sorted = 0;
}

/* lookup: produces child */
/* ltl: root_lifecycle */
static void call_cJSON_GetArraySize(payload in) {
    (void)in;
    if (!root) return;
    REPORT(cJSON_GetArraySize, cJSON_GetArraySize(root), rc >= 0);
}
/* ltl: root_lifecycle, borrowed_child_validity */
static void call_cJSON_GetArrayItem(payload in) {
    if (!root) return;
    if (!preqed_call("cJSON_GetArrayItem")) return;
    take_child("cJSON_GetArrayItem", cJSON_GetArrayItem(root, byte(in, 0)));
}
/* ltl: root_lifecycle, borrowed_child_validity */
static void call_cJSON_GetObjectItem(payload in) {
    if (!root) return;
    if (!preqed_call("cJSON_GetObjectItem")) return;
    take_child("cJSON_GetObjectItem", cJSON_GetObjectItem(root, cstr(key, sizeof key, in)));
}
/* ltl: root_lifecycle, borrowed_child_validity */
static void call_cJSON_GetObjectItemCaseSensitive(payload in) {
    if (!root) return;
    if (!preqed_call("cJSON_GetObjectItemCaseSensitive")) return;
    take_child("cJSON_GetObjectItemCaseSensitive", cJSON_GetObjectItemCaseSensitive(root, cstr(key, sizeof key, in)));
}
/* ltl: root_lifecycle */
static void call_cJSON_HasObjectItem(payload in) {
    if (!root) return;
    REPORT(cJSON_HasObjectItem, cJSON_HasObjectItem(root, cstr(key, sizeof key, in)), rc);
}
/* ltl: root_lifecycle, borrowed_child_validity */
static void call_cJSONUtils_GetPointer(payload in) {
    if (!root) return;
    if (!preqed_call("cJSONUtils_GetPointer")) return;
    take_child("cJSONUtils_GetPointer", cJSONUtils_GetPointer(root, cstr(str, sizeof str, in)));
}
/* ltl: root_lifecycle, borrowed_child_validity */
static void call_cJSONUtils_GetPointerCaseSensitive(payload in) {
    if (!root) return;
    if (!preqed_call("cJSONUtils_GetPointerCaseSensitive")) return;
    take_child("cJSONUtils_GetPointerCaseSensitive", cJSONUtils_GetPointerCaseSensitive(root, cstr(str, sizeof str, in)));
}

/* inspect child */

#define PREDICATE(api) \
    static void call_##api(payload in) { \
        (void)in; \
        if (!child) return; \
        REPORT_VOID(api, api(child)); \
    }
/* ltl: borrowed_child_validity */
PREDICATE(cJSON_IsInvalid)
/* ltl: borrowed_child_validity */
PREDICATE(cJSON_IsFalse)
/* ltl: borrowed_child_validity */
PREDICATE(cJSON_IsTrue)
/* ltl: borrowed_child_validity */
PREDICATE(cJSON_IsBool)
/* ltl: borrowed_child_validity */
PREDICATE(cJSON_IsNull)
/* ltl: borrowed_child_validity */
PREDICATE(cJSON_IsNumber)
/* ltl: borrowed_child_validity */
PREDICATE(cJSON_IsString)
/* ltl: borrowed_child_validity */
PREDICATE(cJSON_IsArray)
/* ltl: borrowed_child_validity */
PREDICATE(cJSON_IsObject)
/* ltl: borrowed_child_validity */
PREDICATE(cJSON_IsRaw)
/* ltl: borrowed_child_validity */
static void call_cJSON_GetStringValue(payload in) {
    (void)in;
    if (!child) return;
    REPORT_VOID(cJSON_GetStringValue, cJSON_GetStringValue(child));
}
/* ltl: borrowed_child_validity */
static void call_cJSON_GetNumberValue(payload in) {
    (void)in;
    if (!child) return;
    REPORT_VOID(cJSON_GetNumberValue, cJSON_GetNumberValue(child));
}
/* ltl: borrowed_child_validity */
static void call_cJSON_SetNumberHelper(payload in) {
    if (!child) return;
    REPORT_VOID(cJSON_SetNumberHelper, cJSON_SetNumberHelper(child, number(in)));
}
/* ltl: borrowed_child_validity */
static void call_cJSON_SetValuestring(payload in) {
    if (!child) return;
    if (!preqed_call("cJSON_SetValuestring")) return;
    preqed_result("cJSON_SetValuestring", cJSON_SetValuestring(child, cstr(str, sizeof str, in)) != NULL);
}
/* ltl: root_lifecycle, borrowed_child_validity */
static void call_cJSONUtils_FindPointerFromObjectTo(payload in) {
    (void)in;
    if (!root || !child) return;
    if (!preqed_call("cJSONUtils_FindPointerFromObjectTo")) return;
    char *pointer = cJSONUtils_FindPointerFromObjectTo(root, child);
    preqed_result("cJSONUtils_FindPointerFromObjectTo", pointer != NULL);
    cJSON_free(pointer);
}

/* create: produces item */

#define CREATE(api, ...) \
    static void call_##api(payload in) { \
        (void)in; \
        if (item) return; \
        if (!preqed_call(#api)) return; \
        take_item(#api, api(__VA_ARGS__)); \
    }
/* ltl: item_ownership */
CREATE(cJSON_CreateNull)
/* ltl: item_ownership */
CREATE(cJSON_CreateTrue)
/* ltl: item_ownership */
CREATE(cJSON_CreateFalse)
/* ltl: item_ownership */
CREATE(cJSON_CreateArray)
/* ltl: item_ownership */
CREATE(cJSON_CreateObject)
/* ltl: item_ownership */
CREATE(cJSON_CreateBool, byte(in, 0) & 1)
/* ltl: item_ownership */
CREATE(cJSON_CreateNumber, number(in))
/* ltl: item_ownership */
CREATE(cJSON_CreateString, cstr(str, sizeof str, in))
/* ltl: item_ownership */
CREATE(cJSON_CreateRaw, cstr(str, sizeof str, in))
/* ltl: item_ownership */
CREATE(cJSON_CreateStringReference, cstr(str2, sizeof str2, in))
/* ltl: root_lifecycle, item_ownership */
static void call_cJSON_CreateObjectReference(payload in) {
    (void)in;
    if (item || !root || !cJSON_IsObject(root)) return;
    if (!preqed_call("cJSON_CreateObjectReference")) return;
    take_item("cJSON_CreateObjectReference", cJSON_CreateObjectReference(root->child));
}
/* ltl: root_lifecycle, item_ownership */
static void call_cJSON_CreateArrayReference(payload in) {
    (void)in;
    if (item || !root || !cJSON_IsArray(root)) return;
    if (!preqed_call("cJSON_CreateArrayReference")) return;
    take_item("cJSON_CreateArrayReference", cJSON_CreateArrayReference(root->child));
}
/* ltl: item_ownership */
static void call_cJSON_CreateIntArray(payload in) {
    if (item) return;
    /* up to 64 numbers read straight from the payload bytes */
    int values[64];
    int count = (int)(in.n / sizeof values[0]) % 65;
    memcpy(values, in.p, count * sizeof values[0]);
    if (!preqed_call("cJSON_CreateIntArray")) return;
    take_item("cJSON_CreateIntArray", cJSON_CreateIntArray(values, count));
}
/* ltl: item_ownership */
static void call_cJSON_CreateFloatArray(payload in) {
    if (item) return;
    float values[64];
    int count = (int)(in.n / sizeof values[0]) % 65;
    memcpy(values, in.p, count * sizeof values[0]);
    if (!preqed_call("cJSON_CreateFloatArray")) return;
    take_item("cJSON_CreateFloatArray", cJSON_CreateFloatArray(values, count));
}
/* ltl: item_ownership */
static void call_cJSON_CreateDoubleArray(payload in) {
    if (item) return;
    double values[64];
    int count = (int)(in.n / sizeof values[0]) % 65;
    memcpy(values, in.p, count * sizeof values[0]);
    if (!preqed_call("cJSON_CreateDoubleArray")) return;
    take_item("cJSON_CreateDoubleArray", cJSON_CreateDoubleArray(values, count));
}
/* ltl: item_ownership */
static void call_cJSON_CreateStringArray(payload in) {
    if (item) return;
    /* up to 16 NUL-separated strings from the payload, each copied into a 256-byte slice of scratch */
    const char *strings[16];
    int count = 0;
    payload cur = in;
    while (count < 16 && cur.n) {
        const uint8_t *nul = memchr(cur.p, 0, cur.n);
        size_t len = nul ? (size_t)(nul - cur.p) : cur.n;
        strings[count] = cstr(scratch + count * 256, 256, (payload){ cur.p, len });
        count++;
        cur = rest(cur, len + 1);
    }
    if (!preqed_call("cJSON_CreateStringArray")) return;
    take_item("cJSON_CreateStringArray", cJSON_CreateStringArray(strings, count));
}
/* ltl: root_lifecycle, item_ownership */
static void call_cJSON_Duplicate(payload in) {
    if (item || !root) return;
    if (!preqed_call("cJSON_Duplicate")) return;
    take_item("cJSON_Duplicate", cJSON_Duplicate(root, byte(in, 0) & 1));
}

/* attach item to root: ownership moves on success */

#define ATTACH(api, kind, expr) \
    do { \
        if (!root || !kind(root) || !item || is_reference(item) || item_referenced || sorted) return; \
        root_mutated(); \
        if (!preqed_call(#api)) return; \
        int ok = expr; \
        preqed_result(#api, ok); \
        if (ok) item = NULL; \
    } while (0)
/* ltl: root_lifecycle, item_ownership, borrowed_child_validity */
static void call_cJSON_AddItemToArray(payload in) {
    (void)in;
    ATTACH(cJSON_AddItemToArray, cJSON_IsArray, cJSON_AddItemToArray(root, item));
}
/* ltl: root_lifecycle, item_ownership, borrowed_child_validity */
static void call_cJSON_AddItemToObject(payload in) {
    ATTACH(cJSON_AddItemToObject, cJSON_IsObject, cJSON_AddItemToObject(root, cstr(key, sizeof key, in), item));
}
/* ltl: root_lifecycle, item_ownership, borrowed_child_validity */
static void call_cJSON_AddItemToObjectCS(payload in) {
    ATTACH(cJSON_AddItemToObjectCS, cJSON_IsObject, cJSON_AddItemToObjectCS(root, cstr(key, sizeof key, in), item));
}
/* ltl: root_lifecycle, item_ownership, borrowed_child_validity */
static void call_cJSON_InsertItemInArray(payload in) {
    ATTACH(cJSON_InsertItemInArray, cJSON_IsArray, cJSON_InsertItemInArray(root, byte(in, 0), item));
}
/* ltl: root_lifecycle, item_ownership, borrowed_child_validity */
static void call_cJSON_ReplaceItemInArray(payload in) {
    ATTACH(cJSON_ReplaceItemInArray, cJSON_IsArray, cJSON_ReplaceItemInArray(root, byte(in, 0), item));
}
/* ltl: root_lifecycle, item_ownership, borrowed_child_validity */
static void call_cJSON_ReplaceItemInObject(payload in) {
    ATTACH(cJSON_ReplaceItemInObject, cJSON_IsObject, cJSON_ReplaceItemInObject(root, cstr(key, sizeof key, in), item));
}
/* ltl: root_lifecycle, item_ownership, borrowed_child_validity */
static void call_cJSON_ReplaceItemInObjectCaseSensitive(payload in) {
    ATTACH(cJSON_ReplaceItemInObjectCaseSensitive, cJSON_IsObject,
           cJSON_ReplaceItemInObjectCaseSensitive(root, cstr(key, sizeof key, in), item));
}
/* ltl: root_lifecycle, item_ownership, borrowed_child_validity */
static void call_cJSON_ReplaceItemViaPointer(payload in) {
    (void)in;
    if (!is_direct_child(child)) return;
    ATTACH(cJSON_ReplaceItemViaPointer, is_container, cJSON_ReplaceItemViaPointer(root, child, item));
}

/* attach a reference to item: item stays owned here, outlives root */
/* ltl: root_lifecycle, item_ownership, borrowed_child_validity */
static void call_cJSON_AddItemReferenceToArray(payload in) {
    (void)in;
    if (!root || !cJSON_IsArray(root) || !item || is_reference(item) || sorted) return;
    root_mutated();
    if (!preqed_call("cJSON_AddItemReferenceToArray")) return;
    int ok = cJSON_AddItemReferenceToArray(root, item);
    preqed_result("cJSON_AddItemReferenceToArray", ok);
    item_referenced |= ok;
}
/* ltl: root_lifecycle, item_ownership, borrowed_child_validity */
static void call_cJSON_AddItemReferenceToObject(payload in) {
    if (!root || !cJSON_IsObject(root) || !item || is_reference(item) || sorted) return;
    root_mutated();
    if (!preqed_call("cJSON_AddItemReferenceToObject")) return;
    int ok = cJSON_AddItemReferenceToObject(root, cstr(key, sizeof key, in), item);
    preqed_result("cJSON_AddItemReferenceToObject", ok);
    item_referenced |= ok;
}

/* add a fresh value to root: result is a borrowed child */

#define ADD_TO_OBJECT(api, args) \
    static void call_##api(payload in) { \
        if (!root || !cJSON_IsObject(root) || sorted) return; \
        root_mutated(); \
        const char *name = cstr(key, sizeof key, rest(in, 8)); \
        payload value = { in.p, in.n < 8 ? in.n : 8 };  /* first 8 bytes: the value, rest: the key */ \
        (void)value; \
        if (!preqed_call(#api)) return; \
        take_child(#api, api args); \
    }
/* ltl: root_lifecycle, borrowed_child_validity */
ADD_TO_OBJECT(cJSON_AddNullToObject, (root, name))
/* ltl: root_lifecycle, borrowed_child_validity */
ADD_TO_OBJECT(cJSON_AddTrueToObject, (root, name))
/* ltl: root_lifecycle, borrowed_child_validity */
ADD_TO_OBJECT(cJSON_AddFalseToObject, (root, name))
/* ltl: root_lifecycle, borrowed_child_validity */
ADD_TO_OBJECT(cJSON_AddObjectToObject, (root, name))
/* ltl: root_lifecycle, borrowed_child_validity */
ADD_TO_OBJECT(cJSON_AddArrayToObject, (root, name))
/* ltl: root_lifecycle, borrowed_child_validity */
ADD_TO_OBJECT(cJSON_AddBoolToObject, (root, name, byte(value, 0) & 1))
/* ltl: root_lifecycle, borrowed_child_validity */
ADD_TO_OBJECT(cJSON_AddNumberToObject, (root, name, number(value)))
/* ltl: root_lifecycle, borrowed_child_validity */
ADD_TO_OBJECT(cJSON_AddStringToObject, (root, name, cstr(str, sizeof str, value)))
/* ltl: root_lifecycle, borrowed_child_validity */
ADD_TO_OBJECT(cJSON_AddRawToObject, (root, name, cstr(str, sizeof str, value)))

/* detach from root: produces item */

#define DETACH(api, expr) \
    do { \
        if (!root || item) return; \
        if (!preqed_call(#api)) return; \
        cJSON *node = expr; \
        root_mutated(); \
        take_item(#api, node); \
    } while (0)
/* ltl: root_lifecycle, item_ownership, borrowed_child_validity */
static void call_cJSON_DetachItemFromArray(payload in) {
    DETACH(cJSON_DetachItemFromArray, cJSON_DetachItemFromArray(root, byte(in, 0)));
}
/* ltl: root_lifecycle, item_ownership, borrowed_child_validity */
static void call_cJSON_DetachItemFromObject(payload in) {
    DETACH(cJSON_DetachItemFromObject, cJSON_DetachItemFromObject(root, cstr(key, sizeof key, in)));
}
/* ltl: root_lifecycle, item_ownership, borrowed_child_validity */
static void call_cJSON_DetachItemFromObjectCaseSensitive(payload in) {
    DETACH(cJSON_DetachItemFromObjectCaseSensitive,
           cJSON_DetachItemFromObjectCaseSensitive(root, cstr(key, sizeof key, in)));
}
/* ltl: root_lifecycle, item_ownership, borrowed_child_validity */
static void call_cJSON_DetachItemViaPointer(payload in) {
    (void)in;
    if (!is_direct_child(child)) return;
    DETACH(cJSON_DetachItemViaPointer, cJSON_DetachItemViaPointer(root, child));
}

/* delete from root */
/* ltl: root_lifecycle, borrowed_child_validity */
static void call_cJSON_DeleteItemFromArray(payload in) {
    if (!root) return;
    root_mutated();
    REPORT_VOID(cJSON_DeleteItemFromArray, cJSON_DeleteItemFromArray(root, byte(in, 0)));
}
/* ltl: root_lifecycle, borrowed_child_validity */
static void call_cJSON_DeleteItemFromObject(payload in) {
    if (!root) return;
    root_mutated();
    REPORT_VOID(cJSON_DeleteItemFromObject, cJSON_DeleteItemFromObject(root, cstr(key, sizeof key, in)));
}
/* ltl: root_lifecycle, borrowed_child_validity */
static void call_cJSON_DeleteItemFromObjectCaseSensitive(payload in) {
    if (!root) return;
    root_mutated();
    REPORT_VOID(cJSON_DeleteItemFromObjectCaseSensitive,
                cJSON_DeleteItemFromObjectCaseSensitive(root, cstr(key, sizeof key, in)));
}

/* whole-tree operations */
/* ltl: root_lifecycle, item_ownership */
static void call_cJSON_Compare(payload in) {
    if (!root || !item) return;
    REPORT_VOID(cJSON_Compare, cJSON_Compare(root, item, byte(in, 0) & 1));
}
/* ltl: root_lifecycle, borrowed_child_validity */
static void call_cJSONUtils_SortObject(payload in) {
    (void)in;
    if (!root) return;
    root_mutated();
    REPORT_VOID(cJSONUtils_SortObject, cJSONUtils_SortObject(root));
    sorted = 1;
}
/* ltl: root_lifecycle, borrowed_child_validity */
static void call_cJSONUtils_SortObjectCaseSensitive(payload in) {
    (void)in;
    if (!root) return;
    root_mutated();
    REPORT_VOID(cJSONUtils_SortObjectCaseSensitive, cJSONUtils_SortObjectCaseSensitive(root));
    sorted = 1;
}

/* patches: produce and consume patch */
/* ltl: root_lifecycle, item_ownership, patch_lifecycle */
static void call_cJSONUtils_GeneratePatches(payload in) {
    (void)in;
    if (!root || !item || patch) return;
    if (!preqed_call("cJSONUtils_GeneratePatches")) return;
    take_patch("cJSONUtils_GeneratePatches", cJSONUtils_GeneratePatches(root, item));
    sorted = 1;
}
/* ltl: root_lifecycle, item_ownership, patch_lifecycle */
static void call_cJSONUtils_GeneratePatchesCaseSensitive(payload in) {
    (void)in;
    if (!root || !item || patch) return;
    if (!preqed_call("cJSONUtils_GeneratePatchesCaseSensitive")) return;
    take_patch("cJSONUtils_GeneratePatchesCaseSensitive", cJSONUtils_GeneratePatchesCaseSensitive(root, item));
    sorted = 1;
}
/* ltl: root_lifecycle, item_ownership, patch_lifecycle */
static void call_cJSONUtils_GenerateMergePatch(payload in) {
    (void)in;
    if (!root || !item || patch) return;
    if (!preqed_call("cJSONUtils_GenerateMergePatch")) return;
    take_patch("cJSONUtils_GenerateMergePatch", cJSONUtils_GenerateMergePatch(root, item));
    sorted = 1;
}
/* ltl: root_lifecycle, item_ownership, patch_lifecycle */
static void call_cJSONUtils_GenerateMergePatchCaseSensitive(payload in) {
    (void)in;
    if (!root || !item || patch) return;
    if (!preqed_call("cJSONUtils_GenerateMergePatchCaseSensitive")) return;
    take_patch("cJSONUtils_GenerateMergePatchCaseSensitive", cJSONUtils_GenerateMergePatchCaseSensitive(root, item));
    sorted = 1;
}
/* ltl: patch_lifecycle */
static void call_cJSONUtils_AddPatchToArray(payload in) {
    /* the six RFC 6902 operations plus one invalid name, which cJSONUtils_ApplyPatches must reject */
    static const char *const ops[] = { "add", "remove", "replace", "move", "copy", "test", "bogus" };
    if (!patch || !cJSON_IsArray(patch)) return;
    const char *path = cstr(str, sizeof str, rest(in, 1));
    REPORT_VOID(cJSONUtils_AddPatchToArray, cJSONUtils_AddPatchToArray(patch, ops[byte(in, 0) % 7], path, item));
}
/* ltl: root_lifecycle, borrowed_child_validity, patch_lifecycle */
static void call_cJSONUtils_ApplyPatches(payload in) {
    (void)in;
    if (!root || !patch || sorted) return;
    root_mutated();
    sorted = 1;
    REPORT(cJSONUtils_ApplyPatches, cJSONUtils_ApplyPatches(root, patch), rc == 0);
}
/* ltl: root_lifecycle, borrowed_child_validity, patch_lifecycle */
static void call_cJSONUtils_ApplyPatchesCaseSensitive(payload in) {
    (void)in;
    if (!root || !patch || sorted) return;
    root_mutated();
    sorted = 1;
    REPORT(cJSONUtils_ApplyPatchesCaseSensitive, cJSONUtils_ApplyPatchesCaseSensitive(root, patch), rc == 0);
}
/* ltl: root_lifecycle, borrowed_child_validity, patch_lifecycle */
static void call_cJSONUtils_MergePatch(payload in) {
    (void)in;
    if (!root || !patch || sorted) return;
    root_mutated();
    if (!preqed_call("cJSONUtils_MergePatch")) return;
    take_root("cJSONUtils_MergePatch", cJSONUtils_MergePatch(root, patch));
}
/* ltl: root_lifecycle, borrowed_child_validity, patch_lifecycle */
static void call_cJSONUtils_MergePatchCaseSensitive(payload in) {
    (void)in;
    if (!root || !patch || sorted) return;
    root_mutated();
    if (!preqed_call("cJSONUtils_MergePatchCaseSensitive")) return;
    take_root("cJSONUtils_MergePatchCaseSensitive", cJSONUtils_MergePatchCaseSensitive(root, patch));
}

/* memory */
/* ltl: print_buffer_free */
static void call_cJSON_malloc(payload in) {
    if (text) return;
    if (!preqed_call("cJSON_malloc")) return;
    take_text("cJSON_malloc", cJSON_malloc(1 + byte(in, 0) * 16));  /* 1..4081 bytes */
}
/* ltl: print_buffer_free */
static void call_cJSON_free(payload in) {
    (void)in;
    if (!text) return;
    REPORT_VOID(cJSON_free, cJSON_free(text));
    text = NULL;
}

/* dispatch */

static void (*const api[])(payload) = {
    call_cJSON_Version, call_cJSON_InitHooks,
    call_cJSON_Parse, call_cJSON_ParseWithLength, call_cJSON_ParseWithOpts, call_cJSON_ParseWithLengthOpts,
    call_cJSON_GetErrorPtr,
    call_cJSON_Print, call_cJSON_PrintUnformatted, call_cJSON_PrintBuffered, call_cJSON_PrintPreallocated,
    call_cJSON_Minify, call_cJSON_Delete,
    call_cJSON_GetArraySize, call_cJSON_GetArrayItem, call_cJSON_GetObjectItem,
    call_cJSON_GetObjectItemCaseSensitive, call_cJSON_HasObjectItem,
    call_cJSONUtils_GetPointer, call_cJSONUtils_GetPointerCaseSensitive,
    call_cJSON_IsInvalid, call_cJSON_IsFalse, call_cJSON_IsTrue, call_cJSON_IsBool, call_cJSON_IsNull,
    call_cJSON_IsNumber, call_cJSON_IsString, call_cJSON_IsArray, call_cJSON_IsObject, call_cJSON_IsRaw,
    call_cJSON_GetStringValue, call_cJSON_GetNumberValue, call_cJSON_SetNumberHelper, call_cJSON_SetValuestring,
    call_cJSONUtils_FindPointerFromObjectTo,
    call_cJSON_CreateNull, call_cJSON_CreateTrue, call_cJSON_CreateFalse, call_cJSON_CreateBool,
    call_cJSON_CreateNumber, call_cJSON_CreateString, call_cJSON_CreateRaw, call_cJSON_CreateArray,
    call_cJSON_CreateObject, call_cJSON_CreateStringReference, call_cJSON_CreateObjectReference,
    call_cJSON_CreateArrayReference, call_cJSON_CreateIntArray, call_cJSON_CreateFloatArray,
    call_cJSON_CreateDoubleArray, call_cJSON_CreateStringArray, call_cJSON_Duplicate,
    call_cJSON_AddItemToArray, call_cJSON_AddItemToObject, call_cJSON_AddItemToObjectCS,
    call_cJSON_InsertItemInArray, call_cJSON_ReplaceItemInArray, call_cJSON_ReplaceItemInObject,
    call_cJSON_ReplaceItemInObjectCaseSensitive, call_cJSON_ReplaceItemViaPointer,
    call_cJSON_AddItemReferenceToArray, call_cJSON_AddItemReferenceToObject,
    call_cJSON_AddNullToObject, call_cJSON_AddTrueToObject, call_cJSON_AddFalseToObject,
    call_cJSON_AddBoolToObject, call_cJSON_AddNumberToObject, call_cJSON_AddStringToObject,
    call_cJSON_AddRawToObject, call_cJSON_AddObjectToObject, call_cJSON_AddArrayToObject,
    call_cJSON_DetachItemFromArray, call_cJSON_DetachItemFromObject,
    call_cJSON_DetachItemFromObjectCaseSensitive, call_cJSON_DetachItemViaPointer,
    call_cJSON_DeleteItemFromArray, call_cJSON_DeleteItemFromObject, call_cJSON_DeleteItemFromObjectCaseSensitive,
    call_cJSON_Compare, call_cJSONUtils_SortObject, call_cJSONUtils_SortObjectCaseSensitive,
    call_cJSONUtils_GeneratePatches, call_cJSONUtils_GeneratePatchesCaseSensitive,
    call_cJSONUtils_GenerateMergePatch, call_cJSONUtils_GenerateMergePatchCaseSensitive,
    call_cJSONUtils_AddPatchToArray, call_cJSONUtils_ApplyPatches, call_cJSONUtils_ApplyPatchesCaseSensitive,
    call_cJSONUtils_MergePatch, call_cJSONUtils_MergePatchCaseSensitive,
    call_cJSON_malloc, call_cJSON_free,
};

#define API_COUNT (sizeof api / sizeof api[0])

static void cleanup(void) {
    cJSON_Delete(root);
    cJSON_Delete(item);
    cJSON_Delete(patch);
    cJSON_free(text);
    root = item = patch = child = NULL;
    text = NULL;
    item_referenced = 0;
    cJSON_InitHooks(NULL);
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
