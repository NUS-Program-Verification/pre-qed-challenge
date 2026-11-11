#define TINYOBJLOADER_IMPLEMENTATION
#include "tiny_obj_loader.h"
#include "preqed_ltl.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <unistd.h>

#define OBJ_PATH "tinyobj-harness.obj"
#define MTL_PATH "tinyobj-harness.mtl"

struct payload {
    const uint8_t *p;
    size_t n;
};

static tinyobj::ObjReader *reader;
static bool reader_parsed;
static std::string obj_text, mtl_text;    /* the two documents later calls refer to */
static tinyobj::ArenaAllocator *arena;
static tinyobj::TypedArray<int> array;    /* a view into arena memory */
static bool array_stale;                  /* the arena memory behind `array` was released */

static uint8_t byte(payload in, size_t i) { return i < in.n ? in.p[i] : 0; }
static payload rest(payload in, size_t skip) {
    return { in.p + (skip < in.n ? skip : in.n), in.n > skip ? in.n - skip : 0 };
}
static std::string text(payload in) { return std::string(reinterpret_cast<const char *>(in.p), in.n); }
static void split(payload in, size_t &obj_len) {
    const uint8_t *sep = static_cast<const uint8_t *>(std::memchr(in.p, 0, in.n));
    obj_len = sep ? static_cast<size_t>(sep - in.p) : in.n;
}
static void write_file(const char *path, const std::string &body) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f << body;
}

#define REPORT(api, stmt, ok_cond) \
    do { if (preqed_call(#api)) { stmt; preqed_result(#api, (ok_cond)); } } while (0)
#define REPORT_VOID(api, stmt) REPORT(api, stmt, true)

/* documents: the payload carries obj text, a NUL, then mtl text */

static void call_set_documents(payload in) {
    size_t obj_len;
    split(in, obj_len);
    obj_text = text({ in.p, obj_len });
    mtl_text = obj_len < in.n ? text(rest(in, obj_len + 1)) : std::string();
    write_file(OBJ_PATH, "mtllib " MTL_PATH "\n" + obj_text);
    write_file(MTL_PATH, mtl_text);
}

/* ObjReader */
/* ltl: objreader_lifecycle, objreader_results_after_parse */
static void call_ObjReader_ctor(payload) {
    if (reader) return;
    if (!preqed_call("ObjReader::ObjReader")) return;
    reader = new tinyobj::ObjReader();
    preqed_result("ObjReader::ObjReader", true);
    reader_parsed = false;
}
/* ltl: objreader_lifecycle */
static void call_ObjReader_dtor(payload) {
    if (!reader) return;
    REPORT_VOID(ObjReader::~ObjReader, delete reader);
    reader = nullptr;
    reader_parsed = false;
}

static tinyobj::ObjReaderConfig reader_config(uint8_t b) {
    tinyobj::ObjReaderConfig cfg;
    cfg.triangulate = b & 1;
    cfg.vertex_color = b & 2;
    cfg.triangulation_method = b & 4 ? "earcut" : "simple";  /* the two methods ObjReaderConfig documents */
    cfg.mtl_search_path = b & 8 ? "." : "";  /* "." finds MTL_PATH in cwd; "" uses the obj's own directory */
    return cfg;
}
/* ltl: objreader_lifecycle, objreader_results_after_parse */
static void call_ObjReader_ParseFromString(payload in) {
    if (!reader) return;
    tinyobj::ObjReaderConfig cfg = reader_config(byte(in, 0));
    if (!preqed_call("ObjReader::ParseFromString")) return;
    bool ok = reader->ParseFromString(obj_text, mtl_text, cfg);
    preqed_result("ObjReader::ParseFromString", ok);
    reader_parsed = true;
}
/* ltl: objreader_lifecycle, objreader_results_after_parse */
static void call_ObjReader_ParseFromFile(payload in) {
    if (!reader) return;
    tinyobj::ObjReaderConfig cfg = reader_config(byte(in, 0));
    if (!preqed_call("ObjReader::ParseFromFile")) return;
    bool ok = reader->ParseFromFile(OBJ_PATH, cfg);
    preqed_result("ObjReader::ParseFromFile", ok);
    reader_parsed = true;
}

#define READER_GETTER(name) \
    static void call_ObjReader_##name(payload) { \
        if (!reader || !reader_parsed) return; \
        REPORT_VOID(ObjReader::name, reader->name()); \
    }
/* ltl: objreader_lifecycle, objreader_results_after_parse */
READER_GETTER(Valid)
/* ltl: objreader_lifecycle, objreader_results_after_parse */
READER_GETTER(GetAttrib)
/* ltl: objreader_lifecycle, objreader_results_after_parse */
READER_GETTER(GetShapes)
/* ltl: objreader_lifecycle, objreader_results_after_parse */
READER_GETTER(GetMaterials)
/* ltl: objreader_lifecycle, objreader_results_after_parse */
READER_GETTER(Warning)
/* ltl: objreader_lifecycle, objreader_results_after_parse */
READER_GETTER(Error)

/* free functions */

static void call_LoadObj_file(payload in) {
    tinyobj::attrib_t attrib;
    std::vector<tinyobj::shape_t> shapes;
    std::vector<tinyobj::material_t> materials;
    std::string warn, err;
    REPORT(LoadObj(filename),
           bool ok = tinyobj::LoadObj(&attrib, &shapes, &materials, &warn, &err, OBJ_PATH,
                                      byte(in, 0) & 1 ? "." : nullptr, byte(in, 0) & 2, byte(in, 0) & 4),
           ok);
}

static void call_LoadObj_stream(payload in) {
    tinyobj::attrib_t attrib;
    std::vector<tinyobj::shape_t> shapes;
    std::vector<tinyobj::material_t> materials;
    std::string warn, err;
    std::istringstream obj(obj_text), mtl(mtl_text);
    tinyobj::MaterialStreamReader mtl_reader(mtl);
    tinyobj::MaterialFileReader file_reader(".");
    tinyobj::MaterialReader *mr = byte(in, 0) & 8 ? nullptr
                                : byte(in, 0) & 16 ? static_cast<tinyobj::MaterialReader *>(&file_reader)
                                : &mtl_reader;
    REPORT(LoadObj(istream),
           bool ok = tinyobj::LoadObj(&attrib, &shapes, &materials, &warn, &err, &obj, mr, byte(in, 0) & 2, byte(in, 0) & 4),
           ok);
}

struct cb_state {
    unsigned vertices, indices, groups;
};

static void vertex_cb(void *u, tinyobj::real_t, tinyobj::real_t, tinyobj::real_t, tinyobj::real_t) { static_cast<cb_state *>(u)->vertices++; }
static void vertex_color_cb(void *u, tinyobj::real_t, tinyobj::real_t, tinyobj::real_t, tinyobj::real_t, tinyobj::real_t, tinyobj::real_t, bool) { static_cast<cb_state *>(u)->vertices++; }
static void normal_cb(void *, tinyobj::real_t, tinyobj::real_t, tinyobj::real_t) {}
static void texcoord_cb(void *, tinyobj::real_t, tinyobj::real_t, tinyobj::real_t) {}
static void index_cb(void *u, tinyobj::index_t *, int n) { static_cast<cb_state *>(u)->indices += n; }
static void usemtl_cb(void *, const char *, int) {}
static void mtllib_cb(void *, const tinyobj::material_t *, int) {}
static void group_cb(void *u, const char **, int) { static_cast<cb_state *>(u)->groups++; }
static void object_cb(void *, const char *) {}

/* byte 0: one bit per callback to install (unset callbacks stay NULL, which the API allows);
   byte 1 bit 0: pass a material reader */
static void call_LoadObjWithCallback(payload in) {
    tinyobj::callback_t cb;
    uint8_t mask = byte(in, 0);
    if (mask & 1) cb.vertex_cb = vertex_cb;
    if (mask & 2) cb.vertex_color_cb = vertex_color_cb;
    if (mask & 4) cb.normal_cb = normal_cb;
    if (mask & 8) cb.texcoord_cb = texcoord_cb;
    if (mask & 16) cb.index_cb = index_cb;
    if (mask & 32) cb.usemtl_cb = usemtl_cb;
    if (mask & 64) cb.mtllib_cb = mtllib_cb;
    if (mask & 128) { cb.group_cb = group_cb; cb.object_cb = object_cb; }
    cb_state state = {};
    std::string warn, err;
    std::istringstream obj(obj_text), mtl(mtl_text);
    tinyobj::MaterialStreamReader mtl_reader(mtl);
    REPORT(LoadObjWithCallback,
           bool ok = tinyobj::LoadObjWithCallback(obj, cb, &state, byte(in, 1) & 1 ? &mtl_reader : nullptr, &warn, &err),
           ok);
}

static void call_LoadMtl(payload) {
    std::map<std::string, int> material_map;
    std::vector<tinyobj::material_t> materials;
    std::string warn, err;
    std::istringstream mtl(mtl_text);
    REPORT_VOID(LoadMtl, tinyobj::LoadMtl(&material_map, &materials, &mtl, &warn, &err));
}

static void call_ParseTextureNameAndOption(payload in) {
    std::string line = text(in);
    std::string texname;
    tinyobj::texture_option_t opt;
    REPORT(ParseTextureNameAndOption, bool ok = tinyobj::ParseTextureNameAndOption(&texname, &opt, line.c_str()), ok);
}

static tinyobj::OptLoadConfig opt_config(uint8_t b) {
    tinyobj::OptLoadConfig cfg;
    cfg.num_threads = 1;  /* default -1 spawns hardware_concurrency() threads; keep runs deterministic */
    cfg.triangulate = b & 1;
    cfg.float_cache = b & 2;
    cfg.fp32_cache = b & 4;
    cfg.float_cache_max_nodes = 1 + (b >> 3) * 16;  /* 1..497 cache nodes */
    return cfg;
}

static void call_LoadObjOpt_buffer(payload in) {
    tinyobj::basic_attrib_t<> attrib;
    std::vector<tinyobj::basic_shape_t<>> shapes;
    std::vector<tinyobj::material_t> materials;
    std::string warn, err;
    REPORT(LoadObjOpt(buffer),
           bool ok = tinyobj::LoadObjOpt(&attrib, &shapes, &materials, &warn, &err, obj_text.data(), obj_text.size(), opt_config(byte(in, 0))),
           ok);
}

static void call_LoadObjOpt_file(payload in) {
    tinyobj::basic_attrib_t<> attrib;
    std::vector<tinyobj::basic_shape_t<>> shapes;
    std::vector<tinyobj::material_t> materials;
    std::string warn, err;
    REPORT(LoadObjOpt(filename),
           bool ok = tinyobj::LoadObjOpt(&attrib, &shapes, &materials, &warn, &err, OBJ_PATH, byte(in, 0) & 8 ? "." : nullptr, opt_config(byte(in, 0))),
           ok);
}

/* LoadObjOptTyped: the result owns an arena, and its attrib arrays are views into it */

template <typename T> static void touch(const tinyobj::TypedArray<T> &a) {
    /* read every element: a view that overruns or outlives its arena block is an ASan report */
    for (const T &v : a) {
        T copy;
        std::memcpy(&copy, &v, sizeof copy);
    }
}
static void touch_result(const tinyobj::OptResult &r) {
    touch(r.attrib.vertices);
    touch(r.attrib.vertex_weights);
    touch(r.attrib.normals);
    touch(r.attrib.texcoords);
    touch(r.attrib.texcoord_ws);
    touch(r.attrib.colors);
    touch(r.attrib.indices);
    touch(r.attrib.face_num_verts);
    touch(r.attrib.material_ids);
    touch(r.attrib.smoothing_group_ids);
}

static void call_LoadObjOptTyped_buffer(payload in) {
    std::string warn, err;
    if (!preqed_call("LoadObjOptTyped(buffer)")) return;
    tinyobj::OptResult r = tinyobj::LoadObjOptTyped(obj_text.data(), obj_text.size(), &warn, &err, opt_config(byte(in, 0)));
    preqed_result("LoadObjOptTyped(buffer)", r.valid);
    touch_result(r);
}

static void call_LoadObjOptTyped_file(payload in) {
    std::string warn, err;
    if (!preqed_call("LoadObjOptTyped(filename)")) return;
    tinyobj::OptResult r = tinyobj::LoadObjOptTyped(OBJ_PATH, &warn, &err, byte(in, 0) & 8 ? "." : nullptr, opt_config(byte(in, 0)));
    preqed_result("LoadObjOptTyped(filename)", r.valid);
    touch_result(r);
}

static void call_OptResult_ctor(payload) {
    REPORT(OptResult::OptResult, tinyobj::OptResult r, !r.valid && r.shapes.empty());
}

/* OptResult is move-only: the target takes over the arena and the source's views are cleared */
static void call_OptResult_move_assign(payload in) {
    std::string warn, err;
    tinyobj::OptResult kept;
    if (!preqed_call("LoadObjOptTyped(buffer)")) return;
    tinyobj::OptResult r = tinyobj::LoadObjOptTyped(obj_text.data(), obj_text.size(), &warn, &err, opt_config(byte(in, 0)));
    preqed_result("LoadObjOptTyped(buffer)", r.valid);
    bool valid = r.valid;
    REPORT(OptResult::operator=, kept = std::move(r), kept.valid == valid && !r.valid);
    touch_result(kept);
    touch_result(r);
}

static void call_OptShapeRange_ctor(payload) {
    REPORT(OptShapeRange::OptShapeRange, tinyobj::OptShapeRange range, range.face_count == 0 && range.index_count == 0);
}

/* ArenaAllocator: the harness keeps one arena */

/* reset, move assignment and destruction free every block: the view in `array` dangles */
static void arena_released() { array_stale = true; }
/* block size 64..16384 bytes: small enough that allocations spill into new blocks */
static size_t block_size(uint8_t b) { return 64 + static_cast<size_t>(b) * 64; }

/* ltl: arena_lifecycle */
static void call_ArenaAllocator_ctor(payload in) {
    if (arena) return;
    REPORT_VOID(ArenaAllocator::ArenaAllocator, arena = new tinyobj::ArenaAllocator(block_size(byte(in, 0))));
}
/* ltl: arena_lifecycle, typed_array_view_tied_to_arena */
static void call_ArenaAllocator_dtor(payload) {
    if (!arena) return;
    REPORT_VOID(ArenaAllocator::~ArenaAllocator, delete arena);
    arena = nullptr;
    arena_released();
}
/* ltl: arena_lifecycle */
static void call_ArenaAllocator_allocate(payload in) {
    if (!arena) return;
    size_t alignment = static_cast<size_t>(1) << (byte(in, 0) % 7);  /* 1..64: std::align needs a power of two */
    size_t bytes = byte(in, 1) | static_cast<size_t>(byte(in, 2)) << 8;  /* 0..65535 */
    REPORT(ArenaAllocator::allocate, void *p = arena->allocate(bytes, alignment); if (p) std::memset(p, 0xA5, bytes),
           p != nullptr && reinterpret_cast<uintptr_t>(p) % alignment == 0);
}
/* ltl: arena_lifecycle, typed_array_view_tied_to_arena */
static void call_ArenaAllocator_reset(payload) {
    if (!arena) return;
    REPORT_VOID(ArenaAllocator::reset, arena->reset());
    arena_released();
}
/* ltl: arena_lifecycle, typed_array_view_tied_to_arena */
static void call_ArenaAllocator_move_assign(payload in) {
    if (!arena) return;
    REPORT_VOID(ArenaAllocator::operator=, *arena = tinyobj::ArenaAllocator(block_size(byte(in, 0))));
    arena_released();
}

/* TypedArray<int>: "Non-owning, contiguous array view allocated from an ArenaAllocator" */

/* ltl: typed_array_view_tied_to_arena */
static void call_TypedArray_ctor(payload) {
    REPORT(TypedArray::TypedArray, array = tinyobj::TypedArray<int>(), array.empty());
    array_stale = false;
}
/* ltl: arena_lifecycle, typed_array_view_tied_to_arena */
static void call_TypedArray_allocate(payload in) {
    if (!arena) return;
    size_t count = byte(in, 0) | static_cast<size_t>(byte(in, 1) & 3) << 8;  /* 0..1023 elements */
    REPORT(TypedArray::allocate, bool ok = array.allocate(*arena, count), ok && array.size() == count);
    array_stale = false;
}
/* ltl: arena_lifecycle, typed_array_view_tied_to_arena */
static void call_TypedArray_set(payload in) {
    /* "Caller must ensure ptr points into a live arena and count is within bounds": a fresh arena allocation */
    if (!arena) return;
    size_t count = byte(in, 0);
    if (!preqed_call("ArenaAllocator::allocate")) return;
    int *p = static_cast<int *>(arena->allocate(count * sizeof(int), alignof(int)));
    preqed_result("ArenaAllocator::allocate", p != nullptr);
    if (!p) return;
    std::memset(p, 0, count * sizeof(int));
    REPORT(TypedArray::set, array.set(p, count), array.data() == p && array.size() == count);
    array_stale = false;
}
static void call_TypedArray_truncate(payload in) {
    size_t before = array.size();
    size_t n = byte(in, 0) | static_cast<size_t>(byte(in, 1) & 3) << 8;
    REPORT(TypedArray::truncate, array.truncate(n), array.size() == (n < before ? n : before));
}
/* ltl: typed_array_view_tied_to_arena */
static void call_TypedArray_clear(payload) {
    REPORT(TypedArray::clear, array.clear(), array.empty());
    array_stale = false;
}
static void call_TypedArray_data(payload) { REPORT_VOID(TypedArray::data, array.data()); }
static void call_TypedArray_size(payload) { REPORT_VOID(TypedArray::size, array.size()); }
static void call_TypedArray_empty(payload) { REPORT(TypedArray::empty, bool e = array.empty(), e == (array.size() == 0)); }
static void call_TypedArray_begin(payload) { REPORT(TypedArray::begin, int *b = array.begin(), b == array.data()); }
static void call_TypedArray_end(payload) { REPORT(TypedArray::end, int *e = array.end(), e == array.data() + array.size()); }
/* ltl: typed_array_view_tied_to_arena */
static void call_TypedArray_index(payload in) {
    if (array_stale || array.empty()) return;
    size_t i = (byte(in, 0) | static_cast<size_t>(byte(in, 1)) << 8) % array.size();
    REPORT(TypedArray::operator[], int &v = array[i]; v += 1, &v == array.data() + i);
}

/* arena_adapter<T>: std-style allocator over an ArenaAllocator; with a null arena it uses operator new/delete.
   Each wrapper builds its own adapter, so none outlives the arena it points at. */

static tinyobj::ArenaAllocator *adapter_arena(payload in, size_t i) { return byte(in, i) & 1 ? arena : nullptr; }

static void call_arena_adapter_ctor(payload in) {
    tinyobj::ArenaAllocator *a = adapter_arena(in, 0);
    REPORT(arena_adapter::arena_adapter, tinyobj::arena_adapter<int> adapter(a), adapter.arena() == a);
}
static void call_arena_adapter_arena(payload in) {
    tinyobj::ArenaAllocator *a = adapter_arena(in, 0);
    tinyobj::arena_adapter<int> adapter(a);
    REPORT(arena_adapter::arena, tinyobj::ArenaAllocator *got = adapter.arena(), got == a);
}
static void call_arena_adapter_eq(payload in) {
    tinyobj::arena_adapter<int> a(adapter_arena(in, 0));
    tinyobj::arena_adapter<char> b(adapter_arena(in, 1));
    REPORT(arena_adapter::operator==, bool eq = a == b, eq == (a.arena() == b.arena()));
}
static void call_arena_adapter_ne(payload in) {
    tinyobj::arena_adapter<int> a(adapter_arena(in, 0));
    tinyobj::arena_adapter<char> b(adapter_arena(in, 1));
    REPORT(arena_adapter::operator!=, bool ne = a != b, ne == (a.arena() != b.arena()));
}
/* allocate and deallocate are one wrapper: the block goes back to the adapter that returned it */
static void call_arena_adapter_allocate(payload in) {
    tinyobj::arena_adapter<int> adapter(adapter_arena(in, 0));
    size_t n = 1 + static_cast<size_t>(byte(in, 1));  /* 1..256 ints */
    if (!preqed_call("arena_adapter::allocate")) return;
    int *p = adapter.allocate(n);
    preqed_result("arena_adapter::allocate", p != nullptr);
    if (!p) return;
    std::memset(p, 0, n * sizeof(int));
    if (!preqed_call("arena_adapter::deallocate")) return;
    adapter.deallocate(p, n);
    preqed_result("arena_adapter::deallocate", true);
}

/* material readers */

/* the MaterialReader interface implemented by the caller: this one serves mtl_text for every material id */
struct TextMaterialReader : tinyobj::MaterialReader {
    TextMaterialReader() : tinyobj::MaterialReader() {}
    bool operator()(const std::string &, std::vector<tinyobj::material_t> *materials, std::map<std::string, int> *matMap,
                    std::string *warn, std::string *err) override {
        std::istringstream mtl(mtl_text);
        tinyobj::LoadMtl(matMap, materials, &mtl, warn, err);
        return true;
    }
};
static void call_MaterialReader_ctor(payload in) {
    tinyobj::attrib_t attrib;
    std::vector<tinyobj::shape_t> shapes;
    std::vector<tinyobj::material_t> materials;
    std::string warn, err;
    std::istringstream obj(obj_text);
    if (!preqed_call("MaterialReader::MaterialReader")) return;
    TextMaterialReader custom;
    preqed_result("MaterialReader::MaterialReader", true);
    REPORT(LoadObj(istream),
           bool ok = tinyobj::LoadObj(&attrib, &shapes, &materials, &warn, &err, &obj, &custom, byte(in, 0) & 2, byte(in, 0) & 4),
           ok);
}

static void call_MaterialStreamReader_call(payload) {
    std::istringstream mtl(mtl_text);
    tinyobj::MaterialStreamReader mtl_reader(mtl);
    std::vector<tinyobj::material_t> materials;
    std::map<std::string, int> material_map;
    std::string warn, err;
    REPORT(MaterialStreamReader::operator(), bool ok = mtl_reader("", &materials, &material_map, &warn, &err), ok);
}

/* attrib_t accessors ("For pybind11"), on the attributes LoadObj just filled */

#define ATTRIB_GETTER(name, field) \
    static void call_attrib_##name(payload in) { \
        tinyobj::attrib_t attrib; \
        std::vector<tinyobj::shape_t> shapes; \
        std::vector<tinyobj::material_t> materials; \
        std::string warn, err; \
        std::istringstream obj(obj_text); \
        REPORT(LoadObj(istream), \
               bool ok = tinyobj::LoadObj(&attrib, &shapes, &materials, &warn, &err, &obj, nullptr, byte(in, 0) & 2, byte(in, 0) & 4), \
               ok); \
        REPORT(attrib_t::name, const std::vector<tinyobj::real_t> &v = attrib.name(), &v == &attrib.field); \
    }
ATTRIB_GETTER(GetVertices, vertices)
ATTRIB_GETTER(GetVertexWeights, vertex_weights)

/* the operator= templates of basic_tag_t / basic_skin_weight_t (assignment from a value with another allocator) */

static void call_basic_tag_t_assign(payload in) {
    tinyobj::tag_t src, dst;
    src.name = text({ in.p, in.n < 8 ? in.n : 8 });
    for (size_t i = 0; i < byte(in, 8) % 8u; i++) {  /* 0..7 values of each kind */
        src.intValues.push_back(byte(in, 9 + i));
        src.floatValues.push_back(static_cast<tinyobj::real_t>(byte(in, 9 + i)));
        src.stringValues.push_back(src.name);
    }
    /* named explicitly: plain `dst = src` picks the implicit copy assignment, not the template. The same allocator
       is used: with another one `name = rhs.name` assigns between unrelated string types, which compiles only
       from C++17 on (repro.cpp). */
    REPORT(basic_tag_t::operator=, dst.operator=<std::allocator<char>>(src),
           dst.name == src.name && dst.intValues == src.intValues && dst.stringValues == src.stringValues);
}

static void call_basic_skin_weight_t_assign(payload in) {
    tinyobj::skin_weight_t src;
    src.vertex_id = byte(in, 0);
    for (size_t i = 0; i < byte(in, 1) % 8u; i++) {  /* 0..7 joint weights */
        tinyobj::joint_and_weight_t jw;
        jw.joint_id = byte(in, 2 + i);
        jw.weight = static_cast<tinyobj::real_t>(byte(in, 2 + i)) / 255;
        src.weightValues.push_back(jw);
    }
    /* the target's vector allocates from an arena that outlives it */
    tinyobj::ArenaAllocator local;
    tinyobj::basic_skin_weight_t<tinyobj::arena_adapter<char>> dst{ tinyobj::arena_adapter<char>(&local) };
    REPORT(basic_skin_weight_t::operator=, dst = src,
           dst.vertex_id == src.vertex_id && dst.weightValues.size() == src.weightValues.size());
}

/* dispatch */

static void (*const api[])(payload) = {
    call_set_documents,
    call_ObjReader_ctor, call_ObjReader_dtor, call_ObjReader_ParseFromString, call_ObjReader_ParseFromFile,
    call_ObjReader_Valid, call_ObjReader_GetAttrib, call_ObjReader_GetShapes, call_ObjReader_GetMaterials,
    call_ObjReader_Warning, call_ObjReader_Error,
    call_LoadObj_file, call_LoadObj_stream, call_LoadObjWithCallback, call_LoadMtl, call_ParseTextureNameAndOption,
    call_LoadObjOpt_buffer, call_LoadObjOpt_file,
    call_LoadObjOptTyped_buffer, call_LoadObjOptTyped_file, call_OptResult_ctor, call_OptResult_move_assign,
    call_OptShapeRange_ctor,
    call_ArenaAllocator_ctor, call_ArenaAllocator_dtor, call_ArenaAllocator_allocate, call_ArenaAllocator_reset,
    call_ArenaAllocator_move_assign,
    call_TypedArray_ctor, call_TypedArray_allocate, call_TypedArray_set, call_TypedArray_truncate, call_TypedArray_clear,
    call_TypedArray_data, call_TypedArray_size, call_TypedArray_empty, call_TypedArray_begin, call_TypedArray_end,
    call_TypedArray_index,
    call_arena_adapter_ctor, call_arena_adapter_arena, call_arena_adapter_eq, call_arena_adapter_ne,
    call_arena_adapter_allocate,
    call_MaterialReader_ctor, call_MaterialStreamReader_call, call_attrib_GetVertices, call_attrib_GetVertexWeights,
    call_basic_tag_t_assign, call_basic_skin_weight_t_assign,
};

static const size_t API_COUNT = sizeof api / sizeof api[0];

static void cleanup() {
    delete reader;
    reader = nullptr;
    reader_parsed = false;
    delete arena;
    arena = nullptr;
    array = tinyobj::TypedArray<int>();
    array_stale = false;
    obj_text.clear();
    mtl_text.clear();
    unlink(OBJ_PATH);
    unlink(MTL_PATH);
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
