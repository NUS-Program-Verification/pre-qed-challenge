/* libFuzzer harness for libomx-clap-core.so.1: the 102 exports of src/omx-clap-core.map (omx_clap_host_*,
 * omx_clap_chain_*, omx_clap_param_*, omx_clap_resource_hint_*, omx_clap_core_version), driven through the public
 * headers (CORE_HEADERS in the Makefile) on one live host instance, one opened binary and one chain.
 *
 * Record: opcode byte, 2-byte LE payload length, payload. api[op % API_COUNT] runs the wrapper.
 * Fixtures: the .clap files named by fixture_at(), looked up in $OMX_CLAP_FIXTURES (default "."), see LLVMFuzzerInitialize.
 */

#include <math.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "clap_chain.h"   /* includes clap_host.h */
#include "clap_host.h"
#include "preqed_ltl.h"

/* frames per process call (largest block_of size); channels per port as clap_host.h allows; chain members;
   bytes kept from a state save (fixture plugins save far less) */
#define FRAMES_CAP  1024u
#define CH_CAP      CLAP_HOST_PORT_CHANNELS
#define MAX_MEMBERS 8u
#define STATE_CAP   (1u << 16)

/* ---------------------------------------------------------------- a plugin of the harness's own, linked in */

/* omx_clap_host_open_entry and omx_clap_host_entry_presets take a clap_plugin_entry_t of the caller's own (a linked-in
 * registry); this one is a stereo gain with one parameter and one preset, so both calls have something to open. */

#define SELF_ID        "org.preqed.fuzz.gain"
#define SELF_PRESETS   "org.preqed.fuzz.presets"
#define SELF_PARAM     0

static const char *const self_features[] = { CLAP_PLUGIN_FEATURE_AUDIO_EFFECT, CLAP_PLUGIN_FEATURE_STEREO, NULL };
static const clap_plugin_descriptor_t self_desc = {
    CLAP_VERSION_INIT, SELF_ID, "preqed fuzz gain", "preqed", "https://example.invalid", "", "", "0.0.0", "", self_features
};

struct self_plugin { clap_plugin_t plugin; clap_host_t *host; double gain; };   /* one allocation: destroy frees it */

static bool CLAP_ABI self_init(const clap_plugin_t *p) { (void)p; return true; }
static void CLAP_ABI self_destroy(const clap_plugin_t *p) { free(p->plugin_data); }
static bool CLAP_ABI self_activate(const clap_plugin_t *p, double rate, uint32_t min, uint32_t max)
{
    (void)p; (void)rate; (void)min; (void)max;
    return true;
}
static void CLAP_ABI self_deactivate(const clap_plugin_t *p) { (void)p; }
static bool CLAP_ABI self_start(const clap_plugin_t *p) { (void)p; return true; }
static void CLAP_ABI self_stop(const clap_plugin_t *p) { (void)p; }
static void CLAP_ABI self_reset(const clap_plugin_t *p) { (void)p; }
static void CLAP_ABI self_main_thread(const clap_plugin_t *p) { (void)p; }

static clap_process_status CLAP_ABI self_process(const clap_plugin_t *p, const clap_process_t *proc)
{
    const struct self_plugin *s = p->plugin_data;
    uint32_t c, i, ch;

    if (!proc->audio_inputs_count || proc->audio_inputs[0].data32 == NULL || !proc->audio_outputs_count)
        return CLAP_PROCESS_CONTINUE;
    ch = proc->audio_outputs[0].channel_count;
    if (ch > proc->audio_inputs[0].channel_count)
        ch = proc->audio_inputs[0].channel_count;
    for (c = 0; c < ch; c++)
    {
        float *out = proc->audio_outputs[0].data32[c];
        const float *inl = proc->audio_inputs[0].data32[c];

        if (!out || !inl)
            continue;
        for (i = 0; i < proc->frames_count; i++)
            out[i] = inl[i] * (float)s->gain;
    }
    return CLAP_PROCESS_CONTINUE;
}

static uint32_t CLAP_ABI self_port_count(const clap_plugin_t *p, bool is_input) { (void)p; (void)is_input; return 1; }

static bool CLAP_ABI self_port_get(const clap_plugin_t *p, uint32_t index, bool is_input, clap_audio_port_info_t *info)
{
    (void)p;
    if (index != 0)
        return false;
    memset(info, 0, sizeof *info);
    info->id = 0;
    snprintf(info->name, sizeof info->name, "%s", is_input ? "in" : "out");
    info->channel_count = 2;
    info->port_type = CLAP_PORT_STEREO;
    info->in_place_pair = 0;
    return true;
}

static uint32_t CLAP_ABI self_param_count(const clap_plugin_t *p) { (void)p; return 1; }

static bool CLAP_ABI self_param_info(const clap_plugin_t *p, uint32_t index, clap_param_info_t *info)
{
    (void)p;
    if (index != 0)
        return false;
    memset(info, 0, sizeof *info);
    info->id = SELF_PARAM;
    info->flags = CLAP_PARAM_IS_AUTOMATABLE | CLAP_PARAM_IS_MODULATABLE;
    snprintf(info->name, sizeof info->name, "Gain");
    info->min_value = 0.0;
    info->max_value = 2.0;
    info->default_value = 1.0;
    return true;
}

static bool CLAP_ABI self_param_value(const clap_plugin_t *p, clap_id id, double *value)
{
    const struct self_plugin *s = p->plugin_data;

    if (id != SELF_PARAM)
        return false;
    *value = s->gain;
    return true;
}

static bool CLAP_ABI self_param_to_text(const clap_plugin_t *p, clap_id id, double value, char *out, uint32_t size)
{
    (void)p;
    if (id != SELF_PARAM || !size)
        return false;
    snprintf(out, size, "%g", value);
    return true;
}

static bool CLAP_ABI self_param_from_text(const clap_plugin_t *p, clap_id id, const char *txt, double *value)
{
    (void)p;
    if (id != SELF_PARAM || !txt)
        return false;
    *value = strtod(txt, NULL);
    return true;
}

/* the parameter events the host queued: an input list, which the stage hands over, one value per record */
static void CLAP_ABI self_param_flush(const clap_plugin_t *p, const clap_input_events_t *in, const clap_output_events_t *out)
{
    struct self_plugin *s = p->plugin_data;
    uint32_t i, n = in ? in->size(in) : 0;

    (void)out;
    for (i = 0; i < n && i < 16; i++)
    {
        const clap_event_header_t *ev = in->get(in, i);

        if (!ev || ev->type != CLAP_EVENT_PARAM_VALUE)
            continue;
        {
            const clap_event_param_value_t *v = (const clap_event_param_value_t *)ev;

            if (v->param_id == SELF_PARAM)
                s->gain = v->value;
        }
    }
}

static const clap_plugin_audio_ports_t self_ports = { self_port_count, self_port_get };
static const clap_plugin_params_t self_params = { self_param_count, self_param_info, self_param_value, self_param_to_text,
                                                  self_param_from_text, self_param_flush };

static const void *CLAP_ABI self_extension(const clap_plugin_t *p, const char *id)
{
    (void)p;
    if (!strcmp(id, CLAP_EXT_AUDIO_PORTS))
        return &self_ports;
    return !strcmp(id, CLAP_EXT_PARAMS) ? &self_params : NULL;
}

static const clap_plugin_t *CLAP_ABI self_create(const clap_plugin_factory_t *f, const clap_host_t *host, const char *id)
{
    struct self_plugin *s;
    clap_plugin_t *p;

    (void)f;
    if (!id || strcmp(id, SELF_ID) != 0 || !(s = calloc(1, sizeof *s)))
        return NULL;
    p = &s->plugin;
    s->gain = 1.0;
    s->host = (clap_host_t *)host;
    p->desc = &self_desc;
    p->plugin_data = s;
    p->init = self_init;
    p->destroy = self_destroy;
    p->activate = self_activate;
    p->deactivate = self_deactivate;
    p->start_processing = self_start;
    p->stop_processing = self_stop;
    p->reset = self_reset;
    p->process = self_process;
    p->get_extension = self_extension;
    p->on_main_thread = self_main_thread;
    return p;
}

static uint32_t CLAP_ABI self_factory_count(const clap_plugin_factory_t *f) { (void)f; return 1; }
static const clap_plugin_descriptor_t *CLAP_ABI self_factory_desc(const clap_plugin_factory_t *f, uint32_t index)
{
    (void)f;
    return index == 0 ? &self_desc : NULL;
}
static const clap_plugin_factory_t self_factory = { self_factory_count, self_factory_desc, self_create };

/* clap.preset-discovery-factory/2: one provider, one PLUGIN location, one preset */
static const clap_preset_discovery_provider_descriptor_t self_provider_desc = { CLAP_VERSION_INIT, SELF_PRESETS, "preqed presets", "preqed" };

struct self_provider { clap_preset_discovery_provider_t provider; const clap_preset_discovery_indexer_t *indexer; };

static bool CLAP_ABI self_provider_init(const clap_preset_discovery_provider_t *provider)
{
    const struct self_provider *p = provider->provider_data;
    const clap_preset_discovery_filetype_t type = { "preqed preset", NULL, "uvpreset" };
    const clap_preset_discovery_location_t loc = { CLAP_PRESET_DISCOVERY_IS_FACTORY_CONTENT, "built in",
                                                   CLAP_PRESET_DISCOVERY_LOCATION_PLUGIN, NULL };

    return p->indexer->declare_filetype(p->indexer, &type) && p->indexer->declare_location(p->indexer, &loc);
}

static void CLAP_ABI self_provider_destroy(const clap_preset_discovery_provider_t *provider) { free(provider->provider_data); }

static bool CLAP_ABI self_provider_metadata(const clap_preset_discovery_provider_t *provider, uint32_t kind, const char *location,
                                            const clap_preset_discovery_metadata_receiver_t *r)
{
    const clap_universal_plugin_id_t self = { "clap", SELF_ID };

    (void)provider;
    (void)location;
    if (kind != CLAP_PRESET_DISCOVERY_LOCATION_PLUGIN)
        return true;
    if (!r->begin_preset(r, "Init", "init"))
        return true;
    r->add_plugin_id(r, &self);
    return true;
}

static const void *CLAP_ABI self_provider_extension(const clap_preset_discovery_provider_t *provider, const char *id)
{
    (void)provider;
    (void)id;
    return NULL;
}

static uint32_t CLAP_ABI self_preset_count(const clap_preset_discovery_factory_t *f) { (void)f; return 1; }
static const clap_preset_discovery_provider_descriptor_t *CLAP_ABI self_preset_desc(const clap_preset_discovery_factory_t *f,
                                                                                    uint32_t index)
{
    (void)f;
    return index == 0 ? &self_provider_desc : NULL;
}
static const clap_preset_discovery_provider_t *CLAP_ABI self_preset_create(const clap_preset_discovery_factory_t *f,
                                                                            const clap_preset_discovery_indexer_t *indexer,
                                                                            const char *id)
{
    struct self_provider *p;

    (void)f;
    if (!id || strcmp(id, SELF_PRESETS) != 0 || !(p = calloc(1, sizeof *p)))
        return NULL;
    p->indexer = indexer;
    p->provider = (clap_preset_discovery_provider_t){ &self_provider_desc, p, self_provider_init, self_provider_destroy,
                                                      self_provider_metadata, self_provider_extension };
    return &p->provider;
}

static const clap_preset_discovery_factory_t self_preset_factory = { self_preset_count, self_preset_desc, self_preset_create };

static bool CLAP_ABI self_entry_init(const char *path) { (void)path; return true; }
static void CLAP_ABI self_entry_deinit(void) {}

static const void *CLAP_ABI self_entry_factory(const char *factory_id)
{
    if (!strcmp(factory_id, CLAP_PLUGIN_FACTORY_ID))
        return &self_factory;
    return !strcmp(factory_id, CLAP_PRESET_DISCOVERY_FACTORY_ID) ? &self_preset_factory : NULL;
}

static const clap_plugin_entry_t harness_entry = { CLAP_VERSION_INIT, self_entry_init, self_entry_deinit, self_entry_factory };

/* ---------------------------------------------------------------- payload */

typedef struct { const uint8_t *p; size_t n; } payload;

static uint8_t byte(payload in, size_t i) { return i < in.n ? in.p[i] : 0; }
static uint32_t u32(payload in, size_t i)
{
    return (uint32_t)byte(in, i) | (uint32_t)byte(in, i + 1) << 8 | (uint32_t)byte(in, i + 2) << 16 | (uint32_t)byte(in, i + 3) << 24;
}
static uint32_t pick(payload in, size_t i, uint32_t n) { return n ? u32(in, i) % n : 0; }
/* parameter values: NaN, +-inf and 0 explicitly (hosts must reject or clamp them), otherwise a 16.16 fixed-point number */
static double val(payload in, size_t i)
{
    switch (byte(in, i) & 15)
    {
    case 0: return NAN;
    case 1: return INFINITY;
    case 2: return -INFINITY;
    case 3: return 0.0;
    default: return (double)(int32_t)u32(in, i) / 65536.0;
    }
}
/* parameter id 0..7 (the fixtures declare a few low ids) or, with bit 7 of the next byte, an id none declares */
static clap_id id_of(payload in, size_t i)
{
    if (byte(in, i + 1) & 0x80u)
        return 0xFFFFFF00u | byte(in, i);   /* never a parameter id a fixture declares */
    return byte(in, i) % 8u;
}
static void text(payload in, size_t i, char *out, size_t cap)
{
    size_t len, k;

    if (!cap)
        return;
    len = in.n > i ? in.n - i : 0;
    if (len > cap - 1)
        len = cap - 1;
    if (len > 128)  /* names and keys: 128 characters is past every fixed-size name field */
        len = 128;
    for (k = 0; k < len; k++)
    {
        const char c = (char)in.p[i + k];
        out[k] = (c >= ' ' && c < 127 && c != '\\' && c != ':') ? c : 'a';   /* a plain relative name, no path walks */
    }
    out[len] = '\0';
}
static double rate_of(payload in, size_t i)
{
    /* common sample rates, then degenerate ones (1, 0, 1e9) that configure must reject or survive */
    static const double rates[] = { 44100.0, 48000.0, 96000.0, 8000.0, 192000.0, 1.0, 0.0, 1e9 };
    return rates[pick(in, i, 8)];
}
static uint32_t block_of(payload in, size_t i)
{
    /* max block sizes from 1 frame to FRAMES_CAP */
    static const uint32_t blocks[] = { 1, 8, 32, 64, 128, 256, 512, 1024 };
    return blocks[pick(in, i, 8)];
}
static uint32_t frames_of(payload in, size_t i) { return 1u + pick(in, i, FRAMES_CAP); }

/* ---------------------------------------------------------------- fixtures */

struct fixture { const char *file; const char *id; };

/* one entry per (file, plugin id) a record may open; NULL id is the factory's first descriptor */
static const struct fixture fixtures[] = {
    { "fake.clap", NULL },
    { "fake.clap", "org.omx-clap-host.test.passthrough" },
    { "fake.clap", "org.omx-clap-host.test.wide" },
    { "fake.clap", "org.omx-clap-host.test.sidechain" },
    { "fake.clap", "org.omx-clap-host.test.notes" },
    { "fake.clap", "org.omx-clap-host.test.mono-stereo" },
    { "fake.clap", "org.omx-clap-host.test.stereo-mono" },
    { "fake.clap", "org.omx-clap-host.test.auxout" },
    { "fake.clap", "org.omx-clap-host.test.surround" },
    { "fake.clap", "org.omx-clap-host.test.configurable" },
    { "fake.clap", "org.omx-clap-host.test.zero-port" },
    { "fake.clap", "org.example.none" },
    { "fake_synth.clap", NULL },
    { "fake_synth.clap", "org.omx-clap-host.test.synth" },
    { "fake_synth.clap", "org.omx-clap-host.test.synth-midi" },
    { "fake_synth.clap", "org.omx-clap-host.test.synth-poly" },
    { "fake_synth.clap", "org.omx-clap-host.test.synth-mpe" },
    { "fake_synth.clap", "org.omx-clap-host.test.silent" },
    { "fake_compressor.clap", NULL },
    { "fake_compressor.clap", "org.omx-clap-host.test.compressor" },
    { "fake_ext.clap", NULL },
    { "fake_ext.clap", "org.omx-clap-host.test.ext" },
    { "fake_mover.clap", NULL },
    { "fake_transport.clap", NULL },
    { "fault-0.clap", NULL },
    { "fault-3.clap", NULL },
    { "fault-6.clap", NULL },
    { "fault-8.clap", NULL },
    { "fault-10.clap", NULL },
    { "fault-11.clap", NULL },
    { "fault-12.clap", NULL },
    { "fault-15.clap", NULL },
    { "fault-16.clap", NULL },
    { "fault-17.clap", NULL },
    { "nonexistent.clap", NULL },
};

#define FIXTURE_COUNT (sizeof fixtures / sizeof fixtures[0])

static const char *fixture_dir = ".";
static char fixture_path[512];

static const struct fixture *fixture_at(payload in, size_t i)
{
    return &fixtures[pick(in, i, FIXTURE_COUNT)];
}
static const char *fixture_file(const struct fixture *f)
{
    snprintf(fixture_path, sizeof fixture_path, "%s/%s", fixture_dir, f->file);
    return fixture_path;
}

/* ---------------------------------------------------------------- objects */

static struct omx_clap_instance *in;         /* the one live instance */
static struct omx_clap_binary *bin;          /* the one open binary (omx_clap_host_binary_open) */
static struct omx_clap_chain *chain;
static int instance_from_bin;                /* the instance was created from `bin` */
static int published;                        /* the stage was armed since the last unpublish/stop/deactivate */
static int role_held;

static struct omx_clap_host_config config;
static int configured = -1;                  /* omx_clap_host_configure's outcome, set once in LLVMFuzzerInitialize */
static int gui_offered = -1;                 /* omx_clap_host_offer_gui's outcome, the same */

static float audio_in[CH_CAP][FRAMES_CAP];
static float audio_out[CH_CAP][FRAMES_CAP];
static float aux_bufs[CH_CAP][FRAMES_CAP];
static float *aux_ptrs[CH_CAP];

static unsigned char state_buf[STATE_CAP];
static size_t state_len;
static char why[OMX_CLAP_WHY_MAX];
static char str_a[256], str_b[256];
static double dvalues[OMX_CLAP_METER_CHANNELS_MAX];
static struct omx_clap_param_row *rows;   /* the roster's malloc'd rows */
static struct omx_clap_param_row prow;    /* one row, for param_row/param_row_of */
static struct omx_clap_param_event events[32];
static struct omx_clap_meter meter;
static struct omx_clap_param_meaning meaning;
static struct omx_clap_role role;
static struct omx_clap_transport_src tsrc;
static struct omx_clap_tempo tempo;
static struct omx_clap_idle_hold hold;
static omx_resource_hints_t hints;
static clap_note_name_t note_name;
static clap_audio_port_configuration_request_t reqs[4];
static uint32_t member_ids[MAX_MEMBERS];
static uint32_t member_count;
static float stage_gain = 0.5f;
static uint32_t stage_channels = 1;   /* a chain member stage's width: its ctx, outliving the record that added it */
static int audio_ctx;

static void on_latency(void *ctx, uint32_t frames) { (void)ctx; (void)frames; }
static int is_audio_role(void *ctx, pthread_t self) { (void)ctx; return pthread_equal(self, pthread_self()); }

static void chain_stage(void *ctx, const float *const *ins, float *const *outs, uint32_t n)
{
    const uint32_t ch = *(const uint32_t *)ctx;
    uint32_t c, i;

    for (c = 0; c < ch; c++)
        for (i = 0; i < n; i++)
            outs[c][i] = ins[c][i] * stage_gain;
}

static int preset_keep(void *ctx, const struct omx_clap_preset *preset)
{
    (void)preset;
    return ++*(uint32_t *)ctx >= 8;   /* stop after eight: a listing is the library's to bound, the record's to stop */
}

/* one audio cycle on this thread, which is the instance's audio role: omx_clap_host_run_ports, the header's RT body */
static void run_block(uint32_t frames)
{
    const float *ins[CH_CAP];
    float *outs[CH_CAP];
    uint32_t c;

    if (frames > FRAMES_CAP)
        frames = FRAMES_CAP;
    for (c = 0; c < CH_CAP; c++)
    {
        ins[c] = audio_in[c];
        outs[c] = audio_out[c];
    }
    omx_clap_host_run_ports(in, ins, outs, frames);
}

/* no cycle runs but this one: the control thread stops the stage in the cycle's place (omx_clap_host_stop, 'once no
 * cycle can run anymore'), so the calls that want a stopped stage do not wait out CLAP_HOST_ROLE_TIMEOUT_US */
static void rt_stop(void)
{
    if (in && in->active && atomic_load(&in->stage.state) == OMX_CLAP_PROCESSING)
        omx_clap_host_stop(in);
    published = 0;
}

/* unpublish wants the RT to answer the stop; the block omx_clap_take_state turns STOPPING into STOPPED is run here */
static int unpublish_settle(unsigned poll_us, unsigned timeout_us)
{
    int rc = omx_clap_host_unpublish(in, poll_us, timeout_us);
    int tries;

    for (tries = 0; rc != 0 && tries < 2; tries++)
    {
        if (atomic_load(&in->stage.state) != OMX_CLAP_STOPPING)
            break;
        run_block(1);
        rc = omx_clap_host_unpublish(in, poll_us, timeout_us);
    }
    published = 0;
    return rc;
}

/* ---------------------------------------------------------------- dispatch macros */

#define REPORT_INT(name, expr, ok_cond) \
    do { if (!preqed_call(name)) return; int rc_ = (expr); preqed_result(name, (ok_cond)); } while (0)
#define REPORT_PTR(name, expr) \
    do { if (!preqed_call(name)) return; const void *p_ = (expr); preqed_result(name, p_ != NULL); } while (0)
#define REPORT_DONE(name, expr) \
    do { if (!preqed_call(name)) return; (void)(expr); preqed_result(name, 1); } while (0)

/* ---------------------------------------------------------------- version and configuration */

static void call_omx_clap_core_version(payload p) { (void)p; REPORT_INT("omx_clap_core_version", (int)omx_clap_core_version(), rc_ > 0); }

static void call_omx_clap_host_config_default(payload p)
{
    (void)p;
    REPORT_DONE("omx_clap_host_config_default", (omx_clap_host_config_default(&config), config.abi == OMX_CLAP_CORE_ABI));
}

static void call_omx_clap_host_config_default_sized(payload p)
{
    uint32_t size = 1u + pick(p, 1, (uint32_t)sizeof config);

    REPORT_DONE("omx_clap_host_config_default_sized", omx_clap_host_config_default_sized(&config, size));
}

/* configured once, in LLVMFuzzerInitialize (the header: once per process, before the first binary is opened); the record
 * reports that outcome */
static void call_omx_clap_host_configure(payload p)
{
    (void)p;
    REPORT_INT("omx_clap_host_configure", configured, rc_ == 0);
}

static void call_omx_clap_host_idle_hold_set(payload p)
{
    /* clap_host.h: OFF (-1) holds nothing, 0 refuses every idle state, 10 us is the default; -2 and 20000 are outside it */
    static const int32_t targets[] = { OMX_CLAP_IDLE_HOLD_OFF, 0, 1, 10, 100, 1000, -2, 20000 };
    REPORT_INT("omx_clap_host_idle_hold_set", omx_clap_host_idle_hold_set(targets[pick(p, 0, 8)]), rc_ == 0);
}

static void call_omx_clap_host_idle_hold(payload p)
{
    (void)p;
    REPORT_DONE("omx_clap_host_idle_hold", (omx_clap_host_idle_hold(&hold), hold.active));
}

/* offered once, in LLVMFuzzerInitialize (the header: before the first binary is opened), a clap_host_gui_t that creates
 * no window: the window paths need a display and are excluded; the record reports the outcome */
static void call_omx_clap_host_offer_gui(payload p)
{
    (void)p;
    REPORT_INT("omx_clap_host_offer_gui", gui_offered, rc_ == 0);
}

/* ---------------------------------------------------------------- binaries */
/* ltl: binary_lifecycle */
static void call_omx_clap_host_binary_open(payload p)
{
    const struct fixture *f;

    if (bin)
        return;
    f = fixture_at(p, 1);
    if (!preqed_call("omx_clap_host_binary_open"))
        return;
    str_a[0] = '\0';
    bin = omx_clap_host_binary_open(fixture_file(f), str_a, sizeof str_a);
    preqed_result("omx_clap_host_binary_open", bin != NULL);
}
/* ltl: binary_lifecycle */
static void call_omx_clap_host_binary_close(payload p)
{
    (void)p;
    if (!bin || (in && instance_from_bin))
        return;
    REPORT_DONE("omx_clap_host_binary_close", omx_clap_host_binary_close(bin));
    bin = NULL;
}
/* ltl: binary_lifecycle */
static void call_omx_clap_host_binary_count(payload p)
{
    (void)p;
    if (!bin)
        return;
    REPORT_INT("omx_clap_host_binary_count", (int)omx_clap_host_binary_count(bin), rc_ > 0);
}
/* ltl: binary_lifecycle */
static void call_omx_clap_host_binary_descriptor(payload p)
{
    if (!bin)
        return;
    if (!preqed_call("omx_clap_host_binary_descriptor"))
        return;
    (void)omx_clap_host_binary_descriptor(bin, pick(p, 1, omx_clap_host_binary_count(bin) + 2u));
    preqed_result("omx_clap_host_binary_descriptor", 1);
}

static void call_omx_clap_host_binaries_open(payload p)
{
    (void)p;
    REPORT_INT("omx_clap_host_binaries_open", (int)omx_clap_host_binaries_open(), rc_ >= 0);
}

/* the fixtures' directory holds more than one .clap, so the walk refuses it by count: the two answers the header names */
static void call_omx_clap_host_bundle_object(payload p)
{
    /* search dirs: cwd (where the fixtures are, twice as likely), a missing directory, and a file instead of a directory */
    static const char *dirs[] = { ".", ".", "/nonexistent", "fake.clap" };
    char object[256];
    char reason[128];
    const uint32_t which = pick(p, 0, 4);
    const char *dir = which < 2 ? fixture_dir : dirs[which];
    uint32_t cap = 1u + pick(p, 1, (uint32_t)sizeof object);

    if (!preqed_call("omx_clap_host_bundle_object"))
        return;
    (void)omx_clap_host_bundle_object(dir, object, cap, reason, sizeof reason);
    preqed_result("omx_clap_host_bundle_object", 1);
}
/* ltl: binary_lifecycle */
static void call_omx_clap_host_presets(payload p)
{
    uint32_t kept = 0;

    if (!bin)
        return;
    REPORT_INT("omx_clap_host_presets", omx_clap_host_presets(bin, preset_keep, &kept), rc_ >= 0);
}

static void call_omx_clap_host_entry_presets(payload p)
{
    uint32_t kept = 0;

    (void)p;
    REPORT_INT("omx_clap_host_entry_presets", omx_clap_host_entry_presets(&harness_entry, preset_keep, &kept), rc_ >= 0);
}

/* ---------------------------------------------------------------- open, create, close */
/* ltl: instance_lifecycle */
static void call_omx_clap_host_open(payload p)
{
    const struct fixture *f;

    if (in)
        return;
    f = fixture_at(p, 1);
    if (!preqed_call("omx_clap_host_open"))
        return;
    why[0] = '\0';
    if (omx_clap_host_open(fixture_file(f), f->id, &in, why) != 0)
        in = NULL;
    instance_from_bin = 0;
    preqed_result("omx_clap_host_open", in != NULL);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_open_entry(payload p)
{
    /* plugin id: NULL (first in the entry), the linked-in plugin, a fixture plugin's id (absent from this entry), an unknown id */
    static const char *ids[] = { NULL, SELF_ID, "org.omx-clap-host.test.synth", "org.example.none" };

    if (in)
        return;
    if (!preqed_call("omx_clap_host_open_entry"))
        return;
    why[0] = '\0';
    if (omx_clap_host_open_entry(&harness_entry, ids[pick(p, 1, 4)], &in, why) != 0)
        in = NULL;
    instance_from_bin = 0;
    preqed_result("omx_clap_host_open_entry", in != NULL);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_open_timed(payload p)
{
    /* a timeout that fires abandons the worker mid-load and leaks what it allocated (src/clap_host.c timed_open_run); the
     * fixtures open well within these, so the fuzz case reaches the completed arm and not the abandoned one */
    static const unsigned timeouts[] = { 100, 500, 2000 };  /* ms; 100 can abandon a slow open (NOTES.md omx-clap-core) */
    const struct fixture *f;

    if (in)
        return;
    f = fixture_at(p, 1);
    if (!preqed_call("omx_clap_host_open_timed"))
        return;
    why[0] = '\0';
    if (omx_clap_host_open_timed(fixture_file(f), f->id, timeouts[pick(p, 2, 3)], &in, why) != 0)
        in = NULL;
    instance_from_bin = 0;
    preqed_result("omx_clap_host_open_timed", in != NULL);
}
/* ltl: instance_lifecycle, binary_lifecycle */
static void call_omx_clap_host_create(payload p)
{
    const clap_plugin_descriptor_t *desc;

    if (in || !bin)
        return;
    desc = omx_clap_host_binary_descriptor(bin, 0);
    if (!desc)
        return;
    if (!preqed_call("omx_clap_host_create"))
        return;
    if (omx_clap_host_create(bin, desc, &in) != 0)
        in = NULL;
    instance_from_bin = in != NULL;
    preqed_result("omx_clap_host_create", in != NULL);
}
/* ltl: instance_lifecycle, activate_deactivate, audio_role_take_release, binary_lifecycle */
static void call_omx_clap_host_close(payload p)
{
    (void)p;
    if (!in)
        return;
    REPORT_DONE("omx_clap_host_close", omx_clap_host_close(in));
    in = NULL;
    published = 0;
    role_held = 0;
    instance_from_bin = 0;
    member_count = 0;
}

/* ---------------------------------------------------------------- activate, publish, unpublish */
/* ltl: instance_lifecycle, activate_deactivate, publish_when_active */
static void call_omx_clap_host_activate(payload p)
{
    if (!in)
        return;
    if (!preqed_call("omx_clap_host_activate"))
        return;
    why[0] = '\0';
    preqed_result("omx_clap_host_activate", omx_clap_host_activate(in, rate_of(p, 1), block_of(p, 5), why) == 0);
}

/* publish, publish_role, set_audio_thread, set_audio_role and arm all need an activated instance: the stage they touch
 * is the one omx_clap_host_activate binds (src/clap_host.h, omx_clap_take_state dereferences stage.plugin) */
/* ltl: instance_lifecycle, publish_when_active, bind_aux_while_stopped */
static void call_omx_clap_host_publish(payload p)
{
    (void)p;
    if (!in || !in->active)
        return;
    if (!preqed_call("omx_clap_host_publish"))
        return;
    omx_clap_host_publish(in, pthread_self());
    published = 1;
    preqed_result("omx_clap_host_publish", 1);
}
/* ltl: instance_lifecycle, publish_when_active */
static void call_omx_clap_host_publish_role(payload p)
{
    if (!in || !in->active)
        return;
    if (!preqed_call("omx_clap_host_publish_role"))
        return;
    omx_clap_host_publish_role(in, pthread_self(), pick(p, 0, 2) ? is_audio_role : NULL, pick(p, 0, 2) ? &audio_ctx : NULL);
    published = 1;
    preqed_result("omx_clap_host_publish_role", 1);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_set_audio_thread(payload p)
{
    (void)p;
    if (!in)
        return;
    REPORT_DONE("omx_clap_host_set_audio_thread", omx_clap_host_set_audio_thread(in, pthread_self()));
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_set_audio_role(payload p)
{
    if (!in)
        return;
    REPORT_DONE("omx_clap_host_set_audio_role",
                omx_clap_host_set_audio_role(in, pthread_self(), pick(p, 0, 2) ? is_audio_role : NULL,
                                             pick(p, 0, 2) ? &audio_ctx : NULL));
}
/* ltl: instance_lifecycle, publish_when_active */
static void call_omx_clap_host_arm(payload p)
{
    (void)p;
    if (!in || !in->active)
        return;
    if (!preqed_call("omx_clap_host_arm"))
        return;
    omx_clap_host_arm(in);
    published = 1;
    preqed_result("omx_clap_host_arm", 1);
}
/* ltl: instance_lifecycle, bind_aux_while_stopped */
static void call_omx_clap_host_unpublish(payload p)
{
    if (!in)
        return;
    if (!preqed_call("omx_clap_host_unpublish"))
        return;
    preqed_result("omx_clap_host_unpublish", unpublish_settle(10u, 50u + pick(p, 1, 500)) == 0);
}
/* ltl: instance_lifecycle, bind_aux_while_stopped */
static void call_omx_clap_host_stop(payload p)
{
    (void)p;
    if (!in)
        return;
    if (!preqed_call("omx_clap_host_stop"))
        return;
    omx_clap_host_stop(in);
    published = 0;
    preqed_result("omx_clap_host_stop", 1);
}
/* ltl: instance_lifecycle, activate_deactivate */
static void call_omx_clap_host_restart(payload p)
{
    (void)p;
    if (!in)
        return;
    if (!preqed_call("omx_clap_host_restart"))
        return;
    rt_stop();
    preqed_result("omx_clap_host_restart", omx_clap_host_restart(in) >= 0);
    published = in->active && atomic_load(&in->stage.state) == OMX_CLAP_ARMED;
}
/* ltl: instance_lifecycle, activate_deactivate, publish_when_active */
static void call_omx_clap_host_deactivate(payload p)
{
    (void)p;
    if (!in)
        return;
    if (!preqed_call("omx_clap_host_deactivate"))
        return;
    omx_clap_host_deactivate(in);
    published = 0;
    role_held = 0;
    preqed_result("omx_clap_host_deactivate", 1);
}
/* ltl: instance_lifecycle, activate_deactivate */
static void call_omx_clap_host_set_rate(payload p)
{
    if (!in)
        return;
    if (!preqed_call("omx_clap_host_set_rate"))
        return;
    rt_stop();
    why[0] = '\0';
    preqed_result("omx_clap_host_set_rate", omx_clap_host_set_rate(in, rate_of(p, 1), block_of(p, 5), why) >= 0);
    published = in->active && atomic_load(&in->stage.state) == OMX_CLAP_ARMED;
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_latency(payload p) { (void)p; if (!in) return; REPORT_INT("omx_clap_host_latency", (int)omx_clap_host_latency(in), rc_ >= 0); }
/* ltl: instance_lifecycle, audio_role_take_release */
static void call_omx_clap_host_take_role(payload p)
{
    (void)p;
    if (!in || role_held)
        return;
    if (!preqed_call("omx_clap_host_take_role"))
        return;
    omx_clap_host_take_role(in, &role);
    role_held = 1;
    preqed_result("omx_clap_host_take_role", 1);
}
/* ltl: instance_lifecycle, audio_role_take_release */
static void call_omx_clap_host_release_role(payload p)
{
    uint32_t state = pick(p, 0, 2) ? OMX_CLAP_STOPPED : role.state;

    if (!in || !role_held)
        return;
    if (!preqed_call("omx_clap_host_release_role"))
        return;
    omx_clap_host_release_role(in, &role, state);
    role_held = 0;
    preqed_result("omx_clap_host_release_role", 1);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_bypass(payload p)
{
    if (!in)
        return;
    REPORT_DONE("omx_clap_host_bypass", omx_clap_host_bypass(in, byte(p, 0) & 1));
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_bypassed(payload p) { (void)p; if (!in) return; REPORT_INT("omx_clap_host_bypassed", omx_clap_host_bypassed(in), 1); }

/* ---------------------------------------------------------------- parameters */
/* ltl: instance_lifecycle */
static void call_omx_clap_host_param_count(payload p) { (void)p; if (!in) return; REPORT_INT("omx_clap_host_param_count", (int)omx_clap_host_param_count(in), 1); }
/* ltl: instance_lifecycle */
static void call_omx_clap_host_param_row(payload p)
{
    if (!in)
        return;
    REPORT_INT("omx_clap_host_param_row", omx_clap_host_param_row(in, pick(p, 1, omx_clap_host_param_count(in) + 2u), &prow),
               rc_ == 0);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_param_roster(payload p)
{
    const char *why_roster = NULL;
    struct omx_clap_param_row *fresh = NULL;

    (void)p;
    if (!in)
        return;
    if (!preqed_call("omx_clap_host_param_roster"))
        return;
    free(rows);
    rows = NULL;
    preqed_result("omx_clap_host_param_roster", omx_clap_host_param_roster(in, &fresh, &why_roster) >= 0);
    rows = fresh;
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_param_write(payload p)
{
    if (!in)
        return;
    REPORT_INT("omx_clap_host_param_write", omx_clap_host_param_write(in, id_of(p, 0), val(p, 4)), rc_ == 0);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_param_modulate(payload p)
{
    if (!in)
        return;
    REPORT_INT("omx_clap_host_param_modulate", omx_clap_host_param_modulate(in, id_of(p, 0), val(p, 4)), rc_ == 0);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_param_gesture(payload p)
{
    if (!in)
        return;
    REPORT_INT("omx_clap_host_param_gesture", omx_clap_host_param_gesture(in, id_of(p, 0), byte(p, 4) & 1), rc_ == 0);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_param_flush(payload p)
{
    (void)p;
    if (!in)
        return;
    REPORT_INT("omx_clap_host_param_flush", omx_clap_host_param_flush(in), rc_ == 0);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_param_deliver(payload p)
{
    (void)p;
    if (!in)
        return;
    if (!preqed_call("omx_clap_host_param_deliver"))
        return;
    omx_clap_host_param_deliver(in);
    preqed_result("omx_clap_host_param_deliver", 1);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_settle(payload p)
{
    if (!in)
        return;
    if (!preqed_call("omx_clap_host_settle"))
        return;
    omx_clap_host_settle(in, pick(p, 1, 2000));
    preqed_result("omx_clap_host_settle", 1);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_param_compare(payload p)
{
    double applied = 0.0;

    if (!in)
        return;
    if (!preqed_call("omx_clap_host_param_compare"))
        return;
    (void)omx_clap_host_param_compare(in, id_of(p, 0), &applied);
    preqed_result("omx_clap_host_param_compare", 1);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_param_read(payload p)
{
    double value = 0.0;

    if (!in)
        return;
    if (!preqed_call("omx_clap_host_param_read"))
        return;
    (void)omx_clap_host_param_read(in, id_of(p, 0), &value);
    preqed_result("omx_clap_host_param_read", 1);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_param_value(payload p)
{
    double value = 0.0;

    if (!in)
        return;
    if (!preqed_call("omx_clap_host_param_value"))
        return;
    (void)omx_clap_host_param_value(in, id_of(p, 0), &value);
    preqed_result("omx_clap_host_param_value", 1);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_param_is_row(payload p) { if (!in) return; REPORT_INT("omx_clap_host_param_is_row", omx_clap_host_param_is_row(in, id_of(p, 0)), 1); }
/* ltl: instance_lifecycle */
static void call_omx_clap_host_param_readable(payload p) { if (!in) return; REPORT_INT("omx_clap_host_param_readable", omx_clap_host_param_readable(in, id_of(p, 0)), 1); }
/* ltl: instance_lifecycle */
static void call_omx_clap_host_param_row_of(payload p)
{
    if (!in)
        return;
    REPORT_INT("omx_clap_host_param_row_of", omx_clap_host_param_row_of(in, id_of(p, 0), &prow), rc_ == 0);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_params_rescanned(payload p) { (void)p; if (!in) return; REPORT_INT("omx_clap_host_params_rescanned", (int)omx_clap_host_params_rescanned(in), 1); }
/* ltl: instance_lifecycle */
static void call_omx_clap_host_param_text(payload p)
{
    uint32_t size = pick(p, 5, sizeof str_a);

    if (!in)
        return;
    REPORT_INT("omx_clap_host_param_text", omx_clap_host_param_text(in, id_of(p, 0), val(p, 1), str_a, size), rc_ == 0);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_param_parse(payload p)
{
    double value = 0.0;

    if (!in)
        return;
    text(p, 5, str_a, sizeof str_a);
    if (!preqed_call("omx_clap_host_param_parse"))
        return;
    (void)omx_clap_host_param_parse(in, id_of(p, 0), str_a, &value);
    preqed_result("omx_clap_host_param_parse", 1);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_param_contract(payload p)
{
    const char *why_contract = NULL;
    uint32_t version = 0;

    (void)p;
    if (!in)
        return;
    REPORT_INT("omx_clap_host_param_contract", omx_clap_host_param_contract(in, &version, &why_contract), rc_ >= 0);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_param_meaning(payload p)
{
    if (!in)
        return;
    REPORT_INT("omx_clap_host_param_meaning", omx_clap_host_param_meaning(in, id_of(p, 0), &meaning), rc_ == 0);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_param_events_take(payload p)
{
    if (!in)
        return;
    REPORT_INT("omx_clap_host_param_events_take", (int)omx_clap_host_param_events_take(in, events, pick(p, 1, 32)), 1);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_param_events_dropped(payload p) { (void)p; if (!in) return; REPORT_INT("omx_clap_host_param_events_dropped", (int)omx_clap_host_param_events_dropped(in), 1); }

static void call_omx_clap_param_unit_name(payload p)
{
    /* codes inside and past the OMX_CLAP_PARAM_UNITS table; the getter returns NULL for unknown ones */
    static const uint32_t units[] = { 0, 1, 13, 16, 22, 0x100, 0x103, 0x200, UINT32_MAX };
    REPORT_PTR("omx_clap_param_unit_name", omx_clap_param_unit_name(units[pick(p, 0, 9)]));
}

static void call_omx_clap_param_scale_name(payload p)
{
    static const uint32_t scales[] = { 0, 1, 2, 3, UINT32_MAX };  /* linear, log, stepped, and two unknown codes */
    REPORT_PTR("omx_clap_param_scale_name", omx_clap_param_scale_name(scales[pick(p, 0, 5)]));
}

static void call_omx_clap_param_number(payload p)
{
    size_t size = pick(p, 5, sizeof str_a);

    if (!preqed_call("omx_clap_param_number"))
        return;
    (void)omx_clap_param_number(val(p, 1), str_a, size);
    preqed_result("omx_clap_param_number", 1);
}

/* ---------------------------------------------------------------- state and presets */
/* ltl: instance_lifecycle */
static void call_omx_clap_host_state_save(payload p)
{
    size_t len = 0;
    size_t cap = 1u + pick(p, 1, STATE_CAP);

    if (!in)
        return;
    if (!preqed_call("omx_clap_host_state_save"))
        return;
    if (omx_clap_host_state_save(in, state_buf, cap, &len) == 0)
    {
        state_len = len < sizeof state_buf ? len : sizeof state_buf;
        preqed_result("omx_clap_host_state_save", 1);
    }
    else
        preqed_result("omx_clap_host_state_save", 0);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_state_load(payload p)
{
    const void *blob = byte(p, 1) & 1 ? state_buf : (p.n > 2 ? p.p + 2 : NULL);
    size_t len = state_len && (byte(p, 1) & 1) ? state_len : (p.n > 2 ? p.n - 2 : 0);

    if (!in)
        return;
    if (!blob && len)
        return;
    REPORT_INT("omx_clap_host_state_load", omx_clap_host_state_load(in, blob, len), rc_ == 0);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_state_save_context(payload p)
{
    /* the three CLAP state contexts and two invalid ones */
    static const uint32_t contexts[] = { CLAP_STATE_CONTEXT_FOR_PRESET, CLAP_STATE_CONTEXT_FOR_DUPLICATE, CLAP_STATE_CONTEXT_FOR_PROJECT, 0, 9 };
    size_t len = 0;
    size_t cap = 1u + pick(p, 5, STATE_CAP);

    if (!in)
        return;
    if (!preqed_call("omx_clap_host_state_save_context"))
        return;
    if (omx_clap_host_state_save_context(in, contexts[pick(p, 1, 5)], state_buf, cap, &len) == 0)
    {
        state_len = len < sizeof state_buf ? len : sizeof state_buf;
        preqed_result("omx_clap_host_state_save_context", 1);
    }
    else
        preqed_result("omx_clap_host_state_save_context", 0);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_state_load_context(payload p)
{
    /* the three CLAP state contexts and two invalid ones */
    static const uint32_t contexts[] = { CLAP_STATE_CONTEXT_FOR_PRESET, CLAP_STATE_CONTEXT_FOR_DUPLICATE, CLAP_STATE_CONTEXT_FOR_PROJECT, 0, 9 };
    const void *blob = byte(p, 2) & 1 ? state_buf : (p.n > 3 ? p.p + 3 : NULL);
    size_t len = state_len && (byte(p, 2) & 1) ? state_len : (p.n > 3 ? p.n - 3 : 0);

    if (!in || (!blob && len))
        return;
    REPORT_INT("omx_clap_host_state_load_context", omx_clap_host_state_load_context(in, contexts[pick(p, 1, 5)], blob, len), rc_ == 0);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_preset_load(payload p)
{
    if (!in)
        return;
    text(p, 1, str_a, sizeof str_a);
    REPORT_INT("omx_clap_host_preset_load", omx_clap_host_preset_load(in, str_a), rc_ == 0);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_preset_load_key(payload p)
{
    /* the two CLAP location kinds and two invalid ones */
    const uint32_t kinds[] = { CLAP_PRESET_DISCOVERY_LOCATION_FILE, CLAP_PRESET_DISCOVERY_LOCATION_PLUGIN, 0, 9 };
    const char *key = byte(p, 2) & 2 ? str_b : NULL;

    if (!in)
        return;
    text(p, 3, str_a, sizeof str_a);
    if (key)
        text(p, 3, str_b, sizeof str_b);
    REPORT_INT("omx_clap_host_preset_load_key", omx_clap_host_preset_load_key(in, kinds[pick(p, 1, 4)], str_a, key), rc_ == 0);
}

/* ---------------------------------------------------------------- what the plugin declares */
/* ltl: instance_lifecycle */
static void call_omx_clap_host_meter_count(payload p) { (void)p; if (!in) return; REPORT_INT("omx_clap_host_meter_count", (int)omx_clap_host_meter_count(in), 1); }
/* ltl: instance_lifecycle */
static void call_omx_clap_host_meter_info(payload p)
{
    if (!in)
        return;
    REPORT_INT("omx_clap_host_meter_info", omx_clap_host_meter_info(in, pick(p, 1, omx_clap_host_meter_count(in) + 1u), &meter), rc_ == 0);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_meter_values(payload p)
{
    if (!in)
        return;
    REPORT_INT("omx_clap_host_meter_values", (int)omx_clap_host_meter_values(in, id_of(p, 0), dvalues, pick(p, 5, OMX_CLAP_METER_CHANNELS_MAX + 1u)), 1);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_voice_info(payload p)
{
    uint32_t count = 0, capacity = 0;
    uint64_t flags = 0;

    (void)p;
    if (!in)
        return;
    REPORT_INT("omx_clap_host_voice_info", omx_clap_host_voice_info(in, &count, &capacity, &flags), 1);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_resource_hints(payload p)
{
    const char *why_hints = NULL;

    (void)p;
    if (!in)
        return;
    REPORT_INT("omx_clap_host_resource_hints", omx_clap_host_resource_hints(in, &hints, &why_hints), rc_ >= 0);
}

/* hint indexes: the defined ones and indexes past the end (32, UINT32_MAX) */
static void call_omx_clap_resource_hint_word(payload p) { static const uint32_t idx[] = { 0, 1, 2, 3, 4, 5, 32, UINT32_MAX }; REPORT_PTR("omx_clap_resource_hint_word", omx_clap_resource_hint_word(idx[pick(p, 0, 8)])); }

static void call_omx_clap_resource_hint_unit(payload p) { static const uint32_t idx[] = { 0, 1, 2, 3, 4, 5, 32, UINT32_MAX }; REPORT_PTR("omx_clap_resource_hint_unit", omx_clap_resource_hint_unit(idx[pick(p, 0, 8)])); }

static void call_omx_clap_resource_hint_figure(payload p)
{
    uint64_t figure = 0;
    const omx_resource_hints_t *h = byte(p, 1) & 1 ? &hints : NULL;

    if (!preqed_call("omx_clap_resource_hint_figure"))
        return;
    (void)omx_clap_resource_hint_figure(h, pick(p, 2, 34), &figure);  /* index 0..33, past the hint table */
    preqed_result("omx_clap_resource_hint_figure", 1);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_tail(payload p) { (void)p; if (!in) return; REPORT_INT("omx_clap_host_tail", (int)omx_clap_host_tail(in), 1); }
/* ltl: instance_lifecycle */
static void call_omx_clap_host_note_name_count(payload p) { (void)p; if (!in) return; REPORT_INT("omx_clap_host_note_name_count", (int)omx_clap_host_note_name_count(in), 1); }
/* ltl: instance_lifecycle */
static void call_omx_clap_host_note_name(payload p)
{
    if (!in)
        return;
    REPORT_INT("omx_clap_host_note_name", omx_clap_host_note_name(in, pick(p, 1, omx_clap_host_note_name_count(in) + 2u), &note_name), rc_ == 0);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_note_names_changed(payload p) { (void)p; if (!in) return; REPORT_INT("omx_clap_host_note_names_changed", omx_clap_host_note_names_changed(in), 1); }
/* ltl: instance_lifecycle */
static void call_omx_clap_host_note_ports_rescanned(payload p) { (void)p; if (!in) return; REPORT_INT("omx_clap_host_note_ports_rescanned", (int)omx_clap_host_note_ports_rescanned(in), 1); }
/* ltl: instance_lifecycle */
static void call_omx_clap_host_ports_rescanned(payload p) { (void)p; if (!in) return; REPORT_INT("omx_clap_host_ports_rescanned", omx_clap_host_ports_rescanned(in), 1); }
/* ltl: instance_lifecycle */
static void call_omx_clap_host_request_layout(payload p)
{
    uint32_t n = pick(p, 1, 4);
    uint32_t k;

    if (!in)
        return;
    for (k = 0; k < n; k++)
    {
        reqs[k].is_input = byte(p, 2 + k) & 1;
        reqs[k].port_index = pick(p, 2 + k, 2);
        reqs[k].channel_count = 1u + pick(p, 3 + k, CH_CAP);
        reqs[k].port_type = (byte(p, 4 + k) & 1) ? CLAP_PORT_STEREO : (byte(p, 4 + k) & 2 ? CLAP_PORT_MONO : NULL);
        reqs[k].port_details = NULL;
    }
    if (!preqed_call("omx_clap_host_request_layout"))
        return;
    why[0] = '\0';
    preqed_result("omx_clap_host_request_layout",
                   omx_clap_host_request_layout(in, n ? reqs : NULL, n, why) >= 0);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_tick(payload p)
{
    (void)p;
    if (!in)
        return;
    REPORT_INT("omx_clap_host_tick", omx_clap_host_tick(in), 1);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_log_take(payload p)
{
    (void)p;
    if (!in)
        return;
    if (!preqed_call("omx_clap_host_log_take"))
        return;
    (void)omx_clap_host_log_take(in);
    preqed_result("omx_clap_host_log_take", 1);
}

static void call_omx_clap_host_has_feature(payload p)
{
    /* standard CLAP feature strings and one no plugin declares */
    static const char *features[] = { CLAP_PLUGIN_FEATURE_AUDIO_EFFECT, CLAP_PLUGIN_FEATURE_INSTRUMENT,
                                      CLAP_PLUGIN_FEATURE_NOTE_EFFECT, CLAP_PLUGIN_FEATURE_STEREO, "org.omx-clap-host.test.x" };
    const clap_plugin_descriptor_t *desc = bin ? omx_clap_host_binary_descriptor(bin, 0) : NULL;

    REPORT_INT("omx_clap_host_has_feature", omx_clap_host_has_feature(desc ? desc : &self_desc, features[pick(p, 1, 5)]), 1);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_track_info_set(payload p)
{
    clap_color_t color = { byte(p, 3), byte(p, 4), byte(p, 5), byte(p, 6) };
    const clap_color_t *c = byte(p, 7) & 1 ? &color : NULL;

    if (!in)
        return;
    text(p, 8, str_a, sizeof str_a);
    REPORT_INT("omx_clap_host_track_info_set", omx_clap_host_track_info_set(in, byte(p, 0) & 2 ? NULL : str_a, c, byte(p, 9) & 7), rc_ == 0);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_remote_controls_changed(payload p) { (void)p; if (!in) return; REPORT_INT("omx_clap_host_remote_controls_changed", omx_clap_host_remote_controls_changed(in), 1); }
/* ltl: instance_lifecycle */
static void call_omx_clap_host_set_render(payload p)
{
    static const int32_t modes[] = { CLAP_RENDER_REALTIME, CLAP_RENDER_OFFLINE, 9 };  /* the two CLAP render modes and an invalid one */

    if (!in)
        return;
    REPORT_INT("omx_clap_host_set_render", omx_clap_host_set_render(in, modes[pick(p, 0, 3)]), rc_ == 0);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_set_tempo(payload p)
{
    if (!in)
        return;
    if (!preqed_call("omx_clap_host_set_tempo"))
        return;
    omx_clap_tempo_publish(&tempo, byte(p, 0) & 2 ? 0.0 : 40.0 + (double)pick(p, 1, 200));  /* 40..239 BPM, or 0 = no tempo */
    omx_clap_host_set_tempo(in, byte(p, 0) & 1 ? NULL : &tempo);
    preqed_result("omx_clap_host_set_tempo", 1);
}
/* ltl: instance_lifecycle */
static void call_omx_clap_host_set_transport(payload p)
{
    struct omx_clap_transport t;

    if (!in)
        return;
    if (!preqed_call("omx_clap_host_set_transport"))
        return;
    memset(&t, 0, sizeof t);
    t.flags = u32(p, 0) & (CLAP_TRANSPORT_HAS_TEMPO | CLAP_TRANSPORT_HAS_BEATS_TIMELINE | CLAP_TRANSPORT_HAS_SECONDS_TIMELINE
                           | CLAP_TRANSPORT_HAS_TIME_SIGNATURE | CLAP_TRANSPORT_IS_PLAYING | CLAP_TRANSPORT_IS_LOOP_ACTIVE
                           | CLAP_TRANSPORT_IS_RECORDING);
    t.tempo = 20.0 + (double)pick(p, 4, 400);  /* 20..419 BPM; positions below are raw fixed-point CLAP beat/second times */
    t.song_pos_beats = (clap_beattime)(int64_t)u32(p, 8);
    t.song_pos_seconds = (clap_sectime)(int64_t)u32(p, 12);
    t.bar_start = (clap_beattime)(int64_t)u32(p, 16);
    t.bar_number = (int32_t)pick(p, 20, 64);
    t.tsig_num = (uint16_t)(1u + pick(p, 24, 16));
    t.tsig_denom = (uint16_t)(1u << pick(p, 26, 5));  /* time signature 1..16 over 1, 2, 4, 8, 16 */
    omx_clap_transport_publish(&tsrc, &t);
    omx_clap_host_set_transport(in, byte(p, 28) & 1 ? NULL : &tsrc);
    preqed_result("omx_clap_host_set_transport", 1);
}
/* ltl: instance_lifecycle, bind_aux_while_stopped */
static void call_omx_clap_host_bind_aux_input(payload p)
{
    uint32_t port = pick(p, 1, 3);
    uint32_t channels;
    uint32_t c;

    if (!in)
        return;
    channels = in->aux_inputs > port && !(byte(p, 2) & 0x80) ? in->aux_in[port].channels : pick(p, 3, CH_CAP);
    for (c = 0; c < CH_CAP; c++)
        aux_ptrs[c] = (byte(p, 4) & 1) ? audio_in[c] : NULL;
    REPORT_INT("omx_clap_host_bind_aux_input",
               omx_clap_host_bind_aux_input(in, port, byte(p, 0) & 1 ? aux_ptrs : NULL, channels, FRAMES_CAP), rc_ == 0);
}
/* ltl: instance_lifecycle, bind_aux_while_stopped */
static void call_omx_clap_host_bind_aux_output(payload p)
{
    uint32_t port = pick(p, 1, 3);
    uint32_t channels;
    uint32_t c;

    if (!in)
        return;
    channels = in->aux_outputs > port && !(byte(p, 2) & 0x80) ? in->aux_out[port].channels : pick(p, 3, CH_CAP);
    for (c = 0; c < CH_CAP; c++)
        aux_ptrs[c] = (byte(p, 4) & 1) ? audio_out[c] : NULL;
    REPORT_INT("omx_clap_host_bind_aux_output",
               omx_clap_host_bind_aux_output(in, port, byte(p, 0) & 1 ? aux_ptrs : NULL, channels, FRAMES_CAP), rc_ == 0);
}

/* ---------------------------------------------------------------- chain */
/* ltl: chain_lifecycle */
static void call_omx_clap_chain_create(payload p)
{
    struct omx_clap_chain_config cfg;

    if (chain)
        return;
    omx_clap_chain_config_init(&cfg);
    cfg.channels = 1u + pick(p, 1, 4);  /* 1..4 chain channels */
    cfg.latency_changed = byte(p, 2) & 1 ? on_latency : NULL;
    cfg.ctx = &audio_ctx;
    if (!preqed_call("omx_clap_chain_create"))
        return;
    preqed_result("omx_clap_chain_create", omx_clap_chain_create(&cfg, &chain) == OMX_CLAP_CHAIN_OK && chain != NULL);
    member_count = 0;
}
/* ltl: chain_lifecycle */
static void call_omx_clap_chain_destroy(payload p)
{
    (void)p;
    if (!chain)
        return;
    REPORT_DONE("omx_clap_chain_destroy", omx_clap_chain_destroy(chain));
    chain = NULL;
    member_count = 0;
}
/* ltl: chain_lifecycle */
static void call_omx_clap_chain_add(payload p)
{
    struct omx_clap_chain_member m;
    struct omx_clap_chain_report report;
    uint32_t id = 0;
    int use_instance;

    if (!chain)
        return;
    omx_clap_chain_report_init(&report);
    (void)omx_clap_chain_report(chain, &report);
    /* an instance member: one the caller opened, activated and published, of the chain's width */
    use_instance = byte(p, 1) & 1 && in && in->active && published && in->main_in.channels == report.channels
                   && in->main_out.channels == report.channels;
    omx_clap_chain_member_init(&m);
    if (use_instance)
        m.instance = in;
    else
    {
        stage_channels = report.channels;
        m.process = chain_stage;
        m.ctx = &stage_channels;
        m.in_channels = report.channels;
        m.out_channels = report.channels;
        m.latency = pick(p, 2, 256);  /* reported latency 0..255 frames */
    }
    m.bypass = byte(p, 3) & 1;
    if (!preqed_call("omx_clap_chain_add"))
        return;
    preqed_result("omx_clap_chain_add",
                   omx_clap_chain_add(chain, &m, byte(p, 4) & 1 ? OMX_CLAP_CHAIN_END : pick(p, 5, MAX_MEMBERS + 2u), &id) == OMX_CLAP_CHAIN_OK);
    if (member_count < MAX_MEMBERS)
        member_ids[member_count++] = id;
}
/* ltl: chain_lifecycle */
static void call_omx_clap_chain_remove(payload p)
{
    uint32_t id = byte(p, 0) & 1 && member_count ? member_ids[pick(p, 1, member_count)] : pick(p, 1, MAX_MEMBERS);

    if (!chain)
        return;
    REPORT_INT("omx_clap_chain_remove", omx_clap_chain_remove(chain, id), rc_ == OMX_CLAP_CHAIN_OK || rc_ == OMX_CLAP_CHAIN_ERR_NO_MEMBER);
}
/* ltl: chain_lifecycle */
static void call_omx_clap_chain_bypass(payload p)
{
    uint32_t id = byte(p, 0) & 1 && member_count ? member_ids[pick(p, 1, member_count)] : pick(p, 1, MAX_MEMBERS);

    if (!chain)
        return;
    REPORT_INT("omx_clap_chain_bypass", omx_clap_chain_bypass(chain, id, byte(p, 2) & 1),
               rc_ == OMX_CLAP_CHAIN_OK || rc_ == OMX_CLAP_CHAIN_ERR_NO_MEMBER);
}
/* ltl: chain_lifecycle */
static void call_omx_clap_chain_member_latency_set(payload p)
{
    uint32_t id = byte(p, 0) & 1 && member_count ? member_ids[pick(p, 1, member_count)] : pick(p, 1, MAX_MEMBERS);

    if (!chain)
        return;
    REPORT_INT("omx_clap_chain_member_latency_set", omx_clap_chain_member_latency_set(chain, id, pick(p, 2, 512)),
               rc_ == OMX_CLAP_CHAIN_OK || rc_ == OMX_CLAP_CHAIN_ERR_NO_MEMBER);
}
/* ltl: chain_lifecycle */
static void call_omx_clap_chain_refresh(payload p) { (void)p; if (!chain) return; REPORT_INT("omx_clap_chain_refresh", omx_clap_chain_refresh(chain), rc_ == OMX_CLAP_CHAIN_OK); }
/* ltl: chain_lifecycle */
static void call_omx_clap_chain_report(payload p)
{
    struct omx_clap_chain_report report;

    (void)p;
    if (!chain)
        return;
    omx_clap_chain_report_init(&report);
    REPORT_INT("omx_clap_chain_report", omx_clap_chain_report(chain, &report), rc_ == OMX_CLAP_CHAIN_OK);
}
/* ltl: chain_lifecycle */
static void call_omx_clap_chain_member_info(payload p)
{
    struct omx_clap_chain_member_info info;

    if (!chain)
        return;
    omx_clap_chain_member_info_init(&info);
    REPORT_INT("omx_clap_chain_member_info", omx_clap_chain_member_info(chain, pick(p, 0, MAX_MEMBERS + 2u), &info),
               rc_ == OMX_CLAP_CHAIN_OK || rc_ == OMX_CLAP_CHAIN_ERR_NO_MEMBER);
}
/* ltl: chain_lifecycle */
static void call_omx_clap_chain_process(payload p)
{
    struct omx_clap_chain_report report;
    const float *ins[CH_CAP];
    float *outs[CH_CAP];
    uint32_t frames = frames_of(p, 1), c;

    if (!chain)
        return;
    omx_clap_chain_report_init(&report);
    if (omx_clap_chain_report(chain, &report) != OMX_CLAP_CHAIN_OK || !report.channels)
        return;
    for (c = 0; c < report.channels && c < CH_CAP; c++)
    {
        ins[c] = audio_in[c];
        outs[c] = audio_out[c];
    }
    if (frames > FRAMES_CAP)
        frames = FRAMES_CAP;
    REPORT_INT("omx_clap_chain_process", omx_clap_chain_process(chain, ins, outs, frames),
               rc_ == OMX_CLAP_CHAIN_OK || rc_ == OMX_CLAP_CHAIN_PASSED);
}

/* ---------------------------------------------------------------- the RT body (no export: reports no event) */

static void call_run_block(payload p)
{
    uint32_t frames, ni, no, c, i;
    uint32_t notes = pick(p, 1, 5);

    if (!in || !in->active)
        return;
    frames = frames_of(p, 8);
    if (frames > FRAMES_CAP)
        frames = FRAMES_CAP;
    ni = in->main_in.channels;
    no = in->main_out.channels;
    if (ni > CH_CAP)
        ni = CH_CAP;
    if (no > CH_CAP)
        no = CH_CAP;
    for (c = 0; c < ni; c++)
        for (i = 0; i < frames; i++)
            audio_in[c][i] = (float)(int8_t)byte(p, 12 + c * 3 + i % 3) / 128.0f;
    while (notes--)
    {
        uint8_t msg[3];

        msg[0] = (uint8_t)(0x90 | (byte(p, 9) & 0x0f));  /* MIDI note-on, channel 0..15, note and velocity 0..127 */
        msg[1] = (uint8_t)pick(p, 10, 128);
        msg[2] = (uint8_t)pick(p, 11, 128);
        omx_clap_host_note_in(in, 0, msg, sizeof msg);
    }
    run_block(frames);
}

/* ---------------------------------------------------------------- dispatch */

static void (*const api[])(payload) = {
    call_omx_clap_core_version,
    call_omx_clap_host_config_default, call_omx_clap_host_config_default_sized, call_omx_clap_host_configure,
    call_omx_clap_host_idle_hold_set, call_omx_clap_host_idle_hold, call_omx_clap_host_offer_gui,
    call_omx_clap_host_binary_open, call_omx_clap_host_binary_close, call_omx_clap_host_binary_count,
    call_omx_clap_host_binary_descriptor, call_omx_clap_host_binaries_open, call_omx_clap_host_bundle_object,
    call_omx_clap_host_presets, call_omx_clap_host_entry_presets,
    call_omx_clap_host_open, call_omx_clap_host_open_entry, call_omx_clap_host_open_timed, call_omx_clap_host_create,
    call_omx_clap_host_close,
    call_omx_clap_host_activate, call_omx_clap_host_publish, call_omx_clap_host_publish_role,
    call_omx_clap_host_set_audio_thread, call_omx_clap_host_set_audio_role, call_omx_clap_host_arm,
    call_omx_clap_host_unpublish, call_omx_clap_host_stop, call_omx_clap_host_restart, call_omx_clap_host_deactivate,
    call_omx_clap_host_set_rate, call_omx_clap_host_latency, call_omx_clap_host_take_role,
    call_omx_clap_host_release_role, call_omx_clap_host_bypass, call_omx_clap_host_bypassed,
    call_omx_clap_host_param_count, call_omx_clap_host_param_row, call_omx_clap_host_param_roster,
    call_omx_clap_host_param_write, call_omx_clap_host_param_modulate, call_omx_clap_host_param_gesture,
    call_omx_clap_host_param_flush, call_omx_clap_host_param_deliver, call_omx_clap_host_settle,
    call_omx_clap_host_param_compare, call_omx_clap_host_param_read, call_omx_clap_host_param_value,
    call_omx_clap_host_param_is_row, call_omx_clap_host_param_readable, call_omx_clap_host_param_row_of,
    call_omx_clap_host_params_rescanned, call_omx_clap_host_param_text, call_omx_clap_host_param_parse,
    call_omx_clap_host_param_contract, call_omx_clap_host_param_meaning, call_omx_clap_host_param_events_take,
    call_omx_clap_host_param_events_dropped, call_omx_clap_param_unit_name, call_omx_clap_param_scale_name,
    call_omx_clap_param_number,
    call_omx_clap_host_state_save, call_omx_clap_host_state_load, call_omx_clap_host_state_save_context,
    call_omx_clap_host_state_load_context, call_omx_clap_host_preset_load, call_omx_clap_host_preset_load_key,
    call_omx_clap_host_meter_count, call_omx_clap_host_meter_info, call_omx_clap_host_meter_values,
    call_omx_clap_host_voice_info, call_omx_clap_host_resource_hints, call_omx_clap_resource_hint_word,
    call_omx_clap_resource_hint_unit, call_omx_clap_resource_hint_figure, call_omx_clap_host_tail,
    call_omx_clap_host_note_name_count, call_omx_clap_host_note_name, call_omx_clap_host_note_names_changed,
    call_omx_clap_host_note_ports_rescanned, call_omx_clap_host_ports_rescanned, call_omx_clap_host_request_layout,
    call_omx_clap_host_tick, call_omx_clap_host_log_take, call_omx_clap_host_has_feature,
    call_omx_clap_host_track_info_set, call_omx_clap_host_remote_controls_changed, call_omx_clap_host_set_render,
    call_omx_clap_host_set_tempo, call_omx_clap_host_set_transport, call_omx_clap_host_bind_aux_input,
    call_omx_clap_host_bind_aux_output,
    call_omx_clap_chain_create, call_omx_clap_chain_destroy, call_omx_clap_chain_add, call_omx_clap_chain_remove,
    call_omx_clap_chain_bypass, call_omx_clap_chain_member_latency_set, call_omx_clap_chain_refresh,
    call_omx_clap_chain_report, call_omx_clap_chain_member_info, call_omx_clap_chain_process,
    call_run_block,
};

#define API_COUNT (sizeof api / sizeof api[0])

static void cleanup(void)
{
    if (chain)
        omx_clap_chain_destroy(chain);
    if (in)
        omx_clap_host_close(in);
    if (bin)
        omx_clap_host_binary_close(bin);
    chain = NULL;
    in = NULL;
    bin = NULL;
    free(rows);
    rows = NULL;
    state_len = 0;
    member_count = 0;
    published = 0;
    role_held = 0;
    instance_from_bin = 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    const char *dir = getenv("OMX_CLAP_FIXTURES");

    (void)argc;
    (void)argv;
    /* idle_hold.c:67 writes /dev/cpu_dma_latency unless this names another file */
    setenv("OMX_CLAP_IDLE_HOLD_DEVICE", "omx-idle-hold", 0);
    if (dir && *dir)
        fixture_dir = dir;
    omx_clap_host_config_default(&config);
    config.clamp = 1;
    config.nonfinite = 1;
    config.warmup = 1;
    config.note_inputs = 1;
    config.preset_load = 1;
    config.track_info = 1;
    config.remote_controls = 1;
    config.lane_channels = 0;
    configured = omx_clap_host_configure(&config);
    {
        static const clap_host_gui_t no_window = { 0 };

        gui_offered = omx_clap_host_offer_gui(&no_window);
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    size_t off = 0;

    preqed_reset();
    while (size - off >= 3)
    {
        const uint8_t op = data[off];
        const size_t len = (size_t)data[off + 1] | (size_t)data[off + 2] << 8;
        payload p;

        off += 3;
        if (len > size - off)
            break;
        p.p = data + off;
        p.n = len;
        api[op % API_COUNT](p);
        off += len;
    }
    cleanup();
    return 0;
}
