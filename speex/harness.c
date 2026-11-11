#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <speex/speex.h>
#include <speex/speex_callbacks.h>
#include <speex/speex_header.h>
#include <speex/speex_stereo.h>
#include "preqed_ltl.h"

#define MAX_FRAME 640                       /* ultra-wideband: 20 ms at 32 kHz */
#define PACKET_CAP 8192

typedef struct {
    const uint8_t *p;
    size_t n;
} payload;

static void *enc, *dec;
static int enc_frame, dec_frame;
static SpeexBits bits;
static int bits_valid;
static SpeexStereoState *stereo;
static int dec_uses_stereo;                 /* decoder holds a SET_HANDLER callback pointing at stereo */
static SpeexHeader header;
static int header_valid;
static char *header_packet;                 /* speex_header_to_packet result, freed with speex_header_free */
static int header_packet_size;
static SpeexHeader *parsed_header;          /* speex_packet_to_header result, freed with speex_header_free */
static char bit_buffer[PACKET_CAP];
static char packet[PACKET_CAP];
static int packet_size;
static spx_int16_t pcm[2 * MAX_FRAME];
static float pcm_float[2 * MAX_FRAME];

static uint8_t byte(payload in, size_t i) { return i < in.n ? in.p[i] : 0; }
static payload rest(payload in, size_t skip) {
    payload r = { in.p + (skip < in.n ? skip : in.n), in.n > skip ? in.n - skip : 0 };
    return r;
}

/* speex.h exports the three modes; frames are 20 ms: 160 / 320 / 640 samples */
static const SpeexMode *mode_of(uint8_t b) {
    static const SpeexMode *const modes[] = { &speex_nb_mode, &speex_wb_mode, &speex_uwb_mode };
    return modes[b % 3];
}
static int frame_of(uint8_t b) { return 160 << (b % 3); }  /* 20 ms frames: 160 / 320 / 640 samples */

static void fill_pcm(payload in, int samples) {
    for (int i = 0; i < samples; i++) {
        unsigned lo = in.n ? in.p[(2 * (size_t)i) % in.n] : 0, hi = in.n ? in.p[(2 * (size_t)i + 1) % in.n] : 0;
        pcm[i] = (spx_int16_t)((lo | hi << 8) - 32768);  /* full-scale signed 16-bit samples */
        pcm_float[i] = pcm[i];
    }
}

static int encoder_request(uint8_t b) {
    /* every speex_encoder_ctl request (speex.h) */
    static const int r[] = { SPEEX_SET_QUALITY, SPEEX_SET_COMPLEXITY, SPEEX_SET_MODE, SPEEX_SET_LOW_MODE,
        SPEEX_SET_HIGH_MODE, SPEEX_SET_VBR, SPEEX_SET_VBR_QUALITY, SPEEX_SET_BITRATE, SPEEX_SET_SAMPLING_RATE,
        SPEEX_SET_VAD, SPEEX_SET_ABR, SPEEX_SET_DTX, SPEEX_SET_SUBMODE_ENCODING, SPEEX_SET_PLC_TUNING,
        SPEEX_SET_VBR_MAX_BITRATE, SPEEX_SET_HIGHPASS, SPEEX_GET_FRAME_SIZE, SPEEX_GET_MODE, SPEEX_GET_LOW_MODE,
        SPEEX_GET_HIGH_MODE, SPEEX_GET_VBR, SPEEX_GET_VBR_QUALITY, SPEEX_GET_COMPLEXITY, SPEEX_GET_BITRATE,
        SPEEX_GET_SAMPLING_RATE, SPEEX_GET_VAD, SPEEX_GET_ABR, SPEEX_GET_DTX, SPEEX_GET_SUBMODE_ENCODING,
        SPEEX_GET_LOOKAHEAD, SPEEX_GET_PLC_TUNING, SPEEX_GET_VBR_MAX_BITRATE, SPEEX_GET_HIGHPASS, SPEEX_RESET_STATE };
    return r[b % (sizeof r / sizeof r[0])];
}
static int decoder_request(uint8_t b) {
    /* every speex_decoder_ctl request except SET_HANDLER/SET_USER_HANDLER, which have their own wrappers */
    static const int r[] = { SPEEX_SET_ENH, SPEEX_GET_ENH, SPEEX_GET_FRAME_SIZE, SPEEX_SET_MODE, SPEEX_GET_MODE,
        SPEEX_SET_LOW_MODE, SPEEX_GET_LOW_MODE, SPEEX_SET_HIGH_MODE, SPEEX_GET_HIGH_MODE, SPEEX_GET_BITRATE,
        SPEEX_SET_SAMPLING_RATE, SPEEX_GET_SAMPLING_RATE, SPEEX_GET_LOOKAHEAD, SPEEX_SET_HIGHPASS,
        SPEEX_GET_HIGHPASS, SPEEX_GET_ACTIVITY, SPEEX_RESET_STATE };
    return r[b % (sizeof r / sizeof r[0])];
}
static int request_value(int req, uint8_t b) {
    switch (req) {
    /* values in each request's documented range, plus out-of-range ones for the ranged ones */
    case SPEEX_SET_SAMPLING_RATE: return 8000 * (1 + b % 4);  /* 8, 16, 24, 32 kHz */
    case SPEEX_SET_BITRATE: case SPEEX_SET_ABR: case SPEEX_SET_VBR_MAX_BITRATE: return 2000 + b * 160;  /* 2..42.8 kbps */
    case SPEEX_SET_QUALITY: case SPEEX_SET_COMPLEXITY: return b % 11;  /* 0..10 */
    case SPEEX_SET_MODE: case SPEEX_SET_LOW_MODE: case SPEEX_SET_HIGH_MODE: return b % 8;  /* submode 0..7 */
    case SPEEX_SET_PLC_TUNING: return b % 101;  /* expected loss 0..100 % */
    default: return b & 1;
    }
}

#define REPORT(api, stmt, ok_cond) \
    do { if (preqed_call(#api)) { stmt; preqed_result(#api, (ok_cond)); } } while (0)
#define REPORT_VOID(api, stmt) REPORT(api, stmt, 1)

/* modes and library */

static void call_speex_lib_get_mode(payload in) {
    REPORT(speex_lib_get_mode, const SpeexMode *m = speex_lib_get_mode(byte(in, 0) % 4), m != NULL);  /* 0..2 = nb/wb/uwb, 3 invalid */
}

static void call_speex_mode_query(payload in) {
    int request = byte(in, 1) & 1 ? SPEEX_SUBMODE_BITS_PER_FRAME : SPEEX_MODE_FRAME_SIZE;
    int value = byte(in, 2) % (byte(in, 0) % 3 ? 8 : 16);  /* submode index: NB_SUBMODES 16, SB_SUBMODES 8 (modes.h) */
    REPORT(speex_mode_query, int rc = speex_mode_query(mode_of(byte(in, 0)), request, &value), rc == 0);
}

static void call_speex_lib_ctl(payload in) {
    int request = 1 + 2 * (byte(in, 0) % 5);  /* SPEEX_LIB_GET_MAJOR/MINOR/MICRO_VERSION (ints), EXTRA/VERSION_STRING (strings) */
    int value = 0;
    const char *version = NULL;
    REPORT(speex_lib_ctl, int rc = speex_lib_ctl(request, request <= 5 ? (void *)&value : (void *)&version), rc == 0);
}

/* encoder */
/* ltl: encoder_lifecycle */
static void call_speex_encoder_init(payload in) {
    if (enc) return;
    REPORT(speex_encoder_init, enc = speex_encoder_init(mode_of(byte(in, 0))), enc != NULL);
    enc_frame = frame_of(byte(in, 0));
}
/* ltl: encoder_lifecycle */
static void call_speex_encoder_ctl(payload in) {
    if (!enc) return;
    int req = encoder_request(byte(in, 0));
    int value = request_value(req, byte(in, 1));
    float fvalue = byte(in, 1) % 11;  /* VBR quality 0..10 */
    int is_float = req == SPEEX_SET_VBR_QUALITY || req == SPEEX_GET_VBR_QUALITY;
    REPORT(speex_encoder_ctl, int rc = speex_encoder_ctl(enc, req, is_float ? (void *)&fvalue : (void *)&value), rc == 0);
}
/* ltl: encoder_lifecycle, bits_lifecycle */
static void call_speex_encode(payload in) {
    if (!enc || !bits_valid) return;
    fill_pcm(in, enc_frame);
    REPORT(speex_encode, int rc = speex_encode(enc, pcm_float, &bits), rc >= 0);
}
/* ltl: encoder_lifecycle, bits_lifecycle */
static void call_speex_encode_int(payload in) {
    if (!enc || !bits_valid) return;
    fill_pcm(in, enc_frame);
    REPORT(speex_encode_int, int rc = speex_encode_int(enc, pcm, &bits), rc >= 0);
}
/* ltl: encoder_lifecycle */
static void call_speex_encoder_destroy(payload in) {
    (void)in;
    if (!enc) return;
    REPORT_VOID(speex_encoder_destroy, speex_encoder_destroy(enc));
    enc = NULL;
}

/* decoder */
/* ltl: decoder_lifecycle */
static void call_speex_decoder_init(payload in) {
    if (dec) return;
    REPORT(speex_decoder_init, dec = speex_decoder_init(mode_of(byte(in, 0))), dec != NULL);
    dec_frame = frame_of(byte(in, 0));
    dec_uses_stereo = 0;
}
/* ltl: decoder_lifecycle */
static void call_speex_decoder_ctl(payload in) {
    if (!dec) return;
    int req = decoder_request(byte(in, 0));
    int value = request_value(req, byte(in, 1));
    REPORT(speex_decoder_ctl, int rc = speex_decoder_ctl(dec, req, &value), rc == 0);
}
/* ltl: decoder_lifecycle, stereo_state_lifecycle, stereo_state_outlives_decoder_handler */
static void call_speex_decoder_ctl_set_handler(payload in) {
    (void)in;
    if (!dec || !stereo) return;
    SpeexCallback cb = { .callback_id = SPEEX_INBAND_STEREO, .func = speex_std_stereo_request_handler, .data = stereo };
    if (!preqed_call("speex_decoder_ctl(SPEEX_SET_HANDLER)")) return;
    int rc = speex_decoder_ctl(dec, SPEEX_SET_HANDLER, &cb);
    preqed_result("speex_decoder_ctl(SPEEX_SET_HANDLER)", rc == 0);
    dec_uses_stereo |= rc == 0;
}
/* ltl: decoder_lifecycle */
static void call_speex_decoder_ctl_set_user_handler(payload in) {
    (void)in;
    if (!dec) return;
    SpeexCallback cb = { .func = speex_default_user_handler };
    REPORT(speex_decoder_ctl(SPEEX_SET_USER_HANDLER), int rc = speex_decoder_ctl(dec, SPEEX_SET_USER_HANDLER, &cb), rc == 0);
}
/* ltl: decoder_lifecycle, bits_lifecycle */
static void call_speex_decode(payload in) {
    if (!dec || !bits_valid) return;
    REPORT(speex_decode, int rc = speex_decode(dec, byte(in, 0) & 1 ? NULL : &bits, pcm_float), rc >= 0);
}
/* ltl: decoder_lifecycle, bits_lifecycle */
static void call_speex_decode_int(payload in) {
    if (!dec || !bits_valid) return;
    REPORT(speex_decode_int, int rc = speex_decode_int(dec, byte(in, 0) & 1 ? NULL : &bits, pcm), rc >= 0);
}
/* ltl: decoder_lifecycle, stereo_state_outlives_decoder_handler */
static void call_speex_decoder_destroy(payload in) {
    (void)in;
    if (!dec) return;
    REPORT_VOID(speex_decoder_destroy, speex_decoder_destroy(dec));
    dec = NULL;
    dec_uses_stereo = 0;
}

/* bit-stream */
/* ltl: bits_lifecycle */
static void call_speex_bits_init(payload in) {
    (void)in;
    if (bits_valid) return;
    REPORT(speex_bits_init, speex_bits_init(&bits), bits.chars != NULL);
    bits_valid = bits.chars != NULL;
}
/* ltl: bits_lifecycle */
static void call_speex_bits_init_buffer(payload in) {
    (void)in;
    if (bits_valid) return;
    REPORT_VOID(speex_bits_init_buffer, speex_bits_init_buffer(&bits, bit_buffer, sizeof bit_buffer));
    bits_valid = 1;
}
/* ltl: bits_lifecycle */
static void call_speex_bits_set_bit_buffer(payload in) {
    (void)in;
    if (bits_valid) return;
    memset(bit_buffer, 0, sizeof bit_buffer);
    REPORT_VOID(speex_bits_set_bit_buffer, speex_bits_set_bit_buffer(&bits, bit_buffer, sizeof bit_buffer));
    bits_valid = 1;
}
/* ltl: bits_lifecycle */
static void call_speex_bits_destroy(payload in) {
    (void)in;
    if (!bits_valid) return;
    REPORT_VOID(speex_bits_destroy, speex_bits_destroy(&bits));
    bits_valid = 0;
}
/* ltl: bits_lifecycle */
static void call_speex_bits_reset(payload in) {
    (void)in;
    if (!bits_valid) return;
    REPORT_VOID(speex_bits_reset, speex_bits_reset(&bits));
}
/* ltl: bits_lifecycle */
static void call_speex_bits_rewind(payload in) {
    (void)in;
    if (!bits_valid) return;
    REPORT_VOID(speex_bits_rewind, speex_bits_rewind(&bits));
}

/* input: the last written packet, the header packet, or the payload */
/* ltl: bits_lifecycle */
static void call_speex_bits_read_from(payload in) {
    if (!bits_valid) return;
    const char *src = (const char *)in.p + (in.n ? 1 : 0);
    int len = in.n ? (int)in.n - 1 : 0;
    if ((byte(in, 0) & 1) && packet_size) src = packet, len = packet_size;
    else if ((byte(in, 0) & 2) && header_packet) src = header_packet, len = header_packet_size;
    REPORT_VOID(speex_bits_read_from, speex_bits_read_from(&bits, src, len));
}

/* read_whole_bytes grows the buffer, which only a bit-stream that owns its buffer can do */
/* ltl: bits_lifecycle */
static void call_speex_bits_read_whole_bytes(payload in) {
    if (!bits_valid || !bits.owner || !in.n) return;
    REPORT_VOID(speex_bits_read_whole_bytes, speex_bits_read_whole_bytes(&bits, (const char *)in.p, (int)in.n));
}
/* ltl: bits_lifecycle */
static void call_speex_bits_write(payload in) {
    (void)in;
    if (!bits_valid) return;
    if (!preqed_call("speex_bits_write")) return;
    int rc = speex_bits_write(&bits, packet, sizeof packet);
    preqed_result("speex_bits_write", rc >= 0);
    if (rc >= 0) packet_size = rc;
}

/* bits.c:221 reads chars[nbBits / 8] when bitPtr > 0; that is past the buffer once the stream is full */
/* ltl: bits_lifecycle */
static void call_speex_bits_write_whole_bytes(payload in) {
    (void)in;
    if (!bits_valid || (bits.bitPtr > 0 && bits.nbBits >> 3 >= bits.buf_size)) return;
    if (!preqed_call("speex_bits_write_whole_bytes")) return;
    int rc = speex_bits_write_whole_bytes(&bits, packet, sizeof packet);
    preqed_result("speex_bits_write_whole_bytes", rc >= 0);
    if (rc >= 0) packet_size = rc;
}
/* ltl: bits_lifecycle */
static void call_speex_bits_pack(payload in) {
    if (!bits_valid) return;
    REPORT_VOID(speex_bits_pack, speex_bits_pack(&bits, byte(in, 1), 1 + byte(in, 0) % 16));  /* 1..16 bits per call, as the codec uses */
}
/* ltl: bits_lifecycle */
static void call_speex_bits_unpack_signed(payload in) {
    if (!bits_valid) return;
    REPORT(speex_bits_unpack_signed, speex_bits_unpack_signed(&bits, 1 + byte(in, 0) % 16), !bits.overflow);
}
/* ltl: bits_lifecycle */
static void call_speex_bits_unpack_unsigned(payload in) {
    if (!bits_valid) return;
    REPORT(speex_bits_unpack_unsigned, speex_bits_unpack_unsigned(&bits, 1 + byte(in, 0) % 16), !bits.overflow);
}
/* ltl: bits_lifecycle */
static void call_speex_bits_peek_unsigned(payload in) {
    if (!bits_valid) return;
    REPORT(speex_bits_peek_unsigned, speex_bits_peek_unsigned(&bits, 1 + byte(in, 0) % 16), !bits.overflow);
}
/* ltl: bits_lifecycle */
static void call_speex_bits_peek(payload in) {
    (void)in;
    if (!bits_valid) return;
    REPORT(speex_bits_peek, speex_bits_peek(&bits), !bits.overflow);
}
/* ltl: bits_lifecycle */
static void call_speex_bits_advance(payload in) {
    if (!bits_valid) return;
    REPORT_VOID(speex_bits_advance, speex_bits_advance(&bits, byte(in, 0) % 32));  /* skip 0..31 bits */
}
/* ltl: bits_lifecycle */
static void call_speex_bits_remaining(payload in) {
    (void)in;
    if (!bits_valid) return;
    REPORT(speex_bits_remaining, int n = speex_bits_remaining(&bits), n >= 0);
}
/* ltl: bits_lifecycle */
static void call_speex_bits_nbytes(payload in) {
    (void)in;
    if (!bits_valid) return;
    REPORT(speex_bits_nbytes, int n = speex_bits_nbytes(&bits), n >= 0);
}
/* ltl: bits_lifecycle */
static void call_speex_bits_insert_terminator(payload in) {
    (void)in;
    if (!bits_valid) return;
    REPORT_VOID(speex_bits_insert_terminator, speex_bits_insert_terminator(&bits));
}

/* in-band request handlers read their request from the bit-stream */
/* ltl: decoder_lifecycle, bits_lifecycle */
static void call_speex_inband_handler(payload in) {
    (void)in;
    if (!bits_valid || !dec) return;
    SpeexCallback callbacks[SPEEX_MAX_CALLBACKS];
    memset(callbacks, 0, sizeof callbacks);
    if (stereo) callbacks[SPEEX_INBAND_STEREO] = (SpeexCallback){ .callback_id = SPEEX_INBAND_STEREO, .func = speex_std_stereo_request_handler, .data = stereo };
    REPORT(speex_inband_handler, int rc = speex_inband_handler(&bits, callbacks, dec), rc >= 0);
}

#define ENCODER_HANDLER(api) \
    static void call_##api(payload in) { \
        (void)in; \
        if (!bits_valid || bits.overflow || !enc) return; \
        REPORT(api, int rc = api(&bits, dec, enc), rc >= 0); \
    }
/* ltl: encoder_lifecycle, bits_lifecycle */
ENCODER_HANDLER(speex_std_mode_request_handler)
/* ltl: encoder_lifecycle, bits_lifecycle */
ENCODER_HANDLER(speex_std_low_mode_request_handler)
/* ltl: encoder_lifecycle, bits_lifecycle */
ENCODER_HANDLER(speex_std_vbr_request_handler)
/* ltl: encoder_lifecycle, bits_lifecycle */
ENCODER_HANDLER(speex_std_vbr_quality_request_handler)

/* the handler forwards 4 stream bits to SPEEX_SET_HIGH_MODE unchecked; sb_celp.c:744 then indexes
 * submodes[SB_SUBMODES = 8] with them and calls through the out-of-bounds pointer */
/* ltl: encoder_lifecycle, bits_lifecycle */
static void call_speex_std_high_mode_request_handler(payload in) {
    (void)in;
    if (!bits_valid || bits.overflow || !enc) return;
    if (enc_frame != 160 && speex_bits_peek_unsigned(&bits, 4) >= 8) return;
    REPORT(speex_std_high_mode_request_handler, int rc = speex_std_high_mode_request_handler(&bits, dec, enc), rc >= 0);
}
/* ltl: decoder_lifecycle, bits_lifecycle */
static void call_speex_std_enh_request_handler(payload in) {
    (void)in;
    if (!bits_valid || bits.overflow || !dec) return;
    REPORT(speex_std_enh_request_handler, int rc = speex_std_enh_request_handler(&bits, dec, dec), rc >= 0);
}
/* ltl: bits_lifecycle, stereo_state_lifecycle */
static void call_speex_std_stereo_request_handler(payload in) {
    (void)in;
    if (!bits_valid || bits.overflow || !stereo) return;
    REPORT(speex_std_stereo_request_handler, int rc = speex_std_stereo_request_handler(&bits, dec, stereo), rc >= 0);
}
/* ltl: bits_lifecycle */
static void call_speex_default_user_handler(payload in) {
    (void)in;
    if (!bits_valid || bits.overflow) return;
    REPORT(speex_default_user_handler, int rc = speex_default_user_handler(&bits, dec, NULL), rc >= 0);
}
/* ltl: bits_lifecycle */
static void call_speex_std_char_handler(payload in) {
    (void)in;
    if (!bits_valid || bits.overflow) return;
    REPORT(speex_std_char_handler, int rc = speex_std_char_handler(&bits, dec, stderr), rc >= 0);
}

/* stereo */
/* ltl: stereo_state_lifecycle */
static void call_speex_stereo_state_init(payload in) {
    (void)in;
    if (stereo) return;
    REPORT(speex_stereo_state_init, stereo = speex_stereo_state_init(), stereo != NULL);
}
/* ltl: stereo_state_lifecycle */
static void call_speex_stereo_state_reset(payload in) {
    (void)in;
    if (!stereo) return;
    REPORT_VOID(speex_stereo_state_reset, speex_stereo_state_reset(stereo));
}
/* ltl: stereo_state_lifecycle, stereo_state_outlives_decoder_handler */
static void call_speex_stereo_state_destroy(payload in) {
    (void)in;
    if (!stereo || dec_uses_stereo) return;
    REPORT_VOID(speex_stereo_state_destroy, speex_stereo_state_destroy(stereo));
    stereo = NULL;
}
/* ltl: bits_lifecycle */
static void call_speex_encode_stereo(payload in) {
    if (!bits_valid) return;
    int frame = frame_of(byte(in, 0));
    fill_pcm(rest(in, 1), 2 * frame);
    REPORT_VOID(speex_encode_stereo, speex_encode_stereo(pcm_float, frame, &bits));
}
/* ltl: bits_lifecycle */
static void call_speex_encode_stereo_int(payload in) {
    if (!bits_valid) return;
    int frame = frame_of(byte(in, 0));
    fill_pcm(rest(in, 1), 2 * frame);
    REPORT_VOID(speex_encode_stereo_int, speex_encode_stereo_int(pcm, frame, &bits));
}
/* ltl: stereo_state_lifecycle */
static void call_speex_decode_stereo(payload in) {
    if (!stereo) return;
    int frame = frame_of(byte(in, 0));
    fill_pcm(rest(in, 1), frame);
    REPORT_VOID(speex_decode_stereo, speex_decode_stereo(pcm_float, frame, stereo));
}

/* stereo.c:284 casts gain * sample to short without saturation; balance gains reach ~2.0 */
/* ltl: stereo_state_lifecycle */
static void call_speex_decode_stereo_int(payload in) {
    if (!stereo) return;
    int frame = frame_of(byte(in, 0));
    fill_pcm(rest(in, 1), frame);
    for (int i = 0; i < frame; i++) pcm[i] /= 2;
    REPORT_VOID(speex_decode_stereo_int, speex_decode_stereo_int(pcm, frame, stereo));
}

/* Ogg Speex header */

static void call_speex_init_header(payload in) {
    /* rate 8..32 kHz, 1 or 2 channels; then 1..10 frames per packet, VBR flag, 0..3 extra headers */
    REPORT_VOID(speex_init_header, speex_init_header(&header, 8000 * (1 + byte(in, 1) % 4), 1 + byte(in, 2) % 2, mode_of(byte(in, 0))));
    header.frames_per_packet = 1 + byte(in, 3) % 10;
    header.vbr = byte(in, 4) & 1;
    header.extra_headers = byte(in, 5) % 4;
    header_valid = 1;
}
/* ltl: header_buffers_freed_once */
static void call_speex_header_to_packet(payload in) {
    (void)in;
    if (!header_valid || header_packet) return;
    REPORT(speex_header_to_packet, header_packet = speex_header_to_packet(&header, &header_packet_size), header_packet != NULL);
}
/* ltl: header_buffers_freed_once */
static void call_speex_packet_to_header(payload in) {
    if (parsed_header) return;
    char *src = (byte(in, 0) & 1) && header_packet ? header_packet : (char *)in.p + (in.n ? 1 : 0);
    int len = (byte(in, 0) & 1) && header_packet ? header_packet_size : (in.n ? (int)in.n - 1 : 0);
    REPORT(speex_packet_to_header, parsed_header = speex_packet_to_header(src, len), parsed_header != NULL);
}
/* ltl: header_buffers_freed_once */
static void call_speex_header_free_packet(payload in) {
    (void)in;
    if (!header_packet) return;
    REPORT_VOID(speex_header_free, speex_header_free(header_packet));
    header_packet = NULL;
}
/* ltl: header_buffers_freed_once */
static void call_speex_header_free_parsed(payload in) {
    (void)in;
    if (!parsed_header) return;
    REPORT_VOID(speex_header_free, speex_header_free(parsed_header));
    parsed_header = NULL;
}

/* dispatch */

static void (*const api[])(payload) = {
    call_speex_lib_get_mode, call_speex_mode_query, call_speex_lib_ctl,
    call_speex_encoder_init, call_speex_encoder_ctl, call_speex_encode, call_speex_encode_int, call_speex_encoder_destroy,
    call_speex_decoder_init, call_speex_decoder_ctl, call_speex_decoder_ctl_set_handler,
    call_speex_decoder_ctl_set_user_handler, call_speex_decode, call_speex_decode_int, call_speex_decoder_destroy,
    call_speex_bits_init, call_speex_bits_init_buffer, call_speex_bits_set_bit_buffer, call_speex_bits_destroy,
    call_speex_bits_reset, call_speex_bits_rewind, call_speex_bits_read_from, call_speex_bits_read_whole_bytes,
    call_speex_bits_write, call_speex_bits_write_whole_bytes, call_speex_bits_pack, call_speex_bits_unpack_signed,
    call_speex_bits_unpack_unsigned, call_speex_bits_peek_unsigned, call_speex_bits_peek, call_speex_bits_advance,
    call_speex_bits_remaining, call_speex_bits_nbytes, call_speex_bits_insert_terminator,
    call_speex_inband_handler, call_speex_std_mode_request_handler, call_speex_std_low_mode_request_handler,
    call_speex_std_high_mode_request_handler, call_speex_std_vbr_request_handler,
    call_speex_std_vbr_quality_request_handler, call_speex_std_enh_request_handler,
    call_speex_std_stereo_request_handler, call_speex_default_user_handler, call_speex_std_char_handler,
    call_speex_stereo_state_init, call_speex_stereo_state_reset, call_speex_stereo_state_destroy,
    call_speex_encode_stereo, call_speex_encode_stereo_int, call_speex_decode_stereo, call_speex_decode_stereo_int,
    call_speex_init_header, call_speex_header_to_packet, call_speex_packet_to_header,
    call_speex_header_free_packet, call_speex_header_free_parsed,
};

#define API_COUNT (sizeof api / sizeof api[0])

static void cleanup(void) {
    if (parsed_header) speex_header_free(parsed_header);
    if (header_packet) speex_header_free(header_packet);
    if (enc) speex_encoder_destroy(enc);
    if (dec) speex_decoder_destroy(dec);
    if (stereo) speex_stereo_state_destroy(stereo);
    if (bits_valid) speex_bits_destroy(&bits);
    parsed_header = NULL;
    header_packet = NULL;
    enc = dec = NULL;
    stereo = NULL;
    bits_valid = header_valid = dec_uses_stereo = 0;
    packet_size = 0;
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
