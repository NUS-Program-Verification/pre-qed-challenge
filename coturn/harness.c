#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ns_turn_ioaddr.h"
#include "ns_turn_msg.h"
#include "ns_turn_msg_addr.h"
#include "preqed_ltl.h"

typedef struct {
    const uint8_t *p;
    size_t n;
} payload;

static uint8_t msg[MAX_STUN_MESSAGE_SIZE];
static size_t msg_len;
static int msg_framed;      /* header length field agrees with msg_len: the offset stun_attr_add_* needs */
static int integrity_sealed; /* MESSAGE-INTEGRITY added: only FINGERPRINT may follow */
static int fingerprint_sealed;
static stun_tid tid;
static int tid_valid;
static ioa_addr a1, a2;
static int a1_valid, a2_valid;
static ioa_addr_range range;
static int range_valid;
static stun_attr_ref attr;
static int attr_valid;
static hmackey_t hkey;
static int hkey_valid;
static SHATYPE hkey_sha;  /* the SHA type hkey was produced for: its length depends on it (ns_turn_msg.c:339-425) */
static password_t pwd;
static char snonce[TURN_STATELESS_NONCE_SIZE];
static int snonce_valid;
static uint8_t nonce_key[TURN_STATELESS_NONCE_KEY_SIZE];
static int nonce_key_valid;
static char encpwd[257]; /* generate_enc_password writes 3+16+1+128 bytes of $5$<salt>$<sha> */
static int encpwd_valid;
/* OAuth/third-party cfield bytes copied from a parsed attribute */
static uint8_t cfield[64];
static int cfield_len;
static int cfield_valid;
/* OAuth (RFC 7635) key converted by convert_oauth_key_data, and the last token encode_oauth_token produced */
static oauth_key okey;
static int okey_valid;
static encoded_oauth_token etoken;
static int etoken_valid;
static const uint8_t server_name[] = "fuzz.server";

/* long-term credentials shared by the integrity add and check calls: the same user/realm/nonce on both
   sides lets a MESSAGE-INTEGRITY added by one record verify in a later one (the password comes from the payload) */
static const uint8_t user[] = "fuzzuser";
static const uint8_t realm[] = "fuzz.realm";
static const uint8_t nonce[] = "0123456789abcdef";

/* the STUN/TURN methods the client library builds (ns_turn_msg_defs.h) */
static const uint16_t methods[] = {
    STUN_METHOD_BINDING, STUN_METHOD_ALLOCATE, STUN_METHOD_REFRESH, STUN_METHOD_CHANNEL_BIND,
    STUN_METHOD_CONNECT, STUN_METHOD_CREATE_PERMISSION, STUN_METHOD_SEND, STUN_METHOD_DATA,
};

/* attribute types for the generic stun_attr_add/get calls: every type with a fixed or string encoding */
static const uint16_t attrs[] = {
    STUN_ATTRIBUTE_USERNAME,          STUN_ATTRIBUTE_REALM,         STUN_ATTRIBUTE_NONCE,
    STUN_ATTRIBUTE_SOFTWARE,          STUN_ATTRIBUTE_DATA,          STUN_ATTRIBUTE_LIFETIME,
    STUN_ATTRIBUTE_REQUESTED_TRANSPORT, STUN_ATTRIBUTE_CHANNEL_NUMBER, STUN_ATTRIBUTE_CHANGE_REQUEST,
    STUN_ATTRIBUTE_RESPONSE_PORT,     STUN_ATTRIBUTE_PADDING,       STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,
    STUN_ATTRIBUTE_MAPPED_ADDRESS,    STUN_ATTRIBUTE_XOR_PEER_ADDRESS, STUN_ATTRIBUTE_OTHER_ADDRESS,
    STUN_ATTRIBUTE_RESPONSE_ORIGIN,   STUN_ATTRIBUTE_BANDWIDTH,     STUN_ATTRIBUTE_EVEN_PORT,
    STUN_ATTRIBUTE_RESERVATION_TOKEN, STUN_ATTRIBUTE_THIRD_PARTY_AUTHORIZATION,
};

/* the address-carrying attributes (stun_attr_add_addr_str / stun_attr_get_addr_str) */
static const uint16_t addr_attrs[] = {
    STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, STUN_ATTRIBUTE_XOR_PEER_ADDRESS,
    STUN_ATTRIBUTE_MAPPED_ADDRESS,     STUN_ATTRIBUTE_OTHER_ADDRESS,
};

/* every MESSAGE-INTEGRITY hash the library supports */
static const SHATYPE shas[] = {SHATYPE_SHA1, SHATYPE_SHA256, SHATYPE_SHA384, SHATYPE_SHA512};

static uint8_t byte(payload in, size_t i) { return i < in.n ? in.p[i] : 0; }
static uint16_t word(payload in, size_t i) { return (uint16_t)(((uint16_t)byte(in, i) << 8) | byte(in, i + 1)); }
static uint32_t dword(payload in, size_t i) { return ((uint32_t)word(in, i) << 16) | word(in, i + 2); }
static payload rest(payload in, size_t skip) {
    payload r = {in.p + (skip < in.n ? skip : in.n), in.n > skip ? in.n - skip : 0};
    return r;
}
static const char *cstr(char *dst, size_t cap, payload in) {
    size_t n = in.n < cap - 1 ? in.n : cap - 1;
    memcpy(dst, in.p, n);
    dst[n] = 0;
    return dst;
}
static SHATYPE sha(payload in) { return shas[byte(in, 0) % (sizeof shas / sizeof shas[0])]; }
static uint16_t method(payload in) { return methods[byte(in, 0) % (sizeof methods / sizeof methods[0])]; }
static uint16_t attr_type(payload in) { return attrs[byte(in, 0) % (sizeof attrs / sizeof attrs[0])]; }
static uint16_t addr_attr(payload in) {
    return addr_attrs[byte(in, 0) % (sizeof addr_attrs / sizeof addr_attrs[0])];
}

static void mkaddr(ioa_addr *a, payload in, size_t off) {
    memset(a, 0, sizeof *a);
    if (byte(in, off) & 1) {
        a->s6.sin6_family = AF_INET6;
        a->s6.sin6_port = htons(word(in, off + 1));
        for (int i = 0; i < 16; i++)
            a->s6.sin6_addr.s6_addr[i] = byte(in, off + 3 + (size_t)i);
    } else {
        a->s4.sin_family = AF_INET;
        a->s4.sin_port = htons(word(in, off + 1));
        a->s4.sin_addr.s_addr = htonl(dword(in, off + 3));
    }
}

/* a numeric address string built from the payload: "" (= IPv4 any), IPv4 or IPv6, optionally space-padded;
   full adds the "ip:port" / "[ip6]:port" form. Numeric only: make_ioa_addr sends a host name to getaddrinfo() (DNS). */
static char addr_text[MAX_IOA_ADDR_STRING + 16];
static const uint8_t *numeric_addr(payload in, size_t off, int full) {
    ioa_addr t;
    char ip[INET6_ADDRSTRLEN];
    mkaddr(&t, in, off);
    int v6 = t.ss.sa_family == AF_INET6;
    inet_ntop(t.ss.sa_family, v6 ? (const void *)&t.s6.sin6_addr : (const void *)&t.s4.sin_addr, ip, sizeof ip);
    uint8_t mode = byte(in, off);
    if (mode & 2)
        addr_text[0] = 0;
    else if (!full)
        snprintf(addr_text, sizeof addr_text, mode & 4 ? " %s " : "%s", ip);
    else if (mode & 8)
        snprintf(addr_text, sizeof addr_text, v6 ? "[%s]" : "%s", ip);
    else
        snprintf(addr_text, sizeof addr_text, v6 ? "[%s]:%u" : "%s:%u", ip, (unsigned)word(in, off + 1));
    return (const uint8_t *)addr_text;
}

static void mk_tid(stun_tid *t, payload in) {
    memset(t, 0, sizeof *t);
    for (size_t i = 0; i < STUN_TID_SIZE; i++)
        t->tsx_id[i] = byte(in, i);
}

#define REPORT(fn, expr, ok_cond)                                                                                      \
    do {                                                                                                               \
        if (preqed_call(#fn)) {                                                                                       \
            int rc = (int)(expr);                                                                                      \
            (void)rc;                                                                                                  \
            preqed_result(#fn, (ok_cond));                                                                            \
        }                                                                                                              \
    } while (0)
#define CALL(fn, expr)                                                                                                 \
    do {                                                                                                               \
        if (preqed_call(#fn)) {                                                                                       \
            (void)(expr);                                                                                              \
            preqed_result(#fn, 1);                                                                                    \
        }                                                                                                              \
    } while (0)

static int framed(void) {
    return msg_len >= STUN_HEADER_LENGTH &&
           (size_t)(((size_t)msg[2] << 8) | (size_t)msg[3]) == msg_len - STUN_HEADER_LENGTH;
}

static void rewritten_by(int ok) {
    msg_framed = ok && framed(); /* a builder that reported failure leaves no usable header */
    integrity_sealed = fingerprint_sealed = 0;
    attr = NULL;
    attr_valid = 0;
}

static void appended(void) { msg_framed = framed(); }

/* every size-mutating call below rewrites msg and derives its write offset from the header */

static void call_set_msg(payload in) {
    msg_len = in.n < sizeof msg ? in.n : sizeof msg;
    memcpy(msg, in.p, msg_len);
    rewritten_by(1);
}

/* transaction ids */
/* ltl: tid_before_response */
static void call_stun_tid_generate(payload in) {
    (void)in;
    if (!preqed_call("stun_tid_generate")) return;
    stun_tid_generate(&tid);
    tid_valid = 1;
    preqed_result("stun_tid_generate", 1);
}

static void call_stun_tid_cpy(payload in) {
    stun_tid copy;
    (void)in;
    if (!tid_valid) return;
    if (!preqed_call("stun_tid_cpy")) return;
    stun_tid_cpy(&copy, &tid);
    preqed_result("stun_tid_cpy", 1);
}

static void call_stun_tid_equals(payload in) {
    stun_tid other;
    if (!tid_valid) return;
    mk_tid(&other, in);
    REPORT(stun_tid_equals, stun_tid_equals(&tid, &other), 1);
}

/* stun_tid_from_message_str / stun_tid_message_cpy / stun_tid_generate_in_message_str touch buf[8..20] without
 * looking at len (ns_turn_msg.c:1436-1460), so the caller must supply a full header */
/* ltl: tid_before_response */
static void call_stun_tid_from_message_str(payload in) {
    (void)in;
    if (msg_len < STUN_HEADER_LENGTH) return;
    if (!preqed_call("stun_tid_from_message_str")) return;
    stun_tid_from_message_str(msg, msg_len, &tid);
    tid_valid = 1;
    preqed_result("stun_tid_from_message_str", 1);
}
/* ltl: tid_before_response */
static void call_stun_tid_generate_in_message_str(payload in) {
    (void)in;
    if (msg_len < STUN_HEADER_LENGTH) return;
    if (!preqed_call("stun_tid_generate_in_message_str")) return;
    stun_tid_generate_in_message_str(msg, &tid);
    tid_valid = 1;
    preqed_result("stun_tid_generate_in_message_str", 1);
}

static void call_stun_tid_message_cpy(payload in) {
    (void)in;
    if (!tid_valid || msg_len < STUN_HEADER_LENGTH) return;
    if (!preqed_call("stun_tid_message_cpy")) return;
    stun_tid_message_cpy(msg, &tid);
    preqed_result("stun_tid_message_cpy", 1);
}

/* message types and lengths (pure) */

static void call_stun_make_type(payload in) { REPORT(stun_make_type, stun_make_type(word(in, 0)), 1); }
static void call_stun_make_request(payload in) { REPORT(stun_make_request, stun_make_request(word(in, 0)), 1); }
static void call_stun_make_indication(payload in) {
    REPORT(stun_make_indication, stun_make_indication(word(in, 0)), 1);
}
static void call_stun_make_success_response(payload in) {
    REPORT(stun_make_success_response, stun_make_success_response(word(in, 0)), 1);
}
static void call_stun_make_error_response(payload in) {
    REPORT(stun_make_error_response, stun_make_error_response(word(in, 0)), 1);
}

static void call_stun_method_str(payload in) {
    char name[32]; /* ns_turn_msg.c:55 keeps STUN_METHOD_STR_MAX private to the implementation */
    REPORT(stun_method_str, stun_method_str(word(in, 0), name), 1);
}

static void call_stun_adjust_allocate_lifetime(payload in) {
    REPORT(stun_adjust_allocate_lifetime,
           stun_adjust_allocate_lifetime((turn_time_t)dword(in, 0), (turn_time_t)dword(in, 4),
                                         (turn_time_t)dword(in, 8)),
           1);
}

static void call_stun_get_message_len_str(payload in) {
    size_t app_len = 0;
    REPORT(stun_get_message_len_str, stun_get_message_len_str(msg, msg_len, byte(in, 0) & 1, &app_len), rc >= 0);
}

static void call_stun_get_command_message_len_str(payload in) {
    (void)in;
    REPORT(stun_get_command_message_len_str, stun_get_command_message_len_str(msg, msg_len), rc >= 0);
}

/* initialisers */
/* ltl: message_init_before_attr */
static void call_stun_init_buffer_str(payload in) {
    (void)in;
    if (!preqed_call("stun_init_buffer_str")) return;
    stun_init_buffer_str(msg, &msg_len);
    int ok = msg_len == STUN_HEADER_LENGTH;
    rewritten_by(ok);
    preqed_result("stun_init_buffer_str", ok);
}
/* ltl: message_init_before_attr */
static void call_stun_init_command_str(payload in) {
    if (!preqed_call("stun_init_command_str")) return;
    stun_init_command_str(word(in, 0), msg, &msg_len);
    int ok = msg_len == STUN_HEADER_LENGTH;
    rewritten_by(ok);
    preqed_result("stun_init_command_str", ok);
}
/* ltl: message_init_before_attr */
static void call_old_stun_init_command_str(payload in) {
    if (!preqed_call("old_stun_init_command_str")) return;
    old_stun_init_command_str(word(in, 0), msg, &msg_len, dword(in, 2));
    int ok = msg_len == STUN_HEADER_LENGTH;
    rewritten_by(ok);
    preqed_result("old_stun_init_command_str", ok);
}
/* ltl: message_init_before_attr */
static void call_stun_init_request_str(payload in) {
    if (!preqed_call("stun_init_request_str")) return;
    stun_init_request_str(method(in), msg, &msg_len);
    int ok = msg_len == STUN_HEADER_LENGTH;
    rewritten_by(ok);
    preqed_result("stun_init_request_str", ok);
}
/* ltl: message_init_before_attr */
static void call_stun_init_indication_str(payload in) {
    if (!preqed_call("stun_init_indication_str")) return;
    stun_init_indication_str(method(in), msg, &msg_len);
    int ok = msg_len == STUN_HEADER_LENGTH;
    rewritten_by(ok);
    preqed_result("stun_init_indication_str", ok);
}
/* ltl: message_init_before_attr, tid_before_response */
static void call_stun_init_success_response_str(payload in) {
    if (!tid_valid) return;
    if (!preqed_call("stun_init_success_response_str")) return;
    stun_init_success_response_str(method(in), msg, &msg_len, &tid);
    int ok = msg_len == STUN_HEADER_LENGTH;
    rewritten_by(ok);
    preqed_result("stun_init_success_response_str", ok);
}
/* ltl: message_init_before_attr */
static void call_old_stun_init_success_response_str(payload in) {
    if (!tid_valid) return;
    if (!preqed_call("old_stun_init_success_response_str")) return;
    old_stun_init_success_response_str(method(in), msg, &msg_len, &tid, dword(in, 2));
    int ok = msg_len == STUN_HEADER_LENGTH;
    rewritten_by(ok);
    preqed_result("old_stun_init_success_response_str", ok);
}
/* ltl: message_init_before_attr, tid_before_response */
static void call_stun_init_error_response_str(payload in) {
    uint8_t reason[64];
    if (!tid_valid) return;
    if (!preqed_call("stun_init_error_response_str")) return;
    /* error code 300..599, the STUN error-class range (RFC 8489 14.8) */
    stun_init_error_response_str(method(in), msg, &msg_len, (uint16_t)(300 + byte(in, 2) % 300),
                                 (const uint8_t *)cstr((char *)reason, sizeof reason, rest(in, 3)), &tid,
                                 byte(in, 1) & 1);
    int ok = msg_len >= STUN_HEADER_LENGTH && msg_len <= sizeof msg;
    rewritten_by(ok);
    preqed_result("stun_init_error_response_str", ok);
}
/* ltl: message_init_before_attr */
static void call_old_stun_init_error_response_str(payload in) {
    uint8_t reason[64];
    if (!tid_valid) return;
    if (!preqed_call("old_stun_init_error_response_str")) return;
    /* error code 300..599; dword 4 is the old-STUN cookie */
    old_stun_init_error_response_str(method(in), msg, &msg_len, (uint16_t)(300 + byte(in, 2) % 300),
                                     (const uint8_t *)cstr((char *)reason, sizeof reason, rest(in, 3)), &tid,
                                     dword(in, 4), byte(in, 1) & 1);
    int ok = msg_len >= STUN_HEADER_LENGTH && msg_len <= sizeof msg;
    rewritten_by(ok);
    preqed_result("old_stun_init_error_response_str", ok);
}
/* ltl: message_init_before_attr */
static void call_stun_init_channel_message_str(payload in) {
    int length = (int)in.n;
    if (in.n > sizeof msg - 8) return;
    memcpy(msg + 4, in.p, in.n);
    if (!preqed_call("stun_init_channel_message_str")) return;
    int ok = stun_init_channel_message_str((uint16_t)(0x4000 + word(in, 0) % 0x3FFF), msg, &msg_len, length,
                                           byte(in, 2) & 1);
    rewritten_by(0); /* channel data is not a STUN command message */
    preqed_result("stun_init_channel_message_str", ok);
}

/* setters */
/* ltl: message_init_before_attr */
static void call_stun_set_binding_request_str(payload in) {
    (void)in;
    if (!preqed_call("stun_set_binding_request_str")) return;
    stun_set_binding_request_str(msg, &msg_len);
    int ok = msg_len == STUN_HEADER_LENGTH;
    rewritten_by(ok);
    preqed_result("stun_set_binding_request_str", ok);
}
/* ltl: message_init_before_attr, tid_before_response */
static void call_stun_set_binding_response_str(payload in) {
    if (!tid_valid || !a1_valid) return;
    if (!preqed_call("stun_set_binding_response_str")) return;
    int ok = stun_set_binding_response_str(msg, &msg_len, &tid, &a1, (byte(in, 0) & 1) ? 401 : 0 /* 401 Unauthorized or no error */,
                                           (const uint8_t *)"failure", dword(in, 1), byte(in, 0) & 2,
                                           byte(in, 0) & 4, byte(in, 0) & 8);
    rewritten_by(ok);
    preqed_result("stun_set_binding_response_str", ok);
}
/* ltl: message_init_before_attr */
static void call_stun_set_allocate_request_str(payload in) {
    if (!preqed_call("stun_set_allocate_request_str")) return;
    /* lifetime, af4, af6, transport UDP or 6 (TCP), mobile, reservation token (any string; the library only copies it), even-port -1/1 */
    int ok = stun_set_allocate_request_str(msg, &msg_len, dword(in, 0), byte(in, 4) & 1, byte(in, 4) & 2,
                                           (byte(in, 4) & 4) ? STUN_ATTRIBUTE_TRANSPORT_UDP_VALUE : 6,
                                           byte(in, 4) & 8, (byte(in, 4) & 16) ? "token123" : NULL,
                                           (byte(in, 4) & 32) ? 1 : -1);
    rewritten_by(ok);
    preqed_result("stun_set_allocate_request_str", ok);
}
/* ltl: message_init_before_attr, tid_before_response */
static void call_stun_set_allocate_response_str(payload in) {
    if (!tid_valid || !a1_valid) return;
    if (!preqed_call("stun_set_allocate_response_str")) return;
    /* lifetime, max lifetime, optional error 437 (Allocation Mismatch) with reason "failure",
       reservation token, mobile id (any string, only copied) */
    int ok = stun_set_allocate_response_str(msg, &msg_len, &tid, &a1, a2_valid ? &a2 : NULL,
                                            a2_valid ? &a2 : NULL, dword(in, 0), dword(in, 4),
                                            (byte(in, 8) & 1) ? 437 : 0, (const uint8_t *)"failure",
                                            (byte(in, 8) & 2) ? dword(in, 9) : 0,
                                            (byte(in, 8) & 4) ? (char *)"mobile" : NULL, byte(in, 8) & 8);
    rewritten_by(ok);
    preqed_result("stun_set_allocate_response_str", ok);
}
/* ltl: message_init_before_attr */
static void call_stun_set_channel_bind_request_str(payload in) {
    if (!preqed_call("stun_set_channel_bind_request_str")) return;
    uint16_t rc = stun_set_channel_bind_request_str(msg, &msg_len, a1_valid ? &a1 : NULL, word(in, 0));
    rewritten_by(rc != 0);
    preqed_result("stun_set_channel_bind_request_str", rc != 0);
}
/* ltl: message_init_before_attr, tid_before_response */
static void call_stun_set_channel_bind_response_str(payload in) {
    if (!tid_valid) return;
    if (!preqed_call("stun_set_channel_bind_response_str")) return;
    stun_set_channel_bind_response_str(msg, &msg_len, &tid, (byte(in, 0) & 1) ? 401 : 0 /* 401 Unauthorized or no error */, (const uint8_t *)"failure",
                                       byte(in, 0) & 2);
    int ok = msg_len >= STUN_HEADER_LENGTH && msg_len <= sizeof msg;
    rewritten_by(ok);
    preqed_result("stun_set_channel_bind_response_str", ok);
}

/* predicates and framing inspectors: every one is length-checked by the library */

static void call_stun_is_command_message_str(payload in) {
    (void)in;
    if (!preqed_call("stun_is_command_message_str")) return;
    int ok = stun_is_command_message_str(msg, msg_len);
    preqed_result("stun_is_command_message_str", ok);
    if (ok) msg_framed = 1; /* the library's own framing check promotes imported bytes */
}

static void call_old_stun_is_command_message_str(payload in) {
    uint32_t cookie = 0;
    (void)in;
    REPORT(old_stun_is_command_message_str, old_stun_is_command_message_str(msg, msg_len, &cookie), 1);
}

static void call_stun_is_command_message_full_check_str(payload in) {
    bool present = false;
    REPORT(stun_is_command_message_full_check_str,
           stun_is_command_message_full_check_str(msg, msg_len, byte(in, 0) & 1, &present), 1);
}

static void call_stun_is_request_str(payload in) {
    (void)in;
    REPORT(stun_is_request_str, stun_is_request_str(msg, msg_len), 1);
}

static void call_stun_is_indication_str(payload in) {
    (void)in;
    REPORT(stun_is_indication_str, stun_is_indication_str(msg, msg_len), 1);
}

static void call_stun_is_response_str(payload in) {
    (void)in;
    REPORT(stun_is_response_str, stun_is_response_str(msg, msg_len), 1);
}

static void call_stun_is_success_response_str(payload in) {
    (void)in;
    REPORT(stun_is_success_response_str, stun_is_success_response_str(msg, msg_len), 1);
}

static void call_stun_is_error_response_str(payload in) {
    int code = 0;
    uint8_t text[256] = {0};
    (void)in;
    REPORT(stun_is_error_response_str, stun_is_error_response_str(msg, msg_len, &code, text, sizeof text), 1);
}

static void call_stun_is_challenge_response_str(payload in) {
    int code = 0;
    uint8_t text[256] = {0}, rlm[STUN_MAX_REALM_SIZE + 1] = {0}, nce[STUN_MAX_NONCE_SIZE + 1] = {0};
    uint8_t srv[STUN_MAX_SERVER_NAME_SIZE + 1] = {0};
    bool oauth = false; /* *err_code is dereferenced whenever the call returns true: never NULL */
    REPORT(stun_is_challenge_response_str,
           stun_is_challenge_response_str(msg, msg_len, &code, text, sizeof text, rlm, nce, srv,
                                          (byte(in, 0) & 1) ? &oauth : NULL),
           1);
}

static void call_stun_is_binding_request_str(payload in) {
    REPORT(stun_is_binding_request_str, stun_is_binding_request_str(msg, msg_len, word(in, 0)), 1);
}

static void call_stun_is_binding_response_str(payload in) {
    (void)in;
    REPORT(stun_is_binding_response_str, stun_is_binding_response_str(msg, msg_len), 1);
}

static void call_stun_get_method_str(payload in) {
    (void)in;
    REPORT(stun_get_method_str, stun_get_method_str(msg, msg_len), 1);
}

static void call_stun_get_msg_type_str(payload in) {
    (void)in;
    REPORT(stun_get_msg_type_str, stun_get_msg_type_str(msg, msg_len), 1);
}

static void call_stun_is_channel_message_str(payload in) {
    size_t blen = msg_len;
    uint16_t chnumber = 0;
    REPORT(stun_is_channel_message_str, stun_is_channel_message_str(msg, &blen, &chnumber, byte(in, 0) & 1), 1);
}

static void call_is_channel_msg_str(payload in) {
    (void)in;
    REPORT(is_channel_msg_str, is_channel_msg_str(msg, msg_len), 1);
}

static void call_get_default_reason(payload in) {
    REPORT(get_default_reason, get_default_reason((int)word(in, 0)) != NULL, rc != 0);
}

/* attribute writers: the write offset comes from the header, so the buffer must hold a framed message */
/* ltl: message_init_before_attr, attributes_stop_after_integrity, fingerprint_is_last */
static void call_stun_attr_add_str(payload in) {
    if (!msg_framed || integrity_sealed) return;
    if (!preqed_call("stun_attr_add_str")) return;
    int ok = stun_attr_add_str(msg, &msg_len, attr_type(in), in.p, (int)in.n);
    appended();
    preqed_result("stun_attr_add_str", ok);
}
/* ltl: message_init_before_attr */
static void call_stun_attr_add_addr_str(payload in) {
    if (!msg_framed || integrity_sealed || !a1_valid) return;
    if (!preqed_call("stun_attr_add_addr_str")) return;
    int ok = stun_attr_add_addr_str(msg, &msg_len, addr_attr(in), &a1);
    appended();
    preqed_result("stun_attr_add_addr_str", ok);
}
/* ltl: message_init_before_attr */
static void call_stun_attr_add_channel_number_str(payload in) {
    if (!msg_framed || integrity_sealed) return;
    if (!preqed_call("stun_attr_add_channel_number_str")) return;
    int ok = stun_attr_add_channel_number_str(msg, &msg_len, (uint16_t)(0x4000 + word(in, 0) % 0x4000));
    appended();
    preqed_result("stun_attr_add_channel_number_str", ok);
}
/* ltl: message_init_before_attr */
static void call_stun_attr_add_bandwidth_str(payload in) {
    if (!msg_framed || integrity_sealed) return;
    if (!preqed_call("stun_attr_add_bandwidth_str")) return;
    int ok = stun_attr_add_bandwidth_str(msg, &msg_len, (band_limit_t)dword(in, 0));
    appended();
    preqed_result("stun_attr_add_bandwidth_str", ok);
}
/* ltl: message_init_before_attr */
static void call_stun_attr_add_address_error_code(payload in) {
    if (!msg_framed || integrity_sealed) return;
    if (!preqed_call("stun_attr_add_address_error_code")) return;
    int ok = stun_attr_add_address_error_code(msg, &msg_len, (byte(in, 0) & 1) ? 1 : 2, 300 + byte(in, 1) % 300);  /* family 1 = IPv4, 2 = IPv6 */
    appended();
    preqed_result("stun_attr_add_address_error_code", ok);
}
/* ltl: message_init_before_attr */
static void call_stun_attr_add_change_request_str(payload in) {
    if (!msg_framed || integrity_sealed) return;
    if (!preqed_call("stun_attr_add_change_request_str")) return;
    int ok = stun_attr_add_change_request_str(msg, &msg_len, byte(in, 0) & 1, byte(in, 0) & 2);
    appended();
    preqed_result("stun_attr_add_change_request_str", ok);
}
/* ltl: message_init_before_attr */
static void call_stun_attr_add_response_port_str(payload in) {
    if (!msg_framed || integrity_sealed) return;
    if (!preqed_call("stun_attr_add_response_port_str")) return;
    int ok = stun_attr_add_response_port_str(msg, &msg_len, word(in, 0));
    appended();
    preqed_result("stun_attr_add_response_port_str", ok);
}
/* ltl: message_init_before_attr */
static void call_stun_attr_add_padding_str(payload in) {
    if (!msg_framed || integrity_sealed) return;
    if (!preqed_call("stun_attr_add_padding_str")) return;
    int ok = stun_attr_add_padding_str(msg, &msg_len, (uint16_t)in.n);
    appended();
    preqed_result("stun_attr_add_padding_str", ok);
}
/* ltl: message_init_before_attr, attributes_stop_after_integrity */
static void call_stun_attr_add_integrity_str(payload in) {
    turn_credential_type ct = (byte(in, 0) & 1) ? TURN_CREDENTIALS_SHORT_TERM : TURN_CREDENTIALS_LONG_TERM;
    if (!msg_framed || fingerprint_sealed) return;
    if (ct == TURN_CREDENTIALS_LONG_TERM && !hkey_valid) return;
    if (!preqed_call("stun_attr_add_integrity_str")) return;
    int ok = stun_attr_add_integrity_str(ct, msg, &msg_len, hkey, pwd,
                                         ct == TURN_CREDENTIALS_LONG_TERM ? hkey_sha : sha(in));
    appended();
    integrity_sealed = ok;
    preqed_result("stun_attr_add_integrity_str", ok);
}
/* ltl: message_init_before_attr, attributes_stop_after_integrity */
static void call_stun_attr_add_integrity_by_key_str(payload in) {
    if (!msg_framed || !hkey_valid || fingerprint_sealed) return;
    if (!preqed_call("stun_attr_add_integrity_by_key_str")) return;
    int ok = stun_attr_add_integrity_by_key_str(msg, &msg_len, user, realm, hkey, nonce, hkey_sha);
    appended();
    integrity_sealed = ok;
    preqed_result("stun_attr_add_integrity_by_key_str", ok);
}
/* ltl: message_init_before_attr, attributes_stop_after_integrity, fingerprint_is_last */
static void call_stun_attr_add_integrity_by_user_str(payload in) {
    if (!msg_framed || fingerprint_sealed) return;
    if (!preqed_call("stun_attr_add_integrity_by_user_str")) return;
    int ok = stun_attr_add_integrity_by_user_str(msg, &msg_len, user, realm, (const uint8_t *)pwd, nonce, sha(in));
    appended();
    integrity_sealed = ok;
    preqed_result("stun_attr_add_integrity_by_user_str", ok);
}
/* ltl: message_init_before_attr, attributes_stop_after_integrity */
static void call_stun_attr_add_integrity_by_user_short_term_str(payload in) {
    if (!msg_framed || fingerprint_sealed) return;
    if (!preqed_call("stun_attr_add_integrity_by_user_short_term_str")) return;
    int ok = stun_attr_add_integrity_by_user_short_term_str(msg, &msg_len, user, pwd, sha(in));
    appended();
    integrity_sealed = ok;
    preqed_result("stun_attr_add_integrity_by_user_short_term_str", ok);
}
/* ltl: message_init_before_attr, attributes_stop_after_integrity, fingerprint_is_last */
static void call_stun_attr_add_fingerprint_str(payload in) {
    (void)in;
    if (!msg_framed || fingerprint_sealed) return;
    if (!preqed_call("stun_attr_add_fingerprint_str")) return;
    int ok = stun_attr_add_fingerprint_str(msg, &msg_len);
    appended();
    fingerprint_sealed = ok;
    preqed_result("stun_attr_add_fingerprint_str", ok);
}

/* attribute readers: a ref points into msg and dies with the next rewrite */
/* ltl: attr_ref_belongs_to_current_message */
static void call_stun_attr_get_first_str(payload in) {
    (void)in;
    if (!preqed_call("stun_attr_get_first_str")) return;
    attr = stun_attr_get_first_str(msg, msg_len);
    attr_valid = attr != NULL;
    preqed_result("stun_attr_get_first_str", attr_valid);
}
/* ltl: attr_ref_belongs_to_current_message */
static void call_stun_attr_get_first_by_type_str(payload in) {
    if (!preqed_call("stun_attr_get_first_by_type_str")) return;
    attr = stun_attr_get_first_by_type_str(msg, msg_len, attr_type(in));
    attr_valid = attr != NULL;
    preqed_result("stun_attr_get_first_by_type_str", attr_valid);
}
/* ltl: attr_ref_belongs_to_current_message */
static void call_stun_attr_get_next_str(payload in) {
    (void)in;
    if (!attr_valid) return;
    if (!preqed_call("stun_attr_get_next_str")) return;
    attr = stun_attr_get_next_str(msg, msg_len, attr);
    attr_valid = attr != NULL;
    preqed_result("stun_attr_get_next_str", attr_valid);
}
/* ltl: attr_ref_belongs_to_current_message */
static void call_stun_attr_get_next_covered_str(payload in) {
    (void)in;
    if (!attr_valid) return;
    if (!preqed_call("stun_attr_get_next_covered_str")) return;
    attr = stun_attr_get_next_covered_str(msg, msg_len, attr);
    attr_valid = attr != NULL;
    preqed_result("stun_attr_get_next_covered_str", attr_valid);
}
/* ltl: attr_ref_belongs_to_current_message */
static void call_stun_attr_get_type(payload in) {
    (void)in;
    if (!attr_valid) return;
    CALL(stun_attr_get_type, stun_attr_get_type(attr));
}
/* ltl: attr_ref_belongs_to_current_message */
static void call_stun_attr_get_len(payload in) {
    (void)in;
    if (!attr_valid) return;
    CALL(stun_attr_get_len, stun_attr_get_len(attr));
}
/* ltl: attr_ref_belongs_to_current_message */
static void call_stun_attr_get_value(payload in) {
    (void)in;
    if (!attr_valid) return;
    CALL(stun_attr_get_value, stun_attr_get_value(attr));
}

static void call_stun_attr_is_addr(payload in) {
    (void)in;
    if (!attr_valid) return;
    CALL(stun_attr_is_addr, stun_attr_is_addr(attr));
}

static void call_stun_attr_get_channel_number(payload in) {
    (void)in;
    if (!attr_valid) return;
    CALL(stun_attr_get_channel_number, stun_attr_get_channel_number(attr));
}

static void call_stun_attr_get_bandwidth(payload in) {
    (void)in;
    if (!attr_valid) return;
    CALL(stun_attr_get_bandwidth, stun_attr_get_bandwidth(attr));
}

static void call_stun_attr_get_even_port(payload in) {
    (void)in;
    if (!attr_valid) return;
    CALL(stun_attr_get_even_port, stun_attr_get_even_port(attr));
}

static void call_stun_attr_get_reservation_token_value(payload in) {
    (void)in;
    if (!attr_valid) return;
    CALL(stun_attr_get_reservation_token_value, stun_attr_get_reservation_token_value(attr));
}
/* ltl: attr_ref_belongs_to_current_message */
static void call_stun_attr_get_addr_str(payload in) {
    (void)in;
    if (!attr_valid) return;
    if (!preqed_call("stun_attr_get_addr_str")) return;
    int ok = stun_attr_get_addr_str(msg, msg_len, attr, &a2, a1_valid ? &a1 : NULL);
    a2_valid = ok;
    preqed_result("stun_attr_get_addr_str", ok);
}

static void call_stun_attr_get_first_addr_str(payload in) {
    if (!preqed_call("stun_attr_get_first_addr_str")) return;
    int ok = stun_attr_get_first_addr_str(msg, msg_len, addr_attr(in), &a2, a1_valid ? &a1 : NULL);
    a2_valid = ok;
    preqed_result("stun_attr_get_first_addr_str", ok);
}

static void call_stun_attr_get_first_channel_number_str(payload in) {
    (void)in;
    CALL(stun_attr_get_first_channel_number_str, stun_attr_get_first_channel_number_str(msg, msg_len));
}

static void call_stun_get_requested_address_family(payload in) {
    (void)in;
    if (!attr_valid) return;
    CALL(stun_get_requested_address_family, stun_get_requested_address_family(attr));
}

static void call_stun_attr_get_change_request_str(payload in) {
    bool change_ip = false, change_port = false;
    (void)in;
    if (!attr_valid) return;
    if (!preqed_call("stun_attr_get_change_request_str")) return;
    int ok = stun_attr_get_change_request_str(attr, &change_ip, &change_port);
    preqed_result("stun_attr_get_change_request_str", ok);
}

static void call_stun_attr_get_response_port_str(payload in) {
    (void)in;
    if (!attr_valid) return;
    CALL(stun_attr_get_response_port_str, stun_attr_get_response_port_str(attr));
}

static void call_stun_attr_get_padding_len_str(payload in) {
    (void)in;
    if (!attr_valid) return;
    CALL(stun_attr_get_padding_len_str, stun_attr_get_padding_len_str(attr));
}

/* integrity keys, HMAC and checks */

static void call_stun_produce_integrity_key_str(payload in) {
    memset(pwd, 0, sizeof pwd);
    cstr((char *)pwd, sizeof pwd, in);
    if (!preqed_call("stun_produce_integrity_key_str")) return;
    hkey_sha = sha(in);
    hkey_valid = stun_produce_integrity_key_str(user, realm, (const uint8_t *)pwd, hkey, hkey_sha);
    preqed_result("stun_produce_integrity_key_str", hkey_valid);
}

static void call_stun_calculate_hmac(payload in) {
    uint8_t mac[MAXSHASIZE] = {0};
    unsigned int mac_len = sizeof mac;
    if (!preqed_call("stun_calculate_hmac")) return;
    SHATYPE st = hkey_valid ? hkey_sha : sha(in);
    int ok = stun_calculate_hmac(msg, msg_len, hkey_valid ? hkey : nonce_key,
                                 hkey_valid ? get_hmackey_size(st) : sizeof nonce_key, mac, &mac_len, st);
    preqed_result("stun_calculate_hmac", ok);
}

static void call_stun_check_message_integrity_str(payload in) {
    turn_credential_type ct = (byte(in, 0) & 1) ? TURN_CREDENTIALS_SHORT_TERM : TURN_CREDENTIALS_LONG_TERM;
    if (!preqed_call("stun_check_message_integrity_str")) return;
    int rc = stun_check_message_integrity_str(ct, msg, msg_len, user, realm, (const uint8_t *)pwd, sha(in));
    preqed_result("stun_check_message_integrity_str", rc == 1);
}

static void call_stun_check_message_integrity_by_key_str(payload in) {
    turn_credential_type ct = (byte(in, 0) & 1) ? TURN_CREDENTIALS_SHORT_TERM : TURN_CREDENTIALS_LONG_TERM;
    if (!preqed_call("stun_check_message_integrity_by_key_str")) return;
    int rc = stun_check_message_integrity_by_key_str(ct, msg, msg_len, hkey, pwd,
                                                     ct == TURN_CREDENTIALS_LONG_TERM && hkey_valid ? hkey_sha : sha(in));
    preqed_result("stun_check_message_integrity_by_key_str", rc == 1);
}

static void call_get_hmackey_size(payload in) { CALL(get_hmackey_size, get_hmackey_size(sha(in))); }

static void call_turn_random_number(payload in) {
    (void)in;
    CALL(turn_random_number, turn_random_number());
}

/* stateless nonce (RFC-free helper trio declared by ns_turn_msg.h) */

static void call_turn_derive_stateless_nonce_key(payload in) {
    if (!preqed_call("turn_derive_stateless_nonce_key")) return;
    nonce_key_valid = turn_derive_stateless_nonce_key(in.p, in.n, nonce_key, sizeof nonce_key);
    preqed_result("turn_derive_stateless_nonce_key", nonce_key_valid);
}

static void call_turn_generate_stateless_nonce(payload in) {
    if (!a1_valid || !nonce_key_valid) return;
    if (!preqed_call("turn_generate_stateless_nonce")) return;
    snonce_valid = turn_generate_stateless_nonce(nonce_key, sizeof nonce_key, &a1, dword(in, 0), snonce, sizeof snonce);
    preqed_result("turn_generate_stateless_nonce", snonce_valid);
}

static void call_turn_check_stateless_nonce(payload in) {
    char presented[TURN_STATELESS_NONCE_SIZE];
    uint32_t stamp = 0;
    if (!a1_valid || !nonce_key_valid) return;
    if (snonce_valid && (byte(in, 0) & 1)) {
        memcpy(presented, snonce, sizeof presented);
    } else {
        cstr(presented, sizeof presented, rest(in, 1));
    }
    if (!preqed_call("turn_check_stateless_nonce")) return;
    int ok = turn_check_stateless_nonce(nonce_key, sizeof nonce_key, &a1, dword(in, 1), dword(in, 5), presented, &stamp);
    preqed_result("turn_check_stateless_nonce", ok);
}

/* text helpers */

static void call_SASLprep(payload in) {
    uint8_t text[STUN_MAX_USERNAME_SIZE + 1];
    size_t n = in.n < sizeof text - 1 ? in.n : sizeof text - 1;
    memcpy(text, in.p, n);
    text[n] = 0;
    if (!preqed_call("SASLprep")) return;
    int ok = SASLprep(text);
    preqed_result("SASLprep", ok);
}

static void call_is_http(payload in) {
    char text[512];
    size_t n = in.n < sizeof text - 1 ? in.n : sizeof text - 1;
    memcpy(text, in.p, n);
    text[n] = 0;
    CALL(is_http, is_http(text, n));
}

static void call_generate_new_enc_password(payload in) {
    memset(pwd, 0, sizeof pwd);
    cstr((char *)pwd, sizeof pwd, in);
    if (!preqed_call("generate_new_enc_password")) return;
    generate_new_enc_password((const char *)pwd, encpwd);
    encpwd_valid = encpwd[0] == '$';
    preqed_result("generate_new_enc_password", encpwd_valid);
}

static void call_check_password_equal(payload in) {
    char pin[STUN_MAX_PWD_SIZE + 1];
    cstr(pin, sizeof pin, rest(in, 1));
    if (!preqed_call("check_password_equal")) return;
    int ok = check_password_equal(pin, (byte(in, 0) & 1) && encpwd_valid ? encpwd : (const char *)pwd);
    preqed_result("check_password_equal", ok);
}

/* address codec */

static void call_stun_addr_encode(payload in) {
    if (!a1_valid) return;
    cfield_len = 0;
    if (!preqed_call("stun_addr_encode")) return;
    int ok = stun_addr_encode(&a1, cfield, &cfield_len, byte(in, 0) & 1, STUN_MAGIC_COOKIE, tid.tsx_id) == 0;
    cfield_valid = ok && cfield_len > 0 && (size_t)cfield_len <= sizeof cfield;
    preqed_result("stun_addr_encode", cfield_valid);
}

static void call_stun_addr_decode(payload in) {
    if (!preqed_call("stun_addr_decode")) return;
    int ok;
    if ((byte(in, 0) & 2) && cfield_valid) {
        ok = stun_addr_decode(&a2, cfield, cfield_len, byte(in, 0) & 1, STUN_MAGIC_COOKIE, tid.tsx_id) == 0;
    } else if (in.n > 0 && in.n <= (size_t)INT32_MAX) {
        ok = stun_addr_decode(&a2, in.p, (int)in.n, byte(in, 0) & 1, STUN_MAGIC_COOKIE, tid.tsx_id) == 0;
    } else {
        return;
    }
    a2_valid = ok;
    preqed_result("stun_addr_decode", ok);
}

/* OAuth token (RFC 7635): key data -> key, token encode and decode */
/* ltl: oauth_key_before_token */
static void call_convert_oauth_key_data(payload in) {
    /* as_rs_alg: both supported algorithms, spellings the call normalizes (case, spaces), one unsupported, one empty */
    static const char *const algs[] = {"A256GCM", "A128GCM", "a128gcm", " A256GCM", "A192GCM", ""};
    oauth_key_data kd;
    char err[256]; /* error text buffer */
    memset(&kd, 0, sizeof kd);
    strcpy(kd.as_rs_alg, algs[byte(in, 0) % (sizeof algs / sizeof algs[0])]);
    /* kid: 0..32 payload bytes (empty = the "KID is not defined" error); the rest is the input keying material */
    size_t kid_len = byte(in, 1) % 33;
    payload body = rest(in, 2);
    payload kid = {body.p, body.n < kid_len ? body.n : kid_len};
    cstr(kd.kid, sizeof kd.kid, kid);
    payload ikm = rest(body, kid_len);
    kd.ikm_key_size = ikm.n < OAUTH_KEY_SIZE ? ikm.n : OAUTH_KEY_SIZE;
    memcpy(kd.ikm_key, ikm.p, kd.ikm_key_size);
    if (!preqed_call("convert_oauth_key_data")) return;
    okey_valid = convert_oauth_key_data(&kd, &okey, err, sizeof err);
    preqed_result("convert_oauth_key_data", okey_valid);
}
/* ltl: oauth_key_before_token */
static void call_encode_oauth_token(payload in) {
    if (!okey_valid) return;
    oauth_token tok;
    uint8_t gcm_nonce[OAUTH_GCM_NONCE_SIZE];
    memset(&tok, 0, sizeof tok);
    /* mac key of 0..MAXSHASIZE bytes (the largest encode accepts), then timestamp and lifetime */
    tok.enc_block.key_length = (uint16_t)(byte(in, 0) % (MAXSHASIZE + 1));
    tok.enc_block.timestamp = ((uint64_t)dword(in, 1) << 32) | dword(in, 5);
    tok.enc_block.lifetime = dword(in, 9);
    for (size_t i = 0; i < sizeof gcm_nonce; i++)
        gcm_nonce[i] = byte(in, 14 + i);
    for (size_t i = 0; i < tok.enc_block.key_length; i++)
        tok.enc_block.mac_key[i] = byte(in, 14 + sizeof gcm_nonce + i);
    if (!preqed_call("encode_oauth_token")) return;
    /* byte 13 bit 0: the caller's 12-byte GCM nonce instead of a random one */
    etoken_valid = encode_oauth_token(server_name, &etoken, &okey, &tok, (byte(in, 13) & 1) ? gcm_nonce : NULL);
    preqed_result("encode_oauth_token", etoken_valid);
}
/* ltl: oauth_key_before_token */
static void call_decode_oauth_token(payload in) {
    if (!okey_valid) return;
    encoded_oauth_token et;
    oauth_token tok;
    memset(&tok, 0, sizeof tok);
    if ((byte(in, 0) & 1) && etoken_valid) {
        et = etoken; /* the token encode_oauth_token produced: decodes when the key is unchanged */
    } else {
        /* a token from the wire: payload bytes, at most the MAX_ENCODED_OAUTH_TOKEN_SIZE the struct holds */
        payload body = rest(in, 1);
        memset(&et, 0, sizeof et);
        et.size = body.n < sizeof et.token ? body.n : sizeof et.token;
        memcpy(et.token, body.p, et.size);
    }
    REPORT(decode_oauth_token, decode_oauth_token(server_name, &et, &okey, &tok), rc);
}

/* ns_turn_defs.h: big-endian field write, errno classification, hex dump */

static void call_turn_write_u64(payload in) {
    uint8_t field[8];
    uint64_t v = ((uint64_t)dword(in, 0) << 32) | dword(in, 4);
    if (!preqed_call("turn_write_u64")) return;
    turn_write_u64(field, v);
    preqed_result("turn_write_u64", turn_read_u64(field) == v);
}

/* every errno value the socket_e*() predicates test, and 0 */
static const int errnos[] = {0,           EPERM,       ENOMEM,     EINTR,        EBADF,     EACCES,   ENOBUFS,
                             EAGAIN,      EWOULDBLOCK, EINPROGRESS, ECONNRESET,  ECONNREFUSED, EHOSTDOWN, EMSGSIZE};
static int pick_errno(payload in) { return errnos[byte(in, 0) % (sizeof errnos / sizeof errnos[0])]; }

static void call_socket_errno(payload in) {
    int e = pick_errno(in);
    REPORT(socket_errno, (errno = e, socket_errno()), rc == e);
}

#define SOCKET_E(fn, code)                                                                                             \
    static void call_##fn(payload in) {                                                                                \
        int e = pick_errno(in);                                                                                        \
        REPORT(fn, (errno = e, fn()), rc == (e == (code)));                                                            \
    }
SOCKET_E(socket_eperm, EPERM)
SOCKET_E(socket_enomem, ENOMEM)
SOCKET_E(socket_eintr, EINTR)
SOCKET_E(socket_ebadf, EBADF)
SOCKET_E(socket_eacces, EACCES)
SOCKET_E(socket_enobufs, ENOBUFS)
SOCKET_E(socket_eagain, EAGAIN)
SOCKET_E(socket_ewouldblock, EWOULDBLOCK)
SOCKET_E(socket_einprogress, EINPROGRESS)
SOCKET_E(socket_econnreset, ECONNRESET)
SOCKET_E(socket_econnrefused, ECONNREFUSED)
SOCKET_E(socket_ehostdown, EHOSTDOWN)
SOCKET_E(socket_emsgsize, EMSGSIZE)

static void call_print_bin_func(payload in) {
    /* prints "<func>:<name>:len=N:[hex]" to stdout: at most 16 payload bytes per line */
    CALL(print_bin_func, (print_bin_func("payload", in.n < 16 ? in.n : 16, in.p, __func__), 0));
}

/* ioa_addr helpers */

static void call_make_ioa_addr(payload in) {
    const uint8_t *text = numeric_addr(in, 2, 0);
    if (!preqed_call("make_ioa_addr")) return;
    int rc = make_ioa_addr(text, word(in, 0), &a1);
    preqed_result("make_ioa_addr", rc == 0);
    a1_valid = rc == 0;
}

static void call_make_ioa_addr_from_full_string(payload in) {
    const uint8_t *text = numeric_addr(in, 2, 1);
    if (!preqed_call("make_ioa_addr_from_full_string")) return;
    int rc = make_ioa_addr_from_full_string(text, word(in, 0), &a1);
    preqed_result("make_ioa_addr_from_full_string", rc == 0);
    a1_valid = rc == 0;
}

static void call_ioa_addr_add_mapping(payload in) {
    /* the public->private table is process-global and only grows (there is no remove call), so the harness adds
       4 fixed mappings at most per process: 192.0.2.1..4 (TEST-NET-1) -> 10.0.0.1..4 */
    static uint32_t added;
    (void)in;
    if (added >= 4) return;
    ioa_addr pub, priv;
    memset(&pub, 0, sizeof pub);
    memset(&priv, 0, sizeof priv);
    pub.s4.sin_family = priv.s4.sin_family = AF_INET;
    pub.s4.sin_addr.s_addr = htonl(0xC0000201u + added);
    priv.s4.sin_addr.s_addr = htonl(0x0A000001u + added);
    CALL(ioa_addr_add_mapping, (ioa_addr_add_mapping(&pub, &priv), 0));
    added++;
}

static void call_get_ioa_addr_len(payload in) {
    mkaddr(&a1, in, 0);
    a1_valid = 1;
    CALL(get_ioa_addr_len, get_ioa_addr_len(&a1));
}

static void call_addr_set_any(payload in) {
    (void)in;
    CALL(addr_set_any, addr_set_any(&a1));
    a1_valid = 1;
}

static void call_addr_any(payload in) {
    (void)in;
    if (!a1_valid) return;
    CALL(addr_any, addr_any(&a1));
}

static void call_addr_any_no_port(payload in) {
    (void)in;
    if (!a1_valid) return;
    CALL(addr_any_no_port, addr_any_no_port(&a1));
}

static void call_addr_hash(payload in) {
    (void)in;
    if (!a1_valid) return;
    CALL(addr_hash, addr_hash(&a1));
}

static void call_addr_hash_no_port(payload in) {
    (void)in;
    if (!a1_valid) return;
    CALL(addr_hash_no_port, addr_hash_no_port(&a1));
}

static void call_addr_cpy(payload in) {
    (void)in;
    if (!a1_valid) return;
    CALL(addr_cpy, addr_cpy(&a2, &a1));
    a2_valid = 1;
}

static void call_addr_cpy4(payload in) {
    struct sockaddr_in s4;
    memset(&s4, 0, sizeof s4);
    s4.sin_family = AF_INET;
    s4.sin_port = htons(word(in, 0));
    s4.sin_addr.s_addr = htonl(dword(in, 2));
    CALL(addr_cpy4, addr_cpy4(&a2, &s4));
    a2_valid = 1;
}

static void call_addr_cpy6(payload in) {
    struct sockaddr_in6 s6;
    memset(&s6, 0, sizeof s6);
    s6.sin6_family = AF_INET6;
    s6.sin6_port = htons(word(in, 0));
    for (int i = 0; i < 16; i++)
        s6.sin6_addr.s6_addr[i] = byte(in, 2 + (size_t)i);
    CALL(addr_cpy6, addr_cpy6(&a2, &s6));
    a2_valid = 1;
}

static void call_addr_eq(payload in) {
    (void)in;
    if (!a1_valid || !a2_valid) return;
    CALL(addr_eq, addr_eq(&a1, &a2));
}

static void call_addr_eq_no_port(payload in) {
    (void)in;
    if (!a1_valid || !a2_valid) return;
    CALL(addr_eq_no_port, addr_eq_no_port(&a1, &a2));
}

static void call_addr_set_port(payload in) {
    if (!a1_valid) return;
    CALL(addr_set_port, addr_set_port(&a1, word(in, 0)));
}

static void call_addr_get_port(payload in) {
    (void)in;
    if (!a1_valid) return;
    CALL(addr_get_port, addr_get_port(&a1));
}

static void call_addr_to_string(payload in) {
    char text[MAX_IOA_ADDR_STRING];
    (void)in;
    if (!a1_valid) return;
    if (!preqed_call("addr_to_string")) return;
    int ok = addr_to_string(&a1, text) == 0;
    preqed_result("addr_to_string", ok);
}

static void call_addr_to_string_no_port(payload in) {
    char text[MAX_IOA_ADDR_STRING];
    (void)in;
    if (!a1_valid) return;
    if (!preqed_call("addr_to_string_no_port")) return;
    int ok = addr_to_string_no_port(&a1, text) == 0;
    preqed_result("addr_to_string_no_port", ok);
}

static void call_hash_int32(payload in) { CALL(hash_int32, hash_int32(dword(in, 0))); }
static void call_hash_int64(payload in) {
    CALL(hash_int64, hash_int64(((uint64_t)dword(in, 0) << 32) | dword(in, 4)));
}

static void call_ioa_addr_range_set(payload in) {
    (void)in;
    if (!a1_valid || !a2_valid) return;
    CALL(ioa_addr_range_set, ioa_addr_range_set(&range, &a1, &a2));
    range_valid = 1;
}

static void call_addr_less_eq(payload in) {
    (void)in;
    if (!a1_valid || !a2_valid) return;
    CALL(addr_less_eq, addr_less_eq(&a1, &a2));
}

static void call_ioa_addr_in_range(payload in) {
    (void)in;
    if (!a1_valid || !range_valid) return;
    CALL(ioa_addr_in_range, ioa_addr_in_range(&range, &a1));
}

static void call_ioa_addr_range_cpy(payload in) {
    ioa_addr_range copy;
    (void)in;
    if (!range_valid) return;
    CALL(ioa_addr_range_cpy, ioa_addr_range_cpy(&copy, &range));
}

static void call_ioa_addr_get_embedded_ipv4(payload in) {
    (void)in;
    if (!a1_valid) return;
    if (!preqed_call("ioa_addr_get_embedded_ipv4")) return;
    int ok = ioa_addr_get_embedded_ipv4(&a1, &a2);
    a2_valid = ok;
    preqed_result("ioa_addr_get_embedded_ipv4", ok);
}

static void call_ioa_addr_is_multicast(payload in) {
    (void)in;
    if (!a1_valid) return;
    CALL(ioa_addr_is_multicast, ioa_addr_is_multicast(&a1));
}

static void call_ioa_addr_is_loopback(payload in) {
    (void)in;
    if (!a1_valid) return;
    CALL(ioa_addr_is_loopback, ioa_addr_is_loopback(&a1));
}

static void call_ioa_addr_is_internal_deny_default(payload in) {
    (void)in;
    if (!a1_valid) return;
    CALL(ioa_addr_is_internal_deny_default, ioa_addr_is_internal_deny_default(&a1));
}

static void call_ioa_addr_is_zero(payload in) {
    (void)in;
    if (!a1_valid) return;
    CALL(ioa_addr_is_zero, ioa_addr_is_zero(&a1));
}

static void call_map_addr_from_public_to_private(payload in) {
    (void)in;
    if (!a1_valid) return;
    CALL(map_addr_from_public_to_private, map_addr_from_public_to_private(&a1, &a2));
    a2_valid = 1;
}

static void call_map_addr_from_private_to_public(payload in) {
    (void)in;
    if (!a1_valid) return;
    CALL(map_addr_from_private_to_public, map_addr_from_private_to_public(&a1, &a2));
    a2_valid = 1;
}

static void (*const api[])(payload) = {
    call_set_msg,
    /* ns_turn_msg.h: ids, types, lengths */
    call_stun_tid_generate, call_stun_tid_cpy, call_stun_tid_equals, call_stun_tid_from_message_str,
    call_stun_tid_generate_in_message_str, call_stun_tid_message_cpy, call_stun_make_type, call_stun_make_request,
    call_stun_make_indication, call_stun_make_success_response, call_stun_make_error_response, call_stun_method_str,
    call_stun_adjust_allocate_lifetime, call_stun_get_message_len_str, call_stun_get_command_message_len_str,
    /* initialisers and setters */
    call_stun_init_buffer_str, call_stun_init_command_str, call_old_stun_init_command_str, call_stun_init_request_str,
    call_stun_init_indication_str, call_stun_init_success_response_str, call_old_stun_init_success_response_str,
    call_stun_init_error_response_str, call_old_stun_init_error_response_str, call_stun_init_channel_message_str,
    call_stun_set_binding_request_str, call_stun_set_binding_response_str, call_stun_set_allocate_request_str,
    call_stun_set_allocate_response_str, call_stun_set_channel_bind_request_str,
    call_stun_set_channel_bind_response_str,
    /* predicates and inspectors */
    call_stun_is_command_message_str, call_old_stun_is_command_message_str, call_stun_is_command_message_full_check_str,
    call_stun_is_request_str, call_stun_is_indication_str, call_stun_is_response_str, call_stun_is_success_response_str,
    call_stun_is_error_response_str, call_stun_is_challenge_response_str, call_stun_is_binding_request_str,
    call_stun_is_binding_response_str, call_stun_get_method_str, call_stun_get_msg_type_str,
    call_stun_is_channel_message_str, call_is_channel_msg_str, call_get_default_reason,
    /* attribute writers */
    call_stun_attr_add_str, call_stun_attr_add_addr_str, call_stun_attr_add_channel_number_str,
    call_stun_attr_add_bandwidth_str, call_stun_attr_add_address_error_code, call_stun_attr_add_change_request_str,
    call_stun_attr_add_response_port_str, call_stun_attr_add_padding_str, call_stun_attr_add_integrity_str,
    call_stun_attr_add_integrity_by_key_str, call_stun_attr_add_integrity_by_user_str,
    call_stun_attr_add_integrity_by_user_short_term_str, call_stun_attr_add_fingerprint_str,
    /* attribute readers */
    call_stun_attr_get_first_str, call_stun_attr_get_first_by_type_str, call_stun_attr_get_next_str,
    call_stun_attr_get_next_covered_str, call_stun_attr_get_type, call_stun_attr_get_len, call_stun_attr_get_value,
    call_stun_attr_is_addr, call_stun_attr_get_channel_number, call_stun_attr_get_bandwidth,
    call_stun_attr_get_even_port, call_stun_attr_get_reservation_token_value, call_stun_attr_get_addr_str,
    call_stun_attr_get_first_addr_str, call_stun_attr_get_first_channel_number_str,
    call_stun_get_requested_address_family, call_stun_attr_get_change_request_str,
    call_stun_attr_get_response_port_str, call_stun_attr_get_padding_len_str,
    /* integrity, HMAC and nonce */
    call_stun_produce_integrity_key_str, call_stun_calculate_hmac, call_stun_check_message_integrity_str,
    call_stun_check_message_integrity_by_key_str, call_get_hmackey_size, call_turn_random_number,
    call_turn_derive_stateless_nonce_key, call_turn_generate_stateless_nonce, call_turn_check_stateless_nonce,
    /* text helpers */
    call_SASLprep, call_is_http, call_generate_new_enc_password, call_check_password_equal,
    /* address codec */
    call_stun_addr_encode, call_stun_addr_decode,
    /* ioa_addr helpers */
    call_get_ioa_addr_len, call_addr_set_any, call_addr_any, call_addr_any_no_port, call_addr_hash,
    call_addr_hash_no_port, call_addr_cpy, call_addr_cpy4, call_addr_cpy6, call_addr_eq, call_addr_eq_no_port,
    call_addr_set_port, call_addr_get_port, call_addr_to_string, call_addr_to_string_no_port, call_hash_int32,
    call_hash_int64, call_ioa_addr_range_set, call_addr_less_eq, call_ioa_addr_in_range, call_ioa_addr_range_cpy,
    call_ioa_addr_get_embedded_ipv4, call_ioa_addr_is_multicast, call_ioa_addr_is_loopback,
    call_ioa_addr_is_internal_deny_default, call_ioa_addr_is_zero, call_map_addr_from_public_to_private,
    call_map_addr_from_private_to_public,
    call_make_ioa_addr, call_make_ioa_addr_from_full_string, call_ioa_addr_add_mapping,
    /* OAuth token */
    call_convert_oauth_key_data, call_encode_oauth_token, call_decode_oauth_token,
    /* ns_turn_defs.h helpers */
    call_turn_write_u64, call_socket_errno, call_socket_eperm, call_socket_enomem, call_socket_eintr,
    call_socket_ebadf, call_socket_eacces, call_socket_enobufs, call_socket_eagain, call_socket_ewouldblock,
    call_socket_einprogress, call_socket_econnreset, call_socket_econnrefused, call_socket_ehostdown,
    call_socket_emsgsize, call_print_bin_func,
};

#define API_COUNT (sizeof api / sizeof api[0])

static void cleanup(void) {
    msg_len = 0;
    msg_framed = integrity_sealed = fingerprint_sealed = 0;
    tid_valid = a1_valid = a2_valid = range_valid = attr_valid = 0;
    hkey_valid = snonce_valid = nonce_key_valid = encpwd_valid = cfield_valid = 0;
    okey_valid = etoken_valid = 0;
    memset(&okey, 0, sizeof okey);
    memset(&etoken, 0, sizeof etoken);
    attr = NULL;
    /* the small buffers outlive one record and are read as credentials, so start each input blank */
    memset(pwd, 0, sizeof pwd);
    memset(hkey, 0, sizeof hkey);
    memset(encpwd, 0, sizeof encpwd);
    memset(snonce, 0, sizeof snonce);
    memset(nonce_key, 0, sizeof nonce_key);
    memset(cfield, 0, sizeof cfield);
    memset(&tid, 0, sizeof tid);
    cfield_len = 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    preqed_reset();
    size_t off = 0;
    while (size - off >= 3) {
        uint8_t op = data[off];
        size_t len = (size_t)data[off + 1] | (size_t)data[off + 2] << 8;
        off += 3;
        if (len > size - off) break;
        payload in = {data + off, len};
        api[op % API_COUNT](in);
        off += len;
    }
    cleanup();
    return 0;
}
