#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <pcap/namedb.h>
#include <pcap/pcap-inttypes.h>
#include "preqed_ltl.h"

#define DUMP_PATH "libpcap-harness.pcap"
/* filter expressions, names and messages from the payload */
#define TEXT_CAP 2048

typedef struct {
    const uint8_t *p;
    size_t n;
} payload;

static pcap_t *pc;
static int pc_offline;                 /* reads packets from a savefile */
static int pc_activated;               /* dead, offline, or successfully activated */
static pcap_dumper_t *dumper;
static int dump_file_exists;
static struct bpf_program prog;
static int prog_valid;
static int *dlts;
static int *tstamp_types;
static pcap_if_t *devices;
static char errbuf[PCAP_ERRBUF_SIZE];
static char text[TEXT_CAP + 1];
static unsigned packets_seen;

/* pcap_next/pcap_next_ex data is only valid until the next read; keep a copy */
static struct pcap_pkthdr last_hdr;
/* copy of the last packet read: 64 KiB = the largest pcap snaplen the harness configures */
static u_char last_pkt[65536];
static int last_valid;

static uint8_t byte(payload in, size_t i) { return i < in.n ? in.p[i] : 0; }
static payload rest(payload in, size_t skip) {
    payload r = { in.p + (skip < in.n ? skip : in.n), in.n > skip ? in.n - skip : 0 };
    return r;
}
static const char *as_text(payload in) {
    size_t n = in.n < TEXT_CAP ? in.n : TEXT_CAP;
    memcpy(text, in.p, n);
    text[n] = 0;
    return text;
}
static int dlt_from(uint8_t b) {
    /* link types with distinct BPF code generation in gencode.c */
    static const int dlt[] = { DLT_EN10MB, DLT_RAW, DLT_NULL, DLT_LINUX_SLL, DLT_IEEE802_11, DLT_PPP, DLT_IPV4,
                               DLT_IPV6, DLT_NFLOG, DLT_IEEE802_11_RADIO, DLT_LINUX_SLL2 };
    return dlt[b % (sizeof dlt / sizeof dlt[0])];
}
/* live handles are limited to loopback so a privileged run never touches real interfaces */
static const char *loopback(uint8_t b) { return b & 1 ? "any" : "lo"; }

static void keep_packet(const struct pcap_pkthdr *h, const u_char *pkt) {
    if (!h || !pkt || h->caplen > sizeof last_pkt) return;
    memcpy(last_pkt, pkt, h->caplen);
    last_hdr = *h;
    last_valid = 1;
}
/* a packet header + bytes: the last packet read, or one built from the payload */
static void packet_from(payload in, struct pcap_pkthdr *h, const u_char **bytes) {
    if ((byte(in, 0) & 1) && last_valid) {
        *h = last_hdr;
        *bytes = last_pkt;
        return;
    }
    payload body = rest(in, 1);
    memset(h, 0, sizeof *h);
    h->caplen = (bpf_u_int32)body.n;
    h->len = h->caplen + byte(in, 0) % 4;  /* original length may exceed the captured length (truncated packet) */
    h->ts.tv_usec = byte(in, 0) * 1000;
    *bytes = body.p;
}

static void packet_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    keep_packet(h, bytes);
    packets_seen++;
}

#define REPORT(api, stmt, ok_cond) \
    do { if (preqed_call(#api)) { stmt; preqed_result(#api, (ok_cond)); } } while (0)
#define REPORT_VOID(api, stmt) REPORT(api, stmt, 1)

/* opening a pcap_t */

static void opened(int offline, int activated) {
    pc_offline = offline;
    pc_activated = activated;
}
/* ltl: pcap_handle_lifecycle */
static void call_pcap_open_dead(payload in) {
    if (pc) return;
    REPORT(pcap_open_dead, pc = pcap_open_dead(dlt_from(byte(in, 0)), (byte(in, 1) << 8 | byte(in, 2)) + 1), pc != NULL);
    opened(0, 1);
}
/* ltl: pcap_handle_lifecycle */
static void call_pcap_open_dead_with_tstamp_precision(payload in) {
    if (pc) return;
    REPORT(pcap_open_dead_with_tstamp_precision,
           pc = pcap_open_dead_with_tstamp_precision(dlt_from(byte(in, 0)), (byte(in, 1) << 8 | byte(in, 2)) + 1, byte(in, 3) & 1),
           pc != NULL);
    opened(0, 1);
}

static FILE *file_from(payload in) {
    FILE *f = tmpfile();
    if (!f) return NULL;
    if (in.n && fwrite(in.p, 1, in.n, f) != in.n) {
        fclose(f);
        return NULL;
    }
    rewind(f);
    return f;
}
/* ltl: pcap_handle_lifecycle */
static void call_pcap_fopen_offline(payload in) {
    if (pc) return;
    FILE *f = file_from(in);
    if (!f) return;
    REPORT(pcap_fopen_offline, pc = pcap_fopen_offline(f, errbuf), pc != NULL);
    if (pc) opened(1, 1);
    else fclose(f);
}
/* ltl: pcap_handle_lifecycle */
static void call_pcap_fopen_offline_with_tstamp_precision(payload in) {
    if (pc) return;
    FILE *f = file_from(rest(in, 1));
    if (!f) return;
    u_int precision = byte(in, 0) & 1 ? PCAP_TSTAMP_PRECISION_NANO : PCAP_TSTAMP_PRECISION_MICRO;
    REPORT(pcap_fopen_offline_with_tstamp_precision, pc = pcap_fopen_offline_with_tstamp_precision(f, precision, errbuf), pc != NULL);
    if (pc) opened(1, 1);
    else fclose(f);
}
/* ltl: pcap_handle_lifecycle */
static void call_pcap_open_offline(payload in) {
    (void)in;
    if (pc || !dump_file_exists) return;
    REPORT(pcap_open_offline, pc = pcap_open_offline(DUMP_PATH, errbuf), pc != NULL);
    opened(1, 1);
}
/* ltl: pcap_handle_lifecycle */
static void call_pcap_open_offline_with_tstamp_precision(payload in) {
    if (pc || !dump_file_exists) return;
    u_int precision = byte(in, 0) & 1 ? PCAP_TSTAMP_PRECISION_NANO : PCAP_TSTAMP_PRECISION_MICRO;
    REPORT(pcap_open_offline_with_tstamp_precision, pc = pcap_open_offline_with_tstamp_precision(DUMP_PATH, precision, errbuf),
           pc != NULL);
    opened(1, 1);
}
/* ltl: pcap_handle_lifecycle */
static void call_pcap_create(payload in) {
    if (pc) return;
    REPORT(pcap_create, pc = pcap_create(loopback(byte(in, 0)), errbuf), pc != NULL);
    opened(0, 0);
}
/* ltl: pcap_handle_lifecycle */
static void call_pcap_open_live(payload in) {
    if (pc) return;
    /* snaplen 64..16384, not promiscuous, 1 ms timeout */
    REPORT(pcap_open_live, pc = pcap_open_live(loopback(byte(in, 0)), (byte(in, 1) + 1) * 64, 0, 1, errbuf), pc != NULL);
    opened(0, 1);
}
/* ltl: pcap_handle_lifecycle */
static void call_pcap_activate(payload in) {
    (void)in;
    if (!pc || pc_activated) return;
    REPORT(pcap_activate, int rc = pcap_activate(pc), rc >= 0);
    pc_activated = 1;
}
/* ltl: pcap_handle_lifecycle */
static void call_pcap_close(payload in) {
    (void)in;
    if (!pc) return;
    REPORT_VOID(pcap_close, pcap_close(pc));
    pc = NULL;
}
/* pcap_init is process-wide: afterwards pcap_lookupdev is not supported (pcap.c:1491-1495) */
static int pcap_init_called;
static void call_pcap_init(payload in) {
    pcap_init_called = 1;
    REPORT(pcap_init, int rc = pcap_init(byte(in, 0) & 1, errbuf), rc == 0);
}

/* configuration before activation (errors after activation are PCAP_ERROR_ACTIVATED returns) */

#define SET(api, arg) \
    static void call_##api(payload in) { \
        if (!pc) return; \
        REPORT(api, int rc = api(pc, arg), rc == 0); \
    }
/* ltl: pcap_handle_lifecycle */
SET(pcap_set_snaplen, (byte(in, 0) + 1) * 256)  /* 256..65536 */
/* ltl: pcap_handle_lifecycle */
SET(pcap_set_promisc, byte(in, 0) & 1)
/* ltl: pcap_handle_lifecycle */
SET(pcap_set_timeout, byte(in, 0) + 1)
/* ltl: pcap_handle_lifecycle */
SET(pcap_set_buffer_size, (byte(in, 0) + 1) * 4096)  /* 4 KiB..1 MiB */
/* ltl: pcap_handle_lifecycle */
SET(pcap_set_immediate_mode, byte(in, 0) & 1)
/* ltl: pcap_handle_lifecycle */
SET(pcap_set_tstamp_precision, byte(in, 0) & 1)
/* ltl: pcap_handle_lifecycle */
SET(pcap_set_tstamp_type, byte(in, 0) % 7)  /* PCAP_TSTAMP_HOST..PCAP_TSTAMP_ADAPTER_UNSYNCED (0..5) and one invalid */
/* ltl: pcap_handle_lifecycle */
SET(pcap_set_rfmon, byte(in, 0) & 1)
/* ltl: pcap_handle_lifecycle */
SET(pcap_set_protocol_linux, byte(in, 0))
/* ltl: pcap_handle_lifecycle */
SET(pcap_setdirection, (pcap_direction_t)(byte(in, 0) % 3))  /* INOUT, IN, OUT */
/* ltl: pcap_handle_lifecycle */
static void call_pcap_can_set_rfmon(payload in) {
    (void)in;
    if (!pc) return;
    REPORT(pcap_can_set_rfmon, int rc = pcap_can_set_rfmon(pc), rc >= 0);
}
/* ltl: pcap_handle_lifecycle */
static void call_pcap_setnonblock(payload in) {
    if (!pc) return;
    REPORT(pcap_setnonblock, int rc = pcap_setnonblock(pc, byte(in, 0) & 1, errbuf), rc == 0);
}
/* ltl: pcap_handle_lifecycle */
static void call_pcap_set_datalink(payload in) {
    if (!pc) return;
    REPORT(pcap_set_datalink, int rc = pcap_set_datalink(pc, dlt_from(byte(in, 0))), rc == 0);
}

/* introspection */

#define QUERY(api) \
    static void call_##api(payload in) { \
        (void)in; \
        if (!pc) return; \
        REPORT(api, int rc = api(pc), rc >= 0); \
    }
/* ltl: pcap_handle_lifecycle */
QUERY(pcap_datalink)
/* ltl: pcap_handle_lifecycle */
QUERY(pcap_datalink_ext)
/* ltl: pcap_handle_lifecycle */
QUERY(pcap_snapshot)
/* ltl: pcap_handle_lifecycle */
QUERY(pcap_get_tstamp_precision)
/* ltl: pcap_handle_lifecycle */
QUERY(pcap_is_swapped)
/* ltl: pcap_handle_lifecycle */
QUERY(pcap_major_version)
/* ltl: pcap_handle_lifecycle */
QUERY(pcap_minor_version)
/* ltl: pcap_handle_lifecycle */
QUERY(pcap_bufsize)
/* ltl: pcap_handle_lifecycle */
QUERY(pcap_fileno)
/* ltl: pcap_handle_lifecycle */
QUERY(pcap_get_selectable_fd)
/* ltl: pcap_handle_lifecycle */
static void call_pcap_getnonblock(payload in) {
    (void)in;
    if (!pc) return;
    REPORT(pcap_getnonblock, int rc = pcap_getnonblock(pc, errbuf), rc >= 0);
}
/* ltl: pcap_handle_lifecycle */
static void call_pcap_stats(payload in) {
    (void)in;
    if (!pc) return;
    struct pcap_stat st;
    REPORT(pcap_stats, int rc = pcap_stats(pc, &st), rc == 0);
}
/* ltl: pcap_handle_lifecycle */
static void call_pcap_file(payload in) {
    (void)in;
    if (!pc) return;
    REPORT(pcap_file, FILE *f = pcap_file(pc), f != NULL);
}
/* ltl: pcap_handle_lifecycle */
static void call_pcap_geterr(payload in) {
    (void)in;
    if (!pc) return;
    REPORT(pcap_geterr, char *s = pcap_geterr(pc), s != NULL);
}
/* ltl: pcap_handle_lifecycle */
static void call_pcap_perror(payload in) {
    if (!pc) return;
    REPORT_VOID(pcap_perror, pcap_perror(pc, as_text(in)));
}
/* ltl: pcap_handle_lifecycle */
static void call_pcap_get_required_select_timeout(payload in) {
    (void)in;
    if (!pc) return;
    /* NULL is the normal result when no timeout is required (pcap_get_required_select_timeout.3pcap) */
    REPORT_VOID(pcap_get_required_select_timeout, (void)pcap_get_required_select_timeout(pc));
}

/* datalink and timestamp-type lists: owned until freed */
/* ltl: pcap_handle_lifecycle, owned_lists_freed_once */
static void call_pcap_list_datalinks(payload in) {
    (void)in;
    if (!pc || dlts) return;
    if (!preqed_call("pcap_list_datalinks")) return;
    int rc = pcap_list_datalinks(pc, &dlts);
    preqed_result("pcap_list_datalinks", rc > 0);
    if (rc <= 0) dlts = NULL;
}
/* ltl: owned_lists_freed_once */
static void call_pcap_free_datalinks(payload in) {
    (void)in;
    if (!dlts) return;
    REPORT_VOID(pcap_free_datalinks, pcap_free_datalinks(dlts));
    dlts = NULL;
}
/* ltl: pcap_handle_lifecycle, owned_lists_freed_once */
static void call_pcap_list_tstamp_types(payload in) {
    (void)in;
    if (!pc || tstamp_types) return;
    if (!preqed_call("pcap_list_tstamp_types")) return;
    int rc = pcap_list_tstamp_types(pc, &tstamp_types);
    preqed_result("pcap_list_tstamp_types", rc >= 0);
    if (rc < 0) tstamp_types = NULL;
}
/* ltl: owned_lists_freed_once */
static void call_pcap_free_tstamp_types(payload in) {
    (void)in;
    if (!tstamp_types) return;
    REPORT_VOID(pcap_free_tstamp_types, pcap_free_tstamp_types(tstamp_types));
    tstamp_types = NULL;
}

/* reading packets */
/* ltl: pcap_handle_lifecycle */
static void call_pcap_next_ex(payload in) {
    (void)in;
    if (!pc || !pc_offline) return;
    struct pcap_pkthdr *h;
    const u_char *pkt;
    if (!preqed_call("pcap_next_ex")) return;
    int rc = pcap_next_ex(pc, &h, &pkt);
    preqed_result("pcap_next_ex", rc >= 0);
    if (rc == 1) keep_packet(h, pkt);
}
/* ltl: pcap_handle_lifecycle */
static void call_pcap_next(payload in) {
    (void)in;
    if (!pc || !pc_offline) return;
    struct pcap_pkthdr h;
    if (!preqed_call("pcap_next")) return;
    const u_char *pkt = pcap_next(pc, &h);
    preqed_result("pcap_next", pkt != NULL);
    if (pkt) keep_packet(&h, pkt);
}
/* ltl: pcap_handle_lifecycle */
static void call_pcap_dispatch(payload in) {
    if (!pc || !pc_offline) return;
    REPORT(pcap_dispatch, int rc = pcap_dispatch(pc, byte(in, 0) % 8 + 1, packet_callback, NULL), rc >= 0);  /* 1..8 packets */
}
/* ltl: pcap_handle_lifecycle */
static void call_pcap_loop(payload in) {
    if (!pc || !pc_offline) return;
    REPORT(pcap_loop, int rc = pcap_loop(pc, byte(in, 0) % 8 + 1, packet_callback, NULL), rc >= 0);  /* 1..8 packets */
}
/* ltl: pcap_handle_lifecycle */
static void call_pcap_breakloop(payload in) {
    (void)in;
    if (!pc) return;
    REPORT_VOID(pcap_breakloop, pcap_breakloop(pc));
}

/* sending (fails without privileges; live handles are loopback only) */
/* ltl: pcap_handle_lifecycle */
static void call_pcap_inject(payload in) {
    if (!pc) return;
    REPORT(pcap_inject, int rc = pcap_inject(pc, in.p, in.n), rc >= 0);
}
/* ltl: pcap_handle_lifecycle */
static void call_pcap_sendpacket(payload in) {
    if (!pc) return;
    REPORT(pcap_sendpacket, int rc = pcap_sendpacket(pc, in.p, (int)in.n), rc == 0);
}

/* BPF programs: owned until pcap_freecode */
/* ltl: pcap_handle_lifecycle, bpf_program_lifecycle */
static void call_pcap_compile(payload in) {
    if (!pc || prog_valid) return;
    if (!preqed_call("pcap_compile")) return;
    int rc = pcap_compile(pc, &prog, as_text(rest(in, 1)), byte(in, 0) & 1, PCAP_NETMASK_UNKNOWN);
    preqed_result("pcap_compile", rc == 0);
    prog_valid = rc == 0;
}
/* ltl: bpf_program_lifecycle */
static void call_pcap_compile_nopcap(payload in) {
    if (prog_valid) return;
    int snaplen = (byte(in, 0) << 8 | byte(in, 1)) + 1;
    if (!preqed_call("pcap_compile_nopcap")) return;
    int rc = pcap_compile_nopcap(snaplen, dlt_from(byte(in, 2)), &prog, as_text(rest(in, 4)), byte(in, 3) & 1, PCAP_NETMASK_UNKNOWN);
    preqed_result("pcap_compile_nopcap", rc == 0);
    prog_valid = rc == 0;
}
/* ltl: pcap_handle_lifecycle, bpf_program_lifecycle */
static void call_pcap_setfilter(payload in) {
    (void)in;
    if (!pc || !prog_valid) return;
    REPORT(pcap_setfilter, int rc = pcap_setfilter(pc, &prog), rc == 0);
}
/* ltl: bpf_program_lifecycle */
static void call_pcap_offline_filter(payload in) {
    if (!prog_valid) return;
    struct pcap_pkthdr h;
    const u_char *bytes;
    packet_from(in, &h, &bytes);
    REPORT(pcap_offline_filter, int rc = pcap_offline_filter(&prog, &h, bytes), rc >= 0);
}
/* ltl: bpf_program_lifecycle */
static void call_bpf_validate(payload in) {
    (void)in;
    if (!prog_valid) return;
    REPORT(bpf_validate, int rc = bpf_validate(prog.bf_insns, (int)prog.bf_len), rc != 0);
}
/* ltl: bpf_program_lifecycle */
static void call_bpf_filter(payload in) {
    if (!prog_valid) return;
    REPORT_VOID(bpf_filter, (void)bpf_filter(prog.bf_insns, in.p, (u_int)in.n, (u_int)in.n));
}
/* ltl: bpf_program_lifecycle */
static void call_bpf_image(payload in) {
    if (!prog_valid || !prog.bf_len) return;
    int index = byte(in, 0) % prog.bf_len;
    REPORT(bpf_image, char *s = bpf_image(&prog.bf_insns[index], index), s != NULL);
}
/* ltl: bpf_program_lifecycle */
static void call_bpf_dump(payload in) {
    if (!prog_valid || prog.bf_len > 32) return;  /* bpf_dump prints every instruction to stdout; keep it short */
    REPORT_VOID(bpf_dump, bpf_dump(&prog, byte(in, 0) % 3));  /* option 0 text, 1 C fragment, 2 decimal */
}
/* ltl: bpf_program_lifecycle */
static void call_pcap_freecode(payload in) {
    (void)in;
    if (!prog_valid) return;
    REPORT_VOID(pcap_freecode, pcap_freecode(&prog));
    prog_valid = 0;
}

/* savefile writing: owned until pcap_dump_close */
/* ltl: pcap_handle_lifecycle, dumper_lifecycle */
static void call_pcap_dump_open(payload in) {
    (void)in;
    if (!pc || !pc_activated || dumper) return;
    REPORT(pcap_dump_open, dumper = pcap_dump_open(pc, DUMP_PATH), dumper != NULL);
    dump_file_exists |= dumper != NULL;
}
/* ltl: pcap_handle_lifecycle, dumper_lifecycle */
static void call_pcap_dump_open_append(payload in) {
    (void)in;
    if (!pc || !pc_activated || dumper || !dump_file_exists) return;
    REPORT(pcap_dump_open_append, dumper = pcap_dump_open_append(pc, DUMP_PATH), dumper != NULL);
}
/* ltl: pcap_handle_lifecycle, dumper_lifecycle */
static void call_pcap_dump_fopen(payload in) {
    (void)in;
    if (!pc || !pc_activated || dumper) return;
    FILE *f = tmpfile();
    if (!f) return;
    REPORT(pcap_dump_fopen, dumper = pcap_dump_fopen(pc, f), dumper != NULL);
    if (!dumper) fclose(f);
}
/* ltl: dumper_lifecycle */
static void call_pcap_dump(payload in) {
    if (!dumper) return;
    struct pcap_pkthdr h;
    const u_char *bytes;
    packet_from(in, &h, &bytes);
    REPORT_VOID(pcap_dump, pcap_dump((u_char *)dumper, &h, bytes));
}
/* ltl: dumper_lifecycle */
static void call_pcap_dump_flush(payload in) {
    (void)in;
    if (!dumper) return;
    REPORT(pcap_dump_flush, int rc = pcap_dump_flush(dumper), rc == 0);
}
/* ltl: dumper_lifecycle */
static void call_pcap_dump_ftell(payload in) {
    (void)in;
    if (!dumper) return;
    REPORT(pcap_dump_ftell, long pos = pcap_dump_ftell(dumper), pos >= 0);
}
/* ltl: dumper_lifecycle */
static void call_pcap_dump_ftell64(payload in) {
    (void)in;
    if (!dumper) return;
    REPORT(pcap_dump_ftell64, int64_t pos = pcap_dump_ftell64(dumper), pos >= 0);
}
/* ltl: dumper_lifecycle */
static void call_pcap_dump_file(payload in) {
    (void)in;
    if (!dumper) return;
    REPORT(pcap_dump_file, FILE *f = pcap_dump_file(dumper), f != NULL);
}
/* ltl: dumper_lifecycle */
static void call_pcap_dump_close(payload in) {
    (void)in;
    if (!dumper) return;
    REPORT_VOID(pcap_dump_close, pcap_dump_close(dumper));
    dumper = NULL;
}

/* devices */
/* ltl: owned_lists_freed_once */
static void call_pcap_findalldevs(payload in) {
    (void)in;
    if (devices) return;
    if (!preqed_call("pcap_findalldevs")) return;
    int rc = pcap_findalldevs(&devices, errbuf);
    preqed_result("pcap_findalldevs", rc == 0);
    if (rc != 0) devices = NULL;
}
/* ltl: owned_lists_freed_once */
static void call_pcap_freealldevs(payload in) {
    (void)in;
    if (!devices) return;
    REPORT_VOID(pcap_freealldevs, pcap_freealldevs(devices));
    devices = NULL;
}

static void call_pcap_lookupnet(payload in) {
    bpf_u_int32 net, mask;
    REPORT(pcap_lookupnet, int rc = pcap_lookupnet(loopback(byte(in, 0)), &net, &mask, errbuf), rc == 0);
}

static void call_pcap_lookupdev(payload in) {
    (void)in;
    if (pcap_init_called) return;
    REPORT(pcap_lookupdev, char *s = pcap_lookupdev(errbuf), s != NULL);
}

/* name/value tables */

static void call_pcap_datalink_name_to_val(payload in) {
    REPORT(pcap_datalink_name_to_val, int v = pcap_datalink_name_to_val(as_text(in)), v >= 0);
}

static void call_pcap_datalink_val_to_name(payload in) {
    REPORT(pcap_datalink_val_to_name, const char *s = pcap_datalink_val_to_name(dlt_from(byte(in, 0))), s != NULL);
}

static void call_pcap_datalink_val_to_description(payload in) {
    REPORT(pcap_datalink_val_to_description, const char *s = pcap_datalink_val_to_description(dlt_from(byte(in, 0))), s != NULL);
}

static void call_pcap_datalink_val_to_description_or_dlt(payload in) {
    REPORT(pcap_datalink_val_to_description_or_dlt,
           const char *s = pcap_datalink_val_to_description_or_dlt(byte(in, 0) | byte(in, 1) << 8), s != NULL);
}

static void call_pcap_tstamp_type_name_to_val(payload in) {
    REPORT(pcap_tstamp_type_name_to_val, int v = pcap_tstamp_type_name_to_val(as_text(in)), v >= 0);
}

static void call_pcap_tstamp_type_val_to_name(payload in) {
    REPORT(pcap_tstamp_type_val_to_name, const char *s = pcap_tstamp_type_val_to_name(byte(in, 0)), s != NULL);
}

static void call_pcap_tstamp_type_val_to_description(payload in) {
    REPORT(pcap_tstamp_type_val_to_description, const char *s = pcap_tstamp_type_val_to_description(byte(in, 0)), s != NULL);
}

static void call_pcap_statustostr(payload in) {
    REPORT(pcap_statustostr, const char *s = pcap_statustostr(-(int)byte(in, 0)), s != NULL);
}

static void call_pcap_strerror(payload in) {
    REPORT(pcap_strerror, const char *s = pcap_strerror(byte(in, 0)), s != NULL);
}

static void call_pcap_lib_version(payload in) {
    (void)in;
    REPORT(pcap_lib_version, const char *s = pcap_lib_version(), s != NULL);
}

/* name to address (pcap/namedb.h) */

static void call_pcap_ether_aton(payload in) {
    /* a MAC-48 string from the payload; the result is an allocated 6-byte buffer, NULL on any error */
    if (!preqed_call("pcap_ether_aton")) return;
    u_char *mac = pcap_ether_aton(as_text(in));
    preqed_result("pcap_ether_aton", mac != NULL);
    free(mac);
}

static void call_pcap_nametoaddr(payload in) {
    /* names that resolve without a DNS query, so a run never depends on the network */
    static const char *const names[] = { "localhost", "127.0.0.1", "0.0.0.0" };
    REPORT(pcap_nametoaddr, bpf_u_int32 **addrs = pcap_nametoaddr(names[byte(in, 0) % 3]), addrs != NULL);
}

static void call_pcap_nametoportrange(payload in) {
    int port1, port2, proto;
    /* "PPP-PPP" from the payload; returns 0 on failure */
    REPORT(pcap_nametoportrange, int rc = pcap_nametoportrange(as_text(in), &port1, &port2, &proto), rc != 0);
}

static void call_pcap_next_etherent(payload in) {
    /* an /etc/ethers-format file from the payload; NULL at end of file */
    FILE *f = file_from(in);
    if (!f) return;
    REPORT(pcap_next_etherent, struct pcap_etherent *ep = pcap_next_etherent(f), ep != NULL);
    fclose(f);
}

/* 64-bit values on a 4-byte boundary (pcap/pcap-inttypes.h) */

static void call_pcap_4_byte_aligned_uint64_val(payload in) {
    pcap_4_byte_aligned_uint64 v = { { 0, 0 } };
    uint64_t want = 0;
    memcpy(&v, in.p, in.n < sizeof v ? in.n : sizeof v);
    memcpy(&want, &v, sizeof want);
    REPORT(pcap_4_byte_aligned_uint64_val, uint64_t got = pcap_4_byte_aligned_uint64_val(v), got == want);
}

static void call_pcap_4_byte_aligned_int64_val(payload in) {
    pcap_4_byte_aligned_int64 v = { { 0, 0 } };
    int64_t want = 0;
    memcpy(&v, in.p, in.n < sizeof v ? in.n : sizeof v);
    memcpy(&want, &v, sizeof want);
    REPORT(pcap_4_byte_aligned_int64_val, int64_t got = pcap_4_byte_aligned_int64_val(v), got == want);
}

/* dispatch */

static void (*const api[])(payload) = {
    call_pcap_open_dead, call_pcap_open_dead_with_tstamp_precision, call_pcap_fopen_offline,
    call_pcap_fopen_offline_with_tstamp_precision, call_pcap_open_offline, call_pcap_open_offline_with_tstamp_precision,
    call_pcap_create, call_pcap_open_live, call_pcap_activate, call_pcap_close, call_pcap_init,
    call_pcap_set_snaplen, call_pcap_set_promisc, call_pcap_set_timeout, call_pcap_set_buffer_size,
    call_pcap_set_immediate_mode, call_pcap_set_tstamp_precision, call_pcap_set_tstamp_type, call_pcap_set_rfmon,
    call_pcap_set_protocol_linux, call_pcap_setdirection, call_pcap_can_set_rfmon, call_pcap_setnonblock,
    call_pcap_set_datalink,
    call_pcap_datalink, call_pcap_datalink_ext, call_pcap_snapshot, call_pcap_get_tstamp_precision,
    call_pcap_is_swapped, call_pcap_major_version, call_pcap_minor_version, call_pcap_bufsize, call_pcap_fileno,
    call_pcap_get_selectable_fd, call_pcap_getnonblock, call_pcap_stats, call_pcap_file, call_pcap_geterr,
    call_pcap_perror, call_pcap_get_required_select_timeout,
    call_pcap_list_datalinks, call_pcap_free_datalinks, call_pcap_list_tstamp_types, call_pcap_free_tstamp_types,
    call_pcap_next_ex, call_pcap_next, call_pcap_dispatch, call_pcap_loop, call_pcap_breakloop,
    call_pcap_inject, call_pcap_sendpacket,
    call_pcap_compile, call_pcap_compile_nopcap, call_pcap_setfilter, call_pcap_offline_filter,
    call_bpf_validate, call_bpf_filter, call_bpf_image, call_bpf_dump, call_pcap_freecode,
    call_pcap_dump_open, call_pcap_dump_open_append, call_pcap_dump_fopen, call_pcap_dump, call_pcap_dump_flush,
    call_pcap_dump_ftell, call_pcap_dump_ftell64, call_pcap_dump_file, call_pcap_dump_close,
    call_pcap_findalldevs, call_pcap_freealldevs, call_pcap_lookupnet, call_pcap_lookupdev,
    call_pcap_datalink_name_to_val, call_pcap_datalink_val_to_name, call_pcap_datalink_val_to_description,
    call_pcap_datalink_val_to_description_or_dlt, call_pcap_tstamp_type_name_to_val,
    call_pcap_tstamp_type_val_to_name, call_pcap_tstamp_type_val_to_description,
    call_pcap_statustostr, call_pcap_strerror, call_pcap_lib_version,
    call_pcap_ether_aton, call_pcap_nametoaddr, call_pcap_nametoportrange, call_pcap_next_etherent,
    call_pcap_4_byte_aligned_uint64_val, call_pcap_4_byte_aligned_int64_val,
};

#define API_COUNT (sizeof api / sizeof api[0])

static void cleanup(void) {
    if (dumper) pcap_dump_close(dumper);
    if (prog_valid) pcap_freecode(&prog);
    if (dlts) pcap_free_datalinks(dlts);
    if (tstamp_types) pcap_free_tstamp_types(tstamp_types);
    if (devices) pcap_freealldevs(devices);
    if (pc) pcap_close(pc);
    dumper = NULL;
    prog_valid = 0;
    dlts = tstamp_types = NULL;
    devices = NULL;
    pc = NULL;
    last_valid = 0;
    if (dump_file_exists) unlink(DUMP_PATH);
    dump_file_exists = 0;
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
