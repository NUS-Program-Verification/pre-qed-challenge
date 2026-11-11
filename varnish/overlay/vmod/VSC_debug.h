/*
 * NB:  This file is machine generated, DO NOT EDIT!
 *
 * Edit debug.vsc and run lib/libvsc/vsctool.py instead.
 */

struct VSC_debug {
	uint64_t	count;
};

#define VSC_debug_size PRNDUP(sizeof(struct VSC_debug))

struct vsmw_cluster;
struct vsc_seg;

struct VSC_debug *VSC_debug_New(struct vsmw_cluster *,
    struct vsc_seg **, const char *fmt, ...);
void VSC_debug_Destroy(struct vsc_seg **);
