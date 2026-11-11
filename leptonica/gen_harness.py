#!/usr/bin/env python3
"""Generate harness.c: one libFuzzer driver over leptonica's whole public API.

Reads src/allheaders.h (the 2747 `LEPT_DLL extern` prototypes) plus the doc
comments and bodies in src/*.c, and emits

    leptonica/harness.c

with one `static void call_<exact_name>(payload in)` per wrapped function, a
`static void (*const api[])(payload)` dispatch table, and typed ownership pools.

Everything the generator decides comes from the library itself: prototypes from
allheaders.h, parameter direction / optionality / ownership from the `\param` and
`\return` doc blocks, borrowed returns from the function bodies (`return x->field`,
the doc's "the returned X is owned by ..." notes).  The OVERRIDES tables in this
file are the complete list of hand decisions, each with its reason.

    python3 gen_harness.py --src /src --out harness.c
    python3 gen_harness.py --src /src --report            # statistics only
    python3 gen_harness.py --src /src --seeds DIR         # seed corpus
"""
import argparse
import json
import os
import re
import sys

# --------------------------------------------------------------------------- #
# type model
# --------------------------------------------------------------------------- #


CAP_FPIX = (
    "        l_int32 w = 0, h = 0;\n"
    "        fpixGetDimensions(o, &w, &h);\n"
    "        if ((l_int64)w * h > 2000000) fpixDestroy(&s_fpix[k]);")
CAP_DPIX = (
    "        l_int32 w = 0, h = 0;\n"
    "        dpixGetDimensions(o, &w, &h);\n"
    "        if ((l_int64)w * h > 2000000) dpixDestroy(&s_dpix[k]);")
CAP_KEL = (
    "        l_int32 sx = 0, sy = 0;\n"
    "        kernelGetParameters(o, &sy, &sx, NULL, NULL);\n"
    "        if ((l_int64)sx * sy > 10000) kernelDestroy(&s_kel[k]);")
class Obj:
    """An owned object type: K slots, one destructor, one cheap size cap."""

    def __init__(self, ctype, pref, dtor, make=None, cap=None, n=3, capcode=None):
        self.ctype = ctype
        self.pref = pref
        self.dtor = dtor        # printf template; %s is a pointer-to-pointer
        self.make = make        # C expression producing a fresh object, or None
        self.cap = cap          # C bool expression over `o`
        self.capcode = capcode  # C statements for caps that need locals
        self.n = n

    def destroy(self, expr):
        return self.dtor % expr


OBJECTS = {}


def obj(ctype, pref, dtor, make=None, cap=None, n=3, capcode=None):
    OBJECTS[ctype] = Obj(ctype, pref, dtor, make, cap, n, capcode)


obj('PIX', 'pix', 'pixDestroy(&%s)', make='pixCreate(4, 4, 1)',
    cap='(l_int64)pixGetWidth(o) * pixGetHeight(o) > 2000000 || pixGetDepth(o) > 32', n=4)
obj('PIXA', 'pixa', 'pixaDestroy(&%s)', make='pixaCreate(0)', cap='pixaGetCount(o) > 128', n=4)
obj('PIXAA', 'pixaa', 'pixaaDestroy(&%s)', make='pixaaCreate(0)', cap='pixaaGetCount(o, NULL) > 32')
obj('PIXAC', 'pixac', 'pixacompDestroy(&%s)', make='pixacompCreate(0)', cap='pixacompGetCount(o) > 128')
obj('PIXC', 'pixc', 'pixcompDestroy(&%s)', make=None)
obj('PIXCMAP', 'cmap', 'pixcmapDestroy(&%s)', make='pixcmapCreate(2)', cap='pixcmapGetCount(o) > 256')
obj('PIXACC', 'pixacc', 'pixaccDestroy(&%s)', make='pixaccCreate(4, 4, 0)',
    cap='pixGetWidth(pixaccGetPix(o)) * pixGetHeight(pixaccGetPix(o)) > 2000000')
obj('PIXTILING', 'tiling', 'pixTilingDestroy(&%s)', make=None)
obj('BOX', 'box', 'boxDestroy(&%s)', make='boxCreate(0, 0, 3, 3)')
obj('BOXA', 'boxa', 'boxaDestroy(&%s)', make='boxaCreate(0)', cap='boxaGetCount(o) > 4096', n=4)
obj('BOXAA', 'boxaa', 'boxaaDestroy(&%s)', make='boxaaCreate(0)', cap='boxaaGetCount(o) > 64')
obj('NUMA', 'numa', 'numaDestroy(&%s)', make=None, cap='numaGetCount(o) > 100000', n=4)
obj('NUMAA', 'numaa', 'numaaDestroy(&%s)', make='numaaCreate(0)', cap='numaaGetCount(o) > 64')
obj('L_DNA', 'dna', 'l_dnaDestroy(&%s)', make=None, cap='l_dnaGetCount(o) > 100000', n=4)
obj('L_DNAA', 'dnaa', 'l_dnaaDestroy(&%s)', make='l_dnaaCreate(0)', cap='l_dnaaGetCount(o) > 64')
obj('L_DNAHASH', 'dnahash', 'l_dnaHashDestroy(&%s)', make='l_dnaHashCreate(4, 4)')
obj('PTA', 'pta', 'ptaDestroy(&%s)', make='ptaCreate(0)', cap='ptaGetCount(o) > 100000', n=4)
obj('PTAA', 'ptaa', 'ptaaDestroy(&%s)', make='ptaaCreate(0)', cap='ptaaGetCount(o) > 64')
obj('SARRAY', 'sa', 'sarrayDestroy(&%s)', make='sarrayCreate(0)', cap='sarrayGetCount(o) > 4096', n=4)
obj('FPIX', 'fpix', 'fpixDestroy(&%s)', make='fpixCreate(4, 4)', capcode=CAP_FPIX)
obj('FPIXA', 'fpixa', 'fpixaDestroy(&%s)', make='fpixaCreate(0)', cap='fpixaGetCount(o) > 128')
obj('DPIX', 'dpix', 'dpixDestroy(&%s)', make='dpixCreate(4, 4)', capcode=CAP_DPIX)
obj('SEL', 'sel', 'selDestroy(&%s)', make='selCreateBrick(3, 3, 1, 1, SEL_HIT)')
obj('SELA', 'sela', 'selaDestroy(&%s)', make=None, cap='selaGetCount(o) > 256')
# an empty NUMA/L_DNA has array == NULL (LEPT_CALLOC(0, ...)), and several readers
# (numaWindowedMean, numafunc2.c:604) index the array without checking the count
MAKECODE = {'NUMA': '''    NUMA *na = numaCreate(4);
    l_int32 i;
    if (!na) return NULL;
    for (i = 1; i <= 4; i++) numaAddNumber(na, (l_float32)i);
    return na;''',
            'L_DNA': '''    L_DNA *da = l_dnaCreate(4);
    l_int32 i;
    if (!da) return NULL;
    for (i = 1; i <= 4; i++) l_dnaAddNumber(da, (l_float64)i);
    return da;''',
            'SELA': '''    SELA *s = selaCreate(4);
    if (s) selaAddSel(s, selCreateBrick(3, 3, 1, 1, SEL_HIT), "s", L_INSERT);
    return s;'''}
obj('L_KERNEL', 'kel', 'kernelDestroy(&%s)', make='kernelCreate(3, 3)', capcode=CAP_KEL)
obj('L_BYTEA', 'ba', 'l_byteaDestroy(&%s)', make='l_byteaCreate(0)',
    cap='l_byteaGetSize(o) > (size_t)(1 << 20)')
obj('L_RECOG', 'recog', 'recogDestroy(&%s)', make=None)
obj('L_DEWARP', 'dewarpa_', 'dewarpDestroy(&%s)', make=None)
obj('L_DEWARPA', 'dewarpa', 'dewarpaDestroy(&%s)', make=None)
obj('CCBORDA', 'ccba', 'ccbaDestroy(&%s)', make=None)
obj('L_BMF', 'bmf', 'bmfDestroy(&%s)', make=None)
obj('JBCLASSER', 'classer', 'jbClasserDestroy(&%s)', make='jbClasserCreate(JB_CORRELATION, 0)')
obj('JBDATA', 'jbdata', 'jbDataDestroy(&%s)', make=None)
obj('L_PTRA', 'ptra', 'ptraDestroy(&%s, 1, 1)', make='ptraCreate(4)')
obj('L_PTRAA', 'ptraa', 'ptraaDestroy(&%s, 1, 1)', make='ptraaCreate(0)')
obj('L_STACK', 'stack', 'lstackDestroy(&%s, 1)', make='lstackCreate(4)', cap='lstackGetCount(o) > 10000')
obj('L_QUEUE', 'queue', 'lqueueDestroy(&%s, 1)', make='lqueueCreate(4)', cap='lqueueGetCount(o) > 10000')
obj('L_HEAP', 'heap', 'lheapDestroy(&%s, 1)', make='lheapCreate(4, L_SORT_INCREASING)',
    cap='lheapGetCount(o) > 10000')
obj('L_RBTREE', 'rb', 'l_rbtreeDestroy(&%s)', make='l_rbtreeCreate(L_INT_TYPE)',
    cap='l_rbtreeGetCount(o) > 10000')
obj('L_AMAP', 'amap', 'l_amapDestroy(&%s)', make='l_amapCreate(L_INT_TYPE)', cap='l_amapSize(o) > 10000')
obj('L_ASET', 'aset', 'l_asetDestroy(&%s)', make='l_asetCreate(L_INT_TYPE)', cap='l_asetSize(o) > 10000')
obj('L_HASHMAP', 'hmap', 'l_hmapDestroy(&%s)', make='l_hmapCreate(4, 2)')
obj('DLLIST', 'dll', 'listDestroy(&%s)', make=None, cap='listGetCount(o) > 10000')
obj('GPLOT', 'gplot', 'gplotDestroy(&%s)', make='gplotCreate("gplt", GPLOT_PNG, "t", "x", "y")')
obj('L_SUDOKU', 'sudoku', 'sudokuDestroy(&%s)', make=None)
obj('L_WSHED', 'wshed', 'wshedDestroy(&%s)', make=None)
obj('L_RCHA', 'rcha', 'rchaDestroy(&%s)', make=None)
obj('L_COMP_DATA', 'cid', 'l_CIDataDestroy(&%s)', make=None)
obj('L_BBUFFER', 'bb', 'bbufferDestroy(&%s)', make='bbufferCreate(NULL, 16)')
obj('L_COLORFILL', 'cfill', 'l_colorfillDestroy(&%s)', make=None)
obj('L_WALLTIMER', 'wtimer', 'stopWallTimer(&%s)', make='startWallTimer()')

# Borrowed pointer types: never owned by the harness.  One borrow slot per type,
# cleared whenever any pool is mutated (the owner may be gone).
BORROW_T = {
    'L_AMAP_NODE': 'bnode_amap', 'L_ASET_NODE': 'bnode_aset', 'L_RBTREE_NODE': 'bnode_rb',
    'L_HASHITEM': 'bitem_hmap',
}
UNKNOWN_PTR = ('L_RCH', 'L_RCHA_PTR', 'L_PDF_DATA', 'L_REGPARAMS', 'L_RDID', 'L_HASHITEM_T')

SCALARS = ('l_int32', 'l_uint32', 'l_int8', 'l_uint8', 'l_int16', 'l_uint16', 'l_int64',
           'l_uint64', 'l_float32', 'l_float64', 'size_t', 'char')

DBG = {'debug', 'debugflag', 'display', 'renderflag', 'show', 'verbose'}
FNAME = {'filename', 'fileout', 'filein', 'fname', 'fname1', 'fname2', 'rootname', 'outroot',
         'outdir', 'dirin', 'dirout', 'dirname', 'dir', 'indir', 'subdir', 'subdirs', 'debugdir',
         'debugfile', 'srcfile', 'pathname', 'localname', 'newdir', 'infile', 'tiffile', 'filepath',
         'basedir', 'newfile', 'destfile', 'pagedir', 'maskdir', 'logfile', 'pdfout', 'rootout',
         'plotname', 'rootpath', 'src2', 'src1'}
# size parameters bound to the preceding byte buffer (encodeBase64 spells it insize)
SIZENAME = {'size', 'nbytes', 'nsize', 'insize'}
COUNTNAME = {'n', 'npts', 'nelems', 'len', 'length', 'count', 'nalloc', 'nsamp', 'nbins', 'nitems',
             'nchars', 'nentries', 'ntimes', 'cx', 'nrow', 'ncol', 'ncols', 'nrows', 'nlines'}
# output sizes / counts that allocate or loop proportionally (a 100000 border or wd builds a
# 10^10-pixel image); bounded like dimensions
SIZELIKE = {'left', 'right', 'top', 'bot', 'nx', 'ny', 'wd', 'hd', 'nbins', 'halfwidth', 'linewidth',
            'linew', 'scaleh', 'maxheight', 'nsamp', 'npts', 'smoothx', 'smoothy', 'maxiters', 'maxw',
            'wf', 'hf', 'dist', 'maxdist', 'mindist', 'redsearch', 'redsweep', 'minsize', 'fontsize',
            'scale', 'scalefactor', 'scalew',  # integer replication factors (floats are dispatched earlier)
            # cell/tile/border/spacing sizes and initial capacities that allocate proportionally
            'cellw', 'cellh', 'addborder', 'addw', 'addh', 'adjw', 'adjh', 'bordersize', 'border1',
            'border2', 'borderwidth', 'lr_border', 'tb_border', 'maxbord', 'dw', 'dh', 'extra',
            'extrapixels', 'halfh', 'halfsize', 'margin', 'nalloc', 'newsize', 'npixels', 'ntiles',
            'pad', 'selsize', 'setsize', 'size1', 'size2', 'spacing1', 'spacing2', 'hspacing',
            'vspacing', 'dispsep', 'tilesize', 'tilewidth', 'tsize', 'tw', 'whsize', 'xsize', 'ysize',
            'dsize', 'initsize', 'ninit', 'nincr', 'outwidth', 'nwidth', 'opensize', 'sharpwidth',
            'xfact', 'yfact', 'w1', 'w2', 'h1', 'h2'}
DIMNAME = {'w', 'h', 'wc', 'hc', 'ww', 'hw', 'wpl', 'wpls', 'wpld', 'nw', 'nh', 'width', 'height',
           'x', 'y', 'i', 'j', 'x0', 'y0', 'x1', 'y1', 'xc', 'yc', 'nlevels', 'ncolors', 'colors',
           'factor', 'sx', 'sy', 'reduction', 'red', 'halfwin', 'shift', 'nbytes', 'size', 'halfw',
           'npages', 'maxparams', 'skip', 'start', 'end', 'first', 'last', 'index', 'iboxa',
           'ibox', 'ipix', 'nterms', 'border', 'maxsize', 'maxwidth', 'hitskip', 'missskip',
           'hitdist', 'missdist', 'topflag', 'botflag', 'leftflag', 'rightflag', 'maxtries',
           'n', 'cx', 'cy', 'radius', 'side', 'sides', 'nsides', 'maxshift', 'etransx',
           'etransy'}
FMTNAME = {'format', 'type', 'comptype', 'codec', 'outformat', 'hint', 'op', 'incolor', 'negvals',
           'errorflag', 'sorttype', 'sortorder', 'useflag', 'subflag', 'fillflag', 'cmapflag',
           'method', 'quality', 'orientflag', 'normflag', 'ditherflag', 'regionflag', 'scanflag',
           'arraytype', 'outdepth', 'ptype', 'pspp', 'pbps', 'filtertype', 'mindepth'}
FLAGNAME = {'copyflag', 'accessflag', 'freeflag', 'warnflag', 'flag', 'shiftflag'}
# Per-function lower bounds on scalar arguments, where the library leaks or
# misbehaves on a degenerate value that is not an error return:
#   makeColorfillTestData: w/h/nseeds = 0 makes pixCreate/pixSeedspread return
#   NULL and the two 8 bpp colormaps built at colorfill.c:447 and :475 are never
#   freed (the function does not check those returns).
MINS = {
    # pix5.c:2137/2265 clamp with factor = L_MIN(1, factor) where L_MAX is meant: factor 0 spins
    # in y += factor (repro 19); a negative factor walks rows before the image (repro 20)
    'pixClipBoxToEdges': {'factor': 1},
    'pixScanForEdge': {'factor': 1},
    # colorcontent.c:522-524 loops i += factor / j += factor with no factor >= 1 check (repro 22);
    # a scan of all exported bodies for unvalidated loop steps found only these three
    'pixColorFraction': {'factor': 1},
    # grayquant.c:1828 divides by 2 * nlevels - 2; the doc gives 2..256 but nothing checks it (repro 24)
    'makeGrayQuantIndexTable': {'nlevels': 2},
    # verified divide-by-zero crashes (see repro.c cases 4-6)
    'makeColorfillTestData': {'w': 1, 'h': 1, 'nseeds': 1},
    'boxaEncapsulateAligned': {'num': 1},      # boxfunc2.c:1744 n / num
    'l_colorfillCreate': {'nx': 1, 'ny': 1},   # colorfill.c:122 w / nx, h / ny
    'reformatPacked64': {'linechars': 1},      # encoding.c:696
    'numaEvalHaarSum': {'width': 1},           # numafunc2.c:3186 (float 0/0 -> NaN -> int)
    # adaptmap.c:1308/1425 w / reduction; the Norm wrappers check 2..16, these exports do not (repro 10)
    'pixGetBackgroundGrayMapMorph': {'reduction': 1},
    'pixGetBackgroundRGBMapMorph': {'reduction': 1},
    # utils2.c:3394-3400 only checks numpre + numpost > len - 1; a negative numpost writes
    # basename[len - numpost] past the buffer (repro 11)
    'extractNumberFromFilename': {'numpre': 0, 'numpost': 0},
    # pixafunc2.c:968 nrows = (n + nx - 1) / nx, nx never checked; pixDisplayColorArray
    # passes its ncols through unchecked (pix4.c:2849) (repro 13)
    'pixaDisplayTiledInColumns': {'nx': 1},
    'pixDisplayColorArray': {'ncols': 1},
}

# Narrow guards for confirmed library bugs: the call is skipped on the inputs
# that crash, and the bug is recorded in notes.md with file:line and a repro.
#   pixGetTextCompNew: pix1.c:1513-1514 does strlen(pixGetText(pix)) with no NULL
#   check, so any PIX without a text field crashes.
#   parseStringForNumbers: kernel.c:1033 calls atof() on the first token without
#   checking it; a string with no token (empty, or only separators) crashes.
SKIPIF = {
    #   (inarray, insize) pairs: insize is the caller's statement of the array length, so it
    #   must not exceed the string the harness built (harness-side, not a library bug)
    'decodeBase64': 'a1 = L_MIN(a1, (l_int32)strlen(a0));',
    #   reformatPacked64: encoding.c:699-705 also writes leadspace bytes into LEPT_CALLOC(0)
    #   when a0 holds no base64 character (repro 16)
    'reformatPacked64': 'a1 = L_MIN(a1, (l_int32)strlen(a0)); '
                        '{ l_int32 k_, h_ = 0; for (k_ = 0; k_ < a1; k_++) { char c_ = a0[k_]; '
                        'h_ |= (c_ >= \'A\' && c_ <= \'Z\') || (c_ >= \'a\' && c_ <= \'z\') || '
                        '(c_ >= \'0\' && c_ <= \'9\') || c_ == \'+\' || c_ == \'/\' || c_ == \'=\'; } '
                        'if (!h_) return; }',
    'decodeAscii85': 'a1 = L_MIN(a1, strlen(a0));',
    #   nextOnPixelInRaster: conncomp.c:495-497 reads data[ystart * wpl + xstart / 32] with no
    #   range check on the caller's start point (repro 12)
    #   classapp.c:406/:470 use an uninitialised BOXA* when pixWordBoxesByDilation rejects a
    #   non-1-bpp pix (jbclass.c:1586 returns before *pboxa = NULL) (repro 14)
    #   convolve.c:741-753 returns early only if nx <= 1 && ny <= 1, then divides w / nx and
    #   h / ny; one of them 0 and the other > 1 divides by zero (repro 15)
    #   jbclass.c:972/976 and correlscore.c round the caller's centroid delta to int with no
    #   range check; |delx| >= 2^31 is UB, yields INT_MIN, and the rasterop clipping then
    #   overflows (roplow.c:520-526) and writes out of bounds (repro 17)
    #   recogCreate*: with scalew == scaleh == 0 templates keep the training images' size (up
    #   to the 2M-pixel pool cap) and every identify/average pass correlates them pairwise,
    #   far past the timeout; use the documented recommendation scaleh = 40 (recogbasic.c)
    #   recogDebugAverages identifies each class average against every sample; on the full
    #   boot recognizer (recogMakeBootDigitRecog nsamp = 0) that takes 111 s under ASan.
    #   Skip it above 200 samples (counted through the public recogExtractPixa)
    #   numafunc2.c:621/647 (and :589) only warn when 2*wc+1 > n; numaAddSpecifiedBorder then
    #   refuses a mirrored border wider than n and returns NULL, which is dereferenced
    #   (numafunc2.c:604/662) (repro 18)
    #   pix5.c:2137/2265 clamp with factor = L_MIN(1, factor) where L_MAX is meant: factor 0
    #   spins in y += factor (repro 19), negative factor walks rows before the image (repro 20)
    'numaWindowedMean': 'if (a1 > numaGetCount(a0)) return;',
    'numaWindowedMeanSquare': 'if (a1 > numaGetCount(a0)) return;',
    'numaWindowedStats': 'if (a1 > numaGetCount(a0)) return;',
    'recogDebugAverages': '{ PIXA *pa_ = recogExtractPixa(a0); l_int32 n_ = pa_ ? pixaGetCount(pa_) : 0; '
                          'pixaDestroy(&pa_); if (n_ > 200) return; }',
    'recogCreate': 'if (a0 <= 0 && a1 <= 0) a1 = 40;',
    'recogCreateFromRecog': 'if (a1 <= 0 && a2 <= 0) a2 = 40;',
    'recogCreateFromPixa': 'if (a1 <= 0 && a2 <= 0) a2 = 40;',
    'recogCreateFromPixaNoFinish': 'if (a1 <= 0 && a2 <= 0) a2 = 40;',
    'pixHaustest': 'if (!(fabsf(a4) < 1e4f && fabsf(a5) < 1e4f)) return;',
    'pixRankHaustest': 'if (!(fabsf(a4) < 1e4f && fabsf(a5) < 1e4f)) return;',
    'pixCorrelationScore': 'if (!(fabsf(a4) < 1e4f && fabsf(a5) < 1e4f)) return;',
    'pixCorrelationScoreThresholded': 'if (!(fabsf(a4) < 1e4f && fabsf(a5) < 1e4f)) return;',
    'pixCorrelationScoreSimple': 'if (!(fabsf(a4) < 1e4f && fabsf(a5) < 1e4f)) return;',
    'pixBlockconvTiled': 'if (a3 < 1 || a4 < 1) return;',
    #   adaptmap.c:1095-1160 pixGetBackgroundRGBMap never validates the optional gray pixg: a
    #   non-8-bpp pixg makes pixThresholdToBinary return NULL and dataf is dereferenced; a smaller
    #   8-bpp pixg is read with pixs's dimensions. The four Norm entry points forward it (repro 23)
    'pixGetBackgroundRGBMap': 'if (a2 && (pixGetDepth(a2) != 8 || pixGetWidth(a2) != pixGetWidth(a0) || pixGetHeight(a2) != pixGetHeight(a0))) return;',
    'pixCleanBackgroundToWhite': 'if (a2 && (pixGetDepth(a2) != 8 || pixGetWidth(a2) != pixGetWidth(a0) || pixGetHeight(a2) != pixGetHeight(a0))) return;',
    'pixBackgroundNormSimple': 'if (a2 && (pixGetDepth(a2) != 8 || pixGetWidth(a2) != pixGetWidth(a0) || pixGetHeight(a2) != pixGetHeight(a0))) return;',
    'pixBackgroundNorm': 'if (a2 && (pixGetDepth(a2) != 8 || pixGetWidth(a2) != pixGetWidth(a0) || pixGetHeight(a2) != pixGetHeight(a0))) return;',
    'pixBackgroundNormRGBArrays': 'if (a2 && (pixGetDepth(a2) != 8 || pixGetWidth(a2) != pixGetWidth(a0) || pixGetHeight(a2) != pixGetHeight(a0))) return;',
    #   in-place horizontal shear (pixHShearIP; pixHShear/Corner/Center with pixd == pixs;
    #   pixRotateShearIP/CenterIP, which shear by angle/2 about ycen) reaches the unclamped
    #   shiftDataHorizontalLow (roplow.c:2468); see hshear_ok (repro 25)
    'pixHShear': 'if (a0 && a0 == a1 && !hshear_ok(a1, a2, a3)) return;',
    'pixHShearCorner': 'if (a0 && a0 == a1 && !hshear_ok(a1, 0, a2)) return;',
    'pixHShearCenter': 'if (a0 && a0 == a1 && !hshear_ok(a1, pixGetHeight(a1) / 2, a2)) return;',
    'pixHShearIP': 'if (!hshear_ok(a0, a1, a2)) return;',
    'pixRotateShearIP': 'if (!hshear_ok(a0, a2, a3 / 2.f)) return;',
    'pixRotateShearCenterIP': 'if (!hshear_ok(a0, pixGetHeight(a0) / 2, a1 / 2.f)) return;',
    'pixGetWordsInTextlines': 'if (pixGetDepth(a0) != 1) return;',
    'pixGetWordBoxesInTextlines': 'if (pixGetDepth(a0) != 1) return;',
    'nextOnPixelInRaster': 'if (a1 < 0 || a2 < 0 || a1 >= pixGetWidth(a0) || a2 >= pixGetHeight(a0)) return;',
    'pixGetTextCompNew': 'if (!pixGetText(a0)) return;',
    'parseStringForNumbers': 'if (!a0[0] || strspn(a0, a1) == strlen(a0)) return;',
    #   modifyTrailingSlash: utils2.c:3289 reads path[len - 1] with no check that the
    #   string is non-empty, so an empty path reads one byte before the buffer.
    'modifyTrailingSlash': 'if (!a0[0]) return;',
    #   kernelCreateFromString -> parseStringForNumbers (bug 4); the kernel string
    #   must contain at least one number
    'kernelCreateFromString': 'if (!strpbrk(a4, "0123456789")) return;',
    #   pixaComparePhotoRegionsByHisto: compare.c:2129 computes 1000 / nim with
    #   nim = pixaGetCount(pixa), so an empty pixa divides by zero.
    'pixaComparePhotoRegionsByHisto': 'if (pixaGetCount(a0) == 0) return;',
    #   generatePtaHashBox: graphics.c:436,444 divide by (n - 1) where
    #   n = 1 + bh/spacing, so a spacing larger than the box height divides by zero.
    #   pixConvolve/pixConvolveSep/fpixConvolve/fpixConvolveSep: the kernel must fit
    #   inside the image; convolve.c:1917 reads past the line when it does not.
    #   convolve.c:1912-1917 picks the writer by outdepth but falls through to the
    #   32-bit store for any other value, so outdepth must be 8, 16 or 32.
    #   Library bug: shiftDataHorizontalLow (roplow.c:2457-2468) computes firstdw = shift / 32
    #   and wpl = wpld - firstdw without clamping, so a horizontal shift of 32 bits or more past
    #   the line writes before the line start (repro.c case 9). Undocumented limit; every public
    #   path that passes a caller-chosen horizontal shift is guarded to |hshift| < width.
    'pixTranslate': 'if (L_ABS(a2) >= pixGetWidth(a1)) return;',
    'pixRasteropHip': 'if (L_ABS(a3) >= pixGetWidth(a0)) return;',
    'pixRasteropIP': 'if (L_ABS(a1) >= pixGetWidth(a0)) return;',
    'pixWarpStereoscopic': 'if (L_ABS(a2) >= pixGetWidth(a0) || L_ABS(a3) >= pixGetWidth(a0)) return;',
    'pixaTranslate': 'if (L_ABS(a1) >= 32) return;',
    'pixConvolve': 'if (a2 != 8 && a2 != 16 && a2 != 32) return;'
                   ' kx0 = ky0 = 0; kernelGetParameters(a1, &ky0, &kx0, NULL, NULL);'
                   ' if (kx0 > pixGetWidth(a0) || ky0 > pixGetHeight(a0)) return;',
    'pixConvolveSep': 'if (a2 != 8 && a2 != 16 && a2 != 32) return;'
                      ' kx0 = ky0 = 0; kernelGetParameters(a1, &ky0, &kx0, NULL, NULL);'
                      ' if (kx0 > pixGetWidth(a0) || ky0 > pixGetHeight(a0)) return;',
    'fpixConvolve': 'kx0 = ky0 = 0; kw0 = kh0 = 0;'
                    ' kernelGetParameters(a1, &ky0, &kx0, NULL, NULL);'
                    ' fpixGetDimensions(a0, &kw0, &kh0);'
                    ' if (kx0 > kw0 || ky0 > kh0) return;',
    #   pixCopyRGBComponent: pix2.c:2700-2703 guard with `&&` instead of `||`, so a
    #   non-32-bpp pix is not rejected and GET_DATA_BYTE walks 4 bytes per pixel.
    'pixCopyRGBComponent': 'if (pixGetDepth(a0) != 32 || pixGetDepth(a1) != 32) return;',
    'generatePtaHashBox': 'bh0 = 0; boxGetGeometry(a0, NULL, NULL, NULL, &bh0);'
                          ' if (a1 < 1 || bh0 / a1 < 1) return;',
}
# out-parameters that return a pointer the callee still owns
BORROW_OUT = {'sarrayGetArray'}
# lookup-table parameters (an input array whose name contains 'tab'): an [optional] one is passed NULL (the
# library makes its own); a required one comes from the library's builder. Freed after the call.
TABLE = {
    ('pixRankHaustest', 'tab8'): 'makePixelSumTab8()',
    ('pixCorrelationScore', 'tab'): 'makePixelSumTab8()',
    ('pixCorrelationScoreThresholded', 'tab'): 'makePixelSumTab8()',
    ('pixCorrelationScoreSimple', 'tab'): 'makePixelSumTab8()',
    ('pixCorrelationScoreShifted', 'tab'): 'makePixelSumTab8()',
    ('getLogBase2', 'logtab'): 'makeLogBase2Tab()',
    ('logScaleRGBVal', 'tab'): 'makeLogBase2Tab()',
}

# *Clone() functions return the same pointer with the ref count incremented, so the
# pool really does acquire a second reference and the returned pointer is stored even
# though it is already in the pool.
CLONE = {'boxClone', 'l_dnaClone', 'fpixClone', 'dpixClone', 'numaClone', 'pixClone',
         'ptaClone', 'sarrayClone'}
# Per-function upper bounds, where the library indexes an array with the value and
# documents (but does not check) the range:
#   getLogBase2: pixarith.c:1589 indexes logtab[val] after only checking val < 0x100,
#   so a negative val reads before the table (doc: "val in range [0 ... 255]").
MAXS = {'getLogBase2': {'val': 255},
        # colorquant1.c:1451 "No error checking!" and indexes rtab[rval] ... with
        # rval in 0..255 (the tables from makeRGBToIndexTables() have 256 entries)
        'getOctcubeIndexFromRGB': {'rval': 255, 'gval': 255, 'bval': 255}}
REF_EXTRA = {'l_byteaJoin', 'recogTrainingFinished', 'pixRenderPlotFromNuma',
             'pixRenderPlotFromNumaGen',
             # replace *precog / destroy *ptimer (recogtrain.c:1042, 1258, 1546; utils1.c:1364)
             'recogRemoveOutliers1', 'recogRemoveOutliers2', 'recogPadDigitTrainingSet', 'stopWallTimer'}
# a `T **` out-parameter that receives a pointer the library still owns: not put in a harness pool
BORROW_OUTPARAM = {('selaFindSelByName', 'psel')}   # sel1.c:700 "sel (not a copy)"
ITEMFUNC = re.compile(r'^(ptra(Add|Insert|Replace)|lstackAdd|lqueueAdd|lheapAdd|listAddTo|'
                      r'listInsert(Before|After))$')

# --------------------------------------------------------------------------- #
# source parsing
# --------------------------------------------------------------------------- #

PROTO = re.compile(r'^LEPT_DLL extern\s+(.+?)\s+(\w+)\s*\(\s*(.*?)\s*\);$')
BODY = re.compile(r'^(\w+)\s*\(([^;{]*?)\)\s*\n\{', re.M)


def parse_params(args):
    ps = []
    if not args.strip() or args.strip() == 'void':
        return ps
    for a in args.split(','):
        a = a.strip()
        m = re.match(r'^(.*?)\s*(\w+)$', a)
        if not m:
            ps.append((a, ''))
            continue
        ps.append((m.group(1).strip(), m.group(2)))
    return ps


def load(src):
    h = open(os.path.join(src, 'allheaders.h')).read()
    funcs = []
    for line in h.split('\n'):
        if not line.startswith('LEPT_DLL extern'):
            continue
        m = PROTO.match(line)
        if not m:
            continue
        ret, name, args = m.groups()
        funcs.append([name, ret.strip(), parse_params(args)])
    names = {f[0]: f for f in funcs}

    docs, files, lines, bodies = {}, {}, {}, {}
    for fn in sorted(f for f in os.listdir(src) if f.endswith('.c')):
        t = open(os.path.join(src, fn), errors='replace').read()
        for m in BODY.finditer(t):
            n = m.group(1)
            if n not in names or n in docs:
                continue
            i = m.end() - 1
            d = 0
            j = i
            while j < len(t):
                if t[j] == '{':
                    d += 1
                elif t[j] == '}':
                    d -= 1
                    if d == 0:
                        break
                j += 1
            start = m.start()
            # the doc is the comment block that ends right before the definition (only the return
            # type in between); leptonica uses both /*! and /* for these blocks
            e = t.rfind('*/', 0, start)
            gap = t[e + 2:start] if e >= 0 else ';'
            ds = t.rfind('/*', 0, e) if e >= 0 and not any(c in gap for c in ';{}') else -1
            docs[n] = t[ds:start] if ds >= 0 else ''
            files[n] = fn
            lines[n] = t[:start].count('\n') + 1
            bodies[n] = t[start:j + 1]
    return funcs, docs, files, lines, bodies


def docmeta(doc):
    dirs, descs = {}, {}
    # a description continues on following indented comment lines (" *        or different from pixs")
    for m in re.finditer(r'\\param\[(\w+(?:,\w+)?)\]\s+(\w+)([^\n]*)((?:\n \*\s{4,}[^\s\\<][^\n]*)*)', doc):
        dirs[m.group(2)] = m.group(1)
        descs[m.group(2)] = m.group(3) + ' ' + ' '.join(x.strip(' *') for x in m.group(4).split('\n') if x)
    r = re.search(r'\\return\s+([^\n]*)', doc) or re.search(r'Return:\s+([^\n]*)', doc)  # older doc style
    return dirs, descs, (r.group(1).strip() if r else '')


# --------------------------------------------------------------------------- #
# hand decisions
# --------------------------------------------------------------------------- #
# exclude(name, reason)  -- not wrapped, reason printed in the report
# DONATE[name] = {param}  -- callee takes ownership of that object argument
# BORROW.add(name)        -- pointer return is borrowed from an argument
# CODE[name] = C lines    -- complete hand-written wrapper body
# NOTE[name] = comment    -- emitted above the wrapper

EXCLUDE = {}
DONATE = {}
DONATE_ITEMS = set()
DONATE_STR = {'generateUncompressedPS': {'hexdata'}}
# pointer arguments the callee stores and later frees (`obj->data = data`):
# a heap array is handed over, and freed by the harness only if the call fails.
#   fpixSetData fpix1.c:474, dpixSetData dpix1.c, pixSetData pix1.c
DONATE_ARR = {'fpixSetData': {'data'}, 'dpixSetData': {'data'}, 'pixSetData': {'data'},
              'pixFreeAndSetData': {'data'}}
BORROW = set()
CODE = {}
NOTE = {}
PRE = {}
SUCCESS = {}
# returnErrorPtr*(msg, procname, pval) returns pval (utils1.c:233-242); the harness passes pval = NULL
SUCCESS['returnErrorPtr'] = SUCCESS['returnErrorPtr1'] = 'r == a2'


def exclude(name, why):
    EXCLUDE[name] = why


_PROC = '''gplotMakeOutput l_pdfRenderFiles l_pdfRenderUnscaledFiles callSystemDebug
pixDisplayWithTitle'''.split()
for n in _PROC:
    exclude(n, 'spawns a process (system()/callSystemDebug) or opens a display')

_DISP = '''pixDisplay pixDisplayWrite'''.split()
for n in _DISP:
    exclude(n, 'opens a viewer via pixDisplayWithTitle (system()) or writes under a fixed '
               'debug directory (lept_mkdir/genPathname)')

_GPLOT = '''gplotSimplePixSeries gplotSimpleXY1 gplotSimpleXY2 gplotSimpleXYN gplotSimple1
gplotSimple2 gplotSimpleN gplotSimplePix1 gplotSimplePix2 gplotSimplePixN gplotSimpleArray
gplotSimpleXYArray gplotDrawLine gplotMakeOutputPix gplotPlot1'''.split()
for n in _GPLOT:
    exclude(n, 'writes gnuplot command/data files and runs gnuplot (callSystemDebug)')

_FS_TMP = '''lept_mkdir lept_rmdir lept_rmrf lept_rm lept_mv lept_cp lept_rename
fileMakeDir pixacompWriteFiles'''.split()
for n in _FS_TMP:
    exclude(n, 'creates, removes or moves files under leptonica\'s fixed /tmp/lept root '
               '(utils2.c genPathname), outside the harness cwd')

_FS_DIR = '''listFiles listFilesInDirectory getFilenamesInDirectory convertFilesTo1bpp
convertToNUpFiles pixaReadFiles pixacompReadFiles pixaMakePixaFromFiles
convertSegmentedPagesToPS convertSegmentedPagesToPSEmbed tiffMultipageToFile'''.split()
for n in _FS_DIR:
    exclude(n, 'walks a caller-named directory and reads every matching file in it')

_LOWLEVEL = '''fmorphopgen_low_1 fmorphopgen_low_2 fhmtgen_low_1
rasteropLow rasteropUniLow rasteropHipLow rasteropVipLow'''.split()
for n in _LOWLEVEL:
    exclude(n, 'vector-level kernel: its (datad, wpl, dx, dy, w, h) arguments must be mutually '
               'consistent (roplow.c:2468 walks past the line otherwise), which the harness '
               'cannot synthesize; the same code runs inside pixRasterop*/pixMorphDwa_*/, which '
               'are wrapped')

for n in ('fileReplaceBytes',):
    exclude(n, 'rewrites a caller-named file at an offset the harness cannot bound: '
               'utils1.c:694 reads past EOF when start/nbytes exceed the file length')

_DIRREAD = '''jbWordsInTextlines jbCorrelation jbRankHaus'''.split()
for n in _DIRREAD:
    exclude(n, 'reads every image in a directory named by the caller; nothing confines it to the '
               'harness cwd, and jbWordsInTextlines dereferences a NULL classer when the '
               'directory is missing (classapp.c:297)')

_REG = '''regTestSetup regTestCleanup regTestCompareValues regTestCompareStrings regTestComparePix
regTestCompareSimilarPix regTestCheckFile regTestCompareFiles regTestWritePixAndCheck
regTestWriteDataAndCheck regTestGenLocalFilename'''.split()
for n in _REG:
    exclude(n, 'regression-test driver: writes numbered reference files into a test directory and '
               'compares against them; it is test infrastructure, not library surface')

_GEN = '''strcodeCreate strcodeCreateFromFile strcodeGenerate strcodeFinalize
fhmtautogen fhmtautogen1 fhmtautogen2 fmorphautogen fmorphautogen1 fmorphautogen2
dwacomautogen dwacomautogen2'''.split()
for n in _GEN:
    exclude(n, 'code generator: writes C source files named by the caller')

for n in ('pixMakeHistoHV',):
    exclude(n, 'reads past its own histogram image: colorspace.c:1096 allocates 256x240 '
               'but colorspace.c:1111 indexes row = red value in 0..255 (notes.md, bug 8). '
               'There is no caller-side guard, so the scan continues without it')
for n in ('zlibUncompress', 'pixGetTextCompNew', 'ccbaRead', 'ccbaReadStream',
          'decodeAscii85WithComp'):
    exclude(n, 'lies on an infinite loop: zlibmem.c:236-258 never checks the status '
               'returned by inflate(), so any buffer it rejects spins the for(;;) loop '
               'forever, and copies its default 1024 bytes out of a zero-length input '
               '(bbuffer.c:147) (notes.md, bugs 1 and 2); the ccba readers and '
               'decodeAscii85WithComp reach it')
exclude('lept_realloc', 'takes a pointer the harness owns and grows it in place; the harness '
        'cannot pass a buffer whose ownership it does not share with the library')
exclude('pmsCreate', 'installs a process-global pix memory store and documents "call this '
        'before any pix have been allocated"; a call from a fuzzer that already holds pixes '
        'breaks that contract, and a numalloc with no levels reads sizes[-1] (pixalloc.c:211)')
exclude('setPixMemoryManager', 'installs a process-global allocator; the harness and the library '
        'would then disagree about who frees pix data')

exclude('lept_stderr', 'variadic printf wrapper: no bounded argument synthesis')
for n in '''pmsDestroy pmsCustomAlloc pmsCustomDealloc pmsGetAlloc pmsGetLevelForAlloc pmsGetLevelForDealloc
            pmsLogInfo'''.split():
    exclude(n, 'operates on the process-global pix memory store that pmsCreate installs (excluded above); '
               'without it every call returns an error (pixalloc.c)')
for n in 'rchExtract rchDestroy rchaExtract rchaDestroy'.split():
    exclude(n, 'takes an L_RCH / L_RCHA, which no public function returns (the recog keeps them internally, '
               'recogident.c)')
exclude('pixGetOuterBorder', 'takes a CCBORD, which only the ccbord.c internals build (no public constructor)')
exclude('reallocNew', 'takes a pointer the harness owns and grows it in place; same reason as lept_realloc')

# Owned-object arguments the callee takes over (body: `field = arg;` with no
# copy, or the doc's "the input is owned by").  A fresh donor object is made for
# each, so no pool slot can be double-freed.
DONATE.update({
    'boxaReplaceBox': {'box'},
    'boxaInsertBox': {'box'},          # boxbasic.c:949 array[index] = box, no copy
    'boxaaInsertBoxa': {'boxa'},       # boxbasic.c:1599
    'boxaaReplaceBoxa': {'boxa'},
    'dewarpaInsertDewarp': {'dew'},
    'l_dnaaReplaceDna': {'da'},
    'numaaReplaceNuma': {'na'},
    'pixSetColormap': {'colormap'},
    'pixaReplacePix': {'pix'},
    'pixaInsertPix': {'pixs', 'box'},  # pixabasic.c:1304 pixa->pix[index] = pixs
    'pixaSetBoxa': {'boxa'},
    'pixaaReplacePixa': {'pixa'},
    'pixacompReplacePixcomp': {'pixc'},
    'ptaaReplacePta': {'pta'},
    'ptraaInsertPtra': {'pa'},
    'rchaExtract': set(),          # doc: the rcha is destroyed
    'dewarpDestroy': set(),
})
# same, for `char *`/`l_uint8 *` arguments that the callee frees
# ptra/stack/queue/heap items are freed by the container's destructor (freeflag 1);
# dllist nodes are freed but their data is not (listDestroy frees nodes only), so a
# dllist "data" pointer is a harness-owned scratch block, never a heap item.
DONATE_ITEMS.update(['ptraAdd', 'ptraInsert', 'ptraReplace', 'lstackAdd', 'lqueueAdd', 'lheapAdd'])

# Pointer returns that are borrowed from an argument (body `return x->field;`,
# or the doc says "owned by", "do not destroy", "do not free").
BORROW.update([
    'dewarpaGetDewarp', 'dpixGetData', 'fpixGetData', 'l_byteaGetData', 'l_rbtreeGetNext',
    'l_rbtreeGetPrev', 'numaaGetPtrArray', 'pixGetColormap', 'pixGetData', 'pixGetText',
    'pixaGetPixArray', 'pixaccGetPix', 'ptraGetPtrToItem', 'selGetName',
    'l_rbtreeGetFirst', 'l_rbtreeGetLast', 'l_amapGetFirst', 'l_amapGetNext', 'l_amapGetLast',
    'l_amapGetPrev', 'l_asetGetFirst', 'l_asetGetNext', 'l_asetGetLast', 'l_asetGetPrev',
    'l_amapFind', 'l_asetFind', 'l_rbtreeLookup', 'l_hmapLookup', 'lheapGetElement',
    'listFindElement', 'listFindTail', 'pixacompGetPixcomp', 'sarrayGetArray',
    'getFormatExtension',
    'selaGetSel',      # sel1.c: "returns a ptr to the sel, not a copy, so the caller must not destroy it"
    'fpixaGetData',    # fpix1.c: "data not a copy"
])

# Wrappers that need hand-written code (keytype tracking, in/out object refs).
PRE_ = {}

CODE['pixFreeData'] = '''
    PIX *a0 = pix_arg(b(in, 0));
    l_int32 r;
    if (!a0) return;
    if (!preqed_call("pixFreeData")) return;
    r = pixFreeData(a0);
    preqed_result("pixFreeData", r == 0);
    /* after this the pix has no data, and pixCopy()/pixBlend*() memcpy from
       pixs->data without a NULL check (pix1.c:706), so the pool drops it */
    if (r == 0) pix_drop(b(in, 0));
'''
CODE['pixExtractData'] = '''
    PIX *a0 = pix_arg(b(in, 0));
    l_uint32 *r;
    if (!a0) return;
    if (!preqed_call("pixExtractData")) return;
    r = pixExtractData(a0);
    preqed_result("pixExtractData", r != NULL);
    lept_free(r);
    /* pix1.c:1756 with refcount 1 leaves pix->data NULL; the doc says only pixDestroy
       remains, so the pool drops the shell (same as pixFreeData) */
    if (!pixGetData(a0)) pix_drop(b(in, 0));
'''
CODE['lept_free'] = '''
    void *p;
    if (!preqed_call("lept_free")) return;
    p = lept_calloc(1, 16);
    lept_free(p);
    preqed_result("lept_free", 1);
'''
CODE['lept_calloc'] = '''
    void *r;
    if (!preqed_call("lept_calloc")) return;
    r = lept_calloc(1 + (size_t)b(in, 0), sizeof(l_uint64));
    preqed_result("lept_calloc", r != NULL);
    lept_free(r);
'''
CODE['l_generateJpegDataMem'] = '''
    /* pdfio2.c:1012-1033 always consumes data: LEPT_FREE on error, cid->datacomp on success
       (freed by l_CIDataDestroy). The header comment does not say so. */
    size_t n = 0;
    const u8 *src = blob(in, b(in, 0), &n);
    l_uint8 *data;
    L_COMP_DATA *r;
    if (!preqed_call("l_generateJpegDataMem")) return;
    data = (l_uint8 *)lept_calloc(n ? n : 1, 1);
    if (!data) { preqed_result("l_generateJpegDataMem", 0); return; }
    if (n) memcpy(data, src, n);
    r = l_generateJpegDataMem(data, n, sint(in, 2));
    preqed_result("l_generateJpegDataMem", r != NULL);
    if (r) cid_put(b(in, 1), r);
'''
CODE['fileConcatenate'] = '''
    /* append to a second file so FNAME does not double on every call */
    if (!preqed_call("fileConcatenate")) return;
    file_prep(in);
    l_ok r = fileConcatenate(FNAME, FNAME2);
    preqed_result("fileConcatenate", r == 0);
    unlink(FNAME2);
'''
CODE['fileCopy'] = '''
    if (!preqed_call("fileCopy")) return;
    file_prep(in);
    l_ok r = fileCopy(FNAME, FNAME2);
    preqed_result("fileCopy", r == 0);
    unlink(FNAME2);
'''
CODE['leptSetStderrHandler'] = '''
    (void)in;
    if (!preqed_call("leptSetStderrHandler")) return;
    /* the upstream fuzzers do the same in FuzzerSetup (prog/fuzzing/leptfuzz.h) */
    leptSetStderrHandler(handler_discard);
    preqed_result("leptSetStderrHandler", 1);
'''
CODE['gaussjordan'] = '''
    l_float32 **aa, *rhs;
    l_int32 n = 1 + (l_int32)(b(in, 0) % 8), i, r;
    if (!preqed_call("gaussjordan")) return;
    /* the argument is a caller-allocated n x n matrix of rows and a rhs vector;
       a NULL row array would only crash the harness's own synthesis, so build a
       real one (and note affine.c:1328 calloc's n with no check that n > 0) */
    aa = create2dFloatArray(n, n);
    rhs = (l_float32 *)lept_calloc((size_t)n, sizeof(l_float32));
    if (!aa || !rhs) {
        if (aa) { for (i = 0; i < n; i++) lept_free(aa[i]); lept_free(aa); }
        lept_free(rhs);
        preqed_result("gaussjordan", 0);
        return;
    }
    r = gaussjordan(aa, rhs, n);
    preqed_result("gaussjordan", r == 0);
    for (i = 0; i < n; i++) lept_free(aa[i]);
    lept_free(aa);
    lept_free(rhs);
'''
CODE['sudokuGenerate'] = '''
    l_int32 *a0 = (l_int32 *)tmp_alloc(81 * sizeof(l_int32));
    l_int32 i;
    L_SUDOKU *r;
    if (!a0) return;
    if (!preqed_call("sudokuGenerate")) return;
    /* sudoku.c:729 spins forever on an array with no non-zero entry, so give it a
       completed solution as the doc says ("array: a valid sudoku solution") */
    for (i = 0; i < 81; i++) {
        l_int32 r0 = i / 9, c0 = i % 9;
        a0[i] = (r0 * 3 + r0 / 3 + c0) % 9 + 1;
    }
    /* each removal runs a backtracking uniqueness check whose cost explodes as cells
       are removed; keep >= 28 givens as prog/sudokutest.c:63 does */
    r = sudokuGenerate(a0, sint(in, 1), L_MAX(28, small(in, 2)), L_MIN(small(in, 3), 8));
    preqed_result("sudokuGenerate", r != NULL);
    if (r) sudoku_put(b(in, 1), r);
'''
# Geometry setters. The library calls them while it builds or reallocates an image (fpix1.c:172-173,
# pix1.c pixResizeImageData); on a live image they must keep it consistent with its data buffer
# (wpl * h words; for fpix/dpix wpl * h elements). New values are drawn inside that buffer.
CODE['pixSetHeight'] = '''
    PIX *a0 = pix_arg(b(in, 0));
    l_int32 w, h, d;
    if (!a0 || pixGetDimensions(a0, &w, &h, &d) || h < 1 || d < 1) return;
    if (!preqed_call("pixSetHeight")) return;
    preqed_result("pixSetHeight", pixSetHeight(a0, 1 + b(in, 1) % h) == 0);
'''
CODE['pixSetWidth'] = '''
    PIX *a0 = pix_arg(b(in, 0));
    l_int32 w, h, d;
    if (!a0 || pixGetDimensions(a0, &w, &h, &d) || h < 1 || d < 1) return;
    l_int32 wmax = 32 * pixGetWpl(a0) / d;   /* the row holds wpl words */
    if (!preqed_call("pixSetWidth")) return;
    preqed_result("pixSetWidth", pixSetWidth(a0, 1 + (l_int32)(u32v(in, 1) % (l_uint32)wmax)) == 0);
'''
CODE['pixSetDepth'] = '''
    static const l_int32 depths[] = {1, 2, 4, 8, 16, 32};
    PIX *a0 = pix_arg(b(in, 0));
    l_int32 w, h, d, nd = depths[b(in, 1) % 6];
    if (!a0 || pixGetDimensions(a0, &w, &h, &d) || h < 1 || d < 1) return;
    /* the row must still fit in wpl words; a colormap's entries are only valid for its own depth */
    if ((l_int64)w * nd > 32 * (l_int64)pixGetWpl(a0) || pixGetColormap(a0)) return;
    if (!preqed_call("pixSetDepth")) return;
    preqed_result("pixSetDepth", pixSetDepth(a0, nd) == 0);
'''
CODE['pixSetWpl'] = '''
    PIX *a0 = pix_arg(b(in, 0));
    l_int32 w, h, d;
    if (!a0 || pixGetDimensions(a0, &w, &h, &d) || h < 1 || d < 1) return;
    l_int32 need = (w * d + 31) / 32, wpl = pixGetWpl(a0);   /* need <= new wpl <= current wpl */
    if (need < 1 || need > wpl) return;
    if (!preqed_call("pixSetWpl")) return;
    preqed_result("pixSetWpl", pixSetWpl(a0, need + b(in, 1) % (wpl - need + 1)) == 0);
'''
CODE['pixSetDimensions'] = '''
    PIX *a0 = pix_arg(b(in, 0));
    l_int32 w, h, d;
    if (!a0 || pixGetDimensions(a0, &w, &h, &d) || h < 1 || d < 1) return;
    l_int32 wmax = 32 * pixGetWpl(a0) / d;
    /* 0 skips a field (pix1.c pixSetDimensions); the depth is kept */
    l_int32 nw = (b(in, 1) & 1) ? 0 : 1 + (l_int32)(u32v(in, 2) % (l_uint32)wmax);
    l_int32 nh = (b(in, 1) & 2) ? 0 : 1 + b(in, 6) % h;
    if (!preqed_call("pixSetDimensions")) return;
    preqed_result("pixSetDimensions", pixSetDimensions(a0, nw, nh, 0) == 0);
'''
for T, P in (('FPIX', 'fpix'), ('DPIX', 'dpix')):
    CODE[P + 'SetDimensions'] = '''
    %(T)s *a0 = %(P)s_arg(b(in, 0));
    l_int32 w, h;
    if (!a0 || %(P)sGetDimensions(a0, &w, &h)) return;
    l_int32 wpl = %(P)sGetWpl(a0);   /* one element per pixel: w <= wpl */
    if (wpl < 1 || h < 1) return;
    if (!preqed_call("%(P)sSetDimensions")) return;
    preqed_result("%(P)sSetDimensions", %(P)sSetDimensions(a0, 1 + b(in, 1) %% wpl, 1 + b(in, 2) %% h) == 0);
''' % {'T': T, 'P': P}
    CODE[P + 'SetWpl'] = '''
    %(T)s *a0 = %(P)s_arg(b(in, 0));
    l_int32 w, h;
    if (!a0 || %(P)sGetDimensions(a0, &w, &h)) return;
    l_int32 wpl = %(P)sGetWpl(a0);   /* w <= new wpl <= current wpl */
    if (w < 1 || w > wpl) return;
    if (!preqed_call("%(P)sSetWpl")) return;
    preqed_result("%(P)sSetWpl", %(P)sSetWpl(a0, w + b(in, 1) %% (wpl - w + 1)) == 0);
''' % {'T': T, 'P': P}
# pixCreateHeader makes a pix without image data; the library completes it the way pixCreateNoInit does
# (pix1.c:352-361: allocate wpl * h words, pixSetData). Only a completed pix goes into the image pool.
CODE['pixCreateHeader'] = '''
    if (!preqed_call("pixCreateHeader")) return;
    PIX *r = pixCreateHeader(small(in, 0), small(in, 1), depthv(in, 2));
    preqed_result("pixCreateHeader", r != NULL);
    if (!r) return;
    l_uint32 *data = (l_uint32 *)lept_calloc((size_t)pixGetWpl(r) * pixGetHeight(r) + 1, sizeof(l_uint32));
    if (!data) { pixDestroy(&r); return; }
    pixSetData(r, data);
    pix_put(b(in, 1), r);
'''
# FNAME2 is FNAME's content, or that content with one byte changed
CODE['filesAreIdentical'] = '''
    l_int32 same = 0;
    file_prep(in);
    size_t n = 0;
    l_uint8 *data = l_binaryRead(FNAME, &n);
    if (!data) return;
    if (n && (b(in, 0) & 1)) data[b(in, 1) % n] ^= 1;
    l_binaryWrite(FNAME2, "w", data, n);
    lept_free(data);
    if (preqed_call("filesAreIdentical")) {
        l_ok r = filesAreIdentical(FNAME, FNAME2, &same);
        preqed_result("filesAreIdentical", r == 0);
    }
    unlink(FNAME2);
'''
# the three octcube tables come from makeRGBToIndexTables (colorquant1.c:1342, cqlevels 1..6)
CODE['getOctcubeIndexFromRGB'] = '''
    l_uint32 *rtab = NULL, *gtab = NULL, *btab = NULL, index = 0;
    if (makeRGBToIndexTables(1 + b(in, 3) % 6, &rtab, &gtab, &btab)) return;
    if (preqed_call("getOctcubeIndexFromRGB")) {
        getOctcubeIndexFromRGB(b(in, 0), b(in, 1), b(in, 2), rtab, gtab, btab, &index);
        preqed_result("getOctcubeIndexFromRGB", 1);
    }
    lept_free(rtab);
    lept_free(gtab);
    lept_free(btab);
'''
# tab: a caller-defined 256-entry LUT, 1 = write to the mask (pix3.c:1034); 256 bits of the input
CODE['pixMakeMaskFromLUT'] = '''
    PIX *a0 = pix_arg(b(in, 0));
    l_int32 tab[256];
    for (int i = 0; i < 256; i++) tab[i] = (b(in, 2 + i / 8) >> (i % 8)) & 1;
    if (!preqed_call("pixMakeMaskFromLUT")) return;
    PIX *r = pixMakeMaskFromLUT(a0, tab);
    int okv = r != NULL;
    if (r) pix_put(b(in, 1), r);
    preqed_result("pixMakeMaskFromLUT", okv);
'''
CODE['pixSetupByteProcessing'] = '''
    PIX *a0 = pix_arg(b(in, 0));
    l_int32 w = 0, h = 0;
    if (!a0) return;
    if (!preqed_call("pixSetupByteProcessing")) return;
    if (lineptrs_pending) lept_free(lineptrs_pending);
    lineptrs_pending = pixSetupByteProcessing(a0, &w, &h);
    preqed_result("pixSetupByteProcessing", lineptrs_pending != NULL);  /* NULL on error (pix2.c) */
'''
CODE['pixCleanupByteProcessing'] = '''
    PIX *a0 = pix_arg(b(in, 0));
    l_ok r;
    if (!a0) return;
    if (!preqed_call("pixCleanupByteProcessing")) return;
    r = pixCleanupByteProcessing(a0, lineptrs_pending);
    preqed_result("pixCleanupByteProcessing", r == 0);
    if (r == 0) lineptrs_pending = NULL;   /* pix2.c:3508 frees it */
'''
CODE['startTimerNested'] = '''
    (void)in;
    if (!preqed_call("startTimerNested")) return;
    if (timer_pending) stopTimerNested(timer_pending);
    timer_pending = startTimerNested();
    preqed_result("startTimerNested", timer_pending != NULL);
'''
CODE['stopTimerNested'] = '''
    (void)in;
    if (!timer_pending) return;   /* utils1.c:1175 dereferences it */
    if (!preqed_call("stopTimerNested")) return;
    timer_elapsed = stopTimerNested(timer_pending);
    timer_pending = NULL;
    preqed_result("stopTimerNested", timer_elapsed >= 0.0f);
'''
CODE['l_amapCreate'] = '''
    l_int32 kt = b(in, 0) % 3 == 0 ? L_INT_TYPE : (b(in, 0) % 3 == 1 ? L_UINT_TYPE : L_FLOAT_TYPE);
    if (!preqed_call("l_amapCreate")) return;
    L_AMAP *r = l_amapCreate(kt);
    preqed_result("l_amapCreate", r != NULL);
    if (r) { s_amap[b(in, 0) % 3] = r; kt_amap[b(in, 0) % 3] = kt; }
'''
CODE['l_asetCreate'] = '''
    l_int32 kt = b(in, 0) % 3 == 0 ? L_INT_TYPE : (b(in, 0) % 3 == 1 ? L_UINT_TYPE : L_FLOAT_TYPE);
    if (!preqed_call("l_asetCreate")) return;
    L_ASET *r = l_asetCreate(kt);
    preqed_result("l_asetCreate", r != NULL);
    if (r) { s_aset[b(in, 0) % 3] = r; kt_aset[b(in, 0) % 3] = kt; }
'''
CODE['l_rbtreeCreate'] = '''
    l_int32 kt = b(in, 0) % 3 == 0 ? L_INT_TYPE : (b(in, 0) % 3 == 1 ? L_UINT_TYPE : L_FLOAT_TYPE);
    if (!preqed_call("l_rbtreeCreate")) return;
    L_RBTREE *r = l_rbtreeCreate(kt);
    preqed_result("l_rbtreeCreate", r != NULL);
    if (r) { s_rb[b(in, 0) % 3] = r; kt_rb[b(in, 0) % 3] = kt; }
'''

# --------------------------------------------------------------------------- #
# per-parameter classification and emission
# --------------------------------------------------------------------------- #


class P:
    def __init__(self, i, ctype, name):
        self.i = i
        self.ctype = ctype
        self.name = name
        self.kind = 'unknown'
        self.base = ctype.replace('const', '').replace('*', '').strip()
        self.stars = ctype.count('*')
        self.dir = ''
        self.decl = []
        self.arg = 'NULL'
        self.post = []
        self.obj = None
        self.sel = 'b(in, %d)' % i
        self.fail = 'return;'
        self.byref = False
        self.donate = False
        self.is_item = False
        self.str_donor = False


def classify(ps, doc):
    dirs, descs, _ret = docmeta(doc)
    out = []
    for i, (ctype, name) in enumerate(ps):
        p = P(i, ctype, name)
        p.dir = dirs.get(name, '')
        b, s = p.base, p.stars
        if name == '...' or ctype.strip() == '...':
            p.kind = 'varargs'
        elif '(' in ctype:
            p.kind = 'callback'
        elif b in OBJECTS:
            p.obj = OBJECTS[b]
            p.kind = 'objout' if s == 2 else 'obj'
        elif b in BORROW_T:
            p.kind = 'borrowobj'
        elif b == 'RB_TYPE':
            p.kind = 'rbtype'
        elif b == 'L_TIMER':
            p.kind = 'timer'
        elif b == 'FILE':
            p.kind = 'file'
        elif b == 'char':
            p.kind = 'scalar' if s == 0 else ('str' if s == 1 else ('starr' if s == 2 else 'unknown'))
        elif b in SCALARS:
            p.kind = 'scalar' if s == 0 else ('sptr' if s == 1 else ('sarrout' if s == 2 else 'unknown'))
        elif b == 'void':
            p.kind = 'voidptr' if s == 1 else 'unknown'
        else:
            p.kind = 'unknown'
        # NULL is allowed when the parameter doc says so: "[optional]", or any mention of null ("can be null",
        # "use null to ...", "usual 3 choices: null, ...", "either null or ..."), except "non-null"/"not null"
        desc = descs.get(name, '').lower()
        p.opt = '[optional]' in desc or (bool(re.search(r'(?<!non-)\bnull\b', desc)) and
                                         not re.search(r'(must|can|may|should) ?not be null', desc))
        # "null or equal to pixs" / "if not null, must == pixs": when not NULL it must be that argument;
        # unless another object is also allowed ("existing", "!= pixs", "or different from pixs")
        m = re.search(r'(?:equal to|==|same as)\s+(\w+)', desc)
        names = [q[1] for q in ps]
        p.alias = (names.index(m.group(1)) if m and p.opt and m.group(1) in names and m.group(1) != name and
                   not re.search(r'existing|!=|different', desc) else None)
        out.append(p)
    # a byte buffer takes its length from a later size parameter
    for p in out:
        p.sizeof = None
        if p.kind == 'sptr' and p.base == 'l_uint8':
            for q in out[p.i + 1:]:
                if q.kind == 'scalar' and q.base in ('size_t', 'l_int32', 'l_uint64') and q.name in SIZENAME:
                    p.sizeof = q
                    q.bound = p
                    break
    for p in out:
        if not hasattr(p, 'bound'):
            p.bound = None
    return out


def emit_param(p, notes):
    """Return C lines that declare p and set p.arg."""
    L = []
    if p.kind == 'obj':
        T = p.obj
        sel = p.sel
        if p.alias is not None:   # NULL, or the argument it must equal (set once all arguments exist)
            L.append('%s *a%d = NULL;' % (T.ctype, p.i))
        elif p.opt:
            L.append('%s *a%d = (b(in, %d) & 1) ? %s_arg(%s) : NULL;' % (T.ctype, p.i, p.i + 3, T.pref, sel))
        else:
            L.append('%s *a%d = %s_arg(%s);' % (T.ctype, p.i, T.pref, sel))
            if not T.make:
                L.append('if (!a%d) { %s }' % (p.i, p.fail))
        p.arg = 'a%d' % p.i
    elif p.kind == 'objout':
        T = p.obj
        # a callee that frees/replaces the held object gets the pool slot itself, whatever its doc says
        # about direction (some say [in], some nothing), unless the parameter is a documented [out]
        if p.dir != 'out' and getattr(p, 'byref', False):
            L.append('%s **a%d = %s_ref(%s);' % (T.ctype, p.i, T.pref, p.sel))
            p.arg = 'a%d' % p.i
        else:
            L.append('%s *o%d = NULL;' % (T.ctype, p.i))
            p.arg = '&o%d' % p.i
            if not getattr(p, 'borrow_out', False):
                p.post.append('if (o%d) %s_put(%s, o%d);' % (p.i, T.pref, p.sel, p.i))
    elif p.kind == 'borrowobj':
        L.append('%s *a%d = %s;' % (p.base, p.i, BORROW_T[p.base]))
        p.arg = 'a%d' % p.i
    elif p.kind == 'rbtype':
        L.append('RB_TYPE a%d = rbt(%s, in, %d);' % (p.i, notes['keytype'], p.i))
        p.arg = 'a%d' % p.i
    elif p.kind == 'timer':
        L.append('L_TIMER a%d;' % p.i)
        L.append('memset(&a%d, 0, sizeof a%d);' % (p.i, p.i))
        p.arg = 'a%d' % p.i
    elif p.kind == 'file':
        if notes['file_write']:
            L.append('char *fb%d = NULL;' % p.i)
            L.append('size_t ln%d = 0;' % p.i)
            L.append('FILE *a%d = fstream_w(&fb%d, &ln%d);' % (p.i, p.i, p.i))
            L.append('if (!a%d) { %s }' % (p.i, p.fail))
            p.post.append('fstream_w_done(a%d, &fb%d, &ln%d);' % (p.i, p.i, p.i))
        else:
            L.append('size_t bn%d = 0;' % p.i)
            L.append('FILE *a%d = fstream_r(in, %s, &bn%d);' % (p.i, p.sel, p.i))
            L.append('if (!a%d) { %s }' % (p.i, p.fail))
            if not notes.get('closes_stream'):   # lept_fclose closes the stream itself
                p.post.append('fclose(a%d);' % p.i)
        p.arg = 'a%d' % p.i
    elif p.kind == 'scalar':
        e = scalar_expr(p)
        L.append('%s a%d = (%s)%s;' % (p.base, p.i, p.base, e))
        p.arg = 'a%d' % p.i
    elif p.kind == 'sptr':
        elem = p.base
        if getattr(p, 'table', None) == 'NULL':
            L.append('%s *a%d = NULL;' % (elem, p.i))
        elif getattr(p, 'table', None):
            L.append('%s *a%d = %s;' % (elem, p.i, p.table))
            L.append('if (!a%d) { %s }' % (p.i, p.fail))
            p.post.append('lept_free(a%d);' % p.i)
        elif getattr(p, 'arr_donor', False):
            L.append('%s *a%d = (%s *)lept_calloc(INARR, sizeof(%s));' % (elem, p.i, elem, elem))
            L.append('if (!a%d) { %s }' % (p.i, p.fail))
        elif elem == 'l_uint8' and getattr(p, 'sizeof', None) is not None:
            L.append('size_t bn%d = 0;' % p.i)
            L.append('const u8 *a%d = blob(in, %s, &bn%d);' % (p.i, p.sel, p.i))
        elif elem == 'char':
            L.append('char *a%d = (char *)strv(in, %d);' % (p.i, p.i))
        elif p.dir == 'out':
            L.append('%s *a%d = (%s *)tmp_alloc(OUTARR * sizeof(%s));' % (elem, p.i, elem, elem))
            L.append('if (!a%d) { %s }' % (p.i, p.fail))
        else:
            L.append('%s *a%d = (%s *)tmp_alloc(INARR * sizeof(%s));' % (elem, p.i, elem, elem))
            L.append('if (!a%d) { %s }' % (p.i, p.fail))
        p.arg = 'a%d' % p.i
    elif p.kind == 'sarrout':
        elem = p.base
        if elem == 'char':
            L.append('char *o%d = NULL;' % p.i)
            p.arg = '&o%d' % p.i
            if not getattr(p, 'borrow', False):
                p.post.append('if (o%d) lept_free(o%d);' % (p.i, p.i))
        else:
            L.append('%s *o%d = NULL;' % (elem, p.i))
            p.arg = '&o%d' % p.i
            p.post.append('if (o%d) lept_free(o%d);' % (p.i, p.i))
    elif p.kind == 'str':
        if getattr(p, 'str_donor', False):
            L.append('char *a%d = strdv(in, %d);' % (p.i, p.i + 8))
            L.append('if (!a%d) { %s }' % (p.i, p.fail))
        elif 'const' in p.ctype:
            if p.name in FNAME:
                # two file parameters (filein/fileout, fname1/fname2) name two different files
                L.append('const char *a%d = %s;' % (p.i, 'FNAME2' if getattr(p, 'fname2', False) else 'FNAME'))
                if getattr(p, 'fname2', False):
                    p.post.append('unlink(FNAME2);')
            else:
                L.append('const char *a%d = strv(in, %d);' % (p.i, p.i + 8))
        else:
            L.append('char *a%d = (char *)strv(in, %d);' % (p.i, p.i + 8))
        p.arg = 'a%d' % p.i
    elif p.kind == 'starr':
        L.append('char *o%d = NULL;' % p.i)
        p.arg = '&o%d' % p.i
        if not getattr(p, 'borrow', False):
            p.post.append('if (o%d) lept_free(o%d);' % (p.i, p.i))
    elif p.kind == 'voidptr':
        if p.name == 'pval':
            # returnErrorPtr*(msg, procname, pval) hands pval back as its result:
            # it must not be a harness buffer, or the caller's lept_free() would
            # free it twice
            L.append('void *a%d = NULL;' % p.i)
        elif getattr(p, 'is_item', False):
            L.append('void *a%d = item_new();' % p.i)
            L.append('if (!a%d) { %s }' % (p.i, p.fail))
            p.donate = True
        else:
            L.append('void *a%d = tmp_alloc(INARR);' % p.i)
            L.append('if (!a%d) { %s }' % (p.i, p.fail))
        p.arg = 'a%d' % p.i
    elif p.kind == 'varargs':
        p.arg = 'NULL'
    elif p.kind == 'callback':
        L.append('void *a%d = NULL;' % p.i)
        p.arg = 'a%d' % p.i
    else:
        if p.stars >= 1:
            L.append('%s a%d = NULL;' % (p.ctype, p.i))
        else:
            L.append('%s a%d = 0;' % (p.ctype, p.i))
        p.arg = 'a%d' % p.i
    return L


def scalar_expr(p):
    n, b_ = p.name, p.base
    if n in DBG:
        return '0'
    if getattr(p, 'bound', None) is not None:
        return 'bn%d' % p.bound.i if p.base == 'size_t' else '(l_int32)bn%d' % p.bound.i
    if b_ == 'l_float32':
        return 'flt(in, %d)' % p.i
    if b_ == 'l_float64':
        return 'dbl(in, %d)' % p.i
    if b_ == 'l_uint32':
        return 'u32v(in, %d)' % p.i
    if b_ == 'l_uint64':
        return 'u64v(in, %d)' % p.i
    if b_ == 'size_t':
        return 'small(in, %d)' % p.i
    if n == 'spacing':
        # graphics.c:436 (generatePtaHashBox, reached from every pixRenderHash*)
        # computes n = 1 + boxheight/spacing and then divides by (n - 1)
        return '(l_int32)(1 + b(in, %d) %% 3)' % p.i
    if n in ('d', 'depth', 'depth1', 'outdepth', 'depth2'):
        return "depthv(in, %d)" % p.i
    if n in FLAGNAME:
        return 'L_COPY'
    if n in DIMNAME or n in SIZELIKE:
        return 'small(in, %d)' % p.i
    if n in ('hsize', 'vsize'):
        # brick/Sel sizes: morphdwa.c pads by 32 + (size / 64) * 32 per side on the >63
        # (Extend) path, so a 100000 brick builds 100032x100032 images; cap at 200
        return 'brickv(in, %d)' % p.i
    if n in FMTNAME:
        return 'enump(in, %d)' % p.i
    return 'sint(in, %d)' % p.i


def ok_expr(ret, retdoc):
    if ret == 'void':
        return None
    if '*' in ret:
        return 'r != NULL'
    if ret == 'l_ok':
        return 'r == 0'
    if retdoc.startswith('0 if OK') or retdoc.startswith('0 if ok'):
        return 'r == 0'
    # a documented error value: "0 on success, non-zero on failure" -> r == 0; "-1 on error", "1 on error",
    # "2 on error" -> r != that value. "0 on error" stays unknown: 0 is also a valid count there.
    low = retdoc.lower()
    if 'non-zero on failure' in low:
        return 'r == 0'
    m = re.search(r'(?<![\w.])(-?\d+) (?:on|if) (?:error|failure)', low)
    if m and m.group(1) != '0':
        return 'r != %s' % m.group(1)
    return '1'




def ok_locals(ret, retdoc, call, name):
    """Emit the call + success flag; returns (lines, has_r)."""
    L = []
    r = ret.strip()
    if r == 'void':
        L.append('    %s;' % call)
        L.append('    int okv = 1;')
        return L, False
    ok = SUCCESS.get(name) or ok_expr(r, retdoc)
    L.append('    %s r = %s;' % (r, call))
    L.append('    int okv = %s;' % ok)
    return L, True


def emit_wrapper(name, ret, ps, doc):
    if name in EXCLUDE:
        return None
    if name in CODE:
        head = ['static void call_%s(payload in) {' % name]
        tail = ['}']
        body = CODE[name].strip('\n').split('\n')
        return head + ['    ' + x if x.strip() else x for x in body] + tail
    _dirs, _descs, retdoc = docmeta(doc)
    write_side = bool(re.search(r'Write|write|print|Print|WStream|genData|CreateFromFile', name)) or \
        any(q[1] in ('fpout', 'fout') for q in ps)
    keytype = 'L_INT_TYPE'
    for i, q in enumerate(ps):
        bb = q[0].replace('const', '').replace('*', '').strip()
        if bb in ('L_AMAP', 'L_ASET', 'L_RBTREE'):
            arr = {'L_AMAP': 'kt_amap', 'L_ASET': 'kt_aset', 'L_RBTREE': 'kt_rb'}[bb]
            keytype = '%s[b(in, %d) %% 3]' % (arr, i)
            break
    notes = {'file_write': write_side, 'keytype': keytype, 'closes_stream': name == 'lept_fclose'}
    writename = any(q[1] in FNAME for q in ps)
    readname = writename
    donate = DONATE.get(name, set())
    plist = classify(ps, doc)
    for p in [q for q in plist if q.name in FNAME and q.kind == 'str'][1:]:
        p.fname2 = True
    # `T **` parameters are out-parameters unless the callee frees/replaces the
    # object we hold (a *Destroy, an in-place list mutator, a pix replacement) --
    # for those the slot itself must be passed, else the old object leaks or the
    # slot keeps a dangling pointer.
    byref = bool(re.search(r'Destroy|Free|TransferAllData|SwapAndDestroy|^list[A-Z]',
                           name)) or name in REF_EXTRA
    NONRES = ('obj', 'objout', 'borrowobj', 'scalar', 'rbtype', 'timer', 'varargs', 'callback',
              'str')
    for p in plist:
        p.byref = byref
        # a resource that cannot be made cancels the call, but the call event has
        # already been reported, so it must still produce a result event
        if p.kind not in NONRES or p.bound is not None:
            p.fail = 'preqed_result("%s", 0); return;' % name

    L = []
    if name in NOTE:
        L.append('/* %s */' % NOTE[name])
    L.append('static void call_%s(payload in) {' % name)
    pre, res = [], []
    prevsel = {}
    for p in plist:
        # a dllist is (head, tail): the tail pointer must be the same list as the
        # head, otherwise listAddToTail()/listRemoveFromTail() link two pool slots
        # to one node chain and both slots destroy it
        if p.kind == 'objout' and p.name == 'ptail' and p.base in prevsel:
            p.sel = prevsel[p.base]
        elif p.kind == 'objout':
            prevsel[p.base] = p.sel
        if p.name in donate:
            p.arg = 'a%d' % p.i
            p.donate = True
            res.append('%s *a%d = %s_make();' % (p.obj.ctype, p.i, p.obj.pref))
            res.append('if (!a%d) { %s }' % (p.i, p.fail))
            continue
        if p.name in DONATE_ARR.get(name, set()):
            p.arr_donor = True
            p.donate = True
        if p.name in DONATE_STR.get(name, set()):
            p.str_donor = True
            p.donate = True
        if p.name in DONATE_ITEMS and p.kind == 'voidptr':
            p.is_item = True
            p.donate = True
        elif p.kind == 'voidptr':
            p.is_item = bool(re.match(r'^(ptra|lstack|lqueue|lheap)', name)) or p.name == 'item'
        isres = (p.kind not in NONRES or p.bound is not None or
                 (p.kind == 'str' and p.str_donor))
        if name in BORROW_OUT:
            p.borrow = True
        if (name, p.name) in BORROW_OUTPARAM:
            p.borrow_out = True
        if p.kind == 'sptr' and p.dir != 'out' and 'tab' in p.name:
            p.table = 'NULL' if p.opt else TABLE.get((name, p.name))
        (res if isres else pre).extend(emit_param(p, notes))
    L.extend('    ' + d for d in pre)
    for p in plist:
        if p.kind == 'obj' and getattr(p, 'alias', None) is not None:
            L.append('    if (b(in, %d) & 1) a%d = a%d;' % (p.i + 3, p.i, p.alias))
    if name in SKIPIF:
        if 'bh0' in SKIPIF[name]:
            L.append('    l_int32 bh0 = 0;')
        if 'kx0' in SKIPIF[name]:
            L.append('    l_int32 kx0 = 0, ky0 = 0;')
        if 'kw0' in SKIPIF[name]:
            L.append('    l_int32 kw0 = 0, kh0 = 0;')
        L.append('    ' + SKIPIF[name])
    L.append('    if (!preqed_call("%s")) return;' % name)
    L.extend('    ' + d for d in res)
    for p in plist:
        key = MINS.get(name, {}).get(p.name)
        if key is not None and p.kind == 'scalar':
            L.append('    a%d = L_MAX(a%d, %d);' % (p.i, p.i, key))
        if name in MAXS and p.name in MAXS[name] and p.kind == 'scalar':
            L.append('    a%d = L_MAX(L_MIN(a%d, %d), 0);' % (p.i, p.i, MAXS[name][p.name]))
    if readname and not write_side:
        L.append('    file_prep(in);')
    if write_side and writename:
        L.append('    file_written = 1;')
    call = '%s(%s)' % (name, ', '.join(p.arg for p in plist))
    lines, has_r = ok_locals(ret.strip(), retdoc, call, name)
    L.extend(lines)
    # donated arguments are consumed only if the call succeeded
    for p in plist:
        if getattr(p, 'donate', False):
            if p.kind in ('voidptr', 'str', 'sptr'):
                L.append('    if (!okv) lept_free(%s);' % p.arg)
            else:
                L.append('    if (!okv) %s;' % p.obj.destroy(p.arg))
    # returned object / borrowed pointer
    r = ret.strip()
    if has_r and '*' in r:
        base = r.replace('const', '').replace('*', '').strip()
        if base in OBJECTS:
            if name in BORROW:
                L.append('    (void)r;')
            elif name in CLONE:   # a second reference: kept even when the pointer is already pooled
                L.append('    if (r) %s_putc(b(in, 1), r);' % OBJECTS[base].pref)
            else:
                L.append('    if (r) %s_put(b(in, 1), r);' % OBJECTS[base].pref)
        elif base in BORROW_T:
            L.append('    if (r) %s = r;' % BORROW_T[base])
        elif base == 'FILE':
            L.append('    if (r) fclose(r);')
        elif base in SCALARS or base == 'void':
            if name in BORROW or name.startswith('list'):
                # borrowed, or a dllist node payload the harness still owns
                L.append('    (void)r;')
            else:
                L.append('    lept_free(r);')
    # out-parameter stores, then stream closes / frees
    for p in plist:
        for s in p.post:
            L.append('    ' + s)
    L.append('    preqed_result("%s", okv);' % name)
    L.append('}')
    return L


# --------------------------------------------------------------------------- #
# file emission
# --------------------------------------------------------------------------- #

HEADER = r'''/* Generated by gen_harness.py -- do not edit.
 *
 * One libFuzzer harness for the whole public API of leptonica (see allheaders.h):
 * %(wrapped)d of the %(declared)d declared functions, %(excluded)d excluded (gen_harness.py
 * EXCLUDE, each with a reason).
 *
 * Record format:  u16 LE opcode | u16 LE payload length | payload
 *                 api[op %% API_COUNT](payload)
 * (the opcode is 16 bits because a single byte reaches only 256 of the %(wrapped)d wrappers)
 *
 * Ownership: one pool of K slots per object type holds pointers the harness owns and
 * destroys with the type's own destructor; returned objects and T** out-parameters go
 * into a slot, destroying its previous occupant.  Borrowed returns (a body that is
 * `return obj->field;`, or a doc block that says the result is owned by an argument)
 * are never stored.  A function that takes ownership of an argument object gets a
 * freshly made donor object instead of a pool slot.  L_INSERT/L_NOCOPY are never passed:
 * copyflag parameters always get L_COPY.
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "allheaders.h"
#include "preqed_ltl.h"

typedef unsigned char u8;
typedef struct { const u8 *p; size_t n; } payload;

'''


def helpers_c():
    return r'''
/* ---------------- payload decoding helpers ---------------- */

static u8 b(payload in, size_t i) { return i < in.n ? in.p[i] : 0; }

/* small non-negative scalar: dimensions, counts, indices */
static l_int32 small(payload in, size_t i) { return (l_int32)(b(in, i) % 17); }

/* brick sizes: both the composable (<= 63) and the extended (> 63) DWA paths, and the 63/64 boundary */
static l_int32 brickv(payload in, size_t i) {
    static const l_int32 v[] = { 0, 1, 2, 3, 5, 7, 15, 31, 63, 64, 65, 100, 127, 200, -1 };
    return v[b(in, i) % (sizeof v / sizeof v[0])];
}

/* concentrated signed scalar (thresholds, values, coordinates): small values, word/byte boundaries
   (8, 16, 32, 64, 255), negatives, and two large values that must hit range checks */
static l_int32 sint(payload in, size_t i) {
    static const l_int32 v[] = { 0, 1, 2, 3, 4, 5, 7, 8, 16, 32, 64, 255, -1, -2, 1000, 100000 };
    return v[b(in, i) % (sizeof v / sizeof v[0])];
}

/* the pixel depths leptonica supports */
static l_int32 depthv(payload in, size_t i) {
    static const l_int32 v[] = { 1, 2, 4, 8, 16, 32 };
    return v[b(in, i) % (sizeof v / sizeof v[0])];
}

/* enum/flag parameters: 0..23 covers every L_* enum used as an argument plus invalid values past its end */
static l_int32 enump(payload in, size_t i) { return (l_int32)(b(in, i) % 24); }

/* floats: 0, +-1, fractions, powers of two, and extremes (1e6, 1e30, -0.0) that reach overflow and
   division-by-zero handling */
static l_float32 flt(payload in, size_t i) {
    static const l_float32 v[] = { 0.0f, 1.0f, -1.0f, 0.5f, 2.0f, 4.0f, 8.0f, 0.25f, 1e-3f,
                                   1e6f, -8.0f, 3.5f, 1e30f, -0.0f, 100.0f, 0.1f };
    return v[b(in, i) % (sizeof v / sizeof v[0])];
}

static l_float64 dbl(payload in, size_t i) { return (l_float64)flt(in, i); }

static l_uint32 u32v(payload in, size_t i) {
    l_uint32 v = 0;
    int k;
    for (k = 0; k < 4; k++) v = (v << 8) | b(in, i + (size_t)k);
    return v;
}

static l_uint64 u64v(payload in, size_t i) {
    l_uint64 v = 0;
    int k;
    for (k = 0; k < 8; k++) v = (v << 8) | b(in, i + (size_t)k);
    return v;
}

static void handler_discard(const char *msg) { (void)msg; }

static RB_TYPE rbt(l_int32 keytype, payload in, size_t i) {
    RB_TYPE k;
    l_int32 v = sint(in, i);
    memset(&k, 0, sizeof k);
    if (keytype == L_FLOAT_TYPE) k.ftype = (l_float32)v / 4.0f;
    else if (keytype == L_UINT_TYPE) k.utype = (l_uint32)v;
    else k.itype = v;
    return k;
}

/* strings: printable, NUL-terminated, no path separator, capped */
#define NSP 8
static int sp_i;
static char sp[NSP][512];
static const char *strv(payload in, size_t off) {
    char *d = sp[sp_i++ % NSP];
    size_t n = in.n > off ? in.n - off : 0, i;
    if (n > sizeof sp[0] - 1) n = sizeof sp[0] - 1;
    for (i = 0; i < n; i++) {
        u8 c = in.p[off + i];
        d[i] = (c >= 0x20 && c < 0x7f && c != '/' && c != '.') ? (char)c : 'x';
    }
    d[n] = 0;
    return d;
}

/* heap copy of a payload string, for the callee that frees its argument */
static char *strdv(payload in, size_t off) {
    const char *s = strv(in, off);
    size_t n = strlen(s) + 1;
    char *d = (char *)lept_calloc(n, 1);
    if (d) memcpy(d, s, n);
    return d;
}

/* The single relative filename every path-taking function uses, so a writer's
   output is the next reader's input.  Removed by cleanup(). */
#define FNAME "leptfuzzed"
#define FNAME2 "leptfuzzed2"

/* Bytes the library wrote: *WriteMem out-parameters and every open_memstream.
   A reader's (data,size) pair can read this instead of the payload. */
#define WBUF_MAX (1 << 16)
static u8 wbuf[WBUF_MAX];
static size_t wbuf_n;
static void wbuf_add(const void *p, size_t n) {
    if (!p || wbuf_n >= WBUF_MAX) return;
    if (n > WBUF_MAX - wbuf_n) n = WBUF_MAX - wbuf_n;
    memcpy(wbuf + wbuf_n, p, n);
    wbuf_n += n;
}

/* byte source for a (data, size) pair: payload or what the library wrote.
   A zero-length buffer is never handed out: several readers document "size
   includes the terminating null", and bbufferCreate(indata, 0) copies its
   default 1024 bytes from indata (bbuffer.c:147). */
static const u8 empty1[1];
static const u8 *blob(payload in, int sel, size_t *pn) {
    if ((sel & 1) && wbuf_n) { *pn = wbuf_n; return wbuf; }
    if (!in.n) { *pn = 1; return empty1; }
    *pn = in.n > 8192 ? 8192 : in.n;
    return in.p;
}

static int file_written;   /* a write-side call already produced FNAME */

/* before a read-side call: if nothing has been written yet, let the reader see
   the payload, so file readers are reachable from the first record */
static void file_prep(payload in) {
    FILE *fp;
    if (file_written || wbuf_n) return;
    fp = fopen(FNAME, "wb");
    if (!fp) return;
    if (in.n) fwrite(in.p, 1, in.n, fp);
    fclose(fp);
}

/* temporary arrays: generous and zeroed, so an over-read is the library's.
   INARR/OUTARR are element counts; tmp_alloc takes bytes. */
#define INARR 8192
#define OUTARR 64
#define MAXTMP 24
static void *tmp[MAXTMP];
static int ntmp;
static void *tmp_alloc(size_t elems) {
    void *p;
    if (ntmp >= MAXTMP) return NULL;
    p = calloc(elems + 1, 1);
    if (!p) abort();
    tmp[ntmp++] = p;
    return p;
}
static void tmp_free(void) {
    while (ntmp > 0) free(tmp[--ntmp]);
    ntmp = 0;
    sp_i = 0;
}

/* FILE* parameters: readers see the payload or the collected buffer, writers
   get a memstream whose bytes join the collected buffer */
static FILE *fstream_w(char **pbuf, size_t *plen) {
    *pbuf = NULL;
    *plen = 0;
    return open_memstream(pbuf, plen);
}
static void fstream_w_done(FILE *fp, char **pbuf, size_t *plen) {
    char *buf;
    if (!fp) return;
    fclose(fp);                     /* memstream writes its final buffer back here */
    buf = *pbuf;
    if (buf) { wbuf_add(buf, *plen); free(buf); }
    *pbuf = NULL;
}
static FILE *fstream_r(payload in, int sel, size_t *pn) {
    size_t n;
    const u8 *d = blob(in, sel, &n);
    *pn = n;
    if (!n) return NULL;
    return fmemopen((void *)d, n, "rb");
}

/* roplow.c:2457-2468: in-place horizontal shear writes past the line once a band shift reaches the
   width; the largest shift is max(|yloc|, |h - 1 - yloc|) * |tan(radang)| (repro 25) */
static int hshear_ok(PIX *p, l_int32 yloc, l_float32 radang) {
    l_int32 w, h;
    double far;
    if (!p) return 1;
    pixGetDimensions(p, &w, &h, NULL);
    far = fmax(fabs((double)yloc), fabs((double)(h - 1 - yloc)));
    return far * fabs(tan((double)radang)) < (double)w - 1.0;
}

/* one heap item for the void* containers; lept_malloc'd because ptra/stack/
   queue/heap/dllist destroy their items with lept_free when the freeflag is set */
static void *item_new(void) {
    l_uint64 *p = (l_uint64 *)lept_calloc(1, sizeof(l_uint64));
    if (p) *p = 0;
    return p;
}
'''


def slots_c():
    L = ['/* ---------------- ownership pools ---------------- */']
    for ty in OBJECTS.values():
        L.append('static %s *s_%s[%d];' % (ty.ctype, ty.pref, ty.n))
    L.append('static L_TIMER timer_pending;   /* startTimerNested -> stopTimerNested */')
    L.append('static l_uint8 **lineptrs_pending;  /* pixSetupByteProcessing -> pixCleanupByteProcessing */')
    L.append('static l_float32 timer_elapsed;   /* its result, reported by stopTimerNested */')
    for arr in ('kt_amap', 'kt_aset', 'kt_rb'):
        L.append('static l_int32 %s[3] = { L_INT_TYPE, L_INT_TYPE, L_INT_TYPE };' % arr)
    for tname, var in BORROW_T.items():
        L.append('static %s *%s;' % (tname, var))
    L.append('')
    L.append('static void borrow_invalidate(void) {')
    for var in BORROW_T.values():
        L.append('    %s = NULL;' % var)
    L.append('}')
    L.append('')
    for ty in OBJECTS.values():
        P_ = ty.pref
        if ty.ctype in MAKECODE:   # MAKECODE is keyed by C type
            L.append('static %s *%s_make(void) {' % (ty.ctype, P_))
            L.extend(MAKECODE[ty.ctype].splitlines())
            L.append('}')
        elif ty.make:
            L.append('static %s *%s_make(void) { return %s; }' % (ty.ctype, P_, ty.make))
        else:
            L.append('static %s *%s_make(void) { return NULL; }' % (ty.ctype, P_))
        L.append('static %s *%s_arg(l_int32 sel) {' % (ty.ctype, P_))
        L.append('    l_int32 k = sel %% %d;' % ty.n)
        L.append('    if (!s_%s[k]) s_%s[k] = %s_make();' % (P_, P_, P_))
        L.append('    return s_%s[k];' % P_)
        L.append('}')
        L.append('static %s **%s_ref(l_int32 sel) {' % (ty.ctype, P_))
        L.append('    l_int32 k = sel %% %d;' % ty.n)
        L.append('    if (!s_%s[k]) s_%s[k] = %s_make();' % (P_, P_, P_))
        L.append('    return &s_%s[k];' % P_)
        L.append('}')
        L.append('static void %s_put(l_int32 sel, %s *o) {' % (P_, ty.ctype))
        L.append('    l_int32 k = sel %% %d, i;' % ty.n)
        L.append('    borrow_invalidate();')
        L.append('    /* a function that returns an argument (pixd, boxad, ...) hands back an')
        L.append('       object the pool already owns, with no new reference */')
        L.append('    for (i = 0; i < %d; i++) if (s_%s[i] == o) return;' % (ty.n, P_))
        L.append('    if (s_%s[k]) %s;' % (P_, ty.destroy('s_%s[k]' % P_)))
        L.append('    s_%s[k] = o;' % P_)
        L.append('}')
        L.append('/* a *Clone() result is a real second reference: store it even if the')
        L.append('   pointer is already in the pool */')
        L.append('static void %s_putc(l_int32 sel, %s *o) {' % (P_, ty.ctype))
        L.append('    l_int32 k = sel %% %d;' % ty.n)
        L.append('    borrow_invalidate();')
        L.append('    if (s_%s[k]) %s;' % (P_, ty.destroy('s_%s[k]' % P_)))
        L.append('    s_%s[k] = o;' % P_)
        L.append('}')
        L.append('static void %s_drop(l_int32 sel) {' % P_)
        L.append('    l_int32 k = sel %% %d;' % ty.n)
        L.append('    borrow_invalidate();')
        L.append('    if (s_%s[k]) %s;' % (P_, ty.destroy('s_%s[k]' % P_)))
        L.append('}')
        L.append('static void %s_clear(void) {' % P_)
        L.append('    l_int32 k;')
        L.append('    for (k = 0; k < %d; k++) if (s_%s[k]) %s;' %
                 (ty.n, P_, ty.destroy('s_%s[k]' % P_)))
        L.append('}')
        if ty.capcode:
            L.append('static void %s_trim(void) {' % P_)
            L.append('    l_int32 k;')
            L.append('    for (k = 0; k < %d; k++) {' % ty.n)
            L.append('        %s *o = s_%s[k];' % (ty.ctype, P_))
            L.append('        if (!o) continue;')
            L.extend(ty.capcode.splitlines())
            L.append('    }')
            L.append('}')
        elif ty.cap:
            L.append('static void %s_trim(void) {' % P_)
            L.append('    l_int32 k;')
            L.append('    for (k = 0; k < %d; k++) {' % ty.n)
            L.append('        %s *o = s_%s[k];' % (ty.ctype, P_))
            L.append('        if (o && (%s)) %s;' % (ty.cap, ty.destroy('s_%s[k]' % P_)))
            L.append('    }')
            L.append('}')
        else:
            L.append('static void %s_trim(void) {}' % P_)
        L.append('')
    return L


def emit_all(funcs, docs, files, lines):
    wrapped, excluded = [], {}
    wrappers = []
    for name, ret, ps in funcs:
        doc = docs.get(name, '')
        w = emit_wrapper(name, ret, ps, doc)
        if w is None:
            excluded[name] = EXCLUDE.get(name, 'unparsed')
            continue
        wrapped.append(name)
        wrappers.append('\n'.join(w))
    L = [HEADER % {'wrapped': len(wrapped), 'declared': len(funcs),
                   'excluded': len(funcs) - len(wrapped)}]
    L.append(helpers_c())
    L.extend(slots_c())
    L.append('/* ---------------- one wrapper per wrapped function ---------------- */')
    L.append('\n\n'.join(wrappers))
    L.append('')
    L.append('static void (*const api[])(payload) = {')
    for i in range(0, len(wrapped), 3):
        L.append('    ' + ' '.join('call_%s,' % n for n in wrapped[i:i + 3]))
    L.append('};')
    L.append('')
    L.append('#define API_COUNT (sizeof api / sizeof api[0])')
    L.append('')
    L.append('/* after each record: destroy pooled objects over their size cap (a 2 Mpx image, a 128-entry pixa, ...;')
    L.append('   the *_trim functions above, listed in NOTES.md leptonica "Caps") so records stay fast and memory bounded */')
    L.append('static void trim_all(void) {')
    for t in OBJECTS.values():
        L.append('    %s_trim();' % t.pref)
    L.append('}')
    L.append('')
    L.append('static void cleanup(void) {')
    for t in OBJECTS.values():
        L.append('    %s_clear();' % t.pref)
    L.append('    tmp_free();')
    L.append('    borrow_invalidate();')
    L.append('    wbuf_n = 0;')
    L.append('    if (timer_pending) stopTimerNested(timer_pending);')
    L.append('    timer_pending = NULL;')
    L.append('    if (lineptrs_pending) lept_free(lineptrs_pending);')
    L.append('    lineptrs_pending = NULL;')
    L.append('    unlink(FNAME);')
    L.append('    unlink(FNAME2);')
    L.append('    file_written = 0;')
    L.append('    setMsgSeverity(L_SEVERITY_NONE);')
    L.append('}')
    L.append('')
    L.append('''int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    /* the harness owns the message stream: L_WARNING/L_ERROR inside a fuzz target
       would otherwise print for every failing call */
    setMsgSeverity(L_SEVERITY_NONE);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    size_t off = 0;
    preqed_reset();
    while (size - off >= 4) {
        unsigned op = (unsigned)data[off] | (unsigned)data[off + 1] << 8;
        size_t len = (size_t)data[off + 2] | (size_t)data[off + 3] << 8;
        off += 4;
        if (len > size - off) break;
        payload in = { data + off, len };
        api[op % API_COUNT](in);
        off += len;
        trim_all();
    }
    cleanup();
    return 0;
}''')
    return '\n'.join(L) + '\n', wrapped, excluded


def emit_seeds(path, wrapped, funcs, src, docs):
    """One record per upstream corpus image: pixReadMem(image bytes)."""
    import zipfile
    os.makedirs(path, exist_ok=True)
    if 'pixReadMem' not in wrapped:
        raise SystemExit('pixReadMem not wrapped')
    idx = wrapped.index('pixReadMem')
    n = 0
    zips = []
    fz = os.path.join(src, '..', 'prog', 'fuzzing')
    for z in ('general_corpus.zip', 'barcode_fuzzer_seed_corpus.zip',
              'pixa_recog_fuzzer_seed_corpus.zip'):
        p = os.path.normpath(os.path.join(fz, z))
        if os.path.exists(p):
            zips.append(p)
    for z in zips:
        with zipfile.ZipFile(z) as zf:
            for name in zf.namelist():
                d = zf.read(name)
                if not d or len(d) > 60000:
                    continue
                rec = bytes([idx & 0xff, (idx >> 8) & 0xff, len(d) & 0xff, (len(d) >> 8) & 0xff]) + d
                open(os.path.join(path, 'seed-%04d-%s' % (n, re.sub(r'\W+', '_', name)[-40:])),
                     'wb').write(rec)
                n += 1
    print('seeds: %d records from %d corpora' % (n, len(zips)), file=sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--src', default='/src')
    ap.add_argument('--out', default='harness.c')
    ap.add_argument('--seeds', default=None)
    ap.add_argument('--report', default=None)
    a = ap.parse_args()
    src = a.src
    if os.path.isdir(os.path.join(src, 'src')):
        src = os.path.join(src, 'src')
    funcs, docs, files, lines, bodies = load(src)
    text, wrapped, excluded = emit_all(funcs, docs, files, lines)
    if a.report:
        # exclusion categories
        cats = {}
        for n, why in excluded.items():
            cats.setdefault(why, []).append(n)
        rep = {'declared': len(funcs), 'wrapped': len(wrapped), 'excluded': len(excluded),
               'categories': {k: v for k, v in sorted(cats.items(), key=lambda kv: -len(kv[1]))},
               'wrapped_names': wrapped}
        open(a.report, 'w').write(json.dumps(rep, indent=1))
        for k, v in rep['categories'].items():
            print('%4d  %s' % (len(v), k[:110]), file=sys.stderr)
    if a.seeds:
        emit_seeds(a.seeds, wrapped, funcs, src, docs)
    if a.out != '-':
        open(a.out, 'w').write(text)
        print('wrote %s: %d wrappers, %d excluded' % (a.out, len(wrapped), len(excluded)),
              file=sys.stderr)


if __name__ == '__main__':
    main()
