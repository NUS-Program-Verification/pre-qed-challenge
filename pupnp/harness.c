#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <ixml.h>
#include <upnp.h>
#include <upnptools.h>
#include <UpnpString.h>
#include <UpnpExtraHeaders.h>
#include <list.h>
#include "preqed_ltl.h"

#define FILE_PATH "pupnp-harness.xml"

typedef struct {
    const uint8_t *p;
    size_t n;
} payload;

static IXML_Document *doc;    /* owned document, the live tree */
static IXML_Document *action; /* owned action/propertyset document from the upnptools helpers */
static IXML_Node *loose;      /* owned node outside the tree */
static IXML_Node *node;       /* borrowed pointer into doc */
static DOMString str;         /* owned DOMString from print/render/clone */
static IXML_NodeList *list;   /* owned node list */
static IXML_NamedNodeMap *map;
static UpnpString *ustr, *ustr2;
static UpnpListHead head;
/* the intrusive list: 8 element nodes owned by the harness, each in the list at most once */
static UpnpListHead elts[8];
static unsigned char elts_used[8];
/* distinct addresses to use as opaque ixml user tags (only compared, never dereferenced) */
static unsigned char tag_slots[256];

/* NUL-terminated copies of payload fields: an XML document, six short names/values, and a URL */
static char xml[4096], s1[512], s2[512], s3[512], s4[512], s5[512], s6[512], url[4096];

static uint8_t byte(payload in, size_t i) { return i < in.n ? in.p[i] : 0; }
static payload rest(payload in, size_t skip) {
    payload r = { in.p + (skip < in.n ? skip : in.n), in.n > skip ? in.n - skip : 0 };
    return r;
}

/* NUL-separated field `which` of the payload, copied into dst */
static const char *field(char *dst, size_t cap, payload in, unsigned which) {
    size_t i = 0, n = 0;
    while (which--) {
        while (i < in.n && in.p[i]) i++;
        if (i < in.n) i++;
    }
    if (i > in.n) i = in.n;
    while (i + n < in.n && in.p[i + n]) n++;
    if (n > cap - 1) n = cap - 1;
    memcpy(dst, in.p + i, n);
    dst[n] = 0;
    return dst;
}

static IXML_Node *doc_root(void) { return doc ? doc->n.firstChild : NULL; }
static IXML_Element *root_el(void) {
    IXML_Node *r = doc_root();
    return r && r->nodeType == eELEMENT_NODE ? (IXML_Element *)r : NULL;
}
static IXML_Attr *pick_attr(IXML_Element *el, size_t k) {
    IXML_Node *a = el->n.firstAttr;
    while (a && k--) a = a->nextSibling;
    return (IXML_Attr *)a;
}

/* releasing a slot that is about to be overwritten is bookkeeping, not a fuzzed operation */
static void set_loose(IXML_Node *n) {
    if (loose && loose != n) ixmlNode_free(loose);
    loose = n;
}
static void drop_views(void) {
    if (list) ixmlNodeList_free(list);
    if (map) ixmlNamedNodeMap_free(map);
    list = NULL;
    map = NULL;
}
/* the tree changed shape: borrowed pointers and views into it are stale */
static void tree_mutated(void) {
    node = NULL;
    drop_views();
}

#define REPORT(api, expr, ok_cond) \
    do { \
        if (preqed_call(#api)) { \
            int rc = (expr); \
            preqed_result(#api, (ok_cond)); \
        } \
    } while (0)
#define REPORT_VOID(api, expr) \
    do { \
        if (preqed_call(#api)) { \
            expr; \
            preqed_result(#api, 1); \
        } \
    } while (0)
#define REPORT_NODE(api, expr) \
    do { \
        if (preqed_call(#api)) { \
            IXML_Node *r = (expr); \
            preqed_result(#api, r != NULL); \
            if (r) node = r; \
        } \
    } while (0)

/* node getters and mutators */
/* ltl: borrowed_node_validity */
static void call_ixmlNode_getNodeName(payload in) {
    (void)in;
    if (!node) return;
    if (!preqed_call("ixmlNode_getNodeName")) return;
    preqed_result("ixmlNode_getNodeName", ixmlNode_getNodeName(node) != NULL);
}
/* ltl: borrowed_node_validity */
static void call_ixmlNode_getNodeValue(payload in) {
    (void)in;
    if (!node) return;
    if (!preqed_call("ixmlNode_getNodeValue")) return;
    preqed_result("ixmlNode_getNodeValue", ixmlNode_getNodeValue(node) != NULL);
}
/* ltl: borrowed_node_validity */
static void call_ixmlNode_setNodeValue(payload in) {
    if (!node) return;
    REPORT(ixmlNode_setNodeValue, ixmlNode_setNodeValue(node, field(s1, sizeof s1, in, 0)), rc == IXML_SUCCESS);
}
/* ltl: borrowed_node_validity */
static void call_ixmlNode_getNodeType(payload in) {
    (void)in;
    if (!node) return;
    REPORT_VOID(ixmlNode_getNodeType, ixmlNode_getNodeType(node));
}
/* ltl: borrowed_node_validity */
static void call_ixmlNode_getParentNode(payload in) {
    (void)in;
    if (!node) return;
    REPORT_NODE(ixmlNode_getParentNode, ixmlNode_getParentNode(node));
}
/* ltl: borrowed_node_validity */
static void call_ixmlNode_getChildNodes(payload in) {
    (void)in;
    if (!node) return;
    if (!preqed_call("ixmlNode_getChildNodes")) return;
    IXML_NodeList *r = ixmlNode_getChildNodes(node);
    preqed_result("ixmlNode_getChildNodes", r != NULL);
    drop_views();
    list = r;
}
/* ltl: borrowed_node_validity */
static void call_ixmlNode_getFirstChild(payload in) {
    (void)in;
    if (!node) return;
    REPORT_NODE(ixmlNode_getFirstChild, ixmlNode_getFirstChild(node));
}
/* ltl: borrowed_node_validity */
static void call_ixmlNode_getLastChild(payload in) {
    (void)in;
    if (!node) return;
    REPORT_NODE(ixmlNode_getLastChild, ixmlNode_getLastChild(node));
}
/* ltl: borrowed_node_validity */
static void call_ixmlNode_getPreviousSibling(payload in) {
    (void)in;
    if (!node) return;
    REPORT_NODE(ixmlNode_getPreviousSibling, ixmlNode_getPreviousSibling(node));
}
/* ltl: borrowed_node_validity */
static void call_ixmlNode_getNextSibling(payload in) {
    (void)in;
    if (!node) return;
    REPORT_NODE(ixmlNode_getNextSibling, ixmlNode_getNextSibling(node));
}
/* ltl: borrowed_node_validity */
static void call_ixmlNode_getAttributes(payload in) {
    (void)in;
    if (!node) return;
    if (!preqed_call("ixmlNode_getAttributes")) return;
    IXML_NamedNodeMap *r = ixmlNode_getAttributes(node);
    preqed_result("ixmlNode_getAttributes", r != NULL);
    drop_views();
    map = r;
}
/* ltl: borrowed_node_validity */
static void call_ixmlNode_getOwnerDocument(payload in) {
    (void)in;
    if (!node) return;
    REPORT_VOID(ixmlNode_getOwnerDocument, ixmlNode_getOwnerDocument(node));
}
/* ltl: borrowed_node_validity */
static void call_ixmlNode_getNamespaceURI(payload in) {
    (void)in;
    if (!node) return;
    REPORT_VOID(ixmlNode_getNamespaceURI, ixmlNode_getNamespaceURI(node));
}
/* ltl: borrowed_node_validity */
static void call_ixmlNode_getPrefix(payload in) {
    (void)in;
    if (!node) return;
    REPORT_VOID(ixmlNode_getPrefix, ixmlNode_getPrefix(node));
}
/* ltl: borrowed_node_validity */
static void call_ixmlNode_getLocalName(payload in) {
    (void)in;
    if (!node) return;
    REPORT_VOID(ixmlNode_getLocalName, ixmlNode_getLocalName(node));
}

/* node.c:570 passes refChild to ixmlNode_isParent(), which asserts refChild != NULL, before the branch
 * that treats NULL as "append" (ixml.h documents NULL as append). Only real children are passed here. */
/* the document node is a stable tree handle: it is used as the parent while no node is borrowed */
/* ltl: detached_node_ownership */
static void call_ixmlNode_insertBefore(payload in) {
    (void)in;
    IXML_Node *parent = node ? node : (IXML_Node *)doc;
    if (!parent || !loose) return;
    IXML_Node *child = loose;
    IXML_Node *ref = ixmlNode_getFirstChild(parent);
    if (!ref) return;
    tree_mutated();
    if (!preqed_call("ixmlNode_insertBefore")) return;
    int rc = ixmlNode_insertBefore(parent, child, ref);
    preqed_result("ixmlNode_insertBefore", rc == IXML_SUCCESS);
    if (rc == IXML_SUCCESS) loose = NULL;
}
/* ltl: detached_node_ownership */
static void call_ixmlNode_replaceChild(payload in) {
    (void)in;
    IXML_Node *parent = node ? node : (IXML_Node *)doc;
    if (!parent || !loose) return;
    IXML_Node *child = loose;
    IXML_Node *old = ixmlNode_getFirstChild(parent);
    if (!old) return;
    IXML_Node *out = NULL;
    tree_mutated();
    if (!preqed_call("ixmlNode_replaceChild")) return;
    int rc = ixmlNode_replaceChild(parent, child, old, &out);
    preqed_result("ixmlNode_replaceChild", rc == IXML_SUCCESS && out != NULL);
    if (rc == IXML_SUCCESS) {
        loose = NULL;
        if (out) set_loose(out);
    }
}
/* ltl: detached_node_ownership */
static void call_ixmlNode_removeChild(payload in) {
    (void)in;
    IXML_Node *parent = node ? node : (IXML_Node *)doc;
    if (!parent) return;
    IXML_Node *old = ixmlNode_getFirstChild(parent);
    if (!old) return;
    IXML_Node *out = NULL;
    tree_mutated();
    if (!preqed_call("ixmlNode_removeChild")) return;
    int rc = ixmlNode_removeChild(parent, old, &out);
    preqed_result("ixmlNode_removeChild", rc == IXML_SUCCESS && out == old);
    if (out) set_loose(out);
}
/* ltl: detached_node_ownership */
static void call_ixmlNode_appendChild(payload in) {
    (void)in;
    IXML_Node *parent = node ? node : (IXML_Node *)doc;
    if (!parent || !loose) return;
    IXML_Node *child = loose;
    tree_mutated();
    if (!preqed_call("ixmlNode_appendChild")) return;
    int rc = ixmlNode_appendChild(parent, child);
    preqed_result("ixmlNode_appendChild", rc == IXML_SUCCESS);
    if (rc == IXML_SUCCESS) loose = NULL;
}
/* ltl: borrowed_node_validity */
static void call_ixmlNode_hasChildNodes(payload in) {
    (void)in;
    if (!node) return;
    REPORT_VOID(ixmlNode_hasChildNodes, ixmlNode_hasChildNodes(node));
}
/* ltl: borrowed_node_validity, detached_node_ownership */
static void call_ixmlNode_cloneNode(payload in) {
    if (!node) return;
    if (!preqed_call("ixmlNode_cloneNode")) return;
    IXML_Node *r = ixmlNode_cloneNode(node, byte(in, 0) & 1);
    preqed_result("ixmlNode_cloneNode", r != NULL);
    if (r) set_loose(r);
}
/* ltl: borrowed_node_validity */
static void call_ixmlNode_hasAttributes(payload in) {
    (void)in;
    if (!node) return;
    REPORT_VOID(ixmlNode_hasAttributes, ixmlNode_hasAttributes(node));
}
/* ltl: detached_node_ownership */
static void call_ixmlNode_free(payload in) {
    (void)in;
    if (!loose) return;
    IXML_Node *n = loose;
    loose = NULL;
    REPORT_VOID(ixmlNode_free, ixmlNode_free(n));
}

#ifdef IXML_HAVE_SCRIPTSUPPORT
static void call_ixmlNode_setCTag(payload in) {
    if (!node) return;
    void *tag = &tag_slots[byte(in, 0)];
    REPORT_VOID(ixmlNode_setCTag, ixmlNode_setCTag(node, tag));
}

static void call_ixmlNode_getCTag(payload in) {
    (void)in;
    if (!node) return;
    REPORT_VOID(ixmlNode_getCTag, ixmlNode_getCTag(node));
}
#endif

/* attr and cdata */
/* ltl: detached_node_ownership */
static void call_ixmlAttr_free(payload in) {
    (void)in;
    if (!loose || loose->nodeType != eATTRIBUTE_NODE) return;
    IXML_Node *n = loose;
    loose = NULL;
    REPORT_VOID(ixmlAttr_free, ixmlAttr_free((IXML_Attr *)n));
}
/* ltl: detached_node_ownership */
static void call_ixmlCDATASection_free(payload in) {
    (void)in;
    if (!loose || loose->nodeType != eCDATA_SECTION_NODE) return;
    IXML_Node *n = loose;
    loose = NULL;
    REPORT_VOID(ixmlCDATASection_free, ixmlCDATASection_free((IXML_CDATASection *)n));
}

/* document */
/* ltl: document_lifecycle */
static void call_ixmlDocument_createDocumentEx(payload in) {
    (void)in;
    if (doc) return;
    IXML_Document *d = NULL;
    if (!preqed_call("ixmlDocument_createDocumentEx")) return;
    int rc = ixmlDocument_createDocumentEx(&d);
    preqed_result("ixmlDocument_createDocumentEx", rc == IXML_SUCCESS && d != NULL);
    doc = d;
}
/* ltl: document_lifecycle */
static void call_ixmlDocument_createDocument(payload in) {
    (void)in;
    if (doc) return;
    if (!preqed_call("ixmlDocument_createDocument")) return;
    doc = ixmlDocument_createDocument();
    preqed_result("ixmlDocument_createDocument", doc != NULL);
}
/* ltl: document_lifecycle, detached_node_ownership */
static void call_ixmlDocument_createElementEx(payload in) {
    if (!doc) return;
    IXML_Element *el = NULL;
    if (!preqed_call("ixmlDocument_createElementEx")) return;
    int rc = ixmlDocument_createElementEx(doc, field(s1, sizeof s1, in, 0), &el);
    preqed_result("ixmlDocument_createElementEx", rc == IXML_SUCCESS && el != NULL);
    if (el) set_loose((IXML_Node *)el);
}
/* ltl: document_lifecycle, detached_node_ownership */
static void call_ixmlDocument_createElement(payload in) {
    if (!doc) return;
    if (!preqed_call("ixmlDocument_createElement")) return;
    IXML_Element *el = ixmlDocument_createElement(doc, field(s1, sizeof s1, in, 0));
    preqed_result("ixmlDocument_createElement", el != NULL);
    if (el) set_loose((IXML_Node *)el);
}
/* ltl: document_lifecycle, detached_node_ownership */
static void call_ixmlDocument_createTextNodeEx(payload in) {
    if (!doc) return;
    IXML_Node *n = NULL;
    if (!preqed_call("ixmlDocument_createTextNodeEx")) return;
    int rc = ixmlDocument_createTextNodeEx(doc, field(s1, sizeof s1, in, 0), &n);
    preqed_result("ixmlDocument_createTextNodeEx", rc == IXML_SUCCESS && n != NULL);
    if (n) set_loose(n);
}
/* ltl: document_lifecycle, detached_node_ownership */
static void call_ixmlDocument_createTextNode(payload in) {
    if (!doc) return;
    if (!preqed_call("ixmlDocument_createTextNode")) return;
    IXML_Node *n = ixmlDocument_createTextNode(doc, field(s1, sizeof s1, in, 0));
    preqed_result("ixmlDocument_createTextNode", n != NULL);
    if (n) set_loose(n);
}
/* ltl: document_lifecycle, detached_node_ownership */
static void call_ixmlDocument_createCDATASectionEx(payload in) {
    if (!doc) return;
    IXML_CDATASection *n = NULL;
    if (!preqed_call("ixmlDocument_createCDATASectionEx")) return;
    int rc = ixmlDocument_createCDATASectionEx(doc, field(s1, sizeof s1, in, 0), &n);
    preqed_result("ixmlDocument_createCDATASectionEx", rc == IXML_SUCCESS && n != NULL);
    if (n) set_loose((IXML_Node *)n);
}
/* ltl: document_lifecycle, detached_node_ownership */
static void call_ixmlDocument_createCDATASection(payload in) {
    if (!doc) return;
    if (!preqed_call("ixmlDocument_createCDATASection")) return;
    IXML_CDATASection *n = ixmlDocument_createCDATASection(doc, field(s1, sizeof s1, in, 0));
    preqed_result("ixmlDocument_createCDATASection", n != NULL);
    if (n) set_loose((IXML_Node *)n);
}
/* ltl: document_lifecycle, detached_node_ownership */
static void call_ixmlDocument_createAttribute(payload in) {
    if (!doc) return;
    if (!preqed_call("ixmlDocument_createAttribute")) return;
    IXML_Attr *a = ixmlDocument_createAttribute(doc, field(s1, sizeof s1, in, 0));
    preqed_result("ixmlDocument_createAttribute", a != NULL);
    if (a) set_loose((IXML_Node *)a);
}
/* ltl: document_lifecycle, detached_node_ownership */
static void call_ixmlDocument_createAttributeEx(payload in) {
    if (!doc) return;
    IXML_Attr *a = NULL;
    if (!preqed_call("ixmlDocument_createAttributeEx")) return;
    int rc = ixmlDocument_createAttributeEx(doc, field(s1, sizeof s1, in, 0), &a);
    preqed_result("ixmlDocument_createAttributeEx", rc == IXML_SUCCESS && a != NULL);
    if (a) set_loose((IXML_Node *)a);
}
/* ltl: document_lifecycle, detached_node_ownership */
static void call_ixmlDocument_createElementNSEx(payload in) {
    if (!doc) return;
    IXML_Element *el = NULL;
    if (!preqed_call("ixmlDocument_createElementNSEx")) return;
    int rc = ixmlDocument_createElementNSEx(doc, field(s1, sizeof s1, in, 0), field(s2, sizeof s2, in, 1), &el);
    preqed_result("ixmlDocument_createElementNSEx", rc == IXML_SUCCESS && el != NULL);
    if (el) set_loose((IXML_Node *)el);
}
/* ltl: document_lifecycle, detached_node_ownership */
static void call_ixmlDocument_createElementNS(payload in) {
    if (!doc) return;
    if (!preqed_call("ixmlDocument_createElementNS")) return;
    IXML_Element *el = ixmlDocument_createElementNS(doc, field(s1, sizeof s1, in, 0), field(s2, sizeof s2, in, 1));
    preqed_result("ixmlDocument_createElementNS", el != NULL);
    if (el) set_loose((IXML_Node *)el);
}
/* ltl: document_lifecycle, detached_node_ownership */
static void call_ixmlDocument_createAttributeNSEx(payload in) {
    if (!doc) return;
    IXML_Attr *a = NULL;
    if (!preqed_call("ixmlDocument_createAttributeNSEx")) return;
    int rc = ixmlDocument_createAttributeNSEx(doc, field(s1, sizeof s1, in, 0), field(s2, sizeof s2, in, 1), &a);
    preqed_result("ixmlDocument_createAttributeNSEx", rc == IXML_SUCCESS && a != NULL);
    if (a) set_loose((IXML_Node *)a);
}
/* ltl: document_lifecycle, detached_node_ownership */
static void call_ixmlDocument_createAttributeNS(payload in) {
    if (!doc) return;
    if (!preqed_call("ixmlDocument_createAttributeNS")) return;
    IXML_Attr *a = ixmlDocument_createAttributeNS(doc, field(s1, sizeof s1, in, 0), field(s2, sizeof s2, in, 1));
    preqed_result("ixmlDocument_createAttributeNS", a != NULL);
    if (a) set_loose((IXML_Node *)a);
}
/* ltl: document_lifecycle */
static void call_ixmlDocument_getElementsByTagName(payload in) {
    if (!doc) return;
    if (!preqed_call("ixmlDocument_getElementsByTagName")) return;
    IXML_NodeList *l = ixmlDocument_getElementsByTagName(doc, field(s1, sizeof s1, in, 0));
    preqed_result("ixmlDocument_getElementsByTagName", l != NULL);
    drop_views();
    list = l;
}
/* ltl: document_lifecycle */
static void call_ixmlDocument_getElementsByTagNameNS(payload in) {
    if (!doc) return;
    if (!preqed_call("ixmlDocument_getElementsByTagNameNS")) return;
    IXML_NodeList *l = ixmlDocument_getElementsByTagNameNS(doc, field(s1, sizeof s1, in, 0), field(s2, sizeof s2, in, 1));
    preqed_result("ixmlDocument_getElementsByTagNameNS", l != NULL);
    drop_views();
    list = l;
}
/* ltl: document_lifecycle, borrowed_node_validity */
static void call_ixmlDocument_getElementById(payload in) {
    if (!doc) return;
    REPORT_NODE(ixmlDocument_getElementById, (IXML_Node *)ixmlDocument_getElementById(doc, field(s1, sizeof s1, in, 0)));
}

/* a detached node keeps its ownerDocument; freeing the document first leaves it dangling */
/* ltl: document_lifecycle */
static void call_ixmlDocument_free(payload in) {
    (void)in;
    if (!doc || (loose && loose->ownerDocument == doc)) return;
    IXML_Document *d = doc;
    tree_mutated();
    doc = NULL;
    REPORT_VOID(ixmlDocument_free, ixmlDocument_free(d));
}
/* ltl: document_lifecycle, borrowed_node_validity, detached_node_ownership */
static void call_ixmlDocument_importNode(payload in) {
    if (!doc || !node) return;
    IXML_Node *n = NULL;
    if (!preqed_call("ixmlDocument_importNode")) return;
    int rc = ixmlDocument_importNode(doc, node, byte(in, 0) & 1, &n);
    preqed_result("ixmlDocument_importNode", rc == IXML_SUCCESS && n != NULL);
    if (n) set_loose(n);
}

/* element */


static void call_ixmlElement_getTagName(payload in) {
    IXML_Element *el = root_el();
    (void)in;
    if (!el) return;
    if (!preqed_call("ixmlElement_getTagName")) return;
    preqed_result("ixmlElement_getTagName", ixmlElement_getTagName(el) != NULL);
}

static void call_ixmlElement_getAttribute(payload in) {
    IXML_Element *el = root_el();
    if (!el) return;
    REPORT_VOID(ixmlElement_getAttribute, ixmlElement_getAttribute(el, field(s1, sizeof s1, in, 0)));
}

static void call_ixmlElement_setAttribute(payload in) {
    IXML_Element *el = root_el();
    if (!el) return;
    tree_mutated();
    REPORT(ixmlElement_setAttribute, ixmlElement_setAttribute(el, field(s1, sizeof s1, in, 0), field(s2, sizeof s2, in, 1)),
           rc == IXML_SUCCESS);
}

static void call_ixmlElement_removeAttribute(payload in) {
    IXML_Element *el = root_el();
    if (!el) return;
    tree_mutated();
    REPORT(ixmlElement_removeAttribute, ixmlElement_removeAttribute(el, field(s1, sizeof s1, in, 0)), rc == IXML_SUCCESS);
}
/* ltl: borrowed_node_validity */
static void call_ixmlElement_getAttributeNode(payload in) {
    IXML_Element *el = root_el();
    if (!el) return;
    REPORT_NODE(ixmlElement_getAttributeNode, (IXML_Node *)ixmlElement_getAttributeNode(el, field(s1, sizeof s1, in, 0)));
}
/* ltl: detached_node_ownership */
static void call_ixmlElement_setAttributeNode(payload in) {
    (void)in;
    IXML_Element *el = root_el();
    if (!el || !loose || loose->nodeType != eATTRIBUTE_NODE) return;
    IXML_Attr *old = NULL;
    IXML_Attr *attr = (IXML_Attr *)loose;
    tree_mutated();
    if (!preqed_call("ixmlElement_setAttributeNode")) return;
    int rc = ixmlElement_setAttributeNode(el, attr, &old);
    preqed_result("ixmlElement_setAttributeNode", rc == IXML_SUCCESS);
    if (rc == IXML_SUCCESS) {
        loose = NULL;
        if (old) set_loose((IXML_Node *)old);
    }
}
/* ltl: detached_node_ownership */
static void call_ixmlElement_removeAttributeNode(payload in) {
    IXML_Element *el = root_el();
    if (!el) return;
    IXML_Attr *attr = pick_attr(el, byte(in, 0));
    if (!attr) return;
    IXML_Attr *out = NULL;
    tree_mutated();
    REPORT(ixmlElement_removeAttributeNode, ixmlElement_removeAttributeNode(el, attr, &out), rc == IXML_SUCCESS);
    if (out) set_loose((IXML_Node *)out);
}

static void call_ixmlElement_getElementsByTagName(payload in) {
    IXML_Element *el = root_el();
    if (!el) return;
    if (!preqed_call("ixmlElement_getElementsByTagName")) return;
    IXML_NodeList *l = ixmlElement_getElementsByTagName(el, field(s1, sizeof s1, in, 0));
    preqed_result("ixmlElement_getElementsByTagName", l != NULL);
    drop_views();
    list = l;
}

static void call_ixmlElement_getAttributeNS(payload in) {
    IXML_Element *el = root_el();
    if (!el) return;
    REPORT_VOID(ixmlElement_getAttributeNS,
                ixmlElement_getAttributeNS(el, field(s1, sizeof s1, in, 0), field(s2, sizeof s2, in, 1)));
}

/* element.c:398 strcmp(n->localName, NULL): setAttributeNode_common (element.c:254) packs p2 = NULL, so
 * the create path of setAttributeNS crashes once the element already has a namespaced attribute. */
static int has_ns_attr(IXML_Element *el) {
    IXML_Node *a = el->n.firstAttr;
    for (; a; a = a->nextSibling)
        if (a->localName && a->namespaceURI) return 1;
    return 0;
}

static void call_ixmlElement_setAttributeNS(payload in) {
    IXML_Element *el = root_el();
    if (!el) return;
    const char *ns = field(s1, sizeof s1, in, 0);
    const char *name = field(s2, sizeof s2, in, 1);
    const char *value = field(s3, sizeof s3, in, 2);
    if (ixmlElement_getAttributeNS(el, ns, name) == NULL && has_ns_attr(el)) return;
    tree_mutated();
    REPORT(ixmlElement_setAttributeNS, ixmlElement_setAttributeNS(el, ns, name, value), rc == IXML_SUCCESS);
}

static void call_ixmlElement_removeAttributeNS(payload in) {
    IXML_Element *el = root_el();
    if (!el) return;
    tree_mutated();
    REPORT(ixmlElement_removeAttributeNS,
           ixmlElement_removeAttributeNS(el, field(s1, sizeof s1, in, 0), field(s2, sizeof s2, in, 1)), rc == IXML_SUCCESS);
}
/* ltl: borrowed_node_validity */
static void call_ixmlElement_getAttributeNodeNS(payload in) {
    IXML_Element *el = root_el();
    if (!el) return;
    REPORT_NODE(ixmlElement_getAttributeNodeNS,
                (IXML_Node *)ixmlElement_getAttributeNodeNS(el, field(s1, sizeof s1, in, 0), field(s2, sizeof s2, in, 1)));
}

/* same element.c:254/398 defect as setAttributeNS: any namespaced attribute makes get_attribute_node()
 * compare against a NULL local name. */
/* ltl: detached_node_ownership */
static void call_ixmlElement_setAttributeNodeNS(payload in) {
    (void)in;
    IXML_Element *el = root_el();
    if (!el || !loose || loose->nodeType != eATTRIBUTE_NODE) return;
    if (has_ns_attr(el)) return;
    IXML_Attr *old = NULL;
    IXML_Attr *attr = (IXML_Attr *)loose;
    tree_mutated();
    if (!preqed_call("ixmlElement_setAttributeNodeNS")) return;
    int rc = ixmlElement_setAttributeNodeNS(el, attr, &old);
    preqed_result("ixmlElement_setAttributeNodeNS", rc == IXML_SUCCESS);
    if (rc == IXML_SUCCESS) {
        loose = NULL;
        if (old) set_loose((IXML_Node *)old);
    }
}

static void call_ixmlElement_getElementsByTagNameNS(payload in) {
    IXML_Element *el = root_el();
    if (!el) return;
    if (!preqed_call("ixmlElement_getElementsByTagNameNS")) return;
    IXML_NodeList *l = ixmlElement_getElementsByTagNameNS(el, field(s1, sizeof s1, in, 0), field(s2, sizeof s2, in, 1));
    preqed_result("ixmlElement_getElementsByTagNameNS", l != NULL);
    drop_views();
    list = l;
}

static void call_ixmlElement_hasAttribute(payload in) {
    IXML_Element *el = root_el();
    if (!el) return;
    REPORT_VOID(ixmlElement_hasAttribute, ixmlElement_hasAttribute(el, field(s1, sizeof s1, in, 0)));
}

static void call_ixmlElement_hasAttributeNS(payload in) {
    IXML_Element *el = root_el();
    if (!el) return;
    REPORT_VOID(ixmlElement_hasAttributeNS,
                ixmlElement_hasAttributeNS(el, field(s1, sizeof s1, in, 0), field(s2, sizeof s2, in, 1)));
}
/* ltl: detached_node_ownership */
static void call_ixmlElement_free(payload in) {
    (void)in;
    if (!loose || loose->nodeType != eELEMENT_NODE) return;
    IXML_Node *n = loose;
    loose = NULL;
    REPORT_VOID(ixmlElement_free, ixmlElement_free((IXML_Element *)n));
}

/* named node map and node list */

static void call_ixmlNamedNodeMap_getLength(payload in) {
    (void)in;
    if (!map) return;
    REPORT_VOID(ixmlNamedNodeMap_getLength, ixmlNamedNodeMap_getLength(map));
}
/* ltl: borrowed_node_validity */
static void call_ixmlNamedNodeMap_getNamedItem(payload in) {
    if (!map) return;
    REPORT_NODE(ixmlNamedNodeMap_getNamedItem, ixmlNamedNodeMap_getNamedItem(map, field(s1, sizeof s1, in, 0)));
}
/* ltl: borrowed_node_validity */
static void call_ixmlNamedNodeMap_item(payload in) {
    if (!map) return;
    REPORT_NODE(ixmlNamedNodeMap_item, ixmlNamedNodeMap_item(map, byte(in, 0)));
}

static void call_ixmlNamedNodeMap_free(payload in) {
    (void)in;
    if (!map) return;
    IXML_NamedNodeMap *m = map;
    map = NULL;
    REPORT_VOID(ixmlNamedNodeMap_free, ixmlNamedNodeMap_free(m));
}
/* ltl: borrowed_node_validity */
static void call_ixmlNodeList_item(payload in) {
    if (!list) return;
    REPORT_NODE(ixmlNodeList_item, ixmlNodeList_item(list, byte(in, 0)));
}

static void call_ixmlNodeList_length(payload in) {
    (void)in;
    if (!list) return;
    REPORT_VOID(ixmlNodeList_length, ixmlNodeList_length(list));
}

static void call_ixmlNodeList_free(payload in) {
    (void)in;
    if (!list) return;
    IXML_NodeList *l = list;
    list = NULL;
    REPORT_VOID(ixmlNodeList_free, ixmlNodeList_free(l));
}

/* rendering and DOM strings */
/* ltl: document_lifecycle, domstring_free_once */
static void call_ixmlPrintDocument(payload in) {
    (void)in;
    if (!doc || str) return;
    if (!preqed_call("ixmlPrintDocument")) return;
    str = ixmlPrintDocument(doc);
    preqed_result("ixmlPrintDocument", str != NULL);
}
/* ltl: borrowed_node_validity, domstring_free_once */
static void call_ixmlPrintNode(payload in) {
    (void)in;
    if (!node || str) return;
    if (!preqed_call("ixmlPrintNode")) return;
    str = ixmlPrintNode(node);
    preqed_result("ixmlPrintNode", str != NULL);
}
/* ltl: document_lifecycle, domstring_free_once */
static void call_ixmlDocumenttoString(payload in) {
    (void)in;
    if (!doc || str) return;
    if (!preqed_call("ixmlDocumenttoString")) return;
    str = ixmlDocumenttoString(doc);
    preqed_result("ixmlDocumenttoString", str != NULL);
}
/* ltl: borrowed_node_validity, domstring_free_once */
static void call_ixmlNodetoString(payload in) {
    (void)in;
    if (!node || str) return;
    if (!preqed_call("ixmlNodetoString")) return;
    str = ixmlNodetoString(node);
    preqed_result("ixmlNodetoString", str != NULL);
}

static void call_ixmlRelaxParser(payload in) {
    REPORT_VOID(ixmlRelaxParser, ixmlRelaxParser((char)byte(in, 0)));
}

#ifdef IXML_HAVE_SCRIPTSUPPORT
static void noop_before_free(Nodeptr n) { (void)n; }

static void call_ixmlSetBeforeFree(payload in) {
    REPORT_VOID(ixmlSetBeforeFree, ixmlSetBeforeFree(byte(in, 0) & 1 ? noop_before_free : NULL));
}
#endif

/* parsing */

static void write_file(payload in) {
    FILE *f = fopen(FILE_PATH, "wb");
    if (!f) return;
    size_t off = 0;
    while (off < in.n) {
        size_t w = fwrite(in.p + off, 1, in.n - off, f);
        if (!w) break;
        off += w;
    }
    fclose(f);
}
/* ltl: document_lifecycle */
static void call_ixmlParseBuffer(payload in) {
    if (doc) return;
    if (!preqed_call("ixmlParseBuffer")) return;
    doc = ixmlParseBuffer(field(xml, sizeof xml, in, 0));
    preqed_result("ixmlParseBuffer", doc != NULL);
}
/* ltl: document_lifecycle */
static void call_ixmlParseBufferEx(payload in) {
    if (doc) return;
    IXML_Document *d = NULL;
    if (!preqed_call("ixmlParseBufferEx")) return;
    int rc = ixmlParseBufferEx(field(xml, sizeof xml, in, 0), &d);
    preqed_result("ixmlParseBufferEx", rc == IXML_SUCCESS && d != NULL);
    doc = d;
}
/* ltl: document_lifecycle */
static void call_ixmlLoadDocument(payload in) {
    if (doc) return;
    write_file(in);
    if (!preqed_call("ixmlLoadDocument")) return;
    doc = ixmlLoadDocument(FILE_PATH);
    preqed_result("ixmlLoadDocument", doc != NULL);
}
/* ltl: document_lifecycle */
static void call_ixmlLoadDocumentEx(payload in) {
    if (doc) return;
    write_file(in);
    IXML_Document *d = NULL;
    if (!preqed_call("ixmlLoadDocumentEx")) return;
    int rc = ixmlLoadDocumentEx(FILE_PATH, &d);
    preqed_result("ixmlLoadDocumentEx", rc == IXML_SUCCESS && d != NULL);
    doc = d;
}
/* ltl: domstring_free_once */
static void call_ixmlCloneDOMString(payload in) {
    if (str) return;
    if (!preqed_call("ixmlCloneDOMString")) return;
    str = ixmlCloneDOMString(field(s1, sizeof s1, in, 0));
    preqed_result("ixmlCloneDOMString", str != NULL);
}
/* ltl: domstring_free_once */
static void call_ixmlFreeDOMString(payload in) {
    (void)in;
    if (!str) return;
    DOMString s = str;
    str = NULL;
    REPORT_VOID(ixmlFreeDOMString, ixmlFreeDOMString(s));
}

/* libupnp helpers that work without UpnpInit2, sockets, threads or the web server */

static void call_UpnpGetErrorMessage(payload in) {
    if (!preqed_call("UpnpGetErrorMessage")) return;
    preqed_result("UpnpGetErrorMessage", UpnpGetErrorMessage((int)byte(in, 0) - 128) != NULL);
}

static void call_UpnpSetMaxJobsTotal(payload in) {
    REPORT_VOID(UpnpSetMaxJobsTotal, UpnpSetMaxJobsTotal((int)byte(in, 0)));
}

static void call_UpnpResolveURL(payload in) {
    const char *base = field(s1, sizeof s1, in, 0);
    const char *rel = field(s2, sizeof s2, in, 1);
    REPORT(UpnpResolveURL, UpnpResolveURL(base, rel, url), rc == UPNP_E_SUCCESS);
}

static void call_UpnpResolveURL2(payload in) {
    const char *base = field(s1, sizeof s1, in, 0);
    const char *rel = field(s2, sizeof s2, in, 1);
    char *out = NULL;
    if (!preqed_call("UpnpResolveURL2")) return;
    int rc = UpnpResolveURL2(base, rel, &out);
    preqed_result("UpnpResolveURL2", rc == UPNP_E_SUCCESS && out != NULL);
    free(out);
}

static void call_UpnpMakeAction(payload in) {
    if (!preqed_call("UpnpMakeAction")) return;
    const char *name = field(s1, sizeof s1, in, 0);
    const char *serv = field(s2, sizeof s2, in, 1);
    /* 2 = number of (name, value) argument pairs that follow */
    IXML_Document *d = UpnpMakeAction(name, serv, 2, field(s3, sizeof s3, in, 2), field(s4, sizeof s4, in, 3),
                                      field(s5, sizeof s5, in, 4), field(s6, sizeof s6, in, 5));
    preqed_result("UpnpMakeAction", d != NULL);
    if (d) {
        ixmlDocument_free(action);
        action = d;
    }
}

static void call_UpnpMakeActionResponse(payload in) {
    if (!preqed_call("UpnpMakeActionResponse")) return;
    const char *name = field(s1, sizeof s1, in, 0);
    const char *serv = field(s2, sizeof s2, in, 1);
    /* 2 argument pairs, as in UpnpMakeAction */
    IXML_Document *d = UpnpMakeActionResponse(name, serv, 2, field(s3, sizeof s3, in, 2), field(s4, sizeof s4, in, 3),
                                              field(s5, sizeof s5, in, 4), field(s6, sizeof s6, in, 5));
    preqed_result("UpnpMakeActionResponse", d != NULL);
    if (d) {
        ixmlDocument_free(action);
        action = d;
    }
}

static void call_UpnpAddToAction(payload in) {
    const char *name = field(s1, sizeof s1, in, 0);
    const char *serv = field(s2, sizeof s2, in, 1);
    REPORT(UpnpAddToAction, UpnpAddToAction(&action, name, serv, field(s3, sizeof s3, in, 2), field(s4, sizeof s4, in, 3)),
           rc == UPNP_E_SUCCESS);
}

static void call_UpnpAddToActionResponse(payload in) {
    const char *name = field(s1, sizeof s1, in, 0);
    const char *serv = field(s2, sizeof s2, in, 1);
    REPORT(UpnpAddToActionResponse,
           UpnpAddToActionResponse(&action, name, serv, field(s3, sizeof s3, in, 2), field(s4, sizeof s4, in, 3)),
           rc == UPNP_E_SUCCESS);
}

static void call_UpnpCreatePropertySet(payload in) {
    if (!preqed_call("UpnpCreatePropertySet")) return;
    IXML_Document *d = UpnpCreatePropertySet(2, field(s1, sizeof s1, in, 0), field(s2, sizeof s2, in, 1),
                                             field(s3, sizeof s3, in, 2), field(s4, sizeof s4, in, 3));
    preqed_result("UpnpCreatePropertySet", d != NULL);
    if (d) {
        ixmlDocument_free(action);
        action = d;
    }
}

static void call_UpnpAddToPropertySet(payload in) {
    REPORT(UpnpAddToPropertySet, UpnpAddToPropertySet(&action, field(s1, sizeof s1, in, 0), field(s2, sizeof s2, in, 1)),
           rc == UPNP_E_SUCCESS);
}

/* UpnpString */

static void call_UpnpString_new(payload in) {
    (void)in;
    if (ustr) return;
    if (!preqed_call("UpnpString_new")) return;
    ustr = UpnpString_new();
    preqed_result("UpnpString_new", ustr != NULL);
}

static void call_UpnpString_delete(payload in) {
    (void)in;
    if (!ustr) return;
    UpnpString *p = ustr;
    ustr = NULL;
    REPORT_VOID(UpnpString_delete, UpnpString_delete(p));
}

static void call_UpnpString_dup(payload in) {
    (void)in;
    if (!ustr) return;
    if (!preqed_call("UpnpString_dup")) return;
    UpnpString *p = UpnpString_dup(ustr);
    preqed_result("UpnpString_dup", p != NULL);
    if (p) {
        UpnpString_delete(ustr2);
        ustr2 = p;
    }
}

static void call_UpnpString_assign(payload in) {
    (void)in;
    if (!ustr || !ustr2) return;
    REPORT_VOID(UpnpString_assign, UpnpString_assign(ustr, ustr2));
}

static void call_UpnpString_get_Length(payload in) {
    (void)in;
    if (!ustr) return;
    REPORT_VOID(UpnpString_get_Length, UpnpString_get_Length(ustr));
}

static void call_UpnpString_set_Length(payload in) {
    if (!ustr) return;
    REPORT_VOID(UpnpString_set_Length, UpnpString_set_Length(ustr, byte(in, 0)));
}

static void call_UpnpString_get_String(payload in) {
    (void)in;
    if (!ustr) return;
    if (!preqed_call("UpnpString_get_String")) return;
    preqed_result("UpnpString_get_String", UpnpString_get_String(ustr) != NULL);
}

static void call_UpnpString_set_String(payload in) {
    if (!ustr) return;
    REPORT(UpnpString_set_String, UpnpString_set_String(ustr, field(s1, sizeof s1, in, 0)), rc == 1);
}

static void call_UpnpString_set_StringN(payload in) {
    if (!ustr) return;
    payload in2 = rest(in, 1);
    REPORT(UpnpString_set_StringN, UpnpString_set_StringN(ustr, field(s1, sizeof s1, in2, 0), byte(in, 0)),
           rc == 1);
}

static void call_UpnpString_clear(payload in) {
    (void)in;
    if (!ustr) return;
    REPORT_VOID(UpnpString_clear, UpnpString_clear(ustr));
}

static void call_UpnpString_cmp(payload in) {
    (void)in;
    if (!ustr || !ustr2) return;
    REPORT_VOID(UpnpString_cmp, UpnpString_cmp(ustr, ustr2));
}

static void call_UpnpString_casecmp(payload in) {
    (void)in;
    if (!ustr || !ustr2) return;
    REPORT_VOID(UpnpString_casecmp, UpnpString_casecmp(ustr, ustr2));
}

/* list */

static void call_UpnpListInit(payload in) {
    (void)in;
    REPORT_VOID(UpnpListInit, UpnpListInit(&head));
    memset(elts_used, 0, sizeof elts_used);
}

static void call_UpnpListBegin(payload in) {
    (void)in;
    if (!preqed_call("UpnpListBegin")) return;
    preqed_result("UpnpListBegin", UpnpListBegin(&head) != NULL);
}

static void call_UpnpListEnd(payload in) {
    (void)in;
    if (!preqed_call("UpnpListEnd")) return;
    preqed_result("UpnpListEnd", UpnpListEnd(&head) != NULL);
}

static void call_UpnpListNext(payload in) {
    (void)in;
    if (!preqed_call("UpnpListNext")) return;
    preqed_result("UpnpListNext", UpnpListNext(&head, UpnpListBegin(&head)) != NULL);
}

static void call_UpnpListInsert(payload in) {
    unsigned k = byte(in, 0) % 8;
    if (elts_used[k]) return;
    UpnpListIter pos = UpnpListBegin(&head);
    if (!preqed_call("UpnpListInsert")) return;
    UpnpListIter it = UpnpListInsert(&head, pos, &elts[k]);
    preqed_result("UpnpListInsert", it == &elts[k]);
    if (it == &elts[k]) elts_used[k] = 1;
}

/* erasing the head itself is undefined, only elements that were inserted are erased */
static void call_UpnpListErase(payload in) {
    unsigned k = byte(in, 0) % 8;
    if (!elts_used[k]) return;
    if (!preqed_call("UpnpListErase")) return;
    UpnpListIter it = UpnpListErase(&head, &elts[k]);
    preqed_result("UpnpListErase", it != NULL);
    elts_used[k] = 0;
}

/* generated accessor objects (upnp/inc/Upnp<Class>.h, upnp/src/api/Upnp<Class>.c, "automatically generated"
 * from one template): each class has one owned object in slot 1 and a second, made by dup, in slot 2 for
 * assign. Getters return borrowed pointers. The IXML_Document fields are borrowed too (the *_delete
 * functions only clear them, e.g. UpnpActionRequest.c), so the setters get the live document and the
 * stored pointer is never dereferenced by the harness. set_* of an UpnpString field copies the harness's
 * UpnpString; set_* of a DOMString field clones the argument (ixmlCloneDOMString). */

static UpnpActionComplete *ac, *ac2;
static UpnpActionRequest *areq, *areq2;
static UpnpDiscovery *disc, *disc2;
static UpnpEvent *evt, *evt2;
static UpnpEventSubscribe *esub, *esub2;
static UpnpExtraHeaders *eh, *eh2;
static UpnpFileInfo *fi, *fi2;
static UpnpStateVarComplete *svc, *svc2;
static UpnpStateVarRequest *svr, *svr2;
static UpnpSubscriptionRequest *sreq, *sreq2;

#define REPORT_PTR(api, expr) \
    do { \
        if (preqed_call(#api)) preqed_result(#api, (expr) != NULL); \
    } while (0)

/* a socket address from the payload: byte 0 picks the family, the rest fills the address */
static const struct sockaddr_storage *addr_from(payload in) {
    static struct sockaddr_storage ss;
    payload a = rest(in, 1);
    memset(&ss, 0, sizeof ss);
    if (byte(in, 0) & 1) {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&ss;
        s6->sin6_family = AF_INET6;
        s6->sin6_port = (uint16_t)(byte(a, 0) | byte(a, 1) << 8);
        for (size_t i = 0; i < sizeof s6->sin6_addr; i++) s6->sin6_addr.s6_addr[i] = byte(a, 2 + i);
    } else {
        struct sockaddr_in *s4 = (struct sockaddr_in *)&ss;
        s4->sin_family = AF_INET;
        s4->sin_port = (uint16_t)(byte(a, 0) | byte(a, 1) << 8);
        s4->sin_addr.s_addr = (uint32_t)byte(a, 2) | (uint32_t)byte(a, 3) << 8 | (uint32_t)byte(a, 4) << 16 |
                              (uint32_t)byte(a, 5) << 24;
    }
    return &ss;
}

/* new/dup/delete/assign; dup replaces slot 2 (releasing the old slot-2 object is bookkeeping) */
#define OBJ_NEW_DUP(T, a, b) \
    static void call_##T##_new(payload in) { \
        (void)in; \
        if (a) return; \
        REPORT_PTR(T##_new, a = T##_new()); \
    } \
    static void call_##T##_dup(payload in) { \
        (void)in; \
        if (!a) return; \
        if (!preqed_call(#T "_dup")) return; \
        T *p = T##_dup(a); \
        preqed_result(#T "_dup", p != NULL); \
        if (p) { \
            T##_delete(b); \
            b = p; \
        } \
    }
#define OBJ_DEL_ASSIGN(T, a, b) \
    static void call_##T##_delete(payload in) { \
        (void)in; \
        if (!a) return; \
        T *p = a; \
        a = NULL; \
        REPORT_VOID(T##_delete, T##_delete(p)); \
    } \
    static void call_##T##_assign(payload in) { \
        (void)in; \
        if (!a || !b) return; \
        REPORT(T##_assign, T##_assign(a, b), rc == 1); \
    }
/* int-like field */
#define OBJ_INT(T, a, F, type) \
    static void call_##T##_get_##F(payload in) { \
        (void)in; \
        if (!a) return; \
        REPORT_VOID(T##_get_##F, T##_get_##F(a)); \
    } \
    static void call_##T##_set_##F(payload in) { \
        if (!a) return; \
        REPORT(T##_set_##F, T##_set_##F(a, (type)(int8_t)byte(in, 0)), rc == 1); \
    }
/* UpnpString field */
#define OBJ_STR(T, a, F) \
    static void call_##T##_get_##F(payload in) { \
        (void)in; \
        if (!a) return; \
        REPORT_PTR(T##_get_##F, T##_get_##F(a)); \
    } \
    static void call_##T##_set_##F(payload in) { \
        (void)in; \
        if (!a || !ustr) return; \
        REPORT(T##_set_##F, T##_set_##F(a, ustr), rc == 1); \
    } \
    static void call_##T##_get_##F##_Length(payload in) { \
        (void)in; \
        if (!a) return; \
        REPORT_VOID(T##_get_##F##_Length, T##_get_##F##_Length(a)); \
    } \
    static void call_##T##_get_##F##_cstr(payload in) { \
        (void)in; \
        if (!a) return; \
        REPORT_PTR(T##_get_##F##_cstr, T##_get_##F##_cstr(a)); \
    } \
    static void call_##T##_strcpy_##F(payload in) { \
        if (!a) return; \
        REPORT(T##_strcpy_##F, T##_strcpy_##F(a, field(s1, sizeof s1, in, 0)), rc == 1); \
    } \
    static void call_##T##_strncpy_##F(payload in) { \
        if (!a) return; \
        payload in2 = rest(in, 1); \
        REPORT(T##_strncpy_##F, T##_strncpy_##F(a, field(s1, sizeof s1, in2, 0), byte(in, 0)), rc == 1); \
    } \
    static void call_##T##_clear_##F(payload in) { \
        (void)in; \
        if (!a) return; \
        REPORT_VOID(T##_clear_##F, T##_clear_##F(a)); \
    }
/* DOMString field: NULL until set */
#define OBJ_DOM(T, a, F) \
    static void call_##T##_get_##F(payload in) { \
        (void)in; \
        if (!a) return; \
        REPORT_VOID(T##_get_##F, T##_get_##F(a)); \
    } \
    static void call_##T##_set_##F(payload in) { \
        if (!a) return; \
        REPORT(T##_set_##F, T##_set_##F(a, (DOMString)field(s1, sizeof s1, in, 0)), rc == 1); \
    } \
    static void call_##T##_get_##F##_cstr(payload in) { \
        (void)in; \
        if (!a) return; \
        REPORT_VOID(T##_get_##F##_cstr, T##_get_##F##_cstr(a)); \
    }
/* borrowed IXML_Document field */
#define OBJ_DOC(T, a, F) \
    static void call_##T##_get_##F(payload in) { \
        (void)in; \
        if (!a) return; \
        REPORT_VOID(T##_get_##F, T##_get_##F(a)); \
    } \
    static void call_##T##_set_##F(payload in) { \
        (void)in; \
        if (!a || !doc) return; \
        REPORT(T##_set_##F, T##_set_##F(a, doc), rc == 1); \
    }
/* struct sockaddr_storage field */
#define OBJ_ADDR(T, a, F) \
    static void call_##T##_get_##F(payload in) { \
        (void)in; \
        if (!a) return; \
        REPORT_PTR(T##_get_##F, T##_get_##F(a)); \
    } \
    static void call_##T##_set_##F(payload in) { \
        if (!a) return; \
        REPORT(T##_set_##F, T##_set_##F(a, addr_from(in)), rc == 1); \
    } \
    static void call_##T##_clear_##F(payload in) { \
        (void)in; \
        if (!a) return; \
        REPORT_VOID(T##_clear_##F, T##_clear_##F(a)); \
    }

/* dispatch-table entries for the wrappers above */
#define OPS_LIFE(T) call_##T##_new, call_##T##_dup, call_##T##_delete, call_##T##_assign
#define OPS_INT(T, F) call_##T##_get_##F, call_##T##_set_##F
#define OPS_STR(T, F) \
    call_##T##_get_##F, call_##T##_set_##F, call_##T##_get_##F##_Length, call_##T##_get_##F##_cstr, \
        call_##T##_strcpy_##F, call_##T##_strncpy_##F, call_##T##_clear_##F
#define OPS_DOM(T, F) call_##T##_get_##F, call_##T##_set_##F, call_##T##_get_##F##_cstr
#define OPS_DOC(T, F) call_##T##_get_##F, call_##T##_set_##F
#define OPS_ADDR(T, F) call_##T##_get_##F, call_##T##_set_##F, call_##T##_clear_##F
/* ltl: action_complete_lifecycle */
OBJ_NEW_DUP(UpnpActionComplete, ac, ac2)
/* ltl: action_complete_lifecycle */
OBJ_DEL_ASSIGN(UpnpActionComplete, ac, ac2)
/* ltl: action_complete_lifecycle */
OBJ_INT(UpnpActionComplete, ac, ErrCode, int)
/* ltl: action_complete_lifecycle */
OBJ_STR(UpnpActionComplete, ac, CtrlUrl)
/* ltl: action_complete_lifecycle, document_lifecycle */
OBJ_DOC(UpnpActionComplete, ac, ActionRequest)
/* ltl: action_complete_lifecycle, document_lifecycle */
OBJ_DOC(UpnpActionComplete, ac, ActionResult)
/* ltl: action_request_lifecycle */
OBJ_NEW_DUP(UpnpActionRequest, areq, areq2)
/* ltl: action_request_lifecycle */
OBJ_DEL_ASSIGN(UpnpActionRequest, areq, areq2)
/* ltl: action_request_lifecycle */
OBJ_INT(UpnpActionRequest, areq, ErrCode, int)
/* ltl: action_request_lifecycle */
OBJ_INT(UpnpActionRequest, areq, Socket, int)
/* ltl: action_request_lifecycle */
OBJ_STR(UpnpActionRequest, areq, ErrStr)
/* ltl: action_request_lifecycle */
OBJ_STR(UpnpActionRequest, areq, ActionName)
/* ltl: action_request_lifecycle */
OBJ_STR(UpnpActionRequest, areq, DevUDN)
/* ltl: action_request_lifecycle */
OBJ_STR(UpnpActionRequest, areq, ServiceID)
/* ltl: action_request_lifecycle, document_lifecycle */
OBJ_DOC(UpnpActionRequest, areq, ActionRequest)
/* ltl: action_request_lifecycle, document_lifecycle */
OBJ_DOC(UpnpActionRequest, areq, ActionResult)
/* ltl: action_request_lifecycle, document_lifecycle */
OBJ_DOC(UpnpActionRequest, areq, SoapHeader)
/* ltl: action_request_lifecycle */
OBJ_ADDR(UpnpActionRequest, areq, CtrlPtIPAddr)
/* ltl: action_request_lifecycle */
OBJ_STR(UpnpActionRequest, areq, Os)
/* ltl: discovery_lifecycle */
OBJ_NEW_DUP(UpnpDiscovery, disc, disc2)
/* ltl: discovery_lifecycle */
OBJ_DEL_ASSIGN(UpnpDiscovery, disc, disc2)
/* ltl: discovery_lifecycle */
OBJ_INT(UpnpDiscovery, disc, ErrCode, int)
/* ltl: discovery_lifecycle */
OBJ_INT(UpnpDiscovery, disc, Expires, int)
/* ltl: discovery_lifecycle */
OBJ_STR(UpnpDiscovery, disc, DeviceID)
/* ltl: discovery_lifecycle */
OBJ_STR(UpnpDiscovery, disc, DeviceType)
/* ltl: discovery_lifecycle */
OBJ_STR(UpnpDiscovery, disc, ServiceType)
/* ltl: discovery_lifecycle */
OBJ_STR(UpnpDiscovery, disc, ServiceVer)
/* ltl: discovery_lifecycle */
OBJ_STR(UpnpDiscovery, disc, Location)
/* ltl: discovery_lifecycle */
OBJ_STR(UpnpDiscovery, disc, Os)
/* ltl: discovery_lifecycle */
OBJ_STR(UpnpDiscovery, disc, Date)
/* ltl: discovery_lifecycle */
OBJ_STR(UpnpDiscovery, disc, Ext)
/* ltl: discovery_lifecycle */
OBJ_ADDR(UpnpDiscovery, disc, DestAddr)
/* ltl: event_lifecycle */
OBJ_NEW_DUP(UpnpEvent, evt, evt2)
/* ltl: event_lifecycle */
OBJ_DEL_ASSIGN(UpnpEvent, evt, evt2)
/* ltl: event_lifecycle */
OBJ_INT(UpnpEvent, evt, EventKey, int)
/* ltl: event_lifecycle, document_lifecycle */
OBJ_DOC(UpnpEvent, evt, ChangedVariables)
/* ltl: event_lifecycle */
OBJ_STR(UpnpEvent, evt, SID)
/* ltl: event_subscribe_lifecycle */
OBJ_NEW_DUP(UpnpEventSubscribe, esub, esub2)
/* ltl: event_subscribe_lifecycle */
OBJ_DEL_ASSIGN(UpnpEventSubscribe, esub, esub2)
/* ltl: event_subscribe_lifecycle */
OBJ_INT(UpnpEventSubscribe, esub, ErrCode, int)
/* ltl: event_subscribe_lifecycle */
OBJ_INT(UpnpEventSubscribe, esub, TimeOut, int)
/* ltl: event_subscribe_lifecycle */
OBJ_STR(UpnpEventSubscribe, esub, SID)
/* ltl: event_subscribe_lifecycle */
OBJ_STR(UpnpEventSubscribe, esub, PublisherUrl)
/* ltl: state_var_complete_lifecycle */
OBJ_NEW_DUP(UpnpStateVarComplete, svc, svc2)
/* ltl: state_var_complete_lifecycle */
OBJ_DEL_ASSIGN(UpnpStateVarComplete, svc, svc2)
/* ltl: state_var_complete_lifecycle */
OBJ_INT(UpnpStateVarComplete, svc, ErrCode, int)
/* ltl: state_var_complete_lifecycle */
OBJ_STR(UpnpStateVarComplete, svc, CtrlUrl)
/* ltl: state_var_complete_lifecycle */
OBJ_STR(UpnpStateVarComplete, svc, StateVarName)
/* ltl: state_var_complete_lifecycle */
OBJ_DOM(UpnpStateVarComplete, svc, CurrentVal)
/* ltl: state_var_request_lifecycle */
OBJ_NEW_DUP(UpnpStateVarRequest, svr, svr2)
/* ltl: state_var_request_lifecycle */
OBJ_DEL_ASSIGN(UpnpStateVarRequest, svr, svr2)
/* ltl: state_var_request_lifecycle */
OBJ_INT(UpnpStateVarRequest, svr, ErrCode, int)
/* ltl: state_var_request_lifecycle */
OBJ_INT(UpnpStateVarRequest, svr, Socket, int)
/* ltl: state_var_request_lifecycle */
OBJ_STR(UpnpStateVarRequest, svr, ErrStr)
/* ltl: state_var_request_lifecycle */
OBJ_STR(UpnpStateVarRequest, svr, DevUDN)
/* ltl: state_var_request_lifecycle */
OBJ_STR(UpnpStateVarRequest, svr, ServiceID)
/* ltl: state_var_request_lifecycle */
OBJ_STR(UpnpStateVarRequest, svr, StateVarName)
/* ltl: state_var_request_lifecycle */
OBJ_ADDR(UpnpStateVarRequest, svr, CtrlPtIPAddr)
/* ltl: state_var_request_lifecycle */
OBJ_DOM(UpnpStateVarRequest, svr, CurrentVal)
/* ltl: subscription_request_lifecycle */
OBJ_NEW_DUP(UpnpSubscriptionRequest, sreq, sreq2)
/* ltl: subscription_request_lifecycle */
OBJ_DEL_ASSIGN(UpnpSubscriptionRequest, sreq, sreq2)
/* ltl: subscription_request_lifecycle */
OBJ_STR(UpnpSubscriptionRequest, sreq, ServiceId)
/* ltl: subscription_request_lifecycle */
OBJ_STR(UpnpSubscriptionRequest, sreq, UDN)
/* ltl: subscription_request_lifecycle */
OBJ_STR(UpnpSubscriptionRequest, sreq, SID)

/* UpnpExtraHeaders and UpnpFileInfo carry intrusive list heads: UpnpExtraHeaders.node is the link of one
 * extra header, UpnpFileInfo.ExtraHeadersList is the head of a list of them (webserver.c:1189-1197 links
 * UpnpExtraHeaders_get_node() into it). UpnpListInsert/UpnpListErase (list.c:51-68) rewrite the
 * neighbours, while *_delete only re-initialises its own head (UpnpExtraHeaders.c, UpnpFileInfo.c) and
 * set_node/set_ExtraHeadersList/assign/dup copy a head by value, so the copy points into the source's
 * ring. The harness therefore unlinks every element it linked before deleting or overwriting a head
 * (bookkeeping, like releasing a slot), and never links through a head that holds a copied value. */
static UpnpListHead eh_member;  /* element linked into eh's ring by UpnpExtraHeaders_add_to_list_node */
static int member_in_eh, eh_in_fi; /* eh_member is in eh's ring; eh's node is in fi's list */
static int eh_alias, fi_alias;     /* eh's node / fi's list head holds a value copied from another head */

static void unlink_rings(void) {
    if (member_in_eh) UpnpListErase(NULL, &eh_member);
    if (eh_in_fi) UpnpListErase(NULL, (UpnpListHead *)UpnpExtraHeaders_get_node(eh));
    member_in_eh = eh_in_fi = 0;
}
/* ltl: extra_headers_lifecycle */
OBJ_NEW_DUP(UpnpExtraHeaders, eh, eh2)
/* ltl: extra_headers_lifecycle */
OBJ_STR(UpnpExtraHeaders, eh, name)
/* ltl: extra_headers_lifecycle */
OBJ_STR(UpnpExtraHeaders, eh, value)
/* ltl: extra_headers_lifecycle */
OBJ_DOM(UpnpExtraHeaders, eh, resp)
/* ltl: extra_headers_lifecycle */
static void call_UpnpExtraHeaders_delete(payload in) {
    (void)in;
    if (!eh) return;
    unlink_rings();
    UpnpExtraHeaders *p = eh;
    eh = NULL;
    eh_alias = 0;
    REPORT_VOID(UpnpExtraHeaders_delete, UpnpExtraHeaders_delete(p));
}
/* ltl: extra_headers_lifecycle */
static void call_UpnpExtraHeaders_assign(payload in) {
    (void)in;
    if (!eh || !eh2) return;
    unlink_rings();
    eh_alias = 1;
    REPORT(UpnpExtraHeaders_assign, UpnpExtraHeaders_assign(eh, eh2), rc == 1);
}
/* ltl: extra_headers_lifecycle */
static void call_UpnpExtraHeaders_get_node(payload in) {
    (void)in;
    if (!eh) return;
    REPORT_PTR(UpnpExtraHeaders_get_node, UpnpExtraHeaders_get_node(eh));
}

/* copies slot 2's head into eh (or eh's own head onto itself while there is no slot 2) */
/* ltl: extra_headers_lifecycle */
static void call_UpnpExtraHeaders_set_node(payload in) {
    (void)in;
    if (!eh) return;
    const UpnpListHead *q = UpnpExtraHeaders_get_node(eh2 ? eh2 : eh);
    unlink_rings();
    if (eh2) eh_alias = 1;
    REPORT(UpnpExtraHeaders_set_node, UpnpExtraHeaders_set_node(eh, q), rc == 1);
}
/* ltl: extra_headers_lifecycle */
static void call_UpnpExtraHeaders_add_to_list_node(payload in) {
    (void)in;
    if (!eh || eh_alias || member_in_eh) return;
    REPORT_VOID(UpnpExtraHeaders_add_to_list_node, UpnpExtraHeaders_add_to_list_node(eh, &eh_member));
    member_in_eh = 1;
}
/* ltl: file_info_lifecycle */
OBJ_NEW_DUP(UpnpFileInfo, fi, fi2)
/* ltl: file_info_lifecycle */
OBJ_INT(UpnpFileInfo, fi, FileLength, off_t)
/* ltl: file_info_lifecycle */
OBJ_INT(UpnpFileInfo, fi, LastModified, time_t)
/* ltl: file_info_lifecycle */
OBJ_INT(UpnpFileInfo, fi, IsDirectory, int)
/* ltl: file_info_lifecycle */
OBJ_INT(UpnpFileInfo, fi, IsReadable, int)
/* ltl: file_info_lifecycle */
OBJ_DOM(UpnpFileInfo, fi, ContentType)
/* ltl: file_info_lifecycle */
OBJ_ADDR(UpnpFileInfo, fi, CtrlPtIPAddr)
/* ltl: file_info_lifecycle */
OBJ_STR(UpnpFileInfo, fi, Os)
/* ltl: file_info_lifecycle */
static void call_UpnpFileInfo_delete(payload in) {
    (void)in;
    if (!fi) return;
    unlink_rings();
    UpnpFileInfo *p = fi;
    fi = NULL;
    fi_alias = 0;
    REPORT_VOID(UpnpFileInfo_delete, UpnpFileInfo_delete(p));
}
/* ltl: file_info_lifecycle */
static void call_UpnpFileInfo_assign(payload in) {
    (void)in;
    if (!fi || !fi2) return;
    unlink_rings();
    fi_alias = 1;
    REPORT(UpnpFileInfo_assign, UpnpFileInfo_assign(fi, fi2), rc == 1);
}
/* ltl: file_info_lifecycle */
static void call_UpnpFileInfo_get_ExtraHeadersList(payload in) {
    (void)in;
    if (!fi) return;
    REPORT_PTR(UpnpFileInfo_get_ExtraHeadersList, UpnpFileInfo_get_ExtraHeadersList(fi));
}
/* ltl: file_info_lifecycle */
static void call_UpnpFileInfo_set_ExtraHeadersList(payload in) {
    (void)in;
    if (!fi) return;
    const UpnpListHead *q = UpnpFileInfo_get_ExtraHeadersList(fi2 ? fi2 : fi);
    unlink_rings();
    if (fi2) fi_alias = 1;
    REPORT(UpnpFileInfo_set_ExtraHeadersList, UpnpFileInfo_set_ExtraHeadersList(fi, q), rc == 1);
}

/* links eh into fi's list; the insert rewrites eh's own links, so a copied value in eh's head is gone */
/* ltl: file_info_lifecycle */
static void call_UpnpFileInfo_add_to_list_ExtraHeadersList(payload in) {
    (void)in;
    if (!fi || !eh || fi_alias || eh_in_fi || member_in_eh) return;
    REPORT_VOID(UpnpFileInfo_add_to_list_ExtraHeadersList,
                UpnpFileInfo_add_to_list_ExtraHeadersList(fi, (UpnpListHead *)UpnpExtraHeaders_get_node(eh)));
    eh_in_fi = 1;
    eh_alias = 0;
}

static void free_objects(void) {
    unlink_rings();
    UpnpActionComplete_delete(ac);
    UpnpActionComplete_delete(ac2);
    UpnpActionRequest_delete(areq);
    UpnpActionRequest_delete(areq2);
    UpnpDiscovery_delete(disc);
    UpnpDiscovery_delete(disc2);
    UpnpEvent_delete(evt);
    UpnpEvent_delete(evt2);
    UpnpEventSubscribe_delete(esub);
    UpnpEventSubscribe_delete(esub2);
    UpnpExtraHeaders_delete(eh);
    UpnpExtraHeaders_delete(eh2);
    UpnpFileInfo_delete(fi);
    UpnpFileInfo_delete(fi2);
    UpnpStateVarComplete_delete(svc);
    UpnpStateVarComplete_delete(svc2);
    UpnpStateVarRequest_delete(svr);
    UpnpStateVarRequest_delete(svr2);
    UpnpSubscriptionRequest_delete(sreq);
    UpnpSubscriptionRequest_delete(sreq2);
    ac = ac2 = NULL;
    areq = areq2 = NULL;
    disc = disc2 = NULL;
    evt = evt2 = NULL;
    esub = esub2 = NULL;
    eh = eh2 = NULL;
    fi = fi2 = NULL;
    svc = svc2 = NULL;
    svr = svr2 = NULL;
    sreq = sreq2 = NULL;
    eh_alias = fi_alias = 0;
}

/* the UPnP stack: UpnpInit2 starts the thread pools, the miniserver (HTTP + SSDP sockets) and the web
 * server inside this process. upnpapi.c:4039 skips IFF_LOOPBACK interfaces, so it binds the first
 * non-loopback interface; run the fuzzer in an isolated network (docker network create --internal) so
 * every request, search and event below goes to this process's own device and control point. Only
 * inputs that select UpnpInit2 pay for the start-up; cleanup calls UpnpFinish, so no state outlives an
 * input. Callbacks run on library threads and emit no monitor events. */

#define HARNESS_UDN "uuid:pupnp-harness-device"
#define HARNESS_SERVICE "urn:schemas-upnp-org:service:harness:1"
/* built-in description for UpnpRegisterRootDevice2, so SOAP and GENA requests have a service to reach;
 * the other choice registers the payload as the description */
static const char builtin_desc[] =
    "<?xml version=\"1.0\"?>\n"
    "<root xmlns=\"urn:schemas-upnp-org:device-1-0\"><specVersion><major>1</major><minor>0</minor></specVersion>"
    "<device><deviceType>urn:schemas-upnp-org:device:harness:1</deviceType><friendlyName>h</friendlyName>"
    "<UDN>" HARNESS_UDN "</UDN><serviceList><service><serviceType>" HARNESS_SERVICE "</serviceType>"
    "<serviceId>urn:upnp-org:serviceId:harness1</serviceId><SCPDURL>/scpd.xml</SCPDURL>"
    "<controlURL>/ctl</controlURL><eventSubURL>/evt</eventSubURL></service></serviceList></device></root>\n";

static int sdk;                  /* UpnpInit2 succeeded and UpnpFinish was not called since */
static int dev_ok, cp_ok;        /* the device / control point handle is registered */
static UpnpDevice_Handle dev;
static UpnpClient_Handle cp;
static Upnp_SID sid;             /* last SID returned by UpnpSubscribe */
static unsigned vd_cbs;          /* virtual-dir callbacks set since the web server was last (re)initialised */
static char nurl[1024], nurl2[1024], nbuf[4096];

/* the HTTP client handle: one at a time */
enum { CONN_NONE, CONN_GET, CONN_CONN };
enum { REQ_IDLE, REQ_OPEN, REQ_ENDED, REQ_RESP };
static void *conn;
static int conn_kind, conn_state;

/* subscription request seen by the device callback, for UpnpAcceptSubscription */
static pthread_mutex_t cb_mu = PTHREAD_MUTEX_INITIALIZER;
static Upnp_SID req_sid;
static char req_udn[NAME_SIZE], req_serv[NAME_SIZE];

static int dev_cb(Upnp_EventType type, void *event, void *cookie) {
    (void)cookie;
    switch (type) {
    case UPNP_CONTROL_ACTION_REQUEST: {
        /* soap_device.c:462-475 frees the result document after sending it */
        UpnpActionRequest *r = event;
        IXML_Document *res = UpnpMakeActionResponse(UpnpActionRequest_get_ActionName_cstr(r), HARNESS_SERVICE, 0, NULL);
        UpnpActionRequest_set_ActionResult(r, res);
        UpnpActionRequest_set_ErrCode(r, res ? UPNP_E_SUCCESS : UPNP_E_OUTOF_MEMORY);
        break;
    }
    case UPNP_CONTROL_GET_VAR_REQUEST: {
        UpnpStateVarRequest *r = event;
        UpnpStateVarRequest_set_CurrentVal(r, "0");
        UpnpStateVarRequest_set_ErrCode(r, UPNP_E_SUCCESS);
        break;
    }
    case UPNP_EVENT_SUBSCRIPTION_REQUEST: {
        UpnpSubscriptionRequest *r = event;
        pthread_mutex_lock(&cb_mu);
        snprintf(req_sid, sizeof req_sid, "%s", UpnpSubscriptionRequest_get_SID_cstr(r));
        snprintf(req_udn, sizeof req_udn, "%s", UpnpSubscriptionRequest_get_UDN_cstr(r));
        snprintf(req_serv, sizeof req_serv, "%s", UpnpSubscriptionRequest_get_ServiceId_cstr(r));
        pthread_mutex_unlock(&cb_mu);
        break;
    }
    default:
        break;
    }
    return 0;
}

static int cp_cb(Upnp_EventType type, void *event, void *cookie) {
    (void)type;
    (void)event;
    (void)cookie;
    return 0;
}

/* virtual directory: every file holds its own name; opens are independent per request */
typedef struct {
    size_t pos, len;
    char data[256];
} vfile;

static int vd_get_info(const char *filename, UpnpFileInfo *info, const void *cookie, const void **request_cookie) {
    (void)cookie;
    (void)request_cookie;
    size_t n = strlen(filename);
    UpnpFileInfo_set_FileLength(info, (off_t)(n < sizeof ((vfile *)0)->data ? n : sizeof ((vfile *)0)->data - 1));
    UpnpFileInfo_set_LastModified(info, 0);
    UpnpFileInfo_set_IsDirectory(info, 0);
    UpnpFileInfo_set_IsReadable(info, 1);
    UpnpFileInfo_set_ContentType(info, "text/xml");
    return 0;
}
static UpnpWebFileHandle vd_open(const char *filename, enum UpnpOpenFileMode mode, const void *cookie,
                                 const void *request_cookie) {
    (void)mode;
    (void)cookie;
    (void)request_cookie;
    vfile *f = calloc(1, sizeof *f);
    if (!f) return NULL;
    snprintf(f->data, sizeof f->data, "%s", filename);
    f->len = strlen(f->data);
    return f;
}
static int vd_read(UpnpWebFileHandle h, char *buf, size_t buflen, const void *cookie, const void *request_cookie) {
    (void)cookie;
    (void)request_cookie;
    vfile *f = h;
    size_t n = f->len - f->pos < buflen ? f->len - f->pos : buflen;
    memcpy(buf, f->data + f->pos, n);
    f->pos += n;
    return (int)n;
}
static int vd_write(UpnpWebFileHandle h, char *buf, size_t buflen, const void *cookie, const void *request_cookie) {
    (void)h;
    (void)buf;
    (void)cookie;
    (void)request_cookie;
    return (int)buflen;
}
static int vd_seek(UpnpWebFileHandle h, off_t offset, int origin, const void *cookie, const void *request_cookie) {
    (void)cookie;
    (void)request_cookie;
    vfile *f = h;
    off_t base = origin == SEEK_SET ? 0 : origin == SEEK_END ? (off_t)f->len : (off_t)f->pos;
    if (base + offset < 0 || base + offset > (off_t)f->len) return -1;
    f->pos = (size_t)(base + offset);
    return 0;
}
static int vd_close(UpnpWebFileHandle h, const void *cookie, const void *request_cookie) {
    (void)cookie;
    (void)request_cookie;
    free(h);
    return 0;
}
static int host_ok(const char *hostname, void *cookie) {
    (void)cookie;
    return hostname && hostname[0] != 'x' ? UPNP_E_SUCCESS : UPNP_E_BAD_HTTPMSG;
}

/* http://<this process's web server>/<payload path> */
static const char *own_url(char *dst, size_t cap, payload in, unsigned which) {
    char path[512];
    field(path, sizeof path, in, which);
    snprintf(dst, cap, "http://%s:%u/%s", UpnpGetServerIpAddress(), (unsigned)UpnpGetServerPort(),
             path[0] == '/' ? path + 1 : path);
    return dst;
}

/* releasing the HTTP handle before UpnpFinish or when a failed open left one behind is bookkeeping;
 * http_OpenHttpConnection returns its handle on a failed connect too (httpreadwrite.c:1376-1378) */
static void drop_handle(void *h) {
    if (h) UpnpCloseHttpConnection(h);
}
static void drop_conn(void) {
    drop_handle(conn);
    conn = NULL;
    conn_kind = CONN_NONE;
}
static void sdk_gone(void) {
    sdk = dev_ok = cp_ok = 0;
    vd_cbs = 0;
    memset(sid, 0, sizeof sid);
    pthread_mutex_lock(&cb_mu);
    req_sid[0] = req_udn[0] = req_serv[0] = 0;
    pthread_mutex_unlock(&cb_mu);
}
/* g_maxContentLength (upnpapi.c:216) survives UpnpFinish; restore the default (upnpapi.h:53) so the next
 * input starts from it */
#define DEFAULT_CONTENT_LENGTH 64000
/* ltl: sdk_lifecycle, virtual_dir_callbacks */
static void call_UpnpInit2(payload in) {
    if (sdk) return;
    payload in2 = rest(in, 1);
    const char *ifname = byte(in, 0) & 1 ? field(s1, sizeof s1, in2, 0) : NULL;
    if (!preqed_call("UpnpInit2")) return;
    int rc = UpnpInit2(ifname, 0);
    preqed_result("UpnpInit2", rc == UPNP_E_SUCCESS);
    if (rc == UPNP_E_SUCCESS) sdk = 1;
    vd_cbs = 0;
}
/* ltl: sdk_lifecycle, device_handle, client_handle, http_handle, http_request_order */
static void call_UpnpFinish(payload in) {
    (void)in;
    if (!sdk) return;
    if (!preqed_call("UpnpFinish")) return;
    drop_conn();
    UpnpSetMaxContentLength(DEFAULT_CONTENT_LENGTH);
    int rc = UpnpFinish();
    preqed_result("UpnpFinish", rc == UPNP_E_SUCCESS);
    sdk_gone();
}

/* server addresses and ports: 0 / NULL when the SDK did not bind that family */
/* ltl: sdk_lifecycle */
static void call_UpnpGetServerPort(payload in) {
    (void)in;
    if (!sdk) return;
    REPORT(UpnpGetServerPort, UpnpGetServerPort(), rc != 0);
}
/* ltl: sdk_lifecycle */
static void call_UpnpGetServerPort6(payload in) {
    (void)in;
    if (!sdk) return;
    REPORT(UpnpGetServerPort6, UpnpGetServerPort6(), rc != 0);
}
/* ltl: sdk_lifecycle */
static void call_UpnpGetServerUlaGuaPort6(payload in) {
    (void)in;
    if (!sdk) return;
    REPORT(UpnpGetServerUlaGuaPort6, UpnpGetServerUlaGuaPort6(), rc != 0);
}
/* ltl: sdk_lifecycle */
static void call_UpnpGetSsdpReqPort4(payload in) {
    (void)in;
    if (!sdk) return;
    REPORT(UpnpGetSsdpReqPort4, UpnpGetSsdpReqPort4(), rc != 0);
}
/* ltl: sdk_lifecycle */
static void call_UpnpGetSsdpReqPort6(payload in) {
    (void)in;
    if (!sdk) return;
    REPORT(UpnpGetSsdpReqPort6, UpnpGetSsdpReqPort6(), rc != 0);
}
/* ltl: sdk_lifecycle */
static void call_UpnpGetServerIpAddress(payload in) {
    (void)in;
    if (!sdk) return;
    REPORT_PTR(UpnpGetServerIpAddress, UpnpGetServerIpAddress());
}
/* ltl: sdk_lifecycle */
static void call_UpnpGetServerIp6Address(payload in) {
    (void)in;
    if (!sdk) return;
    REPORT_PTR(UpnpGetServerIp6Address, UpnpGetServerIp6Address());
}
/* ltl: sdk_lifecycle */
static void call_UpnpGetServerUlaGuaIp6Address(payload in) {
    (void)in;
    if (!sdk) return;
    REPORT_PTR(UpnpGetServerUlaGuaIp6Address, UpnpGetServerUlaGuaIp6Address());
}

/* web server */
/* ltl: sdk_lifecycle */
static void call_UpnpSetWebServerRootDir(payload in) {
    if (!sdk) return;
    REPORT(UpnpSetWebServerRootDir, UpnpSetWebServerRootDir(field(s1, sizeof s1, in, 0)), rc == UPNP_E_SUCCESS);
}
/* ltl: sdk_lifecycle */
static void call_UpnpSetWebServerCorsString(payload in) {
    if (!sdk) return;
    REPORT(UpnpSetWebServerCorsString, UpnpSetWebServerCorsString(field(s1, sizeof s1, in, 0)),
           rc == UPNP_E_SUCCESS);
}
/* web_server_init (webserver.c:536-542) clears the virtual-dir callbacks when it re-initialises */
/* ltl: sdk_lifecycle, virtual_dir_callbacks */
static void call_UpnpEnableWebserver(payload in) {
    if (!sdk) return;
    vd_cbs = 0;
    REPORT(UpnpEnableWebserver, UpnpEnableWebserver(byte(in, 0) & 1), rc == UPNP_E_SUCCESS);
}
/* ltl: sdk_lifecycle */
static void call_UpnpIsWebserverEnabled(payload in) {
    (void)in;
    if (!sdk) return;
    REPORT_VOID(UpnpIsWebserverEnabled, UpnpIsWebserverEnabled());
}
/* ltl: sdk_lifecycle */
static void call_UpnpSetHostValidateCallback(payload in) {
    if (!sdk) return;
    REPORT_VOID(UpnpSetHostValidateCallback, UpnpSetHostValidateCallback(byte(in, 0) & 1 ? host_ok : NULL, NULL));
}
/* ltl: sdk_lifecycle */
static void call_UpnpSetAllowLiteralHostRedirection(payload in) {
    if (!sdk) return;
    REPORT_VOID(UpnpSetAllowLiteralHostRedirection, UpnpSetAllowLiteralHostRedirection(byte(in, 0) & 1));
}
/* ltl: sdk_lifecycle */
static void call_UpnpSetMaxContentLength(payload in) {
    if (!sdk) return;
    size_t n = (size_t)byte(in, 0) | (size_t)byte(in, 1) << 8 | (size_t)byte(in, 2) << 16;
    REPORT(UpnpSetMaxContentLength, UpnpSetMaxContentLength(n), rc == UPNP_E_SUCCESS);
}
/* ltl: sdk_lifecycle, virtual_dir_callbacks */
static void call_UpnpVirtualDir_set_GetInfoCallback(payload in) {
    (void)in;
    if (!sdk) return;
    REPORT(UpnpVirtualDir_set_GetInfoCallback, UpnpVirtualDir_set_GetInfoCallback(vd_get_info), rc == UPNP_E_SUCCESS);
    vd_cbs |= 1;
}
/* ltl: sdk_lifecycle, virtual_dir_callbacks */
static void call_UpnpVirtualDir_set_OpenCallback(payload in) {
    (void)in;
    if (!sdk) return;
    REPORT(UpnpVirtualDir_set_OpenCallback, UpnpVirtualDir_set_OpenCallback(vd_open), rc == UPNP_E_SUCCESS);
    vd_cbs |= 2;
}
/* ltl: sdk_lifecycle, virtual_dir_callbacks */
static void call_UpnpVirtualDir_set_ReadCallback(payload in) {
    (void)in;
    if (!sdk) return;
    REPORT(UpnpVirtualDir_set_ReadCallback, UpnpVirtualDir_set_ReadCallback(vd_read), rc == UPNP_E_SUCCESS);
    vd_cbs |= 4;
}
/* ltl: sdk_lifecycle, virtual_dir_callbacks */
static void call_UpnpVirtualDir_set_WriteCallback(payload in) {
    (void)in;
    if (!sdk) return;
    REPORT(UpnpVirtualDir_set_WriteCallback, UpnpVirtualDir_set_WriteCallback(vd_write), rc == UPNP_E_SUCCESS);
    vd_cbs |= 8;
}
/* ltl: sdk_lifecycle, virtual_dir_callbacks */
static void call_UpnpVirtualDir_set_SeekCallback(payload in) {
    (void)in;
    if (!sdk) return;
    REPORT(UpnpVirtualDir_set_SeekCallback, UpnpVirtualDir_set_SeekCallback(vd_seek), rc == UPNP_E_SUCCESS);
    vd_cbs |= 16;
}
/* ltl: sdk_lifecycle, virtual_dir_callbacks */
static void call_UpnpVirtualDir_set_CloseCallback(payload in) {
    (void)in;
    if (!sdk) return;
    REPORT(UpnpVirtualDir_set_CloseCallback, UpnpVirtualDir_set_CloseCallback(vd_close), rc == UPNP_E_SUCCESS);
    vd_cbs |= 32;
}
/* upnp.h:2870-2873: requests under a virtual directory are served through the registered callbacks;
 * webserver.c:1347 and httpreadwrite.c:594-633 call them without a NULL check */
/* ltl: sdk_lifecycle, virtual_dir_callbacks */
static void call_UpnpAddVirtualDir(payload in) {
    if (!sdk || vd_cbs != 63) return;
    const void *old = NULL;
    REPORT(UpnpAddVirtualDir, UpnpAddVirtualDir(field(s1, sizeof s1, in, 0), NULL, &old), rc == UPNP_E_SUCCESS);
}
/* ltl: sdk_lifecycle */
static void call_UpnpRemoveVirtualDir(payload in) {
    if (!sdk) return;
    REPORT(UpnpRemoveVirtualDir, UpnpRemoveVirtualDir(field(s1, sizeof s1, in, 0)), rc == UPNP_E_SUCCESS);
}
/* ltl: sdk_lifecycle */
static void call_UpnpRemoveAllVirtualDirs(payload in) {
    (void)in;
    if (!sdk) return;
    REPORT_VOID(UpnpRemoveAllVirtualDirs, UpnpRemoveAllVirtualDirs());
}

/* device: one handle at a time */
/* ltl: sdk_lifecycle, device_handle */
static void call_UpnpRegisterRootDevice(payload in) {
    if (!sdk || dev_ok) return;
    const char *u = own_url(nurl, sizeof nurl, in, 0);
    if (!preqed_call("UpnpRegisterRootDevice")) return;
    int rc = UpnpRegisterRootDevice(u, dev_cb, NULL, &dev);
    preqed_result("UpnpRegisterRootDevice", rc == UPNP_E_SUCCESS);
    dev_ok = rc == UPNP_E_SUCCESS;
}
/* byte 0: description type (buffer, file, URL), builtin/payload description, config_baseURL */
/* ltl: sdk_lifecycle, device_handle */
static void call_UpnpRegisterRootDevice2(payload in) {
    if (!sdk || dev_ok) return;
    uint8_t b = byte(in, 0);
    payload in2 = rest(in, 1);
    Upnp_DescType type = b % 3 == 0 ? UPNPREG_BUF_DESC : b % 3 == 1 ? UPNPREG_FILENAME_DESC : UPNPREG_URL_DESC;
    const char *d = (b & 8) ? builtin_desc : field(xml, sizeof xml, in2, 0);
    if (type == UPNPREG_FILENAME_DESC) {
        payload f = { (const uint8_t *)d, strlen(d) };
        write_file(f);
        d = FILE_PATH;
    } else if (type == UPNPREG_URL_DESC) {
        d = own_url(nurl, sizeof nurl, in2, 0);
    }
    if (!preqed_call("UpnpRegisterRootDevice2")) return;
    int rc = UpnpRegisterRootDevice2(type, d, strlen(d), (b >> 4) & 1, dev_cb, NULL, &dev);
    preqed_result("UpnpRegisterRootDevice2", rc == UPNP_E_SUCCESS);
    dev_ok = rc == UPNP_E_SUCCESS;
}
/* ltl: sdk_lifecycle, device_handle */
static void call_UpnpRegisterRootDevice3(payload in) {
    if (!sdk || dev_ok) return;
    const char *u = own_url(nurl, sizeof nurl, rest(in, 1), 0);
    if (!preqed_call("UpnpRegisterRootDevice3")) return;
    int rc = UpnpRegisterRootDevice3(u, dev_cb, NULL, &dev, byte(in, 0) & 1 ? AF_INET6 : AF_INET);
    preqed_result("UpnpRegisterRootDevice3", rc == UPNP_E_SUCCESS);
    dev_ok = rc == UPNP_E_SUCCESS;
}
/* ltl: sdk_lifecycle, device_handle */
static void call_UpnpRegisterRootDevice4(payload in) {
    if (!sdk || dev_ok) return;
    payload in2 = rest(in, 1);
    const char *u = own_url(nurl, sizeof nurl, in2, 0);
    const char *lower = own_url(nurl2, sizeof nurl2, in2, 1);
    if (!preqed_call("UpnpRegisterRootDevice4")) return;
    int rc = UpnpRegisterRootDevice4(u, dev_cb, NULL, &dev, byte(in, 0) & 1 ? AF_INET6 : AF_INET, lower);
    preqed_result("UpnpRegisterRootDevice4", rc == UPNP_E_SUCCESS);
    dev_ok = rc == UPNP_E_SUCCESS;
}
/* upnp.h: after UpnpUnRegisterRootDevice* the handle is no longer valid */
/* ltl: sdk_lifecycle, device_handle */
static void call_UpnpUnRegisterRootDevice(payload in) {
    (void)in;
    if (!sdk || !dev_ok) return;
    dev_ok = 0;
    REPORT(UpnpUnRegisterRootDevice, UpnpUnRegisterRootDevice(dev), rc == UPNP_E_SUCCESS);
}
/* ltl: sdk_lifecycle, device_handle */
static void call_UpnpUnRegisterRootDeviceLowPower(payload in) {
    if (!sdk || !dev_ok) return;
    dev_ok = 0;
    REPORT(UpnpUnRegisterRootDeviceLowPower,
           UpnpUnRegisterRootDeviceLowPower(dev, (int8_t)byte(in, 0), (int8_t)byte(in, 1), (int8_t)byte(in, 2)),
           rc == UPNP_E_SUCCESS);
}
/* ltl: sdk_lifecycle, device_handle */
static void call_UpnpSendAdvertisement(payload in) {
    if (!sdk || !dev_ok) return;
    REPORT(UpnpSendAdvertisement, UpnpSendAdvertisement(dev, 60 + byte(in, 0)), rc == UPNP_E_SUCCESS);
}
/* ltl: sdk_lifecycle, device_handle */
static void call_UpnpSendAdvertisementLowPower(payload in) {
    if (!sdk || !dev_ok) return;
    REPORT(UpnpSendAdvertisementLowPower,
           UpnpSendAdvertisementLowPower(dev, 60 + byte(in, 0), (int8_t)byte(in, 1), (int8_t)byte(in, 2),
                                         (int8_t)byte(in, 3)),
           rc == UPNP_E_SUCCESS);
}
/* ltl: sdk_lifecycle, device_handle */
static void call_UpnpSetMaxSubscriptions(payload in) {
    if (!sdk || !dev_ok) return;
    REPORT(UpnpSetMaxSubscriptions, UpnpSetMaxSubscriptions(dev, (int8_t)byte(in, 0)), rc == UPNP_E_SUCCESS);
}
/* ltl: sdk_lifecycle, device_handle */
static void call_UpnpSetMaxSubscriptionTimeOut(payload in) {
    if (!sdk || !dev_ok) return;
    REPORT(UpnpSetMaxSubscriptionTimeOut, UpnpSetMaxSubscriptionTimeOut(dev, (int8_t)byte(in, 0)),
           rc == UPNP_E_SUCCESS);
}
/* accepts the last subscription request the device callback saw, with one variable from the payload */
/* ltl: sdk_lifecycle, device_handle */
static void call_UpnpAcceptSubscription(payload in) {
    if (!sdk || !dev_ok) return;
    Upnp_SID s;
    char udn[NAME_SIZE], serv[NAME_SIZE];
    pthread_mutex_lock(&cb_mu);
    memcpy(s, req_sid, sizeof s);
    memcpy(udn, req_udn, sizeof udn);
    memcpy(serv, req_serv, sizeof serv);
    pthread_mutex_unlock(&cb_mu);
    const char *name[1] = { field(s1, sizeof s1, in, 0) };
    const char *val[1] = { field(s2, sizeof s2, in, 1) };
    REPORT(UpnpAcceptSubscription, UpnpAcceptSubscription(dev, udn, serv, name, val, 1, s), rc == UPNP_E_SUCCESS);
}
/* ltl: sdk_lifecycle, device_handle */
static void call_UpnpAcceptSubscriptionExt(payload in) {
    (void)in;
    if (!sdk || !dev_ok || !action) return;
    Upnp_SID s;
    char udn[NAME_SIZE], serv[NAME_SIZE];
    pthread_mutex_lock(&cb_mu);
    memcpy(s, req_sid, sizeof s);
    memcpy(udn, req_udn, sizeof udn);
    memcpy(serv, req_serv, sizeof serv);
    pthread_mutex_unlock(&cb_mu);
    REPORT(UpnpAcceptSubscriptionExt, UpnpAcceptSubscriptionExt(dev, udn, serv, action, s), rc == UPNP_E_SUCCESS);
}
/* ltl: sdk_lifecycle, device_handle */
static void call_UpnpNotify(payload in) {
    if (!sdk || !dev_ok) return;
    const char *name[1] = { field(s3, sizeof s3, in, 2) };
    const char *val[1] = { field(s4, sizeof s4, in, 3) };
    REPORT(UpnpNotify, UpnpNotify(dev, field(s1, sizeof s1, in, 0), field(s2, sizeof s2, in, 1), name, val, 1),
           rc == UPNP_E_SUCCESS);
}
/* ltl: sdk_lifecycle, device_handle */
static void call_UpnpNotifyExt(payload in) {
    if (!sdk || !dev_ok || !action) return;
    REPORT(UpnpNotifyExt, UpnpNotifyExt(dev, field(s1, sizeof s1, in, 0), field(s2, sizeof s2, in, 1), action),
           rc == UPNP_E_SUCCESS);
}

/* control point: one handle at a time; SOAP and GENA requests go to the own web server */
/* ltl: sdk_lifecycle, client_handle */
static void call_UpnpRegisterClient(payload in) {
    (void)in;
    if (!sdk || cp_ok) return;
    if (!preqed_call("UpnpRegisterClient")) return;
    int rc = UpnpRegisterClient(cp_cb, NULL, &cp);
    preqed_result("UpnpRegisterClient", rc == UPNP_E_SUCCESS);
    cp_ok = rc == UPNP_E_SUCCESS;
}
/* ltl: sdk_lifecycle, client_handle */
static void call_UpnpUnRegisterClient(payload in) {
    (void)in;
    if (!sdk || !cp_ok) return;
    cp_ok = 0;
    REPORT(UpnpUnRegisterClient, UpnpUnRegisterClient(cp), rc == UPNP_E_SUCCESS);
}
/* ltl: sdk_lifecycle, client_handle */
static void call_UpnpSearchAsync(payload in) {
    if (!sdk || !cp_ok) return;
    payload in2 = rest(in, 1);
    REPORT(UpnpSearchAsync, UpnpSearchAsync(cp, 1 + byte(in, 0) % 3, field(s1, sizeof s1, in2, 0), NULL),
           rc == UPNP_E_SUCCESS);
}
/* upnpapi.c:3018-3046 (SendActionEx) and 3097 (SendActionAsync): a non-NULL DevUDN is rejected. The Ex
 * variants send the live document as the SOAP header (upnp.h:1365, NULL means none, which is SendAction) */
/* ltl: sdk_lifecycle, client_handle */
static void call_UpnpSendAction(payload in) {
    if (!sdk || !cp_ok || !action) return;
    IXML_Document *resp = NULL;
    const char *u = own_url(nurl, sizeof nurl, in, 0);
    if (!preqed_call("UpnpSendAction")) return;
    int rc = UpnpSendAction(cp, u, field(s1, sizeof s1, in, 1), NULL, action, &resp);
    preqed_result("UpnpSendAction", rc == UPNP_E_SUCCESS);
    ixmlDocument_free(resp);
}
/* ltl: document_lifecycle, sdk_lifecycle, client_handle */
static void call_UpnpSendActionEx(payload in) {
    if (!sdk || !cp_ok || !action || !doc) return;
    IXML_Document *resp = NULL;
    const char *u = own_url(nurl, sizeof nurl, in, 0);
    if (!preqed_call("UpnpSendActionEx")) return;
    int rc = UpnpSendActionEx(cp, u, field(s1, sizeof s1, in, 1), NULL, doc, action, &resp);
    preqed_result("UpnpSendActionEx", rc == UPNP_E_SUCCESS);
    ixmlDocument_free(resp);
}
/* the async calls copy the action (upnpapi.c:3101-3122) */
/* ltl: sdk_lifecycle, client_handle */
static void call_UpnpSendActionAsync(payload in) {
    if (!sdk || !cp_ok || !action) return;
    const char *u = own_url(nurl, sizeof nurl, in, 0);
    REPORT(UpnpSendActionAsync, UpnpSendActionAsync(cp, u, field(s1, sizeof s1, in, 1), NULL, action, cp_cb, NULL),
           rc == UPNP_E_SUCCESS);
}
/* ltl: document_lifecycle, sdk_lifecycle, client_handle */
static void call_UpnpSendActionExAsync(payload in) {
    if (!sdk || !cp_ok || !action || !doc) return;
    const char *u = own_url(nurl, sizeof nurl, in, 0);
    REPORT(UpnpSendActionExAsync,
           UpnpSendActionExAsync(cp, u, field(s1, sizeof s1, in, 1), NULL, doc, action, cp_cb, NULL),
           rc == UPNP_E_SUCCESS);
}
/* ltl: sdk_lifecycle, client_handle */
static void call_UpnpGetServiceVarStatus(payload in) {
    if (!sdk || !cp_ok) return;
    DOMString v = NULL;
    const char *u = own_url(nurl, sizeof nurl, in, 0);
    if (!preqed_call("UpnpGetServiceVarStatus")) return;
    int rc = UpnpGetServiceVarStatus(cp, u, field(s1, sizeof s1, in, 1), &v);
    preqed_result("UpnpGetServiceVarStatus", rc == UPNP_E_SUCCESS);
    ixmlFreeDOMString(v);
}
/* ltl: sdk_lifecycle, client_handle */
static void call_UpnpGetServiceVarStatusAsync(payload in) {
    if (!sdk || !cp_ok) return;
    const char *u = own_url(nurl, sizeof nurl, in, 0);
    REPORT(UpnpGetServiceVarStatusAsync, UpnpGetServiceVarStatusAsync(cp, u, field(s1, sizeof s1, in, 1), cp_cb, NULL),
           rc == UPNP_E_SUCCESS);
}
/* ltl: sdk_lifecycle, client_handle */
static void call_UpnpSubscribe(payload in) {
    if (!sdk || !cp_ok) return;
    int timeout = (int8_t)byte(in, 0);
    const char *u = own_url(nurl, sizeof nurl, rest(in, 1), 0);
    REPORT(UpnpSubscribe, UpnpSubscribe(cp, u, &timeout, sid), rc == UPNP_E_SUCCESS);
}
/* ltl: sdk_lifecycle, client_handle */
static void call_UpnpSubscribeAsync(payload in) {
    if (!sdk || !cp_ok) return;
    const char *u = own_url(nurl, sizeof nurl, rest(in, 1), 0);
    REPORT(UpnpSubscribeAsync, UpnpSubscribeAsync(cp, u, (int8_t)byte(in, 0), cp_cb, NULL), rc == UPNP_E_SUCCESS);
}
/* ltl: sdk_lifecycle, client_handle */
static void call_UpnpRenewSubscription(payload in) {
    if (!sdk || !cp_ok) return;
    int timeout = (int8_t)byte(in, 0);
    REPORT(UpnpRenewSubscription, UpnpRenewSubscription(cp, &timeout, sid), rc == UPNP_E_SUCCESS);
}
/* ltl: sdk_lifecycle, client_handle */
static void call_UpnpRenewSubscriptionAsync(payload in) {
    if (!sdk || !cp_ok) return;
    REPORT(UpnpRenewSubscriptionAsync, UpnpRenewSubscriptionAsync(cp, (int8_t)byte(in, 0), sid, cp_cb, NULL),
           rc == UPNP_E_SUCCESS);
}
/* ltl: sdk_lifecycle, client_handle */
static void call_UpnpUnSubscribe(payload in) {
    (void)in;
    if (!sdk || !cp_ok) return;
    REPORT(UpnpUnSubscribe, UpnpUnSubscribe(cp, sid), rc == UPNP_E_SUCCESS);
}
/* ltl: sdk_lifecycle, client_handle */
static void call_UpnpUnSubscribeAsync(payload in) {
    (void)in;
    if (!sdk || !cp_ok) return;
    REPORT(UpnpUnSubscribeAsync, UpnpUnSubscribeAsync(cp, sid, cp_cb, NULL), rc == UPNP_E_SUCCESS);
}

/* HTTP client against the own web server; every timeout is 1 s */
/* ltl: sdk_lifecycle */
static void call_UpnpDownloadUrlItem(payload in) {
    if (!sdk) return;
    char *out = NULL;
    char ctype[LINE_SIZE];
    const char *u = own_url(nurl, sizeof nurl, in, 0);
    if (!preqed_call("UpnpDownloadUrlItem")) return;
    int rc = UpnpDownloadUrlItem(u, &out, ctype);
    preqed_result("UpnpDownloadUrlItem", rc == UPNP_E_SUCCESS);
    free(out);
}
/* ltl: document_lifecycle, sdk_lifecycle */
static void call_UpnpDownloadXmlDoc(payload in) {
    if (!sdk || doc) return;
    IXML_Document *d = NULL;
    const char *u = own_url(nurl, sizeof nurl, in, 0);
    if (!preqed_call("UpnpDownloadXmlDoc")) return;
    int rc = UpnpDownloadXmlDoc(u, &d);
    preqed_result("UpnpDownloadXmlDoc", rc == UPNP_E_SUCCESS && d != NULL);
    doc = d;
}
/* contentType points into the handle's response (httpreadwrite.c:1524-1529), it is not freed separately */
/* ltl: sdk_lifecycle, http_handle */
static void call_UpnpOpenHttpGet(payload in) {
    if (!sdk || conn) return;
    void *h = NULL;
    char *ctype = NULL;
    int len = 0, status = 0;
    const char *u = own_url(nurl, sizeof nurl, in, 0);
    if (!preqed_call("UpnpOpenHttpGet")) return;
    int rc = UpnpOpenHttpGet(u, &h, &ctype, &len, &status, 1);
    preqed_result("UpnpOpenHttpGet", rc == UPNP_E_SUCCESS);
    if (rc == UPNP_E_SUCCESS) {
        conn = h;
        conn_kind = CONN_GET;
    } else {
        drop_handle(h);
    }
}
/* ltl: sdk_lifecycle, http_handle */
static void call_UpnpOpenHttpGetProxy(payload in) {
    if (!sdk || conn) return;
    void *h = NULL;
    char *ctype = NULL;
    int len = 0, status = 0;
    const char *u = own_url(nurl, sizeof nurl, in, 0);
    const char *proxy = own_url(nurl2, sizeof nurl2, in, 1);
    if (!preqed_call("UpnpOpenHttpGetProxy")) return;
    int rc = UpnpOpenHttpGetProxy(u, proxy, &h, &ctype, &len, &status, 1);
    preqed_result("UpnpOpenHttpGetProxy", rc == UPNP_E_SUCCESS);
    if (rc == UPNP_E_SUCCESS) {
        conn = h;
        conn_kind = CONN_GET;
    } else {
        drop_handle(h);
    }
}
/* ltl: sdk_lifecycle, http_handle */
static void call_UpnpOpenHttpGetEx(payload in) {
    if (!sdk || conn) return;
    void *h = NULL;
    char *ctype = NULL;
    int len = 0, status = 0;
    const char *u = own_url(nurl, sizeof nurl, rest(in, 2), 0);
    if (!preqed_call("UpnpOpenHttpGetEx")) return;
    int rc = UpnpOpenHttpGetEx(u, &h, &ctype, &len, &status, byte(in, 0), byte(in, 0) + byte(in, 1), 1);
    preqed_result("UpnpOpenHttpGetEx", rc == UPNP_E_SUCCESS);
    if (rc == UPNP_E_SUCCESS) {
        conn = h;
        conn_kind = CONN_GET;
    } else {
        drop_handle(h);
    }
}
/* ltl: sdk_lifecycle, http_handle */
static void call_UpnpReadHttpGet(payload in) {
    if (!sdk || conn_kind != CONN_GET) return;
    size_t n = (size_t)byte(in, 0) * 16;
    REPORT(UpnpReadHttpGet, UpnpReadHttpGet(conn, nbuf, &n, 1), rc == UPNP_E_SUCCESS);
}
/* ltl: sdk_lifecycle, http_handle */
static void call_UpnpHttpGetProgress(payload in) {
    (void)in;
    if (!sdk || conn_kind != CONN_GET) return;
    size_t len = 0, total = 0;
    REPORT(UpnpHttpGetProgress, UpnpHttpGetProgress(conn, &len, &total), rc == UPNP_E_SUCCESS);
}
/* ltl: sdk_lifecycle, http_handle */
static void call_UpnpCancelHttpGet(payload in) {
    (void)in;
    if (!sdk || conn_kind != CONN_GET) return;
    REPORT(UpnpCancelHttpGet, UpnpCancelHttpGet(conn), rc == UPNP_E_SUCCESS);
}
/* ltl: sdk_lifecycle, http_handle */
static void call_UpnpCloseHttpGet(payload in) {
    (void)in;
    if (!sdk || conn_kind != CONN_GET) return;
    void *h = conn;
    conn = NULL;
    conn_kind = CONN_NONE;
    REPORT(UpnpCloseHttpGet, UpnpCloseHttpGet(h), rc == UPNP_E_SUCCESS);
}
/* ltl: sdk_lifecycle, http_handle */
static void call_UpnpOpenHttpConnection(payload in) {
    if (!sdk || conn) return;
    void *h = NULL;
    const char *u = own_url(nurl, sizeof nurl, in, 0);
    if (!preqed_call("UpnpOpenHttpConnection")) return;
    int rc = UpnpOpenHttpConnection(u, &h, 1);
    preqed_result("UpnpOpenHttpConnection", rc == UPNP_E_SUCCESS);
    if (rc == UPNP_E_SUCCESS) {
        conn = h;
        conn_kind = CONN_CONN;
        conn_state = REQ_IDLE;
    } else {
        drop_handle(h);
    }
}
/* upnp.h:2385-2389: a new request while one is being processed is undefined; end it first.
 * byte 0: method, byte 1: content length (UPNP_USING_CHUNKED, UPNP_UNTIL_CLOSE or a small size),
 * byte 2: send the harness UpnpString as the extra headers */
/* ltl: sdk_lifecycle, http_handle, http_request_order */
static void call_UpnpMakeHttpRequest(payload in) {
    if (!sdk || conn_kind != CONN_CONN || conn_state == REQ_OPEN) return;
    payload in2 = rest(in, 3);
    Upnp_HttpMethod m = (Upnp_HttpMethod)(byte(in, 0) % 5);
    uint8_t l = byte(in, 1);
    int len = l == 0xff ? UPNP_USING_CHUNKED : l == 0xfe ? UPNP_UNTIL_CLOSE : l;
    const char *u = own_url(nurl, sizeof nurl, in2, 0);
    const char *ctype = byte(in, 2) & 2 ? field(s1, sizeof s1, in2, 1) : NULL;
    if (!preqed_call("UpnpMakeHttpRequest")) return;
    int rc = UpnpMakeHttpRequest(m, u, conn, byte(in, 2) & 1 ? ustr : NULL, ctype, len, 1);
    preqed_result("UpnpMakeHttpRequest", rc == UPNP_E_SUCCESS);
    if (rc == UPNP_E_SUCCESS) conn_state = REQ_OPEN;
}
/* ltl: sdk_lifecycle, http_handle, http_request_order */
static void call_UpnpWriteHttpRequest(payload in) {
    if (!sdk || conn_kind != CONN_CONN || conn_state != REQ_OPEN) return;
    size_t n = in.n < sizeof nbuf ? in.n : sizeof nbuf;
    memcpy(nbuf, in.p, n);
    REPORT(UpnpWriteHttpRequest, UpnpWriteHttpRequest(conn, nbuf, &n, 1), rc == UPNP_E_SUCCESS);
}
/* ltl: sdk_lifecycle, http_handle, http_request_order */
static void call_UpnpEndHttpRequest(payload in) {
    (void)in;
    if (!sdk || conn_kind != CONN_CONN || conn_state != REQ_OPEN) return;
    conn_state = REQ_ENDED;
    REPORT(UpnpEndHttpRequest, UpnpEndHttpRequest(conn, 1), rc == UPNP_E_SUCCESS);
}
/* the response parser is set up by UpnpMakeHttpRequest (httpreadwrite.c:1419-1420) */
/* ltl: sdk_lifecycle, http_handle, http_request_order */
static void call_UpnpGetHttpResponse(payload in) {
    (void)in;
    if (!sdk || conn_kind != CONN_CONN || conn_state != REQ_ENDED) return;
    char *ctype = NULL;
    int len = 0, status = 0;
    if (!preqed_call("UpnpGetHttpResponse")) return;
    int rc = UpnpGetHttpResponse(conn, ustr2, &ctype, &len, &status, 1);
    preqed_result("UpnpGetHttpResponse", rc == UPNP_E_SUCCESS);
    conn_state = rc == UPNP_E_SUCCESS ? REQ_RESP : REQ_IDLE;
}
/* ltl: sdk_lifecycle, http_handle, http_request_order */
static void call_UpnpReadHttpResponse(payload in) {
    if (!sdk || conn_kind != CONN_CONN || conn_state != REQ_RESP) return;
    size_t n = (size_t)byte(in, 0) * 16;
    REPORT(UpnpReadHttpResponse, UpnpReadHttpResponse(conn, nbuf, &n, 1), rc == UPNP_E_SUCCESS);
}
/* ltl: sdk_lifecycle, http_handle, http_request_order */
static void call_UpnpCloseHttpConnection(payload in) {
    (void)in;
    if (!sdk || conn_kind != CONN_CONN) return;
    void *h = conn;
    conn = NULL;
    conn_kind = CONN_NONE;
    REPORT(UpnpCloseHttpConnection, UpnpCloseHttpConnection(h), rc == UPNP_E_SUCCESS);
}
/* upnpapi.c:3421-3423 passes `handle` (the caller's void **) instead of `*handle` to http_MakeHttpRequest,
 * so every successful connect corrupts the caller's memory (repro-net.c 1). Only the connect-failure path
 * runs here: port 1 of the own address has no listener. UpnpWriteHttpPost / UpnpCloseHttpPost need a handle
 * from a successful UpnpOpenHttpPost (upnp.h:2304-2305, 2330-2331), so they are not called. */
/* ltl: sdk_lifecycle, http_handle */
static void call_UpnpOpenHttpPost(payload in) {
    if (!sdk || conn) return;
    void *h = NULL;
    char path[512];
    snprintf(nurl, sizeof nurl, "http://%s:1/%s", UpnpGetServerIpAddress(), field(path, sizeof path, rest(in, 1), 0));
    if (!preqed_call("UpnpOpenHttpPost")) return;
    int rc = UpnpOpenHttpPost(nurl, &h, "text/xml", byte(in, 0), 1);
    preqed_result("UpnpOpenHttpPost", rc == UPNP_E_SUCCESS);
    drop_handle(h);
}

/* SDK teardown at the end of an input, and the globals that survive UpnpFinish */
static void net_cleanup(void) {
    if (sdk) {
        drop_conn();
        UpnpSetMaxContentLength(DEFAULT_CONTENT_LENGTH);
        UpnpFinish();
        sdk_gone();
    }
    UpnpSetHostValidateCallback(NULL, NULL);
    UpnpSetAllowLiteralHostRedirection(0);
    /* DEFAULT_MAX_JOBS_TOTAL, ThreadPool.h:122; UpnpInit2 sizes its pools from it */
    UpnpSetMaxJobsTotal(1000);
}

/* dispatch */

static void (*const api[])(payload) = {
    call_ixmlNode_getNodeName, call_ixmlNode_getNodeValue, call_ixmlNode_setNodeValue, call_ixmlNode_getNodeType,
    call_ixmlNode_getParentNode, call_ixmlNode_getChildNodes, call_ixmlNode_getFirstChild, call_ixmlNode_getLastChild,
    call_ixmlNode_getPreviousSibling, call_ixmlNode_getNextSibling, call_ixmlNode_getAttributes,
    call_ixmlNode_getOwnerDocument, call_ixmlNode_getNamespaceURI, call_ixmlNode_getPrefix, call_ixmlNode_getLocalName,
    call_ixmlNode_insertBefore, call_ixmlNode_replaceChild, call_ixmlNode_removeChild, call_ixmlNode_appendChild,
    call_ixmlNode_hasChildNodes, call_ixmlNode_cloneNode, call_ixmlNode_hasAttributes, call_ixmlNode_free,
#ifdef IXML_HAVE_SCRIPTSUPPORT
    call_ixmlNode_setCTag, call_ixmlNode_getCTag,
#endif
    call_ixmlAttr_free, call_ixmlCDATASection_free,
    call_ixmlDocument_createDocumentEx, call_ixmlDocument_createDocument,
    call_ixmlDocument_createElementEx, call_ixmlDocument_createElement, call_ixmlDocument_createTextNodeEx,
    call_ixmlDocument_createTextNode, call_ixmlDocument_createCDATASectionEx, call_ixmlDocument_createCDATASection,
    call_ixmlDocument_createAttribute, call_ixmlDocument_createAttributeEx, call_ixmlDocument_createElementNSEx,
    call_ixmlDocument_createElementNS, call_ixmlDocument_createAttributeNSEx, call_ixmlDocument_createAttributeNS,
    call_ixmlDocument_getElementsByTagName, call_ixmlDocument_getElementsByTagNameNS, call_ixmlDocument_getElementById,
    call_ixmlDocument_free, call_ixmlDocument_importNode,
    call_ixmlElement_getTagName, call_ixmlElement_getAttribute, call_ixmlElement_setAttribute,
    call_ixmlElement_removeAttribute, call_ixmlElement_getAttributeNode, call_ixmlElement_setAttributeNode,
    call_ixmlElement_removeAttributeNode, call_ixmlElement_getElementsByTagName, call_ixmlElement_getAttributeNS,
    call_ixmlElement_setAttributeNS, call_ixmlElement_removeAttributeNS, call_ixmlElement_getAttributeNodeNS,
    call_ixmlElement_setAttributeNodeNS, call_ixmlElement_getElementsByTagNameNS, call_ixmlElement_hasAttribute,
    call_ixmlElement_hasAttributeNS, call_ixmlElement_free,
    call_ixmlNamedNodeMap_getLength, call_ixmlNamedNodeMap_getNamedItem, call_ixmlNamedNodeMap_item,
    call_ixmlNamedNodeMap_free, call_ixmlNodeList_item, call_ixmlNodeList_length, call_ixmlNodeList_free,
    call_ixmlPrintDocument, call_ixmlPrintNode, call_ixmlDocumenttoString, call_ixmlNodetoString, call_ixmlRelaxParser,
#ifdef IXML_HAVE_SCRIPTSUPPORT
    call_ixmlSetBeforeFree,
#endif
    call_ixmlParseBuffer, call_ixmlParseBufferEx, call_ixmlLoadDocument, call_ixmlLoadDocumentEx,
    call_ixmlCloneDOMString, call_ixmlFreeDOMString,
    call_UpnpGetErrorMessage, call_UpnpSetMaxJobsTotal, call_UpnpResolveURL, call_UpnpResolveURL2, call_UpnpMakeAction,
    call_UpnpMakeActionResponse, call_UpnpAddToAction, call_UpnpAddToActionResponse, call_UpnpCreatePropertySet,
    call_UpnpAddToPropertySet,
    call_UpnpString_new, call_UpnpString_delete, call_UpnpString_dup, call_UpnpString_assign,
    call_UpnpString_get_Length, call_UpnpString_set_Length, call_UpnpString_get_String, call_UpnpString_set_String,
    call_UpnpString_set_StringN, call_UpnpString_clear, call_UpnpString_cmp, call_UpnpString_casecmp,
    call_UpnpListInit, call_UpnpListBegin, call_UpnpListEnd, call_UpnpListNext, call_UpnpListInsert, call_UpnpListErase,
    OPS_LIFE(UpnpActionComplete), OPS_INT(UpnpActionComplete, ErrCode), OPS_STR(UpnpActionComplete, CtrlUrl),
    OPS_DOC(UpnpActionComplete, ActionRequest), OPS_DOC(UpnpActionComplete, ActionResult),
    OPS_LIFE(UpnpActionRequest), OPS_INT(UpnpActionRequest, ErrCode), OPS_INT(UpnpActionRequest, Socket),
    OPS_STR(UpnpActionRequest, ErrStr), OPS_STR(UpnpActionRequest, ActionName), OPS_STR(UpnpActionRequest, DevUDN),
    OPS_STR(UpnpActionRequest, ServiceID), OPS_DOC(UpnpActionRequest, ActionRequest),
    OPS_DOC(UpnpActionRequest, ActionResult), OPS_DOC(UpnpActionRequest, SoapHeader),
    OPS_ADDR(UpnpActionRequest, CtrlPtIPAddr), OPS_STR(UpnpActionRequest, Os),
    OPS_LIFE(UpnpDiscovery), OPS_INT(UpnpDiscovery, ErrCode), OPS_INT(UpnpDiscovery, Expires),
    OPS_STR(UpnpDiscovery, DeviceID), OPS_STR(UpnpDiscovery, DeviceType), OPS_STR(UpnpDiscovery, ServiceType),
    OPS_STR(UpnpDiscovery, ServiceVer), OPS_STR(UpnpDiscovery, Location), OPS_STR(UpnpDiscovery, Os),
    OPS_STR(UpnpDiscovery, Date), OPS_STR(UpnpDiscovery, Ext), OPS_ADDR(UpnpDiscovery, DestAddr),
    OPS_LIFE(UpnpEvent), OPS_INT(UpnpEvent, EventKey), OPS_DOC(UpnpEvent, ChangedVariables), OPS_STR(UpnpEvent, SID),
    OPS_LIFE(UpnpEventSubscribe), OPS_INT(UpnpEventSubscribe, ErrCode), OPS_INT(UpnpEventSubscribe, TimeOut),
    OPS_STR(UpnpEventSubscribe, SID), OPS_STR(UpnpEventSubscribe, PublisherUrl),
    OPS_LIFE(UpnpStateVarComplete), OPS_INT(UpnpStateVarComplete, ErrCode), OPS_STR(UpnpStateVarComplete, CtrlUrl),
    OPS_STR(UpnpStateVarComplete, StateVarName), OPS_DOM(UpnpStateVarComplete, CurrentVal),
    OPS_LIFE(UpnpStateVarRequest), OPS_INT(UpnpStateVarRequest, ErrCode), OPS_INT(UpnpStateVarRequest, Socket),
    OPS_STR(UpnpStateVarRequest, ErrStr), OPS_STR(UpnpStateVarRequest, DevUDN), OPS_STR(UpnpStateVarRequest, ServiceID),
    OPS_STR(UpnpStateVarRequest, StateVarName), OPS_ADDR(UpnpStateVarRequest, CtrlPtIPAddr),
    OPS_DOM(UpnpStateVarRequest, CurrentVal),
    OPS_LIFE(UpnpSubscriptionRequest), OPS_STR(UpnpSubscriptionRequest, ServiceId), OPS_STR(UpnpSubscriptionRequest, UDN),
    OPS_STR(UpnpSubscriptionRequest, SID),
    OPS_LIFE(UpnpExtraHeaders), call_UpnpExtraHeaders_get_node, call_UpnpExtraHeaders_set_node,
    call_UpnpExtraHeaders_add_to_list_node, OPS_STR(UpnpExtraHeaders, name), OPS_STR(UpnpExtraHeaders, value),
    OPS_DOM(UpnpExtraHeaders, resp),
    OPS_LIFE(UpnpFileInfo), OPS_INT(UpnpFileInfo, FileLength), OPS_INT(UpnpFileInfo, LastModified),
    OPS_INT(UpnpFileInfo, IsDirectory), OPS_INT(UpnpFileInfo, IsReadable), OPS_DOM(UpnpFileInfo, ContentType),
    call_UpnpFileInfo_get_ExtraHeadersList, call_UpnpFileInfo_set_ExtraHeadersList,
    call_UpnpFileInfo_add_to_list_ExtraHeadersList, OPS_ADDR(UpnpFileInfo, CtrlPtIPAddr), OPS_STR(UpnpFileInfo, Os),
    call_UpnpInit2, call_UpnpFinish, call_UpnpGetServerPort, call_UpnpGetServerPort6, call_UpnpGetServerUlaGuaPort6,
    call_UpnpGetSsdpReqPort4, call_UpnpGetSsdpReqPort6, call_UpnpGetServerIpAddress, call_UpnpGetServerIp6Address,
    call_UpnpGetServerUlaGuaIp6Address,
    call_UpnpSetWebServerRootDir, call_UpnpSetWebServerCorsString, call_UpnpEnableWebserver, call_UpnpIsWebserverEnabled,
    call_UpnpSetHostValidateCallback, call_UpnpSetAllowLiteralHostRedirection, call_UpnpSetMaxContentLength,
    call_UpnpVirtualDir_set_GetInfoCallback, call_UpnpVirtualDir_set_OpenCallback, call_UpnpVirtualDir_set_ReadCallback,
    call_UpnpVirtualDir_set_WriteCallback, call_UpnpVirtualDir_set_SeekCallback, call_UpnpVirtualDir_set_CloseCallback,
    call_UpnpAddVirtualDir, call_UpnpRemoveVirtualDir, call_UpnpRemoveAllVirtualDirs,
    call_UpnpRegisterRootDevice, call_UpnpRegisterRootDevice2, call_UpnpRegisterRootDevice3, call_UpnpRegisterRootDevice4,
    call_UpnpUnRegisterRootDevice, call_UpnpUnRegisterRootDeviceLowPower, call_UpnpSendAdvertisement,
    call_UpnpSendAdvertisementLowPower, call_UpnpSetMaxSubscriptions, call_UpnpSetMaxSubscriptionTimeOut,
    call_UpnpAcceptSubscription, call_UpnpAcceptSubscriptionExt, call_UpnpNotify, call_UpnpNotifyExt,
    call_UpnpRegisterClient, call_UpnpUnRegisterClient, call_UpnpSearchAsync, call_UpnpSendAction, call_UpnpSendActionEx,
    call_UpnpSendActionAsync, call_UpnpSendActionExAsync, call_UpnpGetServiceVarStatus, call_UpnpGetServiceVarStatusAsync,
    call_UpnpSubscribe, call_UpnpSubscribeAsync, call_UpnpRenewSubscription, call_UpnpRenewSubscriptionAsync,
    call_UpnpUnSubscribe, call_UpnpUnSubscribeAsync,
    call_UpnpDownloadUrlItem, call_UpnpDownloadXmlDoc, call_UpnpOpenHttpGet, call_UpnpOpenHttpGetProxy,
    call_UpnpOpenHttpGetEx, call_UpnpReadHttpGet, call_UpnpHttpGetProgress, call_UpnpCancelHttpGet, call_UpnpCloseHttpGet,
    call_UpnpOpenHttpConnection, call_UpnpMakeHttpRequest, call_UpnpWriteHttpRequest, call_UpnpEndHttpRequest,
    call_UpnpGetHttpResponse, call_UpnpReadHttpResponse, call_UpnpCloseHttpConnection, call_UpnpOpenHttpPost,
};

#define API_COUNT (sizeof api / sizeof api[0])

static void cleanup(void) {
    net_cleanup();
    free_objects();
    if (str) ixmlFreeDOMString(str);
    drop_views();
    if (loose) ixmlNode_free(loose);
    if (doc) ixmlDocument_free(doc);
    if (action) ixmlDocument_free(action);
    if (ustr) UpnpString_delete(ustr);
    if (ustr2) UpnpString_delete(ustr2);
    str = NULL;
    loose = NULL;
    doc = action = NULL;
    node = NULL;
    ustr = ustr2 = NULL;
    ixmlRelaxParser(0);
#ifdef IXML_HAVE_SCRIPTSUPPORT
    ixmlSetBeforeFree(NULL);
#endif
    unlink(FILE_PATH);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    preqed_reset();
    UpnpListInit(&head);
    memset(elts_used, 0, sizeof elts_used);
    size_t off = 0;
    /* records: 2-byte op (the table has more than 256 entries), 2-byte payload length, payload */
    while (size - off >= 4) {
        size_t op = (size_t)data[off] | (size_t)data[off + 1] << 8;
        size_t len = (size_t)data[off + 2] | (size_t)data[off + 3] << 8;
        off += 4;
        if (len > size - off) break;
        payload in = { data + off, len };
        api[op % API_COUNT](in);
        off += len;
    }
    cleanup();
    return 0;
}
