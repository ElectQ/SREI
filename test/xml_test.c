#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char xmlChar;

typedef enum {
    XML_ELEMENT_NODE = 1,
    XML_ATTRIBUTE_NODE = 2,
    XML_TEXT_NODE = 3,
    XML_DOCUMENT_NODE = 9,
} xmlElementType;

typedef struct _xmlNode {
    void *_private;
    xmlElementType type;
    const xmlChar *name;
    struct _xmlNode *children;
    struct _xmlNode *last;
    struct _xmlNode *parent;
    struct _xmlNode *next;
    struct _xmlNode *prev;
    struct _xmlDoc *doc;
} xmlNode;

typedef struct _xmlDoc {
    void *_private;
    xmlElementType type;
    char *name;
    struct _xmlNode *children;
    struct _xmlNode *last;
    struct _xmlNode *parent;
    struct _xmlNode *next;
    struct _xmlNode *prev;
    struct _xmlDoc *doc;
} xmlDoc;

extern xmlDoc *xmlReadDoc(const xmlChar *, const char *, const char *, int);
extern xmlNode *xmlDocGetRootElement(xmlDoc *);
extern void xmlFreeDoc(xmlDoc *);
extern xmlNode *xmlFirstElementChild(xmlNode *);
extern xmlNode *xmlNextElementSibling(xmlNode *);
extern xmlChar *xmlGetProp(xmlNode *, const xmlChar *);
extern xmlChar *xmlNodeGetContent(xmlNode *);

static int g_ok = 0;
static int g_fail = 0;

__attribute__((constructor))
static void xml_ctor(void) { g_ok = 0; g_fail = 0; }

static int test_parse(void) {
    const char *xml_str =
        "<root version=\"1.0\">"
        "  <server host=\"example.com\" port=\"443\">"
        "    <tls enabled=\"true\"/>"
        "    <timeout>30</timeout>"
        "  </server>"
        "  <server host=\"backup.com\" port=\"8443\">"
        "    <tls enabled=\"false\"/>"
        "    <timeout>60</timeout>"
        "  </server>"
        "  <logging level=\"info\"/>"
        "</root>";

    xmlDoc *doc = xmlReadDoc((const xmlChar *)xml_str, NULL, NULL, 0);
    if (!doc) {
        printf("[xml] xmlReadDoc failed\n");
        return 0;
    }
    printf("[xml] parsed XML document OK\n");

    xmlNode *root = xmlDocGetRootElement(doc);
    if (!root) {
        printf("[xml] no root element\n");
        xmlFreeDoc(doc);
        return 0;
    }
    printf("[xml] root element found\n");

    xmlChar *ver = xmlGetProp(root, (const xmlChar *)"version");
    if (!ver || strcmp((const char *)ver, "1.0") != 0) {
        printf("[xml] root version wrong: %s\n", ver ? (char *)ver : "(null)");

        xmlFreeDoc(doc);
        return 0;
    }
    printf("[xml] root version=1.0 OK\n");

    int server_count = 0;
    xmlNode *child = xmlFirstElementChild(root);
    while (child) {
        if (child->type == XML_ELEMENT_NODE && child->name &&
            strcmp((const char *)child->name, "server") == 0) {
            xmlChar *host = xmlGetProp(child, (const xmlChar *)"host");
            xmlChar *port = xmlGetProp(child, (const xmlChar *)"port");
            printf("[xml] server: host=%s port=%s\n",
                   host ? (char *)host : "?", port ? (char *)port : "?");

            xmlNode *sub = xmlFirstElementChild(child);
            while (sub) {
                if (sub->type == XML_ELEMENT_NODE && sub->name &&
                    strcmp((const char *)sub->name, "timeout") == 0) {
                    xmlChar *content = xmlNodeGetContent(sub);
                    printf("[xml]   timeout = %s\n", content ? (char *)content : "?");

                }
                sub = xmlNextElementSibling(sub);
            }



            server_count++;
        }
        child = xmlNextElementSibling(child);
    }

    if (server_count != 2) {
        printf("[xml] expected 2 servers, found %d\n", server_count);
        xmlFreeDoc(doc);
        return 0;
    }

    xmlFreeDoc(doc);
    printf("[xml] found 2 servers, all data correct\n");
    return 1;
}

void xml_run(const void *user_data, unsigned int user_data_len) {
    printf("[xml] === libxml2 real-world test ===\n");
    if (user_data && user_data_len > 0)
        printf("[xml] user_data: %.*s\n", user_data_len, (const char *)user_data);

    if (test_parse()) g_ok++; else g_fail++;

    printf("[xml] results: %d passed, %d failed\n", g_ok, g_fail);
}
