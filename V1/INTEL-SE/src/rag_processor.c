#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <poppler.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <rag_processor.h>
#include <logger.h>

static char* extract_pdf_text(const char *path) {
    GError *error = NULL;
    char *uri = g_filename_to_uri(path, NULL, &error);
    if (!uri) {
        log_event("RAG_ERROR", "Failed to convert path to URI");
        if (error) g_error_free(error);
        return NULL;
    }
    PopplerDocument *doc = poppler_document_new_from_file(uri, NULL, &error);
    g_free(uri);
    if (!doc) {
        log_event("RAG_ERROR", "Failed to open PDF");
        if (error) g_error_free(error);
        return NULL;
    }

    char *text = malloc(4096);
    if (!text) {
        g_object_unref(doc);
        return NULL;
    }
    text[0] = '\0';
    int n_pages = poppler_document_get_n_pages(doc);
    for (int i = 0; i < n_pages && strlen(text) < 4000; i++) {
        PopplerPage *page = poppler_document_get_page(doc, i);
        if (page) {
            char *page_text = poppler_page_get_text(page);
            if (page_text) {
                strncat(text, page_text, 4000 - strlen(text) - 1);
                g_free(page_text);
            }
            g_object_unref(page);
        }
    }
    g_object_unref(doc);
    return text;
}

static char* extract_docx_text(const char *path) {
    xmlDoc *doc = xmlReadFile(path, NULL, 0);
    if (!doc) {
        log_event("RAG_ERROR", "Failed to open DOCX");
        return NULL;
    }

    char *text = malloc(4096);
    if (!text) {
        xmlFreeDoc(doc);
        return NULL;
    }
    text[0] = '\0';
    xmlNode *root = xmlDocGetRootElement(doc);
    for (xmlNode *node = root->children; node && strlen(text) < 4000; node = node->next) {
        if (node->type == XML_TEXT_NODE && node->content) {
            strncat(text, (char*)node->content, 4000 - strlen(text) - 1);
        }
    }
    xmlFreeDoc(doc);
    return text;
}

char* extract_text_from_docs(const char *directory) {
    DIR *dir = opendir(directory);
    if (!dir) {
        log_event("RAG_ERROR", "Failed to open docs directory");
        return NULL;
    }

    char *all_text = malloc(16384);
    if (!all_text) {
        closedir(dir);
        return NULL;
    }
    all_text[0] = '\0';
    struct dirent *entry;
    while ((entry = readdir(dir)) && strlen(all_text) < 16000) {
        if (entry->d_type != DT_REG) continue;
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
        char *text = NULL;
        if (strstr(entry->d_name, ".pdf")) {
            text = extract_pdf_text(path);
        } else if (strstr(entry->d_name, ".docx")) {
            text = extract_docx_text(path);
        }
        if (text) {
            strncat(all_text, text, 16000 - strlen(all_text) - 1);
            free(text);
        }
    }
    closedir(dir);
    if (strlen(all_text) == 0) {
        free(all_text);
        return NULL;
    }
    return all_text;
}
