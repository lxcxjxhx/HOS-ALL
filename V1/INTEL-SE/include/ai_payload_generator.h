#ifndef AI_PAYLOAD_GENERATOR_H
#define AI_PAYLOAD_GENERATOR_H

typedef struct {
    char *payload;
    char *explanation;
    char *rag_context; // RAG-extracted context
} payload_t;

payload_t* generate_payload(const char *url, const char *vuln_type, char **parameters, int param_count, int waf_bypass);
void free_payload(payload_t *payload);

#endif
