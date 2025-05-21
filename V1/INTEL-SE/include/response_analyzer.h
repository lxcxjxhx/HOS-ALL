#ifndef RESPONSE_ANALYZER_H
#define RESPONSE_ANALYZER_H

#include <attack_executor.h>

typedef struct {
    int success;
    char *details;
} analysis_t;

analysis_t *analyze_response(response_t *response, const char *vuln_type);
void free_analysis(analysis_t *analysis);

#endif
