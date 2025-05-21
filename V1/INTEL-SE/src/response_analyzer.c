#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <response_analyzer.h>
#include <logger.h>

analysis_t *analyze_response(response_t *response, const char *vuln_type) {
    analysis_t *analysis = malloc(sizeof(analysis_t));
    if (!response) {
        analysis->success = 0;
        analysis->details = strdup("No response received");
        return analysis;
    }

    analysis->success = 0;
    analysis->details = NULL;

    if (strcmp(vuln_type, "sql_injection") == 0) {
        if (strstr(response->content, "error") || strstr(response->content, "sql")) {
            analysis->success = 1;
            analysis->details = strdup("SQL error detected in response");
        }
    } else if (strcmp(vuln_type, "xss") == 0) {
        if (strstr(response->content, "<script>")) {
            analysis->success = 1;
            analysis->details = strdup("XSS payload reflected in response");
        }
    } else if (strcmp(vuln_type, "file_inclusion") == 0) {
        if (strstr(response->content, "/etc/passwd")) {
            analysis->success = 1;
            analysis->details = strdup("File inclusion detected");
        }
    }

    if (!analysis->details) {
        analysis->details = strdup("No vulnerability detected");
    }

    char log_msg[512];
    snprintf(log_msg, sizeof(log_msg), "Analysis for %s: %s", vuln_type, analysis->details);
    log_event("ANALYSIS_RESULT", log_msg);

    return analysis;
}

void free_analysis(analysis_t *analysis) {
    if (analysis) {
        free(analysis->details);
        free(analysis);
    }
}
