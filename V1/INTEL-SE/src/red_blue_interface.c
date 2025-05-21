#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <red_blue_interface.h>
#include <logger.h>

char *suggest_defense(analysis_t *attack_result) {
    if (!attack_result || !attack_result->success) {
        return strdup("No defense needed: No vulnerability detected");
    }

    char *defense = NULL;
    if (strstr(attack_result->details, "SQL")) {
        defense = strdup("Implement prepared statements and input sanitization to prevent SQL injection");
    } else if (strstr(attack_result->details, "XSS")) {
        defense = strdup("Use output encoding and Content Security Policy (CSP) to prevent XSS");
    } else if (strstr(attack_result->details, "File inclusion")) {
        defense = strdup("Restrict file access and validate file paths to prevent file inclusion");
    } else {
        defense = strdup("Review application logs and apply general security best practices");
    }

    char log_msg[512];
    snprintf(log_msg, sizeof(log_msg), "Defense suggestion: %s", defense);
    log_event("DEFENSE_SUGGESTION", log_msg);

    return defense;
}
