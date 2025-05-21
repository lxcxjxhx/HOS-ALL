#ifndef ATTACK_EXECUTOR_H
#define ATTACK_EXECUTOR_H

#include <ai_payload_generator.h>

typedef struct {
    char *content;
    int status_code;
} response_t;

response_t *execute_attack(const char *url, const char *method, const char *payload);
void free_response(response_t *response);

#endif
