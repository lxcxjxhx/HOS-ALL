#include <stdio.h>
#include <stdlib.h>
#include "include/ai_payload_generator.h"

int main() {
    char *params[] = {"username"};
    payload_t *payload = generate_payload("http://example.com", "sql_injection", params, 1, 0);
    if (payload) {
        printf("Payload: %s\nExplanation: %s\n", payload->payload, payload->explanation);
        free_payload(payload);
        return 0;
    }
    printf("Test failed: No payload generated\n");
    return 1;
}
