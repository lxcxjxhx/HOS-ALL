#include <stdio.h>
#include <stdlib.h>
#include "include/attack_executor.h"

int main() {
    response_t *response = execute_attack("http://example.com", "GET", "q=test");
    if (response) {
        printf("Response Code: %d\n", response->status_code);
        free_response(response);
        return 0;
    }
    printf("Test failed: No response received\n");
    return 1;
}
