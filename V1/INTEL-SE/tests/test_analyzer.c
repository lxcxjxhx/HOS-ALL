#include <stdio.h>
#include <stdlib.h>
#include "include/response_analyzer.h"
#include "include/attack_executor.h"

int main() {
    response_t *response = execute_attack("http://example.com", "GET", "q=test");
    if (response) {
        analysis_t *result = analyze_response(response, "sql_injection");
        printf("Analysis: %s\n", result->details);
        free_analysis(result);
        free_response(response);
        return 0;
    }
    printf("Test failed: No response received\n");
    return 1;
}
