#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <attack_executor.h>
#include <logger.h>
#include <utils.h>

static size_t write_callback(void *contents, size_t size, size_t nmemb, char **userp) {
    size_t realsize = size * nmemb;
    char *ptr = realloc(*userp, strlen(*userp) + realsize + 1);
    if (!ptr) return 0;
    *userp = ptr;
    memcpy(ptr + strlen(ptr), contents, realsize);
    ptr[strlen(ptr) + realsize] = 0;
    return realsize;
}

response_t *execute_attack(const char *url, const char *method, const char *payload) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;

    response_t *response = malloc(sizeof(response_t));
    response->content = calloc(1, 1);
    response->status_code = 0;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response->content);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5);

    if (strcmp(method, "POST") == 0) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    } else if (strcmp(method, "GET") == 0) {
        char *url_with_params = concat(url, "?");
        url_with_params = concat(url_with_params, payload);
        curl_easy_setopt(curl, CURLOPT_URL, url_with_params);
        free(url_with_params);
    } else {
        log_event("ATTACK_ERROR", "Unsupported method");
        free(response->content);
        free(response);
        curl_easy_cleanup(curl);
        return NULL;
    }

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        log_event("ATTACK_FAILED", curl_easy_strerror(res));
        free(response->content);
        free(response);
        curl_easy_cleanup(curl);
        return NULL;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response->status_code);
    curl_easy_cleanup(curl);

    char log_msg[512];
    snprintf(log_msg, sizeof(log_msg), "Attack executed: %s %s", method, url);
    log_event("ATTACK_EXECUTED", log_msg);

    return response;
}

void free_response(response_t *response) {
    if (response) {
        free(response->content);
        free(response);
    }
}
