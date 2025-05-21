#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <ai_payload_generator.h>
#include <config_parser.h>
#include <logger.h>
#include <utils.h>
#include <rag_processor.h>

static char *build_prompt(const char *url, const char *vuln_type, char **params, int param_count, int waf_bypass, const char *rag_context) {
    char params_str[256] = "";
    for (int i = 0; i < param_count; i++) {
        strcat(params_str, params[i]);
        if (i < param_count - 1) strcat(params_str, ", ");
    }
    char *prompt = malloc(1024);
    snprintf(prompt, 1024,
             "You are a security expert generating attack payloads.\n"
             "Input:\n- Target URL: %s\n- Vulnerability Type: %s\n- Parameters: [%s]\n- WAF Bypass: %d\n- RAG Context: %s\n"
             "Output format:\n```json\n{\n    \"Payload\": \"<specific payload>\",\n"
             "    \"Explanation\": \"<why this payload, expected effect>\",\n"
             "    \"RAG_Context\": \"<used context>\"\n}\n```",
             url, vuln_type, params_str, waf_bypass, rag_context ? rag_context : "None");
    return prompt;
}

static char *call_ollama(const char *prompt) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "echo '%s' | ollama run llama", prompt);
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        log_event("OLLAMA_ERROR", "Failed to call Ollama");
        return NULL;
    }
    char *result = malloc(1024);
    size_t len = 0;
    while (fgets(result + len, 1024 - len, fp)) {
        len += strlen(result + len);
    }
    pclose(fp);
    return result;
}

static size_t write_callback(void *contents, size_t size, size_t nmemb, char **userp) {
    size_t realsize = size * nmemb;
    char *ptr = realloc(*userp, strlen(*userp) + realsize + 1);
    if (!ptr) return 0;
    *userp = ptr;
    memcpy(ptr + strlen(ptr), contents, realsize);
    ptr[strlen(ptr) + realsize] = 0;
    return realsize;
}

static char *call_api(const char *prompt, const char *api_key, const char *endpoint, const char *model) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;

    char *response = calloc(1, 1);
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, concat("Authorization: Bearer ", api_key));
    headers = curl_slist_append(headers, "Content-Type: application/json");

    char post_data[1024];
    snprintf(post_data, sizeof(post_data), "{\"prompt\": \"%s\", \"model\": \"%s\"}", prompt, model);

    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        log_event("API_ERROR", curl_easy_strerror(res));
        free(response);
        response = NULL;
    } else {
        cJSON *json = cJSON_Parse(response);
        if (json) {
            cJSON *choices = cJSON_GetObjectItem(json, "choices");
            if (choices && choices->child && choices->child->child) {
                char *text = cJSON_GetObjectItem(choices->child, "text")->valuestring;
                free(response);
                response = strdup(text);
            } else {
                free(response);
                response = NULL;
            }
            cJSON_Delete(json);
        }
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return response;
}

payload_t *generate_payload(const char *url, const char *vuln_type, char **params, int param_count, int waf_bypass) {
    config_t *config = parse_configs();
    if (!config) return NULL;

    // RAG: Extract text from docs
    char *rag_context = extract_text_from_docs("/home/lxcxjxhx/PROJECT/INTEL-SE/docs");
    char *prompt = build_prompt(url, vuln_type, params, param_count, waf_bypass, rag_context);
    char *raw_result = NULL;

    if (strcmp(config->ai_model, "ollama") == 0) {
        raw_result = call_ollama(prompt);
    } else if (strcmp(config->ai_model, "deepseek") == 0) {
        raw_result = call_api(prompt, config->deepseek_api_key, "https://api.deepseek.com/v1/completions", "deepseek-rag");
    } else if (strcmp(config->ai_model, "claude") == 0) {
        raw_result = call_api(prompt, config->claude_api_key, "https://api.anthropic.com/v1/complete", "claude-3.7");
    } else if (strcmp(config->ai_model, "gemini") == 0) {
        raw_result = call_api(prompt, config->gemini_api_key, "https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent", "gemini-pro");
    } else if (strcmp(config->ai_model, "grok") == 0) {
        raw_result = call_api(prompt, config->grok_api_key, "https://api.x.ai/v1/grok", "grok");
    } else if (strcmp(config->ai_model, "ironheart") == 0) {
        raw_result = call_api(prompt, "", config->ironheart_endpoint, "ironheart");
    }

    free(prompt);
    if (!raw_result) {
        if (rag_context) free(rag_context);
        free_config(config);
        return NULL;
    }

    cJSON *json = cJSON_Parse(raw_result);
    if (!json) {
        log_event("JSON_ERROR", "Failed to parse AI response");
        free(raw_result);
        if (rag_context) free(rag_context);
        free_config(config);
        return NULL;
    }

    cJSON *payload_item = cJSON_GetObjectItem(json, "Payload");
    cJSON *explanation_item = cJSON_GetObjectItem(json, "Explanation");
    cJSON *rag_context_item = cJSON_GetObjectItem(json, "RAG_Context");
    if (!payload_item || !explanation_item || !rag_context_item) {
        log_event("JSON_ERROR", "Missing Payload, Explanation, or RAG_Context in response");
        cJSON_Delete(json);
        free(raw_result);
        if (rag_context) free(rag_context);
        free_config(config);
        return NULL;
    }

    payload_t *payload = malloc(sizeof(payload_t));
    payload->payload = strdup(payload_item->valuestring);
    payload->explanation = strdup(explanation_item->valuestring);
    payload->rag_context = strdup(rag_context_item->valuestring);

    cJSON_Delete(json);
    free(raw_result);
    if (rag_context) free(rag_context);
    free_config(config);
    return payload;
}

void free_payload(payload_t *payload) {
    if (payload) {
        free(payload->payload);
        free(payload->explanation);
        free(payload->rag_context);
        free(payload);
    }
}
