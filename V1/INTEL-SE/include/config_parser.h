#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

typedef struct {
    char *url;
    char **vuln_types;
    int vuln_type_count;
    char **parameters;
    int param_count;
    int waf_bypass;
} target_t;

typedef struct {
    char *ai_model;
    char *deepseek_api_key;
    char *claude_api_key;
    char *gemini_api_key;
    char *grok_api_key;
    char *ironheart_endpoint;
    char *logging_level;
    int waf_bypass_enabled;
    int max_retries;
    target_t *targets;
    int target_count;
} config_t;

config_t *parse_configs();
void free_config(config_t *config);

#endif
