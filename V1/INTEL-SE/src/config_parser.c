#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yaml.h>
#include <config_parser.h>
#include <logger.h>

config_t *parse_configs() {
    config_t *config = malloc(sizeof(config_t));
    if (!config) return NULL;

    config->ai_model = NULL;
    config->deepseek_api_key = NULL;
    config->claude_api_key = NULL;
    config->gemini_api_key = NULL;
    config->grok_api_key = NULL;
    config->ironheart_endpoint = NULL;
    config->logging_level = NULL;
    config->waf_bypass_enabled = 0;
    config->max_retries = 3;
    config->targets = NULL;
    config->target_count = 0;

    FILE *file = fopen("/home/lxcxjxhx/PROJECT/INTEL-SE/config/settings.yaml", "r");
    if (!file) {
        log_event("CONFIG_ERROR", "Failed to open settings.yaml");
        free(config);
        return NULL;
    }

    yaml_parser_t parser;
    yaml_document_t document;
    if (!yaml_parser_initialize(&parser)) {
        fclose(file);
        free(config);
        return NULL;
    }

    yaml_parser_set_input_file(&parser, file);
    if (!yaml_parser_load(&parser, &document)) {
        yaml_parser_delete(&parser);
        fclose(file);
        free(config);
        return NULL;
    }

    yaml_node_t *root = yaml_document_get_root_node(&document);
    if (root && root->type == YAML_MAPPING_NODE) {
        for (yaml_node_pair_t *pair = root->data.mapping.pairs.start; pair < root->data.mapping.pairs.top; pair++) {
            yaml_node_t *key = yaml_document_get_node(&document, pair->key);
            yaml_node_t *value = yaml_document_get_node(&document, pair->value);
            if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE) {
                const char *key_str = (const char *)key->data.scalar.value;
                const char *value_str = (const char *)value->data.scalar.value;
                if (strcmp(key_str, "ai_model") == 0) config->ai_model = strdup(value_str);
                else if (strcmp(key_str, "deepseek_api_key") == 0) config->deepseek_api_key = strdup(value_str);
                else if (strcmp(key_str, "claude_api_key") == 0) config->claude_api_key = strdup(value_str);
                else if (strcmp(key_str, "gemini_api_key") == 0) config->gemini_api_key = strdup(value_str);
                else if (strcmp(key_str, "grok_api_key") == 0) config->grok_api_key = strdup(value_str);
                else if (strcmp(key_str, "ironheart_endpoint") == 0) config->ironheart_endpoint = strdup(value_str);
                else if (strcmp(key_str, "logging_level") == 0) config->logging_level = strdup(value_str);
                else if (strcmp(key_str, "waf_bypass_enabled") == 0) config->waf_bypass_enabled = strcmp(value_str, "true") == 0;
                else if (strcmp(key_str, "max_retries") == 0) config->max_retries = atoi(value_str);
            }
        }
    }

    yaml_document_delete(&document);
    yaml_parser_delete(&parser);
    fclose(file);

    file = fopen("/home/lxcxjxhx/PROJECT/INTEL-SE/config/sites.yaml", "r");
    if (!file) {
        log_event("CONFIG_ERROR", "Failed to open sites.yaml");
        free_config(config);
        return NULL;
    }

    if (!yaml_parser_initialize(&parser)) {
        fclose(file);
        free_config(config);
        return NULL;
    }

    yaml_parser_set_input_file(&parser, file);
    if (!yaml_parser_load(&parser, &document)) {
        yaml_parser_delete(&parser);
        fclose(file);
        free_config(config);
        return NULL;
    }

    root = yaml_document_get_root_node(&document);
    if (root && root->type == YAML_MAPPING_NODE) {
        yaml_node_t *targets_node = NULL;
        for (yaml_node_pair_t *pair = root->data.mapping.pairs.start; pair < root->data.mapping.pairs.top; pair++) {
            yaml_node_t *key = yaml_document_get_node(&document, pair->key);
            if (key->type == YAML_SCALAR_NODE && strcmp((const char *)key->data.scalar.value, "targets") == 0) {
                targets_node = yaml_document_get_node(&document, pair->value);
                break;
            }
        }
        if (targets_node && targets_node->type == YAML_SEQUENCE_NODE) {
            config->target_count = targets_node->data.sequence.items.top - targets_node->data.sequence.items.start;
            config->targets = malloc(config->target_count * sizeof(target_t));
            int i = 0;
            for (yaml_node_item_t *item = targets_node->data.sequence.items.start; item < targets_node->data.sequence.items.top; item++) {
                yaml_node_t *target_node = yaml_document_get_node(&document, *item);
                if (target_node->type == YAML_MAPPING_NODE) {
                    target_t *target = &config->targets[i++];
                    target->url = NULL;
                    target->vuln_types = NULL;
                    target->vuln_type_count = 0;
                    target->parameters = NULL;
                    target->param_count = 0;
                    target->waf_bypass = 0;
                    for (yaml_node_pair_t *pair = target_node->data.mapping.pairs.start; pair < target_node->data.mapping.pairs.top; pair++) {
                        yaml_node_t *key = yaml_document_get_node(&document, pair->key);
                        yaml_node_t *value = yaml_document_get_node(&document, pair->value);
                        if (key->type == YAML_SCALAR_NODE) {
                            const char *key_str = (const char *)key->data.scalar.value;
                            if (strcmp(key_str, "url") == 0 && value->type == YAML_SCALAR_NODE) {
                                target->url = strdup((const char *)value->data.scalar.value);
                            } else if (strcmp(key_str, "vuln_types") == 0 && value->type == YAML_SEQUENCE_NODE) {
                                target->vuln_type_count = value->data.sequence.items.top - value->data.sequence.items.start;
                                target->vuln_types = malloc(target->vuln_type_count * sizeof(char *));
                                int j = 0;
                                for (yaml_node_item_t *v_item = value->data.sequence.items.start; v_item < value->data.sequence.items.top; v_item++) {
                                    yaml_node_t *v_node = yaml_document_get_node(&document, *v_item);
                                    if (v_node->type == YAML_SCALAR_NODE) {
                                        target->vuln_types[j++] = strdup((const char *)v_node->data.scalar.value);
                                    }
                                }
                            } else if (strcmp(key_str, "parameters") == 0 && value->type == YAML_SEQUENCE_NODE) {
                                target->param_count = value->data.sequence.items.top - value->data.sequence.items.start;
                                target->parameters = malloc(target->param_count * sizeof(char *));
                                int j = 0;
                                for (yaml_node_item_t *p_item = value->data.sequence.items.start; p_item < value->data.sequence.items.top; p_item++) {
                                    yaml_node_t *p_node = yaml_document_get_node(&document, *p_item);
                                    if (p_node->type == YAML_SCALAR_NODE) {
                                        target->parameters[j++] = strdup((const char *)p_node->data.scalar.value);
                                    }
                                }
                            } else if (strcmp(key_str, "waf_bypass") == 0 && value->type == YAML_SCALAR_NODE) {
                                target->waf_bypass = strcmp((const char *)value->data.scalar.value, "true") == 0;
                            }
                        }
                    }
                }
            }
        }
    }

    yaml_document_delete(&document);
    yaml_parser_delete(&parser);
    fclose(file);

    return config;
}

void free_config(config_t *config) {
    if (!config) return;
    free(config->ai_model);
    free(config->deepseek_api_key);
    free(config->claude_api_key);
    free(config->gemini_api_key);
    free(config->grok_api_key);
    free(config->ironheart_endpoint);
    free(config->logging_level);
    for (int i = 0; i < config->target_count; i++) {
        free(config->targets[i].url);
        for (int j = 0; j < config->targets[i].vuln_type_count; j++) {
            free(config->targets[i].vuln_types[j]);
        }
        free(config->targets[i].vuln_types);
        for (int j = 0; j < config->targets[i].param_count; j++) {
            free(config->targets[i].parameters[j]);
        }
        free(config->targets[i].parameters);
    }
    free(config->targets);
    free(config);
}
