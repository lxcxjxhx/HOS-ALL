#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <ui.h>
#include <config_parser.h>
#include <ai_payload_generator.h>
#include <attack_executor.h>
#include <response_analyzer.h>
#include <logger.h>
#include <utils.h>
#include <rag_processor.h>

static AppWidgets *app_widgets;

static void apply_css() {
    GtkCssProvider *provider = gtk_css_provider_new();
    const char *css = 
        "* { font-family: Inter, Source Sans Pro, sans-serif; }"
        "window { background-color: " THEME_BG "; }"
        "box { background-color: " THEME_BG "; }"
        "textview { background-color: " THEME_BG "; color: " THEME_TEXT "; padding: 12px; font-family: Monospace; border-radius: 6px; box-shadow: inset 0 2px 4px rgba(0,0,0,0.2); }"
        "button { background-color: " THEME_BUTTON "; color: " THEME_TEXT "; border: 1px solid " THEME_ACCENT "; border-radius: 8px; padding: 10px; margin: 4px; font-weight: 600; box-shadow: 0 2px 4px rgba(0,0,0,0.1); transition: background-color 0.2s; }"
        "button:active { background-color: #C0C0C0; box-shadow: inset 0 2px 4px rgba(0,0,0,0.2); }"
        "entry { background-color: " THEME_BUTTON "; color: " THEME_TEXT "; border: 1px solid " THEME_ACCENT "; border-radius: 6px; padding: 8px; }"
        "label { color: " THEME_TEXT "; font-weight: 700; font-size: 12px; }"
        "scrolledwindow { border: 1px solid " THEME_ACCENT "; border-radius: 6px; background-color: " THEME_BG "; }"
        "dropdown { background-color: " THEME_BUTTON "; color: " THEME_TEXT "; border: 1px solid " THEME_ACCENT "; border-radius: 6px; padding: 8px; font-weight: 600; }";
    gtk_css_provider_load_from_string(provider, css);
    gtk_style_context_add_provider_for_display(gdk_display_get_default(),
                                              GTK_STYLE_PROVIDER(provider),
                                              GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(provider);
}

static void save_config(const char *model, const char *deepseek_key, const char *claude_key,
                        const char *gemini_key, const char *grok_key, const char *ironheart_endpoint) {
    FILE *fp = fopen("/home/lxcxjxhx/PROJECT/INTEL-SE/config/settings.yaml", "w");
    if (fp) {
        fprintf(fp, "ai_model: \"%s\"\n", model);
        fprintf(fp, "deepseek_api_key: \"%s\"\n", deepseek_key);
        fprintf(fp, "claude_api_key: \"%s\"\n", claude_key);
        fprintf(fp, "gemini_api_key: \"%s\"\n", gemini_key);
        fprintf(fp, "grok_api_key: \"%s\"\n", grok_key);
        fprintf(fp, "ironheart_endpoint: \"%s\"\n", ironheart_endpoint);
        fprintf(fp, "logging_level: \"INFO\"\n");
        fprintf(fp, "waf_bypass_enabled: %s\n", app_widgets->config->waf_bypass_enabled ? "true" : "false");
        fprintf(fp, "max_retries: %d\n", app_widgets->config->max_retries);
        fclose(fp);
        log_event("CONFIG_SAVED", "Settings updated");
    }
}

static void on_model_dialog_response(GtkWidget *button, gpointer dialog) {
    GtkWidget *model_dropdown = g_object_get_data(G_OBJECT(dialog), "model_dropdown");
    GtkWidget *deepseek_entry = g_object_get_data(G_OBJECT(dialog), "deepseek_entry");
    GtkWidget *claude_entry = g_object_get_data(G_OBJECT(dialog), "claude_entry");
    GtkWidget *gemini_entry = g_object_get_data(G_OBJECT(dialog), "gemini_entry");
    GtkWidget *grok_entry = g_object_get_data(G_OBJECT(dialog), "grok_entry");
    GtkWidget *ironheart_entry = g_object_get_data(G_OBJECT(dialog), "ironheart_entry");

    if (g_strcmp0(gtk_widget_get_name(button), "save_button") == 0) {
        guint selected = gtk_drop_down_get_selected(GTK_DROP_DOWN(model_dropdown));
        GtkStringList *string_list = GTK_STRING_LIST(gtk_drop_down_get_model(GTK_DROP_DOWN(model_dropdown)));
        const char *model = gtk_string_list_get_string(string_list, selected);
        save_config(model,
                    gtk_editable_get_text(GTK_EDITABLE(deepseek_entry)),
                    gtk_editable_get_text(GTK_EDITABLE(claude_entry)),
                    gtk_editable_get_text(GTK_EDITABLE(gemini_entry)),
                    gtk_editable_get_text(GTK_EDITABLE(grok_entry)),
                    gtk_editable_get_text(GTK_EDITABLE(ironheart_entry)));
    }
    gtk_window_destroy(GTK_WINDOW(dialog));
}

static void show_model_config_dialog(GtkWidget *button, gpointer data) {
    GtkWidget *dialog = gtk_window_new();
    gtk_window_set_title(GTK_WINDOW(dialog), "AI Model Configuration");
    gtk_window_set_transient_for(GTK_WINDOW(dialog), GTK_WINDOW(app_widgets->window));
    gtk_window_set_modal(GTK_WINDOW(dialog), TRUE);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 400, 320);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_margin_start(box, 12);
    gtk_widget_set_margin_end(box, 12);
    gtk_widget_set_margin_top(box, 12);
    gtk_widget_set_margin_bottom(box, 12);
    gtk_window_set_child(GTK_WINDOW(dialog), box);

    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 12);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 12);
    gtk_box_append(GTK_BOX(box), grid);

    GtkWidget *model_label = gtk_label_new("Model:");
    gtk_widget_set_halign(model_label, GTK_ALIGN_START);
    GtkWidget *model_dropdown = gtk_drop_down_new_from_strings(
        (const char *[]){"deepseek", "ollama", "claude", "gemini", "grok", "ironheart", NULL});
    gtk_drop_down_set_selected(GTK_DROP_DOWN(model_dropdown), 0);

    GtkWidget *deepseek_label = gtk_label_new("DeepSeek API Key:");
    gtk_widget_set_halign(deepseek_label, GTK_ALIGN_START);
    GtkWidget *deepseek_entry = gtk_entry_new();
    gtk_editable_set_text(GTK_EDITABLE(deepseek_entry), app_widgets->config->deepseek_api_key ? app_widgets->config->deepseek_api_key : "");

    GtkWidget *claude_label = gtk_label_new("Claude API Key:");
    gtk_widget_set_halign(claude_label, GTK_ALIGN_START);
    GtkWidget *claude_entry = gtk_entry_new();
    gtk_editable_set_text(GTK_EDITABLE(claude_entry), app_widgets->config->claude_api_key ? app_widgets->config->claude_api_key : "");

    GtkWidget *gemini_label = gtk_label_new("Gemini API Key:");
    gtk_widget_set_halign(gemini_label, GTK_ALIGN_START);
    GtkWidget *gemini_entry = gtk_entry_new();
    gtk_editable_set_text(GTK_EDITABLE(gemini_entry), app_widgets->config->gemini_api_key ? app_widgets->config->gemini_api_key : "");

    GtkWidget *grok_label = gtk_label_new("Grok API Key:");
    gtk_widget_set_halign(grok_label, GTK_ALIGN_START);
    GtkWidget *grok_entry = gtk_entry_new();
    gtk_editable_set_text(GTK_EDITABLE(grok_entry), app_widgets->config->grok_api_key ? app_widgets->config->grok_api_key : "");

    GtkWidget *ironheart_label = gtk_label_new("IronHeart Endpoint:");
    gtk_widget_set_halign(ironheart_label, GTK_ALIGN_START);
    GtkWidget *ironheart_entry = gtk_entry_new();
    gtk_editable_set_text(GTK_EDITABLE(ironheart_entry), app_widgets->config->ironheart_endpoint ? app_widgets->config->ironheart_endpoint : "");

    gtk_grid_attach(GTK_GRID(grid), model_label, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), model_dropdown, 1, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), deepseek_label, 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), deepseek_entry, 1, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), claude_label, 0, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), claude_entry, 1, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), gemini_label, 0, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), gemini_entry, 1, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), grok_label, 0, 4, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), grok_entry, 1, 4, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), ironheart_label, 0, 5, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), ironheart_entry, 1, 5, 1, 1);

    GtkWidget *button_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_box_set_homogeneous(GTK_BOX(button_box), TRUE);
    gtk_widget_set_halign(button_box, GTK_ALIGN_END);
    gtk_box_append(GTK_BOX(box), button_box);

    GtkWidget *save_button = gtk_button_new_with_label("Save");
    gtk_widget_set_name(save_button, "save_button");
    GtkWidget *cancel_button = gtk_button_new_with_label("Cancel");
    gtk_box_append(GTK_BOX(button_box), cancel_button);
    gtk_box_append(GTK_BOX(button_box), save_button);

    g_object_set_data(G_OBJECT(dialog), "model_dropdown", model_dropdown);
    g_object_set_data(G_OBJECT(dialog), "deepseek_entry", deepseek_entry);
    g_object_set_data(G_OBJECT(dialog), "claude_entry", claude_entry);
    g_object_set_data(G_OBJECT(dialog), "gemini_entry", gemini_entry);
    g_object_set_data(G_OBJECT(dialog), "grok_entry", grok_entry);
    g_object_set_data(G_OBJECT(dialog), "ironheart_entry", ironheart_entry);

    g_signal_connect(save_button, "clicked", G_CALLBACK(on_model_dialog_response), dialog);
    g_signal_connect(cancel_button, "clicked", G_CALLBACK(on_model_dialog_response), dialog);

    gtk_window_present(GTK_WINDOW(dialog));
}

static void on_file_dialog_response(GtkWidget *button, gpointer dialog) {
    GtkWidget *dir_entry = g_object_get_data(G_OBJECT(dialog), "dir_entry");
    if (g_strcmp0(gtk_widget_get_name(button), "save_button") == 0) {
        const char *dir = gtk_editable_get_text(GTK_EDITABLE(dir_entry));
        char log_msg[512];
        snprintf(log_msg, sizeof(log_msg), "Docs directory set to: %s", dir);
        log_event("CONFIG", log_msg);
    }
    gtk_window_destroy(GTK_WINDOW(dialog));
}

static void show_file_config_dialog(GtkWidget *button, gpointer data) {
    GtkWidget *dialog = gtk_window_new();
    gtk_window_set_title(GTK_WINDOW(dialog), "File Configuration");
    gtk_window_set_transient_for(GTK_WINDOW(dialog), GTK_WINDOW(app_widgets->window));
    gtk_window_set_modal(GTK_WINDOW(dialog), TRUE);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 400, 140);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_margin_start(box, 12);
    gtk_widget_set_margin_end(box, 12);
    gtk_widget_set_margin_top(box, 12);
    gtk_widget_set_margin_bottom(box, 12);
    gtk_window_set_child(GTK_WINDOW(dialog), box);

    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 12);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 12);
    gtk_box_append(GTK_BOX(box), grid);

    GtkWidget *dir_label = gtk_label_new("Docs Directory:");
    gtk_widget_set_halign(dir_label, GTK_ALIGN_START);
    GtkWidget *dir_entry = gtk_entry_new();
    gtk_editable_set_text(GTK_EDITABLE(dir_entry), "/home/lxcxjxhx/PROJECT/INTEL-SE/docs");

    gtk_grid_attach(GTK_GRID(grid), dir_label, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), dir_entry, 1, 0, 1, 1);

    GtkWidget *button_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_box_set_homogeneous(GTK_BOX(button_box), TRUE);
    gtk_widget_set_halign(button_box, GTK_ALIGN_END);
    gtk_box_append(GTK_BOX(box), button_box);

    GtkWidget *save_button = gtk_button_new_with_label("Save");
    gtk_widget_set_name(save_button, "save_button");
    GtkWidget *cancel_button = gtk_button_new_with_label("Cancel");
    gtk_box_append(GTK_BOX(button_box), cancel_button);
    gtk_box_append(GTK_BOX(button_box), save_button);

    g_object_set_data(G_OBJECT(dialog), "dir_entry", dir_entry);
    g_signal_connect(save_button, "clicked", G_CALLBACK(on_file_dialog_response), dialog);
    g_signal_connect(cancel_button, "clicked", G_CALLBACK(on_file_dialog_response), dialog);

    gtk_window_present(GTK_WINDOW(dialog));
}

static void run_attack(GtkWidget *widget, gpointer data) {
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app_widgets->output_view));
    GtkTextBuffer *shell_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app_widgets->shell_view));
    FILE *payload_log = fopen("/home/lxcxjxhx/PROJECT/INTEL-SE/logs/payloads.log", "a");

    for (int i = 0; i < app_widgets->config->target_count; i++) {
        target_t *target = &app_widgets->config->targets[i];
        for (int j = 0; j < target->vuln_type_count; j++) {
            payload_t *payload = generate_payload(target->url, target->vuln_types[j], 
                                                target->parameters, target->param_count, 
                                                target->waf_bypass);
            char payload_msg[1024];
            if (!payload) {
                snprintf(payload_msg, sizeof(payload_msg), "Failed to generate payload for %s (%s)\n", 
                         target->url, target->vuln_types[j]);
                gtk_text_buffer_insert_at_cursor(buffer, payload_msg, -1);
                gtk_text_buffer_insert_at_cursor(shell_buffer, payload_msg, -1);
                if (payload_log) fprintf(payload_log, "%s", payload_msg);
                log_event("PAYLOAD_FAIL", payload_msg);
                continue;
            }

            snprintf(payload_msg, sizeof(payload_msg), "Generated payload for %s (%s): %s\nExplanation: %s\nRAG Context: %s\n", 
                     target->url, target->vuln_types[j], payload->payload, payload->explanation, payload->rag_context);
            gtk_text_buffer_insert_at_cursor(buffer, payload_msg, -1);
            gtk_text_buffer_insert_at_cursor(shell_buffer, payload_msg, -1);
            if (payload_log) fprintf(payload_log, "%s", payload_msg);
            log_event("PAYLOAD_GENERATED", payload_msg);

            response_t *response = execute_attack(target->url, "POST", payload->payload);
            if (!response) {
                snprintf(payload_msg, sizeof(payload_msg), "Attack failed on %s (%s)\n", 
                         target->url, target->vuln_types[j]);
                gtk_text_buffer_insert_at_cursor(buffer, payload_msg, -1);
                gtk_text_buffer_insert_at_cursor(shell_buffer, payload_msg, -1);
                if (payload_log) fprintf(payload_log, "%s", payload_msg);
                log_event("ATTACK_FAIL", payload_msg);
                free_payload(payload);
                continue;
            }

            analysis_t *result = analyze_response(response, target->vuln_types[j]);
            snprintf(payload_msg, sizeof(payload_msg), "Attack on %s (%s): %s\n", 
                     target->url, target->vuln_types[j], result->details);
            gtk_text_buffer_insert_at_cursor(buffer, payload_msg, -1);
            gtk_text_buffer_insert_at_cursor(shell_buffer, payload_msg, -1);
            if (payload_log) fprintf(payload_log, "%s", payload_msg);
            log_event("ATTACK_RESULT", payload_msg);

            free_analysis(result);
            free_response(response);
            free_payload(payload);
        }
    }
    if (payload_log) fclose(payload_log);
}

static void process_documents(GtkWidget *widget, gpointer data) {
    GtkTextBuffer *shell_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app_widgets->shell_view));
    char *text = extract_text_from_docs("/home/lxcxjxhx/PROJECT/INTEL-SE/docs");
    char output[2048];
    if (text) {
        snprintf(output, sizeof(output), "Processed documents. Extracted text length: %lu\n", strlen(text));
        free(text);
    } else {
        snprintf(output, sizeof(output), "No documents processed or error occurred\n");
    }
    gtk_text_buffer_insert_at_cursor(shell_buffer, output, -1);
    log_event("RAG_PROCESS", output);
}

static const char* detect_platform(void) {
    struct utsname uname_data;
    if (uname(&uname_data) == 0) {
        if (strstr(uname_data.sysname, "Linux")) return "Linux";
        if (strstr(uname_data.sysname, "Windows")) return "Windows";
        if (strstr(uname_data.sysname, "Android")) return "Android";
    }
    return "Unknown";
}

static void execute_shell_command(GtkWidget *widget, gpointer data) {
    GtkEntry *shell_entry = GTK_ENTRY(g_object_get_data(G_OBJECT(widget), "shell_entry"));
    GtkTextBuffer *shell_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app_widgets->shell_view));
    const char *command = gtk_editable_get_text(GTK_EDITABLE(shell_entry));
    char output[2048] = "";
    const char *platform = detect_platform();

    if (strncmp(command, "generate_payload ", 16) == 0) {
        char url[256], vuln_type[64];
        if (sscanf(command, "generate_payload %255s %63s", url, vuln_type) == 2) {
            payload_t *payload = generate_payload(url, vuln_type, NULL, 0, 0);
            if (payload) {
                snprintf(output, sizeof(output), "Generated payload: %s\nExplanation: %s\nRAG Context: %s\n", 
                         payload->payload, payload->explanation, payload->rag_context);
                log_event("SHELL_PAYLOAD", output);
                free_payload(payload);
            } else {
                snprintf(output, sizeof(output), "Failed to generate payload for %s (%s)\n", url, vuln_type);
                log_event("SHELL_PAYLOAD_FAIL", output);
            }
            gtk_text_buffer_insert_at_cursor(shell_buffer, output, -1);
            gtk_editable_set_text(GTK_EDITABLE(shell_entry), "");
            return;
        }
    }

    if (strcmp(command, "process_docs") == 0) {
        process_documents(NULL, NULL);
        gtk_editable_set_text(GTK_EDITABLE(shell_entry), "");
        return;
    }

    FILE *fp;
    if (strcmp(platform, "Windows") == 0) {
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "cmd.exe /c %s", command);
        fp = popen(cmd, "r");
    } else {
        fp = popen(command, "r");
    }

    if (!fp) {
        snprintf(output, sizeof(output), "Error: Failed to execute command '%s'\n", command);
        gtk_text_buffer_insert_at_cursor(shell_buffer, output, -1);
        log_event("SHELL_ERROR", output);
        gtk_editable_set_text(GTK_EDITABLE(shell_entry), "");
        return;
    }

    char buffer[512];
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        strncat(output, buffer, sizeof(output) - strlen(output) - 1);
    }
    pclose(fp);

    gtk_text_buffer_insert_at_cursor(shell_buffer, output, -1);
    gtk_text_buffer_insert_at_cursor(shell_buffer, "\n", -1);
    log_event("SHELL_EXEC", output);
    gtk_editable_set_text(GTK_EDITABLE(shell_entry), "");
}

static void show_logs(GtkWidget *widget, gpointer data) {
    GtkTextBuffer *shell_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app_widgets->shell_view));
    FILE *fp = fopen("/home/lxcxjxhx/PROJECT/INTEL-SE/logs/attack_logs.log", "r");
    if (!fp) {
        gtk_text_buffer_insert_at_cursor(shell_buffer, "Error: Failed to open log file\n", -1);
        log_event("LOG_ERROR", "Failed to open attack_logs.log");
        return;
    }

    char buffer[512];
    char output[2048] = "";
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        strncat(output, buffer, sizeof(output) - strlen(output) - 1);
    }
    fclose(fp);

    gtk_text_buffer_insert_at_cursor(shell_buffer, "=== Log File Contents ===\n", -1);
    gtk_text_buffer_insert_at_cursor(shell_buffer, output, -1);
    gtk_text_buffer_insert_at_cursor(shell_buffer, "\n", -1);
    log_event("SHOW_LOGS", "Displayed log file contents");
}

static gboolean monitor_logs(gpointer data) {
    GtkTextBuffer *shell_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app_widgets->shell_view));
    FILE *fp = fopen("/home/lxcxjxhx/PROJECT/INTEL-SE/logs/attack_logs.log", "r");
    if (fp) {
        char buffer[512];
        char output[2048] = "";
        while (fgets(buffer, sizeof(buffer), fp) != NULL) {
            strncat(output, buffer, sizeof(output) - strlen(output) - 1);
        }
        fclose(fp);
        gtk_text_buffer_set_text(shell_buffer, output, -1);
        log_event("LOG_UPDATE", "Log file updated");
    }
    return G_SOURCE_CONTINUE;
}

static void create_top_bar(AppWidgets *widgets) {
    widgets->top_bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_margin_start(widgets->top_bar, 8);
    gtk_widget_set_margin_end(widgets->top_bar, 8);
    gtk_widget_set_margin_top(widgets->top_bar, 4);
    gtk_widget_set_margin_bottom(widgets->top_bar, 4);
    gtk_widget_set_size_request(widgets->top_bar, -1, 40);

    GtkWidget *model_button = gtk_button_new_with_label("AI Model");
    GtkWidget *file_button = gtk_button_new_with_label("Files");
    gtk_box_append(GTK_BOX(widgets->top_bar), model_button);
    gtk_box_append(GTK_BOX(widgets->top_bar), file_button);
    g_signal_connect(model_button, "clicked", G_CALLBACK(show_model_config_dialog), NULL);
    g_signal_connect(file_button, "clicked", G_CALLBACK(show_file_config_dialog), NULL);
}

void create_ui(GtkApplication *app, config_t *config) {
    app_widgets = g_new0(AppWidgets, 1);
    app_widgets->config = config;

    GtkWidget *window = gtk_application_window_new(app);
    app_widgets->window = window;
    gtk_window_set_title(GTK_WINDOW(window), "AI Attack Simulator");
    gtk_window_set_default_size(GTK_WINDOW(window), 800, 600);

    apply_css();

    GtkWidget *main_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_window_set_child(GTK_WINDOW(window), main_box);

    create_top_bar(app_widgets);
    gtk_box_append(GTK_BOX(main_box), app_widgets->top_bar);

    GtkWidget *main_paned = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_box_append(GTK_BOX(main_box), main_paned);

    GtkWidget *sidebar = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_size_request(sidebar, 120, -1);
    gtk_paned_set_start_child(GTK_PANED(main_paned), sidebar);
    gtk_widget_set_margin_start(sidebar, 8);
    gtk_widget_set_margin_end(sidebar, 8);
    gtk_widget_set_margin_top(sidebar, 8);
    gtk_widget_set_margin_bottom(sidebar, 8);

    GtkWidget *rag_button = gtk_button_new_with_label("Process Docs");
    g_signal_connect(rag_button, "clicked", G_CALLBACK(process_documents), NULL);
    gtk_box_append(GTK_BOX(sidebar), rag_button);

    GtkWidget *run_button = gtk_button_new_with_label("Run Attack");
    g_signal_connect(run_button, "clicked", G_CALLBACK(run_attack), NULL);
    gtk_box_append(GTK_BOX(sidebar), run_button);

    GtkWidget *content_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_paned_set_end_child(GTK_PANED(main_paned), content_box);
    gtk_widget_set_margin_start(content_box, 8);
    gtk_widget_set_margin_end(content_box, 8);
    gtk_widget_set_margin_top(content_box, 8);
    gtk_widget_set_margin_bottom(content_box, 8);

    GtkWidget *output_label = gtk_label_new("Attack Output:");
    gtk_widget_set_halign(output_label, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(content_box), output_label);

    app_widgets->output_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(app_widgets->output_view), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(app_widgets->output_view), GTK_WRAP_WORD);
    GtkWidget *output_scrolled = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(output_scrolled), app_widgets->output_view);
    gtk_scrolled_window_set_min_content_height(GTK_SCROLLED_WINDOW(output_scrolled), 90);
    gtk_box_append(GTK_BOX(content_box), output_scrolled);

    GtkWidget *shell_label = gtk_label_new("Shell:");
    gtk_widget_set_halign(shell_label, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(content_box), shell_label);

    app_widgets->shell_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(app_widgets->shell_view), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(app_widgets->shell_view), GTK_WRAP_WORD);
    GtkWidget *shell_scrolled = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(shell_scrolled), app_widgets->shell_view);
    gtk_scrolled_window_set_min_content_height(GTK_SCROLLED_WINDOW(shell_scrolled), 480);
    gtk_box_append(GTK_BOX(content_box), shell_scrolled);

    GtkWidget *shell_entry_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_append(GTK_BOX(content_box), shell_entry_box);

    GtkWidget *shell_entry_label = gtk_label_new("Command:");
    gtk_widget_set_halign(shell_entry_label, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(shell_entry_box), shell_entry_label);
    GtkWidget *shell_entry = gtk_entry_new();
    gtk_widget_set_hexpand(shell_entry, TRUE);
    gtk_box_append(GTK_BOX(shell_entry_box), shell_entry);

    GtkWidget *shell_button_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_append(GTK_BOX(content_box), shell_button_box);

    GtkWidget *shell_button = gtk_button_new_with_label("Execute");
    g_object_set_data(G_OBJECT(shell_button), "shell_entry", shell_entry);
    g_signal_connect(shell_button, "clicked", G_CALLBACK(execute_shell_command), NULL);
    gtk_box_append(GTK_BOX(shell_button_box), shell_button);

    GtkWidget *log_button = gtk_button_new_with_label("Show Logs");
    g_signal_connect(log_button, "clicked", G_CALLBACK(show_logs), NULL);
    gtk_box_append(GTK_BOX(shell_button_box), log_button);

    g_timeout_add_seconds(2, monitor_logs, NULL);
    gtk_window_present(GTK_WINDOW(window));
}
