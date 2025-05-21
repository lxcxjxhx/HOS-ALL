#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <ui.h>
#include <config_parser.h>
#include <ai_payload_generator.h>
#include <attack_executor.h>
#include <response_analyzer.h>
#include <logger.h>
#include <utils.h>
#include <rag_processor.h>

// Forward declarations
static TabWidgets* create_tab_content(void);
static void close_tab(GtkWidget *button, gpointer tab_widgets);
static void init_cli(gpointer tab_widgets);
static void process_documents(GtkWidget *widget, gpointer tab_widgets);
static void run_attack(GtkWidget *widget, gpointer tab_widgets);
static gboolean monitor_logs(gpointer tab_widgets);
static void add_new_tab(GtkWidget *button, gpointer data);
static void on_key_pressed(GtkEventControllerKey *controller, guint keyval, guint keycode, GdkModifierType state, gpointer tab_widgets);
static void on_query_key_pressed(GtkEventControllerKey *controller, guint keyval, guint keycode, GdkModifierType state, gpointer tab_widgets);
static void execute_command(const char *command, TabWidgets *tab);
static void toggle_right_sidebar(GtkWidget *button, gpointer data);

// Static widgets for header bar buttons
static GtkWidget *model_button = NULL;
static GtkWidget *file_button = NULL;
static GtkWidget *ip_button = NULL;
static GtkWidget *new_tab_button = NULL;

static AppWidgets *app_widgets;

static void apply_css(const char *platform) {
    GtkCssProvider *provider = gtk_css_provider_new();
    const char *cli_font = strcmp(platform, "Windows") == 0 ? "Consolas" : "Monospace";
    char css[4096];
    snprintf(css, sizeof(css),
        "* { font-family: Inter, Source Sans Pro, sans-serif; font-size: 12px; }\n"
        "window { background-color: " THEME_BG "; padding: 8px; }\n"
        "box { background-color: " THEME_BG "; }\n"
        "headerbar { background-color: " THEME_BG "; border-bottom: 1px solid " THEME_ACCENT "; "
            "box-shadow: 0 2px 3px rgba(0,0,0,0.15); min-height: 36px; padding: 0 6px; }\n"
        "notebook { background-color: " THEME_BG "; border: 1px solid " THEME_ACCENT "; "
            "border-radius: 6px; margin: 8px; }\n"
        "notebook tab { background-color: " THEME_BUTTON "; border-radius: 6px 6px 0 0; padding: 6px 12px; }\n"
        "notebook tab:checked { background-color: " THEME_BG "; border-bottom: 2px solid " THEME_ACCENT "; }\n"
        "textview#output_view { background-color: #5A6EBB; color: " THEME_TEXT "; padding: 8px; "
            "font-family: Monospace; font-size: 12px; border: 2px solid " THEME_ACCENT "; "
            "border-radius: 6px; box-shadow: inset 0 1px 3px rgba(0,0,0,0.15); }\n"
        "textview#cli_view { background-color: #000000; color: #FFFFFF; padding: 8px; font-family: %s; "
            "font-size: 12px; border: 2px solid " THEME_ACCENT "; border-radius: 6px; "
            "box-shadow: inset 0 1px 3px rgba(0,0,0,0.15); }\n"
        "textview#query_input { background-color: #000000; color: #FFFFFF; padding: 8px; font-family: %s; "
            "font-size: 12px; border: 2px solid " THEME_ACCENT "; border-radius: 6px; "
            "box-shadow: inset 0 1px 3px rgba(0,0,0,0.15); }\n"
        "textview#query_output { background-color: #5A6EBB; color: " THEME_TEXT "; padding: 8px; "
            "font-family: Monospace; font-size: 12px; border: 2px solid " THEME_ACCENT "; "
            "border-radius: 6px; box-shadow: inset 0 1px 3px rgba(0,0,0,0.15); }\n"
        "button { background-color: " THEME_BUTTON "; color: " THEME_TEXT "; "
            "border: 1px solid " THEME_ACCENT "; border-radius: 6px; padding: 6px 12px; margin: 4px; "
            "font-weight: 600; box-shadow: 0 1px 3px rgba(0,0,0,0.1); transition: background-color 0.2s; }\n"
        "button:hover { background-color: #E8E8E8; }\n"
        "button:active { background-color: #C0C0C0; box-shadow: inset 0 1px 3px rgba(0,0,0,0.2); }\n"
        "entry { background-color: " THEME_BUTTON "; color: " THEME_TEXT "; "
            "border: 1px solid " THEME_ACCENT "; border-radius: 6px; padding: 6px; margin: 4px; }\n"
        "label { color: " THEME_TEXT "; font-weight: 600; margin-bottom: 4px; }\n"
        "scrolledwindow { border: none; border-radius: 6px; background-color: #5A6EBB; }\n"
        "dropdown { background-color: " THEME_BUTTON "; color: " THEME_TEXT "; "
            "border: 1px solid " THEME_ACCENT "; border-radius: 6px; padding: 6px; font-weight: 600; }",
        cli_font, cli_font);
    gtk_css_provider_load_from_string(provider, css);
    gtk_style_context_add_provider_for_display(gdk_display_get_default(),
                                              GTK_STYLE_PROVIDER(provider),
                                              GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(provider);
}

static void save_config(const char *model, const char *deepseek_key, const char *claude_key,
                        const char *gemini_key, const char *grok_key, const char *ironheart_endpoint,
                        TabWidgets *tab_widgets) {
    if (!tab_widgets || !tab_widgets->config) {
        log_event("CONFIG_ERROR", "Invalid tab_widgets or config");
        return;
    }
    FILE *fp = fopen("/home/lxcxjxhx/PROJECT/INTEL-SE/config/settings.yaml", "w");
    if (!fp) {
        log_event("CONFIG_ERROR", "Failed to open settings.yaml");
        return;
    }
    fprintf(fp, "ai_model: \"%s\"\n", model ? model : "");
    fprintf(fp, "deepseek_api_key: \"%s\"\n", deepseek_key ? deepseek_key : "");
    fprintf(fp, "claude_api_key: \"%s\"\n", claude_key ? claude_key : "");
    fprintf(fp, "gemini_api_key: \"%s\"\n", gemini_key ? gemini_key : "");
    fprintf(fp, "grok_api_key: \"%s\"\n", grok_key ? grok_key : "");
    fprintf(fp, "ironheart_endpoint: \"%s\"\n", ironheart_endpoint ? ironheart_endpoint : "");
    fprintf(fp, "ip_addresses: \"%s\"\n", tab_widgets->ip_addresses ? tab_widgets->ip_addresses : "");
    fprintf(fp, "logging_level: \"INFO\"\n");
    fprintf(fp, "waf_bypass_enabled: %s\n", tab_widgets->config->waf_bypass_enabled ? "true" : "false");
    fprintf(fp, "max_retries: %d\n", tab_widgets->config->max_retries);
    fclose(fp);
    log_event("CONFIG_SAVED", "Settings updated");
}

static void on_model_dialog_response(GtkWidget *button, gpointer dialog) {
    GtkWidget *model_dropdown = g_object_get_data(G_OBJECT(dialog), "model_dropdown");
    GtkWidget *deepseek_entry = g_object_get_data(G_OBJECT(dialog), "deepseek_entry");
    GtkWidget *claude_entry = g_object_get_data(G_OBJECT(dialog), "claude_entry");
    GtkWidget *gemini_entry = g_object_get_data(G_OBJECT(dialog), "gemini_entry");
    GtkWidget *grok_entry = g_object_get_data(G_OBJECT(dialog), "grok_entry");
    GtkWidget *ironheart_entry = g_object_get_data(G_OBJECT(dialog), "ironheart_entry");
    TabWidgets *tab_widgets = g_object_get_data(G_OBJECT(dialog), "tab_widgets");

    if (g_strcmp0(gtk_widget_get_name(button), "save_button") == 0) {
        guint selected = gtk_drop_down_get_selected(GTK_DROP_DOWN(model_dropdown));
        GtkStringList *string_list = GTK_STRING_LIST(gtk_drop_down_get_model(GTK_DROP_DOWN(model_dropdown)));
        const char *model = gtk_string_list_get_string(string_list, selected);
        save_config(model,
                    gtk_editable_get_text(GTK_EDITABLE(deepseek_entry)),
                    gtk_editable_get_text(GTK_EDITABLE(claude_entry)),
                    gtk_editable_get_text(GTK_EDITABLE(gemini_entry)),
                    gtk_editable_get_text(GTK_EDITABLE(grok_entry)),
                    gtk_editable_get_text(GTK_EDITABLE(ironheart_entry)),
                    tab_widgets);
    }
    gtk_widget_unparent(gtk_window_get_child(GTK_WINDOW(dialog)));
    gtk_window_destroy(GTK_WINDOW(dialog));
}

static void show_model_config_dialog(GtkWidget *button, gpointer tab_widgets) {
    TabWidgets *tab = (TabWidgets *)tab_widgets;
    if (!tab || !tab->config) {
        log_event("DIALOG_ERROR", "Invalid tab or config in show_model_config_dialog");
        return;
    }
    GtkWidget *dialog = gtk_window_new();
    gtk_window_set_title(GTK_WINDOW(dialog), "AI Model Configuration");
    gtk_window_set_transient_for(GTK_WINDOW(dialog), GTK_WINDOW(app_widgets->window));
    gtk_window_set_modal(GTK_WINDOW(dialog), TRUE);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 400, 320);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_margin_start(box, 8);
    gtk_widget_set_margin_end(box, 8);
    gtk_widget_set_margin_top(box, 8);
    gtk_widget_set_margin_bottom(box, 8);
    gtk_window_set_child(GTK_WINDOW(dialog), box);

    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_box_append(GTK_BOX(box), grid);

    GtkWidget *model_label = gtk_label_new("Model:");
    gtk_widget_set_halign(model_label, GTK_ALIGN_START);
    GtkWidget *model_dropdown = gtk_drop_down_new_from_strings(
        (const char *[]){"deepseek", "ollama", "claude", "gemini", "grok", "ironheart", NULL});
    gtk_drop_down_set_selected(GTK_DROP_DOWN(model_dropdown), 0);

    GtkWidget *deepseek_label = gtk_label_new("DeepSeek API Key:");
    gtk_widget_set_halign(deepseek_label, GTK_ALIGN_START);
    GtkWidget *deepseek_entry = gtk_entry_new();
    gtk_editable_set_text(GTK_EDITABLE(deepseek_entry), tab->config->deepseek_api_key ? tab->config->deepseek_api_key : "");

    GtkWidget *claude_label = gtk_label_new("Claude API Key:");
    gtk_widget_set_halign(claude_label, GTK_ALIGN_START);
    GtkWidget *claude_entry = gtk_entry_new();
    gtk_editable_set_text(GTK_EDITABLE(claude_entry), tab->config->claude_api_key ? tab->config->claude_api_key : "");

    GtkWidget *gemini_label = gtk_label_new("Gemini API Key:");
    gtk_widget_set_halign(gemini_label, GTK_ALIGN_START);
    GtkWidget *gemini_entry = gtk_entry_new();
    gtk_editable_set_text(GTK_EDITABLE(gemini_entry), tab->config->gemini_api_key ? tab->config->gemini_api_key : "");

    GtkWidget *grok_label = gtk_label_new("Grok API Key:");
    gtk_widget_set_halign(grok_label, GTK_ALIGN_START);
    GtkWidget *grok_entry = gtk_entry_new();
    gtk_editable_set_text(GTK_EDITABLE(grok_entry), tab->config->grok_api_key ? tab->config->grok_api_key : "");

    GtkWidget *ironheart_label = gtk_label_new("IronHeart Endpoint:");
    gtk_widget_set_halign(ironheart_label, GTK_ALIGN_START);
    GtkWidget *ironheart_entry = gtk_entry_new();
    gtk_editable_set_text(GTK_EDITABLE(ironheart_entry), tab->config->ironheart_endpoint ? tab->config->ironheart_endpoint : "");

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

    GtkWidget *button_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
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
    g_object_set_data(G_OBJECT(dialog), "tab_widgets", tab_widgets);

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
    gtk_widget_unparent(gtk_window_get_child(GTK_WINDOW(dialog)));
    gtk_window_destroy(GTK_WINDOW(dialog));
}

static void show_file_config_dialog(GtkWidget *button, gpointer tab_widgets) {
    if (!tab_widgets) {
        log_event("DIALOG_ERROR", "Invalid tab_widgets in show_file_config_dialog");
        return;
    }
    GtkWidget *dialog = gtk_window_new();
    gtk_window_set_title(GTK_WINDOW(dialog), "File Configuration");
    gtk_window_set_transient_for(GTK_WINDOW(dialog), GTK_WINDOW(app_widgets->window));
    gtk_window_set_modal(GTK_WINDOW(dialog), TRUE);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 400, 140);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_margin_start(box, 8);
    gtk_widget_set_margin_end(box, 8);
    gtk_widget_set_margin_top(box, 8);
    gtk_widget_set_margin_bottom(box, 8);
    gtk_window_set_child(GTK_WINDOW(dialog), box);

    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_box_append(GTK_BOX(box), grid);

    GtkWidget *dir_label = gtk_label_new("Docs Directory:");
    gtk_widget_set_halign(dir_label, GTK_ALIGN_START);
    GtkWidget *dir_entry = gtk_entry_new();
    gtk_editable_set_text(GTK_EDITABLE(dir_entry), "/home/lxcxjxhx/PROJECT/INTEL-SE/docs");

    gtk_grid_attach(GTK_GRID(grid), dir_label, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), dir_entry, 1, 0, 1, 1);

    GtkWidget *button_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
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

static void on_ip_dialog_response(GtkWidget *button, gpointer dialog) {
    GtkWidget *ip_entry = g_object_get_data(G_OBJECT(dialog), "ip_entry");
    TabWidgets *tab_widgets = g_object_get_data(G_OBJECT(dialog), "tab_widgets");
    if (!tab_widgets) {
        log_event("DIALOG_ERROR", "Invalid tab_widgets in on_ip_dialog_response");
        return;
    }
    if (g_strcmp0(gtk_widget_get_name(button), "save_button") == 0) {
        const char *ip = gtk_editable_get_text(GTK_EDITABLE(ip_entry));
        if (tab_widgets->ip_addresses) g_free(tab_widgets->ip_addresses);
        tab_widgets->ip_addresses = g_strdup(ip);
        char log_msg[512];
        snprintf(log_msg, sizeof(log_msg), "IP addresses set to: %s", ip);
        log_event("CONFIG", log_msg);
        save_config(tab_widgets->config->ai_model,
                    tab_widgets->config->deepseek_api_key,
                    tab_widgets->config->claude_api_key,
                    tab_widgets->config->gemini_api_key,
                    tab_widgets->config->grok_api_key,
                    tab_widgets->config->ironheart_endpoint,
                    tab_widgets);
    }
    gtk_widget_unparent(gtk_window_get_child(GTK_WINDOW(dialog)));
    gtk_window_destroy(GTK_WINDOW(dialog));
}

static void show_ip_config_dialog(GtkWidget *button, gpointer tab_widgets) {
    TabWidgets *tab = (TabWidgets *)tab_widgets;
    if (!tab || !tab->config) {
        log_event("DIALOG_ERROR", "Invalid tab or config in show_ip_config_dialog");
        return;
    }
    GtkWidget *dialog = gtk_window_new();
    gtk_window_set_title(GTK_WINDOW(dialog), "IP Configuration");
    gtk_window_set_transient_for(GTK_WINDOW(dialog), GTK_WINDOW(app_widgets->window));
    gtk_window_set_modal(GTK_WINDOW(dialog), TRUE);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 400, 140);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_margin_start(box, 8);
    gtk_widget_set_margin_end(box, 8);
    gtk_widget_set_margin_top(box, 8);
    gtk_widget_set_margin_bottom(box, 8);
    gtk_window_set_child(GTK_WINDOW(dialog), box);

    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_box_append(GTK_BOX(box), grid);

    GtkWidget *ip_label = gtk_label_new("IP Address or Range:");
    gtk_widget_set_halign(ip_label, GTK_ALIGN_START);
    GtkWidget *ip_entry = gtk_entry_new();
    gtk_editable_set_text(GTK_EDITABLE(ip_entry), tab->ip_addresses ? tab->ip_addresses : "");

    gtk_grid_attach(GTK_GRID(grid), ip_label, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), ip_entry, 1, 0, 1, 1);

    GtkWidget *button_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_box_set_homogeneous(GTK_BOX(button_box), TRUE);
    gtk_widget_set_halign(button_box, GTK_ALIGN_END);
    gtk_box_append(GTK_BOX(box), button_box);

    GtkWidget *save_button = gtk_button_new_with_label("Save");
    gtk_widget_set_name(save_button, "save_button");
    GtkWidget *cancel_button = gtk_button_new_with_label("Cancel");
    gtk_box_append(GTK_BOX(button_box), cancel_button);
    gtk_box_append(GTK_BOX(button_box), save_button);

    g_object_set_data(G_OBJECT(dialog), "ip_entry", ip_entry);
    g_object_set_data(G_OBJECT(dialog), "tab_widgets", tab_widgets);
    g_signal_connect(save_button, "clicked", G_CALLBACK(on_ip_dialog_response), dialog);
    g_signal_connect(cancel_button, "clicked", G_CALLBACK(on_ip_dialog_response), dialog);

    gtk_window_present(GTK_WINDOW(dialog));
}

static const char* detect_platform(void) {
    struct utsname uname_data;
    if (uname(&uname_data) == 0) {
        if (strstr(uname_data.sysname, "Linux")) {
            // Check for WSL
            FILE *fp = fopen("/proc/version", "r");
            if (fp) {
                char buffer[256];
                if (fgets(buffer, sizeof(buffer), fp)) {
                    if (strstr(buffer, "Microsoft") || strstr(buffer, "WSL")) {
                        fclose(fp);
                        return "Windows";
                    }
                }
                fclose(fp);
            }
            return "Linux";
        }
        if (strstr(uname_data.sysname, "Windows") || strstr(uname_data.sysname, "CYGWIN") || strstr(uname_data.sysname, "MINGW")) {
            return "Windows";
        }
    }
    return "Linux"; // Default to Linux for safety
}

static void init_cli(gpointer tab_widgets) {
    TabWidgets *tab = (TabWidgets *)tab_widgets;
    if (!tab || !tab->cli_view || !GTK_IS_TEXT_VIEW(tab->cli_view)) {
        log_event("CLI_ERROR", "Invalid CLI view");
        return;
    }
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(tab->cli_view));
    gtk_text_buffer_set_text(buffer, "", -1); // Clear buffer
    gtk_text_buffer_set_text(buffer, "Available commands: generate_payload, process_docs, run_attack, or any shell command\n> ", -1);
    log_event("CLI_INIT", "Embedded CLI initialized");
}

static void append_to_cli(TabWidgets *tab, const char *text) {
    if (!tab || !tab->cli_view || !GTK_IS_TEXT_VIEW(tab->cli_view)) {
        log_event("CLI_ERROR", "Failed to append to CLI: Invalid tab or cli_view");
        return;
    }
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(tab->cli_view));
    if (!buffer) {
        log_event("CLI_ERROR", "Failed to get CLI buffer");
        return;
    }
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(buffer, &end);
    gtk_text_buffer_insert(buffer, &end, text, -1);
    gtk_text_buffer_insert(buffer, &end, "\n> ", -1);

    // Scroll to end
    GtkTextMark *mark = gtk_text_buffer_create_mark(buffer, NULL, &end, FALSE);
    gtk_text_view_scroll_to_mark(GTK_TEXT_VIEW(tab->cli_view), mark, 0.0, FALSE, 0.0, 0.0);
    gtk_text_buffer_delete_mark(buffer, mark);

    // Log to attack_logs.log for CLI commands
    FILE *fp = fopen("/home/lxcxjxhx/PROJECT/INTEL-SE/logs/attack_logs.log", "a");
    if (fp) {
        fprintf(fp, "%s\n", text);
        fclose(fp);
    } else {
        log_event("LOG_ERROR", "Failed to open attack_logs.log");
    }
}

static void execute_command(const char *command, TabWidgets *tab) {
    if (!tab || !tab->config || !command || !command[0]) {
        log_event("COMMAND_ERROR", "Invalid or empty command or tab/config");
        return;
    }
    char output[2048] = "";
    char *cmd = g_strdup(command);
    char *trimmed = g_strstrip(cmd);

    char log_msg[512];
    snprintf(log_msg, sizeof(log_msg), "Executing command: %s", trimmed);
    log_event("COMMAND_ATTEMPT", log_msg);

    // Basic sanitization: block dangerous commands
    if (strstr(trimmed, "rm ") || strstr(trimmed, "sudo ") || strstr(trimmed, "&") || strstr(trimmed, "|") ||
        strstr(trimmed, "dd ") || strstr(trimmed, "mkfs") || strstr(trimmed, "reboot") || strstr(trimmed, "halt")) {
        snprintf(output, sizeof(output), "Error: Command blocked for safety");
        append_to_cli(tab, output);
        log_event("COMMAND_BLOCKED", trimmed);
        g_free(cmd);
        return;
    }

    // Debug: Log shell commands to trace unintended executions
    if (strncmp(trimmed, "generate_payload", 15) != 0 && strcmp(trimmed, "process_docs") != 0 && strcmp(trimmed, "run_attack") != 0) {
        snprintf(log_msg, sizeof(log_msg), "Shell command executed: %s", trimmed);
        log_event("SHELL_DEBUG", log_msg);
    }

    if (strncmp(trimmed, "generate_payload", 15) == 0) {
        char *args = trimmed + 15;
        while (*args == ' ') args++;
        char *url = strtok(args, " ");
        char *vuln_type = strtok(NULL, " ");
        if (url && vuln_type) {
            payload_t *payload = generate_payload(url, vuln_type, NULL, 0, tab->config->waf_bypass_enabled);
            if (payload) {
                snprintf(output, sizeof(output), "Generated payload for %s (%s): %s\nExplanation: %s\nRAG Context: %s",
                         url, vuln_type, payload->payload, payload->explanation, payload->rag_context);
                free_payload(payload);
            } else {
                snprintf(output, sizeof(output), "Failed to generate payload for %s (%s)", url, vuln_type);
            }
        } else {
            snprintf(output, sizeof(output), "Usage: generate_payload <url> <vuln_type>");
        }
    } else if (strcmp(trimmed, "process_docs") == 0) {
        char *text = extract_text_from_docs("/home/lxcxjxhx/PROJECT/INTEL-SE/docs");
        if (text) {
            snprintf(output, sizeof(output), "Processed documents. Extracted text length: %lu", strlen(text));
            free(text);
        } else {
            snprintf(output, sizeof(output), "No documents processed or error occurred");
        }
    } else if (strcmp(trimmed, "run_attack") == 0) {
        if (!tab->ip_addresses || strlen(tab->ip_addresses) == 0) {
            snprintf(output, sizeof(output), "Error: No IP addresses configured");
        } else {
            char *ip_list = g_strdup(tab->ip_addresses);
            char *ip_token = strtok(ip_list, ",");
            while (ip_token) {
                char url[256];
                snprintf(url, sizeof(url), "http://%s", ip_token);
                for (int i = 0; i < tab->config->target_count; i++) {
                    target_t *target = &tab->config->targets[i];
                    for (int j = 0; j < target->vuln_type_count; j++) {
                        payload_t *payload = generate_payload(url, target->vuln_types[j], 
                                                             target->parameters, target->param_count, 
                                                             target->waf_bypass);
                        if (payload) {
                            char payload_msg[1024];
                            snprintf(payload_msg, sizeof(payload_msg), "Generated payload for %s (%s): %s",
                                     url, target->vuln_types[j], payload->payload);
                            strncat(output, payload_msg, sizeof(output) - strlen(output) - 1);
                            strncat(output, "\n", sizeof(output) - strlen(output) - 1);
                            response_t *response = execute_attack(url, "POST", payload->payload);
                            if (response) {
                                analysis_t *result = analyze_response(response, target->vuln_types[j]);
                                snprintf(payload_msg, sizeof(payload_msg), "Attack on %s (%s): %s",
                                         url, target->vuln_types[j], result->details);
                                strncat(output, payload_msg, sizeof(output) - strlen(output) - 1);
                                strncat(output, "\n", sizeof(output) - strlen(output) - 1);
                                free_analysis(result);
                                free_response(response);
                            }
                            free_payload(payload);
                        }
                    }
                }
                ip_token = strtok(NULL, ",");
            }
            g_free(ip_list);
        }
    } else {
        // Execute shell command
        char cmd_buffer[512];
        snprintf(cmd_buffer, sizeof(cmd_buffer), "%s 2>&1", trimmed); // Capture stderr
        FILE *fp = popen(cmd_buffer, "r");
        if (fp) {
            char line[512];
            output[0] = '\0';
            while (fgets(line, sizeof(line), fp)) {
                strncat(output, line, sizeof(output) - strlen(output) - 1);
            }
            int status = pclose(fp);
            if (status == -1) {
                snprintf(output, sizeof(output), "Error executing command: %s", trimmed);
            } else if (strlen(output) == 0) {
                snprintf(output, sizeof(output), "Command executed: %s", trimmed);
            }
            log_event("SHELL_EXEC", output);
        } else {
            snprintf(output, sizeof(output), "Error executing command: %s", trimmed);
        }
    }

    append_to_cli(tab, output);
    log_event("COMMAND_EXEC", trimmed);
    g_free(cmd);
}

static void on_key_pressed(GtkEventControllerKey *controller, guint keyval, guint keycode, GdkModifierType state, gpointer tab_widgets) {
    TabWidgets *tab = (TabWidgets *)tab_widgets;
    if (!tab || !tab->cli_view) {
        log_event("CLI_ERROR", "Invalid tab or cli_view in on_key_pressed");
        return;
    }
    if (keyval != GDK_KEY_Return) return;

    GtkWidget *widget = gtk_event_controller_get_widget(GTK_EVENT_CONTROLLER(controller));
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(widget));
    GtkTextIter start, end;
    gtk_text_buffer_get_start_iter(buffer, &start);
    gtk_text_buffer_get_end_iter(buffer, &end);
    char *text = gtk_text_buffer_get_text(buffer, &start, &end, FALSE);

    // Debug: Log input
    char log_msg[512];
    snprintf(log_msg, sizeof(log_msg), "CLI input received: %s", text);
    log_event("CLI_INPUT", log_msg);

    // Find last prompt
    char *last_prompt = strrchr(text, '>');
    if (last_prompt) {
        char *command = last_prompt + 1;
        while (*command == ' ') command++;
        if (command[0]) {
            execute_command(command, tab);
            // Clear buffer after command execution
            gtk_text_buffer_set_text(buffer, "> ", -1);
        } else {
            log_event("CLI_INPUT", "Empty command ignored");
        }
    } else {
        log_event("CLI_ERROR", "No prompt found in CLI input");
    }

    g_free(text);
}

static void on_query_key_pressed(GtkEventControllerKey *controller, guint keyval, guint keycode, GdkModifierType state, gpointer tab_widgets) {
    TabWidgets *tab = (TabWidgets *)tab_widgets;
    if (!tab || !tab->config) {
        log_event("QUERY_ERROR", "Invalid tab or config in on_query_key_pressed");
        return;
    }
    if (keyval != GDK_KEY_Return) return;

    GtkWidget *widget = gtk_event_controller_get_widget(GTK_EVENT_CONTROLLER(controller));
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(widget));
    GtkTextIter start, end;
    gtk_text_buffer_get_start_iter(buffer, &start);
    gtk_text_buffer_get_end_iter(buffer, &end);
    char *query = gtk_text_buffer_get_text(buffer, &start, &end, FALSE);

    if (query && query[0]) {
        // Mock AI query (replace with actual ai_query implementation)
        char response[2048];
        snprintf(response, sizeof(response), "AI Response: Query '%s' processed using model %s", 
                 query, tab->config->ai_model ? tab->config->ai_model : "unknown");
        // Example: char *response = ai_query(query, tab->config);

        GtkTextBuffer *output_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app_widgets->query_output));
        gtk_text_buffer_set_text(output_buffer, response, -1);
        log_event("AI_QUERY", query);
        // Clear query input
        gtk_text_buffer_set_text(buffer, "", -1);
    }

    g_free(query);
}

static gboolean monitor_logs(gpointer tab_widgets) {
    TabWidgets *tab = (TabWidgets *)tab_widgets;
    if (!tab || !tab->output_view || !GTK_IS_TEXT_VIEW(tab->output_view)) {
        log_event("LOG_ERROR", "Invalid tab or output_view in monitor_logs");
        return G_SOURCE_CONTINUE;
    }
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(tab->output_view));
    if (!buffer) {
        log_event("LOG_ERROR", "Failed to get output_view buffer");
        return G_SOURCE_CONTINUE;
    }

    // Read from attack_results.log
    FILE *fp = fopen("/home/lxcxjxhx/PROJECT/INTEL-SE/logs/attack_results.log", "r");
    if (!fp) {
        log_event("LOG_ERROR", "Failed to open attack_results.log");
        return G_SOURCE_CONTINUE;
    }
    char output[2048] = "";
    char line[512];
    while (fgets(line, sizeof(line), fp) != NULL) {
        strncat(output, line, sizeof(output) - strlen(output) - 1);
    }
    fclose(fp);
    gtk_text_buffer_set_text(buffer, output, -1);
    log_event("LOG_UPDATE", "Attack results log updated");
    return G_SOURCE_CONTINUE;
}

static void run_attack(GtkWidget *widget, gpointer tab_widgets) {
    TabWidgets *tab = (TabWidgets *)tab_widgets;
    if (!tab || !tab->config) {
        log_event("ATTACK_ERROR", "Invalid tab or config in run_attack");
        return;
    }
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(tab->output_view));
    FILE *payload_log = fopen("/home/lxcxjxhx/PROJECT/INTEL-SE/logs/payloads.log", "a");
    FILE *results_log = fopen("/home/lxcxjxhx/PROJECT/INTEL-SE/logs/attack_results.log", "a");

    if (!payload_log) {
        log_event("LOG_ERROR", "Failed to open payloads.log");
    }
    if (!results_log) {
        log_event("LOG_ERROR", "Failed to open attack_results.log");
    }

    char *ip_list = tab->ip_addresses ? g_strdup(tab->ip_addresses) : NULL;
    if (!ip_list || strlen(ip_list) == 0) {
        gtk_text_buffer_insert_at_cursor(buffer, "Error: No IP addresses configured\n", -1);
        if (payload_log) fprintf(payload_log, "Error: No IP addresses configured\n");
        if (results_log) fprintf(results_log, "Error: No IP addresses configured\n");
        log_event("ATTACK_FAIL", "No IP addresses configured");
        if (payload_log) fclose(payload_log);
        if (results_log) fclose(results_log);
        return;
    }

    char *ip_token = strtok(ip_list, ",");
    while (ip_token) {
        char url[256];
        snprintf(url, sizeof(url), "http://%s", ip_token);

        for (int i = 0; i < tab->config->target_count; i++) {
            target_t *target = &tab->config->targets[i];
            for (int j = 0; j < target->vuln_type_count; j++) {
                payload_t *payload = generate_payload(url, target->vuln_types[j], 
                                                    target->parameters, target->param_count, 
                                                    target->waf_bypass);
                char payload_msg[1024];
                if (!payload) {
                    snprintf(payload_msg, sizeof(payload_msg), "Failed to generate payload for %s (%s)\n", 
                             url, target->vuln_types[j]);
                    gtk_text_buffer_insert_at_cursor(buffer, payload_msg, -1);
                    if (payload_log) fprintf(payload_log, "%s", payload_msg);
                    if (results_log) fprintf(results_log, "%s", payload_msg);
                    log_event("PAYLOAD_FAIL", payload_msg);
                    continue;
                }

                snprintf(payload_msg, sizeof(payload_msg), "Generated payload for %s (%s): %s\nExplanation: %s\nRAG Context: %s\n", 
                         url, target->vuln_types[j], payload->payload, payload->explanation, payload->rag_context);
                gtk_text_buffer_insert_at_cursor(buffer, payload_msg, -1);
                if (payload_log) fprintf(payload_log, "%s", payload_msg);
                if (results_log) fprintf(results_log, "%s", payload_msg);
                log_event("PAYLOAD_GENERATED", payload_msg);

                response_t *response = execute_attack(url, "POST", payload->payload);
                if (!response) {
                    snprintf(payload_msg, sizeof(payload_msg), "Attack failed on %s (%s)\n", 
                             url, target->vuln_types[j]);
                    gtk_text_buffer_insert_at_cursor(buffer, payload_msg, -1);
                    if (payload_log) fprintf(payload_log, "%s", payload_msg);
                    if (results_log) fprintf(results_log, "%s", payload_msg);
                    log_event("ATTACK_FAIL", payload_msg);
                    free_payload(payload);
                    continue;
                }

                analysis_t *result = analyze_response(response, target->vuln_types[j]);
                snprintf(payload_msg, sizeof(payload_msg), "Attack on %s (%s): %s\n", 
                         url, target->vuln_types[j], result->details);
                gtk_text_buffer_insert_at_cursor(buffer, payload_msg, -1);
                if (payload_log) fprintf(payload_log, "%s", payload_msg);
                if (results_log) fprintf(results_log, "%s", payload_msg);
                log_event("ATTACK_RESULT", payload_msg);

                free_analysis(result);
                free_response(response);
                free_payload(payload);
            }
        }
        ip_token = strtok(NULL, ",");
    }
    g_free(ip_list);
    if (payload_log) fclose(payload_log);
    if (results_log) fclose(results_log);
}

static void process_documents(GtkWidget *widget, gpointer tab_widgets) {
    TabWidgets *tab = (TabWidgets *)tab_widgets;
    if (!tab || !tab->config) {
        log_event("RAG_ERROR", "Invalid tab or config in process_documents");
        return;
    }
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(tab->output_view));
    FILE *results_log = fopen("/home/lxcxjxhx/PROJECT/INTEL-SE/logs/attack_results.log", "a");
    if (!results_log) {
        log_event("LOG_ERROR", "Failed to open attack_results.log");
    }
    char *text = extract_text_from_docs("/home/lxcxjxhx/PROJECT/INTEL-SE/docs");
    char output[2048];
    if (text) {
        snprintf(output, sizeof(output), "Processed documents. Extracted text length: %lu\n", strlen(text));
        free(text);
    } else {
        snprintf(output, sizeof(output), "No documents processed or error occurred\n");
    }
    gtk_text_buffer_insert_at_cursor(buffer, output, -1);
    if (results_log) {
        fprintf(results_log, "%s", output);
        fclose(results_log);
    }
    log_event("RAG_PROCESS", output);
}

static void close_tab(GtkWidget *button, gpointer tab_widgets) {
    TabWidgets *tab = (TabWidgets *)tab_widgets;
    if (!tab) {
        log_event("TAB_ERROR", "Invalid tab in close_tab");
        return;
    }
    gint page_num = gtk_notebook_page_num(GTK_NOTEBOOK(app_widgets->notebook), tab->content_box);
    if (page_num > 0) { // Prevent closing the first tab
        gtk_notebook_remove_page(GTK_NOTEBOOK(app_widgets->notebook), page_num);
        app_widgets->tabs = g_list_remove(app_widgets->tabs, tab);
        if (tab->ip_addresses) g_free(tab->ip_addresses);
        g_free(tab);
        log_event("TAB_CLOSED", "Closed attack session tab");
    }
}

static TabWidgets* create_tab_content(void) {
    TabWidgets *tab = g_new0(TabWidgets, 1);
    if (!tab) {
        log_event("ERROR", "Failed to allocate TabWidgets");
        return NULL;
    }
    tab->config = app_widgets->config;
    tab->ip_addresses = g_strdup("");
    if (!tab->config) {
        log_event("ERROR", "Invalid app_widgets->config in create_tab_content");
        g_free(tab->ip_addresses);
        g_free(tab);
        return NULL;
    }

    tab->content_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_halign(tab->content_box, GTK_ALIGN_FILL);
    gtk_widget_set_margin_start(tab->content_box, 4);
    gtk_widget_set_margin_end(tab->content_box, 4);
    gtk_widget_set_margin_top(tab->content_box, 4);
    gtk_widget_set_margin_bottom(tab->content_box, 4);

    GtkWidget *output_label = gtk_label_new("Attack Output:");
    gtk_widget_set_halign(output_label, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(tab->content_box), output_label);

    tab->output_view = gtk_text_view_new();
    gtk_widget_set_name(tab->output_view, "output_view");
    if (!GTK_IS_TEXT_VIEW(tab->output_view)) {
        log_event("ERROR", "Failed to create output_view");
        g_free(tab->ip_addresses);
        g_free(tab);
        return NULL;
    }
    gtk_text_view_set_editable(GTK_TEXT_VIEW(tab->output_view), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(tab->output_view), GTK_WRAP_WORD);
    GtkWidget *output_scrolled = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(output_scrolled), tab->output_view);
    gtk_scrolled_window_set_min_content_height(GTK_SCROLLED_WINDOW(output_scrolled), 300);
    gtk_scrolled_window_set_min_content_width(GTK_SCROLLED_WINDOW(output_scrolled), 360);
    gtk_scrolled_window_set_propagate_natural_height(GTK_SCROLLED_WINDOW(output_scrolled), TRUE);
    gtk_widget_set_hexpand(output_scrolled, TRUE);
    gtk_widget_set_vexpand(output_scrolled, TRUE);
    gtk_box_append(GTK_BOX(tab->content_box), output_scrolled);

    GtkWidget *cli_label = gtk_label_new("Command Line:");
    gtk_widget_set_halign(cli_label, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(tab->content_box), cli_label);

    tab->cli_view = gtk_text_view_new();
    gtk_widget_set_name(tab->cli_view, "cli_view");
    if (!GTK_IS_TEXT_VIEW(tab->cli_view)) {
        log_event("ERROR", "Failed to create cli_view");
        g_free(tab->ip_addresses);
        g_free(tab);
        return NULL;
    }
    gtk_text_view_set_editable(GTK_TEXT_VIEW(tab->cli_view), TRUE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(tab->cli_view), GTK_WRAP_WORD);
    GtkWidget *cli_scrolled = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(cli_scrolled), tab->cli_view);
    gtk_scrolled_window_set_min_content_height(GTK_SCROLLED_WINDOW(cli_scrolled), 200);
    gtk_scrolled_window_set_min_content_width(GTK_SCROLLED_WINDOW(cli_scrolled), 360);
    gtk_scrolled_window_set_propagate_natural_height(GTK_SCROLLED_WINDOW(cli_scrolled), TRUE);
    gtk_widget_set_hexpand(cli_scrolled, TRUE);
    gtk_widget_set_vexpand(cli_scrolled, TRUE);
    gtk_box_append(GTK_BOX(tab->content_box), cli_scrolled);

    // Add key controller for CLI
    GtkEventController *key_controller = gtk_event_controller_key_new();
    g_signal_connect(key_controller, "key-pressed", G_CALLBACK(on_key_pressed), tab);
    gtk_widget_add_controller(tab->cli_view, key_controller);

    // Ensure CLI has focus only if valid
    if (GTK_IS_WIDGET(tab->cli_view) && gtk_widget_get_realized(tab->cli_view)) {
        gtk_widget_grab_focus(tab->cli_view);
    } else {
        log_event("CLI_ERROR", "Failed to grab focus for cli_view");
    }

    init_cli(tab);

    g_timeout_add_seconds(2, monitor_logs, tab);
    app_widgets->tabs = g_list_append(app_widgets->tabs, tab);

    return tab;
}

static void toggle_right_sidebar(GtkWidget *button, gpointer data) {
    if (!app_widgets || !app_widgets->right_sidebar) {
        log_event("SIDEBAR_ERROR", "Invalid app_widgets or right_sidebar");
        return;
    }
    gboolean revealed = gtk_revealer_get_reveal_child(GTK_REVEALER(app_widgets->right_sidebar));
    gtk_revealer_set_reveal_child(GTK_REVEALER(app_widgets->right_sidebar), !revealed);
    gtk_button_set_label(GTK_BUTTON(button), revealed ? ">" : "<");
}

static void add_new_tab(GtkWidget *button, gpointer data) {
    TabWidgets *tab = create_tab_content();
    if (!tab) {
        log_event("TAB_ERROR", "Failed to create new tab");
        return;
    }
    char tab_label[32];
    snprintf(tab_label, sizeof(tab_label), "Attack Session %d", ++app_widgets->tab_counter);

    GtkWidget *label_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    GtkWidget *label = gtk_label_new(tab_label);
    gtk_box_append(GTK_BOX(label_box), label);

    GtkWidget *close_button = gtk_button_new_from_icon_name("window-close-symbolic");
    gtk_widget_set_valign(close_button, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(label_box), close_button);

    g_signal_connect(close_button, "clicked", G_CALLBACK(close_tab), tab);

    gtk_notebook_append_page(GTK_NOTEBOOK(app_widgets->notebook), tab->content_box, label_box);
    gtk_notebook_set_current_page(GTK_NOTEBOOK(app_widgets->notebook), gtk_notebook_get_n_pages(GTK_NOTEBOOK(app_widgets->notebook)) - 1);
    log_event("TAB_CREATED", tab_label);
}

static void create_header_bar(AppWidgets *widgets) {
    widgets->header_bar = gtk_header_bar_new();
    gtk_header_bar_set_show_title_buttons(GTK_HEADER_BAR(widgets->header_bar), TRUE);

    model_button = gtk_button_new_with_label("AI Model");
    file_button = gtk_button_new_with_label("Files");
    ip_button = gtk_button_new_with_label("IP Config");
    new_tab_button = gtk_button_new_with_label("+");
    widgets->sidebar_toggle_button = gtk_button_new_with_label(">");

    gtk_header_bar_pack_start(GTK_HEADER_BAR(widgets->header_bar), model_button);
    gtk_header_bar_pack_start(GTK_HEADER_BAR(widgets->header_bar), file_button);
    gtk_header_bar_pack_start(GTK_HEADER_BAR(widgets->header_bar), ip_button);
    gtk_header_bar_pack_start(GTK_HEADER_BAR(widgets->header_bar), new_tab_button);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(widgets->header_bar), widgets->sidebar_toggle_button);
}

void create_ui(GtkApplication *app, config_t *config) {
    app_widgets = g_new0(AppWidgets, 1);
    if (!app_widgets) {
        log_event("ERROR", "Failed to allocate AppWidgets");
        return;
    }
    app_widgets->config = config;
    app_widgets->tabs = NULL;
    app_widgets->tab_counter = 0;

    if (!app_widgets->config) {
        log_event("ERROR", "Invalid config in create_ui");
        g_free(app_widgets);
        return;
    }

    GtkWidget *window = gtk_application_window_new(app);
    app_widgets->window = window;
    gtk_window_set_title(GTK_WINDOW(window), "AI Attack Simulator");
    gtk_window_set_default_size(GTK_WINDOW(window), 800, 600);

    apply_css(detect_platform());

    create_header_bar(app_widgets);
    gtk_window_set_titlebar(GTK_WINDOW(window), app_widgets->header_bar);

    GtkWidget *main_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_window_set_child(GTK_WINDOW(window), main_box);

    GtkWidget *left_sidebar = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_size_request(left_sidebar, 80, -1);
    gtk_box_append(GTK_BOX(main_box), left_sidebar);
    gtk_widget_set_margin_start(left_sidebar, 8);
    gtk_widget_set_margin_end(left_sidebar, 4);
    gtk_widget_set_margin_top(left_sidebar, 8);
    gtk_widget_set_margin_bottom(left_sidebar, 8);

    app_widgets->notebook = gtk_notebook_new();
    gtk_box_append(GTK_BOX(main_box), app_widgets->notebook);
    gtk_widget_set_margin_start(app_widgets->notebook, 4);
    gtk_widget_set_margin_end(app_widgets->notebook, 4);
    gtk_widget_set_margin_top(app_widgets->notebook, 8);
    gtk_widget_set_margin_bottom(app_widgets->notebook, 8);
    gtk_widget_set_hexpand(app_widgets->notebook, TRUE);
    gtk_widget_set_vexpand(app_widgets->notebook, TRUE);

    app_widgets->right_sidebar = gtk_revealer_new();
    gtk_revealer_set_transition_type(GTK_REVEALER(app_widgets->right_sidebar), GTK_REVEALER_TRANSITION_TYPE_SLIDE_LEFT);
    gtk_revealer_set_transition_duration(GTK_REVEALER(app_widgets->right_sidebar), 300);
    gtk_box_append(GTK_BOX(main_box), app_widgets->right_sidebar);

    GtkWidget *sidebar_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_size_request(sidebar_box, 250, -1); // Increased width
    gtk_revealer_set_child(GTK_REVEALER(app_widgets->right_sidebar), sidebar_box);
    gtk_widget_set_margin_start(sidebar_box, 4);
    gtk_widget_set_margin_end(sidebar_box, 8);
    gtk_widget_set_margin_top(sidebar_box, 8);
    gtk_widget_set_margin_bottom(sidebar_box, 8);

    GtkWidget *query_label = gtk_label_new("AI Query (Cybersecurity):");
    gtk_widget_set_halign(query_label, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(sidebar_box), query_label);

    app_widgets->query_input = gtk_text_view_new();
    gtk_widget_set_name(app_widgets->query_input, "query_input");
    gtk_text_view_set_editable(GTK_TEXT_VIEW(app_widgets->query_input), TRUE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(app_widgets->query_input), GTK_WRAP_WORD);
    GtkWidget *query_input_scrolled = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(query_input_scrolled), app_widgets->query_input);
    gtk_scrolled_window_set_min_content_height(GTK_SCROLLED_WINDOW(query_input_scrolled), 150); // Increased height
    gtk_box_append(GTK_BOX(sidebar_box), query_input_scrolled);

    GtkWidget *query_output_label = gtk_label_new("AI Response:");
    gtk_widget_set_halign(query_output_label, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(sidebar_box), query_output_label);

    app_widgets->query_output = gtk_text_view_new();
    gtk_widget_set_name(app_widgets->query_output, "query_output");
    gtk_text_view_set_editable(GTK_TEXT_VIEW(app_widgets->query_output), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(app_widgets->query_output), GTK_WRAP_WORD);
    GtkWidget *query_output_scrolled = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(query_output_scrolled), app_widgets->query_output);
    gtk_scrolled_window_set_min_content_height(GTK_SCROLLED_WINDOW(query_output_scrolled), 400); // Increased height
    gtk_box_append(GTK_BOX(sidebar_box), query_output_scrolled);

    TabWidgets *tab = create_tab_content();
    if (!tab) {
        log_event("ERROR", "Failed to create initial tab");
        gtk_window_destroy(GTK_WINDOW(window));
        g_free(app_widgets);
        return;
    }
    char tab_label[32];
    snprintf(tab_label, sizeof(tab_label), "Attack Session %d", ++app_widgets->tab_counter);
    gtk_notebook_append_page(GTK_NOTEBOOK(app_widgets->notebook), tab->content_box, gtk_label_new(tab_label));

    // Add key controller for query input after tab creation
    GtkEventController *query_key_controller = gtk_event_controller_key_new();
    g_signal_connect(query_key_controller, "key-pressed", G_CALLBACK(on_query_key_pressed), tab);
    gtk_widget_add_controller(app_widgets->query_input, query_key_controller);

    // Connect header bar signals
    g_signal_connect(model_button, "clicked", G_CALLBACK(show_model_config_dialog), tab);
    g_signal_connect(file_button, "clicked", G_CALLBACK(show_file_config_dialog), tab);
    g_signal_connect(ip_button, "clicked", G_CALLBACK(show_ip_config_dialog), tab);
    g_signal_connect(new_tab_button, "clicked", G_CALLBACK(add_new_tab), NULL);
    g_signal_connect(app_widgets->sidebar_toggle_button, "clicked", G_CALLBACK(toggle_right_sidebar), NULL);

    GtkWidget *rag_button = gtk_button_new_with_label("Process Docs");
    g_signal_connect(rag_button, "clicked", G_CALLBACK(process_documents), tab);
    gtk_box_append(GTK_BOX(left_sidebar), rag_button);

    GtkWidget *run_button = gtk_button_new_with_label("Run Attack");
    g_signal_connect(run_button, "clicked", G_CALLBACK(run_attack), tab);
    gtk_box_append(GTK_BOX(left_sidebar), run_button);

    gtk_notebook_set_show_border(GTK_NOTEBOOK(app_widgets->notebook), TRUE);
    gtk_notebook_set_tab_pos(GTK_NOTEBOOK(app_widgets->notebook), GTK_POS_TOP);

    gtk_window_present(GTK_WINDOW(window));
}
