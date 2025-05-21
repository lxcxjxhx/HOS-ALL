#include <gtk/gtk.h>
#include <config_parser.h>
#include <ui.h>
#include <logger.h>

static void activate(GtkApplication *app, gpointer user_data) {
    config_t *config = (config_t *)user_data;
    if (!config) {
        log_event("CONFIG_ERROR", "Failed to parse configurations");
        return;
    }
    create_ui(app, config);
}

int main(int argc, char *argv[]) {
    GtkApplication *app = gtk_application_new("com.example.ai_attack_simulator", G_APPLICATION_DEFAULT_FLAGS);
    config_t *config = parse_configs();
    if (!config) {
        log_event("CONFIG_ERROR", "Failed to parse configurations");
        g_object_unref(app);
        return 1;
    }
    g_signal_connect(app, "activate", G_CALLBACK(activate), config);
    int status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);
    free_config(config);
    return status;
}
