#ifndef UI_H
#define UI_H

#include <gtk/gtk.h>
#include "config_parser.h"

#define THEME_BG "#4B5EAA"      // Iron-gray
#define THEME_BUTTON "#D8D8D8"  // Silver-white
#define THEME_TEXT "#000000"    // Black
#define THEME_ACCENT "#3B4A88"  // Darker gray for borders

typedef struct {
    GtkWidget *window;
    GtkWidget *top_bar;
    GtkWidget *output_view;
    GtkWidget *shell_view;
    GThread *log_thread;
    config_t *config;
} AppWidgets;

void create_ui(GtkApplication *app, config_t *config);

#endif
