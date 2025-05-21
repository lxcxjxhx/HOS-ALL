#ifndef UI_H
#define UI_H

#include <gtk/gtk.h>
#include "config_parser.h"

#define THEME_BG "#4B5EAA"      // Iron-gray
#define THEME_BUTTON "#D8D8D8"  // Silver-white
#define THEME_TEXT "#000000"    // Black
#define THEME_ACCENT "#3B4A88"  // Darker gray for borders

typedef struct {
    GtkWidget *output_view; // Attack output display
    GtkWidget *cli_view;    // Embedded CLI window
    GtkWidget *content_box; // Stores tab's content box
    char *ip_addresses;     // Per-tab IP config
    config_t *config;       // Shared config
} TabWidgets;

typedef struct {
    GtkWidget *window;
    GtkWidget *header_bar;
    GtkWidget *notebook;    // For tabbed sessions
    GtkWidget *right_sidebar; // Collapsible sidebar for AI queries
    GtkWidget *sidebar_toggle_button; // Button to toggle sidebar
    GtkWidget *query_input;   // Text input for AI queries
    GtkWidget *query_output;  // Display for AI responses
    GThread *log_thread;
    config_t *config;
    GList *tabs;           // List of TabWidgets
    int tab_counter;       // For naming tabs
} AppWidgets;

void create_ui(GtkApplication *app, config_t *config);

#endif
