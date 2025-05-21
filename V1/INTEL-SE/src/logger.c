#include <stdio.h>
#include <time.h>
#include <string.h>
#include <utils.h>

void log_event(const char *event_type, const char *message) {
    FILE *log_file = fopen("/home/lxcxjxhx/PROJECT/INTEL-SE/logs/attack_logs.log", "a");
    if (!log_file) return;

    time_t now = time(NULL);
    char time_str[64];
    ctime_r(&now, time_str);
    time_str[strlen(time_str) - 1] = '\0';

    fprintf(log_file, "%s - %s - %s\n", time_str, event_type, message);
    fclose(log_file);
}
