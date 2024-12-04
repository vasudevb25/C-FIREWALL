


// Log events to a file
void log_event(const char *message) {
    mkdir(LOG_DIR, 0777); // Ensure the log directory exists
    char log_file[256];
    time_t now = time(NULL);
    struct tm *timestamp = localtime(&now);
    strftime(log_file, sizeof(log_file), LOG_DIR "/log_%Y-%m-%d_%H-%M-%S.txt", timestamp);
    
    FILE *file = fopen(log_file, "a");
    if (file != NULL) {
        fprintf(file, "%s\n", message);
        fclose(file);
    } else {
        perror("Error opening log file");
    }
}




