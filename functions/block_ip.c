// Function to Block IP
void block_ip(const char *ip) {
    char command[128];
    snprintf(command, sizeof(command), BLOCK_CMD_WINDOWS, ip, ip);
    system(command);

    char log_message[128];
    snprintf(log_message, sizeof(log_message), "Blocked IP: %s", ip);
    log_event(log_message);
}