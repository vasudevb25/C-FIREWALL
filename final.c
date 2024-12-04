#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
// Constants
#define THRESHOLD 1.0 // Packet rate threshold in packets/sec
#define LOG_DIR "logs"
// #define LOG_FILE "log.txt"
#define BLOCK_CMD_WINDOWS "netsh advfirewall firewall add rule name=\"Block %s\" dir=in action=block remoteip=%s"

// Hash table for IP counts
struct PacketInfo {
    char ip[16]; // IPv4 address
    int count;  // Packet count
    double last_time;  
}PacketInfo;

PacketInfo tracked_ips[1024];
int tracked_count = 0;


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


// Function to Block IP
void block_ip(const char *ip) {
    char command[128];
    snprintf(command, sizeof(command), BLOCK_CMD_WINDOWS, ip, ip);
    system(command);

    char log_message[128];
    snprintf(log_message, sizeof(log_message), "Blocked IP: %s", ip);
    log_event(log_message);
}




int main() {
    printf("threshold: %f packets/sec\n",threshold)
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    char *device;
    
    // Find a suitable device for sniffing
    device = pcap_lookupdev(error_buffer);
    if (device == NULL) {
        fprintf(stderr, "Error finding device: %s\n", error_buffer);
        return 1;
    }
    printf("Sniffing on device: %s\n", device);
    
    // Open the device for live packet capture
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, error_buffer);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", error_buffer);
        return 1;
    }
    
    // Initialize start time
    start_time = time(NULL);
    
    // Start sniffing packets
    printf("Monitoring network traffic...\n");
    pcap_loop(handle, 0, packet_handler, NULL);
    
    // Close the handle
    pcap_close(handle);
    return 0;
}
