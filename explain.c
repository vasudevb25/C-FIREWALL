#include <pcap.h>      // Library for packet capture (PCAP)
#include <stdio.h>      // Standard I/O for printing messages
#include <stdlib.h>     // For general utility functions like exit()
#include <string.h>     // For string handling functions
#include <time.h>       // For handling time functions
#include <unistd.h>     // For POSIX functions
#include <signal.h>     // For signal handling (to stop the program gracefully)
#include <arpa/inet.h>  // For IP address handling (e.g., inet_ntoa)
#include <sys/types.h>  // For system-related types

#ifdef _WIN32
#include <windows.h>    // Windows-specific functions (e.g., checking admin rights)
#endif

// For Linux, include the required headers for packet parsing
#include <netinet/ip.h>    // To define the IP header
#include <netinet/in.h>    // For functions like htons(), ntohs()
#include <netinet/ether.h> // For Ethernet header

// Constants
#define THRESHOLD 1 // packets/sec - The threshold to block an IP
#define CHECK_INTERVAL 0.5 // seconds - Interval to check packet rate
#define MAX_IPS 1000  // Max number of unique IPs to monitor

// Struct to store IP address and its packet count
typedef struct {
    char ip[16];       // IP address (IPv4 in string format)
    int packet_count;  // Count of packets from that IP
} IPEntry;

IPEntry ip_table[MAX_IPS];  // Array of IPEntry structures
int ip_table_size = 0;       // Keeps track of the number of unique IPs
char blocked_ips[MAX_IPS][16];  // List to store blocked IPs
int blocked_ip_count = 0;    // Keeps track of the number of blocked IPs
time_t start_time;           // To track the start time for packet rate calculation

// Function Prototypes
void reset_packet_counts();
void block_ip(const char *ip);
int is_ip_blocked(const char *ip);
void add_to_blocked_ips(const char *ip);
void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void check_privileges();
void signal_handler(int signo);

// Signal handler to stop the program gracefully
void signal_handler(int signo) {
    if (signo == SIGINT) {
        printf("\nMonitoring stopped. Cleaning up...\n");
        exit(0);
    }
}

// Function to check if the program is run with proper privileges (root/admin)
void check_privileges() {
#ifdef _WIN32
    if (!IsUserAnAdmin()) {
        fprintf(stderr, "You need to run this program as an administrator.\n");
        exit(1);
    }
#else
    if (geteuid() != 0) {
        fprintf(stderr, "You need to run this program as root.\n");
        exit(1);
    }
#endif
}

// Function to check if an IP is already blocked
int is_ip_blocked(const char *ip) {
    for (int i = 0; i < blocked_ip_count; i++) {
        if (strcmp(blocked_ips[i], ip) == 0) {  // Compare IPs
            return 1;  // Return true if blocked
        }
    }
    return 0;  // Return false if not blocked
}

// Function to add an IP to the blocked list
void add_to_blocked_ips(const char *ip) {
    if (blocked_ip_count < MAX_IPS) {
        strncpy(blocked_ips[blocked_ip_count], ip, 16);  // Copy IP into blocked list
        blocked_ip_count++;
    } else {
        printf("Blocked IP list is full. Cannot block more IPs.\n");
    }
}

// Function to block an IP using system commands (iptables for Linux or netsh for Windows)
void block_ip(const char *ip) {
    if (is_ip_blocked(ip)) {
        printf("IP %s is already blocked.\n", ip);
        return;
    }

    char command[256];  // String to store the system command
#ifdef _WIN32
    // Command to block the IP using Windows firewall
    snprintf(command, sizeof(command), "netsh advfirewall firewall add rule name=\"Block %s\" dir=in action=block remoteip=%s", ip, ip);
#else
    // Command to block the IP using Linux iptables
    snprintf(command, sizeof(command), "iptables -A INPUT -s %s -j DROP", ip);
#endif

    int result = system(command);  // Execute the system command
    if (result == -1) {
        perror("Failed to execute block command");
    } else {
        printf("Blocked IP: %s\n", ip);
        add_to_blocked_ips(ip);  // Add the IP to the blocked list
    }
}

// Function to reset packet counts for all IPs after each interval
void reset_packet_counts() {
    for (int i = 0; i < ip_table_size; i++) {
        ip_table[i].packet_count = 0;  // Reset the packet count
    }
    ip_table_size = 0;  // Reset the table size
}

// Function to handle incoming packets
void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_hdr = (struct ether_header *) packet;  // Ethernet header
    struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header)); // IP header (skipping Ethernet header)

    const char *src_ip = inet_ntoa(ip_hdr->ip_src);  // Convert IP to string

    // Find or add the IP in the IP table
    int found = 0;
    for (int i = 0; i < ip_table_size; i++) {
        if (strcmp(ip_table[i].ip, src_ip) == 0) {
            ip_table[i].packet_count++;  // Increment packet count for this IP
            found = 1;
            break;
        }
    }

    if (!found && ip_table_size < MAX_IPS) {
        strncpy(ip_table[ip_table_size].ip, src_ip, 16);  // Add new IP to the table
        ip_table[ip_table_size].packet_count = 1;  // Set initial packet count to 1
        ip_table_size++;
    }

    // Periodically check the packet rates
    time_t current_time = time(NULL);  // Get current time
    double time_interval = difftime(current_time, start_time);  // Calculate time difference

    // If the interval has reached or exceeded the check interval
    if (time_interval >= CHECK_INTERVAL) {
        printf("Elapsed time: %.2f seconds\n", time_interval);

        // Calculate packet rate for each IP
        for (int i = 0; i < ip_table_size; i++) {
            double packet_rate = ip_table[i].packet_count / time_interval;
            printf("IP: %s, Packet Rate: %.2f packets/sec\n", ip_table[i].ip, packet_rate);

            // If the packet rate exceeds the threshold, block the IP
            if (packet_rate > THRESHOLD && !is_ip_blocked(ip_table[i].ip)) {
                printf("Blocking IP: %s, Packet Rate: %.2f packets/sec\n", ip_table[i].ip, packet_rate);
                block_ip(ip_table[i].ip);
            }
        }

        reset_packet_counts();  // Reset counts after checking
        start_time = current_time;  // Reset start time for the next interval
    }
}

// Main function
int main() {
    char error_buffer[PCAP_ERRBUF_SIZE];  // Buffer for error messages from pcap
    pcap_t *handle;  // Handle for the pcap session
    char *device = NULL;  // Network device to capture from
    pcap_if_t *all_devices, *device_ptr;

    signal(SIGINT, signal_handler);  // Setup signal handler for Ctrl+C
    check_privileges();  // Check if the program is running with sufficient privileges
    start_time = time(NULL);  // Set the initial start time

    // Find all network devices available for packet capture
    if (pcap_findalldevs(&all_devices, error_buffer) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", error_buffer);
        return 1;
    }

    // Select the first available device
    for (device_ptr = all_devices; device_ptr != NULL; device_ptr = device_ptr->next) {
        if (device_ptr->name != NULL) {
            device = device_ptr->name;
            break;
        }
    }

    if (device == NULL) {
        fprintf(stderr, "No devices found. Exiting.\n");
        pcap_freealldevs(all_devices);  // Free the device list
        return 1;
    }

    printf("Using device: %s\n", device);

    // Open the selected device for live packet capture
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, error_buffer);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
        pcap_freealldevs(all_devices);  // Free the device list
        return 1;
    }
    pcap_freealldevs(all_devices);  // Free the device list after opening

    // Set filter to capture only IP packets (to avoid irrelevant data)
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "ip", 0, PCAP_NETMASK_UNKNOWN) == -1 || 
        pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter\n");
        return 1;
    }

    // Start the packet capture loop
    while (1) {
        pcap_loop(handle, 0, handle_packet, NULL);  // Handle packets as they arrive
    }

    pcap_close(handle);  // Close the pcap handle when done
    return 0;
}
