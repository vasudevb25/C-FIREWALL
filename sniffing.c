#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/types.h>

#ifdef _WIN32
#include <windows.h>
#endif

// For Linux, include the required headers
#include <netinet/ip.h>   // for IP header definition
#include <netinet/in.h>   // for ntohs(), htons()
#include <netinet/ether.h> // for Ethernet header

#define THRESHOLD 1 // packets/sec
#define CHECK_INTERVAL 0.5 // seconds
#define MAX_IPS 1000

typedef struct {
    char ip[16];
    int packet_count;
} IPEntry;

IPEntry ip_table[MAX_IPS];
int ip_table_size = 0;
char blocked_ips[MAX_IPS][16];
int blocked_ip_count = 0;
time_t start_time;

// Function Prototypes
void reset_packet_counts();
void block_ip(const char *ip);
int is_ip_blocked(const char *ip);
void add_to_blocked_ips(const char *ip);
void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void check_privileges();
void signal_handler(int signo);

void signal_handler(int signo) {
    if (signo == SIGINT) {
        printf("\nMonitoring stopped. Cleaning up...\n");
        exit(0);
    }
}

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

// Check if an IP is already blocked
int is_ip_blocked(const char *ip) {
    for (int i = 0; i < blocked_ip_count; i++) {
        if (strcmp(blocked_ips[i], ip) == 0) {
            return 1;
        }
    }
    return 0;
}

// Add an IP to the blocked list
void add_to_blocked_ips(const char *ip) {
    if (blocked_ip_count < MAX_IPS) {
        strncpy(blocked_ips[blocked_ip_count], ip, 16);
        blocked_ip_count++;
    } else {
        printf("Blocked IP list is full. Cannot block more IPs.\n");
    }
}

// Block an IP
void block_ip(const char *ip) {
    if (is_ip_blocked(ip)) {
        printf("IP %s is already blocked.\n", ip);
        return;
    }

    char command[256];
#ifdef _WIN32
    snprintf(command, sizeof(command), "netsh advfirewall firewall add rule name=\"Block %s\" dir=in action=block remoteip=%s", ip, ip);
#else
    snprintf(command, sizeof(command), "iptables -A INPUT -s %s -j DROP", ip);
#endif

    int result = system(command);
    if (result == -1) {
        perror("Failed to execute block command");
    } else {
        printf("Blocked IP: %s\n", ip);
        add_to_blocked_ips(ip);
    }
}

// Reset the packet count table
void reset_packet_counts() {
    for (int i = 0; i < ip_table_size; i++) {
        ip_table[i].packet_count = 0;
    }
    ip_table_size = 0;
}

// Handle incoming packets
void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_hdr = (struct ether_header *) packet;
    struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header)); // Offset by Ethernet header size

    const char *src_ip = inet_ntoa(ip_hdr->ip_src);

    // Find or add the IP in the table
    int found = 0;
    for (int i = 0; i < ip_table_size; i++) {
        if (strcmp(ip_table[i].ip, src_ip) == 0) {
            ip_table[i].packet_count++;
            found = 1;
            break;
        }
    }

    if (!found && ip_table_size < MAX_IPS) {
        strncpy(ip_table[ip_table_size].ip, src_ip, 16);
        ip_table[ip_table_size].packet_count = 1;
        ip_table_size++;
    }

    // Check packet rates periodically
    time_t current_time = time(NULL);
    double time_interval = difftime(current_time, start_time);

    if (time_interval >= CHECK_INTERVAL) {
    printf("Elapsed time: %.2f seconds\n", time_interval);

    for (int i = 0; i < ip_table_size; i++) {
        double packet_rate = ip_table[i].packet_count / time_interval;
        printf("IP: %s, Packet Rate: %.2f packets/sec\n", ip_table[i].ip, packet_rate);

        if (packet_rate > THRESHOLD && !is_ip_blocked(ip_table[i].ip)) {
            printf("Blocking IP: %s, Packet Rate: %.2f packets/sec\n", ip_table[i].ip, packet_rate);
            block_ip(ip_table[i].ip);
        }
    }

    reset_packet_counts(); // Reset after each interval
    start_time = current_time; // Reset timer
}

}

int main() {
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    char *device = NULL;
    pcap_if_t *all_devices, *device_ptr;

    signal(SIGINT, signal_handler);
    check_privileges();
    start_time = time(NULL);

    // Find all devices
    if (pcap_findalldevs(&all_devices, error_buffer) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", error_buffer);
        return 1;
    }

    // Select the first device
    for (device_ptr = all_devices; device_ptr != NULL; device_ptr = device_ptr->next) {
        if (device_ptr->name != NULL) {
            device = device_ptr->name;
            break;
        }
    }
    if (device == NULL) {
        fprintf(stderr, "No devices found. Exiting.\n");
        pcap_freealldevs(all_devices);
        return 1;
    }

    printf("Using device: %s\n", device);

    // Open the device for live capture
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, error_buffer);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
        pcap_freealldevs(all_devices);
        return 1;
    }
    pcap_freealldevs(all_devices);

    // Set filter to capture only IP traffic
    struct bpf_program filter;
    char filter_exp[] = "ip";
    if (pcap_compile(handle, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    printf("Monitoring network traffic...\n");
    pcap_loop(handle, 0, handle_packet, NULL);

    pcap_close(handle);
    return 0;
}
