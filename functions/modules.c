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

#define LOG_FILE "log.txt"
//#define BLOCK_CMD_LINUX "iptables -A INPUT -s %s -j DROP"
#define BLOCK_CMD_WINDOWS "netsh advfirewall firewall add rule name=\"Block %s\" dir=in action=block remoteip=%s"

// Hash table for IP counts
struct PacketInfo {
    char ip[16]; // IPv4 address
    int count;  // Packet count
    double last_time;  
}PacketInfo;

PacketInfo tracked_ips[1024];
int tracked_count = 0;




