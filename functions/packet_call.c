// Packet handler callback
void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    struct iphdr *ip_header = (struct iphdr *)(packet + 14); // Skip Ethernet header
    struct in_addr src_addr;
    src_addr.s_addr = ip_header->saddr;
    const char *src_ip = inet_ntoa(src_addr);
    
    packet_count++;
    time_t now = time(NULL);
    double elapsed_time = difftime(now, start_time);
    
    if (elapsed_time >= 1.0) { // Check every second
        double packet_rate = packet_count / elapsed_time;
        printf("IP: %s, Packet Rate: %.2f packets/sec\n", src_ip, packet_rate);
        
        if (packet_rate > THRESHOLD) {
            int already_blocked = 0;
            for (int i = 0; i < blocked_count; i++) {
                if (strcmp(blocked_ips[i], src_ip) == 0) {
                    already_blocked = 1;
                    break;
                }
            }
            
            if (!already_blocked) {
                block_ip(src_ip);
                strncpy(blocked_ips[blocked_count++], src_ip, 15);
            }
        }
        
        // Reset the counter and time
        packet_count = 0;
        start_time = now;
    }
}