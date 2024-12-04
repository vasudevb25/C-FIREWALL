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