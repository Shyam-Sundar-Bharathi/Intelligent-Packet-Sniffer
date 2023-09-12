void handleINT(int sig){
    char  c;
    signal(sig, SIG_IGN);
    clock_t CPU_time_2 = clock();
    printf("CPU end time is : %d\n", CPU_time_2);
    printf("TCP: %d\n", tcp);
    printf("UDP: %d\n", udp);
    printf("ipv4: %d\n", ipv4);
    printf("ipv6: %d\n", ipv6);
    printf("ARP: %d\n", arp);
    printf("HTTP: %d\n", http);
    printf("DNS: %d\n", dns);
    printf("FTP: %d\n", ftp);
    printf("SMTP: %d\n", smtp);
    printf("Total: %d\n", num);
    exit(0);  
}

void print(unsigned char* data , int Size){
    int i, j, num2 = 0;
    for(i = 0; i < Size; i++){
        if(i != 0 && i % 16 == 0){
            for(j = i - 16; j < i ; j++){
                if(data[j] >= 32 && data[j] <= 128) 
                    fprintf(logfile , "%c", (unsigned char)data[j]); 
                else fprintf(logfile , "."); 
            }
        } 

        if(i == Size-1){
            for(j= i - i % 16; j <= i; j++){
                if(data[j]>=32 && data[j]<=128) 
                  fprintf(logfile , "%c",(unsigned char)data[j]);
                else
                  fprintf(logfile , ".");
            }
        }
    }
}

void displayEthernet(struct ether_header *eth){
    fprintf(logfile , "\n");
    fprintf(logfile , "Ethernet Header:\n");
    fprintf(logfile , "   -->Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->ether_dhost[0] , eth->ether_dhost[1] , eth->ether_dhost[2] , eth->ether_dhost[3] , eth->ether_dhost[4] , eth->ether_dhost[5]);
    fprintf(logfile , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->ether_shost[0] , eth->ether_shost[1] , eth->ether_shost[2] , eth->ether_shost[3] , eth->ether_shost[4] , eth->ether_shost[5]);
    fprintf(logfile , "   |-Protocol            : %u \n", (unsigned short)eth->ether_type);
}

void displayTcpHeader(struct tcphdr *tcph){
    fprintf(logfile , "\n");
    fprintf(logfile , "TCP Header:\n");
    fprintf(logfile , "   |-Source Port      : %u\n", ntohs(tcph->source));
    fprintf(logfile , "   |-Destination Port : %u\n",ntohs(tcph->dest));
    fprintf(logfile , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    fprintf(logfile , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    fprintf(logfile , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    fprintf(logfile , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    fprintf(logfile , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    fprintf(logfile , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    fprintf(logfile , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    fprintf(logfile , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    fprintf(logfile , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    fprintf(logfile , "   |-Window         : %d\n",ntohs(tcph->window));
    fprintf(logfile , "   |-Checksum       : %d\n",ntohs(tcph->check));
    fprintf(logfile , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    fprintf(logfile , "\n");
    return;
}

void displayIpv4Header(struct iphdr *iph){
    unsigned short iphdrlen;
    fprintf(logfile , "\n");
    fprintf(logfile , "IP Header:\n");
    fprintf(logfile , "   |-IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(logfile , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(logfile , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    fprintf(logfile , "   |-Identification    : %d\n",ntohs(iph->id));
    fprintf(logfile , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(logfile , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(logfile , "   |-Checksum : %d\n",ntohs(iph->check));

}

void displayIpv6Header(struct ipv6_header *hdr){
    char src[50], dst[50], stemp[5], dtemp[5];
    int i;
    zero(src);
    zero(dst);
    for (i = 1; i <= 16; i++) {
        if (i % 2 == 0 && i < 16) {
            sprintf(stemp, "%02x:", hdr->src_ipv6[i - 1]);
            sprintf(dtemp, "%02x:", hdr->dst_ipv6[i - 1]);
        } else {
            sprintf(stemp, "%02x", hdr->src_ipv6[i - 1]);
            sprintf(dtemp, "%02x", hdr->dst_ipv6[i - 1]);
        }
        strcat(src, stemp);
        strcat(dst, dtemp);
    }
    fprintf(logfile , "\nIPV6 Header\n");
    fprintf(logfile , "   |-Source       : %s\n" , src);
    fprintf(logfile , "   |-Destination  : %s\n" , dst);
    fprintf(logfile , "\n");
}

void displayUdpHeader(struct udphdr *udph){
    fprintf(logfile , "\nUDP Header\n");
    fprintf(logfile , "   |-Source Port      : %d\n" , ntohs(udph->source));
    fprintf(logfile , "   |-Destination Port : %d\n" , ntohs(udph->dest));
    fprintf(logfile , "   |-UDP Length       : %d\n" , ntohs(udph->len));
    fprintf(logfile , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
    fprintf(logfile , "\n");
}

void displayIcmpHeader(struct icmphdr* icmph ){
    fprintf(logfile , "ICMP Header:\n");
    fprintf(logfile , "   |-Type : %d",(unsigned int)(icmph->type));
    if((unsigned int)(icmph->type) == 11)
        fprintf(logfile , "  (TTL Expired)\n");
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
        fprintf(logfile , "  (ICMP Echo Reply)\n");
    fprintf(logfile , "   |-Code : %d\n", (unsigned int)(icmph->code));
    fprintf(logfile , "   |-Checksum : %d\n", ntohs(icmph->checksum));
    fprintf(logfile , "\n");
 
} 

void displayHTTP(unsigned char* data , int size, int hdrsize ){
    fprintf(logfile , "\n");
    fprintf(logfile , "HTTP message\n");
    print(data+hdrsize, size-hdrsize);
}

void displayDnsHeader(struct dnshdr *dnsh){
    fprintf(logfile , "\n");
    fprintf(logfile , "DNS Header:\n");
    fprintf(logfile , "   |-Identification Number      : %u\n",dnsh->id);
    fprintf(logfile , "   |-Recursion Desired          : %u\n",dnsh->rd);
    fprintf(logfile , "   |-Truncated Message          : %u\n",(dnsh->tc));
    fprintf(logfile , "   |-Authoritative Answer       : %u\n",(dnsh->aa));
    fprintf(logfile , "   |-Purpose of message         : %d\n",(unsigned int)dnsh->opcode);
    fprintf(logfile , "   |-Query/Response Flag        : %d\n",(unsigned int)dnsh->qr);
    fprintf(logfile , "   |-Response code              : %d\n",(unsigned int)dnsh->rcode);
    fprintf(logfile , "   |-Checking Disabled          : %d\n",(unsigned int)dnsh->cd);
    fprintf(logfile , "   |-Authenticated data         : %d\n",(unsigned int)dnsh->ad);
    fprintf(logfile , "   |-Recursion available        : %d\n",(unsigned int)dnsh->ra);
    fprintf(logfile , "   |-Number of question entries : %d\n",(dnsh->q_count));
    fprintf(logfile , "   |-Number of answer entries   : %d\n",(dnsh->ans_count));
    fprintf(logfile , "   |-Number of authority entries: %d\n",dnsh->auth_count);
    fprintf(logfile , "   |-Number of resource entries : %d\n",dnsh->add_count);
    fprintf(logfile , "\n");
    return;
}

void displayARP(struct arp_header* hdr){
    fprintf(logfile , "\n");
    fprintf(logfile , "ARP Header\n");
    fprintf(logfile , "   |-Hardware type      : %d\n",ntohs(hdr->htype));
    fprintf(logfile , "   |-Protocol Type : %d\n",ntohs(hdr->ptype));
    fprintf(logfile , "   |-Hardware addr len    : %d\n",ntohs(hdr->hlen));
    fprintf(logfile , "   |-Protocol addr len   : %d\n",ntohs(hdr->plen));
    fprintf(logfile , "   |-Operation      : %d\n" ,ntohs(hdr->plen));
    fprintf(logfile , "\n"); 
}