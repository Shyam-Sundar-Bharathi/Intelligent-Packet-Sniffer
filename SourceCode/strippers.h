void stripARP(unsigned char* buffer, int size){
    arp++;
	struct arp_header *hdr=(struct arp_header *)(buffer + sizeof(struct ether_header));
    fprintf(logfile , "Packet type: ARP\n");
    displayARP(hdr);
 }

void stripTCP(unsigned char* buffer, int size, int type){
    tcp++;
    struct tcphdr *hdr;
    if(type)
        hdr = (struct tcphdr *)(buffer + sizeof(struct ether_header) + sizeof(struct iphdr));
    else
        hdr = (struct tcphdr *)(buffer + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
	struct ether_header *eth = (struct ether_header*)(buffer);
    u_short src_port;
	u_short dst_port;
	u_int seq;
	u_int ack;
	src_port = ntohs(hdr->source);
	dst_port = ntohs(hdr->dest);
	seq = ntohl(hdr->seq);
	ack = ntohl(hdr->ack);
	int hdrsize;
    if (src_port == 80 || dst_port == 80){
        http++;
        fprintf(logfile , "Packet type: HTTP\n");
        struct httphdr *shdr;
          if(type){  
            shdr = (struct httphdr *)(buffer + sizeof(struct tcphdr) + sizeof(struct ether_header) + sizeof(struct iphdr));
            hdrsize= sizeof(struct tcphdr) + sizeof(struct ether_header) + sizeof(struct iphdr);
            fprintf(logfile , "\n");
            fprintf(logfile , "HTTP message\n");
            print(buffer + hdrsize, size-hdrsize); 
            fprintf(logfile , "\n");
          }
          else{
            shdr = (struct httphdr *)(buffer + sizeof(struct tcphdr) + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            hdrsize= sizeof(struct tcphdr) + sizeof(struct ether_header) + sizeof(struct ip6_hdr);
            fprintf(logfile , "\n");
            fprintf(logfile , "HTTP message\n");
            print(buffer + hdrsize, size-hdrsize); 
            fprintf(logfile , "\n");

          }
        }
	else if (src_port == 25 || dst_port == 25){
            smtp++;
            fprintf(logfile , "Packet type: SMTP\n");
            struct smtphdr *shdr;
            if(type) 
                shdr = (struct smtphdr *)(buffer + sizeof(struct tcphdr) + sizeof(struct ether_header) + sizeof(struct iphdr));
            else
                shdr = (struct smtphdr *)(buffer + sizeof(struct tcphdr) + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
        }
	else if (src_port == 53 || dst_port == 53){
            dns++;
            fprintf(logfile , "Packet type: DNS\n");
            struct dnshdr *shdr;
            if(type){  
                shdr = (struct dnshdr *)(buffer + sizeof(struct tcphdr) + sizeof(struct ether_header) + sizeof(struct iphdr));
                hdrsize= sizeof(struct udphdr) + sizeof(struct ether_header) + sizeof(struct iphdr);
                fprintf(logfile , "\n");
                fprintf(logfile , "DNS message\n");
                displayDnsHeader(shdr); 
                fprintf(logfile , "\n");
            }
            else{
                shdr = (struct dnshdr *)(buffer + sizeof(struct tcphdr) + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
                hdrsize= sizeof(struct udphdr) + sizeof(struct ether_header) + sizeof(struct ip6_hdr);
                fprintf(logfile , "\n");
                fprintf(logfile , "DNS message\n");
                displayDnsHeader(shdr); 
                fprintf(logfile , "\n");
            }                
        }
		
	else if (src_port == 20 || dst_port == 20 || src_port == 21 || dst_port == 21){
        ftp++;
        fprintf(logfile , "Packet type: FTP\n");
        struct ftphdr *shdr;
        if(type)
            shdr = (struct ftphdr *)(buffer + sizeof(struct tcphdr) + sizeof(struct ether_header) + sizeof(struct iphdr));
        else
            shdr = (struct ftphdr *)(buffer + sizeof(struct tcphdr) + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
	}

    else fprintf(logfile , "Packet type: TCP\n");
    
	displayTcpHeader(hdr);
    if(type){
        struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ether_header));
        displayIpv4Header(iph);
    }
    else{
        struct ipv6_header *iph = (struct ipv6_header *)(buffer + sizeof(struct ether_header));
        displayIpv6Header(iph);
    }
    displayEthernet(eth);
}

void stripUDP(unsigned char* buffer, int size, int type){
    udp++;
    struct udphdr *hdr;
    if(type)
        hdr = (struct udphdr *)(buffer + sizeof(struct ether_header) + sizeof(struct iphdr));
    else
        hdr = (struct udphdr *)(buffer + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
    struct ether_header *eth = (struct ether_header*)(buffer);
    u_short src_port;
    u_short dst_port;
    src_port = ntohs(hdr->source);
    dst_port = ntohs(hdr->dest);
    int hdrsize;
    if (src_port == 80 || dst_port == 80){
        fprintf(logfile , "Packet type: HTTP\n");
        http++;
        struct httphdr *shdr;
        if(type){  
            shdr = (struct httphdr *)(buffer + sizeof(struct udphdr) + sizeof(struct ether_header) + sizeof(struct iphdr));
            hdrsize= sizeof(struct udphdr) + sizeof(struct ether_header) + sizeof(struct iphdr);
            fprintf(logfile , "\n");
            fprintf(logfile , "HTTP message\n");
            print(buffer + hdrsize, size-hdrsize); 
            fprintf(logfile , "\n");
        }
        else{
            shdr = (struct httphdr *)(buffer + sizeof(struct udphdr) + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            hdrsize= sizeof(struct udphdr) + sizeof(struct ether_header) + sizeof(struct ip6_hdr);
            fprintf(logfile , "\n");
            fprintf(logfile , "HTTP message\n");
            print(buffer + hdrsize, size-hdrsize); 
            fprintf(logfile , "\n");
        }
    }
    else if (src_port == 25 || dst_port == 25){
        smtp++;
        fprintf(logfile , "Packet type: SMTP\n");
        struct smtphdr *shdr;
        if(type)
            shdr = (struct smtphdr *)(buffer + sizeof(struct udphdr) + sizeof(struct ether_header) + sizeof(struct iphdr));
        else
            shdr = (struct smtphdr *)(buffer + sizeof(struct udphdr) + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
    }
    else if (src_port == 53 || dst_port == 53) {
            dns++;
            fprintf(logfile , "Packet type: DNS\n");
            struct dnshdr *shdr;
            if(type){  
                shdr = (struct dnshdr *)(buffer + sizeof(struct udphdr) + sizeof(struct ether_header) + sizeof(struct iphdr));
                hdrsize= sizeof(struct udphdr) + sizeof(struct ether_header) + sizeof(struct iphdr);
                fprintf(logfile , "\n");
                fprintf(logfile , "DNS message\n");
                displayDnsHeader(shdr); 
                fprintf(logfile , "\n");    
            }
            else{
                shdr = (struct dnshdr *)(buffer + sizeof(struct udphdr) + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
                hdrsize= sizeof(struct udphdr) + sizeof(struct ether_header) + sizeof(struct ip6_hdr);
                fprintf(logfile , "\n");
                fprintf(logfile , "DNS message\n");
                displayDnsHeader(shdr); 
                fprintf(logfile , "\n");
            }             
        }
    else if (src_port == 20 || dst_port == 20 || src_port == 21 || dst_port == 21) {
        ftp++;
        struct ftphdr *shdr;
        if(type)
            shdr = (struct ftphdr *)(buffer + sizeof(struct udphdr) + sizeof(struct ether_header) + sizeof(struct iphdr));
        else
            shdr = (struct ftphdr *)(buffer + sizeof(struct udphdr) + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
        fprintf(logfile , "Packet type: FTP\n");
    }

    else fprintf(logfile , "Packet type: UDP\n");

    displayUdpHeader(hdr);
    if(type){
        struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ether_header));
        displayIpv4Header(iph);
    }
    else{
        struct ipv6_header *iph = (struct ipv6_header *)(buffer + sizeof(struct ether_header));
        displayIpv6Header(iph);
    }
    displayEthernet(eth);

}

void stripIpv4(unsigned char* buffer, int size){
    ipv4++;
	struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ether_header));
	struct ether_header *eth = (struct ether_header*)(buffer);
    switch (iph->protocol) {
	case 6:
		stripTCP(buffer,size,1);
		break;

	case 17:
		stripUDP(buffer,size,1);
		break;

	case 1:
		break;

	default:
        fprintf(logfile , "Packet type: IPv4\n");
	    displayIpv4Header(iph);
        displayEthernet(eth);
		break;
	}
}

void stripIpv6(unsigned char* buffer, int size){
    ipv6++;
    struct ipv6_header *ip6h = (struct ipv6_header *)(buffer+ sizeof(struct ether_header));
    struct ether_header *eth = (struct ether_header*)(buffer);
    switch (ntohs(ip6h->next_header)){
        case 6 :
            stripTCP(buffer,size,0);
            break;

        case 17:
            stripUDP(buffer,size,0);
            break;

        default:
            fprintf(logfile , "Packet type: IPv6\n");
            displayIpv6Header(ip6h);
            displayEthernet(eth);
            break;
    }
}

void stripEther(unsigned char* buffer, int size)
{
	struct ether_header *eth = (struct ether_header*)(buffer);
    ++total;
    switch (ntohs(eth->ether_type)){
        case 0x0800: //Ethernet Protocol
            stripIpv4(buffer,size);
            break;
         
        case 0x0806:  //ARP Protocol
            displayEthernet(eth);
            stripARP(buffer,size);
            break;
         
        case 0x86dd:  //IPv6 Protocol
            stripIpv6(buffer,size);
            break;
         
        default: 
            fprintf(logfile , "Packet type: Ethernet\n");
            displayEthernet(eth);
            break;
    }
}