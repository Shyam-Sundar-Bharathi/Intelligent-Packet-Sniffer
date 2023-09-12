#include "declarations.h"

void openSocket(){
    buffer = (unsigned char *)malloc(65536); 
    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) ;
}

void closeSocket(){
    close(sock_raw);
}

void startSniff(){
    signal(SIGINT, handleINT);
    while(1){
        saddr_size = sizeof saddr;
        data_size = recvfrom(sock_raw , buffer, 65536, 0, &saddr, (socklen_t*)&saddr_size);
        if(data_size < 0){
            printf("Recvfrom error, failed to get packets\n");
            return 1;
        }
        num++;
        fprintf(logfile , "\nPacket number %d\n", num);
        stripEther(buffer, data_size);
    }
}

int main(){
    printf("\nCN Mini Project by Ajay Rajendra Kumar and Shyam Sundar Bharathi.\n\n");
    openSocket();
    logfile = fopen("log.txt", "w+");
    printf("CPU start time is : %d \n", clock());
    startSniff();
    closeSocket();
    return 0;
}