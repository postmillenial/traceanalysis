#include <stdio.h>
#include <pcap.h>
//#include <pcap/pcap.h> //needed on OSX?
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "sandy.h"
#include <string.h>

// He wore a dark-blue mantle and called himself Sandy,
//  but said no more about himself, though he was questioned.

#define SIZE_PPP        4
#define SIZE_ETHERNET   14
#define SERVER_IP       "128.8.126.92"

int clientCount = 0;
int serverCount = 0;
struct timeval lasttime = {0, 0};
long totalTime = 0; //totalTime = nanoseconds

void callback(u_char *args, const struct pcap_pkthdr *header, 
    const u_char *packet){
    char output[256]; 
    static int count = 1;
    sprintf(output, "Result no: %d at time: %ld.%06d\n",
        count, header->ts.tv_sec, header->ts.tv_usec );

    long sinceLast = timevaldiff(&lasttime, &(header->ts));
    //printf("sinceLast = %ld + timesofar: %ld\n", sinceLast, totalTime);
    //printf("Last result: %ld.%06d\n", lasttime.tv_sec, lasttime.tv_usec);
    sprintf(output + strlen(output),
        "\tTime since last result: %ldms\n", sinceLast);
    lasttime = header->ts;
    count++;
    totalTime+= sinceLast;

    const struct sniff_ethernet *ethernet;
    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;
    int size_link;
    if ( pcap_datalink(cap_h) != DLT_EN10MB)
        size_link = SIZE_PPP;
    else
        size_link = SIZE_ETHERNET; 
    ethernet = (struct sniff_ethernet*)(packet);
    ip = (struct sniff_ip*)(packet + size_link);
    int size_ip = IP_HL(ip) * 4;
    if (size_ip<20){
        sprintf(output + strlen(output), "\tInvalid IP header length: %u bytes\n", size_ip);
        return;
    }

    sprintf(output + strlen(output), "\tFrom: %s", inet_ntoa(ip->ip_src));
    sprintf(output + strlen(output), "\tTo: %s\n", inet_ntoa(ip->ip_dst));

    if (ip->ip_p != IPPROTO_TCP){
        sprintf(output + strlen(output), "\tNon-TCP packet somehow made it.");
        return;
    }

    tcp = (struct sniff_tcp*)(packet + size_link + size_ip);
    int size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp<20) {
        sprintf(output + strlen(output), "\tInvalid TCP header length: %u bytes\n", size_tcp);
        return;
    }

    if (strcmp(inet_ntoa(ip->ip_src), SERVER_IP) == 0)
        serverCount++;
    else clientCount++;

    sprintf(output + strlen(output), "\tsrc port: %d\n", ntohs(tcp->th_sport) );
    sprintf(output + strlen(output), "\tdst port: %d\n", ntohs(tcp->th_dport) );
    if (tcp->th_flags & TH_ACK)
        sprintf(output + strlen(output), "\tAck number: %d\n", tcp->th_ack);

    char* payload = (u_char *)(packet + size_link + size_ip + size_tcp);
    int size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
    if (size_payload > 0)
        sprintf(output + strlen(output), "\tPayload (%d bytes):\n",
            size_payload);
    printf("%s\n", output);
}


int main(int argc, char* argv[]){

    printf("WELCOME TO HURRICANE SANDY.\n"); 

    if (argc<2){
        printf("usage: %s <pcap savefile> [\"user_filter\"]\n", argv[0]);
        exit(1);
    }
    char* filter = "tcp";
    if (argc == 3){
        filter = argv[2];
        printf("Using your filter: %s\n", filter);
    }
        
    // open capture file
    char *file = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    cap_h = pcap_open_offline(file, errbuf);
    if (cap_h == NULL){
        printf("Error: %s\n", errbuf);
        exit(1);
    }
    printf("%s successfully opened.\n", file);

    int datalink;
    if ( (datalink = pcap_datalink(cap_h)) < 0)
        failure("pcap_datalink");
//    if ( pcap_datalink(cap_h) != DLT_EN10MB)
//        failure("Not ethernet.");
    printf( "iface: savefile, linktype: %s (%s)\n",
        pcap_datalink_val_to_name(datalink),
        pcap_datalink_val_to_description(datalink));

    // filters!
    struct bpf_program bpfilter;

    if (pcap_compile(cap_h, &bpfilter, filter, 0, PCAP_NETMASK_UNKNOWN) == -1)
        failure("Couldn't parse filter."); 


    if (pcap_setfilter(cap_h, &bpfilter) == -1)
        failure("Couldn't set filter.");

    printf("Filter compiled and set.\n");
    pcap_loop(cap_h, -1, callback, NULL);

    printf("Client packets sent: %d \t Server packets sent: %d\n",
        clientCount, serverCount);
    printf("Total time elapsed: %ld\n", totalTime);
    pcap_freecode(&bpfilter);
    pcap_close(cap_h); 
    printf("\n");
    return 0;
}
