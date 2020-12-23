#include <string>
#include <iostream>
#include <pcap.h>

using namespace std;

struct    ether_header {
    u_char    ether_dhost[6];
    u_char    ether_shost[6];
    u_char    ether_type[2];
};

/* 4 bytes IP address */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service
    u_short tlen;           // Total length
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
}udp_header;

void PrintData(u_int startOctet, u_int endOctet, const u_char *data)
{
    for (u_int i = startOctet; i <= endOctet; i++)
    {
        // Print each octet as hex (x), make sure there is always two characters (.2).
        printf("%.2x", data[i]);
        
        if(i<endOctet)
            printf(":");
    }
    printf(" ");
}

int main(int argc, char *argv[])
{
    // Get a file name
    string file = argv[1];
    
    // Create an char array to hold the error.
    char errbuff[PCAP_ERRBUF_SIZE];
    
    // Open the file and store result in pointer to pcap_t
    // Use pcap_open_offline
    pcap_t * pcap = pcap_open_offline(file.c_str(), errbuff);
    
    // Create a header and a data object
    // Create a header object:
    struct pcap_pkthdr *header;
    
    // Create a character array using a u_char
    // typedef unsigned char   u_char;
    const u_char *data;
    
    //Loop through packets and print them to screen
    u_int packetCount = 0;
    while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0)
    {
        // Show the packet number
        //printf("Packet # %i\n", ++packetCount);
        
        // Show the size in bytes of the packet
        //printf("Packet size: %d bytes\n", header->len);
        
        // Show a warning if the length captured is different
        if (header->len != header->caplen)
            printf("Warning!\n");
        
        // Show Epoch Time
        //printf("Epoch Time: %d:%d seconds\n", header->ts.tv_sec, header->ts.tv_usec);
        
        char my_time[1024];
        strftime(my_time, sizeof(my_time), "%Y-%m-%d %T", localtime(&(header->ts.tv_sec))); //獲取時間
        
        printf("%s ", my_time);
        
        ip_header *ih;
        udp_header *uh;
        u_int ip_len;
        u_short sport,dport;
        
        struct ether_header *ethernet;
        ethernet = (struct ether_header*)(data);
        
        // Print Source Mac Address
        //printf("Src MAC: ");
        PrintData(0,5,ethernet->ether_shost);
        
        // Print Destination Mac Address
        //printf("Dst MAC: ");
        PrintData(0,5,ethernet->ether_dhost);
        
        // Print EtherType
        int ethertype = (ethernet->ether_type[0] << 8) + ethernet->ether_type[1];
        //printf("Ethertype: %s (%#.4x)\n", get_ethertype(ethertype), ethertype);
        
        switch (ethertype) {
            case 0x0800:
                printf("IPv4");
                break;
            case 0x0842:
                printf("ARP");
                break;
            case 0x86DD:
                printf("IPv6");
                break;
            default:
                printf("unknown");
                break;
        }
        
        printf("(%#.4x) ", ethertype);
        
        if(ethertype==0x0800)
        {
        
            /* retireve the position of the ip header */
            ih = (ip_header *) (data +
                                14); //length of ethernet header
            
            int pr=-1;
            
            switch (ih->proto) {
                case 6:
                    //printf("TCP ");
                    pr=6;
                    break;
                case 17:
                    //printf("UDP ");
                    pr=17;
                    break;
                default:
                    //printf("unknown ");
                    break;
            }
            
            /* retireve the position of the udp header */
            ip_len = (ih->ver_ihl & 0xf) * 4;
            uh = (udp_header *) ((u_char*)ih + ip_len);
            
            /* convert from network byte order to host byte order */
            sport = ntohs( uh->sport );
            dport = ntohs( uh->dport );
            
            /* print ip addresses and udp ports */
            printf("%d.%d.%d.%d",
                   ih->saddr.byte1,
                   ih->saddr.byte2,
                   ih->saddr.byte3,
                   ih->saddr.byte4);
            
            if(pr != -1)
                printf(":%d", sport);
            
            printf(" -> ");
            
            printf("%d.%d.%d.%d",
                   ih->daddr.byte1,
                   ih->daddr.byte2,
                   ih->daddr.byte3,
                   ih->daddr.byte4);
            
            if(pr != -1)
                printf(":%d", dport);
        }
            
        printf("\n");
        
        // loop through the packet and print it as hexidecimal representations of octets
        // We also have a function that does this similarly below: PrintData()
        for (u_int i=0; (i < header->caplen ) ; i++)
        {
            // Start printing on the next after every 16 octets
            if ( (i % 16) == 0) printf("\n");
            
            // Print each octet as hex (x), make sure there is always two characters (.2).
            printf("%.2x ", data[i]);
        }
        
        // Add two lines between packets
        printf("\n\n");
    }
}
