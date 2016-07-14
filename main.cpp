#include<iostream>
#include<pcap.h>
#include<string.h>
#include<arpa/inet.h>

#define BUFSIZE 65000
#define TCP 0x06

using namespace std;

pcap_t *handle;         // packet handle

/***************************************
 * Header Structure
 * ethernet : Ethernet header
 * ip : IP header
 * ip_type : IP version
 * ip_length : IP header length
 * tcp : Tcp header
 ***************************************/
typedef struct sHeader{
    u_char ethernet[14];
    u_char ip[60];
    int ip_type, ip_length=0;
    u_char tcp[20];
}header;

/***************************************
 * Callback Function
 * pkthdr : Packet header information
 * packet : Packet starting pointer
 ***************************************/
void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    static int num=1;                                   // Packet numbering
    header info;                                        // Packet header structure declare
    int temp, cnt=0;
    int header_length=0, data_length = 0;               // Header length(Ethernet+IP+TCP)
    u_char sMAC[6], dMAC[6];                            // SrcMAC, DstMAC
    unsigned short type=0, sPORT, dPORT;                // IP Type, SrcPORT, DstPORT
    unsigned long sIP, dIP;                             // SrcIP, DstIP
    int protocol=0, s1, s2, s3, s4, d1, d2, d3, d4;     // Protocol type, Src, Dst IP token

    memcpy(info.ethernet, packet, 14);                  // ethernet header copy(14 byte)
    packet = &packet[14];                               // packet pointer move
    temp = packet[0];
    info.ip_type = (temp & 0x000000F0) >> 4;            // get ip_type
    info.ip_length = (temp & 0x0000000F) * 4;           // get ip_length(4 byte block)
    memcpy(info.ip, packet, info.ip_length);            // ip header copy(20~60 byte)
    packet = &packet[info.ip_length];                   // packet pointer move
    memcpy(info.tcp, packet, 20);                       // tcp header copy(20 byte)

    for(int i=0; i<6; i++){
        sMAC[i] = info.ethernet[i+6];
        dMAC[i] = info.ethernet[i];
    }

    protocol = info.ip[9];
    header_length = 14 + info.ip_length + 20;           // Ethernet(14) + IP(ip_length) + TCP(20)
    data_length = int(pkthdr->len)-header_length;
    if( (type = ntohs(*((unsigned short *)&(info.ethernet[12])))) != 0x0800) return;    // Type_IP validation
    else if( (info.ip_type != 4) || (protocol != TCP) ) return;                           // IPv4, protocol validation
    else{
        sPORT = ntohs(*((unsigned short *)&(info.tcp[0])));                             // PORT parsing
        dPORT = ntohs(*((unsigned short *)&(info.tcp[2])));
        sIP = ntohl(*((unsigned long *)&(info.ip[12])));
        dIP = ntohl(*((unsigned long *)&(info.ip[16])));
        s1 = (sIP&0xFF000000)>>24;                                                      // SrcIP parsing
        s2 = (sIP&0x00FF0000)>>16;
        s3 = (sIP&0x0000FF00)>>8;
        s4 = (sIP&0x000000FF);
        d1 = (dIP&0xFF000000)>>24;                                                      // DstIP parsing
        d2 = (dIP&0x00FF0000)>>16;
        d3 = (dIP&0x0000FF00)>>8;
        d4 = (dIP&0x000000FF);
        printf("================================[ PACKET %00005d ]================================\n", num);
        printf(">>> Packet Size : %d\n", int(pkthdr->len));
        printf("[*] Protocol : TCP\t\t\t");
        printf("[*] IP Type : IPv4\n");
        printf("[*] Source MAC : %02X:%02X:%02X:%02X:%02X:%02X\t", sMAC[0], sMAC[1], sMAC[2], sMAC[3], sMAC[4], sMAC[5]);
        printf("[*] Destination MAC : %02X:%02X:%02X:%02X:%02X:%02X\n", dMAC[0], dMAC[1], dMAC[2], dMAC[3], dMAC[4], dMAC[5]);
        printf("[*] Source IP : %d.%d.%d.%d\t\t", s1, s2, s3, s4);
        printf("[*] Destination IP : %d.%d.%d.%d\n", d1, d2, d3, d4);
        printf("[*] Source PORT : %d\t\t\t", sPORT);
        printf("[*] Destination PORT : %d\n", dPORT);

        if( data_length != 0 ){                                 // Hexdata(HTTP) routine
            printf("[*] Hex Data\n[0000] ");
            packet = &packet[20];                               // Packet pointer move(Starting point of HTTP data)
            while( cnt != data_length ){
                if( (cnt%16 == 0) && (cnt != 0) ){
                    for(int i=16; i>0; i--){
                        temp = packet[cnt-i];
                        if( !((temp >= 32) && (temp <= 126)) ){ // Not readable data
                            printf(".");
                            continue;
                        }
                        printf("%c", temp);
                    }
                    printf("\n[%0004X] ", cnt);
                }
                printf("%02X ", packet[cnt]);                   // Print hex data
                cnt += 1;
            }
            if( cnt%16 != 0 ){
                for(int i=16-(cnt%16); i>0; i--) printf("   "); // Padding
                for(int i=(cnt%16); i>0; i--){
                    temp = packet[cnt-i];
                    if( !((temp >= 32) && (temp <= 126)) ){     // Not readble data
                        printf(".");
                        continue;
                    }
                    printf("%c", temp);
                }
                printf("\n");
            }
        }
    }
    printf("\n");
    num++;
}

/***************************************
 * Packet Capture Function
 * Get Device information
 * Get pCap handle
 * Packet sniffing
 ***************************************/
void pCapture(){
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL){
        cout << "Can't open dev!" << endl;
        cout << "Err : " << errbuf << endl;
        exit(2);
    }
    handle = pcap_open_live(dev, BUFSIZE, 1, 1000, errbuf);
    if(handle == NULL){
        cout << "Can't open capture!" << endl;
        cout << "Err : " << errbuf << endl;
        exit(2);
    }

    pcap_loop(handle, 0, callback, NULL);
}

int main(int argc, char *argv[]){
    pCapture();

    return 0;
}
