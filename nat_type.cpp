#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include "nat_type.h"

#pragma comment(lib, "Ws2_32.lib")

#define EADDRINUSE              WSAEADDRINUSE

static const char* nat_types[] = {
    "blocked",
    "open internet",
    "full cone",
    "restricted NAT",
    "port-restricted cone",
    "symmetric NAT",
    "error"
};

char* encode16(char* buf, uint16_t data) {
    uint16_t ndata = htons(data);
    memcpy(buf, (void*)(&ndata), sizeof(uint16_t));
    return buf + sizeof(uint16_t);
}

char* encode32(char* buf, uint32_t data) {
    uint32_t ndata = htonl(data);
    memcpy(buf, (void*)(&ndata), sizeof(uint32_t));

    return buf + sizeof(uint32_t);
}

char* encodeAtrUInt32(char* ptr, uint16_t type, uint32_t value) {
    ptr = encode16(ptr, type);
    ptr = encode16(ptr, 4);
    ptr = encode32(ptr, value);

    return ptr;
}

char* encode(char* buf, const char* data, unsigned int length) {
    memcpy(buf, data, length);
    return buf + length;
}

static int stun_parse_atr_addr( char* body, unsigned int hdrLen, StunAtrAddress* result, int type )
{
    if (hdrLen == 8 /* ipv4 size */ || hdrLen == 20 /* ipv6 size */ ) {
        body++;  // Skip pad
        result->family = *body++;

        uint16_t nport;
        memcpy(&nport, body, 2);
        body += 2;
        result->port = ntohs(nport);

        if (result->family == IPv4Family)
        {     
            uint32_t naddr;
            memcpy(&naddr, body, sizeof(uint32_t)); body+=sizeof(uint32_t);
            result->addr.ipv4 = ntohl(naddr);
            uint8_t *p = (uint8_t *)&naddr;

            if (type)
                printf(" local  : %d.%d.%d.%d:%d\n", p[0], p[1], p[2], p[3], result->port);
            else
                printf(" remote : %d.%d.%d.%d:%d\n", p[0], p[1], p[2], p[3], result->port);

            // Note:  addr.ipv4 is stored in host byte order
            return 0;
        } else if (result->family == IPv6Family) {
            printf("ipv6 is not implemented yet");
        }
    }

    return -1;
}

static void gen_random_string(char *s, const int len) {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    int i = 0;
    for (; i < len; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }
}

static int send_bind_request(SOCKET sock, const char* remote_host, uint16_t remote_port, uint32_t change_flag, StunAtrAddress* addr_array)
{
    char* buf = (char*)malloc(MAX_STUN_MESSAGE_LENGTH);
    char* ptr = buf;

    StunHeader h;
    h.msgType = BindRequest;
    
    gen_random_string((char*)&h.magicCookieAndTid, 16);

    ptr = encode16(ptr, h.msgType);
    char* lengthp = ptr;
    ptr = encode16(ptr, 0);
    ptr = encode(ptr, (const char*)&h.id, sizeof(h.id));

    if (change_flag) {
        ptr = encodeAtrUInt32(ptr, ChangeRequest, change_flag);

        // length of stun body
        encode16(lengthp, (uint16_t)(ptr - buf - sizeof(StunHeader)));
    }

    struct hostent *server = gethostbyname(remote_host);
    if (server == NULL) {
        fprintf(stderr, "no such host, %s\n", remote_host);
        free(buf);

        return -1;
    }

    if (remote_host)
        printf("\nstun server : %s\n", remote_host);
    struct sockaddr_in remote_addr;

    remote_addr.sin_family = AF_INET;
    memcpy(&remote_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);
    remote_addr.sin_port = htons(remote_port); 

    uint8_t *p = (uint8_t *)&remote_addr.sin_addr.s_addr;
    printf("\nsendto   %d.%d.%d.%d:%d\n", p[0], p[1], p[2], p[3], remote_port);

    if (-1 == sendto(sock, buf, (int)(ptr - buf), 0, (struct sockaddr *)&remote_addr, sizeof(remote_addr))) {
        free(buf);
        return -1;
    }

    ULONG time = 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&time, sizeof(time));

    socklen_t fromlen = sizeof remote_addr;
    int32_t RevcLen = recvfrom(sock, buf, 512, 0, (struct sockaddr *)&remote_addr, &fromlen);
    if (RevcLen <= 0) {
        free(buf);
        int error = WSAGetLastError();
        return -1;
    }
    p = (uint8_t *)&remote_addr.sin_addr.S_un.S_addr;
    printf("recvfrom %d.%d.%d.%d:%d\n", p[0], p[1], p[2], p[3], ntohs(remote_addr.sin_port));

    StunHeader reply_header;
    memcpy(&reply_header, buf, sizeof(StunHeader));

    uint16_t msg_type = ntohs(reply_header.msgType);

    if (msg_type == BindResponse) {
        char* body = buf + sizeof(StunHeader);
        uint16_t size = ntohs(reply_header.msgLength);

        StunAtrHdr* attr;
        unsigned int attrLen;
        unsigned int attrLenPad;  
        int atrType;

        while (size > 0) {
            attr = (StunAtrHdr*)(body);

            attrLen = ntohs(attr->length);
            // attrLen may not be on 4 byte boundary, in which case we need to pad to 4 bytes when advancing to next attribute
            attrLenPad = attrLen % 4 == 0 ? 0 : 4 - (attrLen % 4);  
            atrType = ntohs(attr->type);

            if ( attrLen + attrLenPad + 4 > size ) {
                free(buf);
                return -1;
            }

            body += 4; // skip the length and type in attribute header
            size -= 4;

            switch (atrType) {
            case MappedAddress:
                if (stun_parse_atr_addr(body, attrLen, addr_array, 1)) {
                    free(buf);
                    return -1;
                }
                break;
            case ChangedAddress:
                if (stun_parse_atr_addr( body, attrLen, addr_array + 1, 0)) {
                    free(buf);
                    return -1;
                }
                break;
            default:
                // ignore
                break;
            }
            body += attrLen + attrLenPad;
            size -= attrLen + attrLenPad;
        }
    }

    free(buf);
    return 0;
}

const char* get_nat_desc(nat_type type) {
    return nat_types[type];
}

nat_type detect_nat_type(const char* stun_host, uint16_t stun_port, const char* local_host, uint16_t local_port)
{
    nat_type type;
    uint32_t mapped_ip   = 0;
    uint16_t mapped_port = 0;

    WSADATA   wsaData = {0};
    if (0 != WSAStartup(MAKEWORD(2,2), &wsaData))
    {
        printf ("WSAStartup failed. errno=[%d]\n", WSAGetLastError());
        return   Error;
    }

    SOCKET s;
    if((s = socket(AF_INET, SOCK_DGRAM, 0)) <= 0)  {  
        return Error;  
    }

    struct sockaddr_in local_addr;
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = inet_addr(local_host);
    local_addr.sin_port = htons(local_port);  

    if (bind(s, (struct sockaddr *)&local_addr, sizeof(local_addr))) {
        if (errno == EADDRINUSE) {
            printf("addr in use, try another port\n");
        }

        type = Error;
        goto cleanup_sock;
    }

    // 0 for mapped addr, 1 for changed addr
    StunAtrAddress bind_result[2];
    memset(bind_result, 0, sizeof(StunAtrAddress) * 2);

    if (send_bind_request(s, stun_host, stun_port, 0, bind_result))
    {
        type = Blocked;
        goto cleanup_sock;
    }

    mapped_ip = bind_result[0].addr.ipv4; // in host byte order
    mapped_port = bind_result[0].port;
    uint32_t changed_ip = bind_result[1].addr.ipv4;
    uint16_t changed_port = bind_result[1].port;

    struct in_addr mapped_addr;
    mapped_addr.s_addr = htonl(mapped_ip);

    if (changed_ip != 0 && changed_port != 0)
    {
        if (send_bind_request(s, stun_host, stun_port, ChangeIpFlag | ChangePortFlag, bind_result))
        {
            struct in_addr addr;
            addr.S_un.S_addr = htonl(changed_ip);
            char* alt_host = inet_ntoa(addr);

            memset(bind_result, 0, sizeof(StunAtrAddress) * 2);

            // changed port only 
            if (send_bind_request(s, alt_host, changed_port, 0, bind_result))
            {
                printf("failed to send request to alterative server\n");
                type = Error;
                goto cleanup_sock;
            }

            if (mapped_ip != bind_result[0].addr.ipv4 || mapped_port != bind_result[0].port) {
                type = SymmetricNAT;
                goto cleanup_sock;
            }

            if (send_bind_request(s, alt_host, changed_port, ChangePortFlag, bind_result)) {
                type = RestricPortNAT;
                goto cleanup_sock;
            }

            type = RestricNAT;
            goto cleanup_sock;
        }
        else
        {
            type = FullCone;    
            goto cleanup_sock;
        }
    } else {
        printf("no alterative server, can't detect nat type\n");
        type = Error;
        goto cleanup_sock;
    }

cleanup_sock:
    closesocket(s);
    return type;
}
