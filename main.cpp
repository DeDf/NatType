
#include <stdio.h>
#include <stdlib.h>
#include "nat_type.h"

#pragma comment(lib, "Ws2_32.lib")

static char* STUN_SERVER = "stun.ideasip.com";
#define STUN_SERVER_PORT 3478
#define LOCAL_PORT 34780

int main(int argc, char* argv[])
{
    char*    stun_server = STUN_SERVER;
    uint16_t stun_port   = STUN_SERVER_PORT;
    //
    char*    local_host  = "0.0.0.0";
    uint16_t local_port  = LOCAL_PORT;
    //
    int i = 1;

    static char* usage = "usage: [-h] [-H STUN_HOST] [-P STUN_PORT] [-i SOURCE_IP] [-p SOURCE_PORT]\n";
    char opt;
    while (i < argc)
    {
        opt = argv[i][1];

        switch (opt)
        {
            case 'h':
                printf("%s", usage);
                break;
            case 'H':
                stun_server = &argv[i][3];
                break;
            case 'P':
                stun_port = atoi(&argv[i][3]);
                break;
            case 'i':
                local_host = &argv[i][3];
                break;
            case 'p':
                local_port = atoi(&argv[i][3]);
                break;
            case '?':
            default:
                printf("invalid option: %c\n", opt);
                printf("%s", usage);

                return -1;
        }

        i++;
    }

    nat_type type = detect_nat_type(stun_server, stun_port, local_host, local_port);

    printf("NAT type: %s\n", get_nat_desc(type));

    getchar();
    return 0;
}
