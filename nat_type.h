
#pragma once

typedef signed char        int8_t;
typedef short              int16_t;
typedef int                int32_t;
typedef long long          int64_t;
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;

typedef enum {
    Blocked,
    OpenInternet,
    FullCone,
    RestricNAT,
    RestricPortNAT,
    SymmetricNAT,
    Error,
} nat_type;

#define MAX_STUN_MESSAGE_LENGTH 512

// const static constants cannot be used in case label
#define MappedAddress 0x0001
#define SourceAddress 0x0004
#define ChangedAddress 0x0005

// define stun constants
const static uint8_t  IPv4Family = 0x01;
const static uint8_t  IPv6Family = 0x02;

const static uint32_t ChangeIpFlag   = 0x04;
const static uint32_t ChangePortFlag = 0x02;

const static uint16_t BindRequest      = 0x0001;
const static uint16_t BindResponse     = 0x0101;

const static uint16_t ResponseAddress  = 0x0002;
const static uint16_t ChangeRequest    = 0x0003; /* removed from rfc 5389.*/
const static uint16_t MessageIntegrity = 0x0008;
const static uint16_t ErrorCode        = 0x0009;
const static uint16_t UnknownAttribute = 0x000A;
const static uint16_t XorMappedAddress = 0x0020;

typedef struct { uint32_t longpart[4]; }  UInt128;
typedef struct { uint32_t longpart[3]; }  UInt96;

typedef struct 
{
    uint32_t magicCookie; // rfc 5389
    UInt96 tid;
} Id;

typedef struct 
{
    uint16_t msgType;
    uint16_t msgLength; // length of stun body
    union
    {
        UInt128 magicCookieAndTid;
        Id id;
    };
} StunHeader;

typedef struct
{
    uint16_t type;
    uint16_t length;
} StunAtrHdr;

typedef struct
{
    uint8_t family;
    uint16_t port;
    union
    {
        uint32_t ipv4;  // in host byte order
        UInt128 ipv6; // in network byte order
    } addr;
} StunAtrAddress;

nat_type detect_nat_type(const char* stun_host, uint16_t stun_port, const char* local_host, uint16_t local_port);

const char* get_nat_desc(nat_type type);
