#include "stdint.h"

struct intrareTabelRoutare
{
    uint32_t prefix; 
    uint32_t nextHop;
    uint32_t masca;
    int descriptorInterfata;
};

struct tabelRoutare
{
    int lungime;
    struct intrareTabelRoutare* intrari;
};

struct trieRoutare
{
    struct intrareTabelRoutare cheie;
    struct trieRoutare *left; //1
    struct trieRoutare *right; //0
};

//mapare intre adresaip la adresa mac
struct intrareArp
{
    uint32_t adresaIp;
    uint8_t adresaMac[6]; //vector de 6 octeti 
};

struct tabelaArp
{
    int numarIntrari;
    struct intrareArp *intrari;
};

//content dupa arp hdr
struct headerulArpEFoarteTampit
{
    uint8_t ar_sha[6];
    uint8_t ar_sip[4];
    uint8_t ar_tha[6];
    uint8_t ar_tip[4];
};
