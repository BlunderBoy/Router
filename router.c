#include "skel.h"
#include "stdio.h"
#include "stdlib.h"
#include "tabelRoutare.h"
#include "string.h"
#include "netinet/ip_icmp.h"
#include <netinet/in.h>
#include "queue.h"

#define null NULL
typedef struct intrareTabelRoutare intrareTabelRoutare;
typedef struct tabelRoutare tabelRoutare;
typedef struct trieRoutare trieRoutare;
typedef struct intrareArp intrareArp;
typedef struct headerulArpEFoarteTampit arpData;
typedef struct tabelaArp tabelaArp;

void bonus_ip_checksum(struct iphdr *headerulIp)
{
	uint16_t oldChecksum = headerulIp->check;
	uint16_t oldFieldValue = (headerulIp->protocol << 8) | headerulIp->ttl;
	headerulIp->ttl--;
	uint16_t newFieldValue = (headerulIp->protocol << 8) | headerulIp->ttl;
	uint16_t newChecksum = oldChecksum - (~oldFieldValue) - newFieldValue - 1; 
	headerulIp->check = newChecksum;
}
//se putea face intr-un for loop dar mi se pare 
//ca arata mai inteligibil asa daca o mai verific
uint32_t createNumberFromIP(char *ip)
{
	//un ip e de forma a.b.c.d astfel
	char *token = strtok(ip, "."); //a
	uint32_t a = (uint32_t)atoi(token);

	token = strtok(null, "."); //b
	uint32_t b = (uint32_t)atoi(token);

	token = strtok(null, "."); //c
	uint32_t c = (uint32_t)atoi(token);

	token = strtok(null, "."); //d
	uint32_t d = (uint32_t)atoi(token);

	return (a << 24 | b << 16 | c << 8 | d);
}

intrareTabelRoutare genereazaIntrare(char *buffer)
{
	intrareTabelRoutare intrare;
	char prefix[100];
	char nextHop[100];
	char masca[100];
	char descriptorInterfata[100];

	char *token = strtok(buffer, " "); //prefix
	memcpy(prefix, token, strlen(token));
	
	token = strtok(null, " ");//nextHop
	memcpy(nextHop, token, strlen(token));

	token = strtok(null, " ");//masca
	memcpy(masca, token, strlen(token));

	token = strtok(null, " ");//descriptor interfata
	memcpy(descriptorInterfata, token, strlen(token));


	intrare.prefix = createNumberFromIP(prefix);
	intrare.nextHop = createNumberFromIP(nextHop);
	intrare.masca = createNumberFromIP(masca);
	intrare.descriptorInterfata = atoi(descriptorInterfata);

	return intrare;
}

trieRoutare *creareNod()
{
	trieRoutare *nod = (trieRoutare*)malloc(sizeof(trieRoutare));
	nod->left = null;
	nod->right = null;
	return nod;
}

void adaugaLaTrie(trieRoutare *root, intrareTabelRoutare intrare)
{
	uint32_t coordonate = intrare.masca & intrare.prefix;
	uint32_t shifter = 1u<<31;
	trieRoutare* nodCurent = root;
	while(1)
	{
		if((shifter & coordonate) == 0) //mergem pe dreapta
		{
			if(root->right == null) //daca nu exista nodul il creez
			{
				root->right = creareNod();
				root = root->right;
			}
			else
			{
				root = root->right;
			}
			
			//nodul exista sigur pentru ca ori a fost deja creat, ori tocmai l-am creat
			//deci daca urmatorul bit din masca ar fi 0 masca e gata
			//inseamna ca nodul curent e terminal
			if(((shifter >> 1) & intrare.masca) == 0)
			{
				root->cheie = intrare;
				root = nodCurent;
				break;
			}
		}
		else //mergem pe stanga
		{
			if(root->left == null) //daca nu exista nodul il creez
			{
				root->left = creareNod();
				root = root->left;
			}
			else
			{
				root = root->left;
			}
			//nodul exista sigur pentru ca ori a fost deja creat, ori tocmai l-am creat
			//deci daca urmatorul bit din masca ar fi 0 masca e gata
			//inseamna ca nodul curent e terminal
			if(((shifter >> 1) & intrare.masca) == 0)
			{
				root->cheie = intrare;
				root = nodCurent;
				break;
			}
		}
		shifter >>= 1;
	}
}

trieRoutare* creareTrie()
{
	FILE *fisierIntrare;
	fisierIntrare = fopen("rtable.txt","rt");
	char* buffer = (char*) malloc(100);
	
	//error checking
	DIE(fisierIntrare == null, "nu am gasit fisierul de intrare");

	//alocam spatiu pentru radacina, dummy node
	trieRoutare *root = (trieRoutare* )malloc(sizeof(trieRoutare));
	root->left = null;
	root->right = null;
	//parcurgem fisierul si umplem tabela de routare
	while(fgets(buffer, 100, fisierIntrare))
	{
		intrareTabelRoutare intrare =  genereazaIntrare(buffer);
		adaugaLaTrie(root, intrare);
	}
	return root;
}
intrareTabelRoutare cautareInTrie(uint32_t ip,trieRoutare *root)
{
	unsigned int shifter = 1u<<31;
	trieRoutare *nodCurent = root;

	while(shifter)
	{
		if((shifter & ip) == 0)
		{
			if(nodCurent->right == null)
			{
				return nodCurent->cheie;
			}
			nodCurent = nodCurent->right;
		}
		else
		{
			if(nodCurent->left == null)
			{
				return nodCurent->cheie;
			}
			nodCurent = nodCurent->left;
		}
		shifter >>= 1;
	}	
	//truc ca sa nu mai apara warning de neinitializat
	intrareTabelRoutare dummy = dummy;
	return dummy;
}



// intrareArp* creareTabelaArp()
// {
// 	FILE* fisierArp;
// 	char buffer[100];
// 	fisierArp = fopen("arp_table.txt", "rt");
// 	DIE(fisierArp == null, "nu am gasit arp table");

// 	int counter = 0;
// 	intrareArp *tabelaArp = (intrareArp*)malloc(sizeof(tabelaArp) * 4);
// 	while (fgets(buffer, 100, fisierArp))
// 	{
// 		intrareArp intrare;
// 		char* ip = strtok(buffer, " ");
// 		char* mac = strtok(NULL, " ");

// 		intrare.adresaIp = createNumberFromIP(ip);
// 		hwaddr_aton(mac, intrare.adresaMac);

// 		tabelaArp[counter] = intrare;
// 		counter++;
// 	}
// 	return tabelaArp;
// }

uint32_t extrageAdresaIp(packet packet)
{
	struct iphdr *headerulIp = (struct iphdr *) (packet.payload + sizeof(struct ether_header));
	return headerulIp->daddr;
}

uint32_t extrageSursa(packet packet)
{
	struct iphdr *headerulIp = (struct iphdr *) (packet.payload + sizeof(struct ether_header));
	return headerulIp->saddr;
}

int cautaMAC(uint32_t nextHop, tabelaArp *tabelaArp, uint8_t* mac)
{
	int counter = 0;
	if(tabelaArp->numarIntrari == 0)
	{
		return -1;
	}
	while(counter < tabelaArp->numarIntrari)
	{
		if(tabelaArp->intrari[counter].adresaIp == nextHop)
		{
			memcpy(mac, tabelaArp->intrari[counter].adresaMac, sizeof(uint8_t)*6);
			return 1;
		}
		else
		{
			counter++;
		}
	}
	return -1;
}

void modificaHeaderulEth(uint8_t *adresaMac, int interfata, packet *packet)
{
	//extrag headerul de ip
	uint8_t macInferfata[6];
	get_interface_mac(interfata, macInferfata);
	struct ether_header *headerEthernet = (struct ether_header *)(*packet).payload;
	memcpy(headerEthernet->ether_shost, macInferfata, sizeof(uint8_t) * 6);
	memcpy(headerEthernet->ether_dhost, adresaMac, sizeof(uint8_t) * 6);
}

uint16_t ip_checksum(void* vdata, size_t length) {
	char* data=(char*)vdata;
	uint64_t acc=0xffff;

	unsigned int offset=((uintptr_t)data)&3;
	if (offset) {
		size_t count=4-offset;
		if (count>length) count=length;
		uint32_t word=0;
		memcpy(offset+(char*)&word,data,count);
		acc+=ntohl(word);
		data+=count;
		length-=count;
	}

	char* data_end=data+(length&~3);
	while (data!=data_end) {
		uint32_t word;
		memcpy(&word,data,4);
		acc+=ntohl(word);
		data+=4;
	}
	length&=3;
	if (length) {
		uint32_t word=0;
		memcpy(&word,data,length);
		acc+=ntohl(word);
	}

	acc=(acc&0xffffffff)+(acc>>32);
	while (acc>>16) {
		acc=(acc&0xffff)+(acc>>16);
	}

	if (offset&1) {
		acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
	}

	return htons(~acc);
}

int trimiteICMP(packet* primit, int typeICMP)
{
	struct iphdr *headerulIp = (struct iphdr *) ((*primit).payload + sizeof(struct ether_header));
		packet raspunsICMP;
		struct ether_header *headerEthernetOld = (struct ether_header *)(*primit).payload;

		//completez headerul ethernet
		struct ether_header *headerEthernetICMP = (struct ether_header *)malloc(sizeof(struct ether_header));
		memcpy(headerEthernetICMP->ether_dhost, headerEthernetOld->ether_shost, sizeof(uint8_t) * 6);
		memcpy(headerEthernetICMP->ether_shost, headerEthernetOld->ether_dhost, sizeof(uint8_t) * 6);
		headerEthernetICMP->ether_type = htons(ETHERTYPE_IP);

		//copiez informatia din fostul header si modific ce trebuie modificat la nivel ip
		struct iphdr *headerIpICMP = (struct iphdr *)malloc(sizeof(struct iphdr));
		memcpy(headerIpICMP, headerulIp, sizeof(struct iphdr));
		
		headerIpICMP->saddr = htonl(createNumberFromIP(get_interface_ip(primit->interface)));
		headerIpICMP->daddr = headerulIp->saddr;
		//type of service ICMP = 1
		headerIpICMP->protocol = 0x1;
		headerIpICMP->ttl = 64;
		headerIpICMP->tot_len = htons(sizeof(struct icmphdr) + sizeof(struct iphdr));

		//4 octeti o sa modific cand merge struct icmphdr
		int icmpOFF = sizeof(struct ether_header) + sizeof(struct iphdr);
		struct icmphdr *headerICMPfinal = (struct icmphdr *)malloc(sizeof(struct icmphdr));
		if(typeICMP == 0)
		{
			memcpy(headerICMPfinal, primit->payload + icmpOFF, sizeof(struct icmphdr));
		}
		headerICMPfinal->type = typeICMP; //destination unreacheble
		headerICMPfinal->code = 0;
		headerICMPfinal->checksum = 0;
		headerICMPfinal->checksum = ip_checksum(headerICMPfinal, sizeof(struct icmphdr));

		int ipOFF = sizeof(struct ether_header);

		memcpy(raspunsICMP.payload, headerEthernetICMP, sizeof(struct ether_header));
		memcpy(raspunsICMP.payload + ipOFF, headerIpICMP, sizeof(struct iphdr));
		memcpy(raspunsICMP.payload + icmpOFF, headerICMPfinal, sizeof(struct icmphdr));

		raspunsICMP.len = icmpOFF + sizeof(struct icmphdr);
		send_packet(primit->interface, &raspunsICMP);

		return -1;
}

int verificaPachetSiModifica(packet *primit)
{
	struct iphdr *headerulIp = (struct iphdr *) ((*primit).payload + sizeof(struct ether_header));

	if(headerulIp->ttl <= 1)
	{
		return trimiteICMP(primit, 11);
	}


	//arunca daca checksum e gresit
	if(ip_checksum(headerulIp, sizeof(struct iphdr)) != 0)
	{
		return -1;
	}

	//creste checksum cand scade ttl
	bonus_ip_checksum(headerulIp);
	memcpy(primit->payload + sizeof(struct ether_header), headerulIp, sizeof(struct iphdr));

	return 0;
}

void ipToNetworkOrder(char *ipSursa)
{
	//partea1.partea2.partea3.partea4
	struct in_addr a;
	a.s_addr = inet_addr(ipSursa);
	int partea1 = (a.s_addr & (0xff<<24)) >> 24;
	int partea2 = (a.s_addr & (0xff<<16)) >> 8;
	int partea3 = (a.s_addr & (0xff<<8)) << 8;
	int partea4 = (a.s_addr & (0xff)) << 24;
	a.s_addr = partea1 | partea2 | partea3 | partea4;
	inet_ntoa(a);
}

void trimiteArpRequest(int interfata, uint32_t nextHop)
{
	packet arpRequest;
	uint8_t *macBroadcast = (uint8_t*)malloc(sizeof(uint8_t)*6);
	macBroadcast[0] = 0xff;
	macBroadcast[1] = 0xff;
	macBroadcast[2] = 0xff;
	macBroadcast[3] = 0xff;
	macBroadcast[4] = 0xff;
	macBroadcast[5] = 0xff;
	uint8_t *macUnknown = (uint8_t*)malloc(sizeof(uint8_t)*6);
	macUnknown[0] = 0xff;
	macUnknown[1] = 0xff;
	macUnknown[2] = 0xff;
	macUnknown[3] = 0xff;
	macUnknown[4] = 0xff;
	macUnknown[5] = 0xff;
	uint8_t *macInterfata = (uint8_t*)malloc(sizeof(uint8_t)*6);
	get_interface_mac(interfata, macInterfata);

	struct ether_header* headerEthArp = (struct ether_header*)malloc(sizeof(struct ether_header));
	memcpy(headerEthArp->ether_dhost, macBroadcast, sizeof(uint8_t)*6);
	memcpy(headerEthArp->ether_shost, macInterfata, sizeof(uint8_t)*6);
	headerEthArp->ether_type = htons(ETHERTYPE_ARP);
	struct arphdr* headerArp = (struct arphdr*)malloc(sizeof(struct arphdr)); 
	headerArp->ar_hrd = htons(1);
	headerArp->ar_pro = htons(0x800);
	headerArp->ar_hln = 6;
	headerArp->ar_pln = 4;
	headerArp->ar_op  = htons(1);
	arpData* dateRequest = (arpData*)malloc(sizeof(arpData));

	char *ipSursa;
	ipSursa = get_interface_ip(interfata);
	uint32_t aasd = createNumberFromIP(ipSursa);
	char *chiarIP = (char*)malloc(sizeof(char)*4);
	chiarIP[0] = (aasd>>24) & 0xff;
	chiarIP[1] = (aasd>>16) & 0xff;
	chiarIP[2] = (aasd>>8) & 0xff;
	chiarIP[3] = aasd & 0xff;
	memcpy(dateRequest->ar_sha, macInterfata, sizeof(uint8_t)*6);
	memcpy(dateRequest->ar_sip, chiarIP, sizeof(uint32_t));
	memcpy(dateRequest->ar_tha, macUnknown, sizeof(uint8_t)*6);
	char auxiliar[4];
	auxiliar[0] = (nextHop >> 24) & 0xff;
	auxiliar[1] = (nextHop >> 16) & 0xff;
	auxiliar[2] = (nextHop >> 8) & 0xff;
	auxiliar[3] = nextHop & 0xff;
	memcpy(dateRequest->ar_tip,auxiliar,sizeof(uint32_t));
	int length = sizeof(struct ether_header) + sizeof(struct arphdr) + sizeof(arpData);
	arpRequest.len = length;

	int arpOffset = sizeof(struct ether_header);
	int dataOffset = arpOffset + sizeof(struct arphdr); 
	memcpy(arpRequest.payload, headerEthArp, sizeof(struct ether_header));
	memcpy(arpRequest.payload + arpOffset, headerArp, sizeof(struct arphdr));
	memcpy(arpRequest.payload + dataOffset, dateRequest, sizeof(arpData));
	send_packet(interfata, &arpRequest);
}

int handleIpPachet(packet primit, trieRoutare *radacinaTrie, tabelaArp *tabelaArp, queue *q)
{

	uint32_t adresaDestinatie = ntohl(extrageAdresaIp(primit));

	if(adresaDestinatie == createNumberFromIP(get_interface_ip(primit.interface)))
	{
		struct iphdr *headerulIp = (struct iphdr *) (primit.payload + sizeof(struct ether_header));
		if(headerulIp->protocol == 1) //daca e icmp
		{
			struct icmphdr* headerICMP = (struct icmphdr*)(primit.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
			if (headerICMP->type == 8)
			{
				trimiteICMP(&primit, 0);
			}
			return -1;
		}
	}

	intrareTabelRoutare search = cautareInTrie(adresaDestinatie, radacinaTrie);
	uint32_t nextHop = search.nextHop;
	if(nextHop == 0)
	{
		return trimiteICMP(&primit, 3);
	}

	if(verificaPachetSiModifica(&primit) == -1) //se printeaza din functie eroarea
	{
		return -1;
	}

	int interfata = search.descriptorInterfata;

	uint8_t *adresaMac = (uint8_t*)malloc(sizeof(uint8_t)*6);
	if(tabelaArp->numarIntrari == 0) //initial
	{
		packet *p = (packet*)malloc(sizeof(packet));
		memcpy(p, &primit, sizeof(packet));
		queue_enq(*q, p);
		//send arp request
		trimiteArpRequest(interfata, nextHop);	
		return 1;
	}
	if(cautaMAC(nextHop, tabelaArp, adresaMac) == -1)
	{
		packet *p = (packet*)malloc(sizeof(packet));
		memcpy(p, &primit, sizeof(packet));
		queue_enq(*q, p);
		//send arp request
		trimiteArpRequest(interfata, nextHop);
		return 1;
	}
	else
	{
		modificaHeaderulEth(adresaMac, interfata, &primit);
		send_packet(interfata, &primit);
	}
	return 0;
}
//verifica pentru ce interfata e si o si intoarce cu +1 ca sa mearga ca conditie
int ePentruMine(arpData* data)
{
	int a = 0;
	a = (data->ar_tip[0])<<24 |
		(data->ar_tip[1])<<16 |
		(data->ar_tip[2])<<8 |
		(data->ar_tip[3]);
	uint32_t ip0 = createNumberFromIP(get_interface_ip(0));
	uint32_t ip1 = createNumberFromIP(get_interface_ip(1));
	uint32_t ip2 = createNumberFromIP(get_interface_ip(2));
	uint32_t ip3 = createNumberFromIP(get_interface_ip(3));
	if(a == ip0)
		return 1;
	if(a == ip1)
		return 2;
	if(a == ip2)
		return 3;
	if(a == ip3)
		return 4;
	return 0;
}
intrareArp intrareNouaArp(arpData* data)
{
	intrareArp intrareNoua;
	int ip = 0;
	ip = (data->ar_sip[0])<<24 |
		(data->ar_sip[1])<<16 |
		(data->ar_sip[2])<<8 |
		(data->ar_sip[3]);
	intrareNoua.adresaIp = ip;
	uint8_t mac[6];
	mac[0] = data->ar_sha[0];
	mac[1] = data->ar_sha[1];
	mac[2] = data->ar_sha[2];
	mac[3] = data->ar_sha[3];
	mac[4] = data->ar_sha[4];
	mac[5] = data->ar_sha[5];
	memcpy(intrareNoua.adresaMac, mac, sizeof(uint8_t)*6);
	return intrareNoua;
}

void handleArpPachet(packet primit, trieRoutare *radacinaTrie, tabelaArp *arpTable, queue *q)
{
	//extrag headerul arp ca sa-l modific 
	struct ether_header* header_ethernet = (struct ether_header*)primit.payload;
	uint8_t *auxi = (uint8_t*)malloc(sizeof(uint8_t)*6);
	memcpy(auxi, header_ethernet->ether_shost, sizeof(uint8_t)*6);
	struct arphdr* headerulARP = (struct arphdr*)(primit.payload + sizeof(struct ether_header));
	int offset = sizeof(struct ether_header) + sizeof(struct arphdr);
	arpData* date = (arpData*)(primit.payload + offset); 
	
	//request
	if(ntohs(headerulARP->ar_op) == 1)
	{
		int interfata = 1;
		headerulARP->ar_op = htons(2);
		if((interfata = ePentruMine(date)))
		{
			interfata--;
			//incape si mac si ip pe 6 octeti
			uint8_t *aux = (uint8_t *)malloc(sizeof(uint8_t)*6);
			//interschimb ip-urile
			memcpy(aux, date->ar_sip, sizeof(uint32_t));
			memcpy(date->ar_sip, date->ar_tip, sizeof(uint32_t));
			memcpy(date->ar_tip, aux, sizeof(uint32_t));
			//schimb mac-ul
			memcpy(date->ar_tha, date->ar_sha, sizeof(uint8_t)*6);
			uint8_t *mac = (uint8_t*)malloc(sizeof(uint8_t)*6);
			get_interface_mac(primit.interface, mac);
			memcpy(date->ar_sha, mac, sizeof(uint8_t)*6);
			modificaHeaderulEth(auxi, primit.interface, &primit);
		}
		memcpy(primit.payload + offset, date, sizeof(arpData));
		send_packet(primit.interface, &primit);
	}
	//reply
	else
	{
		arpData* date = (arpData*)(primit.payload + offset);
		intrareArp intrareNoua = intrareNouaArp(date);
		arpTable->intrari[arpTable->numarIntrari] = intrareNoua;
		arpTable->numarIntrari++;

		while(!queue_empty(*q))
		{
			packet *p = (packet*)malloc(sizeof(packet));
			p = (packet*)queue_deq(*q); 
			uint8_t *adresaMac = (uint8_t*)malloc(sizeof(uint8_t*)*6);
			uint32_t adresaDestinatie = ntohl(extrageAdresaIp((packet)*p));
			intrareTabelRoutare search = cautareInTrie(adresaDestinatie, radacinaTrie);
			int nextHop = search.nextHop;
			if(cautaMAC(nextHop, arpTable, adresaMac) == -1)
			{
				break;
			}
			else
			{
				struct ether_header *headerEth = (struct ether_header*)p->payload;
				memcpy(headerEth->ether_dhost, adresaMac, sizeof(uint8_t)*6);
				memcpy((*p).payload, headerEth, sizeof(struct ether_header));
				send_packet(search.descriptorInterfata, p);
			}
		}
		return;
	}
}

int main()
{
	setvbuf ( stdout , NULL , _IONBF , 0) ;
	init();
	int rc;
	packet primit;

	trieRoutare* radacinaTrie = creareTrie();
	tabelaArp* arpTable = (tabelaArp*)malloc(sizeof(tabelaArp));
	arpTable->intrari = (intrareArp*)malloc(sizeof(intrareArp) * 4);
	arpTable->numarIntrari = 0;
	queue q ;
	q = queue_create();

	while (1) {
		//primesc pachetul
		rc = get_packet(&primit);
		DIE(rc < 0, "dawdawfaw");

		//1 pentru ip, 2 arpm
		struct ether_header *headerEthernet = (struct ether_header *)primit.payload;
		int etherType = ntohs(headerEthernet->ether_type);
		
		if(etherType == ETHERTYPE_IP)
		{
			handleIpPachet(primit, radacinaTrie, arpTable, &q);
		}
		if(etherType == ETHERTYPE_ARP)
		{
			handleArpPachet(primit, radacinaTrie, arpTable, &q);
		}		
	}
}
