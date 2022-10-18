#include "queue.h"
#include "skel.h"

void bonus(struct iphdr *ip_hdr) {

	uint16_t oldChecksum = ip_hdr->check;
	uint16_t oldTtl = (ip_hdr->protocol << 8) | ip_hdr->ttl;
	ip_hdr->ttl--;
	uint16_t newTtl = (ip_hdr->protocol << 8) | ip_hdr->ttl;
	uint16_t newChecksum = oldChecksum - (~oldTtl) - newTtl - 1;
	ip_hdr->check = newChecksum;
}

int get_best_route(uint32_t dest_ip, struct route_table_entry *route_table, int rtable_len) {
	size_t index = -1;
	for (size_t i = 0; i < rtable_len; i++) {
		if (route_table[i].prefix == (route_table[i].mask & dest_ip)) {
			if (index == -1 || ntohl(route_table[index].mask) < ntohl(route_table[i].mask)) {
				index = i;
			} else if (route_table[index].mask == route_table[i].mask) {
				index = i;
			}
		}
	}
	return index;
}

int compare(const void * a, const void * b) {
	struct route_table_entry *route_table1 = (struct route_table_entry *)a;
	struct route_table_entry *route_table2 = (struct route_table_entry *)b;
	if (ntohl(route_table1->prefix) == ntohl(route_table2->prefix)) {
			return (int)route_table2->mask - (int)route_table1->mask; 
	}

	return (int)route_table2->prefix - (int)route_table1->prefix;
}


/* sortare crescatoare dupa prefix si masca
	(daca prefixurile sunt egale sortam dupa masca) */
void sortare(struct route_table_entry *route_table, int rtable_len){
	for(int i = 0; i < rtable_len; i++) {
		for(int j = i + 1; j < rtable_len; j++) {
			if (ntohl(route_table[i].prefix) > ntohl(route_table[j].prefix) ||
				(route_table[i].prefix == route_table[j].prefix && (ntohl(route_table[i].mask) > ntohl(route_table[j].mask)))){
				struct route_table_entry aux;
				aux = route_table[i];
				route_table[i] = route_table[j];
				route_table[j] = aux;
			}
		}
	}
}

int get_route(uint32_t dest_ip, struct route_table_entry *route_table, int l, int r){
/* este o cautare binara modificata 
   cand se gaseste un match ( adica if-ul cu egal este adevarat)
   mask-ul cel mai mare s-ar afla la ultima pozitie cand if-ul este adevarat 
   si cautam indexul */
	if( r >= l) {
		int mid = l + (r - l) / 2;

		if (route_table[mid].prefix == (dest_ip & route_table[mid].mask)){
			while(route_table[mid + 1].prefix == (dest_ip & route_table[mid + 1].mask)){
				mid = mid + 1;
			}
			return mid;
		}

		if (route_table[mid].prefix > (dest_ip & route_table[mid].mask))
			return get_route(dest_ip, route_table, l, mid - 1);

		return get_route(dest_ip, route_table, mid + 1, r);
	}
	return -1;
}

void sendArpRequest(int interface, uint32_t nextHop) {

	packet request;

	uint8_t macBroadcast[6];
	memset(macBroadcast, 255, 6); // 0xffffffffff

	uint8_t macInterface[6];
	get_interface_mac(interface, macInterface);

	struct ether_header *eth_header = (struct ether_header*)malloc(sizeof(struct ether_header));
	memcpy(eth_header->ether_dhost, macBroadcast, 6);
	memcpy(eth_header->ether_shost, macInterface, 6);
	eth_header->ether_type = htons(ETHERTYPE_ARP);

	struct arp_header *arp_hdr = (struct arp_header*)malloc(sizeof(struct arp_header));
	arp_hdr->htype = htons(1); // for Ethernet
	arp_hdr->hlen = ETH_ALEN; // length 6 for MAC
	arp_hdr->ptype = htons(ETHERTYPE_IP); // for IPv4
	arp_hdr->plen = 4; // length 4 for IPv4
	arp_hdr->op = htons(1); // Request
	memcpy(arp_hdr->sha, macInterface, 6);
	memcpy(arp_hdr->tha, macBroadcast, 6);

	uint32_t senderIP;
	inet_aton(get_interface_ip(interface), (struct in_addr *) &senderIP);
	arp_hdr->spa = senderIP;

	arp_hdr->tpa = nextHop;

	request.len = sizeof(struct ether_header) + sizeof(struct arp_header);
	memcpy(request.payload, eth_header, sizeof(struct ether_header));
	memcpy(request.payload + sizeof(struct ether_header), arp_hdr, sizeof(struct arp_header));
	request.interface = interface;

	send_packet(&request);
}

int send_icmp(packet *m, int type) {
	
	packet response;
	struct iphdr *old_ip_hdr = (struct iphdr *)(m->payload + sizeof(struct ether_header));
	struct ether_header *old_eth_hdr = (struct ether_header *)m->payload;

	// noul header
	struct ether_header *new_eth_hdr = (struct ether_header *)malloc(sizeof(struct ether_header));
	memcpy(new_eth_hdr->ether_dhost, old_eth_hdr->ether_dhost, 6);
	memcpy(new_eth_hdr->ether_shost, old_eth_hdr->ether_shost, 6);
	new_eth_hdr->ether_type = htons(ETHERTYPE_IP);
	
	struct iphdr *new_ip_hdr = (struct iphdr *)malloc(sizeof(struct iphdr));
	memcpy(new_ip_hdr, old_ip_hdr, sizeof(struct iphdr));
	new_ip_hdr->daddr = old_ip_hdr->saddr;
	uint32_t sender;
	inet_aton(get_interface_ip((*m).interface), (struct in_addr *) &sender);
	new_ip_hdr->saddr = htonl(sender);
	new_ip_hdr->ttl = 64;
	new_ip_hdr->protocol = 1;
	new_ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));

	struct icmphdr *icmp_hdr = (struct icmphdr *)malloc(sizeof(struct icmphdr));
	icmp_hdr->type = type;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = icmp_checksum((void *)icmp_hdr, sizeof(struct icmphdr));

	memcpy(response.payload, new_eth_hdr, sizeof(struct ether_header));
	memcpy(response.payload + sizeof(struct ether_header), new_ip_hdr, sizeof(struct iphdr));
	memcpy(response.payload + sizeof(struct ether_header) + sizeof(struct iphdr), icmp_hdr, sizeof(struct icmphdr));
	response.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
	response.interface = m->interface;

	send_packet(&response);

	return -1;
}

int searchMac(uint32_t nextHop, int arp_table_len, struct arp_entry *arp_table, uint8_t *mac) {
	int counter = 0;
	if (arp_table_len == 0) {
		return -1;
	}

	while (counter < arp_table_len) {
		if (arp_table[counter].ip == nextHop) {
			memcpy(mac, arp_table[counter].mac, 6);
			return 1;
		} else {
			counter++;
		}
	}
	return -1;
}

void handleARP(packet *m, struct route_table_entry *rtable, struct arp_entry *arp_table, int rtable_len, int *arp_table_len, queue q, int *q_len) {

	struct ether_header *eth_header = (struct ether_header *)m->payload;
	struct arp_header *arp_hdr = (struct arp_header *)(m->payload + sizeof(struct ether_header));

	if (arp_hdr->op == htons(1)) {
		uint32_t senderIP;
		inet_aton(get_interface_ip(m->interface), (struct in_addr *) &senderIP);
		if (arp_hdr->tpa == senderIP) {

			arp_hdr->op = htons(2);
			uint32_t aux;
			aux = arp_hdr->spa;
			arp_hdr->spa = arp_hdr->tpa;
			arp_hdr->tpa = aux;

			memcpy(arp_hdr->tha, arp_hdr->sha, 6);
			get_interface_mac(m->interface, arp_hdr->sha);

			memcpy(eth_header->ether_dhost, eth_header->ether_shost, 6);
			memcpy(eth_header->ether_shost, arp_hdr->sha, 6);
		
			send_packet(m);
		}

	} else if (arp_hdr->op == htons(2)) {

		arp_table[*arp_table_len].ip = arp_hdr->spa;
		memcpy(arp_table[*arp_table_len].mac, arp_hdr->sha, 6);
		(*arp_table_len)++;

		for (int i = 0; i < *q_len && !queue_empty(q); i++){

			packet *received ;

			received = (packet*)queue_deq(q);


			struct iphdr *ip_hdr = (struct iphdr *)(received->payload + sizeof(struct ether_header));

			int index = get_best_route(ip_hdr->daddr, rtable, rtable_len);


			if (index < 0)
				continue;


			struct route_table_entry *found = &rtable[index];

            if (found->next_hop == arp_hdr->spa) {
                (*q_len)--;
                struct ether_header *ether_header = (struct ether_header *) received->payload;
                get_interface_mac(found->interface, ether_header->ether_shost);
                memcpy(ether_header->ether_dhost, arp_hdr->sha, 6);
                received->interface = found->interface;
                send_packet(received);
            } else {
                queue_enq(q, received);

            }
		}
		return;
	}
}

int handleIP(packet *m, struct route_table_entry *rtable, struct arp_entry *arp_table, int rtable_len, int *arp_table_len, queue q, int *q_len) {

	struct iphdr *ip_hdr = (struct iphdr *)(m->payload + sizeof(struct ether_header));
	struct ether_header *eth_header = (struct ether_header *)m->payload;
	uint32_t address;
	inet_aton(get_interface_ip(m->interface), (struct in_addr *) &address);

	if (ip_hdr->daddr == address) {
		if (ip_hdr->protocol == 1) {
			struct icmphdr *icmp_hdr = (struct icmphdr *)(m->payload + sizeof(struct ether_header) + sizeof(struct iphdr));
			if (icmp_hdr->type == 8) {
				send_icmp(m, 0);
			}
			return -1;
		}
	}

	/* functia returneaza indexul din vectorul de structuri in urma cautarii */
	int index = get_best_route(ip_hdr->daddr, rtable, rtable_len);

	/* daca este mai mic decat zero inseamna ca nu s-a gasit*/
	if (index < 0)
		return send_icmp(m, 3);

	/* o salvam intr-o copie */
	struct route_table_entry *found = &rtable[index];

	if (found->next_hop == 0) {
		return send_icmp(m, 3);
	}

	if (ip_hdr->ttl <= 1) {
		return send_icmp(m, 11);
	}

	if (ip_checksum((void *) ip_hdr, sizeof(struct iphdr)) != 0) {
		return -1;
	}

	bonus(ip_hdr);

	uint8_t adresaMac[6];

	if (searchMac(found->next_hop, *arp_table_len, arp_table, adresaMac) == -1) {
		packet *pack = malloc(sizeof(packet));
		memcpy(pack, m, sizeof(packet));
        queue_enq(q, pack);
		(*q_len)++;
		sendArpRequest(found->interface, found->next_hop);
		return 1;
	} else {
		uint8_t macInterface[6];
		get_interface_mac(found->interface, macInterface);
		memcpy(eth_header->ether_shost, macInterface, 6);
		memcpy(eth_header->ether_dhost, adresaMac, 6);
		m->interface = found->interface;
		send_packet(m); 
	}
	return 0;
}

int main(int argc, char *argv[]) {
	packet m;
	int rc;

	init(argc - 2, argv + 2);

	struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * 100000);
	struct arp_entry *arp_table = malloc(sizeof(struct arp_entry) * 100000);
	
	/* functiile de citire pentru rtable si arp_table */
	int rtable_len = read_rtable(argv[1], rtable);
	int arp_table_len = 0;

	/* sortarea lui rtable */
	// sortare(rtable, rtable_len);
	//qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare);

	queue q;
	q = queue_create();
	int q_len = 0;

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");
		/* TODO */

		struct ether_header *eth_header = (struct ether_header *)m.payload;

		uint8_t macAddress[6];
		uint8_t mac1[6];
		uint8_t mac2[6];
		get_interface_mac(m.interface, macAddress);
		memcpy(mac1, macAddress, 6);

		uint8_t macBroadcast[6];
		memset(macBroadcast, 255, 6); // 0xffffffffff
		memcpy(mac2, macBroadcast, 6);

		if ((memcmp(eth_header->ether_dhost, mac1, 6) == 0) || (memcmp(eth_header->ether_dhost, mac2, 6) == 0)) {
			if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
				handleIP(&m, rtable, arp_table, rtable_len, &arp_table_len, q, &q_len);
			} else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
				handleARP(&m, rtable, arp_table, rtable_len, &arp_table_len, q, &q_len);
			}
		}
	}
}