#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h> 
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define ETHERTYPE_IP 0x0800
#define TABLESIZE 100000
#define ICMP_ECHO 8

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* Mac table */
struct arp_entry *arp_table;
int arp_table_len;


/* comparator that sorts by prefix and then if they are equal by mask */
int comp(const void* ip1, const void* ip2) {
	const struct route_table_entry* a = ip1;
	const struct route_table_entry* b = ip2;

    if ((ntohl(a->prefix) & ntohl(a->mask)) == (ntohl(b->prefix) & ntohl(b->mask))) {
        if (ntohl(a->mask) <= ntohl(b->mask))
        	return -1;
    	else
        	return 1;
	}

	return ((ntohl(a->prefix) & ntohl(a->mask))) - ((ntohl(b->prefix) & ntohl(b->mask)));
}

/*
 Returns a pointer to the best matching route, or NULL if there
 is no matching route.
*/
struct route_table_entry *get_best_route(uint32_t ip_dest) {
    int l = 0, r = rtable_len - 1;

    // Searching the best route entry through binary search
    while (l <= r) {
        int mid = l + (r - l) / 2;
        if ((ntohl(rtable[mid].mask) & ntohl(ip_dest)) >= ntohl(rtable[mid].prefix))
            l = mid + 1;
        else
            r = mid - 1;
    }
    // If we found it we return it else we return NULL
    if ((ntohl(rtable[r].mask) & ntohl(ip_dest)) == ntohl(rtable[r].prefix)){
        return &rtable[r];
	}

    return NULL;
}

/* Iterate through the MAC table and search for an entry
that matches given IP. */
struct arp_entry *get_mac_entry(uint32_t given_ip) {
	for (int i = 0; i < arp_table_len; i++) {
        if (arp_table[i].ip == given_ip) {
            return &arp_table[i];
		}
    }

	return NULL;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	/* Code to allocate the MAC and route tables */
	rtable = malloc(sizeof(struct route_table_entry) * TABLESIZE);
	DIE(rtable == NULL, "memory");

	arp_table = malloc(sizeof(struct  arp_entry) * TABLESIZE);
	DIE(arp_table == NULL, "memory");
	
	/* Read the static routing table and the MAC table */
	rtable_len = read_rtable(argv[1], rtable);
	arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	/* Sorting the route table */
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), comp);

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
		struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

		/* Check if we don't have an IPv4 packet and drop it
		because I haven't implemented the ARP */
		if (eth_hdr->ether_type != ntohs(ETHERTYPE_IP)) {
			printf("Ignored non-IPv4 packet\n");
			continue;
		}

		// Check if packet is ICMP and act accordingly.
		if (ip_hdr->daddr == inet_addr(get_interface_ip(interface)) && icmp_hdr->type == ICMP_ECHO) {
			// icmp reply
			icmp_hdr->type = 0;
			icmp_hdr->checksum = 0;
			icmp_hdr->checksum = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr) + sizeof(struct icmphdr));

			//swap MAC adress
			unsigned char aux[6];
			memcpy(aux, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
			memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, sizeof(eth_hdr->ether_dhost));
			memcpy(eth_hdr->ether_dhost, aux, sizeof(aux));

			//swap IP adress
			uint32_t aux2;
			aux2 = ip_hdr->daddr;
			ip_hdr->daddr = ip_hdr->saddr;
			ip_hdr->saddr = aux2;

			send_to_link(interface, buf, len);
			continue;
		}

		/* TODO 2.1: Check the ip_hdr integrity by verifying checksum */
		uint16_t iphdrsave = ntohs(ip_hdr->check);
		ip_hdr->check = htons(0);
		uint16_t sum = 0;
		sum = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
		if (sum != iphdrsave) {
			continue;
		}

		/* Call get_best_route to find the most specific route */
		struct route_table_entry* route = get_best_route(ip_hdr->daddr);
		if (route == NULL) {
			//icmp host unreachable
			ip_hdr->protocol = 1;
			icmp_hdr->type = 3;
	 		icmp_hdr->code = 0;
	 		icmp_hdr->checksum = 0;
	 		icmp_hdr->checksum = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr) + sizeof(struct icmphdr));

			//swap MAC adress
			unsigned char aux[6];
			memcpy(aux, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
			memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, sizeof(eth_hdr->ether_dhost));
			memcpy(eth_hdr->ether_dhost, aux, sizeof(aux));

			//swap IP adress
			uint32_t aux2;
			aux2 = ip_hdr->daddr;
			ip_hdr->daddr = ip_hdr->saddr;
			ip_hdr->saddr = aux2;

			ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
			len =  sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
			send_to_link(interface, buf, len);
			continue;
		}

		/*Check TTL and update TTL.*/
		if (ip_hdr->ttl == 0) {
			continue;
		}
		ip_hdr->ttl--;
		if (ip_hdr->ttl <= 0) {
			//icmp timeout
			ip_hdr->protocol = 1;
			icmp_hdr->type = 11;
	 		icmp_hdr->code = 0;
	 		icmp_hdr->checksum = 0;
	 		icmp_hdr->checksum = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr) + sizeof(struct icmphdr));

			//swap MAC adress
			unsigned char aux[6];
			memcpy(aux, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
			memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, sizeof(eth_hdr->ether_dhost));
			memcpy(eth_hdr->ether_dhost, aux, sizeof(aux));

			//swap IP adress
			uint32_t aux2;
			aux2 = ip_hdr->daddr;
			ip_hdr->daddr = ip_hdr->saddr;
			ip_hdr->saddr = aux2;

			ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
			len =  sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
			send_to_link(interface, buf, len);
			continue;
		}
		// Recalculate checksum  
		ip_hdr->check = htons(0);
        sum = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
        ip_hdr->check = htons(sum);

		/* Update the ethernet addresses. */
		struct arp_entry* entry;
        entry = get_mac_entry(ip_hdr->daddr);

		for (int i = 0; i < 6; i++) {
        	eth_hdr->ether_dhost[i] = entry->mac[i];
        }
		get_interface_mac(route->interface, eth_hdr->ether_shost);

		// Send packet
		send_to_link(route->interface, buf, len);
	}
}

