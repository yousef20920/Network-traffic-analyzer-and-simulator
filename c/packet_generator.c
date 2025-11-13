#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void write_u16(uint8_t **ptr, uint16_t value) {
    uint16_t net = htons(value);
    memcpy(*ptr, &net, sizeof(net));
    *ptr += sizeof(net);
}

static void write_u32(uint8_t **ptr, uint32_t value) {
    uint32_t net = htonl(value);
    memcpy(*ptr, &net, sizeof(net));
    *ptr += sizeof(net);
}

static size_t build_bgp_update(uint8_t *buffer, const char *prefix, const char *next_hop) {
    uint8_t *cursor = buffer;
    memset(cursor, 0xff, 16);
    cursor += 16;
    uint8_t *length_ptr = cursor;
    cursor += 2;
    *cursor++ = 2;  // UPDATE

    write_u16(&cursor, 0);  // withdrawn routes length

    uint8_t *path_length_ptr = cursor;
    cursor += 2;

    // ORIGIN attribute
    *cursor++ = 0x40;
    *cursor++ = 1;
    *cursor++ = 1;
    *cursor++ = 0;

    // AS_PATH attribute
    *cursor++ = 0x40;
    *cursor++ = 2;
    *cursor++ = 6;
    *cursor++ = 2;  // AS_SEQUENCE
    *cursor++ = 2;  // two ASNs
    write_u16(&cursor, 65001);
    write_u16(&cursor, 65002);

    // NEXT_HOP attribute
    *cursor++ = 0x40;
    *cursor++ = 3;
    *cursor++ = 4;
    struct in_addr hop_addr;
    inet_pton(AF_INET, next_hop, &hop_addr);
    memcpy(cursor, &hop_addr, 4);
    cursor += 4;

    // MED attribute
    *cursor++ = 0x80;
    *cursor++ = 4;
    *cursor++ = 4;
    write_u32(&cursor, 25);

    uint16_t path_length = (uint16_t)(cursor - path_length_ptr - 2);
    uint8_t *tmp_cursor = path_length_ptr;
    write_u16(&tmp_cursor, path_length);

    char prefix_ip[32];
    int prefix_length = 0;
    snprintf(prefix_ip, sizeof(prefix_ip), "%s", prefix);
    char *slash = strchr(prefix_ip, '/');
    if (slash) {
        *slash = '\0';
        prefix_length = atoi(slash + 1);
    }
    struct in_addr prefix_addr;
    inet_pton(AF_INET, prefix_ip, &prefix_addr);
    int prefix_bytes = (prefix_length + 7) / 8;
    *cursor++ = (uint8_t)prefix_length;
    memcpy(cursor, &prefix_addr, prefix_bytes);
    cursor += prefix_bytes;

    uint16_t total_length = (uint16_t)(cursor - buffer);
    tmp_cursor = length_ptr;
    write_u16(&tmp_cursor, total_length);
    return cursor - buffer;
}

static size_t build_ospf_router_lsa(uint8_t *buffer, const char *router, const char *neighbor, uint16_t metric) {
    uint8_t *cursor = buffer;
    *cursor++ = 2;  // version
    *cursor++ = 4;  // type
    uint8_t *length_ptr = cursor;
    cursor += 2;

    struct in_addr router_addr;
    inet_pton(AF_INET, router, &router_addr);
    memcpy(cursor, &router_addr, 4);
    cursor += 4;

    struct in_addr area_addr;
    inet_pton(AF_INET, "0.0.0.0", &area_addr);
    memcpy(cursor, &area_addr, 4);
    cursor += 4;

    write_u16(&cursor, 0);  // checksum
    write_u16(&cursor, 0);  // AuType
    memset(cursor, 0, 8);
    cursor += 8;

    write_u32(&cursor, 1);  // number of LSAs

    write_u16(&cursor, 1);  // LS age
    *cursor++ = 0;          // options
    *cursor++ = 1;          // type (router LSA)

    struct in_addr neighbor_addr;
    inet_pton(AF_INET, neighbor, &neighbor_addr);
    memcpy(cursor, &neighbor_addr, 4);
    cursor += 4;

    memcpy(cursor, &router_addr, 4);
    cursor += 4;

    write_u32(&cursor, 0x80000001);  // sequence
    write_u16(&cursor, 0);           // checksum
    uint8_t *lsa_length_ptr = cursor;
    cursor += 2;

    uint8_t *lsa_body_start = cursor;
    *cursor++ = 0;  // flags
    *cursor++ = 0;
    write_u16(&cursor, 1);  // number of links

    memcpy(cursor, &neighbor_addr, 4);
    cursor += 4;

    struct in_addr mask_addr;
    inet_pton(AF_INET, "255.255.255.0", &mask_addr);
    memcpy(cursor, &mask_addr, 4);
    cursor += 4;

    *cursor++ = 1;  // link type
    *cursor++ = 0;  // TOS count
    write_u16(&cursor, metric);

    uint16_t lsa_length = (uint16_t)(cursor - lsa_body_start + 20);
    uint8_t *tmp_cursor = lsa_length_ptr;
    write_u16(&tmp_cursor, lsa_length);

    uint16_t packet_length = (uint16_t)(cursor - buffer);
    tmp_cursor = length_ptr;
    write_u16(&tmp_cursor, packet_length);
    return cursor - buffer;
}

static void hex_encode(const uint8_t *data, size_t length, char *output) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < length; ++i) {
        output[i * 2] = hex[data[i] >> 4];
        output[i * 2 + 1] = hex[data[i] & 0x0f];
    }
    output[length * 2] = '\0';
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <count> [seed]\n", argv[0]);
        return 1;
    }

    int count = atoi(argv[1]);
    if (count <= 0) {
        fprintf(stderr, "Count must be positive\n");
        return 1;
    }

    if (argc >= 3) {
        srand((unsigned int)strtoul(argv[2], NULL, 10));
    } else {
        srand((unsigned int)time(NULL));
    }

    const char *routers[] = {"198.51.100.1", "198.51.100.2", "198.51.100.3"};
    const char *peers[] = {"203.0.113.1", "203.0.113.2"};
    const char *prefixes[] = {"10.0.0.0/24", "10.1.0.0/24", "10.2.0.0/24"};
    const char *neighbors[] = {"198.51.100.2", "198.51.100.3", "198.51.100.4"};

    uint8_t buffer[512];
    char hex_payload[1024];

    for (int i = 0; i < count; ++i) {
        double timestamp = i * 0.25;
        double latency = 10.0 + (rand() % 120);
        double throughput = 80.0 + (rand() % 120);

        if (i % 2 == 0) {
            const char *router = routers[i % 3];
            const char *peer = peers[i % 2];
            const char *prefix = prefixes[i % 3];
            size_t payload_len = build_bgp_update(buffer, prefix, router);
            hex_encode(buffer, payload_len, hex_payload);
            printf(
                "{\"timestamp\":%.3f,\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"transport_protocol\":\"TCP\","
                "\"payload_protocol\":\"BGP\",\"length\":%zu,\"latency_ms\":%.2f,\"throughput_mbps\":%.2f,\"payload_hex\":\"%s\"}\n",
                timestamp,
                peer,
                router,
                payload_len,
                latency,
                throughput,
                hex_payload);
        } else {
            const char *router = routers[i % 3];
            const char *neighbor = neighbors[i % 3];
            uint16_t metric = (uint16_t)(5 + rand() % 20);
            size_t payload_len = build_ospf_router_lsa(buffer, router, neighbor, metric);
            hex_encode(buffer, payload_len, hex_payload);
            printf(
                "{\"timestamp\":%.3f,\"src_ip\":\"%s\",\"dst_ip\":\"224.0.0.5\",\"transport_protocol\":\"IP\","
                "\"payload_protocol\":\"OSPF\",\"length\":%zu,\"latency_ms\":%.2f,\"throughput_mbps\":%.2f,\"payload_hex\":\"%s\"}\n",
                timestamp,
                router,
                payload_len,
                latency,
                throughput,
                hex_payload);
        }
    }

    return 0;
}
