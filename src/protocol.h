/*
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
// CONTRIBUTORS AND COPYRIGHT HOLDERS (c) 2013:
// Bob Mottram (bob@robotics.uk.to)
// Dag Robøle (BM-2DAS9BAs92wLKajVy9DS1LFcDiey5dxp5c)

#ifndef PROTO_H
#define PROTO_H

#include <stdint.h>

// Message encodings
enum {
    BM_ENCODING_IGNORE = 0,
    BM_ENCODING_TRIVIAL,
    BM_ENCODING_SIMPLE
};

// Message header
struct message_header_struct {
    uint32_t magic;
    char command[12];
    uint32_t length;
    uint32_t checksum;
};
typedef struct message_header_struct message_header;

// Network address
struct net_addr_struct {
    uint32_t time;
    uint32_t stream;
    uint64_t services;
    char ip_address[16];
    uint16_t port;
};
typedef struct net_addr_struct net_addr;

// Inventory vector element
struct inventory_element_struct {
    char hash[32];
};
typedef struct inventory_element_struct inventory_element;

// Version request
struct bm_version_header_struct {
    int32_t version;
    uint64_t services;
    int64_t timestamp;
    net_addr addr_recv;
    net_addr addr_from;
    uint64_t nonce;
};
typedef struct version_header_struct version_header;

#endif
