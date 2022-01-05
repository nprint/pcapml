/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef INCLUDE_PCAP_READER_PCAP_HPP_
#define INCLUDE_PCAP_READER_PCAP_HPP_

#if defined(__NetBSD__)
#include <net/if_ether.h>
#else
#include <net/ethernet.h>
#endif

#define PCAP_NEXT_EX_EOF -2
#define PCAP_NEXT_EX_ERR -1
#define PCAP_NEXT_EX_NOP 0

#define LINUX_COOKED_HEADER_SIZE 16

#include <pcap.h>
#include "util.hpp"

class PcapReader {
 public:
    void close_file();
    void print_stats();
    pcap_t *get_pcap_t();
    uint16_t get_linktype();
    int open_live(char *devce);
    int open_file(char *infile);
    PcapPacketInfo *get_next_packet();
 private:
    pcap_t *f = NULL;
};

#endif  // INCLUDE_PCAP_READER_PCAP_HPP_
