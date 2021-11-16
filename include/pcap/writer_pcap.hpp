/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef INCLUDE_PCAP_WRITER_PCAP_HPP_
#define INCLUDE_PCAP_WRITER_PCAP_HPP_

#if defined(__NetBSD__)
#include <net/if_ether.h>
#else
#include <net/ethernet.h>
#endif

#define LINUX_COOKED_HEADER_SIZE 16

#include <pcap.h>
#include "util.hpp"

class PcapWriter {
 public:
    void close_file();
    int open_file(char *outfile, uint16_t linktype);
    int write_packet(pcap_pkthdr *hdr, uint8_t *buf);
 private:
    pcap_t *pd = NULL;
    pcap_dumper_t *t = NULL;

    pcap_t *get_pcap_handle();
};

#endif  // INCLUDE_PCAP_WRITER_PCAP_HPP_
