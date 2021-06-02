/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef PCAP_READER
#define PCAP_READER

#if defined(__NetBSD__)
#include <net/if_ether.h>
#else
#include <net/ethernet.h>
#endif

#define LINUX_COOKED_HEADER_SIZE 16

#include <pcap.h>
#include "util.hpp"

class PcapReader {
  public:
    int open_file(char *infile);
    void close_file();
    pcap_packet_info *get_next_packet();

  private:
    pcap_t *f;
    pcap_t *get_pcap_handle();
};

#endif
