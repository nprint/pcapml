/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef INCLUDE_PCAPNG_WRITER_PCAPNG_HPP_
#define INCLUDE_PCAPNG_WRITER_PCAPNG_HPP_

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

#define MAGICA 0x1A2B3C4D
#define MAGICB 0x1A2BC34D

#define BIG_END 0
#define LITTLE_END 1

#define COMMENT_MAX 4096

#define TRAILER_LEN 4
#define BASE_BLOCK_LEN 12

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include <string>
#include <iostream>
#include <exception>

#include "util.hpp"
#include "block_pcapng.hpp"

class PcapNGWriter {
 public:
    int open_file(char *file_name, bool append = false);
    void close_file();
    int write_section_block();
    int write_interface_block(uint16_t link_type, uint32_t snap_len);
    int write_epb_from_pcap_pkt(pcap_packet_info *pi, std::string comment);
 private:
    FILE *pcapng;

    int write_option(uint16_t code, uint16_t len, uint8_t *buf);
    int write_pkt_comment(std::string comment);
    int write_block_header(uint32_t block_type, uint32_t len);
    int write_block_trailer(uint32_t len);
    int get_pad_len(int len);
    int pad_packet(int pkt_len);
};

#endif  // INCLUDE_PCAPNG_WRITER_PCAPNG_HPP_
