/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef INCLUDE_PCAPNG_READER_PCAPNG_HPP_
#define INCLUDE_PCAPNG_READER_PCAPNG_HPP_

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

#define MAGICA 0x1A2B3C4D
#define MAGICB 0x1A2BC34D

#define BIG_END 0
#define LITTLE_END 1

#define BUF_SIZE 8192*2
#define COMMENT_MAX 4096

#define TRAILER_LEN 4

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include <map>
#include <vector>
#include <string>
#include <algorithm>

#include "util.hpp"
#include "block_pcapng.hpp"

class PcapNGReader {
 public:
    virtual bool process_block(Block *b, void *p) = 0;
    int open_pcapng(char *pcapng);
    int close_pcapng();
    Block *read_block();
    std::string get_pkt_comment(Block *b);

 private:
    FILE *f;
    uint8_t sec_e;
    uint8_t sys_e;
    uint32_t block_bytes_read;
    uint32_t packets_processed;
    uint64_t total_bytes_read = 0;

    void print_state();
    uint8_t get_sys_endianness();
    uint8_t get_padding(uint32_t n);
    uint8_t get_sec_endianness(uint8_t *magic);

    bool seek_and_update(uint32_t len);
    bool read_and_update(void *buf, uint32_t len);

    void read_eph(Block *b);
    void read_idb(Block *b);
    void read_options(Block *b);
    void read_unknown(Block *b);
    void read_section_header(Block *b);
};

#endif  // INCLUDE_PCAPNG_READER_PCAPNG_HPP_
