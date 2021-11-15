/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef INCLUDE_PCAPNG_SORTER_PCAPNG_HPP_
#define INCLUDE_PCAPNG_SORTER_PCAPNG_HPP_

#include <vector>
#include <algorithm>

#include "util.hpp"
#include "block_pcapng.hpp"
#include "reader_pcapng.hpp"

struct PacketSortInfo {
    size_t sid;
    uint64_t ts;
    FileWindow fw;

    bool operator<(const PacketSortInfo &rhs) const {
        if (rhs.sid == sid) {
            return rhs.ts < ts;
        } else {
            return rhs.sid < sid;
        }
    }
};

class Sorter : public PcapNGReader {
 public:
    bool process_block(Block *b, void *p);
    int sort_pcapng(char *infile, char *outfile);
 private:
    bool process_packet_block(Block *b);
    int copy_output(char *infile, char *outfile);
    int copy_range(FileWindow fw, FILE *in, FILE *out);
    std::vector<FileWindow> section_headers;
    std::vector<FileWindow> idbs;
    std::vector<PacketSortInfo> pkt_blocks;
};

#endif  // INCLUDE_PCAPNG_SORTER_PCAPNG_HPP_
