/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef INCLUDE_PCAPNG_SPLITTER_PCAPNG_HPP_
#define INCLUDE_PCAPNG_SPLITTER_PCAPNG_HPP_

#include <string>

#include "util.hpp"
#include "writer_pcap.hpp"
#include "block_pcapng.hpp"
#include "reader_pcapng.hpp"

class Splitter : public PcapNGReader {
 public:
    bool process_block(Block *b, void *p);
    int split_pcapng(char *infile, char *outdir);
 private:
    uint16_t cur_linktype = 999;
    uint16_t samples_processed = 0;
    PcapWriter w;
    std::string outdir;
    std::string cur_sid = "";
    std::string cur_metadata = "";
    FILE *mdf = NULL;

    FILE *fopen_mkdir(char *path);
    FILE *open_metadata_file(char *path);
    void recursive_mkdir(char *path);
    bool process_idb(Block *b);
    bool process_packet_block(Block *b);
};

#endif  // INCLUDE_PCAPNG_SPLITTER_PCAPNG_HPP_
