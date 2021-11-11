/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef INCLUDE_PCAPNG_PCAPNG_SPLITTER_HPP_
#define INCLUDE_PCAPNG_PCAPNG_SPLITTER_HPP_

#include "util.hpp"
#include "block.hpp"
#include "pcapng_reader.hpp"
#include "pcap_writer.hpp"

class Splitter : public PcapNGReader {
 public:
    bool process_block(Block *b, void *p);
    int split_pcapng(char *infile, char *outdir);
 private:
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
    bool update_io(std::vector<std::string> &tokens);
};

#endif  // INCLUDE_PCAPNG_PCAPNG_SPLITTER_HPP_
