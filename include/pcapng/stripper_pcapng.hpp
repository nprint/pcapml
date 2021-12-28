/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef INCLUDE_PCAPNG_STRIPPER_PCAPNG_HPP_
#define INCLUDE_PCAPNG_STRIPPER_PCAPNG_HPP_

#define SENTINEL_LINKTYPE 999

#include "util.hpp"
#include "block_pcapng.hpp"
#include "reader_pcapng.hpp"
#include "writer_pcap.hpp"

class Stripper : public PcapNGReader {
  public:
    bool process_block(Block *b, void *p);
    int strip_pcapng(char *infile, char *outfile);
  private:
    PcapWriter w;
    uint16_t link_type=SENTINEL_LINKTYPE;
    
    int process_packet_block(Block *b);
    int process_interface_header(Block *b, char *outfile); 
};

#endif  // INCLUDE_PCAPNG_STRIPPER_PCAPNG_HPP_
