/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef INCLUDE_LABEL_LABELER_HPP_
#define INCLUDE_LABEL_LABELER_HPP_

#include <signal.h>

static volatile int stop = 0;

#include <vector>
#include <fstream>

#include "util.hpp"
#include "label.hpp"
#include "reader_pcap.hpp"
#include "writer_pcapng.hpp"

#define TRAFFIC_LOC  0
#define METADATA_LOC 1
#define HASHKEY_LOC  2

class Labeler {
 public:
    virtual void print_stats() = 0;
    virtual uint32_t process_packet(PcapPacketInfo *pi) = 0;
    
    int process_traffic(PcapReader r);
    int load_labels(std::string label_file, pcap_t *handle = NULL);
 protected:
    PcapNGWriter w;
    std::vector<Label *> labels;
    uint64_t packets_matched =  0;
    uint64_t packets_received = 0;
 private:
    Label *process_label_line(std::string line, pcap_t *handle = NULL);
    Label *process_traffic_filter(std::string traffic_filter,
                                  std::string hash_key,
                                  std::string metadata,
                                  pcap_t *handle = NULL);
};

#endif  // INCLUDE_LABEL_LABELER_HPP_
