/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef INCLUDE_LABEL_LABEL_HPP_
#define INCLUDE_LABEL_LABEL_HPP_

#include <pcap.h>

#include <inttypes.h>
#include <string>

#include "util.hpp"

class Label {
 public:
    void print();
    uint32_t set_info(uint64_t sample_id, std::string metadata, 
                      std::string bpf_filter = "", std::string file = "", 
                      uint64_t ts_start = 0, uint64_t ts_end = UINT64_MAX,
                      pcap_t *handle = NULL);
    uint64_t get_sample_id();
    std::string get_file();
    std::string get_metadata();
    std::string get_comment_string();
    bool match_packet(PcapPacketInfo *pi);
 private:
    bool info_set = false;
    uint64_t ts_end;
    uint64_t ts_start;
    uint64_t sample_id;
    std::string file;
    std::string metadata;
    std::string comment_str;
    std::string bpf_string_filter;
    struct bpf_program *bpf_pcap_filter = NULL;
};

#endif  // INCLUDE_LABEL_LABEL_HPP_
