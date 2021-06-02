/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef LABEL
#define LABEL

#include <string>
#include <inttypes.h>

#include <pcap.h>

#include "util.hpp"

class Label {
    public:
        void print();
        bool set_info(std::string label, std::string bpf_filter="",
                      uint64_t ts_start=0, uint64_t ts_end=UINT64_MAX);
        std::string get_label();
        std::string get_sample_id();
        std::string get_comment_string();
        std::string get_unhashed_sample_id();
        bool match_packet(pcap_packet_info *pi);
    private:
        bool info_set=false;
        std::string bpf_string_filter;
        struct bpf_program *bpf_pcap_filter=NULL;
        uint64_t ts_start, ts_end;
        std::string sample_id, unhashed_sample_id, label, comment_str;
};

#endif
