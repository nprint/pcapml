/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#include "label.hpp"

std::string Label::get_comment_string() {
    return comment_str;
}

std::string Label::get_label() {
    return label;
}

std::string Label::get_sample_id() {
    return sample_id;
}

std::string Label::get_unhashed_sample_id() {
    return unhashed_sample_id;
}

bool Label::set_info(std::string label, std::string bpf_string_filter,
                     uint64_t ts_start, uint64_t ts_end) {
    bool rv;
    std::hash<std::string> str_hash;
    pcap_t *fake_handle;

    rv = true;
    /* set passed in values */
    this->label = label;
    this->ts_end = ts_end;
    this->ts_start = ts_start;
    this->bpf_string_filter = bpf_string_filter;

    /* make sure filter is valid */
    if (bpf_string_filter.compare("") != 0) {
        bpf_pcap_filter = new bpf_program;
        fake_handle = pcap_open_dead(1, 4096);
        if (pcap_compile(fake_handle, bpf_pcap_filter,
                         bpf_string_filter.c_str(), 1, 0) == -1) {
            printf("Invalid BPF filter: %s\n", bpf_string_filter.c_str());
            return false;
        }
    }


    /* build longid, hashid, and comment string for file */
    unhashed_sample_id = label + "_" + bpf_string_filter + "_" + std::to_string(ts_start) + "_" + std::to_string(ts_end);
    sample_id = std::to_string(str_hash(unhashed_sample_id));
    comment_str = sample_id + "," + label;

    /* mark that this label is ready */
    info_set = true;

    return rv;
}

bool Label::match_packet(pcap_packet_info *pi) {
    uint64_t pkt_ts;
    int bpf_match;
    bool ts_match;

    bpf_match = pcap_offline_filter(bpf_pcap_filter, &(pi->hdr), pi->buf);

    pkt_ts = pi->hdr.ts.tv_sec;
    ts_match = ((ts_start <= pkt_ts) && (pkt_ts <= ts_end)) ? true : false;

    return bpf_match && ts_match;
}

void Label::print() {
    printf("Label {\n");
    printf("  bpf:    %s\n",  bpf_string_filter.c_str());
    printf("  tstart: %llu\n", ts_start);
    printf("  tend:   %llu\n", ts_end);
    printf("}\n");
}
