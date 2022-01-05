/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */


#include "labeler.hpp"

void sig_handler(int useless) {
    stop = 1;
}

int Labeler::load_labels(std::string label_file, pcap_t *handle) {
    Label *l;
    std::string line;
    
    /* register signal now as this is a one time process */
    signal(SIGINT, sig_handler);

    printf("Loading labels\n");
    std::ifstream instream(label_file);
    while (getline(instream, line)) {
        l = process_label_line(line, handle);
        if (l != NULL) {
            labels.push_back(l);
        }
    }
    
    printf("Number of labels successfully loaded: %ld\n", labels.size());
    if (labels.size() != 0) {
        return 0;
    } else {
        return 1;
    }
}

Label *Labeler::process_label_line(std::string line, pcap_t *handle) {
    Label *l;
    std::string metadata, hash_key;
    std::vector<std::string> line_tokens;

    l = NULL;
    tokenize_string(line, line_tokens, ',');

    /* Skip non-normal lines */
    if (line_tokens[0][0] == '#') return l;
    if (line_tokens.size() != 2 && line_tokens.size() != 3) {
        fprintf(stderr, "Incorrect number of tokens on line: %s\n", line.c_str());
        return l;
    }

    /* Grab metadata and hashkey if it exists */
    metadata = line_tokens[METADATA_LOC];

    hash_key = "";
    if (line_tokens.size() == 3) {
        hash_key = line_tokens[HASHKEY_LOC];
    }

    l = process_traffic_filter(line_tokens[TRAFFIC_LOC], hash_key, metadata, handle);

    return l;
}

Label *Labeler::process_traffic_filter(std::string traffic_filter,
                                       std::string hash_key,
                                       std::string metadata,
                                       pcap_t *handle) {
    Label *l;
    uint32_t i, rv;
    uint64_t ts_start, ts_end;
    std::string bpf_filter, file;
    std::vector<std::string> filter_tokens, block_tokens;

    /* Defaults */
    l = NULL;
    file = "";
    bpf_filter = "";
    ts_start = 0;
    ts_end = UINT64_MAX;

    /* Process each individual traffic filter */
    tokenize_string(traffic_filter, filter_tokens, '|');
    for (i = 0; i < filter_tokens.size(); i++) {
            tokenize_string(filter_tokens[i], block_tokens, ':');
            if (block_tokens[0] == "BPF") {
                bpf_filter = block_tokens[1];
            } else if (block_tokens[0] == "TS_START") {
                ts_start = std::stoull(block_tokens[1]);
            } else if (block_tokens[0] == "TS_END") {
                ts_end = std::stoull(block_tokens[1]);
            } else if (block_tokens[0] == "FILE") {
                file = block_tokens[1];
            } else {
                fprintf(stderr, "Error with traffic filter: %s\n", filter_tokens[i].c_str());
                return NULL;
            }
    }

    l = new Label();
    rv = l->set_info(metadata, bpf_filter, file, hash_key,
                     ts_start, ts_end, handle);
    if (rv != 0) {
        delete l;
        return NULL;
    }

    return l;
}

int Labeler::process_traffic(PcapReader r) {
    PcapPacketInfo *pi;

    while (1) {
        if (stop) {
            break;
        }
        pi = r.get_next_packet();
        if (pi == NULL) {
            break;
        } else if (pi->pcap_next_rv == PCAP_NEXT_EX_NOP) {
            continue;
        }
        packets_received++;
        process_packet(pi);
        delete pi;
    }
    return 0;
}
