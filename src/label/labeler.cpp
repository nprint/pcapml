/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#include "labeler.hpp"

int Labeler::load_labels(char *label_file, pcap_t *handle) {
    bool rv;
    Label *l;
    uint64_t tsize, ts_start, ts_end;
    std::string line, filter, metadata, bpf_filter, comment, file, hash_key;
    std::vector<std::string> line_tokens, traffic_tokens, filter_tokens;

    std::ifstream instream(label_file);
    while (getline(instream, line)) {
        printf("%s\n", line.c_str());
        tokenize_string(line, line_tokens, ',');
        tsize = line_tokens.size();
        if (line_tokens[0][0] == '#') continue;
        if (tsize != 2 && tsize != 3) {
            printf("Incorrect number of tokens on line: %s\n", line.c_str());
            continue;
        }

        /* Set defaults to pass */
        file = "";
        hash_key = "";
        bpf_filter = "";
        ts_start = 0;
        ts_end = UINT64_MAX;
        metadata = line_tokens[METADATA_LOC];
    
        /* parse out traffic filter */
        tokenize_string(line_tokens[TRAFFIC_LOC], traffic_tokens, '|');
        for(uint32_t i = 0; i < traffic_tokens.size(); i++) {
            tokenize_string(traffic_tokens[i], filter_tokens, ':');
            if(filter_tokens[0] == "BPF") {
                bpf_filter = filter_tokens[1];
            } else if(filter_tokens[0] == "TS_START") {
                ts_start = std::stoull(filter_tokens[1]);
            } else if(filter_tokens[0] == "TS_END") {
                ts_end = std::stoull(filter_tokens[1]);
            } else if(filter_tokens[0] == "FILE") {
                file = filter_tokens[1];
            }
        }
        
        /* Grab hash key if exists */
        if(tsize == 3) {
            hash_key = line_tokens[HASHKEY_LOC];
        }

        l = new Label();
        rv = l->set_info(metadata, bpf_filter, file, hash_key,
                         ts_start, ts_end, handle);
        if (!(rv)) {
            printf("failure creating label instance for line: %s\n",
                   line.c_str());
            delete l;
            continue;
        } else {
            labels.push_back(l);
        }
    }

    if (labels.size() > 0) {
        return true;
    } else {
        return false;
    }
}
