/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#include "labeler.hpp"

bool PcapMLLabeler::load_labels(char *label_file) {
    bool rv;
    Label *l;
    std::vector<std::string> tokens;
    uint64_t tsize, ts_start, ts_end;
    std::string line, filter, label, bpf_filter, comment;

    std::ifstream instream(label_file);
    while (getline(instream, line)) {
        tokenize_string(line, tokens, ',');
        tsize = tokens.size();
        if (tokens[0][0] == '#') continue;
        if (tsize == 0 || tsize == 1) {
            printf("not enough tokens on line: %s\n", line.c_str());
            continue;
        }

        /* Set defaults to pass */
        bpf_filter = "";
        ts_start = 0;
        ts_end = UINT64_MAX;
        label = tokens[LABEL_FILE_LOC];
        if (tsize >= 2) bpf_filter = tokens[FILTER_LOC];
        if (tsize >= 3) ts_start = std::stoull(tokens[TS_START]);
        if (tsize >= 4) ts_end = std::stoull(tokens[TS_END]);

        l = new Label();
        rv = l->set_info(label, bpf_filter, ts_start, ts_end);
        if(!(rv)) {
            printf("failure creating label instance for line: %s\n", line.c_str());
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

bool PcapMLLabeler::label_pcap(char *infile, char *outfile) {
    uint16_t linktype;
    uint64_t matched, total;
    std::vector<Label *>::iterator vit;
    PcapNGWriter w;
    PcapReader r;
    pcap_packet_info *pi;

    if (labels.size() == 0) {
        printf("Cowardly refusing to label pcap without any labels loaded\n");
        return false;
    }
    /* IO */
    r.open_file(infile);
    linktype = r.get_linktype();
    w.open_file(outfile);
    w.write_interface_block(linktype, 0); 

    total = 0;
    matched = 0;
    while (1) {
        pi = r.get_next_packet();
        if (pi == NULL) {
            break;
        }
        for (vit = labels.begin(); vit != labels.end(); vit++) {
            /* match here */
            if ((*vit)->match_packet(pi)) {
                w.write_epb_from_pcap_pkt(pi, (*vit)->get_comment_string());
                matched++;
                break;
            }
        }
        total++;
    }
    w.close_file();

    return true;
}
