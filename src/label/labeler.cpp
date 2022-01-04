/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#include "labeler.hpp"

bool PcapMLLabeler::load_labels(char *label_file, pcap_t *handle) {
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
        rv = l->set_info(label, bpf_filter, ts_start, ts_end, handle);
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

void sig_handler(int useless) {
    stop = 1;
}

bool PcapMLLabeler::label_pcap(char *label_file, char *infile, char *outfile,
                               bool infile_is_device, bool stats_out) {
    uint16_t linktype;
    std::vector<Label *>::iterator vit;
    PcapNGWriter w;
    PcapReader r;
    pcap_packet_info *pi;

    if (infile_is_device) {
        r.open_live(infile);
    } else {
        r.open_file(infile);
    }

    /* IO */
    linktype = r.get_linktype();
    w.open_file(outfile);
    w.write_interface_block(linktype, 0);

    /* Load labels now that we have the pcap_t */
    load_labels(label_file, r.get_pcap_t());

    if (labels.size() == 0) {
        printf("Cowardly refusing to label pcap without any labels loaded\n");
        return false;
    }

    /* register signal now */
    signal(SIGINT, sig_handler);


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

        for (vit = labels.begin(); vit != labels.end(); vit++) {
            /* match here */
            if ((*vit)->match_packet(pi)) {
                w.write_epb_from_pcap_pkt(pi, (*vit)->get_comment_string());
                packets_matched++;
                break;
            }
        }
        delete pi;
        packets_received++;
    }
    if (stats_out) {
        print_stats(stdout);
        r.print_stats(stdout);
    }
    w.close_file();

    return true;
}

void PcapMLLabeler::print_stats(FILE *stream) {
    fprintf(stream, "Labeler: packets received: %ld\n", packets_received);
    fprintf(stream, "Labeler: packets matched:  %ld\n", packets_matched);
}
