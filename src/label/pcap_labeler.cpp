/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#include "pcap_labeler.hpp"

void sig_handler(int useless) {
    stop = 1;
}

bool PcapLabeler::label_pcap(char *label_file, char *infile, char *outfile,
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

void PcapLabeler::print_stats(FILE *stream) {
    fprintf(stream, "Labeler: packets received: %ld\n", packets_received);
    fprintf(stream, "Labeler: packets matched:  %ld\n", packets_matched);
}
