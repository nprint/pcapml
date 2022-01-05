/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#include "pcap_labeler.hpp"

uint32_t PcapLabeler::label_pcap(char *label_file, char *infile, char *outfile,
                                 bool infile_is_device, bool stats_out) {
    uint32_t rv;
    uint16_t linktype;
    std::vector<Label *>::iterator vit;
    PcapReader r;


    /* IO */
    if (infile_is_device) {
        r.open_live(infile);
    } else {
        r.open_file(infile);
    }

    linktype = r.get_linktype();
    w.open_file(outfile);
    w.write_interface_block(linktype, 0);

    /* Load labels now that we have the pcap_t */
    rv = load_labels(label_file, r.get_pcap_t());
    if(rv != 0) {
        fprintf(stderr, "Refusing to label pcap with zero labels loaded\n");
        return 1;
    }
    
    process_traffic(r);
    
    r.close_file();
    w.close_file();

    if (stats_out) {
        r.print_stats();
        print_stats();
    }

    return 0;
}

uint32_t PcapLabeler::process_packet(PcapPacketInfo *pi) {
    std::vector<Label *>::iterator vit;
    
    for (vit = labels.begin(); vit != labels.end(); vit++) {
        /* match here */
        if ((*vit)->match_packet(pi)) {
            w.write_epb_from_pcap_pkt(pi, (*vit)->get_comment_string());
            packets_matched++;
            return 0;
        }
    }
    
    return 1;
}

void PcapLabeler::print_stats() {
    printf("Labeler: packets received: %ld\n", packets_received);
    printf("Labeler: packets matched:  %ld\n", packets_matched);
}
