/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#include "stripper_pcapng.hpp"

bool Stripper::process_block(Block *b, void *p) {
    uint32_t rv, block_type;

    block_type = b->get_block_type();
    
    rv = 0;
    printf("processing block\n");
    if (block_type == INTERFACE_HEADER) {
        rv = process_interface_header(b, (char *) p);
    } else if(block_type == ENHANCED_PKT_HEADER) {
        rv = process_packet_block(b);
    }

    if(rv == 0) {
        return true;
    } else {
        return false;
    }
}

int Stripper::process_interface_header(Block *b, char *outfile) {
    uint32_t rv;
    InterfaceDescription *idb;
    
    idb = (InterfaceDescription *) b->get_block_buf(); 
    if(link_type == SENTINEL_LINKTYPE) {
        link_type = idb->link_type;
        rv = w.open_file(outfile, link_type);
        if (rv != 0) {
            fprintf(stderr, "Error opening pcap file, exiting\n");
        }
    }
    else {
        rv = 1;
        fprintf(stderr, "PCAP does not support multiple linktypes in a single capture\n");
    }

    return rv;
}

int Stripper::process_packet_block(Block *b) {
    pcap_pkthdr hdr;
    EnhancedPacketBlock *epb;

    epb = (EnhancedPacketBlock *) b->get_block_buf();
    
    hdr.caplen = epb->cap_len;
    hdr.len = epb->og_len;
    hdr.ts.tv_sec = epb->ts_high;
    hdr.ts.tv_usec = epb->ts_low;
    
    w.write_packet(&hdr, b->get_data_buf());

    return 0;
}

int Stripper::strip_pcapng(char *infile, char *outfile) {
    Block *b;
    uint32_t rv;
    
    writer_opened = false;
    rv = open_pcapng(infile);
    if (rv != 0) {
        return 1;
    }

    while (1) {
        b = read_block();
        if (b == NULL) {
            break;
        }
        process_block(b, (void *) outfile);
        
        delete b;
    }

    return 0;
}
