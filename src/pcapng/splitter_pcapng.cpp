/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#include "splitter_pcapng.hpp"

bool Splitter::process_block(Block *b, void *p) {
    uint32_t block_type;

    block_type = b->get_block_type();
    if (block_type == SECTION_HEADER) {
    } else if (block_type == INTERFACE_HEADER) {
        process_idb(b);
    } else if (block_type == ENHANCED_PKT_HEADER) {
        process_packet_block(b);
    } else {
        printf("Unrecognized block, this could be a problem\n");
    }

    return true;
}

bool Splitter::process_idb(Block *b) {
    InterfaceDescription *idb;

    idb = (InterfaceDescription *) b->get_block_buf();
    cur_linktype = idb->link_type;

    return true;
}

bool Splitter::process_packet_block(Block *b) {
    int rv;
    struct timeval time;
    pcap_pkthdr *pcap_header;
    EnhancedPacketBlock *epb;
    std::string comment, outfile;
    std::vector<std::string> tokens;

    comment = get_pkt_comment(b);
    if (comment.compare("") == 0) {
        return false;
    }
    tokenize_string(comment, tokens, ',');

    /* 
     * TODO at some point we will most likely want to make this a faster
     * comparison i.e. integer 
    */
    if (tokens[COMMENT_SID_LOC].compare(cur_sid) != 0) {
        samples_processed += 1;
        /* Update IO */
        w.close_file();
        cur_sid = tokens[COMMENT_SID_LOC];
        cur_metadata = tokens[COMMENT_LABEL_LOC];
        outfile = cur_sid + '_' + cur_metadata + ".pcap";
        fprintf(mdf, "%s,%s\n", outfile.c_str(), tokens[COMMENT_LABEL_LOC].c_str());
        outfile = outdir + outfile;
        rv = w.open_file((char *) outfile.c_str(), cur_linktype);
        if(rv != 0) return false;
    }

    /* update pcap packet header with pcapng block info */
    pcap_header = new pcap_pkthdr;
    epb = (EnhancedPacketBlock *) b->get_block_buf();
    pcap_header->len = epb->og_len;
    pcap_header->caplen = epb->cap_len;

    /* re-convert time from pcapng to pcap and update header */
    time.tv_sec = epb->ts_high;
    time.tv_usec = epb->ts_low;
    pcap_header->ts = time;

    w.write_packet(pcap_header, b->get_data_buf());

    delete pcap_header;

    return true;
}

int Splitter::split_pcapng(char *infile, char *outdir) {
    uint32_t rv;
    Block *b;

    /* Make output directory */
    printf("Making output directory\n");
    this->outdir = outdir;
    recursive_mkdir(outdir);

    mdf = fopen((char *) (this->outdir + "metadata.csv").c_str(), "w");
    fprintf(mdf, "File,Label\n");

    rv = open_pcapng(infile);
    if (rv != 0) {
        return 1;
    }

    printf("Splitting pcapng\n");
    while (1) {
        b = read_block();
        if (b == NULL) {
            break;
        }
        process_block(b, NULL);
        delete b;
    }


    fclose(mdf);
    close_pcapng();
    return 0;
}

void Splitter::recursive_mkdir(char *path) {
    char *sep;

    sep = strrchr(path, '/');
    if (sep != NULL) {
        *sep = 0;
        if (strcmp(path, "") != 0) recursive_mkdir(path);
        *sep = '/';
    }
    if (mkdir(path, 0777) && errno != EEXIST) {
        fprintf(stderr, "error while trying to create '%s', exiting\n", path);
        exit(5);
    }
}

FILE *Splitter::fopen_mkdir(char *path) {
    char *sep, *path0;

    sep = strrchr(path, '/');
    if (sep) {
        path0 = strdup(path);
        path0[sep - path] = 0;
        recursive_mkdir(path0);
        free(path0);
    }
    return fopen(path, "w");
}
