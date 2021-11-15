/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#include "sorter_pcapng.hpp"

bool Sorter::process_block(Block *b, void *p) {
    uint32_t block_type;

    block_type = b->get_block_type();

    if (block_type == SECTION_HEADER) {
        section_headers.push_back(b->get_file_window());
    } else if (block_type == INTERFACE_HEADER) {
        idbs.push_back(b->get_file_window());
    } else if (block_type == ENHANCED_PKT_HEADER) {
        process_packet_block(b);
    }
    return true;
}

bool Sorter::process_packet_block(Block *b) {
    PacketSortInfo *psi;
    std::string comment;
    uint64_t ts;
    std::vector<std::string> tokens;
    EnhancedPacketBlock *epb;

    comment = get_pkt_comment(b);
    if (comment.compare("") == 0) {
        return false;
    }

    tokenize_string(comment, tokens, ',');
    psi = new PacketSortInfo;
    /* set SID */
    sscanf(tokens[COMMENT_SID_LOC].c_str(), "%zu", &psi->sid);
    /* format and set timestamp */
    epb = (EnhancedPacketBlock *) b->get_block_buf();
    ts = transform_ts(epb->ts_low, epb->ts_high);
    psi->ts = ts;
    /* set file window */
    psi->fw = b->get_file_window();

    pkt_blocks.push_back(*psi);

    return true;
}

int Sorter::sort_pcapng(char *infile, char *outfile) {
    uint32_t rv;
    Block *b;

    rv = open_pcapng(infile);
    if (rv != 0) {
        return 1;
    }

    while (1) {
        b = read_block();
        if (b == NULL) {
            break;
        }
        process_block(b, NULL);
        delete b;
    }

    std::sort(pkt_blocks.begin(), pkt_blocks.end());
    copy_output(infile, outfile);

    return 0;
}

int Sorter::copy_output(char *infile,  char *outfile) {
    FILE *in, *out;
    uint32_t i;

    printf("Copying file in sorted order\n");
    printf("  Number of sections:   %ld\n", section_headers.size());
    printf("  Number of idbs:       %ld\n", idbs.size());
    printf("  Number of pkt blocks: %ld\n", pkt_blocks.size());

    in = fopen(infile, "r");
    out = fopen(outfile, "wb");

    for (i = 0; i < section_headers.size(); i++) {
        copy_range(section_headers[i], in, out);
    }

    for (i = 0; i < idbs.size(); i++) {
        copy_range(idbs[i], in , out);
    }

    for (i = 0; i < pkt_blocks.size(); i++) {
        copy_range(pkt_blocks[i].fw, in, out);
    }

    return 0;
}

int Sorter::copy_range(FileWindow fw, FILE *in, FILE *out) {
    uint32_t rv;
    uint8_t buf[8192];
    uint64_t n_bytes;

    n_bytes = fw.f_end - fw.f_start;

    rv = fseek(in, fw.f_start, SEEK_SET);
    if (rv != 0) {
        return 1;
    }
    rv = fread((void *) &buf, 1, n_bytes, in);
    if (rv != n_bytes) {
        return 1;
    }
    rv = fwrite((void *) &buf, 1, n_bytes, out);
    if (rv!= n_bytes) {
        return 1;
    }

    return 0;
}
