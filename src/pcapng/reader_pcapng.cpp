/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#include "reader_pcapng.hpp"

int PcapNGReader::open_pcapng(char *infile) {
    packets_processed = 0;
    sys_e = get_sys_endianness();

    f = fopen(infile , "r");
    if (f == NULL) {
        fprintf(stderr, "Error opening file: %s\n", infile);
        return 1;
    }

    return 0;
}

std::string PcapNGReader::get_pkt_comment(Block *b) {
    Option *o;
    std::string s;

    s = "";
    o = b->get_option_by_code(PKT_COMMENT_OPTION);
    if (o == NULL) {
        return s;
    }

    s = std::string((char *) o->buf, o->header->length);

    return s;
}

int PcapNGReader::close_pcapng() {
    uint32_t rv;

    rv = fclose(f);

    if (rv != 0) {
        fprintf(stderr, "Error closing file handle\n");
    }

    return rv;
}

Block *PcapNGReader::read_block() {
    uint64_t cur_block_start;
    BlockHeader *bh;
    Block *b;

    /* Keep track of file location and block bytes we've read */
    block_bytes_read = 0;
    cur_block_start = ftell(f);
    
    fflush(stdout);

    /* Read header of block as its always the same and tells us what to do */
    bh = new BlockHeader;
    read_and_update((void *) bh, sizeof(BlockHeader));
    
    if (feof(f)) {
        return NULL;
    }

    /* Check if block is jank */
    if (bh->length == 0) {
        delete bh;
        return NULL;
    }

    b = new Block(bh, cur_block_start);

    DEBUG_PRINT(("!Reading New Block!\n"));
    DEBUG_PRINT(("  Block start: %ld, block_end: %ld\n", cur_block_start, cur_block_start + bh->length));
    DEBUG_PRINT(("  Block Size: %u, Block type: %u\n", bh->length, bh->type));
    switch (bh->type) {
        case SECTION_HEADER:
            read_section_header(b);
            break;
        case INTERFACE_HEADER:
            read_idb(b);
            break;
        case ENHANCED_PKT_HEADER:
            read_eph(b);
            packets_processed++;
            break;
        default:
            read_unknown(b);
            break;
    }

    return b;
}

void PcapNGReader::read_unknown(Block *b) {
    fprintf(stderr, "Unknown block type, printing block and exiting\n");
    b->print(stderr);
    print_state();
    exit(3);
}

void PcapNGReader::read_eph(Block *b) {
    uint32_t pkt_bytes_read, chunk_size_to_read, padding, eob_read;
    std::vector<std::string> tokens;
    EnhancedPacketBlock *epb;
    uint8_t *buf;

    epb = new EnhancedPacketBlock;

    DEBUG_PRINT(("    reading eph\n"));
    /* Read EPB Header */
    read_and_update((void *) epb, sizeof(EnhancedPacketBlock));
    DEBUG_PRINT(("      EPH Header read: block_bytes_read: %d\n", block_bytes_read));
    b->set_block_buf((void *) epb);

    pkt_bytes_read = 0;
    /* Consume Packet data */
    /* TODO handle jumbos in a while loop */
    chunk_size_to_read = MIN(epb->cap_len, BUF_SIZE);
    DEBUG_PRINT(("         Consuming: %d bytes of %d left\n", chunk_size_to_read, epb->cap_len - pkt_bytes_read));
    buf = new uint8_t[chunk_size_to_read];
    b->set_data_buf(buf);

    read_and_update((void *) buf, chunk_size_to_read);
    pkt_bytes_read += chunk_size_to_read;

    /* Skip rest of packet for now, need to loop here to save big ones */
    if (chunk_size_to_read < epb->cap_len) {
        seek_and_update(epb->cap_len - chunk_size_to_read);
    }

    /* Data gets padded to 32 bit boundary, need to skip it */
    padding = get_padding(epb->cap_len);
    if (padding != 0) {
       seek_and_update(padding);
    }

    /* Packet options, where we store the comments */
    if (b->get_block_length() - block_bytes_read > TRAILER_LEN) {
       read_options(b);
    }

    /* End of block length read */
    eob_read = b->get_block_length() - block_bytes_read;
    seek_and_update(eob_read);
}

void PcapNGReader::read_options(Block *b) {
    Option *o;
    uint8_t *buf;
    OptionHeader *oh;

    DEBUG_PRINT(("      Processing options in epb\n"));
    while (1) {
        oh = new OptionHeader;
        read_and_update((void *) oh, sizeof(OptionHeader));
        DEBUG_PRINT(("        Option code: %d, option length: %d\n", oh->code, oh->length));
        if (oh->code == 0 || oh->length == 0) {
            delete oh;
            break;
        } else {
            o = new Option;
            o->header = oh;
            buf = new uint8_t[oh->length + 1];
            read_and_update((void *) buf, oh->length + 1);
            o->buf = buf;
        }
        b->add_option(o);
    }
}

void PcapNGReader::read_idb(Block *b) {
    uint32_t eob_read;
    InterfaceDescription *id;
    DEBUG_PRINT(("    Interface description block\n"));

    id = new InterfaceDescription;

    read_and_update((void *) id, sizeof(InterfaceDescription));

    /* read the rest */
    /* TODO formally read these into a buffer if we care */
    eob_read = b->get_block_length() - block_bytes_read;
    seek_and_update(eob_read);

    b->set_block_buf((void *) id);
}

void PcapNGReader::read_section_header(Block *b) {
    uint32_t eob_read;

    SectionInfoBlock *sib;
    sib = new SectionInfoBlock;

    DEBUG_PRINT(("    Section Header block\n"));

    /* Read the section header */
    read_and_update((void *) sib, sizeof(SectionInfoBlock));
    sec_e = get_sec_endianness((uint8_t *) &sib->magic);
    DEBUG_PRINT(("      section endianness: %d\n", sec_e));

    /* read the rest that we don't care about */
    /* TODO at some point, we may want to parse these options formally */
    eob_read = b->get_block_length() - block_bytes_read;
    seek_and_update(eob_read);

    b->set_block_buf((void *) sib);
}

uint8_t PcapNGReader::get_sys_endianness() {
    if (htonl(42) == 42) {
        return BIG_END;
    } else {
        return LITTLE_END;
    }
}

uint8_t PcapNGReader::get_sec_endianness(uint8_t *magic) {
    if (magic[0] == 0x1a && magic[1] == 0x2b && magic[2] == 0x3c && magic[3] == 0x4d) {
        return BIG_END;
    } else if (magic[0] == 0x4d && magic[1] == 0x3c && magic[2] == 0x2b && magic[3] == 0x1a) {
        return LITTLE_END;
    } else {
        return -1;
    }
}

uint8_t PcapNGReader::get_padding(uint32_t n) {
    switch (n % 4) {
        case 0:
            return 0;
        case 1:
            return 3;
        case 2:
            return 2;
        case 3:
            return 1;
        default:
            return -1;
    }
}

void PcapNGReader::print_state() {
    DEBUG_PRINT(("PcapNGReader State:\n"));
    DEBUG_PRINT(("  number of Packets Processed: %d\n", packets_processed));
}

bool PcapNGReader::seek_and_update(uint32_t len) {
    uint32_t rv;

    rv = fseek(f, len, SEEK_CUR);
    if (rv != 0) {
        return false;
    }

    block_bytes_read += len;
    total_bytes_read += len;

    return true;
}

bool PcapNGReader::read_and_update(void *buf, uint32_t len) {
    uint32_t rv;

    rv = fread(buf, 1, len, f);
    if (rv != len) {
        return false;
    }

    block_bytes_read += rv;
    total_bytes_read += rv;

    return true;
}

uint32_t convert_end(uint32_t in) {
    return 0;
}
