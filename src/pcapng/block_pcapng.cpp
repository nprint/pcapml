/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#include "block_pcapng.hpp"

Block::Block(BlockHeader *bh, uint64_t f_start) {
    this->bh = bh;
    /* Calculate and set the file window for this block */
    fw.f_start = f_start;
    fw.f_end = f_start + bh->length;
}

void Block::print(FILE *stream) {
    fprintf(stream, "Block {\n");
    fprintf(stream, "  Header {\n");
    if (bh == NULL) {
        fprintf(stream, "    type:   NULL\n");
        fprintf(stream, "    length: NULL\n");
    } else {
        fprintf(stream, "    type:   %u\n", bh->type);
        fprintf(stream, "    length:   %u\n", bh->length);
    }
    fprintf(stream, "  }\n");
    fprintf(stream, "  FileWindow {\n");
    fprintf(stream, "    start: %llu\n", fw.f_start);
    fprintf(stream, "    end: %llu\n", fw.f_end);
    fprintf(stream, "  }\n");
    fprintf(stream, "}\n");
}

Block::~Block() {
    uint64_t i;

    /* Actual block buf that is dependent on type of block */
    if (block_buf != NULL) {
        switch (get_block_type()) {
            case SECTION_HEADER:
                delete (SectionInfoBlock *) block_buf;
                break;
            case INTERFACE_HEADER:
                delete (InterfaceDescription *) block_buf;
                break;
            case ENHANCED_PKT_HEADER:
                delete (EnhancedPacketBlock *) block_buf;
                break;
            default:
                break;
        }
    }
    /* 8 Byte block header after deleting data dependent on it */
    if (bh != NULL) {
        delete bh;
    }

    /* data buf in memory */
    if (data_buf != NULL) {
        delete data_buf;
    }

    for (i = 0; i < options.size(); i++) {
        delete options[i];
    }
}

/* TODO This could cause problems if multiple comments, 
 * could move to a map with a list / return a vector */
Option *Block::get_option_by_code(uint16_t code) {
    uint32_t i;
    for (i = 0; i < options.size(); i++) {
        if (options[i]->header->code == code) return options[i];
    }

    return NULL;
}

void Block::set_block_buf(void *buf) {
    block_buf = buf;
}

void *Block::get_block_buf() {
    return block_buf;
}

void Block::set_data_buf(uint8_t *buf) {
    data_buf = buf;
}

uint8_t *Block::get_data_buf() {
    return data_buf;
}

void Block::add_option(Option *o) {
    options.push_back(o);
}

uint32_t Block::get_block_length() {
    return bh->length;
}

uint32_t Block::get_block_type() {
    return bh->type;
}

FileWindow Block::get_file_window() {
    return fw;
}

