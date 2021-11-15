/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef INCLUDE_PCAPNG_BLOCK_PCAPNG_HPP_
#define INCLUDE_PCAPNG_BLOCK_PCAPNG_HPP_

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include <vector>

#define SECTION_HEADER      0x0a0d0d0a
#define INTERFACE_HEADER    0x00000001
#define ENHANCED_PKT_HEADER 0x00000006

#define PKT_COMMENT_OPTION 1

#define OPTION_HEADER_LEN 4

#define COMMENT_SID_LOC 0
#define COMMENT_LABEL_LOC 1

#define DEBUG 0

#if DEBUG
# define DEBUG_PRINT(x) printf x
#else
# define DEBUG_PRINT(x) do {} while (0)
#endif

struct BlockHeader {
    uint32_t type;
    uint32_t length;
};

struct SectionInfoBlock {
    uint32_t magic;
    uint16_t major_version;
    uint16_t minor_version;
    uint64_t length;
};

struct InterfaceDescription {
    uint16_t link_type;
    uint16_t reserved;
    uint32_t snap_len;
};

struct EnhancedPacketBlock {
    uint32_t interface_id;
    uint32_t ts_high;
    uint32_t ts_low;
    uint32_t cap_len;
    uint32_t og_len;
};

struct OptionHeader {
    uint16_t code;
    uint16_t length;
};

struct Option {
    OptionHeader *header = NULL;
    void *buf = NULL;

    ~Option() {
        if (header != NULL) delete header;
        if (buf != NULL)    delete (uint8_t *) buf;
    }
};

struct FileWindow {
    uint64_t f_start = 0;
    uint64_t f_end = 0;
};

class Block {
 public:
    void print(FILE *stream);
    Block(BlockHeader *bh, uint64_t f_start);
    ~Block();
    void set_block_buf(void *buf);
    void *get_block_buf();
    void set_data_buf(uint8_t *buf);
    uint8_t *get_data_buf();
    void add_option(Option *o);
    uint32_t get_block_length();
    uint32_t get_block_type();
    FileWindow get_file_window();
    Option *get_option_by_code(uint16_t code);
 private:
    BlockHeader *bh = NULL;    // 8 Byte Header Object
    void *block_buf = NULL;    // Actual Block Header of specific type
    uint8_t *data_buf = NULL;  // Raw data buf, stripped of padding
    struct FileWindow fw;
    std::vector<Option *> options;
};


#endif  // INCLUDE_PCAPNG_BLOCK_PCAPNG_HPP_
