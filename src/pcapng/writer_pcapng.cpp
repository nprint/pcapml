/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#include "writer_pcapng.hpp"

int PcapNGWriter::open_file(char *f, bool append) {
    if (!(check_file_exists(f))) {
        if (append) {
            return 1;
        }
        pcapng = fopen(f, "wb");
    } else {
        pcapng = fopen(f, "wb");
    }

    if (pcapng == NULL) {
        return 1;
    }

    DEBUG_PRINT(("pcapng opened for writing\n"));

    write_section_block();

    return 0;
}

void PcapNGWriter::close_file() {
    fclose(pcapng);
}

int PcapNGWriter::write_section_block() {
    uint32_t block_len;
    SectionInfoBlock sib;

    block_len = BASE_BLOCK_LEN + sizeof(SectionInfoBlock);

    write_block_header(SECTION_HEADER, block_len);

    sib.magic = MAGICA;
    sib.major_version = 1;
    sib.minor_version = 0;
    sib.length = 0xFFFFFFFFFFFFFFFF;
    DEBUG_PRINT(("WRITE: SIB: %ld bytes\n", sizeof(SectionInfoBlock)));
    fwrite((void *) &sib, sizeof(SectionInfoBlock), 1, pcapng);
    write_block_trailer(block_len);

    return 0;
}

int PcapNGWriter::write_block_header(uint32_t block_type, uint32_t len) {
    uint32_t rv;
    BlockHeader bh;

    DEBUG_PRINT(("WRITE: BH : %ld bytes, type: %d, len: %d\n", sizeof(BlockHeader), block_type, len));

    bh.type = block_type;
    bh.length = len;

    rv = fwrite((void *) &bh, sizeof(BlockHeader), 1, pcapng);

    return rv;
}

int PcapNGWriter::write_block_trailer(uint32_t len) {
    uint32_t trailer, rv;

    DEBUG_PRINT(("WRITE: BT: 4 bytes\n"));
    trailer = len;
    rv = fwrite((void *) &trailer, 1, sizeof(uint32_t), pcapng);

    return rv;
}

int PcapNGWriter::write_interface_block(uint16_t link_type, uint32_t snap_len) {
    uint32_t block_len, rv;
    InterfaceDescription idb;

    block_len = BASE_BLOCK_LEN + sizeof(InterfaceDescription);

    write_block_header(INTERFACE_HEADER, block_len);

    /* Default to ethernet for now, we should read this then react */
    idb.link_type = link_type;
    idb.reserved = 0;
    idb.snap_len = snap_len;

    DEBUG_PRINT(("WRITE: IDB: %ld bytes\n", sizeof(InterfaceDescription)));
    rv = fwrite((void *) &idb, 1, sizeof(InterfaceDescription), pcapng);

    write_block_trailer(block_len);

    return rv;
}

int PcapNGWriter::write_epb_from_pcap_pkt(pcap_packet_info *p, std::string comment) {
    uint32_t block_len, rv;
    EnhancedPacketBlock epb;

    epb.interface_id = 0;
    epb.ts_high = p->hdr.ts.tv_sec;
    epb.ts_low = p->hdr.ts.tv_usec;
    epb.cap_len = p->hdr.caplen;
    epb.og_len = p->hdr.len;

    /* Base header + EPB header + packet + packet padding + comment 
     * + comment padding + option headers * 2 (end of options & comment)
    */
    block_len = BASE_BLOCK_LEN + sizeof(EnhancedPacketBlock) + epb.cap_len \
        + comment.size() + (OPTION_HEADER_LEN * 2) + get_pad_len(epb.cap_len) +
        get_pad_len(comment.size());

    write_block_header(ENHANCED_PKT_HEADER, block_len);
    DEBUG_PRINT(("WRITE: EPB: %ld bytes\n", sizeof(EnhancedPacketBlock)));
    rv = fwrite((void *) &epb, sizeof(EnhancedPacketBlock), 1, pcapng);
    DEBUG_PRINT(("WRITE: BUF: %d bytes\n", epb.cap_len));
    rv = fwrite((void *) p->buf, epb.cap_len, 1, pcapng);
    pad_packet(epb.cap_len);
    write_option(1, comment.size(), (uint8_t *) comment.c_str());
    write_option(0, 0, NULL);
    write_block_trailer(block_len);

    return rv;
}

int PcapNGWriter::write_option(uint16_t code, uint16_t len, uint8_t *buf) {
    DEBUG_PRINT(("WRITE: option: code: %d, len: %d\n", code, len));
    fwrite((void *) &code, sizeof(uint16_t), 1, pcapng);
    fwrite((void *) &len, sizeof(uint16_t), 1, pcapng);
    if (code != 0 && len != 0) {
        DEBUG_PRINT(("WRITE: OBUF: %d bytes\n", len));
        fwrite((void *) buf, len, 1, pcapng);
        pad_packet(len);
    }

    return 0;
}

int PcapNGWriter::pad_packet(int pkt_len) {
    int n;
    uint8_t byte[3];
    byte[0] = 0x00;
    byte[1] = 0x00;
    byte[2] = 0x00;

    n = get_pad_len(pkt_len);
    if (n < 0) {
        return -1;
    }

    DEBUG_PRINT(("WRITE: PAD: %d bytes\n", n));
    fwrite((void *) &byte, 1, n, pcapng);

    return 0;
}

int PcapNGWriter::get_pad_len(int len) {
    switch (len % 4) {
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
