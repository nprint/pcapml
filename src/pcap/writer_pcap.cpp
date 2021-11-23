/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#include "writer_pcap.hpp"

int PcapWriter::open_file(char *outfile, uint16_t linktype) {
    pd = pcap_open_dead(linktype, 65535 /* snaplen */);
    if(pd == NULL) {
        return 1;
    }
    t = pcap_dump_open(pd, outfile);
    if(t == NULL) {
        pcap_perror(pd, "Error oepning pcap dump: ");
        return 1;
    }

    return 0;
}

int PcapWriter::write_packet(pcap_pkthdr *hdr, uint8_t *buf) {
    pcap_dump((u_char *) t, hdr, (u_char *) buf);

    return 0;
}

void PcapWriter::close_file() {
    if (pd != NULL) pcap_close(pd);
    if(t != NULL) pcap_dump_close(t);
}
