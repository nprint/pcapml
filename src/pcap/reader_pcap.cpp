/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#include "reader_pcap.hpp"

int PcapReader::open_file(char *infile) {
    char errbuf[PCAP_ERRBUF_SIZE];

    f = pcap_open_offline_with_tstamp_precision(infile,
                                                PCAP_TSTAMP_PRECISION_MICRO,
                                                errbuf);

    return 0;
}

int PcapReader::open_live(char *device) {
    int32_t rv;
    pcap_t *handle;
    pcap_if_t *l;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* get device */
    if (device == NULL) {
        rv = pcap_findalldevs(&l, errbuf);
        if (rv == -1) {
            fprintf(stderr, "Failure looking up default device: %s\n", errbuf);
            exit(2);
        }
    }
    /* open device */
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        exit(2);
    }

    f = handle;

    return 0;
}

void PcapReader::close_file() {
    pcap_close(f);
}

pcap_t *PcapReader::get_pcap_t() {
    return f;
}

PcapPacketInfo *PcapReader::get_next_packet() {
    int32_t rv;
    pcap_pkthdr *hdr;
    const u_int8_t *buf;
    PcapPacketInfo *pi;

    rv = pcap_next_ex(f, &hdr, &buf);
    if (rv == PCAP_NEXT_EX_EOF) {
        return NULL;
    } else if (rv == PCAP_NEXT_EX_ERR) {
        pcap_perror(f, "Error while reading pcap: ");
        exit(99);
    }

    pi = new PcapPacketInfo;
    pi->hdr = hdr;
    pi->buf = buf;
    pi->pcap_next_rv = rv;

    return pi;
}

uint16_t PcapReader::get_linktype() {
    return pcap_datalink(f);
}

void PcapReader::print_stats() {
    int32_t rv;
    struct pcap_stat ps;
    
    rv = pcap_stats(f, &ps);
    /* return as PCAP stats do not work on non-live captures */
    if (rv != 0) return;

    printf("PCAP: packets received: %d\n", ps.ps_recv);
    printf("PCAP: packet buffer drops: %d\n", ps.ps_drop);
    printf("PCAP: packet interface drops: %d\n", ps.ps_ifdrop);
}
