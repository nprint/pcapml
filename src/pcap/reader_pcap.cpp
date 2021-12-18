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

pcap_packet_info *PcapReader::get_next_packet() {
    pcap_pkthdr hdr;
    const u_int8_t *buf;
    pcap_packet_info *pi;

    fflush(stdout);
    buf = pcap_next(f, &hdr);
    if (buf == NULL) {
        return NULL;
    }
    pi = new pcap_packet_info;
    pi->hdr = hdr;
    pi->buf = buf;

    return pi;
}

uint16_t PcapReader::get_linktype() {
    return pcap_datalink(f);
}
