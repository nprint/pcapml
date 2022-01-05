/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef INCLUDE_LABEL_PCAP_LABELER_HPP_
#define INCLUDE_LABEL_PCAP_LABELER_HPP_

#include "labeler.hpp"

class PcapLabeler : public Labeler {
 public:
    void print_stats();
    uint32_t process_packet(PcapPacketInfo *pi);
    uint32_t label_pcap(char *label_file, char *pcap, char *outfile,
                        bool infile_is_device, bool print_stats);
};

#endif  // INCLUDE_LABEL_PCAP_LABELER_HPP_
