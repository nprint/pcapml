/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef INCLUDE_LABEL_PCAP_LABELER_HPP_
#define INCLUDE_LABEL_PCAP_LABELER_HPP_

#include <signal.h>

static volatile int stop = 0;

#include "labeler.hpp"

class PcapLabeler : public Labeler {
 public:
    void print_stats(FILE *stream);
    bool label_pcap(char *label_file, char *pcap, char *outfile,
                    bool infile_is_device, bool print_stats);
 private:
    uint64_t packets_matched = 0;
    uint64_t packets_received = 0;
};

#endif  // INCLUDE_LABEL_PCAP_LABELER_HPP_
