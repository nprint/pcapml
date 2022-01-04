/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef INCLUDE_LABEL_LABELER_HPP_
#define INCLUDE_LABEL_LABELER_HPP_

#include <signal.h>

#include <vector>
#include <fstream>

static volatile int stop = 0;

#include "util.hpp"
#include "label.hpp"
#include "reader_pcap.hpp"
#include "writer_pcapng.hpp"

#define LABEL_FILE_LOC  0
#define FILTER_LOC 1
#define TS_START   2
#define TS_END     3

class PcapMLLabeler {
 public:
    void print_stats(FILE *stream);
    bool label_pcap(char *label_file, char *pcap, char *outfile,
                    bool infile_is_device, bool print_stats);
 private:
    std::vector<Label *> labels;
    uint64_t packets_matched = 0;
    uint64_t packets_received = 0;

    bool load_labels(char *label_file, pcap_t *handle = NULL);
};

#endif  // INCLUDE_LABEL_LABELER_HPP_
