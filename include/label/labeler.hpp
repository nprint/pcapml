/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef LABELER
#define LABELER

#include <fstream>

#include "pcap_reader.hpp"
#include "pcapng_writer.hpp"
#include "util.hpp"
#include "label.hpp"

#define LABEL_FILE_LOC  0
#define FILTER_LOC 1
#define TS_START   2
#define TS_END     3


class PcapMLLabeler {
    public:
        bool load_labels(char *label_file);
        bool label_pcap(char *pcap, char *outfile);
    private:
        std::vector<Label *> labels;
};

#endif 
