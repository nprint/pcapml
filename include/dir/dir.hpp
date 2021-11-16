/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef INCLUDE_DIR_DIR_HPP_
#define INCLUDE_DIR_DIR_HPP_

#define DIR_LABEL_FILE_LOC 0
#define DIR_LABEL_LABEL_LOC 1

#define MAX_FILE_LEN 2056

#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>

#include <map>
#include <set>
#include <vector>
#include <string>
#include <fstream>

#include "util.hpp"
#include "reader_pcap.hpp"
#include "writer_pcapng.hpp"

class DirLabeler {
 public:
    int label_dir(std::string dir, std::string label_file,
                      std::string outfile);
 private:
    uint32_t samples_processed = 0;
    int16_t cur_linktype = 999;
    PcapNGWriter w;
    std::string get_sid(std::string infile, std::string label);
    int label_file(char *f, std::string sid, std::string label,
                   std::string outfile);
    int process_directory(std::string dir, std::string outfile);
    int load_labels(std::string label_file);
    std::map<std::string, std::string> labels;
    std::set<std::string> sids;
};

#endif  // INCLUDE_DIR_DIR_HPP_
