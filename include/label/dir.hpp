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

#include "labeler.hpp"

class DirLabeler : public Labeler {
 public:
    void print_stats();
    uint32_t process_packet(PcapPacketInfo *pi);
    uint32_t label_dir(std::string dir, std::string label_file, 
                       std::string outfile, bool stats_out);
 private:
    uint64_t files_processed = 0;
    uint64_t files_skipped = 0;
    Label *active_file_label;
    int16_t cur_linktype = 999;
    std::map<std::string, Label *> file_labels;
    
    void build_file_label_map();
    uint32_t label_file(Label *l);
    uint32_t process_directory(std::string dir);
};

#endif  // INCLUDE_DIR_DIR_HPP_
