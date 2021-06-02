/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef UTIL
#define UTIL

#include <sys/stat.h>

#include <string>
#include <vector>
#include <sstream>
#include <tuple>

#include <pcap.h>

#include "block.hpp"

struct pcap_packet_info {
    struct pcap_pkthdr hdr;
    const uint8_t *buf;
};

void tokenize_string(std::string s, std::vector<std::string> &to_fill, char delimiter); 
uint64_t transform_ts(uint32_t low, uint32_t high);
std::tuple<size_t, std::string> get_info_from_pkt_comment(std::string comment);
bool check_file_exists(char *f);

#endif
