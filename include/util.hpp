/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef INCLUDE_UTIL_HPP_
#define INCLUDE_UTIL_HPP_

#include <sys/stat.h>

#include <pcap.h>

#include <string>
#include <vector>
#include <sstream>
#include <tuple>

#include "block_pcapng.hpp"

struct pcap_packet_info {
    struct pcap_pkthdr hdr;
    const uint8_t *buf;
};

bool check_file_exists(char *f);
uint64_t transform_ts(uint32_t low, uint32_t high);
std::tuple<size_t, std::string> get_info_from_pkt_comment(std::string comment);
void tokenize_string(std::string s, std::vector<std::string> &to_fill, char delimiter);

#endif  // INCLUDE_UTIL_HPP_
