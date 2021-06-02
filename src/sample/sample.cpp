/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#include "sample.hpp"

Sample::Sample(size_t sid, std::string label) {
    this->sid = sid;
    this->label = label;
}

void Sample::add_pkt(uint8_t *pkt_buf, uint64_t pkt_len, uint64_t ts) {
    pkts.push_back(pkt_buf);
    pkt_lens.push_back(pkt_len);
    pkt_ts.push_back(ts);
}

size_t Sample::get_sid() {
    return sid;
}

void Sample::print(FILE *stream, int verbose) {
    fprintf(stream, "Sample Information { \n");
    fprintf(stream, "  SID:   %zu\n", sid);
    fprintf(stream, "  Label: %s\n", label.c_str());
    fprintf(stream, "  n_pkts: %ld\n", pkts.size());
    fprintf(stream, "}\n");
}
