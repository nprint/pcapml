/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef SAMPLE
#define SAMPLE

#include <vector>
#include <string>
#include <inttypes.h>

class Sample {
    public:
        Sample(size_t sid, std::string label);
        size_t get_sid();
        void print(FILE *stream, int verbose=0);
        void add_pkt(uint8_t *pkt_buf, uint64_t pkt_len, uint64_t ts);
        std::string get_label() {
            return label;
        }
        std::vector<uint8_t *> get_pkts() {
            return pkts;
        }
        std::vector<uint64_t>  get_pkt_ts() {
            return pkt_ts;
        }
        std::vector<uint32_t>  get_pkt_lens() {
            return pkt_lens;
        }
    private:
        size_t                 sid;
        std::string            label;
        std::vector<uint8_t *> pkts;
        std::vector<uint64_t>  pkt_ts;
        std::vector<uint32_t>  pkt_lens;
};

#endif
