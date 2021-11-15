/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef INCLUDE_SAMPLE_SAMPLER_HPP_
#define INCLUDE_SAMPLE_SAMPLER_HPP_

#include "sample.hpp"
#include "block_pcapng.hpp"
#include "reader_pcapng.hpp"

class Sampler : public PcapNGReader {
 public:
    bool process_block(Block *b, void *p);
    Sample *get_next_sample();
 private:
    bool last_sample = false;
    Sample *cur_sample = NULL;
};


#endif  // INCLUDE_SAMPLE_SAMPLER_HPP_
