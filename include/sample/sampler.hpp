/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef PCAPML_SAMPLER
#define PCAPML_SAMPLER

#include "block.hpp"
#include "pcapng_reader.hpp"
#include "sample.hpp"

class Sampler : public PcapNGReader {
    public:
        bool process_block(Block *b, void *p);
        Sample *get_next_sample();
    private:
        bool last_sample=false;
        Sample *cur_sample = NULL;
};


#endif
