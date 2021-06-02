/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#include "sampler.hpp"

bool Sampler::process_block(Block *b, void *p) {
    return true;
}

Sample *Sampler::get_next_sample() {
    size_t sid;
    uint64_t pkt_ts;
    uint32_t pkt_len;
    uint8_t *pkt_buf;
    std::string pkt_comment, label;
    Sample *return_sample;

    Block *b;
    EnhancedPacketBlock *epb;

    while (1) {
        b = read_block();
        if (b == NULL) {
            /* End of file, need to return last sample then on next call bail */
            if (last_sample == false) {
                return_sample = cur_sample;
                last_sample = true;
                break;
            } else {
                return_sample = NULL;
                break;
            }
        }

        /* Skip non packet blocks */
        if (b->get_block_type() != ENHANCED_PKT_HEADER) continue;

        /* Get sampleID and label */
        pkt_comment = get_pkt_comment(b);
        std::tie(sid, label) = get_info_from_pkt_comment(pkt_comment);

        /* First sample */
        if (cur_sample == NULL) {
            cur_sample = new Sample(sid, label);
        }
        /* Get Timestamp */
        epb = (EnhancedPacketBlock *) b->get_block_buf();
        pkt_ts = transform_ts(epb->ts_low, epb->ts_high);

        /* Get packet len */
        pkt_len = epb->cap_len;

        /* Copy packet buf */
        pkt_buf = new uint8_t[pkt_len];
        memcpy(pkt_buf, b->get_data_buf(), pkt_len);

        /* Same sample */
        if (cur_sample->get_sid() == sid) {
            cur_sample->add_pkt(pkt_buf, pkt_len, pkt_ts);
        } else {
            /* New sample */
            return_sample = cur_sample;
            cur_sample = new Sample(sid, label);
            cur_sample->add_pkt(pkt_buf, pkt_len, pkt_ts);
            break;
        }

        delete b;
    }

    return return_sample;
}
