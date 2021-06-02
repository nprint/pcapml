/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#include "util.hpp"

void tokenize_string(std::string s, std::vector<std::string> &to_fill,
                     char delimiter) {
    std::string token;
    std::stringstream ss;

    to_fill.clear();
    ss.str(s);
    while (getline(ss, token, delimiter)) to_fill.push_back(token);
}

uint64_t transform_ts(uint32_t low, uint32_t high) {
    return (uint64_t) high << 32 | low;
}

std::tuple<size_t, std::string> get_info_from_pkt_comment(std::string comment) {
    size_t sid;
    std::string label;
    std::vector<std::string> tokens;

    tokenize_string(comment, tokens, ',');
    sscanf(tokens[COMMENT_SID_LOC].c_str(), "%zu", &sid);
    label = std::string(tokens[COMMENT_LABEL_LOC]);

    return std::make_tuple(sid, label);
}

bool check_file_exists(char *f) {
    struct stat buf;
    return (stat(f, &buf) == 0);
}
