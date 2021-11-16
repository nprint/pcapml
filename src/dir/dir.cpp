/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#include "dir.hpp"

int DirLabeler::label_dir(std::string dir, std::string label_file,
                          std::string outfile) {
    w.open_file((char *) outfile.c_str());

    load_labels(label_file);
    process_directory(dir, outfile);

    w.close_file();

    return 0;
}

int DirLabeler::load_labels(std::string label_file) {
    uint32_t tsize;
    std::string line;
    std::vector<std::string> tokens;

    std::ifstream instream(label_file);
    while (getline(instream, line)) {
        tokenize_string(line, tokens, ',');
        tsize = tokens.size();
        if (tokens[0][0] == '#') continue;
        if (tsize != 2) {
            printf("wrong number of tokens on line: %s\n", line.c_str());
            continue;
        }
        labels.insert(make_pair(tokens[DIR_LABEL_FILE_LOC],
                      tokens[DIR_LABEL_LABEL_LOC]));
    }

    return 0;
}

int DirLabeler::process_directory(std::string dir, std::string outfile) {
    DIR *d;
    struct dirent *de;
    struct stat buf;
    int exists;
    char full_name[MAX_FILE_LEN];
    std::string sid;
    std::map<std::string, std::string>::iterator mit;

    d = opendir(dir.c_str());
    if (d == NULL) {
        fprintf(stderr, "Error opening directory: %s\n", dir.c_str());
        return 1;
    }

    for (de = readdir(d); de != NULL; de = readdir(d)) {
        if (dir[dir.size() - 1] == '/') {
            sprintf(full_name, "%s%s", dir.c_str(), de->d_name);
        } else {
            sprintf(full_name, "%s/%s", dir.c_str(), de->d_name);
        }
        exists = stat(full_name, &buf);
        if (exists < 0) {
            fprintf(stderr, "Error stating: %s\n", full_name);
            continue;
        }

        /* Check if file is in our labels, if so process it */
        mit = labels.find(full_name);
        if (mit != labels.end()) {
            sid = get_sid(mit->first, mit->second);
            label_file(full_name, sid, mit->second, outfile);
        }

        /* Recursively traverse directories */
        if (S_ISDIR(buf.st_mode) && strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0) {
            process_directory(std::string(full_name), outfile);
        }
    }
    
    closedir(d);

    return 0;
}

int DirLabeler::label_file(char *f, std::string sid, std::string label,
                           std::string outfile) {
    PcapReader r;
    uint16_t linktype;
    std::string comment;
    pcap_packet_info *pi;

    r.open_file(f);
    linktype = r.get_linktype();
    if (linktype != cur_linktype) {
        w.write_interface_block(linktype, 0); 
        cur_linktype = linktype;
    }

    comment = sid + "," + label;
    while (1) {
        pi = r.get_next_packet();
        if (pi == NULL) {
            break;
        }
        w.write_epb_from_pcap_pkt(pi, comment);
        delete pi;
    }
    r.close_file();
    samples_processed += 1;

    return 0;
}

std::string DirLabeler::get_sid(std::string infile, std::string label) {
    std::hash<std::string> str_hash;
    std::string unhashed_sid, sid;
    std::set<std::string>::iterator sit;

    unhashed_sid = infile + "_" + label;
    sid = std::to_string(str_hash(unhashed_sid));

    /* Add to global list */
    sit = sids.find(sid);
    if (sit != sids.end()) {
        // TODO loop if collision
        fprintf(stderr, "Hashed SID collision: file: %s, need to fix\n", infile.c_str());
        exit(1);
    } else {
        sids.insert(sid);
    }

    return sid;
}
