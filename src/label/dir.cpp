/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#include "dir.hpp"


uint32_t DirLabeler::process_packet(PcapPacketInfo *pi) {
    w.write_epb_from_pcap_pkt(pi, active_file_label->get_comment_string());
    packets_matched++;

    return 0;
}

uint32_t DirLabeler::label_dir(std::string dir, std::string label_file,
                               std::string outfile, bool stats_out) {
    w.open_file((char *) outfile.c_str());

    load_labels(label_file, NULL);
    build_file_label_map();
    process_directory(dir);
    
    if (stats_out) {
        print_stats();
    }
    w.close_file();

    return 0;
}

void DirLabeler::build_file_label_map() {
    /* Build a file mapping for fast lookups in dir case */
    std::string file;
    std::vector<Label *>::iterator vit;

    for(vit = labels.begin(); vit != labels.end(); vit++) {
        file = (*vit)->get_file();
        if(file != "") {
            file_labels.insert(make_pair(file, *vit));
        }
    }
}

uint32_t DirLabeler::process_directory(std::string dir) {
    DIR *d;
    int exists;
    std::string sid;
    struct stat buf;
    struct dirent *de;
    char full_name[MAX_FILE_LEN];
    std::map<std::string, Label *>::iterator mit;
    
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

        /* Check if file is in labels */
        mit = file_labels.find(full_name);
        if (mit != file_labels.end()) {
            files_processed++;
            active_file_label = mit->second;
            label_file(mit->second);
        } else {
            if (S_ISDIR(buf.st_mode) && strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0) {
                files_skipped++;
                printf("Skipping file: %s\n", full_name);
            }
        }

        if (S_ISDIR(buf.st_mode) && strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0) {
            process_directory(std::string(full_name));
        }
    }

    
    closedir(d);

    return 0;
}

uint32_t DirLabeler::label_file(Label *l) {
    PcapReader r;
    uint16_t linktype;

    r.open_file((char *) l->get_file().c_str());
    linktype = r.get_linktype();
    if (linktype != cur_linktype) {
        w.write_interface_block(linktype, 0); 
        cur_linktype = linktype;
    }

    process_traffic(r);
    r.close_file();

    return 0;
}

void DirLabeler::print_stats() {
    printf("Labeler: packets received:   %ld\n", packets_received);
    printf("Labeler: packets matched:    %ld\n", packets_matched);
    printf("Labeler: files processed:    %ld\n", files_processed);
    printf("Labeler: files skipped over: %ld\n", files_skipped);
}


