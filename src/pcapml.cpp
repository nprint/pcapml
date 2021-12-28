/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#include <argp.h>

#include <string>

#include "dir.hpp"
#include "labeler.hpp"
#include "reader_pcapng.hpp"
#include "sorter_pcapng.hpp"
#include "splitter_pcapng.hpp"
#include "stripper_pcapng.hpp"

const char *argp_program_version = "pcapml 0.2.1";
const char *argp_program_bug_address = "https://github.com/nprint/pcapml";
static char doc[] = "pcapML standardzies the interactions with traffic analysis datasets";
static char args_doc[] = "";
static struct argp_option options[] = {
    {"pcap", 'P', "FILE", 0, "pcap to label"},
    {"outfile", 'W', "FILE", 0, "outfile (pcapng)"},
    {"file_dir", 'D', "FILE", 0, "directory of pcaps to label"},
    {"pcapml", 'M', "FILE", 0, "pcapml to split"},
    {"outdir", 'O', "FILE", 0, "output directory for split pcaps"},
    {"label_file", 'L', "FILE", 0, "labels for packets"},
    {"sort", 's', 0, 0, "sort pcapng by sampleid -> time"},
    {"strip", 'p', 0, 0, "strip pcapng of metadata and transform to pcap"},
    {"device", 'd', "STRING", 0, "device (if not default) to capture traffic from"},
    {0}};

struct arguments {
    bool sort = false;
    bool strip = false;
    char *pcap = NULL;
    char *outfile = NULL;
    char *labels = NULL;
    char *file_dir = NULL;
    char *pcapml = NULL;
    char *outdir = NULL;
    char *device = NULL;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = (struct arguments *) state->input;
    switch (key) {
        break;
    case 'P':
        arguments->pcap = arg;
        break;
    case 'W':
        arguments->outfile = arg;
        break;
    case 'D':
        arguments->file_dir = arg;
        break;
    case 'L':
        arguments->labels = arg;
        break;
    case 'O':
        arguments->outdir = arg;
        break;
    case 'M':
        arguments->pcapml = arg;
        break;
    case 's':
        arguments->sort = true;
        break;
    case 'p':
        arguments->strip = true;
        break;
    case 'd':
        arguments->device = arg;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {options, parse_opt, args_doc, doc};

int main(int argc, char **argv) {
    uint32_t rv;
    struct arguments arguments;
    /* parse args */
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    DirLabeler d;
    Sorter sorter;
    Splitter splitter;
    Stripper stripper;
    PcapMLLabeler labeler;

    if (arguments.outfile == NULL && arguments.outdir == NULL) {
        fprintf(stderr, "No output configuration, exiting\n");
        exit(1);
    }
    
    if(arguments.pcapml != NULL) {
        if (arguments.strip == true) {
            printf("stripping pcapNG file and turning into pcap\n");
            rv = stripper.strip_pcapng(arguments.pcapml, arguments.outfile);
            if (rv != 0) {
                fprintf(stderr, "Error stripping pcapNG file\n");
                exit(10);
            }
        }
        if (arguments.sort == true) {
            printf("Sorting pcapml\n");
            rv = sorter.sort_pcapng(arguments.pcapml, arguments.outfile);
            if (rv != 0) {
                printf("Error sorting pcapML file\n");
                exit(9);
            }
        }
        if (arguments.outdir != NULL) {
            rv = splitter.split_pcapng(arguments.pcapml, arguments.outdir);
            if (rv != 0) {
                printf("Error while splitting pcapml file\n");
                exit(3);
            }
        }
    }

    if(arguments.labels != NULL) {
        if(arguments.file_dir != NULL) {
            printf("Labeling directory: %s\n", arguments.file_dir);
            d.label_dir(std::string(arguments.file_dir),
                        std::string(arguments.labels),
                        std::string(arguments.outfile));
        } else if (arguments.pcap != NULL) {
            printf("Labeling PCAP: %s\n", arguments.pcap);
            rv = labeler.label_pcap(arguments.labels, arguments.pcap,
                                    arguments.outfile, false);
            if (rv == false) {
                printf("Failure while parsing pcap\n");
                exit(4);
            }
        } else {
            printf("processing live traffic\n");
            rv = labeler.label_pcap(arguments.labels, arguments.device,
                                    arguments.outfile, true);
            if (rv == false) {
                printf("Error parsing live traffic, exiting\n");
                exit(5);
            }
        }
    }
    
    exit(0);
}
