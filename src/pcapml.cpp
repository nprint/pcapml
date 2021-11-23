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
    {0}};

struct arguments {
    bool sort = false;
    char *pcap = NULL;
    char *outfile = NULL;
    char *labels = NULL;
    char *file_dir = NULL;
    char *pcapml = NULL;
    char *outdir = NULL;
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
    PcapMLLabeler labeler;

    if (arguments.outfile == NULL && arguments.outdir == NULL) {
        printf("No output configuration, exiting\n");
        exit(1);
    }

    if (arguments.file_dir != NULL && arguments.labels != NULL) {
        printf("Labeling directory: %s\n", arguments.file_dir);
        d.label_dir(std::string(arguments.file_dir),
                    std::string(arguments.labels),
                    std::string(arguments.outfile));
    }

    if (arguments.pcap != NULL && arguments.labels != NULL) {
        printf("Loading labels...\n");
        rv = labeler.load_labels(arguments.labels);
        if (rv == false) {
            printf("Error loading labels, exiting\n");
            exit(1);
        }
        printf("Labeling PCAP: %s\n", arguments.pcap);
        rv = labeler.label_pcap(arguments.pcap, arguments.outfile);
        if (rv == false) {
            printf("Failure while parsing pcap\n");
            exit(1);
        }
    }

    /* TODO use tmp file so that we can label & sort in 1 cmd */
    if (arguments.sort == true && arguments.pcapml != NULL) {
        printf("Sorting pcapml\n");
        sorter.sort_pcapng(arguments.pcapml, arguments.outfile);
    }

    if (arguments.pcapml != NULL && arguments.outdir != NULL) {
        rv = splitter.split_pcapng(arguments.pcapml, arguments.outdir);
        if (rv != 0) {
            printf("Error while splitting pcapml file\n");
            exit(3);
        }
    }

    return 0;
}
