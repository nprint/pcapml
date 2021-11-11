AUTOMAKE_OPTIONS = subdir-objects

bin_PROGRAMS = pcapml

pcapml_SOURCES = include/dir/dir.hpp include/label/label.hpp include/label/labeler.hpp \
				 include/pcap/pcap_reader.hpp include/pcapng/pcapng_reader.hpp include/pcapng/pcapng_writer.hpp \
				 include/pcapng/block.hpp include/pcapng/pcapng_sorter.hpp include/sample/sample.hpp \
				 include/sample/sampler.hpp include/util.hpp include/pcapng/pcapng_splitter.hpp \
				 include/pcap/pcap_writer.hpp \
				 src/dir/dir.cpp src/label/label.cpp src/label/labeler.cpp \
				 src/pcap/pcap_reader.cpp src/pcapng/pcapng_reader.cpp src/pcapng/pcapng_writer.cpp \
				 src/pcapng/block.cpp src/pcapng/pcapng_sorter.cpp src/sample/sample.cpp \
				 src/sample/sampler.cpp src/util.cpp src/pcapml.cpp src/pcapng/pcapng_splitter.cpp \
				 src/pcap/pcap_writer.cpp

AM_CPPFLAGS = -I include/ -I include/dir -I include/pcap/ -I include/pcapng -I include/sample -I include/label -pedantic -Wall -std=gnu++11 $(WRAPPER_CPPFLAGS)
AM_LDFLAGS = $(WRAPPER_LDFLAGS)
