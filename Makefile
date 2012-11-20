# Output binary to be built
TARGET=tcpxm
OUTPUT=output
TAGFILE=.tagfile

ROOTPATH=$(shell pwd)
BUILD=$(ROOTPATH)/build

#
# LIBPCAP LIBARY
#

LIBCONFIG_BUILD=$(BUILD)/libconfig
LIBCONFIG_VER:=1.4.8
LIBCONFIG_MAKE_DIR=$(LIBCONFIG_BUILD)/libconfig-$(LIBCONFIG_VER)

LIBLOG4C_BUILD=$(BUILD)/liblog4c
LIBLOG4C_VER:=1.2.1
LIBLOG4C_MAKE_DIR=$(LIBLOG4C_BUILD)/log4c-$(LIBLOG4C_VER)

LIBPCAP_BUILD=$(BUILD)/libpcap
LIBPCAP_VER:=1.3.0
LIBPCAP_MAKE_DIR=$(LIBPCAP_BUILD)/libpcap-$(LIBPCAP_VER)

OBJ_DIR:=$(ROOTPATH)/obj
SRC_SUFFIX:=c
OBJ:=$(patsubst %.$(SRC_SUFFIX), $(OBJ_DIR)/$(basename %).o, $(wildcard *.$(SRC_SUFFIX)))

# C compiler
CC=gcc

#C Compiler Flags
CFLAGS= -W -Wall -Wpointer-arith -pipe \
	-DCURL_LOADER_FD_SETSIZE=20000 \
	-D_FILE_OFFSET_BITS=64 -lexpat

#
# Making options: e.g. $make optimize=1 debug=0 profile=1 
#
debug ?= 1
optimize ?= 1
profile ?= 0

#Debug flags
ifeq ($(debug),1)
DEBUG_FLAGS+= -g
else
DEBUG_FLAGS=
ifeq ($(profile),0)
OPT_FLAGS+=-fomit-frame-pointer
endif
endif

#Optimization flags
ifeq ($(optimize),1)
OPT_FLAGS+= -O3 -ffast-math -finline-functions -funroll-all-loops \
	-finline-limit=1000 -mmmx -msse -foptimize-sibling-calls
else
OPT_FLAGS= -O0
endif

# CPU-tuning flags for Pentium-4 arch as an example.
#
#OPT_FLAGS+= -mtune=pentium4 -mcpu=pentium4

# CPU-tuning flags for Intel core-2 arch as an example. 
# Note, that it is supported only by gcc-4.3 and higher
#OPT_FLAGS+=  -mtune=core2 -march=core2

#Profiling flags
ifeq ($(profile),1)
PROF_FLAG=-pg
else
PROF_FLAG=
endif


#Linker mapping
LD=gcc

#Linker Flags
LDFLAGS=-L$(ROOTPATH)/lib

# Link Libraries. In some cases, plese add -lidn, or -lldap
LIBS= -lz -ldl -lpthread -lnsl -lrt -lresolv -lpcap -lconfig -llog4c

# Include directories
INCDIR=-I. -I.. -I$(ROOTPATH)/inc

# Targets
#LIBPCAP:=$(ROOTPATH)/lib/libpcap.a
LIBCONFIG:=$(ROOTPATH)/lib/libconfig.a
LIBLOG4C:=$(ROOTPATH)/lib/liblog4c.a

all: $(TARGET)

$(TARGET): $(LIBPCAP) $(LIBCONFIG) $(LIBLOG4C) $(OBJ)
	$(LD) $(PROF_FLAG) $(DEBUG_FLAGS) $(OPT_FLAGS) -o $@ $(OBJ) $(LDFLAGS) $(LIBS)

clean:
	rm -rf $(OBJ_DIR)/*.o $(TARGET) core* output log/*

cleanall: clean
	rm -rf ./build ./inc ./lib ./bin $(TAGFILE) ./log/* 

tags:
	etags --members -o $(TAGFILE) *.h *.c

DESTDIR=/home/guowei/local/tcpxm
install:
	mkdir -p $(DESTDIR)/bin 
	cp -f curl-loader $(DESTDIR)/bin

output:
	rm -rf $(OUTPUT)
	mkdir -p $(OUTPUT)
	mkdir -p $(OUTPUT)/bin
	mkdir -p $(OUTPUT)/conf
	mkdir -p $(OUTPUT)/log
	cp -f $(TARGET) $(OUTPUT)/bin
	cp log4crc $(OUTPUT)/
	cp -rf conf/* $(OUTPUT)/conf

$(LIBPCAP):
	mkdir -p $(LIBPCAP_BUILD)
	cd $(LIBPCAP_BUILD); tar zxfv ../../packages/libpcap-$(LIBPCAP_VER).tar.gz;
	cd $(LIBPCAP_MAKE_DIR); ./configure --prefix $(LIBPCAP_BUILD) \
		CFLAGS="$(PROF_FLAG) $(DEBUG_FLAGS) $(OPT_FLAGS)"
	make -C $(LIBPCAP_MAKE_DIR); make -C $(LIBPCAP_MAKE_DIR) install
	mkdir -p ./inc; mkdir -p ./lib
	cp -prf $(LIBPCAP_BUILD)/include/* ./inc
	cp -prf $(LIBPCAP_BUILD)/lib/*.a ./lib
	
$(LIBCONFIG):
	mkdir -p $(LIBCONFIG_BUILD)
	cd $(LIBCONFIG_BUILD); tar zxfv ../../packages/libconfig-$(LIBCONFIG_VER).tar.gz;
	cd $(LIBCONFIG_MAKE_DIR); ./configure --prefix $(LIBCONFIG_BUILD) \
		CFLAGS="$(PROF_FLAG) $(DEBUG_FLAGS) $(OPT_FLAGS)"
	make -C $(LIBCONFIG_MAKE_DIR); make -C $(LIBCONFIG_MAKE_DIR) install
	mkdir -p ./inc; mkdir -p ./lib
	cp -pf $(LIBCONFIG_BUILD)/include/*.h ./inc
	cp -pf $(LIBCONFIG_BUILD)/lib/libconfig.a ./lib

$(LIBLOG4C):
	mkdir -p $(LIBLOG4C_BUILD)
	cd $(LIBLOG4C_BUILD); tar zxfv ../../packages/log4c-$(LIBLOG4C_VER).tar.gz;
	cd $(LIBLOG4C_MAKE_DIR); ./configure --prefix $(LIBLOG4C_BUILD) --without-expat\
		CFLAGS="$(PROF_FLAG) $(DEBUG_FLAGS) $(OPT_FLAGS)"
	make -C $(LIBLOG4C_MAKE_DIR); make -C $(LIBLOG4C_MAKE_DIR) install
	mkdir -p ./inc; mkdir -p ./lib
	cp -pf $(LIBLOG4C_BUILD)/include/*.h ./inc
	cp -rpf $(LIBLOG4C_BUILD)/include/log4c/ ./inc
	cp -pf $(LIBLOG4C_BUILD)/lib/liblog4c.a ./lib



# Files types rules
.SUFFIXES: .o .c .h

*.o: *.h

$(OBJ_DIR)/%.o: %.c
	$(CC) $(CFLAGS) $(PROF_FLAG) $(OPT_FLAGS) $(DEBUG_FLAGS) $(INCDIR) -c -o $(OBJ_DIR)/$*.o $<

