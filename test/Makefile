CXXFLAGS= -W -Wall -Wpointer-arith -pipe \
	-D_FILE_OFFSET_BITS=64

SRCFILE := $(wildcard test*.c)	
EXE_CXX := $(basename $(SRCFILE))

#OBJALL := $(wildcard ../*.o)
#MAINS := ../bcsfs.o						 
#OBJ := $(filter-out ../bcsfs.o, $(OBJALL))
LIBS := 

all : $(EXE_CXX)
$(EXE_CXX) : % : %.c
	g++ -g -o $@ $< $(CXXFLAGS) -I../ -L../ $(OBJ) $(LIBS)

#=========================================================================
.PHONY  : clean
clean :
	    rm -f  $(EXE_CXX)
