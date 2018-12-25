//
//  MachoOffsetFinder.h
//  MachoOffsetFinder
//
//  Created by Jake James on 12/24/18.
//  Copyright © 2018 Jake James. All rights reserved.
//

#ifndef MachoOffsetFinder_h
#define MachoOffsetFinder_h

#import <unistd.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <stdbool.h>
#import <errno.h>
#import <mach-o/loader.h>
#import <mach-o/swap.h>

// dunno if the built-in headers have something like this but I couldn't find any so DIY :)
struct symbol {
    uint32_t table_index;
    uint8_t type;
    uint8_t section_index;
    uint16_t description;
    uint64_t address;
};

extern FILE *file;
extern uint32_t offset;

extern uint32_t magic;
extern int ncmds;

extern struct symtab_command symtab;

extern uint32_t __cstring_offset;
extern uint64_t __cstring_size;

extern uint64_t __text_offset;
extern uint64_t __text_size;

extern uint64_t base;

void *load_bytes(FILE *obj_file, off_t offset, uint32_t size);

uint64_t find_string(const char *string, bool verbose);
uint64_t find_symbol(const char *symbol, bool verbose);
uint64_t find_reference(uint64_t what, int which);
uint64_t start_of_function(uint64_t addr);
uint64_t calculate_register_value(uint64_t start, uint64_t addr, int reg);

int initWithMacho(const char *macho);

#endif /* MachoOffsetFinder_h */
