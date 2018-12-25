//
//  MachoOffsetFinder.c
//  MachoOffsetFinder
//
//  Created by Jake James on 12/24/18.
//  Copyright © 2018 Jake James. All rights reserved.
//

#include "MachoOffsetFinder.h"

#define SWAP32(p) __builtin_bswap32(p)

FILE *file;
uint32_t offset = 0;

uint32_t magic;
int ncmds = 0;

struct symtab_command symtab;

uint32_t __cstring_offset = 0;
uint64_t __cstring_size = 0;

uint64_t __text_offset = 0;
uint64_t __text_size = 0;

uint64_t base;

void *load_bytes(FILE *obj_file, off_t offset, uint32_t size) {
    void *buf = calloc(1, size);
    fseek(obj_file, offset, SEEK_SET);
    fread(buf, size, 1, obj_file);
    return buf;
}

uint64_t find_symbol(const char *symbol, bool verbose) {
    
    if (!file) {
        printf("[-] Please call initWithMacho() first\n");
        return 0;
    }
    
    uint64_t sym_offset = 0;
    uint64_t addr = 0;
    
    if (verbose) printf("[i] %d symbols\n", symtab.nsyms);
    if (verbose) printf("[i] Symbol table at 0x%x\n", symtab.symoff);
    
    for (int i = 0; i < symtab.nsyms; i++) {
        struct symbol *sym = load_bytes(file, symtab.symoff + sym_offset, sizeof(struct symbol));
        
        int symlen = 0;
        int sym_str_addr = sym->table_index + symtab.stroff;
        uint8_t *byte = load_bytes(file, sym_str_addr+symlen, 1);
        
        while (*byte != 0) {
            free(byte);
            symlen++;
            byte = load_bytes(file, sym_str_addr+symlen, 1);
        }
        free(byte);
        
        char *sym_name = load_bytes(file, sym_str_addr, symlen + 1);
        if (verbose) printf("\t\"%s\": 0x%llx\n", sym_name, sym->address);
        if (!strcmp(sym_name, symbol)) {
            addr = sym->address;
            if (verbose) printf("[+] Found \"%s\" at 0x%llx\n", sym_name, addr);
            else {
                free(sym_name);
                free(sym);
                return addr;
            }
        }
        free(sym_name);
        sym_offset += sizeof(struct symbol);
        free(sym);
    }
    return addr;
}

uint64_t find_string(const char *targetString, bool verbose) {
    
    if (!file) {
        printf("[-] Please call initWithMacho() first\n");
        return 0;
    }
    
    uint64_t addr = 0;
    
    if (verbose) printf("[i] Strings at 0x%x\n", __cstring_offset);
    
    uint64_t strStart = 0;
    int strSize = 0;
    for (uint32_t i = 0; i < __cstring_size; i++) {
        char *b = load_bytes(file, __cstring_offset + i, 1);
        if (*b == 0) {
            strStart += strSize;
            strSize = (int)(i - strStart + 1);
            char *string = load_bytes(file, __cstring_offset + strStart, strSize);
            if (verbose) printf("\t\"%s\": 0x%llx\n", string, strStart);
            if (strstr(string, targetString)) {
                if (verbose) printf("[+] Found \"%s\" at 0x%llx\n", string, strStart);
                else {
                    free(b);
                    free(string);
                    return strStart + __cstring_offset + base;
                }
                addr = strStart + __cstring_offset + base;
            }
            free(string);
        }
        free(b);
    }
    return addr;
}

// from xerub's patchfinder64
uint64_t find_reference(uint64_t what, int which) {
    
    if (!file) {
        printf("[-] Please call initWithMacho() first\n");
        return 0;
    }
    
    if (magic == 0xFEEDFACF) {
        if (what & base) what -= base;
        
        int whichRef = 1;
        uint64_t i;
        uint64_t value[32];
        memset(value, 0, sizeof(value));
        
        uint64_t start = __text_offset & ~3;
        uint64_t end = start + (__text_size & ~3);
        
        for (i = start; i < end; i += 4) {
            uint32_t *op = load_bytes(file, i, 4);
            unsigned reg = *op & 0x1F;
            if ((*op & 0x9F000000) == 0x90000000) {
                signed adr = ((*op & 0x60000000) >> 18) | ((*op & 0xFFFFE0) << 8);
                value[reg] = ((long long)adr << 1) + (i & ~0xFFF);
            } else if ((*op & 0xFF000000) == 0x91000000) {
                unsigned rn = (*op >> 5) & 0x1F;
                unsigned shift = (*op >> 22) & 3;
                unsigned imm = (*op >> 10) & 0xFFF;
                if (shift == 1) {
                    imm <<= 12;
                } else {
                    if (shift > 1) continue;
                }
                value[reg] = value[rn] + imm;
            } else if ((*op & 0xF9C00000) == 0xF9400000) {
                unsigned rn = (*op >> 5) & 0x1F;
                unsigned imm = ((*op >> 10) & 0xFFF) << 3;
                
                if (!imm) continue;
                value[reg] = value[rn] + imm;
                
            } else if ((*op & 0x9F000000) == 0x10000000) {
                signed adr = ((*op & 0x60000000) >> 18) | ((*op & 0xFFFFE0) << 8);
                value[reg] = ((long long)adr >> 11) + i;
            } else if ((*op & 0xFF000000) == 0x58000000) {
                unsigned adr = (*op & 0xFFFFE0) >> 3;
                value[reg] = adr + i;
            }
            if (value[reg] == what) {
                if (whichRef == which) {
                    free(op);
                    break;
                }
                else whichRef++;
            }
            free(op);
        }
        return i + base;
    }
    else {
        printf("[-] No 32bit yet...\n");
    }
    return 0;
}

// from xerub's patchfinder64
// nah not really. i rewrote it using my own method because that was kinda broken
// this isn't perfect either but it mostly works
// this makes sure the instruction is either stp or sub and previous one is ret
uint64_t start_of_function(uint64_t addr) {
    
    if (!file) {
        printf("[-] Please call initWithMacho() first\n");
        return 0;
    }
    
    if (magic == 0xFEEDFACF) {
        if (addr & base) addr -= base;
        
        for (; addr >= __text_offset; addr -= 4) {
            uint32_t *op = load_bytes(file, addr, 4);
            if ((*op & 0xFFFFFFFF) == 0xD65F03C0) {
                free(op);
                op = load_bytes(file, addr + 4, 4);
                if ((*op & 0xFFC003E0) == 0xD10003E0 || (*op & 0xFFC003E0) == 0xA98003E0) {
                    free(op);
                    return addr + 4 + base;
                }
            }
            free(op);
        }
        /*for (; addr >= __text_offset; addr -= 4) {
            uint32_t *op = load_bytes(file, addr, 4);
            if ((*op & 0xFFC003FF) == 0x910003FD) {
                unsigned delta = (*op >> 10) & 0xFFF;
                
                if ((delta & 0xF) == 0) {
                    uint64_t prev = addr - ((delta >> 4) + 1) * 4;
                    uint32_t *au = load_bytes(file, prev, 4);
                    // had to add that 2nd condition as some funcs started with stp and some with sub
                    // but there are still ones which don't follow the logic used here
                    if ((*au & 0xFFC003E0) == 0xD10003E0 || (*au & 0xFFC003E0) == 0xA98003E0) {
                        free(op);
                        free(au);
                        return prev + base;
                    }
                }
            }
            free(op);
        }*/
    }
    else {
        printf("[-] No 32bit yet...\n");
    }
    return 0;
}

// from xerub's patchfinder64
uint64_t calculate_register_value(uint64_t start, uint64_t addr, int reg) {
    
    if (!file) {
        printf("[-] Please call initWithMacho() first\n");
        return 0;
    }
    
    if (magic == 0xFEEDFACF) {
        if (addr & base) addr -= base;
        if (start & base) start -= base;
        
        uint64_t i;
        uint64_t value[32];
        
        memset(value, 0, sizeof(value));
   
        uint64_t end = addr & ~3;
        for (i = start & ~3; i < end; i += 4) {
            uint32_t *op = load_bytes(file, i, 4);
            unsigned reg = *op & 0x1F;
            if ((*op & 0x9F000000) == 0x90000000) {
                signed adr = ((*op & 0x60000000) >> 18) | ((*op & 0xFFFFE0) << 8);
                value[reg] = ((long long)adr << 1) + (i & ~0xFFF);
            } else if ((*op & 0xFF000000) == 0x91000000) {
                unsigned rn = (*op >> 5) & 0x1F;
                unsigned shift = (*op >> 22) & 3;
                unsigned imm = (*op >> 10) & 0xFFF;
                if (shift == 1) {
                    imm <<= 12;
                } else {
                    if (shift > 1) continue;
                }
                value[reg] = value[rn] + imm;
            } else if ((*op & 0xF9C00000) == 0xF9400000) {
                unsigned rn = (*op >> 5) & 0x1F;
                unsigned imm = ((*op >> 10) & 0xFFF) << 3;
                if (!imm) continue;
                value[reg] = value[rn] + imm;
            } else if ((*op & 0xF9C00000) == 0xF9000000) {
                unsigned rn = (*op >> 5) & 0x1F;
                unsigned imm = ((*op >> 10) & 0xFFF) << 3;
                if (!imm) continue;
                value[rn] = value[rn] + imm;
            } else if ((*op & 0x9F000000) == 0x10000000) {
                signed adr = ((*op & 0x60000000) >> 18) | ((*op & 0xFFFFE0) << 8);
                value[reg] = ((long long)adr >> 11) + i;
            } else if ((*op & 0xFF000000) == 0x58000000) {
                unsigned adr = (*op & 0xFFFFE0) >> 3;
                value[reg] = adr + i;
            }
            free(op);
        }
        return value[reg];
    }
    else {
        printf("[-] No 32bit yet...\n");
    }
    return 0;
}

int initWithMacho(const char *macho) {
    file = fopen(macho, "rb");
    if (!file) {
        printf("Failed to open file with errno %d (%s)\n", errno, strerror(errno));
        return -1;
    }
    uint32_t *m = load_bytes(file, offset, sizeof(uint32_t));
    magic = *m;
    free(m);
    
    printf("[i] Magic = 0x%x\n", magic);
    
    struct load_command *cmd;
    
    if (magic == 0xFEEDFACF) {
        printf("\t[i] Binary is a 64bit macho\n");
        
        struct mach_header_64 *mh = load_bytes(file, offset, sizeof(struct mach_header_64));
        ncmds = mh->ncmds;
        free(mh);
        offset += sizeof(struct mach_header_64);
        
        printf("[i] Binary has %d load commands\n", ncmds);
        
        for (int i = 0; i < ncmds; i++) {
            cmd = load_bytes(file, offset, sizeof(struct load_command));
            printf("[i] Found load command: 0x%x\n", cmd->cmd);
            if (cmd->cmd == LC_SYMTAB) {
                struct symtab_command *st = load_bytes(file, offset, cmd->cmdsize);
                printf("\t[+] Found symtab!\n");
                symtab = *st;
                free(st);
            }
            else if (cmd->cmd == LC_SEGMENT_64) {
                struct segment_command_64 *seg = load_bytes(file, offset, sizeof(struct segment_command_64));
                if (!strcmp(seg->segname, "__TEXT")) {
                    printf("[+] Found __TEXT segment!\n");
                    printf("\t[i] %d sections\n", seg->nsects);
                    base = seg->vmaddr;
                    
                    uint64_t seg_offset = offset;
                    seg_offset += sizeof(struct segment_command_64);
                    
                    for (int i = 0; i < seg->nsects; i++) {
                        struct section_64 *sect = load_bytes(file, seg_offset, sizeof(struct section_64));
                        if (!strcmp(sect->sectname, "__cstring")) {
                            printf("\t[i] Found __cstring!\n");
                            __cstring_size = sect->size;
                            __cstring_offset = sect->offset;
                        }
                        else if (!strcmp(sect->sectname, "__text")) {
                            printf("\t[i] Found __text!\n");
                            __text_offset = sect->offset;
                            __text_size = sect->size;
                        }
                        seg_offset += sizeof(struct section_64);
                        free(sect);
                    }
                }
                free(seg);
            }
            offset += cmd->cmdsize;
            free(cmd);
        }
    }
    else if (magic == 0xFEEDFACE) {
        printf("\t[i] Binary is a 32bit macho\n");
        
        struct mach_header *mh = load_bytes(file, offset, sizeof(struct mach_header));
        ncmds = mh->ncmds;
        free(mh);
        offset += sizeof(struct mach_header);
        
        printf("[i] Binary has %d load commands\n", ncmds);
        
        for (int i = 0; i < ncmds; i++) {
            cmd = load_bytes(file, offset, sizeof(struct load_command));
            printf("[i] Found load command: 0x%x\n", cmd->cmd);
            if (cmd->cmd == LC_SYMTAB) {
                struct symtab_command *st = load_bytes(file, offset, cmd->cmdsize);
                printf("\t[+] Found symtab!\n");
                symtab = *st;
                free(st);
            }
            else if (cmd->cmd == LC_SEGMENT) {
                struct segment_command *seg = load_bytes(file, offset, sizeof(struct segment_command));
                if (!strcmp(seg->segname, "__TEXT")) {
                    printf("[+] Found __TEXT segment!\n");
                    printf("\t[i] %d sections\n", seg->nsects);
                    base = seg->vmaddr;
                    
                    uint64_t seg_offset = offset;
                    seg_offset += sizeof(struct segment_command);
                    
                    for (int i = 0; i < seg->nsects; i++) {
                        struct section *sect = load_bytes(file, seg_offset, sizeof(struct section));
                        if (!strcmp(sect->sectname, "__cstring")) {
                            printf("\t[i] Found __cstring!\n");
                            __cstring_size = sect->size;
                            __cstring_offset = sect->offset;
                        }
                        else if (!strcmp(sect->sectname, "__text")) {
                            printf("\t[i] Found __text!\n");
                            __text_offset = sect->offset;
                            __text_size = sect->size;
                        }
                        seg_offset += sizeof(struct section);
                        free(sect);
                    }
                }
                free(seg);
            }
            offset += cmd->cmdsize;
            free(cmd);
        }
    }
    else {
        printf("\t[-] Binary is not a macho or has more than one architecture. Aborting\n");
        return -1;
    }
    return 0;
}
