#ifndef SIMULATOR_H
#define SIMULATOR_H

typedef enum {
    SKIP = 1,
    BITFLIP = 2,
    LOG = 4,
    HAVOC = 8,
    ZERO = 16,
    SET = 32,
    FAULT_END
} fault_t;

typedef enum {
    TARGET_MEMORY = 1,
    TARGET_REGISTER = 2
} target_t;

typedef enum {
    RIP = 1,
    INSTRUCTION = 2
} position_t;

typedef enum {
    LOG_INSTRUCTION = 1,
    LOG_FAULT = 2,
    LOG_REGISTER = 4
} log_t;

typedef enum {
    REG_RAX = 0,
    REG_RBX,
    REG_RCX,
    REG_RDX,
    REG_RSI,
    REG_RDI,
    REG_RBP,
    REG_RSP,
    REG_R8,
    REG_R9,
    REG_R10,
    REG_R11,
    REG_R12,
    REG_R13,
    REG_R14,
    REG_R15,
    REG_RIP,
    REG_RFLAGS,
    REG_END
} reg_id_t;


typedef struct {
    fault_t type;

    log_t log;
    position_t position;

    union {
        size_t rip;
        size_t instruction;
    };

    target_t target;
    reg_id_t reg;
    size_t index;
    size_t destination;
    size_t value;
    size_t value_len;
    size_t width;
} Command;

typedef struct {
    size_t fault_blacklist;
    size_t position_blacklist;
    size_t log_blacklist;
    size_t destination_blacklist;
    int no_code_fault;
    int skip_min;
    int skip_max;
    int timeout;
    size_t fail_every;
    int seed;
    size_t cooldown;
    size_t max_faults;
    int aslr;
    int beforemain;
    size_t entry;
    size_t code_start;
    size_t code_end;
    int print_success;
} Config;

#ifdef SYMMAP_SUPPORT
typedef struct {
    char *key;
    size_t address;
} MapEntry;
#endif


#define TAG_ERROR "\033[91m[ERROR]\033[0m "
#define TAG_DEBUG "\033[94m[DEBUG]\033[0m "
#define TAG_LINE  "\033[95mLine %zd:\033[0m "

#define ERROR(...) tagged_printf(TAG_ERROR, 0, __VA_ARGS__)
#define DEBUG(...) tagged_printf(TAG_DEBUG, 1, __VA_ARGS__)

#define DELIMITER " \t\r\n"
#define SYMMAP_EXT ".symmap"
#define CONFCACHE_EXT ".confcache"

#endif
