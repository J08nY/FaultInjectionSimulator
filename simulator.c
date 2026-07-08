#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <sys/user.h>
#include <stdint.h>
#include <stdarg.h>
#include <time.h>
#include <sys/personality.h>
#include <elf.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <inttypes.h>

#include "simulator.h"


// ------------------------------------------------------------------------------------------------
static Config config = {
    .skip_min = -15,
    .skip_max = 15,
    .timeout = 30,
    .aslr = 1,
    .beforemain = 0,
    .print_success = 1
};

static Command *commands = NULL;
static int commands_count = 0;
static int commands_len = 0;
static const char *command_name[FAULT_END];

static size_t instruction_counter = 0;
static size_t fault_cooldown = 0;
static size_t faults = 0;

static size_t start_time;
static int debug_level = 0;

static const char *register_name(reg_id_t reg);

static int resolve_register(const char *name, reg_id_t *reg);

static unsigned long long register_read(const struct user_regs_struct *regs, reg_id_t reg);

static void register_write(struct user_regs_struct *regs, reg_id_t reg, unsigned long long value);

static size_t register_width(reg_id_t reg);

static size_t effective_width(const Command *c);

static size_t width_mask(size_t width);

static int command_matches(const Command *c, size_t rip, size_t instruction);

static int poke_byte(int pid, size_t addr, unsigned char byte);

#ifdef SYMMAP_SUPPORT
static MapEntry *sym_map = NULL;
static int sym_count = 0;
static MapEntry *line_map = NULL;
static int line_count = 0;

static void load_symmap(char *path);

static int resolve_name(const char *name, size_t *addr);
#endif


// ------------------------------------------------------------------------------------------------
void tagged_printf(const char *tag, int level, const char *format, ...) {
    va_list args;
    if (level > debug_level) return;
    fprintf(stderr, "%s", tag);
    va_start(args, format);
    vfprintf(stderr, format, args);
    fflush(stderr);
    va_end(args);
}

void print(const char *format, ...) {
	va_list args;
	va_start(args, format);
	vfprintf(stdout, format, args);
	fflush(stdout);
	va_end(args);
}

// ------------------------------------------------------------------------------------------------
int add_command(Command *c, size_t line_nr) {
    if (config.fault_blacklist & c->type) {
        ERROR(TAG_LINE "Command '%s' not allowed for this binary!\n", line_nr, command_name[c->type]);
        return 1;
    }
    size_t width = effective_width(c);
    if (config.no_code_fault && c->target == TARGET_MEMORY && (c->type & (BITFLIP | HAVOC | ZERO | SET)) &&
        c->destination < config.code_end && c->destination + width > config.code_start) {
        ERROR(TAG_LINE "Faults in .text section are not allowed!\n", line_nr);
        return 1;
    }

    if (commands == NULL) {
        commands_len = 128;
        commands = (Command *) malloc(commands_len * sizeof(Command));
    }
    commands[commands_count++] = *c;
    if (commands_count == commands_len) {
        commands_len *= 2;
        commands = (Command *) realloc(commands, commands_len * sizeof(Command));
    }
    return 0;
}

// ------------------------------------------------------------------------------------------------
static const char *register_name(reg_id_t reg) {
    switch (reg) {
        case REG_RAX: return "RAX";
        case REG_RBX: return "RBX";
        case REG_RCX: return "RCX";
        case REG_RDX: return "RDX";
        case REG_RSI: return "RSI";
        case REG_RDI: return "RDI";
        case REG_RBP: return "RBP";
        case REG_RSP: return "RSP";
        case REG_R8: return "R8";
        case REG_R9: return "R9";
        case REG_R10: return "R10";
        case REG_R11: return "R11";
        case REG_R12: return "R12";
        case REG_R13: return "R13";
        case REG_R14: return "R14";
        case REG_R15: return "R15";
        case REG_RIP: return "RIP";
        case REG_RFLAGS: return "RFLAGS";
        default: return "UNKNOWN";
    }
}

// ------------------------------------------------------------------------------------------------
static int resolve_register(const char *name, reg_id_t *reg) {
    if (!name) return 1;
    if (!strcasecmp(name, "rax")) *reg = REG_RAX;
    else if (!strcasecmp(name, "rbx")) *reg = REG_RBX;
    else if (!strcasecmp(name, "rcx")) *reg = REG_RCX;
    else if (!strcasecmp(name, "rdx")) *reg = REG_RDX;
    else if (!strcasecmp(name, "rsi")) *reg = REG_RSI;
    else if (!strcasecmp(name, "rdi")) *reg = REG_RDI;
    else if (!strcasecmp(name, "rbp")) *reg = REG_RBP;
    else if (!strcasecmp(name, "rsp")) *reg = REG_RSP;
    else if (!strcasecmp(name, "r8")) *reg = REG_R8;
    else if (!strcasecmp(name, "r9")) *reg = REG_R9;
    else if (!strcasecmp(name, "r10")) *reg = REG_R10;
    else if (!strcasecmp(name, "r11")) *reg = REG_R11;
    else if (!strcasecmp(name, "r12")) *reg = REG_R12;
    else if (!strcasecmp(name, "r13")) *reg = REG_R13;
    else if (!strcasecmp(name, "r14")) *reg = REG_R14;
    else if (!strcasecmp(name, "r15")) *reg = REG_R15;
    else if (!strcasecmp(name, "rip")) *reg = REG_RIP;
    else if (!strcasecmp(name, "rflags") || !strcasecmp(name, "eflags")) *reg = REG_RFLAGS;
    else return 1;
    return 0;
}

// ------------------------------------------------------------------------------------------------
static unsigned long long register_read(const struct user_regs_struct *regs, reg_id_t reg) {
    switch (reg) {
        case REG_RAX: return (unsigned long long) regs->rax;
        case REG_RBX: return (unsigned long long) regs->rbx;
        case REG_RCX: return (unsigned long long) regs->rcx;
        case REG_RDX: return (unsigned long long) regs->rdx;
        case REG_RSI: return (unsigned long long) regs->rsi;
        case REG_RDI: return (unsigned long long) regs->rdi;
        case REG_RBP: return (unsigned long long) regs->rbp;
        case REG_RSP: return (unsigned long long) regs->rsp;
        case REG_R8: return (unsigned long long) regs->r8;
        case REG_R9: return (unsigned long long) regs->r9;
        case REG_R10: return (unsigned long long) regs->r10;
        case REG_R11: return (unsigned long long) regs->r11;
        case REG_R12: return (unsigned long long) regs->r12;
        case REG_R13: return (unsigned long long) regs->r13;
        case REG_R14: return (unsigned long long) regs->r14;
        case REG_R15: return (unsigned long long) regs->r15;
        case REG_RIP: return (unsigned long long) regs->rip;
        case REG_RFLAGS: return (unsigned long long) regs->eflags;
        default: return 0;
    }
}

// ------------------------------------------------------------------------------------------------
static void register_write(struct user_regs_struct *regs, reg_id_t reg, unsigned long long value) {
    switch (reg) {
        case REG_RAX: regs->rax = value;
            break;
        case REG_RBX: regs->rbx = value;
            break;
        case REG_RCX: regs->rcx = value;
            break;
        case REG_RDX: regs->rdx = value;
            break;
        case REG_RSI: regs->rsi = value;
            break;
        case REG_RDI: regs->rdi = value;
            break;
        case REG_RBP: regs->rbp = value;
            break;
        case REG_RSP: regs->rsp = value;
            break;
        case REG_R8: regs->r8 = value;
            break;
        case REG_R9: regs->r9 = value;
            break;
        case REG_R10: regs->r10 = value;
            break;
        case REG_R11: regs->r11 = value;
            break;
        case REG_R12: regs->r12 = value;
            break;
        case REG_R13: regs->r13 = value;
            break;
        case REG_R14: regs->r14 = value;
            break;
        case REG_R15: regs->r15 = value;
            break;
        case REG_RIP: regs->rip = value;
            break;
        case REG_RFLAGS: regs->eflags = value;
            break;
        default: break;
    }
}

// ------------------------------------------------------------------------------------------------
static size_t register_width(reg_id_t reg) {
    (void) reg;
    return 8;
}

// ------------------------------------------------------------------------------------------------
static size_t effective_width(const Command *c) {
    if (c->type == SET) return c->value_len;
    if (c->type == HAVOC || c->type == ZERO) return c->width;
    return 1;
}

// ------------------------------------------------------------------------------------------------
static size_t width_mask(size_t width) {
    if (width >= sizeof(unsigned long long)) return ~(size_t) 0;
    return (((size_t) 1) << (width * 8)) - 1;
}

// ------------------------------------------------------------------------------------------------
static int command_matches(const Command *c, size_t rip, size_t instruction) {
    return (c->position == RIP && c->rip == rip) || (c->position == INSTRUCTION && c->instruction == instruction);
}

// ------------------------------------------------------------------------------------------------
static int poke_byte(int pid, size_t addr, unsigned char byte) {
    errno = 0;
    long oldval = ptrace(PTRACE_PEEKDATA, pid, (void *) addr, 0);
    if (oldval == -1 && errno) return 1;
    if (ptrace(PTRACE_POKEDATA, pid, (void *) addr, (void *) ((oldval & ~0xffL) | (long) byte))) return 1;
    return 0;
}


// ------------------------------------------------------------------------------------------------
int parse_position(char *pos, Command *c, size_t line_nr) {
    if (!pos || strlen(pos) == 0) {
        ERROR(TAG_LINE "No position given\n", line_nr);
        return 1;
    }
    if (pos[0] == '@') {
        // absolute RIP by hex address
        if (config.position_blacklist & RIP) {
            ERROR(TAG_LINE "RIP-based faulting not allowed for this binary!\n", line_nr);
            return 1;
        }
        c->rip = strtoull(pos + 1, NULL, 0);
        c->position = RIP;
    } else if (pos[0] == '&') {
        // absolute RIP by symbol or source line
#ifdef SYMMAP_SUPPORT
        if (config.position_blacklist & RIP) {
            ERROR(TAG_LINE "RIP-based faulting not allowed for this binary!\n", line_nr);
            return 1;
        }
        size_t addr;
        if (resolve_name(pos + 1, &addr)) {
            if (sym_count == 0 && line_count == 0)
                ERROR(TAG_LINE "Symbolic trigger '%s' requires a symmap file (run ./mksymmap.sh first)\n", line_nr,
                  pos);
            else
                ERROR(TAG_LINE "Unknown symbol or line '%s'\n", line_nr, pos);
            return 1;
        }
        c->rip = addr;
#else
        ERROR(TAG_LINE "Symbolic trigger '%s' requires SYMMAP_SUPPORT enabled at compile time\n", line_nr, pos);
        return 1;
#endif
        c->position = RIP;
    } else if (pos[0] == '#') {
        // instruction count
        if (config.position_blacklist & INSTRUCTION) {
            ERROR(TAG_LINE "Instruction-count-based faulting not allowed for this binary!\n", line_nr);
            return 1;
        }
        c->instruction = strtoull(pos + 1, NULL, 0);
        c->position = INSTRUCTION;
    } else {
        ERROR(TAG_LINE "Unsupported position '%s'\n", line_nr, pos);
        return 1;
    }
    return 0;
}

// ------------------------------------------------------------------------------------------------
int parse_destination(char *pos, Command *c, size_t line_nr) {
    if (!pos || strlen(pos) == 0) {
        ERROR(TAG_LINE "No destination given\n", line_nr);
        return 1;
    }
    reg_id_t reg;
    if (resolve_register(pos, &reg) == 0) {
        if (config.destination_blacklist & TARGET_REGISTER) {
            ERROR(TAG_LINE "Register-based faulting not allowed for this binary!\n", line_nr);
            return 1;
        }
        c->target = TARGET_REGISTER;
        c->reg = reg;
        return 0;
    }
    if (config.destination_blacklist & TARGET_MEMORY) {
        ERROR(TAG_LINE "Memory-based faulting not allowed for this binary!\n", line_nr);
        return 1;
    }
    if (pos[0] == '&') {
#ifdef SYMMAP_SUPPORT
        size_t addr;
        if (resolve_name(pos + 1, &addr)) {
            if (sym_count == 0 && line_count == 0)
                ERROR(TAG_LINE "Symbolic destination '%s' requires a symmap file (run ./mksymmap.sh first)\n", line_nr,
                  pos);
            else
                ERROR(TAG_LINE "Unknown symbol '%s'\n", line_nr, pos);
            return 1;
        }
        c->destination = addr;
#else
        ERROR(TAG_LINE "Symbolic destination '%s' requires SYMMAP_SUPPORT enabled at compile time\n", line_nr, pos);
        return 1;
#endif
        c->target = TARGET_MEMORY;
    } else {
        c->destination = strtoull(pos, NULL, 0);
        c->target = TARGET_MEMORY;
    }
    return 0;
}

// ------------------------------------------------------------------------------------------------
int parse_index(char *pos, Command *c, size_t line_nr) {
    if (!pos || strlen(pos) == 0) {
        ERROR(TAG_LINE "No index given\n", line_nr);
        return 1;
    }
    c->index = atoi(pos);
    return 0;
}

// ------------------------------------------------------------------------------------------------
int parse_command(char *cmd, size_t line_nr) {
    char *command = strtok(cmd, DELIMITER);
    Command c = {0};

    if (!command) return 0;
    if (strlen(command) == 0) return 0;
    if (command[0] == '#') return 0; // comment

    if (!strcasecmp(command, command_name[SKIP])) {
        c.type = SKIP;
        if (parse_index(strtok(NULL, DELIMITER), &c, line_nr)) {
            return 1;
        }
        if ((ssize_t) c.index < (ssize_t) config.skip_min) {
            ERROR(TAG_LINE "Skip must be >= %d\n", line_nr, config.skip_min);
            return 1;
        }
        if (c.index > config.skip_max) {
            ERROR(TAG_LINE "Skip must be <= %d\n", line_nr, config.skip_max);
            return 1;
        }
        if (parse_position(strtok(NULL, DELIMITER), &c, line_nr)) {
            return 1;
        }
    } else if (!strcasecmp(command, command_name[LOG])) {
        c.type = LOG;
        char *type = strtok(NULL, DELIMITER);
        if (!type) {
            ERROR(TAG_LINE "Missing log type\n", line_nr);
            return 1;
        }
        if (!strcasecmp(type, "inscnt")) {
            c.log = LOG_INSTRUCTION;
        } else if (!strcasecmp(type, "fault")) {
            c.log = LOG_FAULT;
        } else if (resolve_register(type, &c.reg) == 0) {
            c.log = LOG_REGISTER;
        } else {
            ERROR(TAG_LINE "Unknown logging target '%s'\n", line_nr, type);
            return 1;
        }
        if (c.log & config.log_blacklist) {
            ERROR(TAG_LINE "Logging type '%s' not allowed for this binary!\n", line_nr, type);
            return 1;
        }
        if (c.log == LOG_REGISTER) {
            char *trigger = strtok(NULL, DELIMITER);
            if (trigger && parse_position(trigger, &c, line_nr)) {
                return 1;
            }
        }
    } else if (!strcasecmp(command, command_name[HAVOC])) {
        c.type = HAVOC;
        if (parse_destination(strtok(NULL, DELIMITER), &c, line_nr)) {
            return 1;
        }
        char *maybe_width = strtok(NULL, DELIMITER);
        char *trigger = maybe_width;
        c.width = (c.target == TARGET_REGISTER) ? register_width(c.reg) : 1;
        if (maybe_width && maybe_width[0] != '@' && maybe_width[0] != '#' && maybe_width[0] != '&') {
            c.width = strtoull(maybe_width, NULL, 0);
            if (c.width == 0 || c.width > 8) {
                ERROR(TAG_LINE "Width must be between 1 and 8\n", line_nr);
                return 1;
            }
            trigger = strtok(NULL, DELIMITER);
        }
        if (parse_position(trigger, &c, line_nr)) {
            return 1;
        }
    } else if (!strcasecmp(command, command_name[ZERO])) {
        c.type = ZERO;
        if (parse_destination(strtok(NULL, DELIMITER), &c, line_nr)) {
            return 1;
        }
        char *maybe_width = strtok(NULL, DELIMITER);
        char *trigger = maybe_width;
        c.width = (c.target == TARGET_REGISTER) ? register_width(c.reg) : 1;
        if (maybe_width && maybe_width[0] != '@' && maybe_width[0] != '#' && maybe_width[0] != '&') {
            c.width = strtoull(maybe_width, NULL, 0);
            if (c.width == 0 || c.width > 8) {
                ERROR(TAG_LINE "Width must be between 1 and 8\n", line_nr);
                return 1;
            }
            trigger = strtok(NULL, DELIMITER);
        }
        if (parse_position(trigger, &c, line_nr)) {
            return 1;
        }
    } else if (!strcasecmp(command, command_name[SET])) {
        c.type = SET;
        if (parse_destination(strtok(NULL, DELIMITER), &c, line_nr)) {
            return 1;
        }
        char *val = strtok(NULL, DELIMITER);
        if (!val || strlen(val) == 0) {
            ERROR(TAG_LINE "No value given\n", line_nr);
            return 1;
        }
        size_t hexlen = strlen(val);
        if (hexlen % 2) {
            ERROR(TAG_LINE "Value hex string must have an even number of digits (got %zu)\n", line_nr, hexlen);
            return 1;
        }
        c.value_len = hexlen / 2;
        if (c.value_len > 8) c.value_len = 8;
        c.value = 0;
        for (size_t i = 0; i < c.value_len; i++) {
            unsigned int byte;
            char pair[3] = {val[i * 2], val[i * 2 + 1], '\0'};
            sscanf(pair, "%2x", &byte);
            c.value |= (size_t) (byte & 0xff) << (i * 8);
        }
        if (parse_position(strtok(NULL, DELIMITER), &c, line_nr)) {
            return 1;
        }
    } else if (!strcasecmp(command, command_name[BITFLIP])) {
        c.type = BITFLIP;
        if (parse_index(strtok(NULL, DELIMITER), &c, line_nr)) {
            return 1;
        }
        if (c.index >= 64) {
            ERROR(TAG_LINE "Bit index must be between 0 and 63\n", line_nr);
            return 1;
        }
        if (parse_destination(strtok(NULL, DELIMITER), &c, line_nr)) {
            return 1;
        }
        if (parse_position(strtok(NULL, DELIMITER), &c, line_nr)) {
            return 1;
        }
    } else {
        return 1;
    }
    if (add_command(&c, line_nr)) return 1;
    return 0;
}

// ------------------------------------------------------------------------------------------------
int parse_script(char *file) {
    command_name[SKIP] = "skip";
    command_name[LOG] = "log";
    command_name[BITFLIP] = "bitflip";
    command_name[HAVOC] = "havoc";
    command_name[ZERO] = "zero";
    command_name[SET] = "set";

    DEBUG("Parsing %s...\n", file);
    FILE *f = fopen(file, "r");
    if (!f) {
        ERROR("Could not open script file '%s'\n", file);
        return 1;
    }
    char *line = NULL;
    size_t len = 0;
    size_t line_nr = 0;
    while (getline(&line, &len, f) != -1) {
        if (parse_command(line, ++line_nr)) {
            ERROR(TAG_LINE "Could not parse command '%s'\n", line_nr, line);
            free(line);
            return 1;
        }
        free(line);
        line = NULL;
        len = 0;
    }
    free(line);

    fclose(f);
    return 0;
}

// ------------------------------------------------------------------------------------------------
void parse_config(char *binary) {
    char config_cache[128];
    FILE *f;
    struct stat bin_stat;
    snprintf(config_cache, sizeof(config_cache), "%s" CONFCACHE_EXT, binary);
#ifdef CONFIG_CACHE
    if (!stat(binary, &bin_stat)) {
        f = fopen(config_cache, "rb");
        if (f) {
            time_t cached_mtime;
            off_t cached_size;
            if (fread(&cached_mtime, sizeof(cached_mtime), 1, f) == 1 &&
                fread(&cached_size, sizeof(cached_size), 1, f) == 1 &&
                cached_mtime == bin_stat.st_mtime &&
                cached_size == bin_stat.st_size) {
                DEBUG("Using cached config for '%s'\n", binary);
                fread(&config, sizeof(config), 1, f);
                fclose(f);
                return;
            }
            fclose(f);
        }
    }
#endif
    f = fopen(binary, "rb");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    size_t fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize < 128) {
        fclose(f);
        return;
    }
    char *elf = (char *) malloc(fsize);
    if (!elf) {
        fclose(f);
        return;
    }
    if (fread(elf, fsize, 1, f) != 1) {
        free(elf);
        fclose(f);
        return;
    }
    for (size_t i = 0; i < fsize - 24; i++) {
        if (!strcmp(elf + i, "FAULTCONFIG")) {
            char *conf = elf + i + 12;
            if (!strcmp(conf, "NOZERO")) config.fault_blacklist |= ZERO;
            if (!strcmp(conf, "NOHAVOC")) config.fault_blacklist |= HAVOC;
            if (!strcmp(conf, "NOSKIP")) config.fault_blacklist |= SKIP;
            if (!strcmp(conf, "NOBITFLIP")) config.fault_blacklist |= BITFLIP;
            if (!strcmp(conf, "NOSET")) config.fault_blacklist |= SET;
            if (!strcmp(conf, "NOLOG")) config.fault_blacklist |= LOG;
            if (!strcmp(conf, "NOASLR")) config.aslr = 0;
            if (!strcmp(conf, "NOLOGFAULT")) config.log_blacklist |= LOG_FAULT;
            if (!strcmp(conf, "NOLOGINSTRUCTION")) config.log_blacklist |= LOG_INSTRUCTION;
            if (!strcmp(conf, "NOLOGREGISTER")) config.log_blacklist |= LOG_REGISTER;
            if (!strcmp(conf, "NORIPTRIGGER")) config.position_blacklist |= RIP;
            if (!strcmp(conf, "NOINSTRUCTIONTRIGGER")) config.position_blacklist |= INSTRUCTION;
            if (!strcmp(conf, "BEFOREMAIN")) config.beforemain = 1;
            if (!strcmp(conf, "ENTRY")) config.entry = *(size_t *) (conf + 6);
            if (!strcmp(conf, "NOCODEFAULT")) config.no_code_fault = 1;
            if (!strcmp(conf, "NOMEMFAULT")) config.destination_blacklist |= TARGET_MEMORY;
            if (!strcmp(conf, "NOREGFAULT")) config.destination_blacklist |= TARGET_REGISTER;
            if (!strcmp(conf, "NOSUCCESS")) config.print_success = 0;
            if (!strncmp(conf, "MINSKIP=", 8)) config.skip_min = atoi(conf + 8);
            if (!strncmp(conf, "MAXSKIP=", 8)) config.skip_max = atoi(conf + 8);
            if (!strncmp(conf, "TIMEOUT=", 8)) config.timeout = atoi(conf + 8);
            if (!strncmp(conf, "FAILEVERY=", 10)) config.fail_every = atoi(conf + 10);
            if (!strncmp(conf, "SEED=", 5)) config.seed = atoi(conf + 5);
            if (!strncmp(conf, "COOLDOWN=", 9)) config.cooldown = strtoull(conf + 9, NULL, 0);
            if (!strncmp(conf, "MAXFAULTS=", 10)) config.max_faults = strtoull(conf + 10, NULL, 0);

            DEBUG("Config: %s\n", conf);
        }
    }
    free(elf);
    fclose(f);

#ifdef CONFIG_CACHE
    if (!stat(binary, &bin_stat)) {
        f = fopen(config_cache, "wb");
        if (f) {
            fwrite(&bin_stat.st_mtime, sizeof(bin_stat.st_mtime), 1, f);
            fwrite(&bin_stat.st_size, sizeof(bin_stat.st_size), 1, f);
            fwrite(&config, sizeof(config), 1, f);
            fclose(f);
        }
    }
#endif
}

#ifdef SYMMAP_SUPPORT
// ------------------------------------------------------------------------------------------------
void load_symmap(char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        DEBUG("No symmap file '%s' found, skipping symbolic resolution\n", path);
        return;
    }
    char *line = NULL;
    size_t len = 0;
    while (getline(&line, &len, f) != -1) {
        char type[32];
        char key[1024];
        size_t addr;
        if (sscanf(line, "%31s %1023s %zx", type, key, &addr) < 3)
            continue;
        if (!strcmp(type, "sym")) {
            sym_map = realloc(sym_map, (sym_count + 1) * sizeof(MapEntry));
            sym_map[sym_count].key = strdup(key);
            sym_map[sym_count].address = addr;
            sym_count++;
        } else if (!strcmp(type, "line")) {
            line_map = realloc(line_map, (line_count + 1) * sizeof(MapEntry));
            line_map[line_count].key = strdup(key);
            line_map[line_count].address = addr;
            line_count++;
        }
    }
    free(line);
    fclose(f);
    DEBUG("Loaded %d symbols and %d line mappings from '%s'\n", sym_count, line_count, path);
}

// ------------------------------------------------------------------------------------------------
int resolve_name(const char *name, size_t *addr) {
    const char *plus = strchr(name, '+');
    size_t sym_len;
    size_t offset = 0;
    if (plus) {
        sym_len = plus - name;
        offset = strtoull(plus + 1, NULL, 0);
    } else {
        sym_len = strlen(name);
    }

    for (int i = 0; i < sym_count; i++) {
        if (strlen(sym_map[i].key) == sym_len && !strncmp(sym_map[i].key, name, sym_len)) {
            *addr = sym_map[i].address + offset;
            return 0;
        }
    }

    const char *colon = strchr(name, ':');
    if (colon && (size_t) (colon - name) < sym_len) {
        for (int i = 0; i < line_count; i++) {
            size_t key_len = strlen(line_map[i].key);
            if (key_len == sym_len && !strncmp(line_map[i].key, name, sym_len)) {
                *addr = line_map[i].address + offset;
                return 0;
            }
        }
    }

    return 1;
}
#endif

// ------------------------------------------------------------------------------------------------
void show_status(int status) {
    if (WIFSTOPPED(status)) {
        DEBUG("Child stopped: %d\n", WSTOPSIG(status));
    }
    if (WIFEXITED(status)) {
        DEBUG("Child exited: %d\n", WEXITSTATUS(status));
    }
    if (WIFSIGNALED(status)) {
        DEBUG("Child signaled: %d\n", WTERMSIG(status));
    }
    if (WCOREDUMP(status)) {
        DEBUG("Core dumped.\n");
    }
}

// ------------------------------------------------------------------------------------------------
int ptrace_instruction_pointer(int pid) {
    struct user_regs_struct regs;
    int regs_dirty = 0;
    static int started = 0;
    if (ptrace(PTRACE_GETREGS, pid, NULL, (void *) &regs)) {
        ERROR("Error fetching registers from child process: %s\n", strerror(errno));
        return 1;
    }

    if (!started && (((size_t) regs.rip == config.entry) || config.beforemain || !config.entry)) {
        started = 1;
    }
    if (!started) {
        return 0;
    }

    int i, log_fault = 0;
    for (i = 0; i < commands_count; i++) {
        if (commands[i].type == LOG) {
            if (commands[i].log == LOG_INSTRUCTION) {
                print("Instruction #%zd\n", instruction_counter);
            } else if (commands[i].log == LOG_FAULT) {
                log_fault = 1;
            } else if (commands[i].log == LOG_REGISTER) {
                if (!commands[i].position || command_matches(&commands[i], (size_t) regs.rip, instruction_counter))
                    print("%s: 0x%llx\n", register_name(commands[i].reg), register_read(&regs, commands[i].reg));
            }
        }
    }

    for (i = 0; i < commands_count; i++) {
        if (commands[i].type != LOG && command_matches(&commands[i], (size_t) regs.rip, instruction_counter)) {
            if (fault_cooldown) {
                DEBUG("Cooldown - skipping fault '%s'\n", command_name[commands[i].type]);
                if (log_fault)
                    print("Cannot induce fault '%s' - last fault was too recent\n",
                           command_name[commands[i].type]);
                continue;
            }

            fault_cooldown = config.cooldown;

            if (config.fail_every > 0) {
                if ((rand() % config.fail_every) == 0) {
                    DEBUG("Command '%s' randomly failed\n", command_name[commands[i].type]);
                    continue;
                }
            }

            if (config.max_faults > 0 && faults >= config.max_faults) {
                DEBUG("Max faults reached - skipping fault '%s'\n", command_name[commands[i].type]);
                if (log_fault)
                    print("Cannot induce fault '%s' - max faults reached\n", command_name[commands[i].type]);
                continue;
            }

            faults++;

            if (commands[i].type == SKIP) {
                DEBUG("Skip %d @ 0x%zx\n", commands[i].index, regs.rip);
                if (log_fault)
                    print("SKIP %d (RIP: 0x%zx, Instruction #%zd)\n", (int) commands[i].index,
                           (size_t) regs.rip, instruction_counter);
                regs.rip += commands[i].index;
                regs_dirty = 1;
            } else if (commands[i].type == HAVOC) {
                size_t width = effective_width(&commands[i]);
                if (commands[i].target == TARGET_REGISTER) {
                    DEBUG("Havoc %s (%zu bytes) @ 0x%zx\n", register_name(commands[i].reg), width, regs.rip);
                    unsigned long long oldval = register_read(&regs, commands[i].reg);
                    unsigned long long newval = oldval;
                    size_t mask = width_mask(width);
                    for (size_t b = 0; b < width; b++) {
                        unsigned long long byte = (unsigned long long) (rand() & 0xff);
                        newval = (newval & ~((unsigned long long) 0xff << (b * 8))) | (byte << (b * 8));
                    }
                    if (log_fault)
                        print("HAVOC %s (%zu bytes) -> 0x%llx (RIP: 0x%zx, Instruction #%zd)\n",
                              register_name(commands[i].reg), width, newval & mask, (size_t) regs.rip,
                              instruction_counter);
                    register_write(&regs, commands[i].reg, (oldval & ~mask) | (newval & mask));
                    regs_dirty = 1;
                } else {
                    DEBUG("Havoc 0x%zx (%zu bytes) @ 0x%zx\n", commands[i].destination, width, regs.rip);
                    if (log_fault)
                        print("HAVOC 0x%zx (%zu bytes) (RIP: 0x%zx, Instruction #%zd)\n",
                              commands[i].destination, width, (size_t) regs.rip, instruction_counter);
                    for (size_t b = 0; b < width; b++) {
                        if (poke_byte(pid, commands[i].destination + b, (unsigned char) (rand() & 0xff)))
                            return 1;
                    }
                }
            } else if (commands[i].type == ZERO) {
                size_t width = effective_width(&commands[i]);
                if (commands[i].target == TARGET_REGISTER) {
                    DEBUG("Zero %s (%zu bytes) @ 0x%zx\n", register_name(commands[i].reg), width, regs.rip);
                    if (log_fault)
                        print("ZERO %s (%zu bytes) (RIP: 0x%zx, Instruction #%zd)\n",
                              register_name(commands[i].reg), width, (size_t) regs.rip, instruction_counter);
                    unsigned long long val = register_read(&regs, commands[i].reg);
                    register_write(&regs, commands[i].reg, val & ~width_mask(width));
                    regs_dirty = 1;
                } else {
                    DEBUG("Zero 0x%zx (%zu bytes) @ 0x%zx\n", commands[i].destination, width, regs.rip);
                    if (log_fault)
                        print("ZERO 0x%zx (%zu bytes) (RIP: 0x%zx, Instruction #%zd)\n",
                              commands[i].destination, width, (size_t) regs.rip, instruction_counter);
                    for (size_t b = 0; b < width; b++) {
                        if (poke_byte(pid, commands[i].destination + b, 0)) return 1;
                    }
                }
            } else if (commands[i].type == SET) {
                size_t mask = 0;
                for (size_t b = 0; b < commands[i].value_len; b++)
                    mask |= (size_t) 0xff << (b * 8);
                if (commands[i].target == TARGET_REGISTER) {
                    DEBUG("Set %s <- 0x%zx (%zu bytes) @ 0x%zx\n", register_name(commands[i].reg),
                          commands[i].value, commands[i].value_len, regs.rip);
                    if (log_fault)
                        print("SET %s = 0x%zx (%zu bytes) (RIP: 0x%zx, Instruction #%zd)\n",
                              register_name(commands[i].reg), commands[i].value, commands[i].value_len,
                               (size_t) regs.rip, instruction_counter);
                    unsigned long long val = register_read(&regs, commands[i].reg);
                    register_write(&regs, commands[i].reg,
                                   (val & ~((unsigned long long) mask)) |
                                   ((unsigned long long) commands[i].value & (unsigned long long) mask));
                    regs_dirty = 1;
                } else {
                    DEBUG("Set 0x%zx <- 0x%zx (%zu bytes) @ 0x%zx\n", commands[i].destination, commands[i].value,
                          commands[i].value_len, regs.rip);
                    if (log_fault)
                        print("SET 0x%zx = 0x%zx (%zu bytes) (RIP: 0x%zx, Instruction #%zd)\n",
                              commands[i].destination, commands[i].value, commands[i].value_len,
                               (size_t) regs.rip, instruction_counter);
                    long oldval = ptrace(PTRACE_PEEKDATA, pid, commands[i].destination, 0);
                    ptrace(PTRACE_POKEDATA, pid, commands[i].destination,
                           (oldval & ~mask) | (commands[i].value & mask));
                }
            } else if (commands[i].type == BITFLIP) {
                if (commands[i].target == TARGET_REGISTER) {
                    DEBUG("Bitflip #%d -> %s @ 0x%zx\n", commands[i].index, register_name(commands[i].reg), regs.rip);
                    if (log_fault)
                        print("BITFLIP #%d -> %s (RIP: 0x%zx, Instruction #%zd)\n",
                              (int) commands[i].index, register_name(commands[i].reg), (size_t) regs.rip,
                              instruction_counter);
                    register_write(&regs, commands[i].reg,
                                   register_read(&regs, commands[i].reg) ^ (1ull << commands[i].index));
                    regs_dirty = 1;
                } else {
                    DEBUG("Bitflip #%d -> 0x%zx @ 0x%zx\n", commands[i].index, commands[i].destination, regs.rip);
                    if (log_fault)
                        print("BITFLIP #%d -> 0x%zx (RIP: 0x%zx, Instruction #%zd)\n",
                              (int) commands[i].index, commands[i].destination, (size_t) regs.rip,
                              instruction_counter);
                    unsigned long long val = (unsigned long long) ptrace(
                        PTRACE_PEEKDATA, pid, commands[i].destination, 0);
                    val ^= 1ull << commands[i].index;
                    ptrace(PTRACE_POKEDATA, pid, commands[i].destination, (long) val);
                }
            }
        }
    }

    if (regs_dirty && ptrace(PTRACE_SETREGS, pid, NULL, &regs)) {
        ERROR("Error writing registers to child process: %s\n", strerror(errno));
        return 1;
    }

    // Decrement cooldown at the end of instruction processing
    if (fault_cooldown) fault_cooldown--;

    instruction_counter++;

    if (config.timeout != 0 && (instruction_counter % 1000) == 0 && (time(NULL) - start_time > config.timeout)) {
        ERROR("Timeout of %zd seconds reached\n", config.timeout);
        return 1;
    }

    return 0;
}

// ------------------------------------------------------------------------------------------------
int singlestep(int pid) {
    int retval, status;
    retval = ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
    if (retval) {
        return retval;
    }
    waitpid(pid, &status, 0);
    return status;
}

// ------------------------------------------------------------------------------------------------
int find_section(char *binary, char *section, size_t *start, size_t *end) {
    struct stat statbuf;
    int fd = open(binary, O_RDONLY);
    if (fd == -1) {
        return 1;
    }

    fstat(fd, &statbuf);
    char *fbase = mmap(NULL, statbuf.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (fbase == MAP_FAILED) {
        return 1;
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *) fbase;
    Elf64_Shdr *sects = (Elf64_Shdr *) (fbase + ehdr->e_shoff);
    int shsize = ehdr->e_shentsize;
    int shnum = ehdr->e_shnum;
    int shstrndx = ehdr->e_shstrndx;

    Elf64_Shdr *shstrsect = &sects[shstrndx];
    char *shstrtab = fbase + shstrsect->sh_offset;

    for (int i = 0; i < shnum; i++) {
        if (!strcmp(shstrtab + sects[i].sh_name, section)) {
            *start = sects[i].sh_addr;
            *end = sects[i].sh_addr + sects[i].sh_size;
        }
    }

    close(fd);
    return 0;
}

// ------------------------------------------------------------------------------------------------
int main(int argc, char **argv) {
    pid_t pid;
    int status;

    char *debug_level_str = getenv("DEBUG");
    if (debug_level_str) {
        debug_level = atoi(debug_level_str);
    }


    if (argc < 3) {
        ERROR("Usage: %s <fault script> <binary> [<arg0> <arg1> ...]\n", argv[0]);
        exit(-1);
    }

    config.seed = time(NULL);
    char *program = argv[2];
    parse_config(program);

    if (config.no_code_fault) {
        if (find_section(program, ".text", &config.code_start, &config.code_end)) {
            ERROR("Could not find .text section in target");
            exit(-1);
        }
        DEBUG("Code section from 0x%zx to 0x%zx\n", config.code_start, config.code_end);
    }

#ifdef SYMMAP_SUPPORT
    char symmap_path[1024];
    snprintf(symmap_path, sizeof(symmap_path), "%s" SYMMAP_EXT, program);
    load_symmap(symmap_path);
#endif

    if (parse_script(argv[1])) {
        exit(-1);
    }
    DEBUG("Loaded %d commands\n", commands_count);
    char **child_args = (char **) &argv[2];

    srand(config.seed);

    pid = fork();
    if (pid == -1) {
        ERROR("Error forking: %s\n", strerror(errno));
        exit(-1);
    }
    if (pid == 0) {
        // victim application
        if (ptrace(PTRACE_TRACEME, 0, 0, 0)) {
            ERROR("Error starting tracer: %s\n", strerror(errno));
            exit(-1);
        }
        if (!config.aslr) {
            // disable aslr
            DEBUG("Disabling ASLR\n");
            personality(ADDR_NO_RANDOMIZE);
        }

        char *env[] = { NULL };

        // Drop env from target
        if (execve(program, child_args, env) == -1) {
            ERROR("Failed to start binary '%s'\n", program);
            return -1;
        }
    } else {
        // fault simulator
        waitpid(pid, &status, 0);
        show_status(status);
        start_time = time(NULL);
        while (WIFSTOPPED(status)) {
            if (ptrace_instruction_pointer(pid)) {
                break;
            }
            status = singlestep(pid);
        }
        show_status(status);
        DEBUG("Detaching\n");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        kill(pid, 2);
        usleep(1000);
        kill(pid, 9);
        free(commands);
#ifdef SYMMAP_SUPPORT
        for (int i = 0; i < sym_count; i++) free(sym_map[i].key);
        for (int i = 0; i < line_count; i++) free(line_map[i].key);
        free(sym_map);
        free(line_map);
#endif

        if (config.print_success) {
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                printf("\n\033[92mSuccessfully exploited %s!\033[0m\n", program);
            } else {
                printf("\n\033[91mFailed to exploit %s!\033[0m\n", program);
            }
        }
    }

    return 0;
}
