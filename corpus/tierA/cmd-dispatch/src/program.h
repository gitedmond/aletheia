#ifndef PROGRAM_H
#define PROGRAM_H
#include "aletheia.h"
typedef struct cmd {
    const char *name;
    int (*handler)(int, char **);
} cmd_t;
extern const uint8_t *command_input;
extern size_t command_length;
const cmd_t *lookup_cmd(const char *name);
int dispatch(const char *name, int argc, char **argv);
int run_command(int argc, char **argv);
int cmd_hash(int argc, char **argv);
int cmd_sum(int argc, char **argv);
int cmd_help(int argc, char **argv);
uint32_t fnv1a_32_local(const uint8_t *buf, size_t len);
uint8_t sum8(const uint8_t *buf, size_t len);
void log_msg(const char *fmt, ...);
#endif
