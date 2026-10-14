#include "program.h"
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
const uint8_t *command_input;
size_t command_length;
static const cmd_t commands[] = {
    {"hash", cmd_hash}, {"sum", cmd_sum}, {"help", cmd_help}
};
// @algorithm none
ALETHEIA_TARGET const cmd_t *lookup_cmd(const char *name) {
    for (size_t i = 0; i < sizeof commands / sizeof *commands; ++i)
        if (strcmp(commands[i].name, name) == 0) return &commands[i];
    return NULL;
}
// @algorithm none
// @indirect-targets cmd_hash,cmd_sum,cmd_help
ALETHEIA_TARGET int dispatch(const char *name, int argc, char **argv) {
    const cmd_t *cmd = lookup_cmd(name);
    if (cmd == NULL) return -1;
    return cmd->handler(argc, argv);
}
// @algorithm none
ALETHEIA_TARGET int run_command(int argc, char **argv) {
    if (argc < 1) return -1;
    return dispatch(argv[0], argc, argv);
}
// @algorithm none
ALETHEIA_TARGET int cmd_hash(int argc, char **argv) {
    (void)argc; (void)argv;
    printf("%08" PRIx32 "\n", fnv1a_32_local(command_input, command_length));
    return 0;
}
// @algorithm none
ALETHEIA_TARGET int cmd_sum(int argc, char **argv) {
    (void)argc; (void)argv;
    printf("%02x\n", (unsigned)sum8(command_input, command_length));
    return 0;
}
// @algorithm none
ALETHEIA_TARGET int cmd_help(int argc, char **argv) {
    (void)argc; (void)argv;
    return puts("ok") == EOF ? -1 : 0;
}
// @algorithm fnv/fnv1a-32
ALETHEIA_TARGET uint32_t fnv1a_32_local(const uint8_t *buf, size_t len) {
    uint32_t hash = UINT32_C(0x811c9dc5);
    for (size_t i = 0; i < len; ++i) hash = (hash ^ buf[i]) * UINT32_C(0x01000193);
    return hash;
}
// @algorithm none
ALETHEIA_TARGET uint8_t sum8(const uint8_t *buf, size_t len) {
    uint8_t sum = 0;
    for (size_t i = 0; i < len; ++i) sum = (uint8_t)(sum + buf[i]);
    return sum;
}
// @algorithm none
ALETHEIA_TARGET void log_msg(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}
