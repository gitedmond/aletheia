#include "program.h"
#include <stdlib.h>
// @algorithm none
// @category control.main
int main(int argc, char **argv) {
    if (argc > 3) { log_msg("%s\n", "usage: <in>"); return 1; }
    uint8_t *input;
    size_t len;
    if (read_input(argc == 3 ? argv[2] : NULL, &input, &len) != 0) {
        log_msg("%s\n", "error"); return 1;
    }
    command_input = input;
    command_length = len;
    char *default_args[] = {"hash", NULL};
    int status = argc == 1 ? run_command(1, default_args) : run_command(argc - 1, argv + 1);
    command_input = NULL;
    command_length = 0;
    free(input);
    if (status != 0) { log_msg("%s\n", "error"); return 1; }
    return 0;
}
