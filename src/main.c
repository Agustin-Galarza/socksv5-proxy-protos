#include<stdio.h>
#include"includes/printer.h"
#define do_nothing(X) _Generic( (X), int: do_nothing_i, char**: do_nothing_ss, default: do_nothing_ss )(X)

void do_nothing_i(int param) {
    param = 2;
}

void do_nothing_ss(char** param) {
    param = NULL;
}

int main(int argc, char** argv) {
    do_nothing(argc);
    do_nothing(argv);

    print_something();

    printf("Hello World!");

    return 0;
}