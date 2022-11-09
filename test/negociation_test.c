#include "parser/negociation.h"
#include "logger/logger.h"

void safe_way(struct negociation_parser* parser) {
    uint8_t byte = 0x05;
    negociation_paser_feed(&parser, byte);
    byte = 0x02;
    negociation_paser_feed(&parser, byte);
    byte = 0x00;
    negociation_paser_feed(&parser, byte);
    byte = 0x02;
    negociation_paser_feed(&parser, byte);
}

int main(void) {

    struct negociation_parser parser;
    negociation_parser_init(&parser);

    safe_way(&parser);

    return 0;
}

