#include "../src/utils/parser/negotiation.c"
#include "utils/logger/logger.h"

void safe_way(struct negotiation_parser* parser) {
    uint8_t byte = 0x05;
    negotiation_paser_feed(parser, byte);
    byte = 0x02;
    negotiation_paser_feed(parser, byte);
    byte = 0x00;
    negotiation_paser_feed(parser, byte);
    byte = 0x02;
    negotiation_paser_feed(parser, byte);
}

int main(void) {

    struct negotiation_parser* parser = negotiation_parser_init();

    safe_way(parser);

    negotiation_parser_free(parser);

    return 0;
}

