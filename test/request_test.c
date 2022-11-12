#include "parser/request.h"
#include "utils/buffer.h"
#include <assert.h>

int main(void) {
    struct request_parser* parser = request_parser_init();
    assert(parser != NULL);

    struct buffer* buffer;
    uint8_t data[1024] = { '0x05', '0x02', '0x00', '0x01', '0x7f', '0x00', '0x00', '0x01', '0x00', '0x50' };

    buffer_init(buffer, 1024, data);

    // Parseo
    enum request_results result = request_parser_consume(buffer, parser);

    assert(result == REQUEST_PARSER_FINISH_OK);
    assert(parser->version == 0x05);
    assert(parser->cmd == 0x02);
    assert(parser->rsv == 0x00);
    assert(parser->address_type == 0x01);
    assert(parser->address_length == 4);
    assert(parser->port_length == 2);
    assert(parser->address[0] == 0x7f);
    assert(parser->address[1] == 0x00);
    assert(parser->address[2] == 0x00);
    assert(parser->address[3] == 0x01);
    assert(parser->port[0] == 0x00);
    assert(parser->port[1] == 0x50);


    return 0;
}