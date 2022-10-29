#ifndef BUFFER_H_
#define BUFFER_H_
#include <stdlib.h>
#include <sys/types.h>

struct buffer;

// creates a new buffer with size bytes+1 of space (to include the final '\0')
struct buffer *buffer_init(size_t size);
// advance buffer start by ammount bytes. Returns the space left in buffer
size_t buffer_advance(struct buffer *buf, unsigned ammount);
// frees all buffer resources
void buffer_close(struct buffer *buf);
/* Returns the the start of the designated buffer, which can be manipulated with buffer_advance and buffer_reset.
Example:

    char *buf = buffer_get(buffer_ref);
    size_t size = buffer_get_remaining_size(buffer_ref);
    read(fd, buf, size);

--- or ----

    write(
        fd,
        buffer_get(buffer_ref),
        buffer_get_remaining_size(buffer_ref)
        );
*/
char *buffer_get(struct buffer *buf);
// resets buffer start to the beginning of buffer
void buffer_reset(struct buffer *buf);
// resets buffer and empties its contents
void buffer_clear(struct buffer *buf);
// returns the total size of the buffer, not including the final '\0'
size_t buffer_get_max_size(struct buffer *buf);
// returns the remaining size to write on the buffer, not including the final '\0'
size_t buffer_get_remaining_size(struct buffer *buf);
#endif