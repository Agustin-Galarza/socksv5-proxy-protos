#ifndef BUFFER_H_
#define BUFFER_H_
#include <stdlib.h>
#include <sys/types.h>

struct buffer;

// creates a new buffer with size bytes+1 of space (to include the final '\0')
struct buffer *buffer_init_old(size_t size);
/**
 * @brief Marks that ammount chars have been read from the buffer, so the next time that buffer_get_to_read is called it returns the next char to read.
 *
 * @return The remaining size to read from the buffer
 */
size_t buffer_mark_read(struct buffer *buf, unsigned ammount);
/**
 * @brief Marks that ammount chars have been written into the buffer, so the next time that buffer_get_to_write is called it returns the next position to write.
 *
 * @return The remaining size to write to the buffer
 */
size_t buffer_mark_written(struct buffer *buf, unsigned ammount);
// frees all buffer resources
void buffer_close(struct buffer *buf);
/**
 * Returns the buffer in the next position to start reading from. This position
Example:

    char *buf = buffer_get_to_read(buffer_ref);
    size_t size = buffer_get_remaining_size(buffer_ref);
    int read_chars = read(fd, buf, size);
    buffer_mark_read(buf, read_chars);
*/
char *buffer_get_to_read(struct buffer *buf);
/**
 * Returns the buffer in the next position to start writing from
 * Example:
 * int written_chars =
 * write(
        fd,
        buffer_read(buffer_ref),
        buffer_get_remaining_size(buffer_ref)
        );
    buffer_mark_written(buf, written_chars);
 */
char *buffer_get_to_write(struct buffer *buf);
// Returns the buffer from the start
char *buffer_get_all(struct buffer *buf);
// resets buffer and empties its contents
void buffer_clear(struct buffer *buf);
// sets the buffer to be read from the beginning
void buffer_reset_read(struct buffer *buf);
// returns the total size of the buffer, not including the final '\0'
size_t buffer_get_max_size(struct buffer *buf);
// returns the remaining size to read from the buffer, not including the final '\0'
size_t buffer_get_remaining_read_size(struct buffer *buf);
// returns the remaining size to write into the buffer, not including the final '\0'
size_t buffer_get_remaining_write_size(struct buffer *buf);
#endif