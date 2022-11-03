#include "utils/buffer_old.h"

struct buffer
{
    char *data;
    size_t chars_read;
    size_t chars_written;
    size_t size;
};

struct buffer *buffer_init_old(size_t size)
{
    struct buffer *buf = (struct buffer *)malloc(sizeof(struct buffer));
    buf->data = (char *)malloc(size + 1);
    buf->chars_read = 0;
    buf->chars_written = 0;
    buf->size = size;
    buf->data[buf->size] = '\0';
    buf->data[0] = '\0';
    return buf;
}

size_t buffer_mark_written(struct buffer *buf, unsigned ammount)
{
    buf->chars_written += ammount;
    return buffer_get_remaining_write_size(buf);
}

size_t buffer_mark_read(struct buffer *buf, unsigned ammount)
{
    buf->chars_read += ammount;
    if (buf->chars_read > buf->size)
    {
        buf->chars_read = buf->size;
    }
    return buffer_get_remaining_read_size(buf);
}
inline char *buffer_get_to_read(struct buffer *buf)
{
    return buf->data + buf->chars_read;
}
inline char *buffer_get_to_write(struct buffer *buf)
{
    return buf->data + buf->chars_written;
}
inline void buffer_reset_read(struct buffer *buf)
{
    buf->chars_read = 0;
}
inline void buffer_clear(struct buffer *buf)
{
    buf->data[0] = '\0';
    buf->chars_read = 0;
    buf->chars_written = 0;
}
inline size_t buffer_get_max_size(struct buffer *buf)
{
    return buf->size;
}
inline size_t buffer_get_remaining_read_size(struct buffer *buf)
{
    return buf->chars_written - buf->chars_read;
}
inline size_t buffer_get_remaining_write_size(struct buffer *buf)
{
    return buf->size - buf->chars_written;
}
inline void buffer_close(struct buffer *buf)
{
    free(buf->data);
    free(buf);
}