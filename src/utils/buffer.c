#include "utils/buffer.h"

struct buffer
{
    char *data;
    size_t start;
    size_t size;
};

struct buffer *buffer_init(size_t size)
{
    struct buffer *buf = malloc(sizeof(struct buffer));
    buf->data = malloc(size + 1);
    buf->start = 0;
    buf->size = size;
    buf->data[buf->size] = '\0';
    buf->data[0] = '\0';
    return buf;
}

inline size_t buffer_advance(struct buffer *buf, unsigned ammount)
{
    buf->start += ammount;
    if (buf->start > buf->size)
    {
        buf->start = buf->size;
    }
    return buffer_get_remaining_size(buf);
}
inline char *buffer_get_data(struct buffer *buf)
{
    return buf->data + buf->start;
}
inline void buffer_reset(struct buffer *buf)
{
    buf->start = 0;
}
inline void buffer_clear(struct buffer *buf)
{
    buffer_reset(buf);
    buf->data[0] = '\0';
}
inline size_t buffer_get_max_size(struct buffer *buf)
{
    return buf->size;
}
inline size_t buffer_get_remaining_size(struct buffer *buf)
{
    return buf->size - buf->start;
}
inline void buffer_close(struct buffer *buf)
{
    free(buf->data);
    free(buf);
}