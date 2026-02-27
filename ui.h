#ifndef UI_H
#define UI_H

#include <stddef.h>

#define KEY_ESC 0x1b
#define CTRL(c) ((c) & 037)

void draw_header_frame(const char *text);

void show_text_buffer(const char *title, const char *buf, size_t size);

void show_text_buffer_8bit(const char *title, const char *buf, size_t size);

#endif // UI_H
