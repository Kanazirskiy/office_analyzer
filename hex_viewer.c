#include <curses.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

#include "hex_viewer.h"
#include "ui.h"


#define HEX_BYTES_PER_ROW 16
#define HEX_ROWS_JUMP 64

static bool match_at_pos(const unsigned char *data, size_t size,
                         size_t pos,
                         const char *search, size_t search_len)
{
    if (!search || search_len == 0) return false;

    if (pos + search_len <= size) {
        if (memcmp(data + pos, search, search_len) == 0) {
            return true;
        }
    }

    if (pos + search_len * 2 <= size) {
        bool ok = true;
        for (size_t k = 0; k < search_len; ++k) {
            unsigned char c0 = data[pos + 2 * k];
            unsigned char c1 = data[pos + 2 * k + 1];
            if (c0 != (unsigned char)search[k] || c1 != 0x00) {
                ok = false;
                break;
            }
        }
        if (ok) return true;
    }

    return false;
}

static bool index_in_match(const unsigned char *data, size_t size,
                           size_t idx,
                           const char *search, size_t search_len)
{
    if (!search || search_len == 0 || idx >= size) return false;

    size_t max_span = (search_len * 2 > search_len ? search_len * 2 : search_len);

    size_t start_min = (idx >= (max_span - 1)) ? idx - (max_span - 1) : 0;
    size_t start_max = idx;

    for (size_t s = start_min; s <= start_max; ++s) {
        if (match_at_pos(data, size, s, search, search_len)) {
            if (s + search_len <= size && idx >= s && idx < s + search_len)
                return true;
            if (s + search_len * 2 <= size && idx >= s && idx < s + search_len * 2)
                return true;
        }
    }

    return false;
}

void hex_view_buffer(const unsigned char *data, size_t size, const char *title)
{
    if (!data || size == 0) {
        return;
    }

    size_t offset = 0;
    int ch;
    const int header_rows = 3;
    int screen_rows;

    char  search[256] = "";
    size_t search_len = 0;
    bool  search_on = false;

    while (1) {
        erase();

        char header[256];
        snprintf(header, sizeof(header),
                 "Hex view: %s (ESC/q: back, Up/Down/PgUp/PgDn: scroll, CTRL+f: search)",
                 title ? title : "");
        draw_header_frame(header);

        move(LINES - 1, 0);
        clrtoeol();
        if (search_on && search_len > 0) {
            mvprintw(LINES - 1, 0, "Search (ASCII): %s", search);
        }

        screen_rows = LINES - header_rows - 1;
        if (screen_rows < 1) screen_rows = 1;

        for (int row = 0; row < screen_rows; ++row) {
            size_t base = offset + (size_t)row * HEX_BYTES_PER_ROW;
            if (base >= size) break;

            mvprintw(header_rows + row, 0, "%08zx  ", base);

            int col = 10;
            for (int j = 0; j < HEX_BYTES_PER_ROW; ++j) {
                size_t idx = base + j;
                if (idx < size) {
                    bool in_match = (search_on && search_len > 0) ?
                        index_in_match(data, size, idx, search, search_len) : false;

                    if (in_match) attron(A_REVERSE);
                    mvprintw(header_rows + row, col, "%02X", data[idx] & 0xFF);
                    if (in_match) attroff(A_REVERSE);

                    col += 3;
                } else {
                    mvprintw(header_rows + row, col, "  ");
                    col += 3;
                }
            }

            col += 1;
            for (int j = 0; j < HEX_BYTES_PER_ROW; ++j) {
                size_t idx = base + j;
                if (idx < size) {
                    unsigned char c = data[idx];
                    bool in_match = (search_on && search_len > 0) ?
                        index_in_match(data, size, idx, search, search_len) : false;

                    if (in_match) attron(A_REVERSE);
                    if (c >= 0x20 && c <= 0x7E) {
                        mvaddch(header_rows + row, col + j, c);
                    } else {
                        mvaddch(header_rows + row, col + j, '.');
                    }
                    if (in_match) attroff(A_REVERSE);
                } else {
                    mvaddch(header_rows + row, col + j, ' ');
                }
            }
        }

        refresh();
        ch = getch();

        switch (ch) {
        case KEY_UP:
            if (offset >= HEX_BYTES_PER_ROW)
                offset -= HEX_BYTES_PER_ROW;
            else
                offset = 0;
            break;

        case KEY_DOWN:
            if (offset + HEX_BYTES_PER_ROW < size)
                offset += HEX_BYTES_PER_ROW;
            break;

        case KEY_PPAGE: {
            size_t jump = (size_t)HEX_ROWS_JUMP * HEX_BYTES_PER_ROW;
            if (offset >= jump)
                offset -= jump;
            else
                offset = 0;
            break;
        }

        case KEY_NPAGE: {
            size_t jump = (size_t)HEX_ROWS_JUMP * HEX_BYTES_PER_ROW;
            if (offset + jump < size)
                offset += jump;
            else if (size > jump)
                offset = size - jump;
            break;
        }

        case CTRL('f'): {
            echo();
            curs_set(1);
            move(LINES - 1, 0);
            clrtoeol();
            mvprintw(LINES - 1, 0, "Search (ASCII): ");
            getnstr(search, sizeof(search) - 1);
            noecho();
            curs_set(0);

            search_len = strlen(search);
            if (search_len > 0) {
                search_on = true;

                bool found = false;
                size_t pos = 0;
                for (pos = 0; pos < size; ++pos) {
                    if (match_at_pos(data, size, pos, search, search_len)) {
                        found = true;
                        break;
                    }
                }

                if (found) {
                    offset = (pos / HEX_BYTES_PER_ROW) * HEX_BYTES_PER_ROW;
                } else {
                    search_on = false;
                }
            } else {
                search_on = false;
            }
            break;
        }

        case 'q':
        case 'Q':
        case 0x1B:
            return;

        default:
            break;
        }
    }
}



