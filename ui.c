#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <curses.h>
#include <stdbool.h>

#include "ui.h"

#define MAX_LINES 10000

static void remove_xml_content(wchar_t **lines, int line_count) {
    for (int i = 0; i < line_count; i++) {
        wchar_t *p = lines[i];
        wchar_t *dst = p;
        while (*p) {
            if (*p == L'>') {
                *dst++ = *p++;
                while (*p && *p != L'<') p++;
            } else {
                *dst++ = *p++;
            }
        }
        *dst = L'\0';
    }
}

static void remove_xml_content_char(char **lines, int line_count) {
    for (int i = 0; i < line_count; i++) {
        char *p = lines[i];
        char *dst = p;
        while (*p) {
            if (*p == '>') {
                *dst++ = *p++;
                while (*p && *p != '<') p++;
            } else {
                *dst++ = *p++;
            }
        }
        *dst = '\0';
    }
}

void draw_header_frame(const char *text) {
    int width = COLS;
    if (width < 4) return;

    int inner_width = width - 2;

    mvaddch(0, 0, ACS_ULCORNER);
    for (int x = 1; x < width - 1; ++x) {
        mvaddch(0, x, ACS_HLINE);
    }
    mvaddch(0, width - 1, ACS_URCORNER);

    mvaddch(1, 0, ACS_VLINE);
    mvaddch(1, width - 1, ACS_VLINE);

    for (int x = 1; x < width - 1; ++x) {
        mvaddch(1, x, ' ');
    }

    if (text) {
        char buf[1024];
        snprintf(buf, sizeof(buf), "%s", text);
        if (inner_width - 2 > 0)
            buf[inner_width - 2] = '\0';
        mvaddnstr(1, 2, buf, inner_width - 2);
    }

    mvaddch(2, 0, ACS_LLCORNER);
    for (int x = 1; x < width - 1; ++x) {
        mvaddch(2, x, ACS_HLINE);
    }
    mvaddch(2, width - 1, ACS_LRCORNER);
}

void show_text_buffer(const char *title, const char *buf, size_t size) {
    wchar_t *wbuf = malloc((size + 1) * sizeof(wchar_t));
    if (!wbuf) return;
    mbstowcs(wbuf, buf, size + 1);

    wchar_t **lines = malloc(MAX_LINES * sizeof(wchar_t*));
    if (!lines) { free(wbuf); return; }

    int line_count = 0;
    wchar_t *p = wbuf;

    while (*p && line_count < MAX_LINES) {
        lines[line_count++] = p;
        wchar_t *next = wcschr(p, L'\n');
        if (!next) break;
        *next = L'\0';
        p = next + 1;
    }

    wchar_t **original_lines = malloc(line_count * sizeof(wchar_t*));
    size_t  *original_lens  = malloc(line_count * sizeof(size_t));
    if (!original_lines || !original_lens) {
        free(original_lines);
        free(original_lens);
        free(lines);
        free(wbuf);
        return;
    }
    for (int i = 0; i < line_count; i++)
    {
        original_lines[i] = wcsdup(lines[i]);
        original_lens[i]  = wcslen(lines[i]);
    }

    bool tags_cleared = false;
    int top_line = 0, cursor_line = 0, cursor_col = 0, ch;

    const int first_row = 3;
    int screen_lines = LINES - first_row;

    char    filter8[256] = "";
    wchar_t wfilter[256];
    bool    filter_on = false;

    char    search8[256] = "";
    wchar_t wsearch[256];
    bool    search_on = false;

    erase();
    curs_set(1);

    do {
        char header[1024];
        snprintf(header, sizeof(header),
                 "File: %s (ESC/q: back, CTRL+t: strip tags, CTRL+f: filter, CTRL+g: search/highlight)",
                 title ? title : "");
        draw_header_frame(header);

        move(LINES-1, 0);
        clrtoeol();
        if (filter_on && filter8[0]) {
            mvprintw(LINES-1, 0, "Filter: %s", filter8);
        } else if (search_on && search8[0]) {
            mvprintw(LINES-1, 0, "Search: %s", search8);
        }

        for (int r = first_row; r < first_row + screen_lines; r++) {
            move(r, 0);
            clrtoeol();
        }

        int screen_row = 0;
        int total_lines = 0;

        for (int l = 0; l < line_count; l++) {
            wchar_t *line = lines[l];

            if (filter_on) {
                if (!wcsstr(line, wfilter)) continue;
            }

            int len = wcslen(line);
            for (int start = 0; start < len; start += COLS) {
                if (total_lines >= top_line && screen_row < screen_lines) {
                    int chunk = (start + COLS <= len) ? COLS : len - start;

                    if (search_on && wsearch[0]) {
                        int patLen = wcslen(wsearch);
                        int col = 0;
                        int i = 0;
                        while (i < chunk) {
                            int pos = start + i;
                            bool match = false;
                            if (patLen > 0 &&
                                pos + patLen <= len &&
                                wcsncmp(line + pos, wsearch, patLen) == 0) {
                                match = true;
                            }

                            if (match) {
                                attron(A_REVERSE);
                                for (int k = 0; k < patLen && i < chunk; ++k) {
                                    if (pos + k >= len) break;
                                    mvaddnwstr(screen_row + first_row, col, &line[pos + k], 1);
                                    col++;
                                    i++;
                                }
                                attroff(A_REVERSE);
                            } else {
                                mvaddnwstr(screen_row + first_row, col, &line[pos], 1);
                                col++;
                                i++;
                            }
                        }
                    } else {
                        for (int j = 0; j < chunk; j++) {
                            mvaddnwstr(screen_row + first_row, j, &line[start + j], 1);
                        }
                    }

                    screen_row++;
                }
                total_lines++;
            }
        }

        if (cursor_line + top_line >= total_lines) {
            if (total_lines > 0)
                cursor_line = total_lines - top_line - 1;
            else
                cursor_line = 0;
        }

        move(cursor_line + first_row, cursor_col % COLS);
        refresh();

        ch = getch();

        switch (ch) {
            case KEY_DOWN:
                if (cursor_line < screen_lines - 1)
                    cursor_line++;
                else
                    top_line++;
                break;
            case KEY_UP:
                if (cursor_line > 0)
                    cursor_line--;
                else if (top_line > 0)
                    top_line--;
                break;
            case KEY_NPAGE:
                top_line += (screen_lines > 1 ? screen_lines - 1 : 1);
                cursor_line = 0;
                break;
            case KEY_PPAGE:
                top_line -= (screen_lines > 1 ? screen_lines - 1 : 1);
                if (top_line < 0) top_line = 0;
                cursor_line = 0;
                break;
            case KEY_RIGHT:
                cursor_col++;
                break;
            case KEY_LEFT:
                if (cursor_col > 0) cursor_col--;
                break;
            case CTRL('t'):
                if (!tags_cleared) {
                    remove_xml_content(lines, line_count);
                    tags_cleared = true;
                } else {
                    for (int i = 0; i < line_count; i++)
                        wmemcpy(lines[i], original_lines[i], original_lens[i] + 1);
                    tags_cleared = false;
                }
                break;
            case CTRL('f'): {
                echo(); curs_set(1);
                move(LINES-1, 0);
                clrtoeol();
                mvprintw(LINES-1, 0, "Filter: ");
                getnstr(filter8, sizeof(filter8)-1);
                noecho(); curs_set(1);

                if (filter8[0]) {
                    mbstowcs(wfilter, filter8, sizeof(wfilter)/sizeof(wfilter[0]) - 1);
                    wfilter[sizeof(wfilter)/sizeof(wfilter[0]) - 1] = L'\0';
                    filter_on = true;
                    search_on = false;
                } else {
                    filter_on = false;
                }
                top_line = 0;
                cursor_line = 0;
                break;
            }
            case CTRL('g'): {
                echo(); curs_set(1);
                move(LINES-1, 0);
                clrtoeol();
                mvprintw(LINES-1, 0, "Search: ");
                getnstr(search8, sizeof(search8)-1);
                noecho(); curs_set(1);

                if (search8[0]) {
                    mbstowcs(wsearch, search8, sizeof(wsearch)/sizeof(wsearch[0]) - 1);
                    wsearch[sizeof(wsearch)/sizeof(wsearch[0]) - 1] = L'\0';
                    search_on = true;
                } else {
                    search_on = false;
                }
                top_line = 0;
                cursor_line = 0;
                break;
            }
        }

    } while (ch != KEY_ESC && ch != 'q');

    for (int i = 0; i < line_count; i++)
        free(original_lines[i]);
    free(original_lines);
    free(original_lens);
    free(lines);
    free(wbuf);
}

void show_text_buffer_8bit(const char *title, const char *buf, size_t size)
{
    if (!buf || size == 0) {
        return;
    }

    char *copy = (char *)malloc(size + 1);
    if (!copy) return;
    memcpy(copy, buf, size);
    copy[size] = '\0';

    char **lines = (char **)malloc(MAX_LINES * sizeof(char *));
    if (!lines) {
        free(copy);
        return;
    }

    int line_count = 0;
    char *p = copy;
    while (*p && line_count < MAX_LINES) {
        lines[line_count++] = p;
        char *next = strchr(p, '\n');
        if (!next) break;
        *next = '\0';
        p = next + 1;
    }

    char **original_lines = malloc(line_count * sizeof(char*));
    size_t *original_lens = NULL;

    if (!original_lines) {
        free(lines);
        free(copy);
        return;
    }

    original_lens = malloc(line_count * sizeof(size_t));
    if (!original_lens) {
        free(original_lines);
        free(lines);
        free(copy);
        return;
    }

    for (int i = 0; i < line_count; i++) {
        size_t L = strlen(lines[i]);
        original_lens[i] = L;
        original_lines[i] = malloc(L + 1);
        if (!original_lines[i]) {
            for (int k = 0; k < i; ++k) free(original_lines[k]);
            free(original_lines);
            free(original_lens);
            free(lines);
            free(copy);
            return;
        }
        memcpy(original_lines[i], lines[i], L + 1);
    }


    bool tags_cleared = false;
    int top_line = 0;
    int cursor_line = 0;
    int cursor_col = 0;
    int ch;

    const int first_row = 3;
    int screen_lines = LINES - first_row;
    if (screen_lines < 1) screen_lines = 1;

    char filter[256] = "";
    bool filter_on = false;
    char search[256] = "";
    bool search_on = false;

    erase();
    curs_set(1);

    do {
        char header[1024];
        snprintf(header, sizeof(header),
                 "File: %s (ESC/q: back, CTRL+t: strip tags, CTRL+f: filter, CTRL+g: search)",
                 title ? title : "");
        draw_header_frame(header);

        move(LINES - 1, 0);
        clrtoeol();
        if (filter_on && filter[0]) {
            mvprintw(LINES - 1, 0, "Filter: %s", filter);
        } else if (search_on && search[0]) {
            mvprintw(LINES - 1, 0, "Search: %s", search);
        }

        for (int r = first_row; r < first_row + screen_lines; r++) {
            move(r, 0);
            clrtoeol();
        }

        int screen_row = 0;
        int total_lines = 0;

        for (int l = 0; l < line_count; l++) {
            char *line = lines[l];

            if (filter_on && filter[0]) {
                if (!strstr(line, filter)) continue;
            }

            int len = (int)strlen(line);
            for (int start = 0; start < len; start += COLS) {
                if (total_lines >= top_line && screen_row < screen_lines) {
                    int chunk = (start + COLS <= len) ? COLS : (len - start);

                    if (search_on && search[0]) {
                        int patLen = (int)strlen(search);
                        int col = 0;
                        int i = 0;
                        while (i < chunk) {
                            int pos = start + i;
                            bool match = false;
                            if (patLen > 0 &&
                                pos + patLen <= len &&
                                strncmp(line + pos, search, patLen) == 0) {
                                match = true;
                            }

                            if (match) {
                                attron(A_REVERSE);
                                for (int k = 0; k < patLen && i < chunk; ++k) {
                                    if (pos + k >= len) break;
                                    mvaddnstr(first_row + screen_row, col, &line[pos + k], 1);
                                    col++;
                                    i++;
                                }
                                attroff(A_REVERSE);
                            } else {
                                mvaddnstr(first_row + screen_row, col, &line[pos], 1);
                                col++;
                                i++;
                            }
                        }
                    } else {
                        mvaddnstr(first_row + screen_row, 0, line + start, chunk);
                    }

                    screen_row++;
                }
                total_lines++;
            }
        }

        if (cursor_line + top_line >= total_lines) {
            if (total_lines > 0)
                cursor_line = total_lines - top_line - 1;
            else
                cursor_line = 0;
        }

        move(cursor_line + first_row, cursor_col % COLS);
        refresh();

        ch = getch();

        switch (ch) {
        case KEY_DOWN:
            if (cursor_line < screen_lines - 1)
                cursor_line++;
            else
                top_line++;
            break;

        case KEY_UP:
            if (cursor_line > 0)
                cursor_line--;
            else if (top_line > 0)
                top_line--;
            break;

        case KEY_NPAGE: {
            int delta = (screen_lines > 1 ? screen_lines - 1 : 1);
            top_line += delta;
            cursor_line = 0;
            break;
        }

        case KEY_PPAGE: {
            int delta = (screen_lines > 1 ? screen_lines - 1 : 1);
            if (top_line >= delta) top_line -= delta;
            else top_line = 0;
            cursor_line = 0;
            break;
        }

        case KEY_RIGHT:
            cursor_col++;
            break;

        case KEY_LEFT:
            if (cursor_col > 0) cursor_col--;
            break;

        case CTRL('t'):
            if (!tags_cleared) {
                remove_xml_content_char(lines, line_count);
                tags_cleared = true;
            } else {
                for (int i = 0; i < line_count; i++) {
                    size_t L = original_lens[i];
                    memcpy(lines[i], original_lines[i], L);
                    lines[i][L] = '\0';
                }
                tags_cleared = false;
            }
            break;


        case CTRL('f'):
            echo();
            curs_set(1);
            move(LINES - 1, 0);
            clrtoeol();
            mvprintw(LINES - 1, 0, "Filter: ");
            getnstr(filter, sizeof(filter) - 1);
            noecho();
            curs_set(1);

            if (filter[0]) {
                filter_on = true;
                search_on = false;
            } else {
                filter_on = false;
            }
            top_line = 0;
            cursor_line = 0;
            break;

        case CTRL('g'):
            echo();
            curs_set(1);
            move(LINES - 1, 0);
            clrtoeol();
            mvprintw(LINES - 1, 0, "Search: ");
            getnstr(search, sizeof(search) - 1);
            noecho();
            curs_set(1);

            if (search[0]) {
                search_on = true;
            } else {
                search_on = false;
            }
            top_line = 0;
            cursor_line = 0;
            break;

        default:
            break;
        }

    } while (ch != KEY_ESC && ch != 'q');

    for (int i = 0; i < line_count; i++)
    free(original_lines[i]);
    free(original_lines);
    free(original_lens);
    free(lines);
    free(copy);
}
