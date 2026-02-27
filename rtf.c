#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <strings.h>
#include <stdbool.h>

#include <curses.h>

#include "rtf.h"
#include "ui.h"
#include "hex_viewer.h"

typedef struct {
    char  *name;
    char  *content;
    size_t len;
} RtfSection;

static RtfSection *rtf_sections = NULL;
static int rtf_section_count = 0;

static int hex_val(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static int find_rtf_group_end(const char *buf, size_t len, size_t start_pos) {
    if (start_pos >= len || buf[start_pos] != '{') return -1;

    int depth = 0;
    bool escape = false;

    for (size_t i = start_pos; i < len; ++i) {
        char c = buf[i];

        if (escape) {
            escape = false;
            continue;
        }

        if (c == '\\') {
            escape = true;
            continue;
        }

        if (c == '{') {
            depth++;
        } else if (c == '}') {
            depth--;
            if (depth == 0) {
                return (int)i;
            }
        }
    }

    return -1;
}

static void add_rtf_section(const char *name, const char *data, size_t len) {
    RtfSection *tmp = realloc(rtf_sections, (rtf_section_count + 1) * sizeof(RtfSection));
    if (!tmp) return;
    rtf_sections = tmp;

    RtfSection *sec = &rtf_sections[rtf_section_count];
    sec->name = NULL;
    sec->content = NULL;
    sec->len = 0;

    sec->name = strdup(name);
    sec->content = malloc(len + 1);
    if (!sec->name || !sec->content) {
        free(sec->name);
        free(sec->content);
        sec->name = NULL;
        sec->content = NULL;
        sec->len = 0;
        return;
    }

    memcpy(sec->content, data, len);
    sec->content[len] = '\0';
    sec->len = len;
    rtf_section_count++;
}


static void free_rtf_sections(void) {
    for (int i = 0; i < rtf_section_count; i++) {
        free(rtf_sections[i].name);
        free(rtf_sections[i].content);
    }
    free(rtf_sections);
    rtf_sections = NULL;
    rtf_section_count = 0;
}

typedef struct {
    const char *pattern;
    const char *baseTitle;
} RtfGroupPattern;


static unsigned char *rtf_decode_embedded_hex(const char *content,
                                              size_t len,
                                              size_t *out_len)
{
    if (!content || len == 0 || !out_len) return NULL;

    char *hex = (char *)malloc(len);
    if (!hex) return NULL;

    size_t hlen = 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)content[i];
        if (isxdigit(c)) {
            hex[hlen++] = (char)c;
        }
    }

    if (hlen < 2) {
        free(hex);
        return NULL;
    }

    unsigned char *bin = (unsigned char *)malloc(hlen / 2);
    if (!bin) {
        free(hex);
        return NULL;
    }

    size_t bi = 0;
    for (size_t i = 0; i + 1 < hlen; i += 2) {
        char hi = hex[i];
        char lo = hex[i + 1];

        int hi_val =
            (hi >= '0' && hi <= '9') ? (hi - '0') :
            (hi >= 'a' && hi <= 'f') ? (hi - 'a' + 10) :
            (hi >= 'A' && hi <= 'F') ? (hi - 'A' + 10) : -1;

        int lo_val =
            (lo >= '0' && lo <= '9') ? (lo - '0') :
            (lo >= 'a' && lo <= 'f') ? (lo - 'a' + 10) :
            (lo >= 'A' && lo <= 'F') ? (lo - 'A' + 10) : -1;

        if (hi_val < 0 || lo_val < 0) {
            free(bin);
            free(hex);
            return NULL;
        }

        bin[bi++] = (unsigned char)((hi_val << 4) | lo_val);
    }

    free(hex);

    if (bi == 0) {
        free(bin);
        return NULL;
    }

    *out_len = bi;
    return bin;
}

static void parse_rtf_sections(const char *buf, size_t len) {
    add_rtf_section("Raw RTF (whole document)", buf, len);

    RtfGroupPattern pats[] = {
        { "{\\info",        "info" },
        { "{\\fonttbl",     "fonttbl" },
        { "{\\colortbl",    "colortbl" },
        { "{\\stylesheet",  "stylesheet" },
        { "{\\*\\listtable","listtable" },
        { "{\\pict",        "picture" },
        { "{\\object",      "object" },
        { "{\\objdata",     "objectData" }
    };
    const size_t pats_count = sizeof(pats)/sizeof(pats[0]);

    for (size_t p = 0; p < pats_count; ++p) {
        const char *pattern = pats[p].pattern;
        const char *baseTitle = pats[p].baseTitle;

        const char *pos = buf;
        while (1) {
            const char *found = strstr(pos, pattern);
            if (!found) break;

            size_t start = (size_t)(found - buf);
            if (buf[start] != '{') {
                pos = found + 1;
                continue;
            }

            int end = find_rtf_group_end(buf, len, start);
            if (end < 0) break;

            size_t group_len = (size_t)(end - (int)start + 1);

            int sameCount = 0;
            for (int i = 0; i < rtf_section_count; ++i) {
                if (strncmp(rtf_sections[i].name, baseTitle, strlen(baseTitle)) == 0)
                    sameCount++;
            }

            char title[64];
            if (sameCount == 0) {
                snprintf(title, sizeof(title), "%s", baseTitle);
            } else {
                snprintf(title, sizeof(title), "%s #%d", baseTitle, sameCount + 1);
            }

            add_rtf_section(title, buf + start, group_len);

            pos = buf + end + 1;
        }
    }
}


static void sanitize_control_bytes(char *buf, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        unsigned char c = (unsigned char)buf[i];
        if (c < 0x20 && c != '\n' && c != '\r' && c != '\t') {
            buf[i] = ' ';
        }
    }
}

char *rtf_decode_hex_escapes(const char *src, size_t src_len, size_t *dst_len) {
    if (!src) return NULL;

    size_t cap = src_len + 1;
    char *dst = (char *)malloc(cap);
    if (!dst) return NULL;

    size_t i = 0;
    size_t j = 0;

    while (i < src_len) {
        char c = src[i];

        if (c == '\\') {
            if (i + 1 < src_len) {
                char c2 = src[i + 1];

                if (c2 == '\'') {
                    char Num[3];
                    size_t len = 0;

                    if (i + 2 < src_len) {
                        Num[len++] = src[i + 2];
                    }
                    if (i + 3 < src_len) {
                        Num[len++] = src[i + 3];
                    }

                    if (len == 0) {
                        if (j + 2 > cap) {
                            cap *= 2;
                            char *tmp = realloc(dst, cap);
                            if (!tmp) { free(dst); return NULL; }
                            dst = tmp;
                        }
                        dst[j++] = '\\';
                        dst[j++] = '\'';
                        i += 2;
                        continue;
                    } else if (len == 1) {
                        if (j + 3 > cap) {
                            cap *= 2;
                            char *tmp = realloc(dst, cap);
                            if (!tmp) { free(dst); return NULL; }
                            dst = tmp;
                        }
                        dst[j++] = '\\';
                        dst[j++] = '\'';
                        dst[j++] = Num[0];
                        i += 3;
                        continue;
                    } else {
                        int h1 = hex_val((unsigned char)Num[0]);
                        int h2 = hex_val((unsigned char)Num[1]);
                        if (h1 >= 0 && h2 >= 0) {
                            unsigned char b = (unsigned char)((h1 << 4) | h2);
                            if (j + 1 > cap) {
                                cap *= 2;
                                char *tmp = realloc(dst, cap);
                                if (!tmp) { free(dst); return NULL; }
                                dst = tmp;
                            }
                            dst[j++] = (char)b;
                            i += 4;
                            continue;
                        } else {
                            if (j + 4 > cap) {
                                cap *= 2;
                                char *tmp = realloc(dst, cap);
                                if (!tmp) { free(dst); return NULL; }
                                dst = tmp;
                            }
                            dst[j++] = '\\';
                            dst[j++] = '\'';
                            dst[j++] = Num[0];
                            dst[j++] = Num[1];
                            i += 4;
                            continue;
                        }
                    }
                } else {
                    if (j + 2 > cap) {
                        cap *= 2;
                        char *tmp = realloc(dst, cap);
                        if (!tmp) { free(dst); return NULL; }
                        dst = tmp;
                    }
                    dst[j++] = '\\';
                    dst[j++] = c2;
                    i += 2;
                    continue;
                }
            } else {
                if (j + 1 > cap) {
                    cap *= 2;
                    char *tmp = realloc(dst, cap);
                    if (!tmp) { free(dst); return NULL; }
                    dst = tmp;
                }
                dst[j++] = '\\';
                i++;
                continue;
            }
        } else {
            if (j + 1 > cap) {
                cap *= 2;
                char *tmp = realloc(dst, cap);
                if (!tmp) { free(dst); return NULL; }
                dst = tmp;
            }
            dst[j++] = c;
            i++;
        }
    }

    if (j + 1 > cap) {
        char *tmp = realloc(dst, j + 1);
        if (!tmp) { free(dst); return NULL; }
        dst = tmp;
    }
    dst[j] = '\0';
    if (dst_len) *dst_len = j;
    return dst;
}

static char *rtf_recode_file(const char *filename, size_t *out_size) {
    FILE *f = fopen(filename, "rb");
    if (!f) return NULL;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long fsize = ftell(f);
    if (fsize < 0) { fclose(f); return NULL; }
    rewind(f);

    char *inbuf = (char *)malloc((size_t)fsize);
    if (!inbuf) { fclose(f); return NULL; }

    size_t rd = fread(inbuf, 1, (size_t)fsize, f);
    fclose(f);
    if (rd != (size_t)fsize) {
        free(inbuf);
        return NULL;
    }

    size_t decoded_len = 0;
    char *decoded = rtf_decode_hex_escapes(inbuf, rd, &decoded_len);
    free(inbuf);

    if (!decoded) return NULL;
    if (out_size) *out_size = decoded_len;
    return decoded;
}


static void ui_draw_rtf_sections(const char *filename, int cursor, int offset) {
    erase();

    char header[256];
    snprintf(header, sizeof(header),
             "RTF logical objects in %s (ESC/q to exit, -> to view)",
             filename ? filename : "");
    draw_header_frame(header);

    const int first_row = 3;
    int max_lines = LINES - first_row;

    for (int i = 0; i < max_lines && i + offset < rtf_section_count; i++) {
        int row = first_row + i;
        if (i + offset == cursor) attron(A_REVERSE);
        mvprintw(row, 0, "%s", rtf_sections[i + offset].name);
        if (i + offset == cursor) attroff(A_REVERSE);
    }

    curs_set(0);
    refresh();
}

static void edit_rtf_sections(const char *filename) {
    int cursor = 0;
    int offset = 0;
    int ch;

    while (1) {
        ui_draw_rtf_sections(filename, cursor, offset);
        ch = getch();

        if (ch == KEY_ESC || ch == 'q') break;
        else if (ch == KEY_DOWN) {
            if (cursor < rtf_section_count - 1) {
                cursor++;
                if (cursor >= offset + (LINES - 2)) offset++;
            }
        } else if (ch == KEY_UP) {
            if (cursor > 0) {
                cursor--;
                if (cursor < offset) offset--;
            }
        } else if (ch == KEY_NPAGE) {
            cursor += (LINES - 2);
            if (cursor >= rtf_section_count) cursor = rtf_section_count - 1;
            offset = cursor - (LINES - 2) + 1;
            if (offset < 0) offset = 0;
        } else if (ch == KEY_PPAGE) {
            cursor -= (LINES - 2);
            if (cursor < 0) cursor = 0;
            offset = cursor;
        } else if (ch == KEY_RIGHT) {
            RtfSection *s = &rtf_sections[cursor];

            int is_embedded =
                (strncmp(s->name, "picture", 7) == 0) ||
                (strncmp(s->name, "object", 6) == 0);

            if (!is_embedded) {
                show_text_buffer_8bit(s->name, s->content, s->len);
            } else {
                size_t bin_len = 0;
                unsigned char *bin = rtf_decode_embedded_hex(s->content, s->len, &bin_len);

                if (bin && bin_len > 0) {
                    hex_view_buffer(bin, bin_len, s->name);
                    free(bin);
                } else {
                    show_text_buffer_8bit(s->name, s->content, s->len);
                }
            }
        }
    }
}


int is_rtf_file(const char *filename) {
    if (!filename) return 0;
    size_t len = strlen(filename);
    while (len > 0 && isspace((unsigned char)filename[len-1])) len--;
    if (len < 4) return 0;
    return strcasecmp(filename + len - 4, ".rtf") == 0;
}

void show_rtf_file(const char *filename) {
    size_t size = 0;
    char *decoded = rtf_recode_file(filename, &size);
    if (!decoded) {
        endwin();
        fprintf(stderr,"Cannot read/parse RTF file '%s'\n", filename);
        exit(1);
    }

    sanitize_control_bytes(decoded, size);

    rtf_sections = NULL;
    rtf_section_count = 0;
    parse_rtf_sections(decoded, size);

    edit_rtf_sections(filename);

    free_rtf_sections();
    free(decoded);
}
