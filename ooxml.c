#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <regex.h>

#include <zip.h>
#include <curses.h>

#include "ooxml.h"
#include "ui.h"
#include "hex_viewer.h"

#define MAX_MATCHES 50000

static char **file_names;
static int file_count;
static int cursor;
static int offset;


static const char *whitelist[] = {
    "http://schemas.microsoft.com",
    "http://schemas.openxmlformats.org",
    "http://ns.adobe.com",
    "http://www.w3.org",
    "http:/http/purl.org",
    "http://www.iec.ch",
    "http://dublincore.org"
};
static const size_t whitelist_count = sizeof(whitelist) / sizeof(whitelist[0]);

static const char *patterns[] = {
    "name=\"[^\"]+\"",
    "Target=\"[^\"]+",
    "Type=\"[^\"]+",
    "creator",
    "descr=\"[^\"]+\"",
    "http://[^\"]+",
    "[A-Za-z]:\\\\[^\\\"]+",
    "uri=\"[^\"]+",
    "xmlns:[^=]+=\"[^\"]+",
    "xmlns=\"[^\"]+",

    "<dc:title[^<]*</",
    "<dc:subject[^<]*</",
    "<dc:creator[^<]*</",
    "<cp:keywords[^<]*</",
    "<dc:description[^<]*</",
    "<cp:lastModifiedBy[^<]*</",
    "<cp:revision[^<]*</",
    "<cp:lastPrinted[^<]*</",
    "<dc:language[^<]*</",
    ":created[^<]+</dct",
    ":modified[^<]+</dct"
};
static const size_t patterns_count = sizeof(patterns)/sizeof(patterns[0]);

static int is_whitelisted(const char *s) {
    if (!s) return 0;
    for (size_t i = 0; i < whitelist_count; ++i) {
        if (strstr(s, whitelist[i]) != NULL) return 1;
    }
    return 0;
}

static char *zip_read_file(zip_t *za, int index, size_t *size_out) {
    zip_stat_t st;
    if (zip_stat_index(za, index, 0, &st) != 0) return NULL;

    zip_file_t *zf = zip_fopen_index(za, index, 0);
    if (!zf) return NULL;

    char *buf = malloc(st.size + 1);
    if (!buf) { zip_fclose(zf); return NULL; }

    zip_fread(zf, buf, st.size);
    buf[st.size] = '\0';
    zip_fclose(zf);

    if (size_out) *size_out = st.size;
    return buf;
}

static void ui_draw_file_list(void) {
    erase();

    char header[256];
    snprintf(header, sizeof(header),
             "Files in archive (ESC/q to exit, s to open tags, -> to watch file content)");
    draw_header_frame(header);

    const int first_row = 3;
    int max_lines = LINES - first_row;

    for (int i = 0; i < max_lines && i + offset < file_count; i++) {
        int row = first_row + i;
        if (i + offset == cursor) attron(A_REVERSE);
        mvprintw(row, 0, "%s", file_names[i + offset]);
        if (i + offset == cursor) attroff(A_REVERSE);
    }

    curs_set(0);
    refresh();
}


static int is_text_like_name(const char *name) {
    if (!name) return 0;

    const char *ext = strrchr(name, '.');
    if (ext) {
        ext++; // пропускаем точку
        if (!strcasecmp(ext, "xml")) return 1;
        if (!strcasecmp(ext, "rels")) return 1;
        if (!strcasecmp(ext, "txt")) return 1;
        if (!strcasecmp(ext, "cfg")) return 1;
        if (!strcasecmp(ext, "ini")) return 1;
        if (!strcasecmp(ext, "csv")) return 1;
        if (!strcasecmp(ext, "rdf")) return 1;
        if (!strcasecmp(ext, "vml")) return 1;
    }

    // файл без расширения "mimetype" в ODF – тоже текст
    if (!strcasecmp(name, "mimetype")) return 1;

    return 0;
}

static void show_file_contents(zip_t *za, int index) {
    size_t size;
    char *buf = zip_read_file(za, index, &size);
    if (!buf) return;

    const char *name = file_names[index];

    if (is_text_like_name(name)) {
        // текстовые части (XML, rels, mimetype и т.п.)
        show_text_buffer(name, buf, size);
    } else {
        // всё остальное считаем бинарным и открываем в hex
        hex_view_buffer((const unsigned char *)buf, size, name);
    }

    free(buf);
}



static void add_match(char ***matches, size_t *match_count, size_t max_matches, const char *match) {
    if (*match_count >= max_matches) return;
    (*matches)[*match_count] = strdup(match);
    if ((*matches)[*match_count]) (*match_count)++;
}

static void search_with_regex(const char *buf, size_t buf_size, const char *filename,
                              char ***matches, size_t *match_count, size_t max_matches) {
    regex_t regex[patterns_count];

    for (size_t i = 0; i < patterns_count; i++) {
        if (regcomp(&regex[i], patterns[i], REG_EXTENDED)) {
            fprintf(stderr, "Failed to compile regex: %s\n", patterns[i]);
            return;
        }
    }

    for (size_t i = 0; i < patterns_count; i++) {
        const char *p = buf;
        regmatch_t pmatch[1];

        while (regexec(&regex[i], p, 1, pmatch, 0) == 0) {
            size_t start = pmatch[0].rm_so;
            size_t end   = pmatch[0].rm_eo;
            if (end <= start) break;

            size_t offset = (p - buf) + start;
            size_t match_len = end - start;

            char *match = malloc(match_len + 1);
            if (!match) break;
            memcpy(match, p + start, match_len);
            match[match_len] = '\0';

            if (!is_whitelisted(match)) {
                char tmp[match_len + 100];
                snprintf(tmp, sizeof(tmp), "%s:%zu:%s", filename, offset, match);
                add_match(matches, match_count, max_matches, tmp);
            }

            free(match);
            p += end;
        }
    }

    for (size_t i = 0; i < patterns_count; i++) {
        regfree(&regex[i]);
    }
}


static void search_keys_in_buffer(const char *buf, size_t buf_size, const char *filename,
                                  char ***matches, size_t *match_count, size_t max_matches) {
    const char *keys[] = {"name=", "Target=", "Type=", "creator", "http://", "uri="};
    for (size_t k = 0; k < sizeof(keys)/sizeof(keys[0]); k++) {
        const char *key = keys[k];
        const char *pos = buf;
        size_t key_len = strlen(key);

        while ((pos = strstr(pos, key)) != NULL) {
            size_t offset = pos - buf;
            const char *start = pos;
            const char *val_start = pos + key_len;

            while (val_start < buf + buf_size && (*val_start==' '||*val_start=='\n'||*val_start=='\r'||*val_start=='\t')) val_start++;
            if (val_start < buf + buf_size && *val_start == '=') {
                val_start++;
                while (val_start < buf + buf_size && (*val_start==' '||*val_start=='\n'||*val_start=='\r'||*val_start=='\t')) val_start++;
            }

            if (val_start < buf + buf_size && *val_start == '"') {
                const char *vstart = val_start + 1;
                const char *vend = vstart;
                while (vend < buf + buf_size && *vend != '"') vend++;
                if (vend >= buf + buf_size) break;

                vend++;
                size_t match_len = vend - start;
                char *match = malloc(match_len + 1);
                if (match) {
                    memcpy(match, start, match_len);
                    match[match_len] = '\0';
                    if (!is_whitelisted(match)) {
                        char tmp[match_len + 100];
                        snprintf(tmp, sizeof(tmp), "%s:%zu:%s", filename, offset, match);
                        add_match(matches, match_count, MAX_MATCHES, tmp);
                    }
                    free(match);
                }
                pos = vend;
            } else pos += key_len;
        }
    }
}

static void search_xmlns_in_buffer(const char *buf, size_t buf_size, const char *filename,
                                   char ***matches, size_t *match_count, size_t max_matches) {
    const char *key = "xmlns:";
    const char *pos = buf;

    while ((pos = strstr(pos, key)) != NULL) {
        size_t offset = pos - buf;
        const char *start = pos;
        const char *p = pos + strlen(key);
        const char *pref_end = p;

        while (pref_end < buf + buf_size && *pref_end != '=' && *pref_end != ' ' && *pref_end != '\t' &&
               *pref_end != '\n' && *pref_end != '\r' && *pref_end != '>' && *pref_end != '/') pref_end++;

        if (pref_end == p) { pos = p; continue; }

        const char *eq = pref_end;
        while (eq < buf + buf_size && (*eq==' '||*eq=='\t'||*eq=='\n'||*eq=='\r')) eq++;
        if (eq >= buf + buf_size || *eq != '=') { pos = pref_end; continue; }

        const char *val_start = eq + 1;
        while (val_start < buf + buf_size && (*val_start==' '||*val_start=='\t'||*val_start=='\n'||*val_start=='\r')) val_start++;
        if (val_start >= buf + buf_size || *val_start != '"') { pos = eq + 1; continue; }

        const char *v = val_start + 1;
        while (v < buf + buf_size && *v != '"') v++;
        if (v >= buf + buf_size) break;

        const char *val_end = v + 1;
        size_t match_len = val_end - start;
        char *match = malloc(match_len + 1);
        if (match) {
            memcpy(match, start, match_len);
            match[match_len] = '\0';
            if (!is_whitelisted(match)) {
                char tmp[match_len + 100];
                snprintf(tmp, sizeof(tmp), "%s:%zu:%s", filename, offset, match);
                add_match(matches, match_count, MAX_MATCHES, tmp);
            }
            free(match);
        }
        pos = val_end;
    }
}

static void search_xml_tags_in_buffer(const char *buf, size_t buf_size, const char *filename,
                                      char ***matches, size_t *match_count, size_t max_matches) {
    const char *tags[] = {"creator","title","subject","keywords","description","lastModifiedBy","revision","created","modified"};

    for (size_t t = 0; t < sizeof(tags)/sizeof(tags[0]); t++) {
        const char *tagname = tags[t];
        const char *p = buf;
        while (p < buf + buf_size) {
            const char *start = strchr(p,'<');
            if (!start) break;
            if (*(start+1)=='/') { p = start+1; continue; }

            const char *name_start = start+1;
            const char *colon = strchr(name_start, ':');
            if (colon && colon < buf+buf_size) name_start = colon+1;

            if ((size_t)(buf+buf_size-name_start) < strlen(tagname) ||
                strncmp(name_start, tagname, strlen(tagname)) != 0) {
                p = start+1; continue;
            }

            const char *gt = strchr(name_start+strlen(tagname), '>');
            if (!gt || gt >= buf+buf_size) { p = start+1; continue; }

            const char *content_start = gt+1;
            const char *content_end = content_start;
            while (content_end < buf+buf_size && *content_end != '<') content_end++;

            size_t match_len = content_end - start;
            if (match_len > 0) {
                char *match = malloc(match_len+1);
                if (match) {
                    memcpy(match,start,match_len);
                    match[match_len]='\0';
                    char tmp[match_len + 100];
                    snprintf(tmp,sizeof(tmp), "%s:%zu:%s", filename, (size_t)(start-buf), match);
                    add_match(matches, match_count, max_matches, tmp);
                    free(match);
                }
            }
            p = content_end;
        }
    }
}


static int png_match_key(const char *s) {
    const char *keys[] = {
        "descr", "name=", "C://name", "http://", "creator",
        "xmlns=", "Target=", "Type=", "uri="
    };
    for (size_t i = 0; i < sizeof(keys)/sizeof(keys[0]); i++) {
        if (strstr(s, keys[i])) return 1;
    }
    return 0;
}

static void search_png_tags_in_buffer(const char *buf, size_t buf_size, const char *filename,
                                      char ***matches, size_t *match_count, size_t max_matches) {
    if (buf_size < 8 || memcmp(buf, "\x89PNG\r\n\x1a\n", 8) != 0) return;

    size_t pos = 8;
    while (pos + 8 < buf_size) {
        uint32_t length = ((unsigned char)buf[pos] << 24) |
                          ((unsigned char)buf[pos+1] << 16) |
                          ((unsigned char)buf[pos+2] << 8) |
                          ((unsigned char)buf[pos+3]);
        if (pos + 8 + length + 4 > buf_size) break;
        char type[5] = {buf[pos+4], buf[pos+5], buf[pos+6], buf[pos+7], 0};
        const char *data = buf + pos + 8;

        if (strcmp(type, "tEXt") == 0 || strcmp(type, "iTXt") == 0) {
            size_t i = 0;
            while (i < length && data[i] != '\0') i++;
            i++;
            if (i >= length) { pos += 12 + length; continue; }

            const char *text_start = data + i;
            size_t text_len = length - i;
            char *chunk_text = malloc(text_len + 1);
            if (!chunk_text) { pos += 12 + length; continue; }
            memcpy(chunk_text, text_start, text_len);
            chunk_text[text_len] = '\0';

            if (png_match_key(chunk_text)) {
                char tmp[text_len + 100];
                snprintf(tmp, sizeof(tmp), "%s:PNG:%s", filename, chunk_text);
                if (*match_count < max_matches) {
                    (*matches)[*match_count] = strdup(tmp);
                    if ((*matches)[*match_count]) (*match_count)++;
                }
            }
            free(chunk_text);
        }

        pos += 12 + length;
    }
}


static void display_matches_with_filter(char **matches, size_t match_count) {
    char filter[256] = "";
    int top_line = 0;
    int ch;

    do {
        curs_set(0);
        erase();
        mvprintw(0,0,"Suspicious tags in archive (ESC/q to return, CTRL+f to filter)");
        size_t visible_count = 0;
        for (size_t i = 0; i < match_count; i++) {
            if (filter[0] && !strstr(matches[i], filter)) continue;
            visible_count++;
        }

        if ((size_t)top_line > visible_count - 1) top_line = visible_count > 0 ? visible_count - 1 : 0;

        int screen_row=1, displayed=0;
        for (size_t i=0;i<match_count;i++) {
            if (filter[0] && !strstr(matches[i],filter)) continue;
            if (displayed >= (size_t)top_line) {
                if (screen_row > LINES-2) break;
                mvprintw(screen_row,0,"%s",matches[i]);
                screen_row++;
            }
            displayed++;
        }

        if (filter[0]) mvprintw(LINES-1,0,"Filter: %s",filter);
        refresh();
        ch = getch();

        switch(ch) {
            case CTRL('f'):
                echo(); curs_set(1);
                mvprintw(LINES-1,0,"Filter: ");
                getnstr(filter,sizeof(filter)-1);
                noecho(); curs_set(0);
                top_line=0;
                break;
            case KEY_DOWN:
                if ((size_t)(top_line + (LINES-2)) < visible_count) top_line++;
                break;
            case KEY_UP: if(top_line>0) top_line--; break;
        }
    } while(ch != KEY_ESC && ch != 'q');
}


static void show_suspicious_tags(zip_t *za) {
    char **matches = malloc(MAX_MATCHES * sizeof(char*));
    if (!matches) return;
    size_t match_count = 0;

    int file_count_local = zip_get_num_entries(za, 0);

    for (int index = 0; index < file_count_local; index++) {
        zip_stat_t st;
        if (zip_stat_index(za, index, 0, &st) != 0) continue;

        zip_file_t *zf = zip_fopen_index(za, index, 0);
        if (!zf) continue;

        char *buf = malloc(st.size + 1);
        if (!buf) { zip_fclose(zf); continue; }
        zip_fread(zf, buf, st.size);
        buf[st.size] = '\0';
        zip_fclose(zf);

        const char *filename = zip_get_name(za, index, 0);
        const char *ext = strrchr(filename, '.');

        if (ext && (strcasecmp(ext,".png")==0)) {
            search_png_tags_in_buffer(buf, st.size, filename, &matches, &match_count, MAX_MATCHES);
        } else {
            search_with_regex(buf, st.size, filename, &matches, &match_count, MAX_MATCHES);
            search_keys_in_buffer(buf, st.size, filename, &matches, &match_count, MAX_MATCHES);
            search_xmlns_in_buffer(buf, st.size, filename, &matches, &match_count, MAX_MATCHES);
            search_xml_tags_in_buffer(buf, st.size, filename, &matches, &match_count, MAX_MATCHES);
        }

        free(buf);
    }

    display_matches_with_filter(matches, match_count);

    for (size_t i = 0; i < match_count; i++) free(matches[i]);
    free(matches);
}


static void edit_files(zip_t *za) {
    int ch;
    while(1) {
        ui_draw_file_list();
        ch = getch();

        if(ch == KEY_ESC || ch == 'q') break;
        else if(ch == KEY_DOWN) {
            if(cursor < file_count - 1) {
                cursor++;
                if(cursor >= offset + (LINES - 2)) offset++;
            }
        }
        else if(ch == KEY_UP) {
            if(cursor > 0) {
                cursor--;
                if(cursor < offset) offset--;
            }
        }
        else if(ch == KEY_NPAGE) {
            cursor += (LINES - 2);
            if(cursor >= file_count) cursor = file_count - 1;
            offset = cursor - (LINES - 2) + 1;
            if(offset < 0) offset = 0;
        }
        else if(ch == KEY_PPAGE) {
            cursor -= (LINES - 2);
            if(cursor < 0) cursor = 0;
            offset = cursor;
        }
        else if(ch == KEY_RIGHT) {
            show_file_contents(za, cursor);
        }
        else if(ch == 's') {
            show_suspicious_tags(za);
        }
    }
}


void ooxml_run(const char *filename) {
    int err = 0;
    zip_t *za = zip_open(filename, 0, &err);
    if(!za) {
        endwin();
        fprintf(stderr,"Can't open '%s' as ZIP/OOXML archive\n",filename);
        exit(1);
    }

    file_count = zip_get_num_entries(za, 0);
    file_names = malloc(sizeof(char*) * file_count);
    for(int i = 0; i < file_count; i++)
        file_names[i] = (char*)zip_get_name(za, i, 0);

    cursor = 0;
    offset = 0;
    edit_files(za);

    zip_close(za);
    free(file_names);
}
