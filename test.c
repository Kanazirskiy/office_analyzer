#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curses.h>
#include <signal.h>
#include <zip.h>
#include <locale.h>
#include <wchar.h>
#include <stdbool.h>
#include <ctype.h>
#include <regex.h>


/*-------------------------------------*/
#define MAX_LINES 10000
#define MAX_LINE_LEN 120
#define MAX_CMD 1024
#define MAX_LINE 1024
#define MAX_MATCHES 50000

#define KEY_ESC 0x1b
#define CTRL(c) ((c) & 037)

/*--- Глобальные переменные ---*/
static char **file_names;
static int file_count;
static int cursor;
static int offset;

/*--- Белый список ---*/
const char *whitelist[] = {
    "http://schemas.microsoft.com",
    "http://schemas.openxmlformats.org",
    "http://ns.adobe.com",
    "http://www.w3.org",
    "http://purl.org",
    "http://www.iec.ch",
    "http://dublincore.org"
};
const size_t whitelist_count = sizeof(whitelist) / sizeof(whitelist[0]);

const char *patterns[] = {
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
const size_t patterns_count = sizeof(patterns)/sizeof(patterns[0]);

/*-------------------------------------*/
/* Вспомогательные функции */
int is_whitelisted(const char *s) {
    if (!s) return 0;
    for (size_t i = 0; i < whitelist_count; ++i) {
        if (strstr(s, whitelist[i]) != NULL) return 1;
    }
    return 0;
}

static void donix(int sig) {
    signal(sig, donix);
}

/*-------------------------------------*/
/* Работа с архивом */
char *zip_read_file(zip_t *za, int index, size_t *size_out) {
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

/*-------------------------------------*/
/* UI: список файлов */
static void ui_draw_file_list(void) {
    clear();
    mvprintw(0, 0, "Files in archive (ESC/q to exit, s to open tags, -> to watch file content)");
    int max_lines = LINES - 2;

    for (int i = 0; i < max_lines && i + offset < file_count; i++) {
        if (i + offset == cursor) attron(A_REVERSE);
        mvprintw(i + 1, 0, "%s", file_names[i + offset]);
        if (i + offset == cursor) attroff(A_REVERSE);
    }
    curs_set(0);
    refresh();
}

/*-------------------------------------*/
/* Удаление содержимого между XML-тегами */
void remove_xml_content(wchar_t **lines, int line_count) {
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

/*-------------------------------------*/
/* Отображение содержимого файла */
static void show_file_contents(zip_t *za, int index) {
    size_t size;
    char *buf = zip_read_file(za, index, &size);
    if (!buf) return;

    wchar_t *wbuf = malloc((size + 1) * sizeof(wchar_t));
    if (!wbuf) { free(buf); return; }
    mbstowcs(wbuf, buf, size + 1);
    free(buf);

    wchar_t **lines = malloc(MAX_LINES * sizeof(wchar_t*));
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
    for (int i = 0; i < line_count; i++) {
        original_lines[i] = wcsdup(lines[i]);
    }

    bool tags_cleared = false;
    int top_line = 0, cursor_line = 0, cursor_col = 0, ch;
    int screen_lines = LINES - 1;

    do {
        clear();
        mvprintw(0, 0, "File: %s (ESC/q to return, CTRL+t to delete text between tags)", file_names[index]);

        int screen_row = 0;
        int total_lines = 0;
        curs_set(1);
        for (int l = 0; l < line_count; l++) {
            wchar_t *line = lines[l];
            int len = wcslen(line);
            for (int start = 0; start < len; start += COLS) {
                if (total_lines >= top_line && screen_row < screen_lines) {
                    int chunk = (start + COLS <= len) ? COLS : len - start;
                    for (int j = 0; j < chunk; j++) {
                        if (screen_row == cursor_line && j + start == cursor_col)
                            attron(A_REVERSE);
                        mvaddnwstr(screen_row + 1, j, &line[start + j], 1);
                        if (screen_row == cursor_line && j + start == cursor_col)
                            attroff(A_REVERSE);
                    }
                    screen_row++;
                }
                total_lines++;
            }
        }

        move(cursor_line + 1, cursor_col % COLS);
        refresh();
        ch = getch();

        switch(ch) {
            case KEY_DOWN: cursor_line++; if (cursor_line >= screen_lines) { cursor_line = screen_lines - 1; top_line++; } break;
            case KEY_UP: if (cursor_line > 0) cursor_line--; else if (top_line > 0) top_line--; break;
            case KEY_RIGHT: cursor_col++; break;
            case KEY_LEFT: if (cursor_col > 0) cursor_col--; break;
            case CTRL('t'):
                if (!tags_cleared) {
                    remove_xml_content(lines, line_count);
                    tags_cleared = true;
                } else {
                    for (int i = 0; i < line_count; i++) wcscpy(lines[i], original_lines[i]);
                    tags_cleared = false;
                }
                cursor_line = cursor_col = top_line = 0;
                break;
        }

    } while(ch != KEY_ESC && ch != 'q');

    for (int i = 0; i < line_count; i++) free(original_lines[i]);
    free(original_lines);
    free(lines);
    free(wbuf);
}

static void add_match(char ***matches, size_t *match_count, size_t max_matches, const char *match) {
    if (*match_count >= max_matches) return;
    (*matches)[*match_count] = strdup(match);
    if ((*matches)[*match_count]) (*match_count)++;
}

static void search_with_regex(const char *buf, size_t buf_size, const char *filename,
                              char ***matches, size_t *match_count, size_t max_matches) {
    regex_t regex[patterns_count];

    // компиляция всех regex
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
            p += end; // двигаем указатель дальше
        }
    }

    // очистка regex
    for (size_t i = 0; i < patterns_count; i++) {
        regfree(&regex[i]);
    }
}

// Проверка ключей в буфере
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

// Поиск xmlns: в буфере
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

// Поиск содержимого тегов в буфере
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

            if ((size_t)(buf+buf_size-name_start) < strlen(tagname) || strncmp(name_start, tagname, strlen(tagname)) != 0) {
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


// Отображение результатов с фильтром
static void display_matches_with_filter(char **matches, size_t match_count) {
    char filter[256] = "";
    int top_line = 0;
    int ch;

    do {
        clear();
        mvprintw(0,0,"Suspicious tags in archive (ESC/q to return, CTRL+f to filter)");

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
            case KEY_DOWN: top_line++; break;
            case KEY_UP: if(top_line>0) top_line--; break;
        }
    } while(ch != KEY_ESC && ch != 'q');
}

// Проверка ключа в строке
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

// Функция поиска тегов в PNG
static void search_png_tags_in_buffer(const char *buf, size_t buf_size, const char *filename,
                                      char ***matches, size_t *match_count, size_t max_matches) {
    if (buf_size < 8 || memcmp(buf, "\x89PNG\r\n\x1a\n", 8) != 0) return;

    size_t pos = 8;
    while (pos + 8 < buf_size) {
        uint32_t length = ((unsigned char)buf[pos] << 24) |
                          ((unsigned char)buf[pos+1] << 16) |
                          ((unsigned char)buf[pos+2] << 8) |
                          ((unsigned char)buf[pos+3]);
        if (pos + 8 + length + 4 > buf_size) break; // CRC
        char type[5] = {buf[pos+4], buf[pos+5], buf[pos+6], buf[pos+7], 0};
        const char *data = buf + pos + 8;

        if (strcmp(type, "tEXt") == 0 || strcmp(type, "iTXt") == 0) {
            // В tEXt: Keyword\0Text
            // В iTXt: Keyword\0LangTag\0TranslatedKeyword\0Text
            size_t i = 0;
            while (i < length && data[i] != '\0') i++;
            i++; // пропустить null после Keyword
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

        pos += 12 + length; // length(4) + type(4) + data + CRC(4)
    }
}


// --------------------- Основная функция ---------------------
static void show_suspicious_tags(zip_t *za) {
    char **matches = malloc(MAX_MATCHES * sizeof(char*));
    if (!matches) return;
    size_t match_count = 0;

    int file_count = zip_get_num_entries(za, 0);

    for (int index = 0; index < file_count; index++) {
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
        } else {
            search_with_regex(buf, st.size, filename, &matches, &match_count, MAX_MATCHES);
        }

        free(buf);
    }

    display_matches_with_filter(matches, match_count);

    for (size_t i = 0; i < match_count; i++) free(matches[i]);
    free(matches);
}



/*-------------------------------------*/
/* Основной цикл работы */
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


static void add_pdf_match(char ***matches, size_t *match_count, size_t max_matches,
                          const char *filename, size_t offset, const char *tag, const unsigned char *data, size_t len) {
    if (*match_count >= max_matches) return;
    char tmp[1024];
    size_t context_len = len > 80 ? 80 : len;
    char context[81];
    for (size_t i = 0; i < context_len; i++) {
        unsigned char c = data[i];
        context[i] = isprint(c) ? c : '.';
    }
    context[context_len] = '\0';
    snprintf(tmp, sizeof(tmp), "%s:%zu:%s: %s", filename, offset, tag, context);
    (*matches)[*match_count] = strdup(tmp);
    if ((*matches)[*match_count]) (*match_count)++;
}

// Поиск подозрительных тегов в PDF буфере
static void search_pdf_tags_in_buffer(const char *buf, size_t buf_size, const char *filename,
                                      char ***matches, size_t *match_count, size_t max_matches) {
    const char *pdf_keys[] = {
        "/JavaScript","/JS","/AA","/OpenAction","/Launch","/URI",
        "/EmbeddedFiles","AcroForm","XFA","RichMedia"
    };
    for (size_t k = 0; k < sizeof(pdf_keys)/sizeof(pdf_keys[0]); k++) {
        const char *key = pdf_keys[k];
        const char *pos = buf;
        size_t key_len = strlen(key);
        while ((pos = strstr(pos, key)) != NULL) {
            size_t offset = pos - buf;
            add_pdf_match(matches, match_count, max_matches, filename, offset, key, (const unsigned char*)pos, key_len + 30);
            pos += key_len;
        }
    }

    // Словари << ... >>
    size_t pos = 0;
    while (pos + 1 < buf_size) {
        if (buf[pos] == '<' && buf[pos+1] == '<') {
            size_t start = pos;
            int depth = 1;
            pos += 2;
            while (pos + 1 < buf_size && depth > 0) {
                if (buf[pos] == '<' && buf[pos+1] == '<') { depth++; pos+=2; }
                else if (buf[pos] == '>' && buf[pos+1] == '>') { depth--; pos+=2; }
                else pos++;
            }
            add_pdf_match(matches, match_count, max_matches, filename, start, "<<dictionary>>", (const unsigned char*)(buf+start), pos-start);
        } else pos++;
    }

    // Потоки stream ... endstream
    pos = 0;
    while (pos < buf_size) {
        const char *stream = "stream";
        const char *endstream = "endstream";
        size_t s_len = strlen(stream);
        size_t e_len = strlen(endstream);

        if (pos + s_len <= buf_size && memcmp(buf+pos, stream, s_len) == 0) {
            size_t start = pos;
            size_t content_start = pos + s_len;
            while (content_start < buf_size && (buf[content_start]=='\r'||buf[content_start]=='\n')) content_start++;

            size_t end_pos = content_start;
            while (end_pos + e_len <= buf_size && memcmp(buf+end_pos, endstream, e_len) != 0) end_pos++;

            add_pdf_match(matches, match_count, max_matches, filename, start, "stream", (const unsigned char*)(buf+content_start), end_pos - content_start);
            pos = end_pos + e_len;
        } else pos++;
    }
}

int is_pdf_file(const char *filename) {
    if (!filename) return 0;
    size_t len = strlen(filename);
    while (len > 0 && isspace(filename[len-1])) len--; // убираем пробелы
    if (len < 4) return 0;
    return strcasecmp(filename + len - 4, ".pdf") == 0;
}



/* Основной main */
int main(int argc, char **argv) {
    setlocale(LC_ALL, "");
    if(argc != 2) {
        fprintf(stderr,"Usage: %s filename\n",argv[0]);
        exit(1);
    }

    const char *filename = argv[1];
    const char *ext = strrchr(filename, '.');

    initscr(); refresh();
    cbreak(); noecho();
    keypad(stdscr, TRUE);
    signal(SIGINT, donix);
#ifdef SIGQUIT
    signal(SIGQUIT, donix);
#endif

    if (is_pdf_file(filename)) {
        // ---------------- PDF-режим ----------------
        FILE *f = fopen(filename, "rb");
        if (!f) {
            endwin();
            fprintf(stderr,"Cannot open PDF file '%s'\n", filename);
            exit(1);
        }
        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        rewind(f);

        char *buf = malloc(fsize + 1);
        if (!buf) { fclose(f); endwin(); fprintf(stderr,"Memory error\n"); exit(1); }
        fread(buf, 1, fsize, f);
        buf[fsize] = '\0';
        fclose(f);

        char **matches = malloc(MAX_MATCHES * sizeof(char*));
        if (!matches) { free(buf); endwin(); exit(1); }
        size_t match_count = 0;

        search_pdf_tags_in_buffer(buf, fsize, filename, &matches, &match_count, MAX_MATCHES);

        display_matches_with_filter(matches, match_count);

        for (size_t i = 0; i < match_count; i++) free(matches[i]);
        free(matches);
        free(buf);

        endwin();
        return 0;
    } else {
        // ---------------- ZIP/Docx-режим ----------------
        int err = 0;
        zip_t *za = zip_open(filename, 0, &err);
        if(!za) {
            endwin();
            fprintf(stderr,"Can't open '%s'\n",filename);
            exit(1);
        }

        file_count = zip_get_num_entries(za, 0);
        file_names = malloc(sizeof(char*) * file_count);
        for(int i = 0; i < file_count; i++)
            file_names[i] = (char*)zip_get_name(za, i, 0);

        cursor = 0; offset = 0;
        edit_files(za);

        endwin();
        zip_close(za);
        free(file_names);
        return 0;
    }
}

