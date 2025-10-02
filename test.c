#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curses.h>
#include <fcntl.h>
#include <signal.h>
#include <ctype.h>
#include <zip.h>
#include <locale.h>
#include <wchar.h>
#include <regex.h>
#include <stdbool.h>
#include <unistd.h>


#define MAX_LINES 10000
#define MAX_LINE_LEN 120
#define MAX_CMD 1024
#define MAX_LINE 1024

/*-------------------------------------*/
#define KEY_ESC 0x1b
#define CTRL(c) ((c) & 037)


/*--- Глобальные переменные ---*/
static char **file_names;  // массив строк с именами файлов
static int file_count;     // количество файлов
static int cursor;         // текущая позиция курсора
static int offset;         // смещение для прокрутки

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
int is_whitelisted(const char *s) {
    if (!s) return 0;
    for (size_t i = 0; i < whitelist_count; ++i) {
        if (strstr(s, whitelist[i]) != NULL) return 1;
    }
    return 0;
}

/*--- Обработка сигнала Ctrl-C и Ctrl-Break ---*/
static void donix(int sig) {
    signal(sig, donix);
}

/*--- Вывод списка файлов на экран ---*/
static void disp_files(void) {
    clear();
    mvprintw(0, 0, "Files in archive (ESC/q to exit)");
    int max_lines = LINES - 2;  // оставляем строку для заголовка

    for(int i = 0; i < max_lines && i + offset < file_count; i++) {
        if(i + offset == cursor) attron(A_REVERSE);
        mvprintw(i + 1, 0, "%s", file_names[i + offset]);
        if(i + offset == cursor) attroff(A_REVERSE);
    }
    curs_set(0);
    refresh();

}

void print_char_safe(int y, int x, unsigned char *buf, int i) {
    unsigned char c = buf[i];
    if (c >= 0x20) mvaddch(y, x, c);
    else mvaddch(y, x, '.');
}

static void show_suspicious_tags(zip_t *za) {
    #define MAX_MATCHES 50000
    char **matches = malloc(MAX_MATCHES * sizeof(char*));
    size_t match_count = 0;

    if (!matches) return;

    void add_match(const char *match) {
        if (match_count >= MAX_MATCHES) return;
        matches[match_count] = strdup(match);
        if (matches[match_count]) match_count++;
    }

    int file_count = zip_get_num_entries(za, 0);

    // Проходим по всем файлам
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

        // --- 1. обычные паттерны ---
        const char *keys[] = {"name=", "Target=", "Type=", "creator", "http://", "uri="};
        for (size_t k = 0; k < sizeof(keys)/sizeof(keys[0]); k++) {
            const char *key = keys[k];
            const char *pos = buf;
            size_t key_len = strlen(key);

            while ((pos = strstr(pos, key)) != NULL) {
                size_t offset = pos - buf;
                const char *start = pos;
                const char *val_start = pos + key_len;

                while (val_start < buf + st.size && (*val_start==' '||*val_start=='\n'||*val_start=='\r'||*val_start=='\t')) val_start++;
                if (val_start < buf + st.size && *val_start == '=') {
                    val_start++;
                    while (val_start < buf + st.size && (*val_start==' '||*val_start=='\n'||*val_start=='\r'||*val_start=='\t')) val_start++;
                }
                if (val_start < buf + st.size && *val_start == '"') {
                    const char *vstart = val_start + 1;
                    const char *vend = vstart;
                    while (vend < buf + st.size && *vend != '"') vend++;
                    if (vend < buf + st.size) {
                        vend++;
                        size_t match_len = vend - start;
                        char *match = malloc(match_len + 1);
                        if (match) {
                            memcpy(match, start, match_len);
                            match[match_len] = '\0';
                            if (!is_whitelisted(match)) {
                                char tmp[match_len + 100];
                                snprintf(tmp, sizeof(tmp), "%s:%zu:%s", filename, offset, match);
                                add_match(tmp);
                            }
                            free(match);
                        }
                        pos = vend;
                        continue;
                    } else break;
                } else pos += key_len;
            }
        }

        // --- 2. search_xmlns_prefixed_in_file ---
        const char *pos = buf;
        const char *key = "xmlns:";
        while ((pos = strstr(pos, key)) != NULL) {
            size_t offset = pos - buf;
            const char *start = pos;
            const char *p = pos + strlen(key);
            const char *pref_end = p;
            while (pref_end < buf + st.size && *pref_end != '=' && *pref_end != ' ' && *pref_end != '\t' &&
                   *pref_end != '\n' && *pref_end != '\r' && *pref_end != '>' && *pref_end != '/') pref_end++;
            if (pref_end == p) { pos = p; continue; }
            const char *eq = pref_end;
            while (eq < buf + st.size && (*eq==' '||*eq=='\t'||*eq=='\n'||*eq=='\r')) eq++;
            if (eq >= buf + st.size || *eq != '=') { pos = pref_end; continue; }
            const char *val_start = eq + 1;
            while (val_start < buf + st.size && (*val_start==' '||*val_start=='\t'||*val_start=='\n'||*val_start=='\r')) val_start++;
            if (val_start >= buf + st.size || *val_start != '"') { pos = eq+1; continue; }
            const char *v = val_start + 1;
            while (v < buf + st.size && *v != '"') v++;
            if (v >= buf + st.size) break;
            const char *val_end = v + 1;
            size_t match_len = val_end - start;
            char *match = malloc(match_len + 1);
            if (match) {
                memcpy(match, start, match_len);
                match[match_len] = '\0';
                if (!is_whitelisted(match)) {
                    char tmp[match_len + 100];
                    snprintf(tmp, sizeof(tmp), "%s:%zu:%s", filename, offset, match);
                    add_match(tmp);
                }
                free(match);
            }
            pos = val_end;
        }

        // --- 3. search_xml_tag_content_in_file для "creator","title","subject" ---
        const char *tags[] = {"creator","title","subject","keywords","description","lastModifiedBy","revision","created","modified"};
        for (size_t t = 0; t < sizeof(tags)/sizeof(tags[0]); t++) {
            const char *tagname = tags[t];
            const char *p = buf;
            while (p < buf + st.size) {
                const char *start = strchr(p,'<');
                if (!start) break;
                if (*(start+1)=='/') { p = start+1; continue; }
                const char *name_start = start+1;
                const char *colon = strchr(name_start, ':');
                if (colon && colon < buf+st.size) name_start = colon+1;
                if ((size_t)(buf+st.size-name_start) < strlen(tagname) || strncmp(name_start, tagname, strlen(tagname)) != 0) {
                    p = start+1; continue;
                }
                const char *gt = strchr(name_start+strlen(tagname), '>');
                if (!gt || gt >= buf+st.size) { p = start+1; continue; }
                const char *content_start = gt+1;
                const char *content_end = content_start;
                while (content_end < buf+st.size && *content_end != '<') content_end++;
                size_t match_len = content_end - start;
                if (match_len > 0) {
                    char *match = malloc(match_len+1);
                    if (match) {
                        memcpy(match,start,match_len);
                        match[match_len]='\0';
                        char tmp[match_len + 100];
                        snprintf(tmp,sizeof(tmp), "%s:%zu:%s", filename, (size_t)(start-buf), match);
                        add_match(tmp);
                        free(match);
                    }
                }
                p = content_end;
            }
        }

        free(buf);
    }

    // --- ncurses вывод с фильтром ---
    char filter[256]="";
    int top_line=0;
    int screen_lines=LINES-2;  // последняя строка для фильтра
    int ch;

    do {
        clear();
        mvprintw(0,0,"Suspicious tags in archive (ESC/q to return, / to filter)");

        int screen_row=1, displayed=0;

        for (size_t i=0;i<match_count;i++) {
            if (filter[0] && !strstr(matches[i],filter)) continue;
            if (displayed >= (size_t)top_line) {
                if (screen_row > screen_lines) break;
                mvprintw(screen_row,0,"%s",matches[i]);
                screen_row++;
            }
            displayed++;
        }

        if (filter[0]) {
            mvprintw(LINES-1,0,"Filter: %s",filter);
        }

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
            case KEY_UP: if (top_line>0) top_line--; break;
        }

    } while(ch != KEY_ESC && ch != 'q');

    for (size_t i=0;i<match_count;i++) free(matches[i]);
    free(matches);
}







void remove_xml_content(wchar_t **lines, int line_count) {
    for (int i = 0; i < line_count; i++) {
        wchar_t *p = lines[i];
        wchar_t *dst = p;  // куда писать символы
        while (*p) {
            if (*p == L'>') {
                // копируем '>'
                *dst++ = *p++;
                // пропускаем всё до следующего '<'
                while (*p && *p != L'<') p++;
            } else {
                *dst++ = *p++;
            }
        }
        *dst = L'\0'; // завершение строки
    }
}

static void show_file_contents(zip_t *za, int index) {
    zip_stat_t st;
    if (zip_stat_index(za, index, 0, &st) != 0) return;

    zip_file_t *zf = zip_fopen_index(za, index, 0);
    if (!zf) return;

    char *buf = malloc(st.size + 1);
    if (!buf) { zip_fclose(zf); return; }

    zip_fread(zf, buf, st.size);
    buf[st.size] = '\0';
    zip_fclose(zf);

    wchar_t *wbuf = malloc((st.size + 1) * sizeof(wchar_t));
    if (!wbuf) { free(buf); return; }
    mbstowcs(wbuf, buf, st.size + 1);
    free(buf);
    // Разбиваем на строки по \n
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

    wchar_t **original_lines = malloc(MAX_LINES * sizeof(wchar_t*));
    for (int i = 0; i < line_count; i++) {
        original_lines[i] = wcsdup(lines[i]);
    }
    bool tags_cleared = false;

    int top_line = 0;      // верхняя видимая строка
    int cursor_line = 0;   // вертикальная позиция курсора на экране
    int cursor_col = 0;    // горизонтальная позиция курсора
    int ch;

    int screen_lines = LINES - 1;

    do {
        clear();
        mvprintw(0, 0, "File: %s (ESC/q to return)", file_names[index]);

        // Отображение текста с учетом ширины экрана
        int screen_row = 0;
        int total_lines = 0; // общее количество экранных строк
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
            case KEY_DOWN:
                cursor_line++;
                if (cursor_line >= screen_lines) {
                    cursor_line = screen_lines - 1;
                    top_line++;
                }
                break;
            case KEY_UP:
                if (cursor_line > 0)
                    cursor_line--;
                else if (top_line > 0)
                    top_line--;
                break;
            case KEY_RIGHT:
                cursor_col++;
                break;
            case KEY_LEFT:
                if (cursor_col > 0)
                    cursor_col--;
                break;
            case CTRL('t'):  // Ctrl-T — переключение между очищенным и оригинальным
                if (!tags_cleared) {
                    remove_xml_content(lines, line_count); // удаляем текст между тегами
                    tags_cleared = true;
                } else {
                    for (int i = 0; i < line_count; i++) {
                        wcscpy(lines[i], original_lines[i]); // восстанавливаем
                    }
                    tags_cleared = false;
                }
                cursor_line = cursor_col = top_line = 0; // сброс курсора в начало
                break;
        }

    } while(ch != KEY_ESC && ch != 'q');

    for (int i = 0; i < line_count; i++)
        free(original_lines[i]);
    free(original_lines);
    free(lines);
    free(wbuf);
}

/*--- Обработка перемещения курсора и прокрутки ---*/
static void edit_files(zip_t *za) {
    int ch;
    while(1) {
        disp_files();
        int ch = getch();

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

/*--- Основной цикл обработки команд ---*/
static void command(zip_t *za) {
    cursor = 0;
    offset = 0;
    edit_files(za);
}


/*--- Функция main ---*/
int main(int argc, char **argv) {
    setlocale(LC_ALL, "");
    if(argc != 2) {
        fprintf(stderr,"Usage: %s filename.docx\n",argv[0]);
        exit(1);
    }

    // Открываем zip-архив
    int err = 0;
    zip_t *za = zip_open(argv[1], 0, &err);
    if(!za) {
        fprintf(stderr,"Can't open '%s'\n",argv[1]);
        exit(1);
    }

    // Считываем имена файлов
    file_count = zip_get_num_entries(za, 0);
    file_names = malloc(sizeof(char*) * file_count);
    for(int i = 0; i < file_count; i++)
        file_names[i] = (char*)zip_get_name(za, i, 0);

    // Инициализация ncurses
    initscr(); refresh();
    cbreak(); noecho();
    keypad(stdscr, TRUE);
    signal(SIGINT, donix);
#ifdef SIGQUIT
    signal(SIGQUIT, donix);
#endif

    // Основной цикл
    command(za);

    // Завершение работы
    endwin();
    zip_close(za);
    free(file_names);
    return 0;
}
