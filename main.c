#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <zip.h>

#include <curses.h>

#include "ui.h"
#include "rtf.h"
#include "ooxml.h"
#include "hex_viewer.h"

static void donix(int sig) {
    signal(sig, donix);
}

static void ui_error_pause(const char *filename, const char *msg) {
    erase();
    draw_header_frame("Error");
    mvprintw(5, 2, "File: %s", filename ? filename : "(null)");
    mvprintw(7, 2, "%s", msg ? msg : "Unknown error");
    mvprintw(9, 2, "Press any key to continue...");
    refresh();
    getch();
}

static void analyze_one_file(const char *filename) {
    if (!filename || filename[0] == '\0') {
        ui_error_pause("(empty)", "Empty filename");
        return;
    }

    if (is_rtf_file(filename)) {
        show_rtf_file(filename);
        return;
    }

    int err = 0;
    zip_t *za = zip_open(filename, ZIP_RDONLY, &err);
    if (za) {
        zip_close(za);
        ooxml_run(filename);
        return;
    }

    FILE *f = fopen(filename, "rb");
    if (!f) {
        char buf[512];
        snprintf(buf, sizeof(buf), "Cannot open file (errno=%d: %s)", errno, strerror(errno));
        ui_error_pause(filename, buf);
        return;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        ui_error_pause(filename, "Cannot seek file");
        return;
    }

    long fsize = ftell(f);
    if (fsize <= 0) {
        fclose(f);
        ui_error_pause(filename, "File is empty or ftell() error");
        return;
    }

    rewind(f);

    unsigned char *buf = (unsigned char *)malloc((size_t)fsize);
    if (!buf) {
        fclose(f);
        ui_error_pause(filename, "Memory allocation error");
        return;
    }

    size_t rd = fread(buf, 1, (size_t)fsize, f);
    fclose(f);

    if (rd != (size_t)fsize) {
        free(buf);
        ui_error_pause(filename, "Error reading file");
        return;
    }

    hex_view_buffer(buf, (size_t)fsize, filename);
    free(buf);
}

int main(int argc, char **argv) {
    setlocale(LC_ALL, "");

    if (argc < 2) {
        fprintf(stderr, "Usage: %s file1 [file2 ...]\n", argv[0]);
        return 1;
    }

    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    refresh();

    signal(SIGINT, donix);
#ifdef SIGQUIT
    signal(SIGQUIT, donix);
#endif

    for (int i = 1; i < argc; i++) {
        analyze_one_file(argv[i]);
    }

    endwin();
    return 0;
}
