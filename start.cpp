#include <zip.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <regex>
#include <poppler-document.h>
#include <poppler-page.h>
#include <array>
#include <cctype>


void list_files(zip* za, std::vector<std::string>& files) {
    zip_int64_t num_files = zip_get_num_entries(za, 0);
    for (zip_uint64_t i = 0; i < num_files; i++) {
        const char* name = zip_get_name(za, i, 0);
        files.emplace_back(name);
        std::cout << "[" << i << "] " << name << std::endl;
    }
}

void extract_and_display(zip* za, const std::string& file_name) {
    struct zip_stat st;
    zip_stat_init(&st);
    if (zip_stat(za, file_name.c_str(), 0, &st) == 0) {
        zip_file* zf = zip_fopen(za, file_name.c_str(), 0);
        if (!zf) {
            std::cerr << "Не удалось открыть файл внутри архива.\n";
            return;
        }

        std::vector<char> buffer(st.size);
        zip_fread(zf, buffer.data(), st.size);
        zip_fclose(zf);

        std::cout << "Содержимое файла \"" << file_name << "\":" << std::endl;
        std::cout.write(buffer.data(), st.size);
        std::cout << std::endl;
    } else {
        std::cerr << "Файл не найден в архиве.\n";
    }
}



bool ends_with(const std::string& value, const std::string& ending) {
    if (ending.size() > value.size()) return false;
    return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
}
bool is_macro_file(const std::string& name) {
    return name.find("vbaProject.bin") != std::string::npos ||
           name.find("macros") != std::string::npos;
}

bool is_ole_object(const std::string& name) {
    return name.find("embeddings/") != std::string::npos ||
           name.find(".bin") != std::string::npos;
}

bool contains_external_links(const std::string& content) {
    return content.find("TargetMode=\"External\"") != std::string::npos;
}


bool contains_script_tags(const std::string& content) {
    return content.find("<script") != std::string::npos ||
           content.find("<html") != std::string::npos ||
           content.find("<form") != std::string::npos;
}

void run_security_check(zip* za, const std::vector<std::string>& files) {
    std::cout << "\n=== Анализ на вредоносное содержимое ===\n";

    bool found_macros = false, found_links = false, found_ole = false, found_script = false;

    for (const auto& name : files) {
        if (is_macro_file(name)) {
            found_macros = true;
            std::cout << "[!] Обнаружен файл с макросом: " << name << "\n";
        }
        if (is_ole_object(name)) {
            std::cout << "[!] Обнаружен OLE-объект: " << name << "\n";
            found_ole = true;
        }

        // Проверяем только xml-файлы
        if (ends_with(name, ".xml")) {
            struct zip_stat st;
            zip_stat_init(&st);
            if (zip_stat(za, name.c_str(), 0, &st) == 0) {
                zip_file* zf = zip_fopen(za, name.c_str(), 0);
                std::string xml_content;
                if (zf) {
                    std::vector<char> buffer(st.size);
                    zip_fread(zf, buffer.data(), st.size);
                    xml_content.assign(buffer.begin(), buffer.end());
                    zip_fclose(zf);

                    if (contains_external_links(xml_content)) {
                        std::cout << "[!] Внешняя ссылка найдена в: " << name << "\n";
                        found_links = true;
                    }
                    if (contains_script_tags(xml_content)) {
                        std::cout << "[!] Подозрение на внедрение HTML/JS в: " << name << "\n";
                        found_script = true;
                    }
                }
            }
        }
    }

    if (!(found_macros || found_links || found_ole || found_script)) {
        std::cout << "✓ Подозрительных признаков не обнаружено.\n";
    }
}

bool is_supported_openxml(const std::string& path) {
    return ends_with(path, ".docx") || ends_with(path, ".pptx") || ends_with(path, ".xlsx");
}

bool check_pdf_for_malicious(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Ошибка при открытии PDF.\n";
        return false;
    }

    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());

    bool found = false;
    if (content.find("/JavaScript") != std::string::npos ||
        content.find("/JS") != std::string::npos) {
        std::cout << "[!] Подозрительное содержимое найдено в PDF!\n";
        found = true;
    }

    if (!found)
        std::cout << "✓ PDF-файл не содержит подозрительных элементов.\n";

    return found;
}


bool pdf_reader(const std::string& path) {
    std::unique_ptr<poppler::document> doc(poppler::document::load_from_file(path));
    if (!doc) {
        std::cerr << "Не удалось открыть PDF-файл.\n";
        return false;
    }

    int num_pages = doc->pages();
    std::cout << "\n=== PDF загружен (страниц: " << num_pages << ") ===\n";

    if (num_pages == 0) {
        std::cout << "Файл пустой.\n";
        return true;
    }

    while (true) {
        std::cout << "\nВведите номер страницы для просмотра (1-" << num_pages << ", 0 — выход): ";
        std::string input;
        std::getline(std::cin, input);

        int page_num;
        try {
            page_num = std::stoi(input);
        } catch (...) {
            std::cerr << "Ошибка: введите число.\n";
            continue;
        }

        if (page_num == 0) break;
        if (page_num < 1 || page_num > num_pages) {
            std::cerr << "Неверный номер страницы.\n";
            continue;
        }

        std::unique_ptr<poppler::page> page(doc->create_page(page_num - 1));
        if (!page) {
            std::cerr << "Не удалось открыть страницу.\n";
            continue;
        }

        poppler::ustring text_ustr = page->text();
        poppler::byte_array text_bytes = text_ustr.to_utf8();
        std::string text(text_bytes.begin(), text_bytes.end());

        if (text.empty()) {
            std::cout << "Страница пустая или текст зашифрован.\n";
        } else {
            std::cout << "\n--- Страница " << page_num << " ---\n";
            std::cout << text << "\n";
        }
    }

    return true;
}




bool doc_reader(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        std::cerr << "Не удалось открыть DOC-файл.\n";
        return false;
    }

    // Читаем весь файл и оставляем только печатные символы + пробелы/табуляции/новые строки
    std::string buffer;
    char ch;
    while (file.get(ch)) {
        if (std::isprint(static_cast<unsigned char>(ch)) || ch == '\n' || ch == '\t' || ch == ' ') {
            buffer += ch;
        }
    }
    file.close();

    if (buffer.empty()) {
        std::cerr << "Не удалось извлечь текст из DOC-файла.\n";
        return false;
    }

    // Разбиваем на блоки фиксированного размера
    const size_t BLOCK_SIZE = 800; // регулируемый размер блока
    std::vector<std::string> blocks;
    size_t start = 0;
    while (start < buffer.size()) {
        blocks.push_back(buffer.substr(start, BLOCK_SIZE));
        start += BLOCK_SIZE;
    }

    // Интерактивный выбор блока
    std::cout << "\n=== DOC интерактивный просмотр ===\n";
    while (true) {
        std::cout << "\nВведите номер блока для просмотра (1-" << blocks.size() << ", 0 — выход): ";
        std::string input;
        std::getline(std::cin, input);

        int choice;
        try {
            choice = std::stoi(input);
        } catch (...) {
            std::cerr << "Ошибка: введите корректное число.\n";
            continue;
        }

        if (choice == 0) {
            break;
        } else if (choice < 1 || choice > blocks.size()) {
            std::cerr << "Неверный номер блока.\n";
        } else {
            std::cout << "\n--- Блок " << choice << " ---\n";
            std::cout << blocks[choice - 1] << "\n";
        }
    }

    return true;
}




int main() {
    std::string filepath;
    std::cout << "Введите путь к файлу: ";
    std::getline(std::cin, filepath);

    if (ends_with(filepath, ".pdf")) {
        //check_pdf_for_malicious(filepath);
        check_pdf_for_malicious(filepath);
        pdf_reader(filepath);
        return 0;
    }

    if (ends_with(filepath, ".doc")) {
        doc_reader(filepath);
        return 0;
    }

    if (!is_supported_openxml(filepath)) {
        std::cerr << "❌ Формат не поддерживается (только .docx/.pptx/.xlsx/.pdf)\n";
        return 1;
    }

    int err = 0;
    zip* za = zip_open(filepath.c_str(), ZIP_RDONLY, &err);
    if (!za) {
        std::cerr << "Ошибка при открытии ZIP-файла.\n";
        return 1;
    }

    std::vector<std::string> files;
    list_files(za, files);

    while (true) {
        std::cout << "\nВыберите действие:\n"
                  << "1. Показать список файлов\n"
                  << "2. Открыть файл по номеру\n"
                  << "3. Анализ на вредоносное содержимое\n"
                  << "4. Выход\n> ";

        std::string choice;
        std::getline(std::cin, choice);

        if (choice == "1") {
            files.clear();
            list_files(za, files);
        } else if (choice == "2") {
            std::cout << "Введите номер файла из списка:\n> ";
            std::string input;
            std::getline(std::cin, input);
            try {
                int index = std::stoi(input);
                if (index >= 0 && index < files.size()) {
                    extract_and_display(za, files[index]);
                } else {
                    std::cerr << "Неверный номер файла.\n";
                }
            } catch (...) {
                std::cerr << "Ошибка: введите корректное число.\n";
            }
        } else if (choice == "3") {
            run_security_check(za, files);
        } else if (choice == "4") {
            break;
        } else {
            std::cout << "Неверный выбор.\n";
        }
    }

    zip_close(za);
    return 0;
}

