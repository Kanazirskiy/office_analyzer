#include <podofo/podofo.h>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <locale>
#include <codecvt>

using namespace PoDoFo;
using namespace std;

struct SuspiciousEntry {
    PdfObject* object;
    string description;
};

// Преобразование UTF-8 в wstring
static wstring utf8_to_wstring(const string& str) {
    wstring_convert<codecvt_utf8<wchar_t>, wchar_t> conv;
    return conv.from_bytes(str);
}

// Вывод форматированного текста (ширина в символах)
void printFormatted(const wstring& text) {
    const size_t width = 80;
    wistringstream iss(text);
    wstring word;
    wstring line;
    size_t lineLen = 0;
    while (iss >> word) {
        size_t wlen = word.length();
        if (line.empty()) {
            line = word;
            lineLen = wlen;
        } else if (lineLen + 1 + wlen > width) {
            wcout << L"    " << line << L"\n";
            line = word;
            lineLen = wlen;
        } else {
            line += L' ' + word;
            lineLen += 1 + wlen;
        }
    }
    if (!line.empty()) {
        wcout << L"    " << line << L"\n";
    }
}

// Извлечение и форматированный вывод текста через PdfContentsTokenizer
void extractText(PdfMemDocument& doc) {
    int pageCount = doc.GetPageCount();
    wcout << L"\n=== PDF Content (Pages: " << pageCount << L") ===\n";
    for (int i = 0; i < pageCount; ++i) {
        PdfPage* page = doc.GetPage(i);
        if (!page) continue;

        wcout << L"\n--- Page " << (i+1) << L" ---\n";
        PdfContentsTokenizer tokenizer(page);
        EPdfContentsType type;
        const char* keyword = nullptr;
        PdfVariant var;
        vector<PdfVariant> stack;
        wstring pageText;

        while (tokenizer.ReadNext(type, keyword, var)) {
            if (type == ePdfContentsType_Variant) {
                stack.push_back(var);
            } else if (type == ePdfContentsType_Keyword) {
                if ((strcmp(keyword, "Tj") == 0 || strcmp(keyword, "TJ") == 0) && !stack.empty()) {
                    if (stack.back().IsString()) {
                        const PdfString& pdfStr = stack.back().GetString();
                        wstring wtext;

                        if (pdfStr.IsUnicode()) {
                            std::string utf16be = pdfStr.GetStringUtf16();
                            std::wstring_convert<std::codecvt_utf16<wchar_t, 0x10ffff, std::big_endian>> conv;
                            wtext = conv.from_bytes(utf16be);
                        } else {
                            // fallback: treat as Latin1/Windows-1251 and convert to wstring (unsafe for Russian!)
                            std::string raw = pdfStr.GetString();
                            wtext = wstring_convert<codecvt_utf8<wchar_t>>().from_bytes(raw); // may still fail
                        }

                        pageText += wtext + L" ";
                    } else if (stack.back().IsArray()) {
                        auto arr = stack.back().GetArray();
                        for (auto& elem : arr) {
                            if (elem.IsString()) {
                                const PdfString& pdfStr = elem.GetString();
                                wstring wtext;

                                if (pdfStr.IsUnicode()) {
                                    std::string utf16be = pdfStr.GetStringUtf16();
                                    std::wstring_convert<std::codecvt_utf16<wchar_t, 0x10ffff, std::big_endian>> conv;
                                    wtext = conv.from_bytes(utf16be);
                                } else {
                                    std::string raw = pdfStr.GetString();
                                    wtext = wstring_convert<codecvt_utf8<wchar_t>>().from_bytes(raw);
                                }

                                pageText += wtext + L" ";
                            }
                        }
                    }
                    pageText += L"\n";
                }
                stack.clear();
            }
        }

        printFormatted(pageText);
        wcout << L"---------------------------------------\n";
    }
}


// Сканирование структуры документа на подозрительные элементы
void scanObjects(PdfMemDocument& doc, vector<SuspiciousEntry>& findings) {
    auto objects = doc.GetObjects();
    for (auto obj : objects) {
        if (!obj || !obj->IsDictionary()) continue;
        PdfDictionary& dict = obj->GetDictionary();
        if (dict.HasKey(PdfName("JS")) || dict.HasKey(PdfName("JavaScript")))
            findings.push_back({ obj, "JavaScript action detected" });
        if (dict.HasKey(PdfName("OpenAction")) || dict.HasKey(PdfName("AA")))
            findings.push_back({ obj, "OpenAction or AA entry detected" });
        if (dict.HasKey(PdfName("Launch")))
            findings.push_back({ obj, "Launch action detected" });
        if (dict.HasKey(PdfName("Names"))) {
            PdfObject* namesObj = dict.GetKey(PdfName("Names"));
            if (namesObj && namesObj->IsDictionary()) {
                PdfDictionary& namesDict = namesObj->GetDictionary();
                if (namesDict.HasKey(PdfName("EmbeddedFiles")))
                    findings.push_back({ obj, "EmbeddedFiles entry detected" });
            }
        }
    }
}

// Вывод результатов анализа
void printAnalysis(const vector<SuspiciousEntry>& findings) {
    cout << "\n=== Malicious Content Analysis ===\n";
    if (findings.empty()) {
        cout << "No suspicious entries found." << endl;
    } else {
        cout << "Found " << findings.size() << " suspicious entries:" << endl;
        int idx = 1;
        for (auto& entry : findings) {
            cout << "  " << idx++ << ". Object #" << entry.object->Reference().ToString()
                 << ": " << entry.description << endl;
        }
    }
    cout << "=== End of Analysis ===" << endl;
}

int main(int argc, char* argv[]) {
    // Установка локали для правильного вывода UTF-8
    locale::global(locale(""));
    wcout.imbue(locale());

    if (argc != 2) {
        cerr << "Usage: " << argv[0] << " <file.pdf>" << endl;
        return 1;
    }
    string filename = argv[1];
    PdfMemDocument document;
    try {
        document.Load(filename.c_str());
    } catch (PdfError& e) {
        cerr << "Error loading PDF: " << e.GetError() << endl;
        return 1;
    }

    extractText(document);
    vector<SuspiciousEntry> findings;
    scanObjects(document, findings);
    printAnalysis(findings);

    return 0;
}
