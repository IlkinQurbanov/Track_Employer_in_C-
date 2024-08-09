#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wininet.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <ctime>
#include <Lmcons.h>
#include <string>
#include <array>
#include <memory>
#include <gdiplus.h>
#include <VersionHelpers.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "gdiplus.lib")

// Helper function to convert wstring to string
std::string to_string(const std::wstring& wstr) {
    std::string str(wstr.begin(), wstr.end());
    return str;
}

std::string escapeJson(const std::string& str) {
    std::string escaped;
    for (char c : str) {
        switch (c) {
        case '"':  escaped += "\\\""; break;
        case '\\': escaped += "\\\\"; break;
        case '\b': escaped += "\\b";  break;
        case '\f': escaped += "\\f";  break;
        case '\n': escaped += "\\n";  break;
        case '\r': escaped += "\\r";  break;
        case '\t': escaped += "\\t";  break;
        default:   escaped += c;      break;
        }
    }
    return escaped;
}

std::string createJson(const std::string& startTime, const std::string& endTime, const std::string& duration, const std::string& systemInfo, const std::string& publicIP, const std::string& activeConnections) {
    std::ostringstream json;
    json << "{\n";
    json << "  \"Session Start Time\": \"" << escapeJson(startTime) << "\",\n";
    json << "  \"Session End Time\": \"" << escapeJson(endTime) << "\",\n";
    json << "  \"Session Duration\": \"" << escapeJson(duration) << "\",\n";
    json << "  \"System Information\": \"" << escapeJson(systemInfo) << "\",\n";
    json << "  \"Public IP Address\": \"" << escapeJson(publicIP) << "\",\n";
    json << "  \"Active Network Connections\": \"" << escapeJson(activeConnections) << "\"\n";
    json << "}\n";
    return json.str();
}

std::string createText(const std::string& startTime, const std::string& endTime, const std::string& duration, const std::string& systemInfo, const std::string& publicIP, const std::string& activeConnections) {
    std::ostringstream text;
    text << "Session Start Time: " << startTime << std::endl;
    text << "Session End Time: " << endTime << std::endl;
    text << "Session Duration: " << duration << std::endl;
    text << "System Information: " << systemInfo << std::endl;
    text << "Public IP Address: " << publicIP << std::endl;
    text << "Active Network Connections: " << std::endl << activeConnections << std::endl;
    text << "-------------------------------" << std::endl;
    return text.str();
}

void writeToFile(const std::wstring& filePath, const std::string& content) {
    std::ofstream outFile(to_string(filePath).c_str(), std::ios::trunc);
    if (!outFile) {
        std::wcerr << L"Failed to open file: " << filePath << std::endl;
        return;
    }
    outFile << content;
    if (!outFile.good()) {
        std::wcerr << L"Failed to write to file: " << filePath << std::endl;
    }
    outFile.close();
    std::wcout << L"File saved: " << filePath << std::endl; // Debugging line
}

std::string getCurrentTime() {
    std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm localTime;
    localtime_s(&localTime, &now);

    char buffer[26];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &localTime);
    return std::string(buffer);
}

std::string getOSVersion() {
    typedef void (WINAPI* RtlGetVersionPtr)(OSVERSIONINFOEXW*);
    OSVERSIONINFOEXW osInfo = { 0 };

    HMODULE hModule = GetModuleHandleW(L"ntdll.dll");
    if (hModule) {
        RtlGetVersionPtr rtlGetVersion = (RtlGetVersionPtr)GetProcAddress(hModule, "RtlGetVersion");

        if (rtlGetVersion) {
            osInfo.dwOSVersionInfoSize = sizeof(osInfo);
            rtlGetVersion(&osInfo);
        }
    }

    std::ostringstream osVersion;
    osVersion << "Windows " << osInfo.dwMajorVersion << "." << osInfo.dwMinorVersion << " (Build " << osInfo.dwBuildNumber << ")";
    return osVersion.str();
}

std::string getSystemInfo() {
    char computerName[UNLEN + 1];
    DWORD size = UNLEN + 1;
    if (GetComputerNameA(computerName, &size)) {
        std::string sysInfo = "Computer Name: " + std::string(computerName);

        char userName[UNLEN + 1];
        DWORD userSize = UNLEN + 1;
        if (GetUserNameA(userName, &userSize)) {
            sysInfo += " | User Name: " + std::string(userName);
        }
        else {
            sysInfo += " | User Name: Unknown";
        }

        sysInfo += " | OS: " + getOSVersion();

        return sysInfo;
    }
    else {
        return "Failed to get system information";
    }
}

std::string getPublicIPAddress() {
    HINTERNET hInternet = InternetOpen(L"Public IP Address Lookup", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet == NULL) {
        return "Failed to open internet session.";
    }

    HINTERNET hConnect = InternetOpenUrl(hInternet, L"http://api.ipify.org", NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (hConnect == NULL) {
        InternetCloseHandle(hInternet);
        return "Failed to connect to IP lookup service.";
    }

    char buffer[128];
    DWORD bytesRead;
    std::string ipAddress;

    if (InternetReadFile(hConnect, buffer, sizeof(buffer) - 1, &bytesRead)) {
        buffer[bytesRead] = '\0';
        ipAddress = buffer;
    }
    else {
        ipAddress = "Failed to read response.";
    }

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    return ipAddress;
}

std::string getActiveNetworkConnections() {
    std::string result;
    std::array<char, 4096> buffer;
    std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen("netstat -an", "r"), _pclose);

    if (!pipe) {
        result = "Failed to run netstat command.";
        return result;
    }

    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe.get()) != nullptr) {
        result += buffer.data();
    }

    return result;
}

int GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
    UINT num = 0;
    UINT size = 0;

    Gdiplus::ImageCodecInfo* pImageCodecInfo = NULL;
    Gdiplus::GetImageEncodersSize(&num, &size);
    if (size == 0) {
        return -1;
    }

    pImageCodecInfo = (Gdiplus::ImageCodecInfo*)(malloc(size));
    if (pImageCodecInfo == NULL) {
        return -1;
    }

    Gdiplus::GetImageEncoders(num, size, pImageCodecInfo);

    for (UINT j = 0; j < num; ++j) {
        if (wcscmp(pImageCodecInfo[j].MimeType, format) == 0) {
            *pClsid = pImageCodecInfo[j].Clsid;
            free(pImageCodecInfo);
            return j;
        }
    }

    free(pImageCodecInfo);
    return -1;
}

void captureScreenshot(const std::wstring& filename) {
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

    HDC screenDC = GetDC(NULL);
    int screenWidth = GetDeviceCaps(screenDC, HORZRES);
    int screenHeight = GetDeviceCaps(screenDC, VERTRES);

    HDC memDC = CreateCompatibleDC(screenDC);
    HBITMAP hBitmap = CreateCompatibleBitmap(screenDC, screenWidth, screenHeight);
    SelectObject(memDC, hBitmap);

    BitBlt(memDC, 0, 0, screenWidth, screenHeight, screenDC, 0, 0, SRCCOPY);

    Gdiplus::Bitmap bitmap(hBitmap, NULL);
    CLSID pngClsid;
    GetEncoderClsid(L"image/png", &pngClsid);
    bitmap.Save(filename.c_str(), &pngClsid, NULL);

    DeleteObject(hBitmap);
    DeleteDC(memDC);
    ReleaseDC(NULL, screenDC);
    Gdiplus::GdiplusShutdown(gdiplusToken);
}

std::wstring getDirectoryFromPath(const std::wstring& filePath) {
    size_t pos = filePath.find_last_of(L"\\/");
    if (pos == std::wstring::npos) {
        return L"."; // No directory, return current directory
    }
    return filePath.substr(0, pos);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    std::string startTime = getCurrentTime();

    std::string systemInfo = getSystemInfo();
    std::string publicIP = getPublicIPAddress();
    std::string activeConnections = getActiveNetworkConnections();

    std::wstring screenshotFilename = L"screenshot.png";
    captureScreenshot(screenshotFilename);

    // Extract directory path from screenshot filename
    std::wstring screenshotDir = getDirectoryFromPath(screenshotFilename);
    if (screenshotDir.empty()) {
        screenshotDir = L".";  // Default to current directory if empty
    }
    std::wcout << L"Screenshot Directory: " << screenshotDir << std::endl; // Debugging line

    std::string endTime = getCurrentTime();
    std::chrono::system_clock::time_point start = std::chrono::system_clock::now();
    std::chrono::system_clock::time_point end = std::chrono::system_clock::now();
    std::chrono::duration<double> elapsed_seconds = end - start;
    std::string duration = std::to_string(elapsed_seconds.count()) + "s";

    std::string jsonOutput = createJson(startTime, endTime, duration, systemInfo, publicIP, activeConnections);
    std::wstring jsonFilename = screenshotDir + L"\\output.json";
    std::wcout << L"Saving JSON to: " << jsonFilename << std::endl; // Debugging line
    writeToFile(jsonFilename, jsonOutput);

    std::string textOutput = createText(startTime, endTime, duration, systemInfo, publicIP, activeConnections);
    std::wstring textFilename = screenshotDir + L"\\output.txt";
    std::wcout << L"Saving Text to: " << textFilename << std::endl; // Debugging line
    writeToFile(textFilename, textOutput);

    return 0;
}
