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

void writeJsonToFile(const std::string& filePath, const std::string& json) {
    std::ofstream outFile(filePath, std::ios::trunc); // Open file in truncate mode to overwrite existing content
    if (!outFile) {
        std::cerr << "Failed to open JSON file for writing." << std::endl;
        return;
    }
    outFile << json;
    outFile.close();
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

void writeTextToFile(const std::string& filePath, const std::string& text) {
    std::ofstream outFile(filePath, std::ios::app); // Open file in append mode
    if (!outFile) {
        std::cerr << "Failed to open text file for writing." << std::endl;
        return;
    }
    outFile << text;
    outFile.close();
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
    // Get computer name
    char computerName[UNLEN + 1];
    DWORD size = UNLEN + 1;
    if (GetComputerNameA(computerName, &size)) {
        std::string sysInfo = "Computer Name: " + std::string(computerName);

        // Get user name
        char userName[UNLEN + 1];
        DWORD userSize = UNLEN + 1;
        if (GetUserNameA(userName, &userSize)) {
            sysInfo += " | User Name: " + std::string(userName);
        }
        else {
            sysInfo += " | User Name: Unknown";
        }

        // Get operating system version
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

// Function to get the encoder CLSID for saving images
int GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
    UINT num = 0;          // number of image encoders
    UINT size = 0;         // size of the image encoder array in bytes

    // Get the size of the image encoder array
    Gdiplus::ImageCodecInfo* pImageCodecInfo = NULL;
    Gdiplus::GetImageEncodersSize(&num, &size);
    if (size == 0) {
        return -1; // Failure
    }

    // Allocate memory for the image encoder array
    pImageCodecInfo = (Gdiplus::ImageCodecInfo*)(malloc(size));
    if (pImageCodecInfo == NULL) {
        return -1; // Failure
    }

    // Get the image encoders
    Gdiplus::GetImageEncoders(num, size, pImageCodecInfo);

    // Find the encoder with the requested format
    for (UINT j = 0; j < num; ++j) {
        if (wcscmp(pImageCodecInfo[j].MimeType, format) == 0) {
            *pClsid = pImageCodecInfo[j].Clsid;
            free(pImageCodecInfo);
            return j; // Success
        }
    }

    free(pImageCodecInfo);
    return -1; // Failure
}

// Function to capture a screenshot
void captureScreenshot(const std::wstring& filename) {
    // Initialize GDI+
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

    // Get the screen dimensions
    HDC screenDC = GetDC(NULL);
    int screenWidth = GetDeviceCaps(screenDC, HORZRES);
    int screenHeight = GetDeviceCaps(screenDC, VERTRES);

    // Create a compatible DC and bitmap
    HDC memDC = CreateCompatibleDC(screenDC);
    HBITMAP hBitmap = CreateCompatibleBitmap(screenDC, screenWidth, screenHeight);
    SelectObject(memDC, hBitmap);

    // Copy the screen contents to the bitmap
    BitBlt(memDC, 0, 0, screenWidth, screenHeight, screenDC, 0, 0, SRCCOPY);

    // Save the bitmap to a file using GDI+
    Gdiplus::Bitmap bitmap(hBitmap, NULL);
    CLSID pngClsid;
    GetEncoderClsid(L"image/png", &pngClsid);
    bitmap.Save(filename.c_str(), &pngClsid, NULL);

    // Cleanup
    DeleteObject(hBitmap);
    DeleteDC(memDC);
    ReleaseDC(NULL, screenDC);
    Gdiplus::GdiplusShutdown(gdiplusToken);
}

int main() {
    std::string startTime = getCurrentTime();

    // Example usage of the various functions
    std::string systemInfo = getSystemInfo();
    std::string publicIP = getPublicIPAddress();
    std::string activeConnections = getActiveNetworkConnections();

    // Capture screenshot
    std::wstring screenshotFilename = L"screenshot.png";
    captureScreenshot(screenshotFilename);

    // End of session data
    std::string endTime = getCurrentTime();
    std::chrono::system_clock::time_point start = std::chrono::system_clock::now();
    std::chrono::system_clock::time_point end = std::chrono::system_clock::now();
    std::chrono::duration<double> elapsed_seconds = end - start;
    std::string duration = std::to_string(elapsed_seconds.count()) + "s";

    // Create JSON and text files
    std::string jsonOutput = createJson(startTime, endTime, duration, systemInfo, publicIP, activeConnections);
    writeJsonToFile("output.json", jsonOutput);

    std::string textOutput = createText(startTime, endTime, duration, systemInfo, publicIP, activeConnections);
    writeTextToFile("output.txt", textOutput);

    return 0;
}
