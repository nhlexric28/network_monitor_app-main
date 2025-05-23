#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <pcap.h>
#include <thread>
#include <string>
#include <sstream>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <chrono>
#include <fstream>
#include <richedit.h>
#include <shlobj.h>
#include <commctrl.h>
#include <windowsx.h>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Comctl32.lib")

HWND hLogBox;
HWND hStartBtn, hStopBtn, hThreatsBtn, hBandwidthChartBtn, hBandwidthGraphBtn;
HWND hChartBox;
HWND hInterfaceDropdown;
pcap_t* handle = nullptr;
std::thread captureThread;
bool capturing = false;
HWND hWndMain;

std::unordered_map<std::string, std::string> threatDetails;
std::vector<pcap_if_t*> interfaces;

std::wstring GetLogFilePath() {
    wchar_t path[MAX_PATH];
    SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, path);
    std::wstring logPath = path;
    logPath += L"\\NetThreatDetection\\packet_log.txt";
    CreateDirectoryW((logPath.substr(0, logPath.find_last_of(L'\\'))).c_str(), nullptr);
    return logPath;
}

std::wofstream logFile;

std::unordered_set<std::string> blacklistedIPs = { "1.2.3.4", "8.8.8.8"};
std::unordered_map<std::string, std::vector<std::chrono::steady_clock::time_point>> portScanMap;
std::unordered_map<std::string, size_t> bandwidthMap;

std::wstring ToWString(const char* src) {
    if (!src) return L"(null)";
    int len = MultiByteToWideChar(CP_ACP, 0, src, -1, nullptr, 0);
    std::wstring result(len - 1, 0);
    MultiByteToWideChar(CP_ACP, 0, src, -1, &result[0], len);
    return result;
}

void AppendLog(const std::wstring& message, COLORREF color = RGB(0, 0, 0)) {
    CHARFORMAT cf = { sizeof(cf) };
    cf.dwMask = CFM_COLOR;
    cf.crTextColor = color;
    int len = GetWindowTextLength(hLogBox);
    SendMessage(hLogBox, EM_SETSEL, len, len);
    SendMessage(hLogBox, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
    SendMessage(hLogBox, EM_REPLACESEL, FALSE, (LPARAM)(message + L"\r\n").c_str());
    logFile << message << std::endl;
}

void ShowThreatDetails() {
    std::wstringstream ss;
    ss << L"Threats Detected:\n";
    for (const auto& pair : threatDetails) {
        ss << ToWString(pair.first.c_str()) << L" → " << ToWString(pair.second.c_str()) << L"\n";
    }
    MessageBox(hWndMain, ss.str().c_str(), L"Threat Details", MB_OK | MB_ICONWARNING);
}

void ShowBandwidthChart() {
    std::wstringstream ss;
    ss << L"Bandwidth Usage (KB):\n";
    for (const auto& pair : bandwidthMap) {
        ss << ToWString(pair.first.c_str()) << L": " << pair.second / 1024 << L" KB\n";
    }
    MessageBox(hWndMain, ss.str().c_str(), L"Bandwidth Chart", MB_OK | MB_ICONINFORMATION);
}

void ShowBandwidthGraph() {
    std::wstringstream ss;
    ss << L"Bandwidth Graph (Source IP → KB):\n";
    for (const auto& entry : bandwidthMap) {
        ss << ToWString(entry.first.c_str()) << L" → ";
        int blocks = static_cast<int>(entry.second / 10240); // 10KB per block
        for (int i = 0; i < blocks && i < 50; ++i) ss << L"█";
        ss << L"\n";
    }
    MessageBox(hWndMain, ss.str().c_str(), L"Bandwidth Graph", MB_OK | MB_ICONINFORMATION);
}

void PacketHandler(u_char*, const pcap_pkthdr* header, const u_char* pkt_data) {
    if (header->caplen < 34) return;
    const u_char* ip_header = pkt_data + 14;
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    if ((ip_header[0] >> 4) == 4) {
        inet_ntop(AF_INET, ip_header + 12, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, ip_header + 16, dst_ip, INET_ADDRSTRLEN);
        std::string src(src_ip), dst(dst_ip);
        std::wstringstream ss;
        ss << L"[IPv4] " << src_ip << L" → " << dst_ip;
        std::string timestamp = "Time: " + std::to_string(time(nullptr));
        if (blacklistedIPs.count(src) || blacklistedIPs.count(dst)) {
            ss << L"  [THREAT] Blacklisted IP!";
            AppendLog(ss.str(), RGB(255, 0, 0));
            threatDetails[src + dst] = "Blacklisted IP, MAC: N/A, " + timestamp;
            return;
        }
        auto& timestamps = portScanMap[src];
        auto now = std::chrono::steady_clock::now();
        timestamps.push_back(now);
        if (timestamps.size() > 10) timestamps.erase(timestamps.begin());
        if (timestamps.size() >= 10 && (now - timestamps.front()) < std::chrono::seconds(5)) {
            ss << L"  [THREAT] Port scan detected!";
            AppendLog(ss.str(), RGB(255, 0, 255));
            threatDetails[src] = "Port scan, MAC: N/A, " + timestamp;
            return;
        }
        bandwidthMap[src] += header->len;
        if (bandwidthMap[src] > 1024 * 1024 * 10) {
            ss << L"  [WARN] High bandwidth usage!";
            AppendLog(ss.str(), RGB(255, 140, 0));
            threatDetails[src] = "High bandwidth, MAC: N/A, " + timestamp;
            bandwidthMap[src] = 0;
            return;
        }
        static std::unordered_map<std::string, int> mitmCount;
        mitmCount[dst]++;
        if (mitmCount[dst] > 50) {
            ss << L"  [THREAT] Possible MITM!";
            AppendLog(ss.str(), RGB(139, 0, 0));
            threatDetails[dst] = "MITM, MAC: N/A, " + timestamp;
            mitmCount[dst] = 0;
            return;
        }
        AppendLog(ss.str());
    }
}

void StartCapture() {
    capturing = true;
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        AppendLog(L"[ERROR] WSAStartup failed.", RGB(255, 0, 0));
        return;
    }
    captureThread = std::thread([] {
        char errbuf[PCAP_ERRBUF_SIZE];
        int selIndex = ComboBox_GetCurSel(hInterfaceDropdown);
        if (selIndex < 0 || selIndex >= interfaces.size()) {
            AppendLog(L"[ERROR] Invalid interface selection.", RGB(255, 0, 0));
            return;
        }
        pcap_if_t* selected = interfaces[selIndex];
        handle = pcap_open_live(selected->name, 65536, 1, 1000, errbuf);
        if (!handle) {
            AppendLog(L"[ERROR] pcap_open_live failed.", RGB(255, 0, 0));
            WSACleanup();
            return;
        }
        AppendLog(L"[INFO] Capturing on: " + ToWString(selected->description));
        pcap_loop(handle, 0, PacketHandler, nullptr);
        pcap_close(handle);
        handle = nullptr;
        WSACleanup();
        });
}

void StopCapture() {
    if (handle) pcap_breakloop(handle);
    capturing = false;
    if (captureThread.joinable()) captureThread.join();
    AppendLog(L"[INFO] Capture stopped.");
}

void PopulateInterfaces() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        AppendLog(L"[ERROR] pcap_findalldevs failed.", RGB(255, 0, 0));
        return;
    }
    interfaces.clear();
    SendMessage(hInterfaceDropdown, CB_RESETCONTENT, 0, 0);
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        interfaces.push_back(d);
        std::wstring desc = ToWString(d->description ? d->description : d->name);
        SendMessage(hInterfaceDropdown, CB_ADDSTRING, 0, (LPARAM)desc.c_str());
    }
    ComboBox_SetCurSel(hInterfaceDropdown, 0);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_DESTROY:
        StopCapture();
        logFile.close();
        PostQuitMessage(0);
        return 0;
    case WM_COMMAND:
        if ((HWND)lParam == hStartBtn) {
            EnableWindow(hStartBtn, FALSE);
            EnableWindow(hStopBtn, TRUE);
            AppendLog(L"[INFO] Starting capture...");
            StartCapture();
        }
        else if ((HWND)lParam == hStopBtn) {
            EnableWindow(hStopBtn, FALSE);
            EnableWindow(hStartBtn, TRUE);
            StopCapture();
        }
        else if ((HWND)lParam == hThreatsBtn) {
            ShowThreatDetails();
        }
        else if ((HWND)lParam == hBandwidthChartBtn) {
            ShowBandwidthChart();
        }
        else if ((HWND)lParam == hBandwidthGraphBtn) {
            ShowBandwidthGraph();
        }
        return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

void CreateUI(HWND hwnd) {
    hStartBtn = CreateWindow(L"BUTTON", L"Start Capture", WS_VISIBLE | WS_CHILD, 10, 10, 120, 30, hwnd, nullptr, nullptr, nullptr);
    hStopBtn = CreateWindow(L"BUTTON", L"Stop Capture", WS_VISIBLE | WS_CHILD, 140, 10, 120, 30, hwnd, nullptr, nullptr, nullptr);
    hThreatsBtn = CreateWindow(L"BUTTON", L"Show Threats", WS_VISIBLE | WS_CHILD, 270, 10, 120, 30, hwnd, nullptr, nullptr, nullptr);
    hBandwidthChartBtn = CreateWindow(L"BUTTON", L"Show Bandwidth", WS_VISIBLE | WS_CHILD, 400, 10, 140, 30, hwnd, nullptr, nullptr, nullptr);
    hBandwidthGraphBtn = CreateWindow(L"BUTTON", L"Graph Bandwidth", WS_VISIBLE | WS_CHILD, 550, 10, 140, 30, hwnd, nullptr, nullptr, nullptr);
    hInterfaceDropdown = CreateWindow(WC_COMBOBOX, nullptr, CBS_DROPDOWNLIST | WS_VISIBLE | WS_CHILD, 700, 10, 240, 500, hwnd, nullptr, nullptr, nullptr);
    EnableWindow(hStopBtn, FALSE);
    hLogBox = CreateWindowEx(WS_EX_CLIENTEDGE, L"RICHEDIT50W", nullptr,
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
        10, 50, 930, 550, hwnd, nullptr, nullptr, nullptr);
    PopulateInterfaces();
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow) {
    LoadLibrary(L"Msftedit.dll");
    INITCOMMONCONTROLSEX icex = { sizeof(icex), ICC_BAR_CLASSES };
    InitCommonControlsEx(&icex);

    const wchar_t CLASS_NAME[] = L"NetThreatApp";
    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClass(&wc);
    hWndMain = CreateWindowEx(0, CLASS_NAME, L"Network Threat Detection", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 980, 680, nullptr, nullptr, hInstance, nullptr);
    if (!hWndMain) return 0;
    CreateUI(hWndMain);
    ShowWindow(hWndMain, nCmdShow);
    std::wstring logPath = GetLogFilePath();
    logFile.open(logPath, std::ios::app);
    MSG msg = {};
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}
