#include <windows.h>
#include <restartmanager.h>
#include <iostream>
#include <queue>
#include <string>
#include <vector>
#include <algorithm>

#pragma comment(lib, "rstrtmgr.lib")

// ============================================================================
//  Helper: Check if path is a system-protected directory
// ============================================================================
bool IsProtectedSystemPath(const std::string& path) {
    std::string lower = path;
    for (auto& c : lower) c = tolower(c);
    if (!lower.empty() && lower.back() == '\\') lower.pop_back();

    static const std::vector<std::string> blocked = {
        "c:\\windows", "c:\\windows\\system32", "c:\\windows\\syswow64",
        "c:\\program files", "c:\\program files (x86)", "c:\\programdata",
        "c:\\system volume information", "c:\\$recycle.bin"
    };
    for (const auto& bp : blocked) {
        if (lower.find(bp) == 0) return true;
    }
    return false;
}

// ============================================================================
//  Terminate processes using a file (Restart Manager)
// ============================================================================
int TerminateProcessesUsingFile(const std::wstring& filePath) {
    DWORD dwSession = 0;
    WCHAR szSessionKey[CCH_RM_SESSION_KEY + 1] = { 0 };
    DWORD dwError = RmStartSession(&dwSession, 0, szSessionKey);
    if (dwError != ERROR_SUCCESS) {
        std::cerr << "[Error] RmStartSession failed, error: " << dwError << std::endl;
        return -1;
    }

    LPCWSTR rgszResources[] = { filePath.c_str() };
    dwError = RmRegisterResources(dwSession, 1, rgszResources, 0, nullptr, 0, nullptr);
    if (dwError != ERROR_SUCCESS) {
        std::cerr << "[Error] RmRegisterResources failed, error: " << dwError << std::endl;
        RmEndSession(dwSession);
        return -1;
    }

    DWORD dwReason = 0;
    UINT nProcInfoNeeded = 0;
    UINT nProcInfo = 0;
    RM_PROCESS_INFO rgProcInfo[100] = { 0 };
    dwError = RmGetList(dwSession, &nProcInfoNeeded, &nProcInfo, rgProcInfo, &dwReason);
    if (dwError != ERROR_SUCCESS && dwError != ERROR_MORE_DATA) {
        std::cerr << "[Error] RmGetList failed, error: " << dwError << std::endl;
        RmEndSession(dwSession);
        return -1;
    }

    if (nProcInfo == 0) {
        std::cout << "[Info] No process is using this file." << std::endl;
        RmEndSession(dwSession);
        return 0;
    }

    std::cout << "[Info] Found " << nProcInfo << " process(es) using this file:" << std::endl;
    int terminated = 0;
    for (UINT i = 0; i < nProcInfo; ++i) {
        std::wcout << L"  PID: " << rgProcInfo[i].Process.dwProcessId
                   << L" | App: " << rgProcInfo[i].strAppName << std::endl;

        HANDLE hProc = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, FALSE, rgProcInfo[i].Process.dwProcessId);
        if (hProc) {
            if (TerminateProcess(hProc, 1)) {
                std::wcout << L"[Terminated] PID: " << rgProcInfo[i].Process.dwProcessId << std::endl;
                terminated++;
                WaitForSingleObject(hProc, 3000);
            } else {
                std::wcerr << L"[Error] Failed to terminate PID: " << rgProcInfo[i].Process.dwProcessId
                           << L" (error " << GetLastError() << L")" << std::endl;
            }
            CloseHandle(hProc);
        }
    }

    RmEndSession(dwSession);
    return terminated;
}

// ============================================================================
//  Delete a file with unlock attempt if locked
// ============================================================================
bool DeleteFileWithUnlock(const std::string& filePath) {
    if (DeleteFileA(filePath.c_str())) {
        std::cout << "[Deleted file] " << filePath << std::endl;
        return true;
    }

    DWORD err = GetLastError();
    if (err == ERROR_SHARING_VIOLATION || err == ERROR_ACCESS_DENIED) {
        std::cerr << "[Warning] File locked, trying to unlock: " << filePath << std::endl;

        int len = MultiByteToWideChar(CP_ACP, 0, filePath.c_str(), -1, nullptr, 0);
        std::wstring wPath(len, L'\0');
        MultiByteToWideChar(CP_ACP, 0, filePath.c_str(), -1, wPath.data(), len);

        int killed = TerminateProcessesUsingFile(wPath);
        if (killed > 0) {
            Sleep(500);
            if (DeleteFileA(filePath.c_str())) {
                std::cout << "[Deleted file] " << filePath << " (after unlock)" << std::endl;
                return true;
            }
        }
    }
    std::cerr << "[Error] Failed to delete: " << filePath << std::endl;
    return false;
}

// ============================================================================
//  Structure for priority queue: (depth, path)
// ============================================================================
struct DirEntry {
    int depth;
    std::string path;

    // Max-heap: deeper dirs pop first
    bool operator<(const DirEntry& other) const {
        return depth < other.depth;
    }
};

// ============================================================================
//  Delete directory tree using priority_queue (deepest first)
// ============================================================================
bool DeleteDirectoryTree(const std::string& root) {
    std::queue<std::pair<std::string, int>> bfsQueue;  // (path, depth)
    std::priority_queue<DirEntry> dirHeap;

    bfsQueue.push({root, 0});
    dirHeap.push({0, root});

    bool success = true;

    // Phase 1: BFS traversal – delete files, collect dirs with depth
    while (!bfsQueue.empty()) {
        auto [currentDir, depth] = bfsQueue.front();
        bfsQueue.pop();

        std::string searchPattern = currentDir;
        if (!searchPattern.empty() && searchPattern.back() != '\\')
            searchPattern += '\\';
        searchPattern += '*';

        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA(searchPattern.c_str(), &findData);
        if (hFind == INVALID_HANDLE_VALUE)
            continue;

        do {
            if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0)
                continue;

            std::string fullPath = currentDir;
            if (fullPath.back() != '\\')
                fullPath += '\\';
            fullPath += findData.cFileName;

            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                int childDepth = depth + 1;
                bfsQueue.push({fullPath, childDepth});
                dirHeap.push({childDepth, fullPath});
            } else {
                if (!DeleteFileWithUnlock(fullPath))
                    success = false;
            }
        } while (FindNextFileA(hFind, &findData));

        FindClose(hFind);
    }

    // Phase 2: Delete directories from deepest to shallowest
    std::cout << "\n[Info] Deleting directories (deepest first)..." << std::endl;
    while (!dirHeap.empty()) {
        DirEntry entry = dirHeap.top();
        dirHeap.pop();

        if (!RemoveDirectoryA(entry.path.c_str())) {
            DWORD err = GetLastError();
            if (err != ERROR_DIR_NOT_EMPTY) {
                std::cerr << "[Error] Failed to remove directory (depth " << entry.depth
                          << "): " << entry.path << " (error " << err << ")" << std::endl;
                success = false;
            }
        } else {
            std::cout << "[Deleted directory] " << entry.path << " (depth " << entry.depth << ")" << std::endl;
        }
    }

    return success;
}

// ============================================================================
//  Main entry point – now uses command-line argument for target directory
// ============================================================================
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <target_directory>" << std::endl;
        std::cerr << "Example: " << argv[0] << " D:\\MyTestFolder" << std::endl;
        return 1;
    }

    std::string root = argv[1];

    // Check if directory exists
    DWORD attr = GetFileAttributesA(root.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) {
        std::cerr << "Error: Directory does not exist." << std::endl;
        return 1;
    }
    if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        std::cerr << "Error: Path is not a directory." << std::endl;
        return 1;
    }

    // Protect system directories
    if (IsProtectedSystemPath(root)) {
        std::cerr << "Access Denied" << std::endl;
        return 1;
    }

    std::cout << "==================================================" << std::endl;
    std::cout << "This program will delete ALL contents and subdirectories" << std::endl;
    std::cout << "under the specified directory:" << std::endl;
    std::cout << "  " << root << std::endl;
    std::cout << "WARNING: This operation is IRREVERSIBLE!" << std::endl;
    std::cout << "==================================================" << std::endl;
    std::cout << "Enter 'YES' to continue: ";

    std::string confirm;
    std::cin >> confirm;
    if (confirm != "YES") {
        std::cout << "Operation cancelled." << std::endl;
        return 0;
    }

    std::cout << "Cleaning..." << std::endl;
    bool result = DeleteDirectoryTree(root);

    if (result)
        std::cout << "Cleaning completed successfully." << std::endl;
    else
        std::cout << "Cleaning completed with errors. Check log above." << std::endl;

    return 0;
}
