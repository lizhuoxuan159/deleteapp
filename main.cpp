#include <windows.h>
#include <restartmanager.h>
#include <iostream>
#include <queue>
#include <string>
#include <vector>

#pragma comment(lib, "rstrtmgr.lib")

// ============================================================================
//  Helper: Get current working directory
// ============================================================================
std::string GetCurrentDir() {
    char buffer[MAX_PATH];
    DWORD length = GetCurrentDirectoryA(MAX_PATH, buffer);
    if (length == 0) {
        std::cerr << "[Error] GetCurrentDirectory failed, error: " << GetLastError() << std::endl;
        return "";
    }
    return std::string(buffer, length);
}

// ============================================================================
//  Check if current process is running as SYSTEM
// ============================================================================
bool IsSystemProcess() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return false;

    DWORD size = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &size);
    std::vector<BYTE> buffer(size);
    if (!GetTokenInformation(hToken, TokenUser, buffer.data(), size, &size)) {
        CloseHandle(hToken);
        return false;
    }

    TOKEN_USER* pUser = reinterpret_cast<TOKEN_USER*>(buffer.data());
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID systemSid = nullptr;
    AllocateAndInitializeSid(&ntAuthority, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &systemSid);

    bool isSystem = EqualSid(pUser->User.Sid, systemSid);
    FreeSid(systemSid);
    CloseHandle(hToken);
    return isSystem;
}

// ============================================================================
//  Enable SeDebugPrivilege (required to access SYSTEM processes)
// ============================================================================
bool EnableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bool success = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(hToken);
    return success && GetLastError() != ERROR_NOT_ALL_ASSIGNED;
}

// ============================================================================
//  Relaunch current executable as SYSTEM (with --elevated argument)
// ============================================================================
bool RunAsSystem() {
    if (!EnableDebugPrivilege()) {
        std::cerr << "[Error] Failed to enable SeDebugPrivilege. Run as Administrator." << std::endl;
        return false;
    }

    // Open System process (PID 4)
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, 4);
    if (!hProcess) {
        std::cerr << "[Error] Cannot open System process (PID=4). Error: " << GetLastError() << std::endl;
        return false;
    }

    HANDLE hToken = nullptr;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        std::cerr << "[Error] OpenProcessToken failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    HANDLE hDuplicatedToken = nullptr;
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation, TokenPrimary, &hDuplicatedToken)) {
        CloseHandle(hToken);
        CloseHandle(hProcess);
        std::cerr << "[Error] DuplicateTokenEx failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Get current executable path
    char exePath[MAX_PATH];
    if (!GetModuleFileNameA(nullptr, exePath, MAX_PATH)) {
        std::cerr << "[Error] GetModuleFileName failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hDuplicatedToken);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return false;
    }

    // Build command line: add --elevated
    std::string cmdLine = std::string("\"") + exePath + "\" --elevated";

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessAsUserA(
            hDuplicatedToken,
            exePath,
            cmdLine.data(),
            nullptr, nullptr,
            FALSE,
            CREATE_NEW_CONSOLE,
            nullptr, nullptr,
            &si, &pi)) {
        std::cerr << "[Error] CreateProcessAsUser failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hDuplicatedToken);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return false;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hDuplicatedToken);
    CloseHandle(hToken);
    CloseHandle(hProcess);

    std::cout << "[Info] SYSTEM process launched successfully." << std::endl;
    return true;
}

// ============================================================================
//  The actual deletion logic (same as previous)
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
                   << L" | App: " << rgProcInfo[i].strAppName
                   << L" | Service: " << rgProcInfo[i].strServiceShortName << std::endl;

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
        } else {
            std::wcerr << L"[Error] Failed to open process PID: " << rgProcInfo[i].Process.dwProcessId
                       << L" (error " << GetLastError() << L")" << std::endl;
        }
    }

    RmEndSession(dwSession);
    return terminated;
}

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
            } else {
                std::cerr << "[Error] Retry deletion still failed: " << filePath
                          << " (error " << GetLastError() << ")" << std::endl;
            }
        } else if (killed == 0) {
            std::cerr << "[Warning] No locking process found, but deletion failed: " << filePath << std::endl;
        } else {
            std::cerr << "[Error] Unlock failed: " << filePath << std::endl;
        }
    } else {
        std::cerr << "[Error] Deletion failed: " << filePath << " (error " << err << ")" << std::endl;
    }
    return false;
}

bool DeleteDirectoryTree(const std::string& root) {
    std::queue<std::string> dirQueue;
    std::queue<std::string> allDirs;
    dirQueue.push(root);
    allDirs.push(root);

    bool success = true;

    while (!dirQueue.empty()) {
        std::string currentDir = dirQueue.front();
        dirQueue.pop();

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
                dirQueue.push(fullPath);
                allDirs.push(fullPath);
            } else {
                if (!DeleteFileWithUnlock(fullPath))
                    success = false;
            }
        } while (FindNextFileA(hFind, &findData));

        FindClose(hFind);
    }

    std::vector<std::string> dirList;
    while (!allDirs.empty()) {
        dirList.push_back(allDirs.front());
        allDirs.pop();
    }

    for (auto it = dirList.rbegin(); it != dirList.rend(); ++it) {
        if (!RemoveDirectoryA(it->c_str())) {
            DWORD err = GetLastError();
            if (err != ERROR_DIR_NOT_EMPTY) {
                std::cerr << "[Error] Failed to remove directory: " << *it
                          << " (error " << err << ")" << std::endl;
                success = false;
            }
        } else {
            std::cout << "[Deleted directory] " << *it << std::endl;
        }
    }

    return success;
}

// ============================================================================
//  Main entry point
// ============================================================================
int main(int argc, char* argv[]) {
    // Check if we are running with the --elevated flag
    bool isElevated = false;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--elevated") == 0) {
            isElevated = true;
            break;
        }
    }

    std::string root = GetCurrentDir();
    if (root.empty()) {
        std::cerr << "[Error] Cannot get current directory." << std::endl;
        return 1;
    }

    // If not elevated and not SYSTEM, ask user for consent
    if (!isElevated && !IsSystemProcess()) {
        std::cout << "==================================================" << std::endl;
        std::cout << "Current process is NOT running as SYSTEM." << std::endl;
        std::cout << "To delete protected files (like antivirus), we need SYSTEM privileges." << std::endl;
        std::cout << "Do you agree to elevate to SYSTEM? (This will relaunch this program)" << std::endl;
        std::cout << "Enter 'YES' to continue, anything else to cancel: ";

        std::string answer;
        std::cin >> answer;
        if (answer != "YES") {
            std::cout << "Operation cancelled." << std::endl;
            return 0;
        }

        std::cout << "Attempting to elevate to SYSTEM..." << std::endl;
        if (!RunAsSystem()) {
            std::cerr << "[Error] Elevation failed. Please run as Administrator and try again." << std::endl;
            return 1;
        }

        std::cout << "Elevation successful. The new SYSTEM process is running." << std::endl;
        std::cout << "This process will now exit." << std::endl;
        return 0;
    }

    // Now we are either SYSTEM or elevated by flag
    if (IsSystemProcess())
        std::cout << "[Info] Running with SYSTEM privileges." << std::endl;
    else
        std::cout << "[Info] Running with Administrator privileges (--elevated flag)." << std::endl;

    // Confirm deletion again (extra safety)
    std::cout << "==================================================" << std::endl;
    std::cout << "This program will delete ALL contents and subdirectories" << std::endl;
    std::cout << "under the current directory:" << std::endl;
    std::cout << "  " << root << std::endl;
    std::cout << "WARNING: This operation is IRREVERSIBLE!" << std::endl;
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
