#include <windows.h>
#include <iostream>
#include <queue>
#include <string>
#include <vector>

// Get current working directory
std::string GetCurrentDir() {
    char buffer[MAX_PATH];
    DWORD length = GetCurrentDirectoryA(MAX_PATH, buffer);
    if (length == 0) {
        std::cerr << "GetCurrentDirectory failed, error: " << GetLastError() << std::endl;
        return "";
    }
    return std::string(buffer, length);
}

// Delete all files and subdirectories under the given root (BFS)
bool DeleteDirectoryTree(const std::string& root) {
    std::queue<std::string> dirQueue;
    std::queue<std::string> allDirs;   // used to delete empty dirs in reverse order
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
        if (hFind == INVALID_HANDLE_VALUE) {
            continue;   // Directory may be empty or inaccessible
        }

        do {
            if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0)
                continue;

            std::string fullPath = currentDir;
            if (fullPath.back() != '\\')
                fullPath += '\\';
            fullPath += findData.cFileName;

            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                // Subdirectory: queue it for later deletion
                dirQueue.push(fullPath);
                allDirs.push(fullPath);
            } else {
                // File: delete immediately
                if (!DeleteFileA(fullPath.c_str())) {
                    std::cerr << "Delete file failed: " << fullPath << " (error " << GetLastError() << ")" << std::endl;
                    success = false;
                } else {
                    std::cout << "[Deleted file] " << fullPath << std::endl;
                }
            }
        } while (FindNextFileA(hFind, &findData));

        FindClose(hFind);
    }

    // Delete directories from deepest to root
    std::vector<std::string> dirList;
    while (!allDirs.empty()) {
        dirList.push_back(allDirs.front());
        allDirs.pop();
    }
    for (auto it = dirList.rbegin(); it != dirList.rend(); ++it) {
        if (!RemoveDirectoryA(it->c_str())) {
            DWORD err = GetLastError();
            if (err != ERROR_DIR_NOT_EMPTY) {
                std::cerr << "Remove directory failed: " << *it << " (error " << err << ")" << std::endl;
                success = false;
            }
        } else {
            std::cout << "[Deleted directory] " << *it << std::endl;
        }
    }

    return success;
}

int main() {
    std::string root = GetCurrentDir();
    if (root.empty()) return 1;

    std::cout << "The program will delete ALL contents under: " << root << std::endl;
    std::cout << "WARNING: This operation is IRREVERSIBLE!" << std::endl;
    std::cout << "Type 'YES' to confirm, anything else to cancel: ";

    std::string confirm;
    std::cin >> confirm;
    if (confirm != "YES") {
        std::cout << "Operation cancelled." << std::endl;
        return 0;
    }

    bool result = DeleteDirectoryTree(root);
    if (result)
        std::cout << "Deletion completed." << std::endl;
    else
        std::cout << "Deletion completed with errors, check the log above." << std::endl;

    return 0;
}
