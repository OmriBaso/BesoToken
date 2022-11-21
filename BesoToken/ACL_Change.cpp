#include "ACL_Change.h"



std::string ACL_Change::GetLastErrorAsString()
{
    //Get the error message ID, if any.
    DWORD errorMessageID = ::GetLastError();
    if (errorMessageID == 0) {
        return std::string(); //No error message has been recorded
    }

    LPSTR messageBuffer = nullptr;

    //Ask Win32 to give us the string version of that message ID.
    //The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

    //Copy the error message into a std::string.
    std::string message(messageBuffer, size);

    //Free the Win32's string's buffer.
    LocalFree(messageBuffer);

    return message;
}


BOOL ChangeDesktopDACL(HWINSTA Dekstop, const char* DesktopName) {


    PSID ppsidOwner;
    PSID ppsidGroup;
    PACL ppDacl;
    PACL ppSacl;
    SECURITY_INFORMATION securityInfo = { 0 };
    PSECURITY_DESCRIPTOR SecDesc = { 0 };


    if (GetSecurityInfo(Dekstop, SE_FILE_OBJECT, securityInfo, &ppsidOwner, &ppsidGroup, &ppDacl, &ppSacl, &SecDesc)) {

        printf("[-] Failed GetSecurityInfo\n");
        exit(2);
    }

    DWORD szNeeded = 0;
    CreateWellKnownSid(WinWorldSid, NULL, NULL, &szNeeded); // Gonna fail and fill szNeeded
    PSID SID_Everyone = LocalAlloc(LPTR, szNeeded);
    if (!CreateWellKnownSid(WinWorldSid, NULL, SID_Everyone, &szNeeded)) {

        printf("[-] Failed CreateWellKnownSid \n");
        exit(2);
    }



    CreateWellKnownSid(WinBuiltinAnyPackageSid, NULL, NULL, &szNeeded); // Gonna fail and fill szNeeded
    PSID SID_AllContainers = LocalAlloc(LPTR, szNeeded);
    if (!CreateWellKnownSid(WinBuiltinAnyPackageSid, NULL, SID_AllContainers, &szNeeded)) {

        printf("[-] Failed CreateWellKnownSid2 \n");
        exit(2);
    }
    const int NUM_ACES = 2;

    EXPLICIT_ACCESS WorkstationEA[NUM_ACES];
    TRUSTEE WorkstationTrutEE[NUM_ACES];
    PACL pACL = NULL;
    ZeroMemory(&WorkstationTrutEE, NUM_ACES * sizeof(TRUSTEE));
    ZeroMemory(&WorkstationEA, NUM_ACES * sizeof(EXPLICIT_ACCESS));

    WorkstationTrutEE[0].pMultipleTrustee = NULL;
    WorkstationTrutEE[0].MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
    WorkstationTrutEE[0].TrusteeForm = TRUSTEE_IS_SID;
    WorkstationTrutEE[0].TrusteeType = TRUSTEE_IS_UNKNOWN;
    WorkstationTrutEE[0].ptstrName = (LPWCH)SID_Everyone;

    WorkstationEA[0].grfAccessPermissions = GENERIC_ACCESS;
    WorkstationEA[0].grfAccessMode = GRANT_ACCESS;
    WorkstationEA[0].grfInheritance = NULL;
    WorkstationEA[0].Trustee = WorkstationTrutEE[0];


    WorkstationTrutEE[1].pMultipleTrustee = NULL;
    WorkstationTrutEE[1].MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
    WorkstationTrutEE[1].TrusteeForm = TRUSTEE_IS_SID;
    WorkstationTrutEE[1].TrusteeType = TRUSTEE_IS_UNKNOWN;
    WorkstationTrutEE[1].ptstrName = (LPWCH)SID_AllContainers;


    WorkstationEA[1].grfAccessPermissions = GENERIC_ACCESS;
    WorkstationEA[1].grfAccessMode = GRANT_ACCESS;
    WorkstationEA[1].grfInheritance = NULL;
    WorkstationEA[1].Trustee = WorkstationTrutEE[1];


    EXPLICIT_ACCESS DesktopEA[NUM_ACES];
    TRUSTEE DesktopTrutEE[NUM_ACES];
    ZeroMemory(&DesktopTrutEE, NUM_ACES * sizeof(TRUSTEE));
    ZeroMemory(&DesktopEA, NUM_ACES * sizeof(EXPLICIT_ACCESS));

    DesktopTrutEE[0].pMultipleTrustee = NULL;
    DesktopTrutEE[0].MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
    DesktopTrutEE[0].TrusteeForm = TRUSTEE_IS_SID;
    DesktopTrutEE[0].TrusteeType = TRUSTEE_IS_UNKNOWN;
    DesktopTrutEE[0].ptstrName = (LPWCH)SID_Everyone;

    DesktopEA[0].grfAccessPermissions = GENERIC_ACCESS;
    DesktopEA[0].grfAccessMode = GRANT_ACCESS;
    DesktopEA[0].grfInheritance = NULL;
    DesktopEA[0].Trustee = DesktopTrutEE[0];


    DesktopTrutEE[1].pMultipleTrustee = NULL;
    DesktopTrutEE[1].MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
    DesktopTrutEE[1].TrusteeForm = TRUSTEE_IS_SID;
    DesktopTrutEE[1].TrusteeType = TRUSTEE_IS_UNKNOWN;
    DesktopTrutEE[1].ptstrName = (LPWCH)SID_AllContainers;

    DesktopEA[1].grfAccessPermissions = GENERIC_ACCESS;
    DesktopEA[1].grfAccessMode = GRANT_ACCESS;
    DesktopEA[1].grfInheritance = 0U;
    DesktopEA[1].Trustee = DesktopTrutEE[1];

    PACL oldACL = NULL;
    PACL NewpACL = NULL;

    if (strcmp(DesktopName, "winsta0") == 0) {

        BOOL result = SetEntriesInAclW(NUM_ACES, WorkstationEA, oldACL, &NewpACL);

        if (result == ERROR_SUCCESS) {
            printf("\n[+] Changed ACL %s", DesktopName);

        }
        else {
        
            std::cout << "[-] Error: " << ACL_Change::GetLastErrorAsString << "\n";
            return 0;
        }



    }

    if (strcmp(DesktopName, "default") == 0) {

        BOOL result = SetEntriesInAclW(NUM_ACES, DesktopEA, oldACL, &NewpACL);

        if (result == ERROR_SUCCESS) {
            printf("\n[+] Changed ACL %s", DesktopName);

        }
        else {
        
            std::cout << "[-] Error: " << ACL_Change::GetLastErrorAsString << "\n";
            return 0;

        }



    }


    BOOL result = SetSecurityInfo(Dekstop, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION, 0, 0, NewpACL, 0);
    if (result == ERROR_SUCCESS) {
    
        printf("\n[+] Called SetSecurityInfo\n");
    }
    else {
    
        printf("\n[-] Failed To Call SetSecurityInfo\n");
    }


    return 1;

}


BOOL ACL_Change::AdjustDesktop() {

    HWINSTA  hwinsta = NULL;

    hwinsta = OpenWindowStationA("winsta0", FALSE, READ_CONTROL | WRITE_DAC);
    if (!hwinsta) {

        printf("[-] Failed to get windows station");
    }
    else {

        ChangeDesktopDACL(hwinsta, "winsta0");
    }

    HDESK Desk = OpenDesktopA("default", 0, FALSE, MAXIMUM_ALLOWED);

    if (!Desk) {

        printf("[-] Failed to get windows station");
    }
    else {

        ChangeDesktopDACL((HWINSTA)Desk, "default");
    }




    return 0;

}