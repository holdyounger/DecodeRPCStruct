// DecodeRPCStruct.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <vector>
#include <rpcdef.h>
#include <psapi.h>
#include <rpcdce.h>
#include <Dbghelp.h>
#include <shlwapi.h>
#include <strsafe.h>
using namespace std;
#pragma comment(lib,"Dbghelp.lib")
#pragma comment(lib,"shlwapi.lib")
#pragma comment(lib, "Rpcrt4.lib") // 链接Rpcrt4.lib

#define CV_SIGNATURE_NB10   '01BN'
#define CV_SIGNATURE_RSDS   'SDSR'

#define RESET   "\033[0m"
#define BLACK   "\033[30m"      /* Black */
#define RED     "\033[31m"      /* Red */
#define GREEN   "\033[32m"      /* Green */
#define YELLOW  "\033[33m"      /* Yellow */
#define BLUE    "\033[34m"      /* Blue */
#define MAGENTA "\033[35m"      /* Magenta */
#define CYAN    "\033[36m"      /* Cyan */
#define WHITE   "\033[37m"      /* White */
#define BOLDGREEN    "\033[1m\033[32m"      /* Bold Green */

#include "StringHelper.h"

#define NT_SYMBOLS_FORMATS L"SRV*%ws*http://msdl.microsoft.com/download/symbols"
#define NT_SYMBOLS_DIR L"d:\\symbols\\"
#define SYMCHCKCMD_LINE_FORMATS L"%ws\\symchk.exe  /r  %ws  /s %ws"
#define WINDBG_INSTALLPATH L"D:\\Windows Kits\\10\\Debuggers\\x64"

/**
 * @brief copy from combase.dll
 */
const uint8_t g_data_RPC_SERVER_INTERFACE[96] = {
    0x60, 0x00, 0x00, 0x00, 0x70, 0x07, 0xF7, 0x18, 0x64, 0x8E, 0xCF, 0x11, 0x9A, 0xF1, 0x00, 0x20,
    0xAF, 0x6E, 0x72, 0xF4, 
    0x00, 0x00, 0x00, 0x00, 0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11,
    0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0x4C, 0x25, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x80, 0x4C, 0x25, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00
};

const char* g_Rpc_guid = "18f70770-8e64-11cf-9af1-0020af6e72f4";


// CodeView header 
typedef struct CV_HEADER
{
    DWORD CvSignature; // NBxx
    LONG  Offset;      // Always 0 for NB10
} *PCV_HEADER;

// CodeView NB10 debug information 
// (used when debug information is stored in a PDB 2.00 file) 
typedef struct CV_INFO_PDB20
{
    CV_HEADER  Header;
    DWORD      Signature;       // seconds since 01.01.1970
    DWORD      Age;             // an always-incrementing value 
    BYTE       PdbFileName[1];  // zero terminated string with the name of the PDB file 
} *PCV_INFO_PDB20;

// CodeView RSDS debug information 
// (used when debug information is stored in a PDB 7.00 file) 
typedef struct CV_INFO_PDB70
{
    DWORD      CvSignature;
    GUID       Signature;       // unique identifier 
    DWORD      Age;             // an always-incrementing value 
    BYTE       PdbFileName[1];  // zero terminated string with the name of the PDB file 
} *PCV_INFO_PDB70;

LPBYTE GetRVAOffset(LPBYTE pBuffer, DWORD dwVirtualOffset)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
    PIMAGE_NT_HEADERS32  pNtHeader32 = (PIMAGE_NT_HEADERS32)(pBuffer + pDosHeader->e_lfanew);
    PIMAGE_NT_HEADERS64  pNtHeader64 = (PIMAGE_NT_HEADERS64)(pBuffer + pDosHeader->e_lfanew);
    BOOL bIsX64 = pNtHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;

    int nSectionNum = bIsX64 ? pNtHeader64->FileHeader.NumberOfSections : pNtHeader32->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)(pBuffer + pDosHeader->e_lfanew + (bIsX64 ? sizeof(IMAGE_NT_HEADERS64) : sizeof(IMAGE_NT_HEADERS32)));

    // search for absolute offset
    for (int i = 0; i < nSectionNum; i++)
    {
        DWORD dwStart = pSection->VirtualAddress;
        if (dwStart <= dwVirtualOffset && dwVirtualOffset < dwStart + pSection->SizeOfRawData) {
            return pBuffer + pSection->PointerToRawData + (dwVirtualOffset - dwStart);
        }
        pSection++;
    }

    return 0;
}

BOOL GetPdbFileInfo(LPCWSTR lpszFilePath
    , LPWSTR szPdbFileName
    , DWORD dwPdbFileNameCch
    , LPWSTR szPdbGuid
    , DWORD dwPdbGuidCch
    , LPWSTR szChecksum
    , DWORD dwChecksumCch
)
{

    DWORD dwTotalRead = 0, dwRead = 0;
    DWORD dwSize = 0;
    BOOL bFound = FALSE;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    LPBYTE pBuffer = NULL;
    do
    {
        // read the file into memory
        HANDLE hFile = ::CreateFileW(lpszFilePath
            , GENERIC_READ
            , FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
            , NULL
            , OPEN_EXISTING
            , FILE_ATTRIBUTE_NORMAL
            , NULL
        );
        if (hFile == INVALID_HANDLE_VALUE)
        {
            break;
        }

        dwSize = GetFileSize(hFile, NULL);
        if (dwSize < 4096) // hardcode for file size limit
        {
            break;
        }

        pBuffer = (LPBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
        if (!pBuffer)
        {
            break;
        }



        while (dwTotalRead < dwSize &&
            ReadFile(hFile, pBuffer + dwTotalRead, dwSize - dwTotalRead, &dwRead, NULL))
        {
            dwTotalRead += dwRead;
        }


    } while (0);

    if (hFile != INVALID_HANDLE_VALUE)
    {
        ::CloseHandle(hFile);
    }

    if (pBuffer == NULL)
    {
        return FALSE;
    }

    if (dwTotalRead != dwSize)
    {
        if (pBuffer)
        {
            HeapFree(GetProcessHeap(), 0, pBuffer);
        }
        return FALSE;
    }

    LPWSTR lpszpdbInfo = NULL;

    // locate the DEBUG section
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
    if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
    {
        PIMAGE_DATA_DIRECTORY pDataDic;
        PIMAGE_NT_HEADERS32  pNtHeader32 = (PIMAGE_NT_HEADERS32)(pBuffer + pDosHeader->e_lfanew);
        PIMAGE_NT_HEADERS64  pNtHeader64 = (PIMAGE_NT_HEADERS64)(pBuffer + pDosHeader->e_lfanew);
        if (pNtHeader32->Signature == IMAGE_NT_SIGNATURE)
        {
            BOOL bIsX64 = pNtHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
            if (!bIsX64)
                pDataDic = &pNtHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
            else
                pDataDic = &pNtHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];


            if (pDataDic && pDataDic->Size > 0)
            {
                //The number of entries in the debug directory can be obtained by dividing the size of the debug directory (as specified in the optional header’s data directory entry) by the size of IMAGE_DEBUG_DIRECTORY structure.
                int nNumberOfEntries = pDataDic->Size / sizeof(IMAGE_DEBUG_DIRECTORY);
                PIMAGE_DEBUG_DIRECTORY pDebugDic = (PIMAGE_DEBUG_DIRECTORY)GetRVAOffset(pBuffer, pDataDic->VirtualAddress);

                for (int i = 0; i < nNumberOfEntries && !bFound; i++)
                {
                    // CodeView debug information (stored in the executable) or Program Database debug information (stored in PDB file)
                    if (pDebugDic->Type == IMAGE_DEBUG_TYPE_CODEVIEW)
                    {
                        LPBYTE pDebugData = pBuffer + pDebugDic->PointerToRawData;
                        DWORD dwCVSignature = *(LPDWORD)pDebugData;
                        if (dwCVSignature == CV_SIGNATURE_RSDS)
                        {
                            PCV_INFO_PDB70 pCvInfo = (PCV_INFO_PDB70)pDebugData;
                            StringCbPrintfW(szPdbGuid, dwPdbFileNameCch
                                , L"%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%d"
                                , pCvInfo->Signature.Data1
                                , pCvInfo->Signature.Data2
                                , pCvInfo->Signature.Data3
                                , pCvInfo->Signature.Data4[0]
                                , pCvInfo->Signature.Data4[1]
                                , pCvInfo->Signature.Data4[2]
                                , pCvInfo->Signature.Data4[3]
                                , pCvInfo->Signature.Data4[4]
                                , pCvInfo->Signature.Data4[5]
                                , pCvInfo->Signature.Data4[6]
                                , pCvInfo->Signature.Data4[7]
                                , pCvInfo->Age
                            );

                            lpszpdbInfo = CharToWchar((LPSTR)pCvInfo->PdbFileName);
                            StringCbCopy(szPdbFileName, dwPdbFileNameCch, lpszpdbInfo);
                            delete[]lpszpdbInfo;

                            if (bIsX64)
                            {
                                StringCbPrintfW(szChecksum, dwChecksumCch
                                    , L"%x%x"
                                    , pNtHeader64->FileHeader.TimeDateStamp
                                    , pNtHeader64->OptionalHeader.SizeOfImage
                                );
                            }
                            else
                            {
                                StringCbPrintfW(szChecksum, dwChecksumCch
                                    , L"%x%x"
                                    , pNtHeader32->FileHeader.TimeDateStamp
                                    , pNtHeader32->OptionalHeader.SizeOfImage
                                );
                            }

                            bFound = TRUE;
                        }
                    }

                    pDebugDic++;
                }
            }
        }
    }

    HeapFree(GetProcessHeap(), 0, pBuffer);

    return bFound;
}


BOOL EnableXXXPrivilege(LPCTSTR pszPrivilegeName)
{
    HANDLE hToken;
    LUID seXXXNameValue;
    TOKEN_PRIVILEGES tkp;

    // enable the SeXXXPrivilege
    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        wprintf(L"OpenProcessToken() failed, Error = %d  %s is not available.\n", GetLastError(), pszPrivilegeName);
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, pszPrivilegeName, &seXXXNameValue))
    {
        wprintf(L"LookupPrivilegeValue() failed, Error = %d %s is not available.\n", GetLastError(), pszPrivilegeName);
        CloseHandle(hToken);
        return FALSE;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = seXXXNameValue;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof tkp, NULL, NULL))
    {
        wprintf(L"AdjustTokenPrivileges() failed, Error = %d %s is not available.\n", GetLastError(), pszPrivilegeName);
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);

    return TRUE;

}

std::wstring GetModulePath(const HMODULE hModule) {
    WCHAR path[MAX_PATH];
    DWORD len = GetModuleFileNameW(hModule, path, MAX_PATH);
    if (len == 0) {
        // 获取失败，可以检查错误码
        DWORD lastError = GetLastError();
        std::cerr << "Failed to get module path. Error: " << lastError << std::endl;
        return L"";
    }
    return std::wstring(path);
}


BOOL CALLBACK SymbolCallback(PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext) {
    if ((ULONG64)UserContext == pSymInfo->Address)
    {
        std::cout  << GREEN << "函数名: " << pSymInfo->Name << ", 地址: " << std::hex << (LPVOID)pSymInfo->Address << RESET << std::endl;
    }
    return TRUE;
}

DWORD  RunTheSymchk(LPWSTR szCommandLine)
{
    DWORD dwMbrId = 0;

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));


    BOOL bResult = ::CreateProcess(NULL, szCommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

    if (!bResult)
        return 0;

    if (WaitForSingleObject(pi.hProcess, 180 * 1000) == WAIT_TIMEOUT)
        return 0;

    int dwCode = 0;
    if (!GetExitCodeProcess(pi.hProcess, (DWORD*)&dwCode))
    {

        return 0;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 1;
}

bool LoadSymbols(const char* moduleName, DWORD64 baseAddress, DWORD64 targetAddress) {
    HANDLE process = GetCurrentProcess();

    if (!SymInitialize(process, NULL, FALSE)) {
        std::cerr << "SymInitialize failed" << std::endl;
        return false;
    }

    WCHAR szPdbFileName[MAX_PATH] = { 0 };
    WCHAR szPdbGuid[MAX_PATH] = { 0 };
    WCHAR szChecksum[MAX_PATH] = { 0 };
    WCHAR szNtSymbolUrl[MAX_PATH] = { 0 };
    WCHAR szPdbSymbolPath[MAX_PATH] = { 0 };
    WCHAR szCommandLine[MAX_PATH] = { 0 };

    std::wstring strPath = GetModulePath((HMODULE)baseAddress);

    GetPdbFileInfo(strPath.c_str(), szPdbFileName, MAX_PATH, szPdbGuid, MAX_PATH, szChecksum, MAX_PATH);

    StringCbPrintf(szNtSymbolUrl, MAX_PATH * sizeof(WCHAR), NT_SYMBOLS_FORMATS, NT_SYMBOLS_DIR);
    StringCbPrintf(szCommandLine, MAX_PATH * sizeof(WCHAR), SYMCHCKCMD_LINE_FORMATS, WINDBG_INSTALLPATH, strPath.c_str(), szNtSymbolUrl);

    StringCbCopy(szPdbSymbolPath, MAX_PATH * sizeof(WCHAR), NT_SYMBOLS_DIR);
    StringCbCat(szPdbSymbolPath, MAX_PATH * sizeof(WCHAR), szPdbFileName);
    StringCbCat(szPdbSymbolPath, MAX_PATH * sizeof(WCHAR), L"\\");
    StringCbCat(szPdbSymbolPath, MAX_PATH * sizeof(WCHAR), szPdbGuid);
    StringCbCat(szPdbSymbolPath, MAX_PATH * sizeof(WCHAR), L"\\");
    StringCbCat(szPdbSymbolPath, MAX_PATH * sizeof(WCHAR), szPdbFileName);

    if (!PathFileExistsW(szPdbSymbolPath))
    {
        RunTheSymchk(szCommandLine);
    }

    DWORD64 moduleBase = SymLoadModuleExW(process, NULL, szPdbSymbolPath, NULL, baseAddress, 0, NULL, 0);
    if (moduleBase == 0) {
        std::cerr << "SymLoadModuleEx failed" << std::endl;
        SymCleanup(process);
        return false;
    }

    // 枚举符号
    if (!SymEnumSymbols(process, moduleBase, "*", (PSYM_ENUMERATESYMBOLS_CALLBACK)SymbolCallback, (PVOID)targetAddress)) {
        std::cerr << "SymEnumSymbols failed" << std::endl;
        SymUnloadModule64(process, moduleBase);
        SymCleanup(process);
        return false;
    }

    SymUnloadModule64(process, moduleBase);
    SymCleanup(process);
    return true;
}

int main(int argc, const char* argv[])
{
    std::cout << argv[0] << " Start\n";

    GUID rpcGuid;
    UuidFromStringA((RPC_CSTR)g_Rpc_guid, &rpcGuid);

    uint8_t *queryData = NULL;

    size_t nSize = sizeof(GUID) + sizeof(int);
    queryData = new uint8_t[nSize];
    if (queryData)
    {
        BYTE* pCur = queryData;
        memset(pCur, 0, nSize);
        *pCur = sizeof(RPC_SERVER_INTERFACE);
        pCur += sizeof(int);
        memcpy((char*)pCur, (const char*)&rpcGuid, sizeof(GUID));
    }

    HMODULE hdCombase = LoadLibrary(L"combase.dll");

    // 获取模块信息
    MODULEINFO moduleInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hdCombase, &moduleInfo, sizeof(moduleInfo))) {
        std::cerr << "Failed to get module information. Error: " << GetLastError() << std::endl;
        return 1;
    }

    // 打印模块基地址和大小
    std::cout << "Base address of module: " << moduleInfo.lpBaseOfDll << std::endl;
    std::cout << "Size of module: " << moduleInfo.SizeOfImage << std::endl;

    // 读取模块文件内容
    std::vector<BYTE> moduleData(moduleInfo.SizeOfImage);
    SIZE_T bytesRead;
    if (!ReadProcessMemory(GetCurrentProcess(), moduleInfo.lpBaseOfDll, moduleData.data(), moduleInfo.SizeOfImage, &bytesRead)) {
        std::cerr << "Failed to read module memory. Error: " << GetLastError() << std::endl;
        return 1;
    }

    // 搜索shellcode
    LPVOID lpFindAddr = 0;
    DWORD dwOffset = 0;
    for (DWORD i = 0; i <= moduleData.size() - nSize; ++i) {
        bool found = true;
        for (DWORD j = 0; j < nSize; ++j) {
            if (moduleData[i + j] != queryData[j]) {
                found = false;
                break;
            }
        }
        if (found) {
            dwOffset = i;
            uintptr_t base = (uintptr_t)moduleInfo.lpBaseOfDll;
            lpFindAddr = (LPVOID)(base + i);
            std::cout << "Shellcode found at address: 0x" << hex << lpFindAddr << std::endl;
            break;
        }
    }

    if (!lpFindAddr)
    {
        return -1;
    }

    LPVOID pData = (LPVOID)&(moduleData.data())[dwOffset];

    // PRPC_SERVER_INTERFACE pRpcSerIf = (PRPC_SERVER_INTERFACE)g_data_RPC_SERVER_INTERFACE;
    PRPC_SERVER_INTERFACE pRpcSerIf = (PRPC_SERVER_INTERFACE)pData;

    PRPC_DISPATCH_TABLE pRpcDispatchTable = pRpcSerIf->DispatchTable;
    PMIDL_SERVER_INFO pMidlInfo = (PMIDL_SERVER_INFO)pRpcSerIf->InterpreterInfo;


    LPVOID pDispatchTablePtr = (LPVOID)pMidlInfo->DispatchTable;
    LPVOID pFmtStringOffsetPtr = (LPVOID)pMidlInfo->FmtStringOffset;
    LPVOID pPorcString = (LPVOID)pMidlInfo->ProcString;

    LPVOID* dispatchTable = new LPVOID[pRpcDispatchTable->DispatchTableCount];
    short* fmtStringOffseTable = new short[pRpcDispatchTable->DispatchTableCount];

    // 获取 DispatchTable
    for (int i = 0; i < pRpcDispatchTable->DispatchTableCount; i++)
    {
        uintptr_t pTable = (uintptr_t)pDispatchTablePtr + i * sizeof(LPVOID);
        dispatchTable[i] = (LPVOID)*(LPVOID*)pTable;
    }

    // 获取 fmtstringoffset
    for (int i = 0; i < pRpcDispatchTable->DispatchTableCount; i++)
    {
        uintptr_t pFmtString = (uintptr_t)pFmtStringOffsetPtr + i * sizeof(short);
        fmtStringOffseTable[i] = (short) * (short*)pFmtString;
    }

    // 解析 ProcString
    for (int i = 0; i < pRpcDispatchTable->DispatchTableCount; i++)
    {
        PFORMAT_STRING pFormat = (PFORMAT_STRING)((uintptr_t)pPorcString + fmtStringOffseTable[i]);

        NDR_PROC_CONTEXT ProcContext;
        NDR_PROC_CONTEXT* pContext = &ProcContext;
        PFORMAT_STRING pNewProcDescr;
        INTERPRETER_FLAGS InterpreterFlags;
        ulong RpcFlags;

        pContext->HandleType = *pFormat++;
        pContext->UseLocator = (FC_AUTO_HANDLE == pContext->HandleType);

        pContext->NdrInfo.InterpreterFlags = *((PINTERPRETER_FLAGS)pFormat++);

        InterpreterFlags = pContext->NdrInfo.InterpreterFlags;

        if (InterpreterFlags.HasRpcFlags)
            RpcFlags = *((UNALIGNED ulong*&)pFormat)++;
        else
            RpcFlags = 0;

        int ProcNum = *(ushort*)pFormat; pFormat += 2;
        pContext->StackSize = *(ushort*)pFormat; pFormat += 2;

        pContext->pHandleFormatSave = pFormat;

        pNewProcDescr = pFormat;

        if (!pContext->HandleType)
        {
            // explicit handle
            pNewProcDescr += ((*pFormat == FC_BIND_PRIMITIVE) ? 4 : 6);
        }

        pContext->NdrInfo.pProcDesc = (NDR_PROC_DESC*)pNewProcDescr;

        PNDR_PROC_DESC pNdrDes = (PNDR_PROC_DESC)pNewProcDescr;

        printf("Proc[%d]: Addr:0x%016llx NumberParams: %d\n", i , (uintptr_t)dispatchTable[i], pNdrDes->NumberParams);

        LoadSymbols("combase.dll", (DWORD64)hdCombase, (DWORD64)dispatchTable[i]);
    }

    system("pause");

    return 0;
}
