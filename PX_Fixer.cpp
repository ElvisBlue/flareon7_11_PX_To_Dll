// PX_Fixer.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <stdio.h>
#include <windows.h>
#include "PX.h"
#define FIX32
using namespace std;

bool FixPXFile(BYTE* fileBuffer, size_t fileLength);
bool FixPXFile32(BYTE* fileBuffer, size_t fileLength);
bool PrintPXFile(BYTE* fileBuffer, size_t fileLength);

int main(int argc, char** argv)
{
    printf("PX Fixer for flareon challenge 11 by Elvis\n");
    printf("Let's see if I can do something....\n");
    if (argc != 2)
    {
        printf("Please input some file...\n");
        return 0;
    }
    HANDLE hFile = CreateFile(argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("Could not open file\n");
        return 0;
    }
    size_t fileSize = GetFileSize(hFile, NULL);
    BYTE* fileBuffer = (BYTE*)malloc(fileSize);
    DWORD dwReads;
    ReadFile(hFile, fileBuffer, fileSize, &dwReads, NULL);
    CloseHandle(hFile);
    PrintPXFile(fileBuffer, fileSize);
#if defined FIX32
    FixPXFile32(fileBuffer, fileSize);
#else
    FixPXFile(fileBuffer, fileSize);
#endif
    free(fileBuffer);
    return 1;
}

bool PrintPXFile(BYTE* fileBuffer, size_t fileLength)
{
    PX_HEADER* PXHeader = (PX_HEADER*)fileBuffer;
    printf("magic: 0x%X\n", PXHeader->magic);
    printf("Dos Header size: 0x%X\n", PXHeader->DosHeaderSize);
    printf("Total header size: 0x%X\n", PXHeader->totalHeaderSize);
    printf("Virtual size: 0x%X\n", PXHeader->VirtualSize);
    printf("Number of sections: 0x%X\n", PXHeader->NumberOfSections);
    printf("Address of entry point: 0x%X\n", PXHeader->EntryPoint);
    return true;
}

BYTE DosHeader[] = {
    0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
    0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0x00, 0x00, 0x00
};

BYTE DosStub[] = {
    0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68,
    0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F,
    0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20,
    0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xD9, 0x3C, 0xB5, 0xBB, 0x9D, 0x5D, 0xDB, 0xE8, 0x9D, 0x5D, 0xDB, 0xE8, 0x9D, 0x5D, 0xDB, 0xE8,
    0x94, 0x25, 0x4E, 0xE8, 0x9C, 0x5D, 0xDB, 0xE8, 0x9D, 0x5D, 0xDA, 0xE8, 0xF3, 0x5D, 0xDB, 0xE8,
    0x94, 0x25, 0x48, 0xE8, 0x96, 0x5D, 0xDB, 0xE8, 0x94, 0x25, 0x58, 0xE8, 0x90, 0x5D, 0xDB, 0xE8,
    0x94, 0x25, 0x49, 0xE8, 0x9C, 0x5D, 0xDB, 0xE8, 0x94, 0x25, 0x52, 0xE8, 0x98, 0x5D, 0xDB, 0xE8,
    0x94, 0x25, 0x4F, 0xE8, 0x9C, 0x5D, 0xDB, 0xE8, 0x94, 0x25, 0x4A, 0xE8, 0x9C, 0x5D, 0xDB, 0xE8,
    0x52, 0x69, 0x63, 0x68, 0x9D, 0x5D, 0xDB, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

bool ReadPXFile(BYTE* fileBuffer, size_t fileLength, PX_HEADER* pxHeader)
{
    return true;
}

bool FixPXFile(BYTE* fileBuffer, size_t fileLength)
{
    PIMAGE_NT_HEADERS64 NtHeader = (PIMAGE_NT_HEADERS64)malloc(sizeof(IMAGE_NT_HEADERS64));
    ZeroMemory(NtHeader, sizeof(IMAGE_NT_HEADERS64));

    PX_HEADER* PXHeader = (PX_HEADER*)fileBuffer;

    PIMAGE_SECTION_HEADER SectionHeaderArray = (PIMAGE_SECTION_HEADER)malloc(sizeof(IMAGE_SECTION_HEADER) * PXHeader->NumberOfSections);
    memcpy(SectionHeaderArray, (BYTE*)PXHeader + PXHeader->totalHeaderSize + PXHeader->DosHeaderSize - (PXHeader->NumberOfSections * sizeof(IMAGE_SECTION_HEADER)), PXHeader->NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

    PIMAGE_NT_HEADERS64 TmpNtHeader = (PIMAGE_NT_HEADERS64)((BYTE*)PXHeader + PXHeader->DosHeaderSize);

    NtHeader->Signature = 0x4550;

    NtHeader->FileHeader.Machine = 0x8664;
    NtHeader->FileHeader.NumberOfSections = PXHeader->NumberOfSections;
    NtHeader->FileHeader.TimeDateStamp = TmpNtHeader->FileHeader.TimeDateStamp;
    NtHeader->FileHeader.PointerToSymbolTable = 0;
    NtHeader->FileHeader.NumberOfSymbols = 0;
    NtHeader->FileHeader.SizeOfOptionalHeader = 0xF0;
    NtHeader->FileHeader.Characteristics = 0x2022;

    NtHeader->OptionalHeader.Magic = 0x020B;
    NtHeader->OptionalHeader.MajorLinkerVersion = 9;
    NtHeader->OptionalHeader.MinorLinkerVersion = 0;
    NtHeader->OptionalHeader.SizeOfCode = PXHeader->SectionArray[0].VirtualSize;
    NtHeader->OptionalHeader.SizeOfInitializedData = PXHeader->VirtualSize - PXHeader->SectionArray[0].VirtualSize;
    NtHeader->OptionalHeader.SizeOfUninitializedData = 0;
    NtHeader->OptionalHeader.AddressOfEntryPoint = PXHeader->EntryPoint;
    NtHeader->OptionalHeader.BaseOfCode = PXHeader->SectionArray[0].VirtualAddress;
    NtHeader->OptionalHeader.ImageBase = TmpNtHeader->OptionalHeader.ImageBase;
    NtHeader->OptionalHeader.SectionAlignment = 0x1000;
    NtHeader->OptionalHeader.FileAlignment = 0x200;
    NtHeader->OptionalHeader.MajorOperatingSystemVersion = 6;
    NtHeader->OptionalHeader.MinorOperatingSystemVersion = 1;
    NtHeader->OptionalHeader.MajorImageVersion = 6;
    NtHeader->OptionalHeader.MinorImageVersion = 1;
    NtHeader->OptionalHeader.MajorSubsystemVersion = 6;
    NtHeader->OptionalHeader.MinorSubsystemVersion = 1;
    NtHeader->OptionalHeader.Win32VersionValue = 0;
    NtHeader->OptionalHeader.SizeOfImage = PXHeader->VirtualSize;
    NtHeader->OptionalHeader.SizeOfHeaders = 0x1000;
    NtHeader->OptionalHeader.CheckSum = 0;
    NtHeader->OptionalHeader.Subsystem = 2;
    NtHeader->OptionalHeader.DllCharacteristics = 0x140;
    NtHeader->OptionalHeader.SizeOfStackReserve = 0x40000;
    NtHeader->OptionalHeader.SizeOfStackCommit = 0x1000;
    NtHeader->OptionalHeader.SizeOfHeapReserve = 0x100000;
    NtHeader->OptionalHeader.SizeOfHeapCommit = 0x1000;
    NtHeader->OptionalHeader.LoaderFlags = 0;
    NtHeader->OptionalHeader.NumberOfRvaAndSizes = 0x10;

    NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = PXHeader->PX_IMAGE_DIRECTORY_ENTRY_EXPORT.TargetVirtualAddress;
    NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = PXHeader->PX_IMAGE_DIRECTORY_ENTRY_EXPORT.DataDirectorySize;
    NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = PXHeader->PX_IMAGE_DIRECTORY_ENTRY_IMPORT.TargetVirtualAddress;
    NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = PXHeader->PX_IMAGE_DIRECTORY_ENTRY_IMPORT.DataDirectorySize;
    NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = PXHeader->PX_IMAGE_DIRECTORY_ENTRY_IAT.TargetVirtualAddress;
    NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = PXHeader->PX_IMAGE_DIRECTORY_ENTRY_IAT.DataDirectorySize;
    NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = PXHeader->PX_IMAGE_DIRECTORY_ENTRY_SECURITY.TargetVirtualAddress;
    NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = PXHeader->PX_IMAGE_DIRECTORY_ENTRY_SECURITY.DataDirectorySize;
    NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = PXHeader->PX_IMAGE_DIRECTORY_ENTRY_EXCEPTION.TargetVirtualAddress;
    NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size = PXHeader->PX_IMAGE_DIRECTORY_ENTRY_EXCEPTION.DataDirectorySize;
    NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = PXHeader->PX_IMAGE_DIRECTORY_ENTRY_BASERELOC.TargetVirtualAddress;
    NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = PXHeader->PX_IMAGE_DIRECTORY_ENTRY_BASERELOC.DataDirectorySize;

    //Now build PE File. First Create PE Header
    BYTE* PEFile = (BYTE*)malloc(PXHeader->VirtualSize);
    DWORD PEFileSize = PXHeader->VirtualSize;
    memset(PEFile, 0, PXHeader->VirtualSize);

    //Create Dos Header
    memcpy(PEFile, DosHeader, sizeof(DosHeader));
    //Create Dos Stub
    memcpy((BYTE*)PEFile + sizeof(DosHeader), DosStub, sizeof(DosStub));
    //Create NT Header
    memcpy((BYTE*)PEFile + sizeof(DosHeader) + sizeof(DosStub), NtHeader, sizeof(IMAGE_NT_HEADERS64));

    //Create / Fix Section Header
    for (int i = 0; i < PXHeader->NumberOfSections; i++)
    {
        memcpy((BYTE*)PEFile + SectionHeaderArray[i].VirtualAddress, (BYTE*)PXHeader + PXHeader->SectionArray[i].PointerToRawData, PXHeader->SectionArray[i].SizeOfRawData);
        SectionHeaderArray[i].PointerToRawData = PXHeader->SectionArray[i].VirtualAddress;
        SectionHeaderArray[i].VirtualAddress = PXHeader->SectionArray[i].VirtualAddress;
        SectionHeaderArray[i].SizeOfRawData = PXHeader->SectionArray[i].SizeOfRawData;
    }

    //Copy Section Header
    memcpy((BYTE*)PEFile + sizeof(DosHeader) + sizeof(DosStub) + sizeof(IMAGE_NT_HEADERS64), SectionHeaderArray, sizeof(IMAGE_SECTION_HEADER) * PXHeader->NumberOfSections);

    //Now fix data directory
    memcpy((BYTE*)PEFile + PXHeader->PX_IMAGE_DIRECTORY_ENTRY_EXPORT.TargetVirtualAddress, (BYTE*)PXHeader + PXHeader->PX_IMAGE_DIRECTORY_ENTRY_EXPORT.PX_PointToRawAddress, PXHeader->PX_IMAGE_DIRECTORY_ENTRY_EXPORT.DataDirectorySize);
    memcpy((BYTE*)PEFile + PXHeader->PX_IMAGE_DIRECTORY_ENTRY_IMPORT.TargetVirtualAddress, (BYTE*)PXHeader + PXHeader->PX_IMAGE_DIRECTORY_ENTRY_IMPORT.PX_PointToRawAddress, PXHeader->PX_IMAGE_DIRECTORY_ENTRY_IMPORT.DataDirectorySize);
    memcpy((BYTE*)PEFile + PXHeader->PX_IMAGE_DIRECTORY_ENTRY_IAT.TargetVirtualAddress, (BYTE*)PXHeader + PXHeader->PX_IMAGE_DIRECTORY_ENTRY_IAT.PX_PointToRawAddress, PXHeader->PX_IMAGE_DIRECTORY_ENTRY_IAT.DataDirectorySize);
    memcpy((BYTE*)PEFile + PXHeader->PX_IMAGE_DIRECTORY_ENTRY_SECURITY.TargetVirtualAddress, (BYTE*)PXHeader + PXHeader->PX_IMAGE_DIRECTORY_ENTRY_SECURITY.PX_PointToRawAddress, PXHeader->PX_IMAGE_DIRECTORY_ENTRY_SECURITY.DataDirectorySize);
    memcpy((BYTE*)PEFile + PXHeader->PX_IMAGE_DIRECTORY_ENTRY_EXCEPTION.TargetVirtualAddress, (BYTE*)PXHeader + PXHeader->PX_IMAGE_DIRECTORY_ENTRY_EXCEPTION.PX_PointToRawAddress, PXHeader->PX_IMAGE_DIRECTORY_ENTRY_EXCEPTION.DataDirectorySize);
    memcpy((BYTE*)PEFile + PXHeader->PX_IMAGE_DIRECTORY_ENTRY_BASERELOC.TargetVirtualAddress, (BYTE*)PXHeader + PXHeader->PX_IMAGE_DIRECTORY_ENTRY_BASERELOC.PX_PointToRawAddress, PXHeader->PX_IMAGE_DIRECTORY_ENTRY_BASERELOC.DataDirectorySize);


    free(NtHeader); 
    free(SectionHeaderArray);

    HANDLE hFile = CreateFile("Fixed.dll", GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("Can not open file 'Fixed.dll' to write\n");
        free(PEFile);
        return false;
    }
    DWORD dummy;
    WriteFile(hFile, PEFile, PEFileSize, &dummy, NULL);
    CloseHandle(hFile);
    printf("Fixed.dll has been writen");

    return true;
}

bool FixPXFile32(BYTE* fileBuffer, size_t fileLength)
{
    PIMAGE_NT_HEADERS32 NtHeader = (PIMAGE_NT_HEADERS32)malloc(sizeof(IMAGE_NT_HEADERS32));
    ZeroMemory(NtHeader, sizeof(IMAGE_NT_HEADERS32));

    PX_HEADER* PXHeader = (PX_HEADER*)fileBuffer;

    PIMAGE_SECTION_HEADER SectionHeaderArray = (PIMAGE_SECTION_HEADER)malloc(sizeof(IMAGE_SECTION_HEADER) * PXHeader->NumberOfSections);
    memcpy(SectionHeaderArray, (BYTE*)PXHeader + PXHeader->totalHeaderSize + PXHeader->DosHeaderSize - (PXHeader->NumberOfSections * sizeof(IMAGE_SECTION_HEADER)), PXHeader->NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

    PIMAGE_NT_HEADERS32 TmpNtHeader = (PIMAGE_NT_HEADERS32)((BYTE*)PXHeader + PXHeader->DosHeaderSize);

    NtHeader->Signature = 0x4550;

    NtHeader->FileHeader.Machine = 0x14C;
    NtHeader->FileHeader.NumberOfSections = PXHeader->NumberOfSections;
    NtHeader->FileHeader.TimeDateStamp = TmpNtHeader->FileHeader.TimeDateStamp;
    NtHeader->FileHeader.PointerToSymbolTable = 0;
    NtHeader->FileHeader.NumberOfSymbols = 0;
    NtHeader->FileHeader.SizeOfOptionalHeader = 0xF0;
    NtHeader->FileHeader.Characteristics = 0x2102;

    NtHeader->OptionalHeader.Magic = 0x010B;
    NtHeader->OptionalHeader.MajorLinkerVersion = 9;
    NtHeader->OptionalHeader.MinorLinkerVersion = 0;
    NtHeader->OptionalHeader.SizeOfCode = PXHeader->SectionArray[0].VirtualSize;
    NtHeader->OptionalHeader.SizeOfInitializedData = PXHeader->VirtualSize - PXHeader->SectionArray[0].VirtualSize;
    NtHeader->OptionalHeader.SizeOfUninitializedData = 0;
    NtHeader->OptionalHeader.AddressOfEntryPoint = PXHeader->EntryPoint;
    NtHeader->OptionalHeader.BaseOfCode = PXHeader->SectionArray[0].VirtualAddress;
    NtHeader->OptionalHeader.ImageBase = TmpNtHeader->OptionalHeader.ImageBase;
    NtHeader->OptionalHeader.SectionAlignment = 0x1000;
    NtHeader->OptionalHeader.FileAlignment = 0x200;
    NtHeader->OptionalHeader.MajorOperatingSystemVersion = 6;
    NtHeader->OptionalHeader.MinorOperatingSystemVersion = 1;
    NtHeader->OptionalHeader.MajorImageVersion = 6;
    NtHeader->OptionalHeader.MinorImageVersion = 1;
    NtHeader->OptionalHeader.MajorSubsystemVersion = 6;
    NtHeader->OptionalHeader.MinorSubsystemVersion = 1;
    NtHeader->OptionalHeader.Win32VersionValue = 0;
    NtHeader->OptionalHeader.SizeOfImage = PXHeader->VirtualSize;
    NtHeader->OptionalHeader.SizeOfHeaders = 0x1000;
    NtHeader->OptionalHeader.CheckSum = 0;
    NtHeader->OptionalHeader.Subsystem = 2;
    NtHeader->OptionalHeader.DllCharacteristics = 0x140;
    NtHeader->OptionalHeader.SizeOfStackReserve = 0x40000;
    NtHeader->OptionalHeader.SizeOfStackCommit = 0x1000;
    NtHeader->OptionalHeader.SizeOfHeapReserve = 0x100000;
    NtHeader->OptionalHeader.SizeOfHeapCommit = 0x1000;
    NtHeader->OptionalHeader.LoaderFlags = 0;
    NtHeader->OptionalHeader.NumberOfRvaAndSizes = 0x10;

    NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = PXHeader->PX_IMAGE_DIRECTORY_ENTRY_EXPORT.TargetVirtualAddress;
    NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = PXHeader->PX_IMAGE_DIRECTORY_ENTRY_EXPORT.DataDirectorySize;
    NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = PXHeader->PX_IMAGE_DIRECTORY_ENTRY_IMPORT.TargetVirtualAddress;
    NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = PXHeader->PX_IMAGE_DIRECTORY_ENTRY_IMPORT.DataDirectorySize;
    NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = PXHeader->PX_IMAGE_DIRECTORY_ENTRY_IAT.TargetVirtualAddress;
    NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = PXHeader->PX_IMAGE_DIRECTORY_ENTRY_IAT.DataDirectorySize;
    NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = PXHeader->PX_IMAGE_DIRECTORY_ENTRY_SECURITY.TargetVirtualAddress;
    NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = PXHeader->PX_IMAGE_DIRECTORY_ENTRY_SECURITY.DataDirectorySize;
    NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = PXHeader->PX_IMAGE_DIRECTORY_ENTRY_EXCEPTION.TargetVirtualAddress;
    NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size = PXHeader->PX_IMAGE_DIRECTORY_ENTRY_EXCEPTION.DataDirectorySize;
    NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = PXHeader->PX_IMAGE_DIRECTORY_ENTRY_BASERELOC.TargetVirtualAddress;
    NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = PXHeader->PX_IMAGE_DIRECTORY_ENTRY_BASERELOC.DataDirectorySize;

    //Now build PE File. First Create PE Header
    BYTE* PEFile = (BYTE*)malloc(PXHeader->VirtualSize);
    DWORD PEFileSize = PXHeader->VirtualSize;
    memset(PEFile, 0, PXHeader->VirtualSize);

    //Create Dos Header
    memcpy(PEFile, DosHeader, sizeof(DosHeader));
    //Create Dos Stub
    memcpy((BYTE*)PEFile + sizeof(DosHeader), DosStub, sizeof(DosStub));
    //Create NT Header
    memcpy((BYTE*)PEFile + sizeof(DosHeader) + sizeof(DosStub), NtHeader, sizeof(IMAGE_NT_HEADERS));//???

    //Create / Fix Section Header
    for (int i = 0; i < PXHeader->NumberOfSections; i++)
    {
        memcpy((BYTE*)PEFile + SectionHeaderArray[i].VirtualAddress, (BYTE*)PXHeader + PXHeader->SectionArray[i].PointerToRawData, PXHeader->SectionArray[i].SizeOfRawData);
        SectionHeaderArray[i].PointerToRawData = PXHeader->SectionArray[i].VirtualAddress;
        SectionHeaderArray[i].VirtualAddress = PXHeader->SectionArray[i].VirtualAddress;
        SectionHeaderArray[i].SizeOfRawData = PXHeader->SectionArray[i].SizeOfRawData;
    }

    //Copy Section Header
    memcpy((BYTE*)PEFile + sizeof(DosHeader) + sizeof(DosStub) + sizeof(IMAGE_NT_HEADERS), SectionHeaderArray, sizeof(IMAGE_SECTION_HEADER) * PXHeader->NumberOfSections);//?????

    //Now fix data directory
    memcpy((BYTE*)PEFile + PXHeader->PX_IMAGE_DIRECTORY_ENTRY_EXPORT.TargetVirtualAddress, (BYTE*)PXHeader + PXHeader->PX_IMAGE_DIRECTORY_ENTRY_EXPORT.PX_PointToRawAddress, PXHeader->PX_IMAGE_DIRECTORY_ENTRY_EXPORT.DataDirectorySize);
    memcpy((BYTE*)PEFile + PXHeader->PX_IMAGE_DIRECTORY_ENTRY_IMPORT.TargetVirtualAddress, (BYTE*)PXHeader + PXHeader->PX_IMAGE_DIRECTORY_ENTRY_IMPORT.PX_PointToRawAddress, PXHeader->PX_IMAGE_DIRECTORY_ENTRY_IMPORT.DataDirectorySize);
    memcpy((BYTE*)PEFile + PXHeader->PX_IMAGE_DIRECTORY_ENTRY_IAT.TargetVirtualAddress, (BYTE*)PXHeader + PXHeader->PX_IMAGE_DIRECTORY_ENTRY_IAT.PX_PointToRawAddress, PXHeader->PX_IMAGE_DIRECTORY_ENTRY_IAT.DataDirectorySize);
    memcpy((BYTE*)PEFile + PXHeader->PX_IMAGE_DIRECTORY_ENTRY_SECURITY.TargetVirtualAddress, (BYTE*)PXHeader + PXHeader->PX_IMAGE_DIRECTORY_ENTRY_SECURITY.PX_PointToRawAddress, PXHeader->PX_IMAGE_DIRECTORY_ENTRY_SECURITY.DataDirectorySize);
    memcpy((BYTE*)PEFile + PXHeader->PX_IMAGE_DIRECTORY_ENTRY_EXCEPTION.TargetVirtualAddress, (BYTE*)PXHeader + PXHeader->PX_IMAGE_DIRECTORY_ENTRY_EXCEPTION.PX_PointToRawAddress, PXHeader->PX_IMAGE_DIRECTORY_ENTRY_EXCEPTION.DataDirectorySize);
    memcpy((BYTE*)PEFile + PXHeader->PX_IMAGE_DIRECTORY_ENTRY_BASERELOC.TargetVirtualAddress, (BYTE*)PXHeader + PXHeader->PX_IMAGE_DIRECTORY_ENTRY_BASERELOC.PX_PointToRawAddress, PXHeader->PX_IMAGE_DIRECTORY_ENTRY_BASERELOC.DataDirectorySize);


    free(NtHeader);
    free(SectionHeaderArray);


    HANDLE hFile = CreateFile("Fixed.dll", GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("Can not open file 'Fixed.dll' to write\n");
        free(PEFile);
        return false;
    }
    DWORD dummy;
    WriteFile(hFile, PEFile, PEFileSize, &dummy, NULL);
    CloseHandle(hFile);
    printf("Fixed.dll has been writen");

    return true;
}