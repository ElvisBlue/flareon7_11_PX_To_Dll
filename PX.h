#pragma once
#pragma pack(1)
#include <Windows.h>

#pragma pack(push, 1)

struct PX_IMAGE_DIRECTORY
{
	DWORD TargetVirtualAddress;
	DWORD DataDirectorySize;
	DWORD PX_PointToRawAddress;
};

struct PX_SECTION_HEADER
{
	DWORD VirtualAddress;
	DWORD VirtualSize;
	DWORD PointerToRawData;
	DWORD SizeOfRawData;
	DWORD Unknown;
};

struct PX_HEADER
{
	__int16 magic;
	char field_2[10];
	unsigned int DosHeaderSize;
	int VirtualSize;
	int totalHeaderSize;
	PX_IMAGE_DIRECTORY PX_IMAGE_DIRECTORY_ENTRY_IMPORT;
	PX_IMAGE_DIRECTORY PX_IMAGE_DIRECTORY_ENTRY_EXPORT;
	PX_IMAGE_DIRECTORY PX_IMAGE_DIRECTORY_ENTRY_IAT;
	PX_IMAGE_DIRECTORY PX_IMAGE_DIRECTORY_ENTRY_SECURITY;
	PX_IMAGE_DIRECTORY PX_IMAGE_DIRECTORY_ENTRY_EXCEPTION;
	PX_IMAGE_DIRECTORY PX_IMAGE_DIRECTORY_ENTRY_BASERELOC;
	__int16 field_60;
	WORD NumberOfSections;
	int EntryPoint;
	PX_SECTION_HEADER SectionArray[10];
};
#pragma pack(pop)