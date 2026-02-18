#include <Windows.h>
#include <stdio.h>

BOOL
ReadFileIntoBuffer(
	_In_ LPCWSTR FilePath, // we need to know which file to read
	_Out_ PBYTE* Buffer, // caller needs the buffer pointer back
	_Out_ PDWORD FileSize // calller needs to know how big the file is
)
{
	// declare all variables and initialize it to safe values
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwBytesRead = 0;
	PBYTE pBuffer = NULL;
	DWORD dwFileSize = 0;

	// CreateFileW is an Windows API function to open or create a file
	hFile = CreateFileW(
		FilePath, // the file we want to open
		GENERIC_READ, // we only need to read the file
		FILE_SHARE_READ, // other programs can read while we have it open
		NULL, // use default security
		OPEN_EXISTING, // file must already exist, don't create new
		FILE_ATTRIBUTE_NORMAL, // normal, no special handling
		NULL // not copying attributes from another file
	);

	// error cheecking for CreateFileW
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("[-] CreateFileW failed. Error: %d \n", GetLastError());
		return FALSE;
	}

	// We need to know how much memory to allocate; We need to know how many bytes to read
	dwFileSize = GetFileSize(hFile, NULL); // returns size of an open file in bytes

	// error checking for GetFileSize
	if (dwFileSize == INVALID_FILE_SIZE)
	{
		printf("[-] GetFileSize failed. Error: %d \n", GetLastError());
		CloseHandle(hFile); // close handle to ensure no handle leaks
		return FALSE;	
	}

	// allocate memory from a heap; use HeapAlloc to minimize dependencies
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);

	// error checking for HeapAlloc
	if (pBuffer == NULL)
	{
		printf("[-] HeapAlloc failed. Error: %d \n", GetLastError());
		CloseHandle(hFile);
		return FALSE;
	}

	if (!ReadFile(
		hFile, // which file to read
		pBuffer, // where to store the bytes
		dwFileSize,  // read the entire file
		&dwBytesRead, // receives actual bytes read
		NULL)) // not using async I/O
	{
		printf("[-] ReadFile failed. Error: %d \n", GetLastError());
		HeapFree(GetProcessHeap(), 0, pBuffer);
		CloseHandle(hFile);
		return FALSE;
	}

	*Buffer = pBuffer;
	*FileSize = dwFileSize;

	CloseHandle(hFile);

	// everything succeeded; caller knows to use the buffer
	return TRUE;
}

BOOL
ParseDosHeader(
	_In_ PBYTE Buffer
)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)Buffer;

	// error checking for PIMAGE_DOS_HEADER
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("[-] Invalid DOS signature. Not a PE file.\n");
		return FALSE;
	}

	printf("[+] DOS Header:\n");
	printf("    e_magic:    0x%X (MZ)\n", pDosHeader->e_magic); 
	printf("    e_lfanew:   0x%X (Offset to NT Headers)\n", pDosHeader->e_lfanew); // We add this value to the base address to locate NT headers

	// DOS header was valid; caller can continue parsing
	return TRUE;
}

BOOL
ParseNtHeaders(
	_In_ PBYTE Buffer
)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)Buffer;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(Buffer + pDosHeader->e_lfanew); // pointer to IMAGE_NT_HEADERS structure

	// error checking for NT signature
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) // constant defined in Windows.h
	{
		printf("[-] Invalid NT signature. Not a PE file.\n");
		return FALSE;
	}

	printf("[+] NT Headers:\n");
	printf("    Signature:  0x%X (PE)\n", pNtHeaders->Signature); // confirms we found valid NT headers

	printf("[+] File Header:\n"); // contains basic info about the PE file
	printf("    Machine:              0x%X\n", pNtHeaders->FileHeader.Machine); // the target CPU architecture
	printf("    NumberOfSections:     %d\n", pNtHeaders->FileHeader.NumberOfSections); // prints how many sections the PE has
	printf("    TimeDateStamp:        0x%X\n", pNtHeaders->FileHeader.TimeDateStamp); // unix timestamp when the file was compiled
	printf("    SizeOfOptionalHeader: 0x%X\n", pNtHeaders->FileHeader.SizeOfOptionalHeader); // size of optional header in bytes; needed to find section headers
	printf("    Characteristics:      0x%X\n", pNtHeaders->FileHeader.Characteristics); // big flags describing the file

	printf("[+] Optional Header:\n"); // IMAGE_OPTIONAL_HEADER structure
	printf("    Magic:                0x%X (%s)\n", // identifies PE32 vs PE32+
		pNtHeaders->OptionalHeader.Magic,
		pNtHeaders->OptionalHeader.Magic == 0x20B ? "64-bit" : "32-bit" // ternary conditional operator
	);
	printf("    AddressOfEntryPoint:  0x%X\n", pNtHeaders->OptionalHeader.AddressOfEntryPoint); // RVA where execution begins
	printf("    ImageBase:            0x%llX\n", pNtHeaders->OptionalHeader.ImageBase); // preferred address where the PE wants to be loaded in memory
	printf("    SectionAlignment:     0x%X\n", pNtHeaders->OptionalHeader.SectionAlignment); // alignment of sections when loaded in memory
	printf("    FileAlignment:        0x%X\n", pNtHeaders->OptionalHeader.FileAlignment); // alignment of sections on disk
	printf("    SizeOfImage:          0x%X\n", pNtHeaders->OptionalHeader.SizeOfImage); // total size of PE when loaded in memory
	printf("    SizeOfHeaders:        0x%X\n", pNtHeaders->OptionalHeader.SizeOfHeaders); // combined size of DOS header + NT headers + section headers
	printf("    NumberOfRvaAndSizes:  %d\n", pNtHeaders->OptionalHeader.NumberOfRvaAndSizes); // number of data directories; data directories point to imports, exports, resources, etc

	return TRUE;
}

VOID
ParseSectionHeaders(
	_In_ PBYTE Buffer
)
{	// we need these to find the section headers
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)Buffer;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(Buffer + pDosHeader->e_lfanew); 
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders); // macro defined in Windows.h; calculates address of first section header
	/*
	// What this macro does internally...
	pSectionHeader = (PIMAGE_SECTION_HEADER)(
    (PBYTE)&pNtHeaders->OptionalHeader + 
    pNtHeaders->FileHeader.SizeOfOptionalHeader);
	*/
	WORD wNumSections = pNtHeaders->FileHeader.NumberOfSections; // we need to know how many sections to loop through

	printf("[+] Sections (%d):\n", wNumSections);
	printf("    %-8s %-10s %-10s %-10s %-10s\n",
		"Name", "VirtAddr", "VirtSize", "RawAddr", "RawSize"
	);
	printf("    %-8s %-10s %-10s %-10s %-10s\n",
		"----", "--------", "--------", "-------", "-------"
	);

	// we iterate through each section header
	for (WORD i = 0; i < wNumSections; i++)
	{
		printf("    %-8.8s 0x%-8X 0x%-8X 0x%-8X 0x%-8X\n",
			pSectionHeader[i].Name, // 8 byte section name, examples .text, .data, .rdata, .rsrc
			pSectionHeader[i].VirtualAddress, // RVA where section is loaded in memory
			pSectionHeader[i].Misc.VirtualSize, // size of section in memory
			pSectionHeader[i].PointerToRawData, // file offset where section data starts
			pSectionHeader[i].SizeOfRawData // size of section data on disk
		);
	}
}

// use wmain to receive wide string
INT
wmain( 
	INT    argc,
	PWCHAR argv[] // argv is PWCHAR[] instead of char*[]
)
{
	// initialize to safe values
	PBYTE pFileBuffer = NULL;
	DWORD dwFileSize = 0;

	// error checking for argc, if two values aren't given it will error out
	if (argc != 2)
	{
		wprintf(L"[!] Usage: %s <path to PE file>\n", argv[0]); // program name
		return -1;
	}

	wprintf(L"[+] Parsing: %s\n\n", argv[1]); // first argument (the PE file path)

	// function needs pointer to pointer
	if (!ReadFileIntoBuffer(argv[1], &pFileBuffer, &dwFileSize))
	{
		return -1; // exit with failure code
	}


	printf("[+] File size: %d bytes\n\n", dwFileSize); // prints file size and confirms file was read

	// if DOS header is invalid, don't try to parse NT headers
	if (!ParseDosHeader(pFileBuffer))
	{
		goto Cleanup;
	}

	printf("\n");

	if (!ParseNtHeaders(pFileBuffer))
	{
		goto Cleanup; // even on error we need to free the allocated buffer
	}

	printf("\n");

	ParseSectionHeaders(pFileBuffer);

	// single cleanup point handles all exit paths
Cleanup:
	if (pFileBuffer != NULL)
	{
		HeapFree(GetProcessHeap(), 0, pFileBuffer);
	}

	return 0;
}

