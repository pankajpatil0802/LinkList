
#include<windows.h>
#include<io.h>
#include <fcntl.h>

#include<stdio.h>


bool
IsPEFile(
	int irfDescripter, 
	IMAGE_DOS_HEADER* prDosHeader
	)
{
	//char chBuffer[3];
	int icRead=0;
	
	icRead = _read(irfDescripter,prDosHeader, sizeof(IMAGE_DOS_HEADER));
	if(icRead != sizeof(IMAGE_DOS_HEADER))
	{
		printf("\nError in reading........!!!!!!\n");
		return false;
	}
	//lseek(irfDescripter,prDosHeader->e_lfanew ,0);
	//_read(irfDescripter,chBuffer,2);
	//chBuffer[2]='\0';
	//lseek(irfDescripter, SEEK_SET,0);
	
	if (0x5A4D == prDosHeader -> e_magic)
	{
		printf("File is Portable Executable\n");
		return true;
	}
	else
	{
		printf("\nFile s not Portable Executable ");
		return false;
	}
	

}

bool
PrintDosHeader(
	IMAGE_DOS_HEADER *prDosHeader
	)
{
	printf("\nDosHeader");
	printf("\nMagic no:  %x",prDosHeader->e_magic);
	printf("\nE_Ifanew : %x",prDosHeader->e_lfanew);
	printf("\n------------------------------Dumping DOS Header Info--------------------------");
	printf("\n%-36s%s ","Magic number : ",prDosHeader->e_magic==0x5a4d?"MZ(Mark Zbikowski)":"-");
	printf("\n%-36s%#x","Bytes on last page of file :",prDosHeader->e_cblp);
	printf("\n%-36s%#x","Pages in file : ",prDosHeader->e_cp);
	printf("\n%-36s%#x","Relocation : ",prDosHeader->e_crlc);
	printf("\n%-36s%#x","Size of header in paragraphs : ",prDosHeader->e_cparhdr);
	printf("\n%-36s%#x","Minimum extra paragraphs needed : ",prDosHeader->e_minalloc);
	printf("\n%-36s%#x","Maximum extra paragraphs needed : ",prDosHeader->e_maxalloc);
	printf("\n%-36s%#x","Initial (relative) SS value : ",prDosHeader->e_ss);
	printf("\n%-36s%#x","Initial SP value : ",prDosHeader->e_sp);
	printf("\n%-36s%#x","Checksum : ",prDosHeader->e_csum);
	printf("\n%-36s%#x","Initial IP value : ",prDosHeader->e_ip);
	printf("\n%-36s%#x","Initial (relative) CS value : ",prDosHeader->e_cs);
	printf("\n%-36s%#x","File address of relocation table : ",prDosHeader->e_lfarlc);
	printf("\n%-36s%#x","Overlay number : ",prDosHeader->e_ovno);
	printf("\n%-36s%#x","OEM identifier : ",prDosHeader->e_oemid);
	printf("\n%-36s%#x","OEM information(e_oemid specific) :",prDosHeader->e_oeminfo);
	printf("\n%-36s%#x","RVA address of PE header : ",prDosHeader->e_lfanew);
	printf("\n===============================================================================\n");
	return true;
}

bool
ReadNtHeader(
	int irfDescripter,
	IMAGE_NT_HEADERS64 *prNtHeader
	)
{
	int icRead = 0;
	icRead = _read(irfDescripter, prNtHeader, sizeof(IMAGE_NT_HEADERS64));
	if(icRead != sizeof(IMAGE_NT_HEADERS64))
	{
		printf("\nError in reading........!!!!!!\n");
		return false;
	}
	return true;
}

bool
PrintNtHeader(
	IMAGE_NT_HEADERS64 *prNtHeader
	)
{
	printf("\n\nNTHeader");
	printf("\nSignature: %x",prNtHeader->Signature);
	printf("\n------------------------Dumping COFF/PE Header Info--------------------------");
	printf("\n%-36s%s","Signature :","PE");
	printf("\n===============================================================================\n");
	return true;
}


bool
ReadNtHeader32(
	int irfDescripter,
	IMAGE_NT_HEADERS32 *prNtHeader32
	)
{
	int icRead = 0;
	icRead = _read(irfDescripter, prNtHeader32, sizeof(IMAGE_NT_HEADERS32));
	if(icRead != sizeof(IMAGE_NT_HEADERS32))
	{
		printf("\nError in reading........!!!!!!\n");
		return false;
	}
	return true;
}

bool
ReadFileHeader(
	int irfDescripter,
	IMAGE_FILE_HEADER *prFileHeader
	)
{
	int icRead = 0;
	icRead = _read(irfDescripter, prFileHeader, sizeof(IMAGE_FILE_HEADER));
	if(icRead != sizeof(IMAGE_FILE_HEADER))
	{
		printf("\nError in reading........!!!!!!\n");
		return false;
	}
	return true;
}

bool
PrintFileHeader(
	IMAGE_FILE_HEADER *prFileHeader
	)
{
	printf("\n\nFileHeader");
	printf("\nNo of Sections:          %x", prFileHeader->NumberOfSections);
	printf("\nSize of Optional Header: %x", prFileHeader->SizeOfOptionalHeader);
	printf("\n===============================================================================\n");
	return true;
}

bool
ReadOptionalHeader(
	int irfDescripter,
	IMAGE_OPTIONAL_HEADER *prOptionalHeader
	)
{
	int icRead=0;
	icRead = _read(irfDescripter, prOptionalHeader, sizeof(IMAGE_OPTIONAL_HEADER));
	if(icRead != sizeof(IMAGE_OPTIONAL_HEADER))
	{
		printf("\nError in reading........!!!!!!\n");
		return false;
	}
	return true;
}

bool
PrintOptionalHeader64(
	IMAGE_NT_HEADERS64 *prNtHeader
	)
{
	printf("\n\nOptionHeader");
	printf("\nMagic:                    %x",prNtHeader->OptionalHeader.Magic);
	printf("\nSize of Code:             %x",prNtHeader->OptionalHeader.SizeOfCode);
	printf("\nSize of Initialised Data: %x", prNtHeader->OptionalHeader.SizeOfInitializedData);
	printf("\nAddress of Entry Point:   %x", prNtHeader->OptionalHeader.AddressOfEntryPoint);
	printf("\nImage Base:               %x", prNtHeader->OptionalHeader.ImageBase);
	printf("\nSize of Image:            %x", prNtHeader->OptionalHeader.SizeOfImage);
	printf("\nNo of RVA & Sizes:        %x", prNtHeader->OptionalHeader.NumberOfRvaAndSizes);
	printf("\n===============================================================================\n");
	return true;
}

bool
PrintOptionalHeader32(
	IMAGE_NT_HEADERS32 *prNtHeader32
	)
{
	printf("\n\nOptionHeader");
	printf("\nMagic:                    %x",prNtHeader32->OptionalHeader.Magic);
	printf("\nSize of Code:             %x",prNtHeader32->OptionalHeader.SizeOfCode);
	printf("\nSize of Initialised Data: %x", prNtHeader32->OptionalHeader.SizeOfInitializedData);
	printf("\nAddress of Entry Point:   %x", prNtHeader32->OptionalHeader.AddressOfEntryPoint);
	printf("\nImage Base:               %x", prNtHeader32->OptionalHeader.ImageBase);
	printf("\nSize of Image:            %x", prNtHeader32->OptionalHeader.SizeOfImage);
	printf("\nNo of RVA & Sizes:        %x", prNtHeader32->OptionalHeader.NumberOfRvaAndSizes);
	printf("\n===============================================================================\n");
	return true;
}


bool
ReadDataDirectory(
	int irfDescripter,
	IMAGE_DATA_DIRECTORY *prDataDirectory
	)
{
	int icRead=0;
	icRead = _read(irfDescripter, prDataDirectory, sizeof(IMAGE_DATA_DIRECTORY));
	if(icRead != sizeof(IMAGE_DATA_DIRECTORY))
	{
		printf("\nError in reading........!!!!!!\n");
		return false;
	}
	return true;
}


bool
PrintDataDirectory64(
	IMAGE_NT_HEADERS64 *prNtHeader
	)
{
	printf("\n\nData Diretories");
	printf("\nExport Directory: %x \t Size:%x ",prNtHeader->OptionalHeader.DataDirectory[0].VirtualAddress, prNtHeader->OptionalHeader.DataDirectory[0].Size);
	printf("\nImport Directory: %x \t Size:%x ",prNtHeader->OptionalHeader.DataDirectory[1].VirtualAddress, prNtHeader->OptionalHeader.DataDirectory[1].Size);
	printf("\n===============================================================================\n");
	return true;
}


bool
PrintDataDirectory32(
	IMAGE_NT_HEADERS32 *prNtHeader32
	)
{
	printf("\n\nData Diretories");
	printf("\nExport Directory: %x \t Size:%x ",prNtHeader32->OptionalHeader.DataDirectory[0].VirtualAddress, prNtHeader32->OptionalHeader.DataDirectory[0].Size);
	printf("\nImport Directory: %x \t Size:%x ",prNtHeader32->OptionalHeader.DataDirectory[1].VirtualAddress, prNtHeader32->OptionalHeader.DataDirectory[1].Size);
	printf("\n===============================================================================\n");
	return true;
}

bool
ReadSectionHeader(
	int irfDescripter,
	IMAGE_SECTION_HEADER *prSectionHeader,
	int irNosec
	)
{
	//int icRead=0;
	//icRead = 
	_read(irfDescripter ,prSectionHeader ,irNosec * sizeof(*prSectionHeader));
	//if(icRead != sizeof(*prSectionHeader))
	//{
	//	printf("\nError in reading........!!!!!!\n");
	//	_close(irfDescripter);
	//	exit(1);
	//}
	return true;
}

bool
PrintSectionHeader(
	IMAGE_SECTION_HEADER *prSectionHeader,
	int irNosec
	)
{
	int iLocalIter;
	printf("\n\nSection Header:");
	printf("\nName\tVirtual Size\tSizeofRawData\tPointerToRawData\tCharacteristics");
	for(iLocalIter = 0; iLocalIter < irNosec; iLocalIter++)
	{
		printf("\n");
		printf("%s\t  ",prSectionHeader[iLocalIter].Name);
		printf("%x\t\t  ",prSectionHeader[iLocalIter].Misc.VirtualSize);
		printf("%x\t\t  ",prSectionHeader[iLocalIter].SizeOfRawData);
		printf("%x\t\t\t",prSectionHeader[iLocalIter].PointerToRawData);
		printf("%x",prSectionHeader[iLocalIter].Characteristics);
	}
	printf("\n===============================================================================\n");
	return true;
}


int 
main(
	int argc,
	char *argv[]
	)
{
	int iNosec;
	bool boHeader;
	int iCountRead = 0;
	int ifDescripter = 0;
	int ichChoice1, iRead;
	unsigned long uslOffset;
	IMAGE_DOS_HEADER pDosHeader;
	IMAGE_NT_HEADERS64 pNtHeader;
	IMAGE_NT_HEADERS32 pNtHeader32;
	IMAGE_FILE_HEADER pFileHeader;
	IMAGE_SECTION_HEADER pSectionHeader;
	IMAGE_DATA_DIRECTORY pDataDirectory;
	IMAGE_OPTIONAL_HEADER pOptionalHeader;
	char ichChoice2, szInputReadBuffer,ch;

	//DWORD dwError, systemLocale;
	//HLOCAL hlocal = NULL; 
	//HMODULE hDll;

	//dwError = GetDlgItemInt(hwnd, IDC_ERRORCODE, NULL, FALSE);
	//systemLocale = MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL);
	//BOOL fOk = FormatMessage(
	//	FORMAT_MESSAGE_FROM_SYSTEM | 
	//	FORMAT_MESSAGE_IGNORE_INSERTS | 
	//	FORMAT_MESSAGE_ALLOCATE_BUFFER, 
	//	NULL, dwError, systemLocale, 
	//	(PTSTR) &hlocal, 
	//	0, 
	//	NULL 
	//	);
	//if (!fOk) 
	//{   // Is it a network-related error?   
	//	hDll = LoadLibraryEx(TEXT("netmsg.dll"), NULL,      DONT_RESOLVE_DLL_REFERENCES);
	//	if (hDll != NULL) 
	//	{      
	//		fOk = FormatMessage(         
	//			FORMAT_MESSAGE_FROM_HMODULE | 
	//			FORMAT_MESSAGE_IGNORE_INSERTS |
	//			FORMAT_MESSAGE_ALLOCATE_BUFFER,         
	//			hDll, dwError, systemLocale,         
	//			(PTSTR) &hlocal, 0, NULL);      
	//			FreeLibrary(hDll
	//			);   
	//	} 
	//}
	//if (fOk && (hlocal != NULL)) 
	//{
	//	SetDlgItemText(hwnd, IDC_ERRORTEXT, (PCTSTR) LocalLock(hlocal));   
	//	LocalFree(hlocal); 
	//}
	//else
	//{
	//	SetDlgItemText(hwnd, IDC_ERRORTEXT,      TEXT("No text found for this error number."));
	//}


	if (argc != 2)
	{
		printf("usage: %s filename", argv[0]);
		return 0;
	}
	ifDescripter = _open(argv[1],O_RDONLY);
	//ifDescripter = _open("C:\\Program Files (x86)\\Windows NT\\TableTextService\\TableTextService.dll",O_RDONLY);
	if( ifDescripter == -1 )
	{
		perror( "Open failed on input file\n" );
		return 0;
	}
	printf( "Open succeeded on input file\n" );
	boHeader = IsPEFile(ifDescripter, &pDosHeader);
	if(false == boHeader)
	{
		printf("Given File Is Not a PE File\n");
		_close(ifDescripter);
		return 0;
	}

//To Print Dos Header

	boHeader = PrintDosHeader(&pDosHeader);
	if(false == boHeader)
	{
		printf("\nError in printing Dos Header..!!");
		_close(ifDescripter);
		return 0;
	}

//To Print NT Header

	_lseek(ifDescripter, pDosHeader.e_lfanew, SEEK_SET);
	boHeader = ReadNtHeader(
					ifDescripter,
					&pNtHeader
					);
	if(false == boHeader)
	{
		printf("\nError in Reading NT Header..!!");
		_close(ifDescripter);
		return 0;
	}
	printf("\nNT Header is Successfully Buffered..!!");
	boHeader = PrintNtHeader(&pNtHeader);
	if(false == boHeader)
	{
		printf("\nError in Printing NT Header..!!");
		_close(ifDescripter);
		return 0;
	}

	if(0x020B == pNtHeader.OptionalHeader.Magic)
	{

//To Print File Header

		printf("\n************PE File is of PE64 Type************");
		uslOffset=(pDosHeader.e_lfanew + sizeof(DWORD));
		lseek(ifDescripter, uslOffset, SEEK_SET);

		//No Need of Reading File Header as we have read whole NT Header earlier

		/* 
		boHeader = ReadFileHeader(
						ifDescripter,
						&pFileHeader
						);
		if(false == boHeader)
		{
			printf("\nError in Reading File Header..!!");
			_close(ifDescripter);
			return 0;
		}
		*/
		boHeader = PrintFileHeader(&pNtHeader.FileHeader);//&pFileHeader
		if(false == boHeader)
		{
			printf("\nError in Printing File Header Of PE64..!!");
			_close(ifDescripter);
			return 0;
		}

//To Print Optional Header 

		uslOffset = uslOffset + sizeof(pFileHeader);
		lseek(ifDescripter, uslOffset, SEEK_SET);

		//No Need of Reading Optional Header as we have read whole NT Header earlier

		/*
		boHeader = ReadOptionalHeader(
						ifDescripter,
						&pOptionalHeader
						);
		if(false == boHeader)
		{
			printf("\nError in Reading Optional Header of PE64..!!");
		}
		*/

		boHeader = PrintOptionalHeader64(&pNtHeader);
		if(false == boHeader)
		{
			printf("\nError in Printing OPtional Header Of PE64..!!");
			_close(ifDescripter);
			return 0;
		}

// To Read and Print Data Directory

		//No Need of Reading Data Directory as we have read whole NT Header earlier

		/*
		boHeader = ReadDataDirectory(
						ifDescripter,
						&pDataDirectory
						);
		if(false == boHeader)
		{
			printf("\nError In Reading Data Directory of PE64..!!");
		}
		*/
		boHeader = PrintDataDirectory64(&pNtHeader);
		if(false == boHeader)
		{
			printf("\nError in Printing Data Directory Of PE64..!!");
			_close(ifDescripter);
			return 0;
		}

//To Print Section Header

		iNosec = pNtHeader.FileHeader.NumberOfSections;
		uslOffset = (pDosHeader.e_lfanew + sizeof(pNtHeader));
		_lseek(ifDescripter, uslOffset, SEEK_SET);
		boHeader = ReadSectionHeader(
						ifDescripter,
						&pSectionHeader,
						iNosec
						);
		if(false == boHeader)
		{
			printf("\nError in reading Section Header of PE64..!!");
			_close(ifDescripter);
			return 0;
		}
		boHeader = PrintSectionHeader(
						&pSectionHeader,
						iNosec
						);
		if(false == boHeader)
		{
			printf("\nError in Printing Section Header of PE64..!!");
			_close(ifDescripter);
			return 0;
		}
	}
	else
	{
		printf("\n************PE File is of PE32 Type************");

		_lseek(ifDescripter, pDosHeader.e_lfanew, SEEK_SET);
		boHeader = ReadNtHeader32(
						ifDescripter,
						&pNtHeader32
						);
		if(false == boHeader)
		{
			printf("\nError in Reading NT Header of PE32..!!");
			_close(ifDescripter);
			return 0;
		}

//To Print File Header

		uslOffset=(pDosHeader.e_lfanew + sizeof(DWORD));
		lseek(ifDescripter, uslOffset, SEEK_SET);

		//No Need of Reading File Header as we have read whole NTHeader32 earlier

		/*
		boHeader = ReadFileHeader(
					ifDescripter,
					&pFileHeader
					);
		if(false == boHeader)
		{
			printf("\nError in reading File Header of PE32..!!");
			_close(ifDescripter);
			return 0;
		}
		*/
		boHeader = PrintFileHeader(&pNtHeader32.FileHeader);//&pFileHeader
		if(false == boHeader)
		{
			printf("\nError in Printing File Header of PE32..!!");
			_close(ifDescripter);
			return 0;
		}

//To Print Optional Header 

		uslOffset = uslOffset + sizeof(pFileHeader);
		lseek(ifDescripter, uslOffset, SEEK_SET);

		//No Need of Reading Optional Header as we have read whole NTHeader32 earlier

		/*
		boHeader = ReadOptionalHeader(
						ifDescripter,
						&pOptionalHeader
						);
		if(false == boHeader)
		{
			printf("\nError in Reading Optional Header of PE64..!!");
			_close(ifDescripter);
			return 0;
		}
		*/

		boHeader = PrintOptionalHeader32(&pNtHeader32);
		if(false == boHeader)
		{
			printf("\nError in Printing OPtional Header of PE32..!!");
			_close(ifDescripter);
			return 0;
		}

// To Read and Print Data Directory

		//No Need of Reading Data Directory as we have read whole NTHeader32 earlier

		/*
		boHeader = ReadDataDirectory(
						ifDescripter,
						&pDataDirectory
						);
		if(false == boHeader)
		{
			printf("\nError In Reading Data Directory of PE32..!!");
			_close(ifDescripter);
			return 0;
		}
		*/

		boHeader = PrintDataDirectory32(&pNtHeader32);
		if(false == boHeader)
		{
			printf("\nError in Printing Data Directory of PE32..!!");
			_close(ifDescripter);
			return 0;
		}


//To Print Section Header

		iNosec = pNtHeader32.FileHeader.NumberOfSections;
		uslOffset = (pDosHeader.e_lfanew + sizeof(pNtHeader32));
		_lseek(ifDescripter, uslOffset, SEEK_SET);
		boHeader = ReadSectionHeader(
						ifDescripter,
						&pSectionHeader,
						iNosec
						);
		if(false == boHeader)
		{
			printf("\nError in reading Section Header of PE32..!!");
			_close(ifDescripter);
			return 0;
		}

		boHeader = PrintSectionHeader(
						&pSectionHeader,
						iNosec
						);
		if(false == boHeader)
		{
			printf("\nError in Printing Section Header of PE32..!!");
			_close(ifDescripter);
			return 0;
		}
	}
	_close(ifDescripter);
	getchar();
	return 0;

}
