// doswfsearch.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "windows.h"
#include <fstream>
#include <vector>
using namespace std;

typedef struct {
	byte Version;
	int  FileSize;
	LPVOID BaseAddr;
	bool Compressed;
	//bool Dirty;
} CWSHeader;

vector<CWSHeader> headers;


bool contains(char *begin, int size, char *sub, size_t len) {
	char *end = begin + size - len;
	for (char *p = begin; p < end; p++) {
		if (memcmp(p, sub, len) == 0) {
			return true;
		}
	}
	return false;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		printf("invalid arguments");
		return -1;
	}
	DWORD pid;
	sscanf_s(argv[1], "%d", &pid);
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
	if (hProcess == NULL) {
		printf("unable to open process :%d", pid);
		return -1;
	}

	//get page size
	SYSTEM_INFO si;
	GetSystemInfo(&si);

	//check 32bit or 64bit
	//BOOL isWow64 = false;
	//IsWow64Process(hProcess, &isWow64);
	CWSHeader instance;
	//char *domain = "www.doswf.com";
	//size_t domainLen = strlen(domain);
	SIZE_T bytesRead;

	MEMORY_BASIC_INFORMATION info;
	//std::vector<char> chunk;
	char *chunk = NULL;
	char* p = (char *)si.lpMinimumApplicationAddress;
	while (p < si.lpMaximumApplicationAddress)
	{
		if (VirtualQueryEx(hProcess, p, &info, sizeof(info)))
		{
			if (info.Protect == PAGE_READWRITE && info.State == MEM_COMMIT) {
				p = (char*)info.BaseAddress;
				chunk = (char *)realloc(chunk, info.RegionSize);
				if (chunk == NULL) {
					printf("can't malloc space:%lld", info.RegionSize);
					return -1;
				}
				//chunk.resize(info.RegionSize);
				
				if (ReadProcessMemory(hProcess, p, (LPVOID)chunk, info.RegionSize, &bytesRead))
				{
					for (uint64_t i = 0; i < bytesRead - 8; ) {
						if ((chunk[i] == 'F' || chunk[i]=='C') && chunk[i + 1] == 'W' && chunk[i + 2] == 'S') {
							instance.Version = chunk[i + 3];
							memcpy(&instance.FileSize, &chunk[i + 4], 4);
							instance.BaseAddr = p + i;
							instance.Compressed = chunk[i] == 'C';
							/*if (!instance.Compressed) {
								instance.Dirty = contains((char *)chunk+i, instance.FileSize, domain, domainLen);
							}*/
							
							headers.push_back(instance);
							i += 8;
						}
						else {
							i++;
						}
					}
				}
			}
			p += info.RegionSize;
		} else {
			if (GetLastError() == ERROR_INVALID_PARAMETER) {
				//Address specifies an address above the highest memory address accessible to the process
				break;
			}
			else {
				printf("VirtualQueryEx error: %d\n", GetLastError());
			}
		}
	}
	
	printf(" No\tVersion\t     FileSize\tCompressed\tBaseAddr\n");
	for (uint32_t i = 0; i < headers.size(); i++) {
		printf("%3d\t%7d\t%13d\t%10c\t%llx\n",
			i, 
			headers[i].Version, 
			headers[i].FileSize, 
			headers[i].Compressed ? 'Y' : 'N',
			(uint64_t)headers[i].BaseAddr);
		chunk = (char *)realloc(chunk, headers[i].FileSize);
		ReadProcessMemory(hProcess, headers[i].BaseAddr, chunk, headers[i].FileSize, &bytesRead);
		if (bytesRead != headers[i].FileSize) {
			printf("read process memory err:%lld != %d\n", bytesRead, headers[i].FileSize);
		}
		char szFile[256];
		sprintf_s(szFile, "%d.swf", i);
		ofstream fs(szFile, ios_base::out|ios_base::binary);
		fs.write(chunk, headers[i].FileSize);
		fs.close();
	}
	if (chunk) free(chunk);
    return 0;
}

