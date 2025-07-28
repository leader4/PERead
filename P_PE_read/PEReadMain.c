#include<stdio.h>
#include<stdlib.h>
#include<malloc.h>
#include<string.h>
#include<Windows.h>


//#define F_PATH "C:\\Windows\\System32\\notepad.exe"
#define F_PATH "D:\\DiShui\\func_call\\vc6\\p_func_call\\Debug\\p_func_call.exe"

FILE* open_file(char* file_path, char* open_mode);
int compute_file_size(FILE* file_address);
char* allocate_buffer(int file_size);
char* readfile2memory(char* file_buffer, int file_size, FILE* file_address);
void analysis_PE_head(char* file_buffer);

void PrintNTHeaders() {
	//初始化
	char* file_path = F_PATH;
	char* open_mode = "rb";

	//打开文件
	FILE* file_address = open_file(file_path, open_mode);
	//计算文件长度
	int file_size = compute_file_size(file_address);
	//分配内存
	char* file_buffer = allocate_buffer(file_size);
	//写入内存，返回内存地址
	file_buffer = readfile2memory(file_buffer, file_size, file_address);
	//打印pe头信息
	analysis_PE_head(file_buffer);

	//释放内存，关闭文件流
	free(file_buffer);
	fclose(file_address);
	file_buffer = NULL;
	file_address = NULL;
}

FILE* open_file(char* file_path, char* open_mode) {
	FILE* file_address = fopen(file_path, open_mode);
	if (!file_address) {
		printf("ERROR: falid to open the file\n");
		exit(1);
	}

	return file_address;
}

int compute_file_size(FILE* file_address) {
	int size = 0;
	fseek(file_address, 0, SEEK_END);
	size = ftell(file_address);
	rewind(file_address);
	return size;
}

char* allocate_buffer(int file_size) {
	char* file_buffer = (char*)malloc(file_size);
	if (!file_buffer) {
		printf("ERROR: falid to allocate memory\n");
		exit(1);
	}
	memset(file_buffer, 0, file_size);
	return file_buffer;
}

char* readfile2memory(char* file_buffer, int file_size, FILE* file_address) {
	if (!fread(file_buffer, 1, file_size, file_address)) {
		printf("ERROR: faild to read file to memory\n");
		exit(1);
	}
	return file_buffer;//如果写入成功，返回内存地址
}

void analysis_PE_head(char* file_buffer) {
	//实例化PE文件头几个结构体
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;

	//char* pOptionalHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader32 = NULL;
	PIMAGE_OPTIONAL_HEADER64 pOptionalHeader64 = NULL;



	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	//强制类型转换
	pDosHeader = (PIMAGE_DOS_HEADER)file_buffer;
	//判断MZ标识
	if (*((PWORD)pDosHeader) != IMAGE_DOS_SIGNATURE) {
		printf("ERROR: not a valid MZ signature\n");
		free(file_buffer);
		exit(1);
	}
	pDosHeader = (PIMAGE_DOS_HEADER)file_buffer;
	//打印dos头
	printf("=============================DOS头信息如下===============================\n");
	printf("MZ标志：\t\t\t%04X\n", pDosHeader->e_magic);
	printf("PE偏移：\t\t\t%08X\n", pDosHeader->e_lfanew);

	//test指针偏移
	//printf("0位置+：\t\t\t%X\n", *((short*)(file_buffer + pDosHeader->e_lfanew)));
	//printf("0位置+：\t\t\t%08X\n", ((DWORD)file_buffer + pDosHeader->e_lfanew));

	// 判断是不是有效的PE标志
	if (*((PWORD)(file_buffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("ERROR: not a valid PE signature\n");
		free(file_buffer);
		return;
	}
	//else { printf("PE is ok\n"); }

	//NT头
	pNTHeader = (PIMAGE_NT_HEADERS)(file_buffer + pDosHeader->e_lfanew);
	//打印 NT 头
	printf("=============================NT头信息如下================================\n");
	printf("NT:\t\t\t\t%04X\n", pNTHeader->Signature);
	// 强制类型转换 PIMAGE_FILE_HEADER结构体
	pFileHeader = (PIMAGE_FILE_HEADER)((char*)pNTHeader + 4);
	// 打印标准PE文件头
	printf("=============================标准PE头信息如下============================\n");
	printf("PE_machine:\t\t\t%04X\n", pFileHeader->Machine);
	printf("NumberOfSections:\t\t%04X\n", pFileHeader->NumberOfSections);
	printf("SizeOfOptionalHeader：\t\t%04X\n", pFileHeader->SizeOfOptionalHeader);

	printf("==============================可选PE头信息如下===========================\n");

	//判断64位还是32位,选择强制转换的optional
	if (pFileHeader->Machine == 0x8664) {
		printf("64程序\n");
		pOptionalHeader64 = (PIMAGE_OPTIONAL_HEADER64)((char*)pFileHeader + IMAGE_SIZEOF_FILE_HEADER);
		printf("Magic：\t\t\t\t%04X\n", pOptionalHeader64->Magic);
		printf("AddressOfEntryPoint:\t\t%08X\n", pOptionalHeader64->AddressOfEntryPoint);
		printf("ImageBase:\t\t\t%08llX\n", pOptionalHeader64->ImageBase);
		printf("SizeOfImage:\t\t\t%08X\n", pOptionalHeader64->SizeOfImage);
		printf("SizeOfHeaders:\t\t\t%08X\n", pOptionalHeader64->SizeOfHeaders);
		printf("SectionAlignment:\t\t%08X\n", pOptionalHeader64->SectionAlignment);
		printf("FileAlignment:\t\t\t%08X\n", pOptionalHeader64->FileAlignment);
	}
	else {
		printf("32程序\n");
		pOptionalHeader32 = (PIMAGE_OPTIONAL_HEADER32)((char*)pFileHeader + IMAGE_SIZEOF_FILE_HEADER);
		printf("Magic：\t\t\t\t%04X\n", pOptionalHeader32->Magic);
		printf("AddressOfEntryPoint:\t\t%08X\n", pOptionalHeader32->AddressOfEntryPoint);
		printf("ImageBase:\t\t\t%08lX\n", pOptionalHeader32->ImageBase);
		printf("SizeOfImage:\t\t\t%08X\n", pOptionalHeader32->SizeOfImage);
		printf("SizeOfHeaders:\t\t\t%08X\n", pOptionalHeader32->SizeOfHeaders);
		printf("SectionAlignment:\t\t%08X\n", pOptionalHeader32->SectionAlignment);
		printf("FileAlignment:\t\t\t%08X\n", pOptionalHeader32->FileAlignment);
	}

	//强制类型转换
	pSectionHeader = pFileHeader->Machine == 0x8664 ? (PIMAGE_SECTION_HEADER)((char*)pOptionalHeader64 + pFileHeader->SizeOfOptionalHeader) :
		(PIMAGE_SECTION_HEADER)((char*)pOptionalHeader32 + pFileHeader->SizeOfOptionalHeader);
	printf("==============================节表信息如下===============================\n");
	//printf("name:%s\n", pSectionHeader->Name);
	DWORD dwNumberOfSection = pFileHeader->NumberOfSections;
	for (DWORD i = 0; i < dwNumberOfSection; i++, pSectionHeader++)
	{
		printf("=============================第%d个节信息：===============================\n", i + 1);
		printf("section_name:");
		for (DWORD j = 0; j < IMAGE_SIZEOF_SHORT_NAME; j++)
		{
			printf("%c", pSectionHeader->Name[j]);
		}
		printf("\n");
		printf("Misc:\t\t\t\t%08X\n", pSectionHeader->Misc);
		printf("VirtualAddress:\t\t\t%08X\n", pSectionHeader->VirtualAddress);
		printf("SizeOfRawData:\t\t\t%08X\n", pSectionHeader->SizeOfRawData);
		printf("PointerToRawData:\t\t%08X\n", pSectionHeader->PointerToRawData);
		printf("Characteristics:\t\t%08X\n", pSectionHeader->Characteristics);
	}
}

int main() {
	PrintNTHeaders();
	return 0;
}