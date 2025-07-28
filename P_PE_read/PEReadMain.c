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
	//��ʼ��
	char* file_path = F_PATH;
	char* open_mode = "rb";

	//���ļ�
	FILE* file_address = open_file(file_path, open_mode);
	//�����ļ�����
	int file_size = compute_file_size(file_address);
	//�����ڴ�
	char* file_buffer = allocate_buffer(file_size);
	//д���ڴ棬�����ڴ��ַ
	file_buffer = readfile2memory(file_buffer, file_size, file_address);
	//��ӡpeͷ��Ϣ
	analysis_PE_head(file_buffer);

	//�ͷ��ڴ棬�ر��ļ���
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
	return file_buffer;//���д��ɹ��������ڴ��ַ
}

void analysis_PE_head(char* file_buffer) {
	//ʵ����PE�ļ�ͷ�����ṹ��
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;

	//char* pOptionalHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader32 = NULL;
	PIMAGE_OPTIONAL_HEADER64 pOptionalHeader64 = NULL;



	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	//ǿ������ת��
	pDosHeader = (PIMAGE_DOS_HEADER)file_buffer;
	//�ж�MZ��ʶ
	if (*((PWORD)pDosHeader) != IMAGE_DOS_SIGNATURE) {
		printf("ERROR: not a valid MZ signature\n");
		free(file_buffer);
		exit(1);
	}
	pDosHeader = (PIMAGE_DOS_HEADER)file_buffer;
	//��ӡdosͷ
	printf("=============================DOSͷ��Ϣ����===============================\n");
	printf("MZ��־��\t\t\t%04X\n", pDosHeader->e_magic);
	printf("PEƫ�ƣ�\t\t\t%08X\n", pDosHeader->e_lfanew);

	//testָ��ƫ��
	//printf("0λ��+��\t\t\t%X\n", *((short*)(file_buffer + pDosHeader->e_lfanew)));
	//printf("0λ��+��\t\t\t%08X\n", ((DWORD)file_buffer + pDosHeader->e_lfanew));

	// �ж��ǲ�����Ч��PE��־
	if (*((PWORD)(file_buffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("ERROR: not a valid PE signature\n");
		free(file_buffer);
		return;
	}
	//else { printf("PE is ok\n"); }

	//NTͷ
	pNTHeader = (PIMAGE_NT_HEADERS)(file_buffer + pDosHeader->e_lfanew);
	//��ӡ NT ͷ
	printf("=============================NTͷ��Ϣ����================================\n");
	printf("NT:\t\t\t\t%04X\n", pNTHeader->Signature);
	// ǿ������ת�� PIMAGE_FILE_HEADER�ṹ��
	pFileHeader = (PIMAGE_FILE_HEADER)((char*)pNTHeader + 4);
	// ��ӡ��׼PE�ļ�ͷ
	printf("=============================��׼PEͷ��Ϣ����============================\n");
	printf("PE_machine:\t\t\t%04X\n", pFileHeader->Machine);
	printf("NumberOfSections:\t\t%04X\n", pFileHeader->NumberOfSections);
	printf("SizeOfOptionalHeader��\t\t%04X\n", pFileHeader->SizeOfOptionalHeader);

	printf("==============================��ѡPEͷ��Ϣ����===========================\n");

	//�ж�64λ����32λ,ѡ��ǿ��ת����optional
	if (pFileHeader->Machine == 0x8664) {
		printf("64����\n");
		pOptionalHeader64 = (PIMAGE_OPTIONAL_HEADER64)((char*)pFileHeader + IMAGE_SIZEOF_FILE_HEADER);
		printf("Magic��\t\t\t\t%04X\n", pOptionalHeader64->Magic);
		printf("AddressOfEntryPoint:\t\t%08X\n", pOptionalHeader64->AddressOfEntryPoint);
		printf("ImageBase:\t\t\t%08llX\n", pOptionalHeader64->ImageBase);
		printf("SizeOfImage:\t\t\t%08X\n", pOptionalHeader64->SizeOfImage);
		printf("SizeOfHeaders:\t\t\t%08X\n", pOptionalHeader64->SizeOfHeaders);
		printf("SectionAlignment:\t\t%08X\n", pOptionalHeader64->SectionAlignment);
		printf("FileAlignment:\t\t\t%08X\n", pOptionalHeader64->FileAlignment);
	}
	else {
		printf("32����\n");
		pOptionalHeader32 = (PIMAGE_OPTIONAL_HEADER32)((char*)pFileHeader + IMAGE_SIZEOF_FILE_HEADER);
		printf("Magic��\t\t\t\t%04X\n", pOptionalHeader32->Magic);
		printf("AddressOfEntryPoint:\t\t%08X\n", pOptionalHeader32->AddressOfEntryPoint);
		printf("ImageBase:\t\t\t%08lX\n", pOptionalHeader32->ImageBase);
		printf("SizeOfImage:\t\t\t%08X\n", pOptionalHeader32->SizeOfImage);
		printf("SizeOfHeaders:\t\t\t%08X\n", pOptionalHeader32->SizeOfHeaders);
		printf("SectionAlignment:\t\t%08X\n", pOptionalHeader32->SectionAlignment);
		printf("FileAlignment:\t\t\t%08X\n", pOptionalHeader32->FileAlignment);
	}

	//ǿ������ת��
	pSectionHeader = pFileHeader->Machine == 0x8664 ? (PIMAGE_SECTION_HEADER)((char*)pOptionalHeader64 + pFileHeader->SizeOfOptionalHeader) :
		(PIMAGE_SECTION_HEADER)((char*)pOptionalHeader32 + pFileHeader->SizeOfOptionalHeader);
	printf("==============================�ڱ���Ϣ����===============================\n");
	//printf("name:%s\n", pSectionHeader->Name);
	DWORD dwNumberOfSection = pFileHeader->NumberOfSections;
	for (DWORD i = 0; i < dwNumberOfSection; i++, pSectionHeader++)
	{
		printf("=============================��%d������Ϣ��===============================\n", i + 1);
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