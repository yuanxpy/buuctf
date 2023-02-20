#include<Windows.h>
#include<iostream>
#include<ctime>
#include<cstdio>
#include<cstring>
#include<cstdlib>
using namespace std;
int map[100],c=2;
int key[7]={'b','k','d','c','e','w'};
unsigned int ks[6]={0x8c2c133a,0xf74cb3f6,0xfedfa6f2,0xab293e3b,0x26cf8a2a,0x88a1f279};//{0x8c2cecc5,0xf74cb3f6,0xfedf590d,0xab293e3b,0x26cf75d5,0x88a1f279};
FARPROC proc=NULL;
int initHook()
{
	HMODULE hModule=LoadLibraryA("Kernel32.dll");
	if(hModule)
	{
		proc=GetProcAddress(hModule,"IsDebuggerPresent");
		if(proc==NULL)
			return -1;
	}
	return 0;
}
PDWORD update()
{
	if(initHook()!=0)
		exit(-1);
	HANDLE hProcess=GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER dos_header=(PIMAGE_DOS_HEADER)hProcess;
	PIMAGE_NT_HEADERS nt_header=(PIMAGE_NT_HEADERS)(dos_header->e_lfanew+(DWORD)hProcess);
	IMAGE_OPTIONAL_HEADER* opt_header=&(nt_header->OptionalHeader);
	PIMAGE_IMPORT_DESCRIPTOR iat=(PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hProcess+opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	while(iat->FirstThunk)
	{
		PIMAGE_THUNK_DATA data=(PIMAGE_THUNK_DATA)(iat->FirstThunk+(DWORD)hProcess);
		while(data->u1.Function)
		{
			if(IMAGE_SNAP_BY_ORDINAL(data->u1.AddressOfData))
			{
				data++;
				continue;
			}
			if((DWORD)proc==data->u1.Function)
				return &data->u1.Function;
			data++;
		}
		iat++;
	}
	return NULL;
}
PDWORD table_addr=NULL;
int writeAddr(DWORD addr)
{
	if(table_addr==NULL)
		table_addr=update();
	DWORD dwOldProtect;
	MEMORY_BASIC_INFORMATION mbi_thunk;
	VirtualQuery(table_addr,&mbi_thunk,sizeof(MEMORY_BASIC_INFORMATION));
	VirtualProtect(mbi_thunk.BaseAddress,mbi_thunk.RegionSize,PAGE_READWRITE,&mbi_thunk.Protect);
	*table_addr=(DWORD)addr;
	VirtualProtect(mbi_thunk.BaseAddress,mbi_thunk.RegionSize,mbi_thunk.Protect,&dwOldProtect);
	return 0;
}
bool WINAPI CallBackProc()
{
	writeAddr((DWORD)proc);
	map[0]=2;c--;
	key[0]='a';
	key[1]='k';
	key[2]='e';
	key[3]='y';
	key[4]='e';
	key[5]='z';
	if(IsDebuggerPresent())
	{
		MessageBoxW(NULL,L"U R Using Debugger!",L"U Suck!",MB_OK);
		return true;
	}
	return false;
}
void sleep()
{
	sleep();
}
int checkDebug()
{
	if(*((unsigned char *)(*(DWORD*)(__readfsdword(0x18)+0x30))+0x2))
		sleep();
	return 0;
}
int doit=writeAddr((DWORD)CallBackProc),dd=checkDebug();
bool encode(char* ur_flag)
{
	unsigned int k=0,bk=0;   
	for(int i=0;i<strlen(ur_flag);i+=4)
	{
		k=(((int)ur_flag[i])<<24)|(((int)ur_flag[i+1])<<16)|(((int)ur_flag[i+2])<<8)|((int)ur_flag[i+3]);
		k=(k>>key[i/4]) | (k<<(32-key[i/4]));
		_asm
		{
			call sub2
			_emit 0xEB
			jmp label2
		sub2:
			add dword ptr[esp],1
			retn
		label2:
		}
		k=((~(k>>16))&0x0000ffff) | (k<<16);
		k=(1<<key[i/4])^k;
		_asm
		{
			call sub7
			_emit 0xE8
			jmp label7
		sub7:
			add dword ptr[esp],1
			retn
		label7:
		}
		if(i>0)
			k^=bk;
		bk=k;
		if(k!=ks[i/4])
			return false;
	}
	return true;
}
void genKey()
{
	int len=20,keylen=6,maxium=0;
	int before;
	_asm
	{
		call sub1
		_emit 0xE8
		jmp label1
	sub1:
		add dword ptr[esp],1
		retn
	label1:
	}
	srand(time(NULL));
	for(int i=1;i<=len;i++)
	{
		map[i]=map[i-1]+rand()%5;
		_asm
		{
			call sub3
			_emit 0xE8
			jmp label3
		sub3:
			add dword ptr[esp],1
			retn
		label3:
		}
		maxium=maxium>map[i]?maxium:map[i];
	}
	_asm
	{
		call sub4
		_emit 0xE8
		jmp label4
	sub4:
		add dword ptr[esp],1
		retn
	label4:
	}
	before=time(NULL);
	_asm
	{
		call sub5
		_emit 0xE8
		jmp label5
	sub5:
		add dword ptr[esp],1
		retn
	label5:
	}
	for(int i=0;i<keylen;i++)
	{
		int step=0;
		long long t=time(NULL);
		int delta=t-before;
		_asm
		{
			call sub6
			_emit 0xE8
			jmp label6
		sub6:
			add dword ptr[esp],1
			retn
		label6:
		}
		if(delta>maxium)
			return;
	
		for(int j=0;j<=len;j++)
			if(delta<=map[j])
			{
				step=map[j];
				_asm
				{
					call sub8
					_emit 0xE8
					jmp label8
				sub8:
					add dword ptr[esp],1
					retn
				label8:
				}
				break;
			}
		_asm
		{
			call sub9
			_emit 0xE8
			jmp label9
		sub9:
			add dword ptr[esp],1
			retn
		label9:
		}
		key[i]=(key[i]*c+step+i*3)%32;
		_asm
		{
			call sub10
			_emit 0xE8
			jmp label10
		sub10:
			add dword ptr[esp],1
			retn
		label10:
		}
		before=t;
	}
}

/*void decode()
{
	unsigned int k=0,bk=0;
	for(int i=5;i>=0;i--)
		if(i>0)
			ks[i]^=ks[i-1];
	for(int i=0;i<24;i+=4)
	{
		k=ks[i/4];
		k=(1<<key[i/4])^k;
		k=((k>>16)) | ((~(k<<16))&0xffff0000);
		k=((k<<key[i/4])) | (k>>(32-key[i/4]));
		printf("%X\n",k);
	}
}*/
int main()
{
	char ur_flag[50];
	cout<<"please input your flag:"<<endl;
	cin>>ur_flag;
	if(IsDebuggerPresent())
	{
		cout<<"U suck! 233333"<<endl;
		Sleep(2000);
		exit(0);
	}
	if(strlen(ur_flag)!=24)
	{
		cout<<"Wrong!"<<endl;
		Sleep(2000);
		exit(0);
	}
	genKey();
	bool flag=encode(ur_flag);
	//decode();
	if(flag)
	{
		cout<<"U did it!"<<endl<<"GJ!"<<endl;
		system("pause");
		exit(0);
	}
	cout<<"Wrong!"<<endl;
	Sleep(2000);
    return 0;
}
