#include <Windows.h>
#include <iostream>
#include <libloaderapi.h>

using namespace std;

int main(int argc, char* argv[])
{
    const char* funcName = "GameObject";

    HMODULE hDLL = LoadLibrary(TEXT("D:\\desktop\\ctf题目\\buu_ctf\\buu_re\\[2019红帽杯]Snake\\attachment\\Snake\\Snake_Data\\Plugins\\Interface.dll"));
    if (hDLL != NULL)
    {
        cout << "Load Success!" << endl;
        typedef int(_cdecl* FuncPtr)(int);
        FuncPtr func = (FuncPtr)GetProcAddress(hDLL, funcName);
        func(atoi(argv[1]));
    }
    else
    {
        cout << "Load Failed!" << endl;
    }


    system("PAUSE");
    return 0;
}