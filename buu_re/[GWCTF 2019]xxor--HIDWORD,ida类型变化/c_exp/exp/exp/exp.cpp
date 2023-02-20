#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>

int main()
{
    unsigned int a1[6];
    unsigned int temp[2] = { 0 };
    unsigned int data[4] = { 2,2,3,4 };
    int sum = 0;
    a1[0] = 0xDF48EF7E;
    a1[5] = 0x84F30420;
    a1[1] = 550153460;
    a1[2] = 3774025685;
    a1[3] = 1548802262;
    a1[4] = 2652626477;
    for (int i = 0; i < 5; i += 2) {
        temp[0] = a1[i];
        temp[1] = a1[i + 1];
        sum = 1166789954 * 64;
        for (int i = 63; i >= 0; i--) {
            temp[1] -= (temp[0] + sum + 20) ^ ((temp[0] << 6) + data[2]) ^ ((temp[0] >> 9) + data[3]) ^ 0x10;
            temp[0] -= (temp[1] + sum + 11) ^ ((temp[1] << 6) + data[0]) ^ ((temp[1] >> 9) + data[1]) ^ 0x20;
            sum -= 1166789954;
        }
        a1[i] = temp[0];
        a1[i + 1] = temp[1];
    }
    for (int i = 0; i < 6; i++) printf("%x", a1[i]);

}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
