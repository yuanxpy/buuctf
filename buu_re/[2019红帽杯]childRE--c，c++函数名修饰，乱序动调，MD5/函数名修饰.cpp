#include <iostream>

class R0Pxx {
public:
    R0Pxx() {
        My_Aut0_PWN((unsigned char*)"hello");
    }
private:
    char* __thiscall My_Aut0_PWN(unsigned char*);
};

char* __thiscall R0Pxx::My_Aut0_PWN(unsigned char*) {
    std::cout << __FUNCDNAME__ << std::endl;

    return 0;
}

int main()
{
    R0Pxx A;

    system("PAUSE");
    return 0;
}
