00007FF7A8AC5A50  push        rbp  
00007FF7A8AC5A52  push        rdi  
00007FF7A8AC5A53  sub         rsp,238h  
00007FF7A8AC5A5A  lea         rbp,[rsp+20h]  
00007FF7A8AC5A5F  mov         rdi,rsp  
00007FF7A8AC5A62  mov         ecx,8Eh  
00007FF7A8AC5A67  mov         eax,0CCCCCCCCh  
00007FF7A8AC5A6C  rep stos    dword ptr [rdi]  
00007FF7A8AC5A6E  mov         rax,qword ptr [__security_cookie (07FF7A8AD3018h)]  
00007FF7A8AC5A75  xor         rax,rbp  
00007FF7A8AC5A78  mov         qword ptr [rbp+208h],rax  
00007FF7A8AC5A7F  lea         rcx,[__06A15900_ConsoleApplication@cpp (07FF7A8AD902Ah)]  
00007FF7A8AC5A86  call        __CheckForDebuggerJustMyCode (07FF7A8AC1122h)  
00007FF7A8AC5A8B  lea         rdx,[string "flag{this_is_a_fake_flag}" (07FF7A8ACF450h)]  
00007FF7A8AC5A92  lea         rcx,[flag]  
00007FF7A8AC5A96  call        std::basic_string<char,std::char_traits<char>,std::allocator<char> >::basic_string<char,std::char_traits<char>,std::allocator<char> > (07FF7A8AC15E1h)  
00007FF7A8AC5A9B  nop  
00007FF7A8AC5A9C  mov         dword ptr [p],0  
00007FF7A8AC5AA3  mov         dword ptr [rbp+64h],0  
00007FF7A8AC5AAA  jmp         main+64h (07FF7A8AC5AB4h)  
00007FF7A8AC5AAC  mov         eax,dword ptr [rbp+64h]  
00007FF7A8AC5AAF  inc         eax  
00007FF7A8AC5AB1  mov         dword ptr [rbp+64h],eax  
00007FF7A8AC5AB4  movsxd      rax,dword ptr [rbp+64h]  
00007FF7A8AC5AB8  mov         qword ptr [rbp+1F8h],rax  
00007FF7A8AC5ABF  lea         rcx,[flag]  
00007FF7A8AC5AC3  call        std::basic_string<char,std::char_traits<char>,std::allocator<char> >::length (07FF7A8AC122Bh)  
00007FF7A8AC5AC8  mov         rcx,qword ptr [rbp+1F8h]  
00007FF7A8AC5ACF  cmp         rcx,rax  
00007FF7A8AC5AD2  jae         main+1B2h (07FF7A8AC5C02h)  
00007FF7A8AC5AD8  mov         eax,dword ptr [rbp+64h]  
00007FF7A8AC5ADB  and         eax,1  
00007FF7A8AC5ADE  cmp         eax,1  
00007FF7A8AC5AE1  jne         main+126h (07FF7A8AC5B76h)  
00007FF7A8AC5AE7  movsxd      rax,dword ptr [rbp+64h]  
00007FF7A8AC5AEB  mov         rdx,rax  
00007FF7A8AC5AEE  lea         rcx,[flag]  
00007FF7A8AC5AF2  call        std::basic_string<char,std::char_traits<char>,std::allocator<char> >::operator[] (07FF7A8AC1442h)  
00007FF7A8AC5AF7  movsx       eax,byte ptr [rax]  
00007FF7A8AC5AFA  xor         eax,42h  
00007FF7A8AC5AFD  mov         dword ptr [p],eax  
00007FF7A8AC5B00  mov         dl,30h  
00007FF7A8AC5B02  lea         rcx,[rbp+144h]  
00007FF7A8AC5B09  call        std::setfill<char> (07FF7A8AC1046h)  
00007FF7A8AC5B0E  mov         qword ptr [rbp+1F8h],rax  
00007FF7A8AC5B15  mov         edx,2  
00007FF7A8AC5B1A  lea         rcx,[rbp+168h]  
00007FF7A8AC5B21  call        std::setw (07FF7A8AC10D2h)  
00007FF7A8AC5B26  mov         qword ptr [rbp+200h],rax  
00007FF7A8AC5B2D  lea         rdx,[std::hex (07FF7A8AC1488h)]  
00007FF7A8AC5B34  mov         rcx,qword ptr [__imp_std::cout (07FF7A8AD71C0h)]  
00007FF7A8AC5B3B  call        qword ptr [__imp_std::basic_ostream<char,std::char_traits<char> >::operator<< (07FF7A8AD7160h)]  
00007FF7A8AC5B41  mov         rcx,qword ptr [rbp+200h]  
00007FF7A8AC5B48  mov         rdx,rcx  
00007FF7A8AC5B4B  mov         rcx,rax  
00007FF7A8AC5B4E  call        std::operator<<<char,std::char_traits<char>,__int64> (07FF7A8AC12F8h)  
00007FF7A8AC5B53  mov         rcx,qword ptr [rbp+1F8h]  
00007FF7A8AC5B5A  mov         rdx,rcx  
00007FF7A8AC5B5D  mov         rcx,rax  
00007FF7A8AC5B60  call        std::operator<<<char,std::char_traits<char>,char> (07FF7A8AC11A4h)  
00007FF7A8AC5B65  mov         edx,dword ptr [p]  
00007FF7A8AC5B68  mov         rcx,rax  
00007FF7A8AC5B6B  call        qword ptr [__imp_std::basic_ostream<char,std::char_traits<char> >::operator<< (07FF7A8AD7158h)]  
00007FF7A8AC5B71  jmp         main+1ADh (07FF7A8AC5BFDh)  
00007FF7A8AC5B76  movsxd      rax,dword ptr [rbp+64h]  
00007FF7A8AC5B7A  mov         rdx,rax  
00007FF7A8AC5B7D  lea         rcx,[flag]  
00007FF7A8AC5B81  call        std::basic_string<char,std::char_traits<char>,std::allocator<char> >::operator[] (07FF7A8AC1442h)  
00007FF7A8AC5B86  movsx       eax,byte ptr [rax]  
00007FF7A8AC5B89  mov         dword ptr [p],eax  
00007FF7A8AC5B8C  mov         dl,30h  
00007FF7A8AC5B8E  lea         rcx,[rbp+194h]  
00007FF7A8AC5B95  call        std::setfill<char> (07FF7A8AC1046h)  
00007FF7A8AC5B9A  mov         qword ptr [rbp+1F8h],rax  
00007FF7A8AC5BA1  mov         edx,2  
00007FF7A8AC5BA6  lea         rcx,[rbp+1B8h]  
00007FF7A8AC5BAD  call        std::setw (07FF7A8AC10D2h)  
00007FF7A8AC5BB2  mov         qword ptr [rbp+200h],rax  
00007FF7A8AC5BB9  lea         rdx,[std::hex (07FF7A8AC1488h)]  
00007FF7A8AC5BC0  mov         rcx,qword ptr [__imp_std::cout (07FF7A8AD71C0h)]  
00007FF7A8AC5BC7  call        qword ptr [__imp_std::basic_ostream<char,std::char_traits<char> >::operator<< (07FF7A8AD7160h)]  
00007FF7A8AC5BCD  mov         rcx,qword ptr [rbp+200h]  
00007FF7A8AC5BD4  mov         rdx,rcx  
00007FF7A8AC5BD7  mov         rcx,rax  
00007FF7A8AC5BDA  call        std::operator<<<char,std::char_traits<char>,__int64> (07FF7A8AC12F8h)  
00007FF7A8AC5BDF  mov         rcx,qword ptr [rbp+1F8h]  
00007FF7A8AC5BE6  mov         rdx,rcx  
00007FF7A8AC5BE9  mov         rcx,rax  
00007FF7A8AC5BEC  call        std::operator<<<char,std::char_traits<char>,char> (07FF7A8AC11A4h)  
00007FF7A8AC5BF1  mov         edx,dword ptr [p]  
00007FF7A8AC5BF4  mov         rcx,rax  
00007FF7A8AC5BF7  call        qword ptr [__imp_std::basic_ostream<char,std::char_traits<char> >::operator<< (07FF7A8AD7158h)]  
00007FF7A8AC5BFD  jmp         main+5Ch (07FF7A8AC5AACh)  
00007FF7A8AC5C02  mov         dword ptr [rbp+1E4h],0  
00007FF7A8AC5C0C  lea         rcx,[flag]  
00007FF7A8AC5C10  call        std::basic_string<char,std::char_traits<char>,std::allocator<char> >::~basic_string<char,std::char_traits<char>,std::allocator<char> > (07FF7A8AC1302h)  
00007FF7A8AC5C15  mov         eax,dword ptr [rbp+1E4h]  
00007FF7A8AC5C1B  mov         edi,eax  
00007FF7A8AC5C1D  lea         rcx,[rbp-20h]  
00007FF7A8AC5C21  lea         rdx,[__xt_z+540h (07FF7A8ACEFE0h)]  
00007FF7A8AC5C28  call        _RTC_CheckStackVars (07FF7A8AC1596h)  
00007FF7A8AC5C2D  mov         eax,edi  
00007FF7A8AC5C2F  mov         rcx,qword ptr [rbp+208h]  
00007FF7A8AC5C36  xor         rcx,rbp  
00007FF7A8AC5C39  call        __security_check_cookie (07FF7A8AC1190h)  
00007FF7A8AC5C3E  lea         rsp,[rbp+218h]  
00007FF7A8AC5C45  pop         rdi  
00007FF7A8AC5C46  pop         rbp  
00007FF7A8AC5C47  ret  