#include <bits/stdc++.h>
using namespace std;
int main()
{
	freopen("Plain.txt","r",stdin);
	freopen("Cipher.txt","w",stdout);
	map<char, char> f;
	int arr[26];
	for(int i=0;i<26;++i){
		arr[i]=i;
	}
	random_shuffle(arr,arr+26);
	for(int i=0;i<26;++i){
		f['a'+i]='a'+arr[i];
		f['A'+i]='A'+arr[i];
	}
	char ch;
	while((ch=getchar())!=EOF){
		if(f.count(ch)){
			putchar(f[ch]);
		}else{
			putchar(ch);
		}
	}
	return 0;
}
