#include<iostream>
#include<string>
#include<algorithm>
using namespace std;


int A[10];
void sort(int * A)
{
int i=0;
int n=4;
int j = 0;
while(i < n-1)
{
    j = i +1;
    while(j < n)
    {
        if (A[i] < A[j])
             swap(A[i], A[j]);
    }
    i = i + 1;
}
}


int main()
{
    sort(A);
    return 0;
}