

#include <stdio.h>
#include <time.h>
#include <stdlib.h>

//Nonrecursive quicksort
void quicksort(int a[], int n)
{
#define STACK_MAX 32 //the space complexity of quicksort is O(logN), so 32 is enough!
#define SWAP(a, b) {int temp = a; a = b; b = temp;}

        int low[STACK_MAX]; //low position stack
        int high[STACK_MAX]; // high position stack
        int top = -1; //stack top

        top++;
        low[top] = 0;
        high[top] = n - 1;

        while(top >= 0) // stack is not empty
        {
                int L = low[top];
                int R = high[top];
                top--;

                //printf("TOP:%d,L:%d,R:%d\n", top, L, R);

                if( L < R)
                {
                        //partion
                        SWAP(a[L], a[L + rand() % ( R - L + 1)]);
                       
                        int i;
                        int m = L;
                        for(i = L + 1; i <= R; ++i)
                        {       
                                if(a[i] < a[L])
                                {
                                        ++m;
                                        SWAP(a[m], a[i]);
                                }
                        }
                        SWAP(a[m], a[L]);
                        printf("%d\n" , a[m]);
                       //left part entering stack
                        if(L < m - 1)
                        {
                                top++;
                                low[top] = L;
                                high[top] = m - 1;
                        }
                        printf("%d\n" , low[top]);
                        printf("%d\n" , high[top]);
                        //rigth part entering stack
                        if(m + 1 < R)
                        {
                                top++;
                                low[top] = m + 1;
                                high[top] = R;
                        }
                }
        }
}

void print(int a[], int n)
{
        int i;
        for(i = 0; i < n; ++i)
                printf("%d ", a[i]);
        printf("\n");
}

int* init_array(int n)
{
        int i;
        int *a = (int*)malloc(sizeof(int) * n);
        for(i = 0; i < n; ++i)
        {
                a[i] = rand() % n;
                //printf("%d\n" , a[i]);
        }
        return a;
}

void free_array(int *a)
{
        free(a);
}

int main(int argc, char** argv)
{
        srand(time(NULL));
        const int n = 1000;
        int *a = init_array(n);
        struct  timeval  start;
        struct  timeval  end;
        unsigned long timer;
        gettimeofday(&start,NULL);
        quicksort(a, n);
        gettimeofday(&end,NULL);
        timer = 1000000 * (end.tv_sec-start.tv_sec)+ end.tv_usec-start.tv_usec;
        free_array(a);
        printf("timer = %ld us\n",timer);
        return 0;
}