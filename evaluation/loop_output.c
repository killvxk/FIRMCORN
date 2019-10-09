#include<stdio.h>
#include <time.h>
#include <stdlib.h>

int main()
{
    struct  timeval  start;
    struct  timeval  end;
    unsigned long timer;
    gettimeofday(&start,NULL);
    for(int i =0 ;i<10000 ;i++)
    {
        printf("circulation : %d\n" , i);
    }
    gettimeofday(&end,NULL);
    timer = 1000000 * (end.tv_sec-start.tv_sec)+ end.tv_usec-start.tv_usec;
    printf("timer = %ld us\n",timer);
    return 0;
}