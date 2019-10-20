#include<stdio.h>
#include <time.h>
#include <stdlib.h>


void loop_outputs()
{
    for(int i =0 ;i<100000 ;i++)
    {
        printf("circulation : %d\n" , i);
        puts("print success");
    }
}

int main()
{
    struct  timeval  start;
    struct  timeval  end;
    unsigned long timer;
    gettimeofday(&start,NULL);
    loop_outputs();
    gettimeofday(&end,NULL);
    timer = 1000000 * (end.tv_sec-start.tv_sec)+ end.tv_usec-start.tv_usec;
    printf("timer = %ld us\n",timer);
    return 0;
}