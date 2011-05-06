#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define HUGE_SIZE       (4UL << 30)

int main(int argc, char *argv[])
{
    void *p;
    int err = 0;

    p = malloc(HUGE_SIZE);
    if (!p) {
        printf("Large malloc for %ld Bytes failed w/ %s\n",
               HUGE_SIZE, strerror(errno));
        return ENOMEM;
    }
    memset(p, 0, HUGE_SIZE);
    printf("Large malloc for %ld Bytes passed\n",
           HUGE_SIZE);
    free(p);
    sleep(30);

    return err;
}
