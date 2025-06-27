#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    int *testValue = malloc(sizeof(int));
    *testValue = 12345;
    printf("Test value address: %p\n", (void*)testValue);
    printf("Test value: %d\n", *testValue);
    while(1) {
        sleep(2);
        printf("Test value: %d\n", *testValue);
    }
    return 0;
}
