#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LEN 32

int* heap_ptr = NULL;

void stack_overflow() {
    char buffer[8];
    printf("Enter input for stack overflow: ");
    //read(stdin,buffer,0x10);  // Vulnerable function, susceptible to stack overflow
    scanf("%s", buffer);
    printf("Input received: %s\n", buffer);
}


void format_string_vuln() {
    char buffer[MAX_LEN];
    printf("Enter format string: ");
    scanf("%s",buffer);    // Vulnerable function, susceptible to format string
                     // vulnerability
    printf(buffer);  // User-controlled format string
}

void add_to_heap() {
    int value;
    printf("Enter value to add to heap: ");
    scanf("%d", &value);
    heap_ptr = (int*)malloc(sizeof(int));
    if (heap_ptr != NULL) {
        *heap_ptr = value;
        printf("Value %d added to heap successfully.\n", value);
    } else {
        printf("Failed to allocate memory for heap.\n");
    }
}

void delete_from_heap() {
    if (heap_ptr != NULL) {
        free(heap_ptr);
        //heap_ptr = NULL;
        printf("Heap memory freed successfully.\n");
    } else {
        printf("Heap is empty.\n");
    }
}

int main() {
    setvbuf(stdin, 0, 2, 0);  // 2就是 _IONBF
    setvbuf(stdout, 0, 2, 0);
    int choice;

    while (1) {
        printf("\n1. Stack Overflow\n");
        printf("2. Add to Heap\n");
        printf("3. Delete from Heap\n");
        printf("4. Format String Vulnerability\n");
        printf("5. Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);
        switch (choice) {
            case 1:
                stack_overflow();
                break;
            case 2:
                add_to_heap();
                break;
            case 3:
                delete_from_heap();
                break;
            case 4:
                format_string_vuln();
                break;
            case 5:
                printf("Exiting...\n");
                exit(0);
            default:
                printf("Invalid choice! Please try again.\n");
        }
    }

    return 0;
}
