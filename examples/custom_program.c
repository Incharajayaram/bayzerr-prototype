#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/*
 * Custom vulnerable program template for Bayzzer.
 * To use: 
 * 1. Modify the logic to introduce a bug reachable only via specific input constraints.
 * 2. Run: python run_bayzzer.py --target examples/custom_program.c
 */

void process_input(char *data) {
    int value = atoi(data);
    char buffer[20];
    
    // Example: Bug reachable if value matches a magic number
    if (value == 1337) {
        printf("Magic number found!\n");
        
        // Vulnerability: Stack buffer overflow
        // Requires input longer than 20 chars but starting with "1337"
        // e.g., "1337AAAAAAAAAAAAAAAAAAAA"
        // Note: atoi stops at non-digit, so "1337AAA" parses as 1337.
        strcpy(buffer, data); 
    } else {
        printf("Value is %d. Try harder.\n", value);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    
    process_input(argv[1]);
    return 0;
}


