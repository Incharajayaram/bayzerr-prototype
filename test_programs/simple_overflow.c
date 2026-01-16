#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_function(char *input) {
    char buffer[10];
    int secret = 0;
    
    // Unsafe copy - classic buffer overflow
    strcpy(buffer, input);
    
    if (secret != 0) {
        printf("Secret modified! Buffer overflow successful.\n");
    } else {
        printf("Buffer contents: %s\n", buffer);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input_string>\n", argv[0]);
        return 1;
    }
    
    printf("Processing input: %s\n", argv[1]);
    vulnerable_function(argv[1]);
    
    return 0;
}

