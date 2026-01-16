#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process_data(int data) {
    char buffer[20];
    
    // Taint sink: data used in memory allocation or index
    // Here we use it as an index potentially out of bounds if data is large
    if (data > 0 && data < 20) {
        buffer[data] = 'A'; // Safe if checks pass
        printf("Safe access at index %d\n", data);
    } else {
        printf("Invalid index %d\n", data);
    }

    // Unsafe use of tainted data
    // If data is very large, this could crash or write OOB
    // This represents a flow that missed the check
    int unsafe_index = data * 2; 
    if (unsafe_index >= 0) {
        // buffer is only 20 bytes
        // if data was 15, unsafe_index is 30 -> Overflow
        buffer[unsafe_index % 50] = 'X'; 
        printf("Potentially unsafe write at index %d\n", unsafe_index);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        return 1;
    }

    // Source of taint
    int input_val = atoi(argv[1]);
    
    // Taint propagation
    int intermediate_val = input_val + 5;
    int final_val = intermediate_val - 5; // Back to input_val

    process_data(final_val);

    return 0;
}
