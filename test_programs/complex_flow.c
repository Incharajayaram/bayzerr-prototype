#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int id;
    char name[20];
    int level;
} User;

void admin_panel(User *u, char *command) {
    if (u->level > 10) {
        printf("Welcome Admin %s\n", u->name);
        char cmd_buffer[32];
        
        // Potential overflow if command is long
        strcpy(cmd_buffer, command);
        
        if (strcmp(cmd_buffer, "shutdown") == 0) {
            printf("System shutting down...\n");
        }
    } else {
        printf("Access Denied for %s\n", u->name);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Usage: %s <id> <name> <level> [command]\n", argv[0]);
        return 1;
    }

    User currentUser;
    
    // Input source 1
    currentUser.id = atoi(argv[1]);
    
    // Input source 2
    strncpy(currentUser.name, argv[2], 19);
    currentUser.name[19] = '\0';
    
    // Input source 3
    currentUser.level = atoi(argv[3]);

    // Complex control flow
    if (currentUser.id == 0) {
        printf("Invalid ID\n");
        return 1;
    }

    if (currentUser.level < 0) {
        // Logical bug? Negative levels promoted to super admin?
        currentUser.level = 100; 
    }

    char *cmd = "status"; // Default command
    if (argc > 4) {
        cmd = argv[4]; // Input source 4
    }

    // Branching based on inputs
    if (currentUser.id % 2 == 0) {
        printf("Even user ID path taken.\n");
        admin_panel(&currentUser, cmd);
    } else {
        printf("Odd user ID path taken.\n");
        // Another potential vulnerability path
        if (currentUser.level > 5 && strlen(cmd) > 5) {
            printf("Command too long for odd users!\n");
        }
    }

    return 0;
}
