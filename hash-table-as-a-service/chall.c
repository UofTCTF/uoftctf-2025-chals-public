#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define NUM_HASHTABLE 20

int setup(){
    setvbuf(stdin,NULL,_IONBF,0);
    setvbuf(stdout,NULL,_IONBF,0);
}

typedef struct
{
    int key;
    char value[8];
} hashEntry;

typedef struct
{
    size_t size;
    hashEntry *entries;
} hashTable;

hashTable hashTables[NUM_HASHTABLE];
hashEntry empty = {0};

int allocHashTable(size_t size, hashTable *ptr){
    hashEntry *entries = malloc(size*sizeof(hashEntry));
    if (entries == NULL) return 1;
    ptr->size = size;
    ptr->entries = entries;
    return 0;
}

hashEntry *getHashTable(hashTable *table, int key){
    size_t index = key % (table->size);
    hashEntry *entries = table->entries;
    while (entries[index].key != key){
        if (memcmp(&empty, &(entries[index]), sizeof(hashEntry)) == 0) 
            break; // if hash entry is all 0 bytes then assume it is empty
        index = index + 1;
    }

    return &(entries[index]);
}

void menu(){
    printf("1. New Hash Table\n2. Set\n3. Get\n4. Exit\n");
}

int getChoice(){
    int result;
    printf("> ");
    scanf("%d", &result);
    getc(stdin);
    return result;
}


int main(){
    setup();
    menu();
    int repeat = 1;
    int index, key;
    size_t size;
    hashEntry *entry;
    while (repeat)
    {
        int choice = getChoice();
        switch (choice)
        {
        case 1:
            printf("Index: ");
            scanf("%d", &index);
            if (0 > index || index >= NUM_HASHTABLE) exit(0);
            if (hashTables[index].entries != NULL){
                printf("That index has been used\n");
                break;
            }
            printf("Size: ");
            scanf("%ld", &size);
            if (allocHashTable(size, &(hashTables[index]))){
                printf("Allocation failed");
                exit(0);
            }
            break;
        case 2:
            printf("Index: ");
            scanf("%d", &index);
            printf("Key: ");
            scanf("%d", &key);

            entry = getHashTable(&(hashTables[index]), key);
            entry->key = key;
            printf("Value: ");
            read(0, entry->value, 8);
            break;
        case 3:
            printf("Index: ");
            scanf("%d", &index);
            printf("Key: ");
            scanf("%d", &key);

            entry = getHashTable(&(hashTables[index]), key);
            if (entry->key != key){
                printf("Not found\n");
                break;
            }
            printf("Value: %.8s", entry->value);
            break;
        case 4:
            repeat = 0;
            break;
        default:
            printf("That is not an option\n");
            break;
        }
    }
}