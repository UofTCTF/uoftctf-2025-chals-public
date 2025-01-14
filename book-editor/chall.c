#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char *book;
size_t bookSize;

int setup(){
    setvbuf(stdin,NULL,_IONBF,0);
    setvbuf(stdout,NULL,_IONBF,0);
}

void menu(){
    printf("1. Edit Book\n2. Read Book\n3. Exit\n");
}

int getChoice(){
    int result;
    printf("> ");
    scanf("%d", &result);
    while (getchar() != '\n');
    return result;
}

void editBook(){
    unsigned int offset;
    printf("Where do you want to edit: ");
    scanf("%d", &offset);
    while (getchar() != '\n');
    if (offset >= bookSize) {
        printf("Please dont edit ouside of the book.");
        return;
    }
    printf("What do you want to edit: ");
    printf("%p", - offset + bookSize - 1);
    read(0, book + offset, - offset + bookSize - 1);
}

void readBook(){
    printf("Here is your book: %s\n", book);
}

int main(){
    setup();
    printf("How long will your book be: ");
    scanf("%ld", &bookSize);
    book = malloc(bookSize);

    printf("Contents of the book: ");
    read(0, book, bookSize);

    int repeat = 1;
    while (repeat)
    {
        menu();
        int choice = getChoice();
        switch (choice)
        {
        case 1:
            editBook();
            break;
        case 2:
            readBook();
            break;
        case 3:
            repeat = 0;
            break;
        default:
            printf("That is not an option\n");
            break;
        }
    }
}