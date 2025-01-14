#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <omp.h>
#include <iostream>


#define _PyHASH_XXPRIME_1 ((Py_uhash_t)11400714785074694791ULL)
#define _PyHASH_XXPRIME_2 ((Py_uhash_t)14029467366897019727ULL)
#define _PyHASH_XXPRIME_5 ((Py_uhash_t)2870177450012600261ULL)
#define _PyHASH_XXPRIME_1_INV ((Py_uhash_t)614540362697595703ULL)
#define _PyHASH_XXROTATE(x) ((x << 31) | (x >> 33))  /* Rotate left 31 bits */
#define _PyHASH_XXROTATE_INV(x) ((x >> 31) | (x << 33))  /* Rotate right 31 bits */

#define HASHED_SIZE (256ULL*256ULL*256ULL*32ULL) // i dont have enough memory for a real 50/50 split


// stolen from stack overflow
class ProgressBar{
 private:
  size_t total_work;    ///< Total work to be accomplished
  size_t next_update;   ///< Next point to update the visible progress bar
  size_t call_diff;     ///< Interval between updates in work units
  size_t work_done;
  uint16_t old_percent;   ///< Old percentage value (aka: should we update the progress bar) TODO: Maybe that we do not need this

  ///Clear current line on console so a new progress bar can be written
  void clearConsoleLine() const {
    std::cerr<<"\r\033[2K"<<std::flush;
  }

 public:
  ///@brief Start/reset the progress bar.
  ///@param total_work  The amount of work to be completed, usually specified in cells.
  void start(size_t total_work, int num_threads){
    this->total_work = total_work;
    next_update      = 0;
    call_diff        = (total_work/200)/num_threads;
    old_percent      = 0;
    work_done        = 0;
    clearConsoleLine();
  }

  ///@brief Update the visible progress bar, but only if enough work has been done.
  ///
  ///Define the global `NOPROGRESS` flag to prevent this from having an
  ///effect. Doing so may speed up the program's execution.
  void update(size_t work_done0){
    //Provide simple way of optimizing out progress updates
    #ifdef NOPROGRESS
      return;
    #endif

    //Quick return if this isn't the main thread
    if(omp_get_thread_num()!=0)
      return;

    //Update the amount of work done
    work_done = work_done0;

    //Quick return if insufficient progress has occurred
    if(work_done<next_update)
      return;

    //Update the next time at which we'll do the expensive update stuff
    next_update += call_diff;

    //Use a uint16_t because using a uint8_t will cause the result to print as a
    //character instead of a number
    uint16_t percent = (uint8_t)(work_done*omp_get_num_threads()*100/total_work);

    //Handle overflows
    if(percent>100)
      percent=100;

    //Update old_percent accordingly
    old_percent=percent;

    //Print an update string which looks like this:
    //  [================================================  ] (96% - 4 threads)
    std::cerr<<"\r\033[2K["
             <<std::string(percent/2, '=')<<std::string(50-percent/2, ' ')
             <<"] ("
             <<percent<<"% - "
             <<omp_get_num_threads()<< " threads)"<<std::flush;
  }

  ///Increment by one the work done and update the progress bar
  ProgressBar& operator++(){
    //Quick return if this isn't the main thread
    if(omp_get_thread_num()!=0)
      return *this;

    work_done++;
    update(work_done);
    return *this;
  }
};


typedef size_t Py_uhash_t;

typedef struct {
    Py_uhash_t hash;
    u_int32_t hashed;
} hashEntry;

void printHex(char *buf, int len){
    for (int i = 0; i < len; i++)
    {
        printf("%02hhX", buf[i]);
    }
}

// does the forward hashing with len inp
Py_uhash_t forwardHalfHash(unsigned char *inp, int len){
    Py_uhash_t acc = _PyHASH_XXPRIME_5;
    for (int i = 0; i < len - 1; i++) {
        Py_uhash_t lane = inp[i];
        acc += lane * _PyHASH_XXPRIME_2;
        acc = _PyHASH_XXROTATE(acc);
        acc *= _PyHASH_XXPRIME_1;
    }
    acc += inp[len-1] * _PyHASH_XXPRIME_2;
    return acc;
}

Py_uhash_t backwardHalfHash(unsigned char *inp, int len, int totalLen, Py_uhash_t target){
    Py_uhash_t acc = target;
    acc -= totalLen ^ (_PyHASH_XXPRIME_5 ^ 3527539UL);
    for (int i = len - 1; i >= 0; i--) {
        acc *= _PyHASH_XXPRIME_1_INV;
        acc = _PyHASH_XXROTATE_INV(acc);
        acc -= inp[i] *_PyHASH_XXPRIME_2;
    }
    return acc;
}

void insertHashTable(hashEntry *table, Py_uhash_t key, u_int32_t entry){
    size_t index = key % (HASHED_SIZE * 3);
    while (table[index].hash != 0 || table[index].hashed != 0){
        index = (index + 1) % (HASHED_SIZE * 3);
    }

    table[index].hash = key;
    table[index].hashed = entry;
}

hashEntry *getHashTable(hashEntry *table, Py_uhash_t key){
    size_t index = key % (HASHED_SIZE * 3);
    while (table[index].hash != key){
        if (table[index].hash == 0 || table[index].hashed == 0) 
            return NULL;
        index = (index + 1) % (HASHED_SIZE * 3);
    }

    return &(table[index]);
}

int main(){
    hashEntry *hashTable = (hashEntry *)malloc(sizeof(hashEntry) * HASHED_SIZE * 3);
    if(hashTable == NULL){
        perror("Error mallocing hashTable");
        exit(1);
    }
    memset(hashTable, 0, sizeof(hashEntry) * HASHED_SIZE * 3);

    ProgressBar pg;
    pg.start(HASHED_SIZE, 1);

    for (size_t i = 0; i < HASHED_SIZE; i++)
    {
        pg.update(i);
        Py_uhash_t hash = forwardHalfHash((unsigned char *)&i, 4);
        insertHashTable(hashTable, hash, i);
    }

    printf("\nFinish filling HashTable\n");

    const Py_uhash_t target = 8056584164296638515; // hash(tuple(ADMIN)) should be the same on all the newer python versions

    pg.start(__UINT64_MAX__ / HASHED_SIZE, omp_get_max_threads());

    bool found = false;
    #pragma omp parallel for shared(found)
    for (size_t i = 0; i < __UINT64_MAX__ / HASHED_SIZE; i++)
    {
        if (found) continue;
        pg.update(i);
        size_t toHash = i << 5;
        Py_uhash_t hash = backwardHalfHash((unsigned char *)&toHash, 5, 8, target);
        hashEntry *res;
        if ((res = getHashTable(hashTable, hash)) != NULL){
            #pragma omp critical
            {
                size_t tmp = toHash;
                *(char *) &tmp |=  ((char *)(&(res->hashed)))[3];
                printf("\nFound preimage: ");
                printHex((char *)&res->hashed, 3);
                printHex((char *)&tmp, 5);
                printf("\n");
                //found = true;
            }
        }
    }

    free(hashTable);
}
