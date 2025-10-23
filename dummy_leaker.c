//go:build ignore
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>


#define MAX_OBJECTS 16

#define NSECS_IN_SEC 1000000000


typedef struct {
  char *name;
  size_t n_active;
  size_t n_leaked;
  void *buf[MAX_OBJECTS];
  float leak_prob;
  void *(*make)(size_t);
  void (*free)(void *);
} obj_map_t;

void *make_obj1(size_t size)
{
  return malloc(size);
}

void free_obj1(void *obj)
{
  free(obj);
}

void *make_obj2(size_t size)
{
  return malloc(size);
}

void free_obj2(void *obj)
{
  free(obj);
}

void *make_obj3(size_t size)
{
  return malloc(size);
}

void free_obj3(void *obj)
{
  free(obj);
}

static obj_map_t obj1 = {
  .name = "obj1",
  .n_active = 0,
  .n_leaked = 0,
  .buf = {0},
  .leak_prob = 0.5,
  .make = make_obj1,
  .free = free_obj1,
};

static obj_map_t obj2 = {
  .name = "obj2",
  .n_active = 0,
  .n_leaked = 0,
  .buf = {0},
  .leak_prob = 0.1,
  .make = make_obj2,
  .free = free_obj2,
};

static obj_map_t obj3 = {
  .name = "obj3",
  .n_active = 0,
  .n_leaked = 0,
  .buf = {0},
  .leak_prob = 0.0,
  .make = make_obj3,
  .free = free_obj3,
};

float randf()
{
  return (float)rand() / (float)RAND_MAX;
}


void do_object(obj_map_t *obj)
{
  if (obj->n_active == MAX_OBJECTS) {
    // free one of them
    int idx = rand() % MAX_OBJECTS;
    obj->free(obj->buf[idx]);
    obj->buf[idx] = NULL;
    obj->n_active -= 1;
  } else {
    if (rand() % 5 >= 2) {
      // alloc
      void *data = obj->make(rand() % 256);
      int i;
      if (randf() < obj->leak_prob) {
        // forget to save it, thus to free it
        // printf("Leaking object at %p\n", data);
        obj->n_leaked += 1;
        return;
      }
      for (i = 0; i < MAX_OBJECTS; i++) {
        if (obj->buf[i] == NULL) {
          // printf("Saving object %p at idx %d\n", data, i);
          obj->buf[i] = data;
          obj->n_active += 1;
          break;
        }
      }
    } else {
      // free
      int i;
      for (i = 0; i < MAX_OBJECTS; i++) {
        if (obj->buf[i] != NULL) {
          // printf("Freeing object %p at idx %d\n", obj->buf[i], i);
          obj->free(obj->buf[i]);
          obj->buf[i] = NULL;
          obj->n_active -= 1;
          break;
        }
      }
    }
  }
}


int main(int argc, char **argv)
{
  unsigned long long int steps = 0;
  while (1) {
    int ret = rand() % 3;
    switch (ret) {
      case 0:
        do_object(&obj1);
        break;
      case 1:
        do_object(&obj2);
        break;
      case 2:
        do_object(&obj3);
        break;
    }
    
    // sleep 
    struct timespec ts;
    int delay = rand() / 4;
    ts.tv_sec = delay / NSECS_IN_SEC;
    ts.tv_nsec =  delay % NSECS_IN_SEC;
    printf("Sleeping %lds %ldns\n", ts.tv_sec, ts.tv_nsec);

    nanosleep(&ts, NULL);
    
    steps += 1;
    
    printf("%llu\t obj1: a=%ld, l=%ld\t obj2: a=%ld, l=%ld\t obj3: a=%ld, l=%ld\n",
      steps,
      obj1.n_active,
      obj1.n_leaked,
      obj2.n_active,
      obj2.n_leaked,
      obj3.n_active,
      obj3.n_leaked);
  }
  
  return 0;
}