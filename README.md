# go-memotrack

**go-memotrack** is an EBPF-based tool that tracks memory allocations and tracks which allocations are accumulating and might indicate a memory leak.

It can be used as an alternative to Valgrind. While not as feature rich, it has a few advantages:
* you can use it in production to collect information on a running program
* use it in environments difficult to replicate locally
* no need to compile with debug files; you only need a non-stripped binary
* compatible with operating systems that implement EBPF

## Principle of operation

In order to use **go-memotrack** you need to specify a set of allocator and deallocator functions. Currently it works out of the box with malloc/free style functions: allocators return the address of the newly allocated memory area and deallocators take the memory area to free as the first parameter.

Once you define the allocators and deallocators, attach go-memotrack to a running process and it will keep track of the allocated memory areas.

In order to be useful, the allocated memory areas are tagged with the stack trace at the allocation point in the program. Thus you can easily identify which type of object has leaked, even if you use a very generic allocator (malloc/free). The corresponding stack is collected using EBPF's **bpf_get_stackid** helper function.

## Example usage

We have included an example C program that intentionally leaks memory.

Compile the utility

```
gcc dummy_leaker.c -o dummy
```

Run the utility:
```
./dummy
```

Attach go-memotrack
```
go-memotrack --executable ./dummy --pid `pidof dummy` --object obj1=make_obj1|free_obj1 --object obj2=make_obj2|free_obj2
--object obj3=make_obj3|free_obj3
```

**go-memotrack** will write a report at stdout with the number of objects for each collected stack trace.

### Execution modes

**go-memotrack** has 2 execution modes:
* default/batch: produces a report at exit
* interactive, with the --interactive flag: you can query the state of the allocation tracker at runtime with a REPL interface

## TODO
- [ ] improve reporting
- [ ] compute trends relative to a baseline signal (number of HTTP requests, etc.)
- [ ] improve shell graphics
- [ ] support for defining custom allocators
- [ ] test on non-Linux systems

## License

MIT License
