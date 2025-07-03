some FSOP paths that might be useful

- [an3eii](/fsop/io_paths/an3eii/readme.md) (my favourite)
> `_IO_wfile_underflow` -> `__libio_codecvt_in` -> `__cd_in.step->__fct`

- [pwncollege](/fsop/io_paths/pwn_college/readme.md) (better use this [note](/fsop/io_paths/pwn_college/readme01.md) if you already familiar)
> `_IO_wfile_overflow` -> `_IO_wdoallocbuf` -> `_IO_WDOALLOCATE`
