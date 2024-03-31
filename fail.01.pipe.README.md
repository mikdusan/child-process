### case 00: success baseline (takes 30 seconds to run)
```
$ zig run fail.01.pipe.00.zig
debug: parent pid: 864123
debug: open file descriptors (BEGIN): 4
debug: child[0] pid: 864165
debug: child[1] pid: 864166
debug: answer: 3 bytes ('30')
debug: termv[0]: Child.Term{ .exit = 0 }
debug: termv[1]: Child.Term{ .exit = 0 }
debug: open file descriptors (END): 4
```

---
### case 01: spawn with child 0 bad exe name 
- we identify child 0 as causing the error
```
$ zig run fail.01.pipe.01.zig
debug: parent pid: 864267
debug: open file descriptors (BEGIN): 4
error: exec of childv[0] failed: error.FileNotFound
debug: open file descriptors (END): 4
error: ExecError
/home/mike/project/child-process/Child.zig:429:9: 0x1046512 in spawn (fail.01.pipe.01)
        return error.ExecError;
        ^
/home/mike/project/child-process/fail.01.pipe.01.zig:37:13: 0x10438cd in main (fail.01.pipe.01)
            return err;
            ^
```

---
### case 02: spawn with child 1 bad exe name 
- we identify child 1 as causing the error
```
$ zig run fail.01.pipe.02.zig
debug: parent pid: 864318
debug: open file descriptors (BEGIN): 4
debug: child[0] pid: 864369
error: exec of childv[1] failed: error.FileNotFound
debug: open file descriptors (END): 4
error: ExecError
/home/mike/project/child-process/Child.zig:429:9: 0x1046512 in spawn (fail.01.pipe.02)
        return error.ExecError;
        ^
/home/mike/project/child-process/fail.01.pipe.02.zig:37:13: 0x10438cd in main (fail.01.pipe.02)
            return err;
            ^
```

---
### case 03: run baseline and kill child 0 from another shell
- we see child 0 terminated with signal 15 (SIGTERM)
- due to nature of pipeline, child 1 terminated normally with exit code 0
```
$ zig run fail.01.pipe.00.zig
debug: parent pid: 864774
debug: open file descriptors (BEGIN): 4
debug: child[0] pid: 864817
debug: child[1] pid: 864818
debug: answer: 2 bytes ('7')
debug: termv[0]: Child.Term{ .signal = 15 }
debug: termv[1]: Child.Term{ .exit = 0 }
debug: open file descriptors (END): 4
```

---
### case 04: run baseline and kill child 1 from another shell
- we see child 1 terminated with signal 15 (SIGTERM)
- due to nature of pipeline, child 0 terminated with signal 13 (SIGPIPE)
```
$ zig run fail.01.pipe.00.zig
debug: parent pid: 865000
debug: open file descriptors (BEGIN): 4
debug: child[0] pid: 865043
debug: child[1] pid: 865044
debug: answer: 0 bytes ('')
debug: termv[0]: Child.Term{ .signal = 13 }
debug: termv[1]: Child.Term{ .signal = 15 }
debug: open file descriptors (END): 4
```

---
### case 05: run baseline and kill parent from another shell
- we see parent is terminated
- within the 30-second window:
    - we see child 0 lives and parent pid PPID=1
    - we see child 1 lives and parent pid PPID=1
    - they are still communicating
    - when 30 seconds finishes, presumably they both clean-exit
```
$ zig run fail.01.pipe.00.zig
debug: parent pid: 865169
debug: open file descriptors (BEGIN): 4
debug: child[0] pid: 865212
debug: child[1] pid: 865213
zsh: terminated  zig run fail.01.pipe.00.zig
```
