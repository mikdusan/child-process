- platforms working against zig master:
    - linux
    - macos

- other platforms pending zig master updates for rusage support:
    - netbsd
    - freebsd
    - openbsd
    - dragonfly

### example: spawn 2 children, connect with pipe and collect stdout

```rust
const std = @import("std");
const Child = @import("Child.zig");

// - spawn 2 children
// - connect pipe from one child to the other
// - collect output
pub fn main() !void {
    var _arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const arena = _arena.allocator();
    defer _arena.deinit();

    var childv = [_]Child{
        try Child.init(arena, &.{ "ls", "/." }),
        try Child.init(arena, &.{ "wc", "-l" }),
    };
    defer for (&childv) |*child| child.deinit();

    var answer = std.ArrayList(u8).init(arena);
    try childv[1].collectEndpointInto(.stdout, &answer, 4096);

    try childv[0].connect(.source, .stdout, &childv[1], .stdin);

    try childv[0].spawn();
    try childv[1].spawn();

    try childv[1].collect();

    std.log.debug("answer: {} bytes ('{s}')", .{
        answer.items.len,
        std.mem.trim(u8, answer.items, " \n"),
    });

    const termv = .{
        try childv[0].wait(),
        try childv[1].wait(),
    };

    std.log.debug("termv[0]: {}", .{termv[0]});
    std.log.debug("termv[1]: {}", .{termv[1]});
}
```
