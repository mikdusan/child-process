const std = @import("std");
const Child = @import("Child.zig");

// - spawn 2 children
// - create a pipe to child[0] source
// - create a pipe to child[1] sink
// - read from source and write to sink, replacing '_' → 'l'
//
//      sh -c "echo he__o" | (parent-filter) | grep hello > /dev/null
//      |---- child[0] ----|                 |------ child[1] ------|
//
pub fn main() !void {
    var _arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const arena = _arena.allocator();
    defer _arena.deinit();

    var childv = [_]Child{
        Child.init(arena, &.{ "sh", "-c", "echo he__o; exit" }),
        Child.init(arena, &.{ "grep", "hello" }),
    };
    defer for (&childv) |*child| child.deinit();

    try childv[1].redirectEndpointTo(.stdout, .dev_null);

    const pipe_endv = .{
        try childv[0].pipeEndpoint(.stdout, .source),
        try childv[1].pipeEndpoint(.stdin, .sink),
    };

    try childv[0].spawn();
    try childv[1].spawn();

    try filter(pipe_endv[0], pipe_endv[1]);

    const termv = .{
        try childv[0].wait(),
        try childv[1].wait(),
    };

    std.log.debug("termv[0]: {}", .{termv[0]});
    std.log.debug("termv[1]: {}", .{termv[1]});
}

// replace '_' with 'l'
fn filter(in: std.fs.File, out: std.fs.File) !void {
    const r = in.reader();
    const w = out.writer();
    while (true) {
        const b = r.readByte() catch break;
        try w.writeByte(if (b == '_') 'l' else b);
    }
}
