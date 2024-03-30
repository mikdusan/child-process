const std = @import("std");
const Child = @import("Child.zig");

// - spawn 1 child
// - collect both stdout and stderr
pub fn main() !void {
    var _arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const arena = _arena.allocator();
    defer _arena.deinit();

    var child = try Child.init(arena, &.{ "ls", "-l", "/." });
    defer child.deinit();

    var stdin = std.ArrayList(u8).init(arena);
    var stdout = std.ArrayList(u8).init(arena);
    try child.collectEndpointInto(.stdout, &stdin, 64 * 1024);
    try child.collectEndpointInto(.stderr, &stdout, 64 * 1024);
    try child.spawn();
    try child.collect();

    std.log.debug("stdin: {} bytes", .{stdin.items.len});
    std.log.debug("stdout: {} bytes", .{stdout.items.len});

    const term = try child.wait();
    std.log.debug("term: {}", .{term});
}
