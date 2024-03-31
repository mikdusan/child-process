const std = @import("std");
const Child = @import("Child.zig");

// - spawn 1 child
// - collect only stdout
pub fn main() !void {
    var _arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const arena = _arena.allocator();
    defer _arena.deinit();

    var child = Child.init(arena, &.{ "ls", "-l", "/." });
    defer child.deinit();

    var buf = std.ArrayList(u8).init(arena);
    try child.collectEndpointInto(.stdout, &buf, 64 * 1024);
    try child.spawn();
    try child.collect();

    std.log.debug("stdin: {} bytes", .{buf.items.len});

    const term = try child.wait();
    std.log.debug("term: {}", .{term});
}
