const std = @import("std");
const Child = @import("Child.zig");

// - spawn 5 children
// - collect stdout from 5 children
// - collect stderr from the last 2 children
pub fn main() !void {
    var _arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const arena = _arena.allocator();
    defer _arena.deinit();

    var childv = [_]Child{
        try Child.init(arena, &.{ "ls", "-l", "/." }),
        try Child.init(arena, &.{ "ls", "-l", "/tmp/." }),
        try Child.init(arena, &.{ "ls", "-l", "/var/tmp/." }),
        try Child.init(arena, &.{ "ls", "-al", "/var/tmp/." }),
        try Child.init(arena, &.{ "ls", "-l", "/bogus" }),
    };
    defer for (&childv) |*child| child.deinit();

    const Buffer = std.ArrayList(u8);
    const nbuf = childv.len + 2;
    var bufv: [nbuf]Buffer = undefined;
    for (&bufv) |*buf| buf.* = Buffer.init(arena);

    for (&childv, bufv[0..childv.len]) |*child, *buf| try child.collectEndpointInto(.stdout, buf, 64 * 1024);
    try childv[3].collectEndpointInto(.stderr, &bufv[5], 64 * 1024);
    try childv[4].collectEndpointInto(.stderr, &bufv[6], 64 * 1024);

    for (&childv) |*child| try child.spawn();

    try Child.collectMany(arena, &childv);
    for (&bufv, 0..) |buf, i| std.log.debug("buffer[{}]: {} bytes", .{ i, buf.items.len });

    for (&childv, 0..) |*child, i| {
        const term = try child.wait();
        std.log.debug("term[{}]: {}", .{ i, term });
    }
}
