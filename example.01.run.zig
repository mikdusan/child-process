const std = @import("std");
const Child = @import("Child.zig");

// - run 1 child and collect stdout/stderr
pub fn main() !void {
    var _arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const arena = _arena.allocator();
    defer _arena.deinit();

    const result = try Child.run(.{
        .allocator = arena,
        .argv = &.{"pwd"},
    });

    std.log.debug("term: {}", .{result.term});
    std.log.debug("stdout: '{s}'", .{std.mem.trimRight(u8, result.stdout, "\n")});
    std.log.debug("stderr: '{s}'", .{std.mem.trimRight(u8, result.stderr, "\n")});
}
