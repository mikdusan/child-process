const std = @import("std");
const Child = @import("Child.zig");

// - spawn 1 child
// - child exits with status equal to an environment variable
// - show basic resource usage if available
pub fn main() !void {
    var _arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const arena = _arena.allocator();
    defer _arena.deinit();

    var env = try std.process.getEnvMap(arena);
    try env.put("ULTIMATE_ANSWER", "42");

    var child = try Child.init(arena, &.{ "sh", "-c", "exit $ULTIMATE_ANSWER" });
    defer child.deinit();

    child.env = &env;
    child.cwd = "/tmp";
    child.request_resource_usage_statistics = true;

    try child.redirectEndpointTo(.stdin, .dev_null);
    try child.redirectEndpointTo(.stdout, .dev_null);
    try child.redirectEndpointTo(.stderr, .dev_null);

    try child.spawn();
    const term = try child.wait();
    std.log.debug("term: {}", .{term});
    if (child.resource_usage_statistics.rusage) |ru| std.log.debug("maxrss: {} KiB", .{ru.maxrss});
}
