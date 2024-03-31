const std = @import("std");
const Child = @import("Child.zig");

// - spawn 2 children
// - connect pipe from one child to the other
// - collect output
pub fn main() !void {
    std.log.debug("parent pid: {}", .{std.os.linux.getpid()});
    try countFd("BEGIN");
    defer countFd("END") catch {};

    var _gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const gpa = _gpa.allocator();
    defer {
        _ = _gpa.deinit();
    }

    var childv = [_]Child{
        Child.init(gpa, &.{ "bash", "-c", "for n in {1..30};do echo $n; sleep 1; done" }),
        Child.init(gpa, &.{ "_wc", "-l" }),
    };
    defer childv[0].deinit();
    defer childv[1].deinit();

    var answer = std.ArrayList(u8).init(gpa);
    defer answer.deinit();
    try childv[1].collectEndpointInto(.stdout, &answer, 4096);

    try childv[0].connect(.source, .stdout, &childv[1], .stdin);

    for (&childv, 0..) |*child, i| {
        child.spawn() catch |err| {
            switch (err) {
                error.ExecError => std.log.err("exec of childv[{}] failed: {?}", .{ i, child.exec_err }),
                else => |e| std.log.err("spawn failed: {}", .{e}),
            }
            return err;
        };
        std.log.debug("child[{}] pid: {}", .{ i, child.id });
    }

    try childv[1].collect();

    std.log.debug("answer: {} bytes ('{s}')", .{
        answer.items.len,
        std.mem.trim(u8, answer.items, " \n"),
    });

    for (&childv, 0..) |*child, i| {
        const term = try child.wait();
        std.log.debug("termv[{}]: {}", .{ i, term });
    }
}

fn countFd(text: []const u8) !void {
    var dir = try std.fs.cwd().openDir("/proc/self/fd", .{ .iterate = true });
    defer dir.close();
    var count: usize = 0;
    var it = dir.iterate();
    while (try it.next()) |_| count += 1;
    std.log.debug("open file descriptors ({s}): {}", .{ text, count });
}
