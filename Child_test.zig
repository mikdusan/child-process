const builtin = @import("builtin");
const mem = std.mem;
const os = std.os;
const posix = std.posix;
const std = @import("std");
const testing = std.testing;
const windows = std.os.windows;

const Child = @import("Child.zig");

const native_os = builtin.os.tag;
const native_posix = if (native_os == .windows or native_os == .wasi) false else true;
const default_collect_max_bytes = 16 * 1024;

test "pre-exec error.FileNotFound" {
    try pre_exec(&.{"/bogus.exe"}, error.FileNotFound);
}

test "pre-exec error.AccessDenied" {
    try pre_exec(&.{"/"}, error.AccessDenied);
}

test "pre-exec error.NotDir" {
    try pre_exec(&.{"/etc/passwd/bogus.exe"}, error.NotDir);
}

fn pre_exec(args: []const []const u8, expect_err: anyerror) !void {
    if (!native_posix) return error.SkipZigTest;
    var child = try Child.init(testing.allocator, args);
    defer child.deinit();
    child.spawn() catch |err| if (err != error.ExecError) return err;
    try testing.expectEqual(expect_err, child.exec_err.?);
}

test "exit success" {
    try exit(&.{"true"}, 0);
}

test "exit fail" {
    try exit(&.{"false"}, 1);
}

fn exit(args: []const []const u8, exit_code: u8) !void {
    if (!native_posix) return error.SkipZigTest;
    var child = try Child.init(testing.allocator, args);
    defer child.deinit();
    try child.spawn();
    const term = try child.wait();
    try testing.expectEqual(term.exit, exit_code);
}

test "signal" {
    if (!native_posix) return error.SkipZigTest;
    // TODO: http://mail-index.netbsd.org/netbsd-bugs/2024/03/30/msg082251.html
    // kern/58091: after fork/execve or posix_spawn, parent kill(child, SIGTERM) has race condition making it unreliable
    if (native_os == .netbsd) return error.SkipZigTest;

    var child = try Child.init(testing.allocator, &.{ "/bin/sleep", "30" });
    defer child.deinit();

    try child.spawn();
    try posix.kill(child.id, posix.SIG.TERM);

    const term = try child.wait();
    try testing.expectEqual(posix.SIG.TERM, term.signal);
}

test "cwd, collect" {
    if (!native_posix) return error.SkipZigTest;
    var child = try Child.init(testing.allocator, &.{"pwd"});
    defer child.deinit();

    child.cwd = "/";

    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    try child.collectEndpointInto(.stdout, &buf, default_collect_max_bytes);

    try child.spawn();
    try child.collect();
    // strip LF
    if (buf.items.len > 0 and buf.items[buf.items.len - 1] == '\n') buf.items.len -= 1;

    const term = try child.wait();
    try testing.expectEqual(term.exit, 0);
    try testing.expectEqualSlices(u8, "/", buf.items);
}

test "cwd_dir, collect" {
    if (!native_posix) return error.SkipZigTest;
    var child = try Child.init(testing.allocator, &.{"pwd"});
    defer child.deinit();

    var dir = try std.fs.cwd().openDir("/", .{});
    defer dir.close();
    child.cwd_dir = dir;

    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    try child.collectEndpointInto(.stdout, &buf, default_collect_max_bytes);

    try child.spawn();
    try child.collect();
    // strip LF
    if (buf.items.len > 0 and buf.items[buf.items.len - 1] == '\n') buf.items.len -= 1;

    const term = try child.wait();
    try testing.expectEqual(term.exit, 0);
    try testing.expectEqualSlices(u8, "/", buf.items);
}

test "gid, collect" {
    if (!native_posix) return error.SkipZigTest;
    var child = try Child.init(testing.allocator, &.{ "id", "-g" });
    defer child.deinit();

    child.gid = 1;

    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    try child.collectEndpointInto(.stdout, &buf, default_collect_max_bytes);

    child.spawn() catch |err| if (err != error.ExecError) return err;
    if (child.exec_err) |err| {
        try testing.expectEqual(error.PermissionDenied, err);
        return;
    }
    try child.collect();
    // strip LF
    if (buf.items.len > 0 and buf.items[buf.items.len - 1] == '\n') buf.items.len -= 1;

    const term = try child.wait();
    try testing.expectEqual(term.exit, 0);
    try testing.expectEqualSlices(u8, "1", buf.items);
}

test "uid, collect" {
    if (!native_posix) return error.SkipZigTest;
    var child = try Child.init(testing.allocator, &.{ "id", "-u" });
    defer child.deinit();

    child.uid = 1;

    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    try child.collectEndpointInto(.stdout, &buf, default_collect_max_bytes);

    child.spawn() catch |err| if (err != error.ExecError) return err;
    if (child.exec_err) |err| {
        try testing.expectEqual(error.PermissionDenied, err);
        return;
    }
    try child.collect();
    // strip LF
    if (buf.items.len > 0 and buf.items[buf.items.len - 1] == '\n') buf.items.len -= 1;

    const term = try child.wait();
    try testing.expectEqual(term.exit, 0);
    try testing.expectEqualSlices(u8, "1", buf.items);
}

test "resource usage" {
    if (!native_posix) return error.SkipZigTest;
    var child = try Child.init(testing.allocator, &.{"true"});
    defer child.deinit();
    child.request_resource_usage_statistics = true;
    try child.spawn();
    const term = try child.wait();
    try testing.expect(child.resource_usage_statistics.rusage != null);
    try testing.expectEqual(term.exit, 0);
}

test "user_name, collect" {
    if (!native_posix) return error.SkipZigTest;
    const info = std.process.getUserInfo("daemon") catch return error.SkipZigTest;
    var child = try Child.init(testing.allocator, &.{ "sh", "-c", "echo $(id -g),$(id -u); exit" });
    defer child.deinit();

    try child.setUserName("daemon");

    var buf = std.ArrayList(u8).init(child.arena);
    defer buf.deinit();
    try child.collectEndpointInto(.stdout, &buf, default_collect_max_bytes);

    child.spawn() catch |err| if (err != error.ExecError) return err;
    if (child.exec_err) |err| {
        try testing.expectEqual(error.PermissionDenied, err);
        return;
    }
    try child.collect();
    // strip LF
    if (buf.items.len > 0 and buf.items[buf.items.len - 1] == '\n') buf.items.len -= 1;

    const expect = try std.fmt.allocPrint(testing.allocator, "{d},{d}", .{ info.gid, info.uid });
    defer testing.allocator.free(expect);

    const term = try child.wait();
    try testing.expectEqual(term.exit, 0);
    try testing.expectEqualSlices(u8, expect, buf.items);
}

test "redirect null" {
    if (!native_posix) return error.SkipZigTest;
    var child = try Child.init(testing.allocator, &.{ "cat", "/etc/passwd" });
    defer child.deinit();

    try child.redirectEndpointTo(.stdout, .dev_null);
    try child.spawn();

    const term = try child.wait();
    try testing.expectEqual(term.exit, 0);
}

test "redirect create" {
    if (!native_posix) return error.SkipZigTest;
    var child = try Child.init(testing.allocator, &.{ "cat", "/etc/passwd" });
    defer child.deinit();

    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmpDirPath(testing.allocator, tmp_dir, "new.txt");
    defer testing.allocator.free(tmp_path);

    try child.redirectEndpointTo(.stdout, .{ .create, tmp_path });
    try child.spawn();

    const term = try child.wait();
    try testing.expectEqual(term.exit, 0);
}

// TODO: mike: when this reaches PR state, move to testing.TmpDir.path()
/// Caller owns returned memory.
fn tmpDirPath(allocator: mem.Allocator, tmpDir: testing.TmpDir, basename: []const u8) ![]const u8 {
    return try std.fs.path.join(allocator, &.{ "zig-cache", "tmp", &tmpDir.sub_path, basename });
}

test "redirect open, null" {
    if (!native_posix) return error.SkipZigTest;
    var child = try Child.init(testing.allocator, &.{"cat"});
    defer child.deinit();

    try child.redirectEndpointTo(.stdin, .{ .open, "/etc/passwd" });
    try child.redirectEndpointTo(.stdout, .dev_null);
    try child.spawn();

    const term = try child.wait();
    try testing.expectEqual(term.exit, 0);
}

test "collect stdout" {
    if (!native_posix) return error.SkipZigTest;
    var child = try Child.init(testing.allocator, &.{ "cat", "/etc/passwd" });
    defer child.deinit();

    var buf = std.ArrayList(u8).init(child.arena);
    try child.collectEndpointInto(.stdout, &buf, default_collect_max_bytes);
    try child.spawn();
    try child.collect();

    const term = try child.wait();
    try testing.expectEqual(term.exit, 0);
}

test "collect stderr" {
    if (!native_posix) return error.SkipZigTest;
    var child = try Child.init(testing.allocator, &.{ "sh", "-c", "cat /etc/passwd 1>&2; exit" });
    defer child.deinit();

    var buf = std.ArrayList(u8).init(child.arena);
    try child.collectEndpointInto(.stderr, &buf, default_collect_max_bytes);
    try child.spawn();
    try child.collect();

    const term = try child.wait();
    try testing.expectEqual(term.exit, 0);
}

test "pipe reader" {
    if (!native_posix) return error.SkipZigTest;
    var child = try Child.init(testing.allocator, &.{ "cat", "/etc/passwd" });
    defer child.deinit();

    const stdout_pipe_end = try child.pipeEndpoint(.stdout, .source);
    try child.spawn();
    const bytes = try stdout_pipe_end.reader().readAllAlloc(testing.allocator, default_collect_max_bytes);
    testing.allocator.free(bytes);

    const term = try child.wait();
    try testing.expectEqual(term.exit, 0);
}

test "pipe writer" {
    if (!native_posix) return error.SkipZigTest;
    var child = try Child.init(testing.allocator, &.{ "cat", "/dev/null" });
    defer child.deinit();

    const stdin_pipe_end = try child.pipeEndpoint(.stdin, .sink);
    try child.spawn();
    try stdin_pipe_end.writer().writeAll("goodbye");

    const term = try child.wait();
    try testing.expectEqual(term.exit, 0);
}

// sh -c "echo he__o" | (parent-filter) | grep hello > /dev/null
// |---- child[0] ----|                 |------ child[1] ------|
test "pipeline" {
    if (!native_posix) return error.SkipZigTest;

    var child = .{
        try Child.init(testing.allocator, &.{ "sh", "-c", "echo he__o; exit" }),
        try Child.init(testing.allocator, &.{ "grep", "hello" }),
    };
    defer child[0].deinit();
    defer child[1].deinit();

    try child[1].redirectEndpointTo(.stdout, .dev_null);

    const pipe_end = .{
        try child[0].pipeEndpoint(.stdout, .source),
        try child[1].pipeEndpoint(.stdin, .sink),
    };

    try child[0].spawn();
    try child[1].spawn();

    try pipeline_filter(pipe_end[0], pipe_end[1]);

    const term = .{
        try child[0].wait(),
        try child[1].wait(),
    };

    try testing.expect(term[0] == .exit);
    try testing.expectEqual(term[0].exit, 0);

    try testing.expect(term[1] == .exit);
    try testing.expectEqual(term[1].exit, 0);
}

// replace '_' with 'l'
fn pipeline_filter(in: std.fs.File, out: std.fs.File) !void {
    const r = in.reader();
    const w = out.writer();
    while (true) {
        const b = r.readByte() catch break;
        try w.writeByte(if (b == '_') 'l' else b);
    }
}

test "run" {
    if (!native_posix) return error.SkipZigTest;
    const result = try Child.run(.{
        .allocator = testing.allocator,
        .argv = &.{"true"},
    });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);
}

test "fd management, exit success" {
    if (native_os != .linux) return error.SkipZigTest;

    var main: FdBasic = .{ .args = &.{"true"}, .exit_code = 0 };
    var check = try CheckFd.init(&FdBasic.main, &main, 4);
    defer check.deinit();
    try check.run();
}

test "fd management, exit fail" {
    if (native_os != .linux) return error.SkipZigTest;

    var main: FdBasic = .{ .args = &.{"false"}, .exit_code = 1 };
    var check = try CheckFd.init(&FdBasic.main, &main, 4);
    defer check.deinit();
    try check.run();
}

const FdBasic = struct {
    args: []const []const u8,
    exit_code: u8,

    fn main(any_self: *anyopaque, any_checker: *anyopaque) !void {
        const self: *FdBasic = @ptrCast(@alignCast(any_self));
        const checker: *CheckFd = @ptrCast(@alignCast(any_checker));

        try checker.push();
        defer checker.pop();

        var child = try Child.init(testing.allocator, self.args);
        defer child.deinit();
        try checker.expect();

        try child.spawn();
        try checker.expect();

        const term = try child.wait();
        try checker.expect();

        try testing.expectEqual(term.exit, self.exit_code);
    }
};

test "fd management, pipe reader, exit success" {
    if (native_os != .linux) return error.SkipZigTest;

    var main: FdPipeReader = .{ .args = &.{ "cat", "/etc/passwd" }, .exit_code = 0 };
    var check = try CheckFd.init(&FdPipeReader.main, &main, 4);
    defer check.deinit();
    try check.run();
}

test "fd management, pipe reader, exit fail" {
    if (native_os != .linux) return error.SkipZigTest;

    var main: FdPipeReader = .{ .args = &.{"false"}, .exit_code = 1 };
    var check = try CheckFd.init(&FdPipeReader.main, &main, 4);
    defer check.deinit();
    try check.run();
}

const FdPipeReader = struct {
    args: []const []const u8,
    exit_code: u8,

    fn main(any_self: *anyopaque, any_checker: *anyopaque) !void {
        const self: *FdPipeReader = @ptrCast(@alignCast(any_self));
        const checker: *CheckFd = @ptrCast(@alignCast(any_checker));

        try checker.push();
        defer checker.pop();

        var child = try Child.init(testing.allocator, self.args);
        defer child.deinit();
        try checker.expect();

        const stdout_pipe_end = try child.pipeEndpoint(.stdout, .source);
        checker.inc(2);
        try checker.expect();

        try child.spawn();
        checker.dec(1);
        try checker.expect();

        const bytes = try stdout_pipe_end.reader().readAllAlloc(testing.allocator, default_collect_max_bytes);
        testing.allocator.free(bytes);

        const term = try child.wait();
        checker.dec(1);
        try checker.expect();

        try testing.expectEqual(term.exit, self.exit_code);
    }
};

// Check and track open file-descriptors at various points in a test body.
//
// Linux-only.
//
// The assumption is zig tests are each run sequentially (not in parallel).
//
//  1. at each point the FD count goes up or down, call `inc(N)` or `dec(N)` accordingly
//  2. follow with `try self.expect()`
//  3. it also may be valuable to add `try self.expect()` after an init operation
//
// Initialize with a value which indicates how many times `self.expect()` is
// called in the code. This is required because the check will run each test body
// N times and force the N'th call of `self.expect()` to fail. In other words
// each run gets progressively further into the test body and utimately runs
// the full test.
const CheckFd = struct {
    mainFn: *const Main,
    mainSelf: *anyopaque,
    dir: std.fs.Dir,
    count: std.ArrayList(usize),
    expect_total: usize,
    expect_i: usize = 0,
    errored: bool = false,
    force_error_at_expect: usize = 0,

    const Main = fn (_: *anyopaque, _: *anyopaque) anyerror!void;

    fn init(mainFn: *const Main, mainSelf: *anyopaque, expect_total: usize) !CheckFd {
        var new: CheckFd = .{
            .mainFn = mainFn,
            .mainSelf = mainSelf,
            .dir = try std.fs.cwd().openDir("/proc/self/fd", .{ .iterate = true }),
            .count = std.ArrayList(usize).init(testing.allocator),
            .expect_total = expect_total,
        };
        try new.push();
        return new;
    }

    fn deinit(self: *CheckFd) void {
        self.count.deinit();
        self.dir.close();
    }

    fn run(self: *CheckFd) !void {
        for (0..self.expect_total) |i| try self.runEach(i);
        try self.runEach(std.math.maxInt(usize));
    }

    fn runEach(self: *CheckFd, index: usize) !void {
        const nfd_begin = try self.countFd();
        self.count.clearRetainingCapacity();
        self.force_error_at_expect = index;
        self.expect_i = 0;
        self.errored = false;
        self.mainFn(@ptrCast(self.mainSelf), @ptrCast(self)) catch |err| switch (err) {
            error.__ForcedError => {},
            else => return err,
        };
        try testing.expectEqual(nfd_begin, try self.countFd());
    }

    fn push(self: *CheckFd) !void {
        if (self.count.items.len == 0) {
            try self.count.append(try self.countFd());
        } else {
            try self.count.append(self.count.getLast());
        }
    }

    fn pop(self: *CheckFd) void {
        _ = self.count.pop();
    }

    fn expect(self: *CheckFd) !void {
        if (self.expect_i == self.force_error_at_expect) return error.__ForcedError;
        self.expect_i += 1;
        try testing.expectEqual(self.count.getLast(), try self.countFd());
    }

    fn inc(self: *CheckFd, num: usize) void {
        self.count.items[self.count.items.len - 1] += num;
    }

    fn dec(self: *CheckFd, num: usize) void {
        self.count.items[self.count.items.len - 1] -= num;
    }

    fn countFd(self: *CheckFd) !usize {
        var count: usize = 0;
        var it = self.dir.iterate();
        while (try it.next()) |_| count += 1;
        return count;
    }
};
