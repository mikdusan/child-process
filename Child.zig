const builtin = @import("builtin");
const debug = std.debug;
const mem = std.mem;
const os = std.os;
const posix = std.posix;
const std = @import("std");
const windows = std.os.windows;

const Child = @This();

const native_os = builtin.os.tag;
const native_posix = if (native_os == .windows or native_os == .wasi) false else true;

/// Child main executable command line arguments.
argv: []const []const u8,

/// Expand argv[0] to the absolute path of the main executable.
expand_arg0: if (native_posix) posix.Arg0Expand else void,

/// Set environ for the child process.
env: ?*const std.process.EnvMap = null,

/// Set working directory for the child process.
cwd: ?[]const u8 = null,

/// Set current working directory for the child process.
/// This is not yet implemented for Windows. See https://github.com/ziglang/zig/issues/5190
/// Once that is done, `cwd` will be deprecated in favor of this field.
cwd_dir: ?std.fs.Dir = null,

/// Set child process group ID.
gid: ?posix.gid_t = null,

/// Set child process user ID.
uid: ?posix.uid_t = null,

/// Set to true to obtain rusage information for the child process.
/// Depending on the target platform and implementation status, the
/// requested statistics may or may not be available. If they are
/// available, then the `resource_usage_statistics` field will be populated
/// after calling `wait`.
/// On Linux, Darwin, FreeBSD, NetBSD, OpenBSD and DragonflyBSD,
/// this obtains rusage statistics from wait4().
request_resource_usage_statistics: bool = false,

/// This is available after calling wait if
/// `request_resource_usage_statistics` was set to `true` before calling
/// `spawn`.
resource_usage_statistics: ResourceUsageStatistics = .{},

/// The spawned process system identifier.
/// Valid after calling `spawn()` and before `wait()`.
id: ID,

/// On deinit set signal to be sent prior to final `wait()`.
kill: ?u8 = posix.SIG.TERM,

/// An error tripped during child fork-context which performs final setup
/// and calls system exec.
/// Avaialble after `spawn()` returns `error.ExecError`.
exec_err: ?ExecError = null,

allocator: mem.Allocator,

actions: ActionList,
action_set: EndpointMap,
collectors: CollectorList,
transient_handles: HandleList,
pipe_ends: HandleList,

dev_null: union(enum) {
    none: void,
    pending: void,
    file: std.fs.File,
} = .none,

close_range: ?struct {
    begin: Endpoint.Handle,
    end: Endpoint.Handle,
} = null,

restore_sigterm: posix.Sigaction = undefined,

// internal milestones
did: packed struct {
    fork: bool = false,
    wait: bool = false,
} = .{},

const ArgList = std.ArrayList([]const u8);
const ActionList = std.ArrayList(*Action);
const CollectorList = std.ArrayList(*const Collector);
const EndpointMap = std.AutoArrayHashMap(Endpoint.Handle, *const Action);
const ExecError = @typeInfo(@typeInfo(@TypeOf(exec)).Fn.return_type.?).ErrorUnion.error_set;
const HandleList = std.ArrayList(Endpoint.Handle);

/// First argument in `argv` is the executable.
/// `argv` content memory must remain valid while Child instance is in use.
pub fn init(allocator: mem.Allocator, argv: []const []const u8) Child {
    debug.assert(argv.len != 0);
    return .{
        .expand_arg0 = .no_expand,
        .id = undefined,
        .allocator = allocator,
        .argv = argv,
        .actions = ActionList.init(allocator),
        .action_set = EndpointMap.init(allocator),
        .collectors = CollectorList.init(allocator),
        .transient_handles = HandleList.init(allocator),
        .pipe_ends = HandleList.init(allocator),
    };
}

pub fn deinit(self: *Child) void {
    if (self.did.fork and !self.did.wait) {
        if (self.kill) |sig| posix.kill(self.id, sig) catch {};
        _ = self.wait() catch {};
    }

    for (self.pipe_ends.items) |h| posix.close(h);
    for (self.transient_handles.items) |h| posix.close(h);

    self.pipe_ends.deinit();
    self.transient_handles.deinit();

    for (self.collectors.items) |collector| self.allocator.destroy(collector);
    self.collectors.deinit();
    self.action_set.deinit();
    for (self.actions.items) |action| self.allocator.destroy(action);
    self.actions.deinit();
}

/// Prior to exec, the child `endpoint` is marked to be inherited by child.
pub fn inheritEndpoint(self: *Child, endpoint: anytype) !void {
    const ep = try Endpoint.fromAny(endpoint, false);
    try self.addAction(ep.getHandle(), .{ .inherit = ep });
}

/// Prior to exec, the child `endpoint` is closed.
pub fn closeEndpoint(self: *Child, endpoint: anytype) !void {
    const ep = try Endpoint.fromAny(endpoint, false);
    try self.addAction(ep.getHandle(), .{ .close = ep });
}

/// Prior to exec, the child `endpoint` is redirected.
pub fn redirectEndpointTo(self: *Child, endpoint: anytype, to: anytype) !void {
    const ep0 = try Endpoint.fromAny(endpoint, false);
    const ep1 = try Endpoint.fromAny(to, true);
    try self.addAction(ep0.getHandle(), .{ .redirect = .{ .endpoint = ep0, .to = ep1 } });
    if (ep1 == .dev_null) self.dev_null = .pending;
}

/// Collect output from child `endpoint` into buffer.
pub fn collectEndpointInto(self: *Child, endpoint: anytype, into: *std.ArrayList(u8), max_bytes: ?usize) !void {
    const pipe_end = try self.pipeEndpoint(endpoint, .source);
    try self.addCollect(pipe_end, into, max_bytes);
}

/// Create a pipe and prior to exec, connect the pipe to child `endpoint`.
/// `disposition` specifies `endpoint` is a data-source or data-sink.
///
/// Return the other pipe-end for use by the parent.
///
/// On posix systems the pipe is always created with `.CLOEXEC` flag.
pub fn pipeEndpoint(self: *Child, endpoint: anytype, disposition: PipeDisposition) !std.fs.File {
    const pipe = try posix.pipe2(.{ .CLOEXEC = true });
    if (disposition == .sink) {
        try self.redirectEndpointTo(endpoint, pipe[0]);
        try self.transient_handles.append(pipe[0]);
        try self.pipe_ends.append(pipe[1]);
        return .{ .handle = pipe[1] };
    } else {
        try self.redirectEndpointTo(endpoint, pipe[1]);
        try self.transient_handles.append(pipe[1]);
        try self.pipe_ends.append(pipe[0]);
        return .{ .handle = pipe[0] };
    }
}

/// Create a pipe and prior to exec, connect `endpoint` to `other_endpoint`.
/// `disposition` specifies `endpoint` is a data-source or data-sink.
///
/// On posix systems the pipe is always created with `.CLOEXEC` flag.
pub fn connect(self: *Child, disposition: PipeDisposition, endpoint: anytype, other_child: *Child, other_endpoint: anytype) !void {
    const other_pipe_end = try self.pipeEndpoint(endpoint, disposition);
    try other_child.redirectEndpointTo(other_endpoint, other_pipe_end);
}

/// A convenience API for basic usage for legacy compatibility.
pub fn setEndpointBasicAction(self: *Child, endpoint: Endpoint, action: BasicActionType) !void {
    switch (action) {
        .inherit => try self.inheritEndpoint(endpoint),
        .ignore => try self.redirectEndpointTo(endpoint, .dev_null),
        .close => try self.closeEndpoint(endpoint),
    }
}

/// All child endpoints not used in actions are closed.
/// Only useful on posix systems.
pub fn closeAll(self: *Child) !void {
    self.close_range = .{ .begin = 0, .end = 128 };
}

/// Fetch guid/uid for user and set child process group/user IDs.
pub fn setUserName(self: *Child, name: []const u8) !void {
    const info = try std.process.getUserInfo(name);
    self.gid = info.gid;
    self.uid = info.uid;
}

/// Must be called after `spawn()` and before `wait()` to collect endpoint output.
/// If `max_bytes` is exceeded for any pipe-end, all collection stops and `error.StdoutStreamTooLong` is returned.
pub fn collect(self: *Child) !void {
    return Child.collectMany(self.allocator, &.{self.*});
}

/// Collect output from multiple children.
pub fn collectMany(allocator: mem.Allocator, children: []const Child) !void {
    var builder = std.ArrayList(*const Collector).init(allocator);
    defer builder.deinit();

    for (children) |*child| {
        try builder.ensureUnusedCapacity(child.collectors.items.len);
        for (child.collectors.items) |collector| {
            builder.appendAssumeCapacity(collector);
        }
    }
    const collectorv = builder.items;
    const npipes = collectorv.len;

    const fdv = try allocator.alloc(posix.pollfd, npipes);
    defer allocator.free(fdv);

    const Aux = struct {
        file: std.fs.File,
        reader: std.fs.File.Reader,
        max_bytes: usize,
    };
    const auxv = try allocator.alloc(Aux, npipes);
    defer allocator.free(auxv);

    for (collectorv, fdv, auxv) |collector, *fd, *aux| {
        fd.* = .{
            .fd = collector.pipe_end.handle,
            .events = posix.POLL.IN,
            .revents = undefined,
        };
        aux.* = .{
            .file = .{ .handle = collector.pipe_end.handle },
            .reader = undefined,
            .max_bytes = collector.max_bytes orelse std.math.maxInt(usize),
        };
        aux.reader = aux.file.reader();
    }

    var pending = npipes;
    while (pending != 0) {
        _ = try posix.poll(fdv, -1);
        for (collectorv, fdv, auxv) |collector, *fd, aux| {
            if (fd.revents & posix.POLL.IN != 0) {
                const backing = collector.buffer;
                try backing.ensureUnusedCapacity(4096);
                backing.items.len += try aux.reader.read(backing.unusedCapacitySlice());
                if (backing.items.len > aux.max_bytes) return error.StdoutStreamTooLong;
            }
            if (fd.revents & (posix.POLL.ERR | posix.POLL.HUP) != 0) {
                // no more events from this fd
                fd.fd = -1;
                pending -= 1;
            }
        }
    }
}

/// On success must call `kill` or `wait`.
/// After spawning the `id` is available.
pub fn spawn(self: *Child) SpawnError!void {
    // The POSIX standard does not allow malloc() between fork() and execve(),
    // and `self.allocator` may be a libc allocator.
    // I have personally observed the child process deadlocking when it tries
    // to call malloc() due to a heap allocation between fork() and execve(),
    // in musl v1.1.24.
    // Additionally, we want to reduce the number of possible ways things
    // can fail between fork() and execve().
    // Therefore, we do all the allocation before fork().
    //
    // Memory allocation errors are a red-flag that `exec()` is performing memory allocation.
    comptime {
        for (@typeInfo(ExecError).ErrorSet.?) |x| {
            for (@typeInfo(mem.Allocator.Error).ErrorSet.?) |y| {
                if (mem.eql(u8, x.name, y.name)) {
                    @compileError("ExecError contains 'error." ++ x.name ++ "'. Memory allocation is not allowed in `Child.exec()`. Please audit.");
                }
            }
        }
    }
    if (!std.process.can_spawn) @compileError("the target operating system cannot spawn processes");

    debug.assert(self.cwd == null or self.cwd_dir == null);

    var _arena = std.heap.ArenaAllocator.init(self.allocator);
    defer _arena.deinit();
    const arena = _arena.allocator();

    // Null-terminate argv.
    const argv = try arena.allocSentinel(?[*:0]const u8, self.argv.len, null);
    for (self.argv, 0..) |arg, i| argv[i] = (try arena.dupeZ(u8, arg)).ptr;

    // Null-terminate env.
    const Envp = [*:null]const ?[*:0]const u8;
    const envp: Envp = m: {
        if (self.env) |env| {
            const envp_buf = try createNullDelimitedEnvMap(arena, env);
            break :m envp_buf.ptr;
        } else if (builtin.link_libc) {
            break :m std.c.environ;
        } else if (builtin.output_mode == .Exe) {
            // Then we have Zig start code and this works.
            // TODO type-safety for null-termination of `os.environ`.
            break :m @as([*:null]const ?[*:0]const u8, @ptrCast(os.environ.ptr));
        } else if (native_os == .linux) {
            const result = try createNullDelimitedEnvironFromProcfs(arena);
            break :m @ptrCast(result.slice.ptr);
        } else {
            // TODO come up with a solution for this.
            @compileError("missing std lib enhancement: Child implementation has no way to collect the environment variables to forward to the child process");
        }
    };

    // One or more actions require '/dev/null'.
    // At the end of spawn() parent can safely close.
    if (self.dev_null == .pending) {
        const f = std.fs.cwd().openFile("/dev/null", .{ .mode = .read_write }) catch return error.SystemResources;
        self.dev_null = .{ .file = f };
    }
    defer if (self.dev_null == .file) self.dev_null.file.close();

    // Replace redirect-actions `.to` which are not yet live.
    // Doing this before fork() is a tradeoff and slighly more expensive.
    // It's more efficient to do it after fork() but the golden rule is
    // to do as much work as possible before fork().
    defer {
        for (self.transient_handles.items) |h| posix.close(h);
        self.transient_handles.clearAndFree();
    }
    for (self.actions.items) |action| {
        switch (action.*) {
            .redirect => |*r| switch (r.to) {
                .dev_null => r.to = .{ .handle = self.dev_null.file.handle },
                .create => |create| {
                    const h = (std.fs.cwd().createFile(create.path, create.flags) catch return error.SystemResources).handle;
                    try self.transient_handles.append(h);
                    r.to = .{ .handle = h };
                    try self.inheritEndpoint(h);
                },
                .open => |open| {
                    const h = (std.fs.cwd().openFile(open.path, open.flags) catch return error.SystemResources).handle;
                    try self.transient_handles.append(h);
                    r.to = .{ .handle = h };
                    try self.inheritEndpoint(h);
                },
                else => {},
            },
            else => {},
        }
    }

    // Setup channel to communicate from the child to the parent any
    // error between the time of `fork()` and `execve()`.
    // The child does exactly 0 or 1 write of @sizeOf(u64) bytes.
    // The parent does a blocking read and relies on closure of
    // child pipe-end (CPE) to guarantee parent is unblocked with
    // 0-bytes read result. The CPE is guarnateed to close because
    // pipe is created with `.CLOEXEC = true` and we ensure that
    // our copy of CPE is closed immediately after fork.
    const echan = b: {
        const pipe = try posix.pipe2(.{ .CLOEXEC = true });
        const io: [2]std.fs.File = .{
            .{ .handle = pipe[0] },
            .{ .handle = pipe[1] },
        };
        try self.inheritEndpoint(io[1]);
        break :b .{
            .io = io,
            .reader = io[0].reader(),
            .writer = io[1].writer(),
        };
    };
    defer echan.io[0].close();
    try self.inheritEndpoint(echan.io[0]);
    var echan1_open = true;
    defer if (echan1_open) echan.io[1].close();

    const pid_result = try posix.fork();
    self.did.fork = true;

    if (pid_result == 0) self.exec(envp, argv) catch |err| {
        // We are the child and tripped an error before or at callsite of `execve()`
        echan.writer.writeInt(u64, @intFromError(err), .little) catch return error.SystemResources;

        // If we're linking libc, some naughty applications may have registered atexit handlers
        // which we really do not want to run in the fork child. I caught LLVM doing this and
        // it caused a deadlock instead of doing an exit syscall. In the words of Avril Lavigne,
        // "Why'd you have to go and make things so complicated?"
        if (builtin.link_libc) {
            // The _exit(2) function does nothing but make the exit syscall, unlike exit(3).
            std.c._exit(1);
        }
        posix.exit(1);
    };

    // We are the parent.
    self.id = pid_result;

    // Error channel blocking read.
    //
    // The other pipe-end must be closed before blocking read so that the child has
    // last reference to pipe-end and when it is closed the read will unblock and
    // return 0-bytes. If this isn't done then when `exec()` is successful we will
    // block forever.
    echan.io[1].close();
    echan1_open = false;

    var buf: [8]u8 = undefined;
    const nbytes = echan.reader.read(&buf) catch return error.SystemResources;
    if (nbytes == 8) {
        const ErrorInt = std.meta.Int(.unsigned, @bitSizeOf(anyerror));
        self.exec_err = @as(ExecError, @errorCast(@errorFromInt(@as(ErrorInt, @intCast(mem.readVarInt(u64, buf[0..nbytes], .little))))));
        return error.ExecError;
    }
}

pub fn spawnAndWait(self: *Child) SpawnError!Term {
    debug.assert(self.pipe_ends.len == 0);
    if ((try self.spawn()).err) |err| return err;
    return self.wait();
}

/// Spawns a child process, waits for it, collecting stdout and stderr, and then returns.
/// If it succeeds, the caller owns result.stdout and result.stderr memory.
pub fn run(
    config: struct {
        allocator: mem.Allocator,
        argv: []const []const u8,
        cwd: ?[]const u8 = null,
        cwd_dir: ?std.fs.Dir = null,
        env: ?*const std.process.EnvMap = null,
        max_output_bytes: usize = 50 * 1024,
        expand_arg0: posix.Arg0Expand = .no_expand,
    },
) RunError!RunResult {
    var child = Child.init(config.allocator, config.argv);
    defer child.deinit();

    child.expand_arg0 = config.expand_arg0;
    child.cwd = config.cwd;
    child.cwd_dir = config.cwd_dir;
    child.env = config.env;

    try child.redirectEndpointTo(.stdin, .dev_null);

    var stdout = std.ArrayList(u8).init(config.allocator);
    errdefer stdout.deinit();
    try child.collectEndpointInto(.stdout, &stdout, config.max_output_bytes);

    var stderr = std.ArrayList(u8).init(config.allocator);
    errdefer stderr.deinit();
    try child.collectEndpointInto(.stderr, &stderr, config.max_output_bytes);

    try child.spawn();
    try child.collect();

    return RunResult{
        .term = try child.wait(),
        .stdout = try stdout.toOwnedSlice(),
        .stderr = try stderr.toOwnedSlice(),
    };
}

/// Forcibly terminates child process and then cleans up all resources.
pub fn kill(self: *Child) !Term {
    if (native_os == .windows) {
        return self.killWindows(1);
    } else {
        return self.killPosix();
    }
}

/// Blocks until child process terminates and then cleans up all resources.
pub fn wait(self: *Child) !Term {
    debug.assert(!self.did.wait);
    debug.assert(self.did.fork);

    self.did.wait = true;
    defer self.id = undefined;

    // Close all pipe-ends that were returned to user.
    for (self.pipe_ends.items) |h| posix.close(h);
    self.pipe_ends.clearAndFree();

    const res = b: {
        if (self.request_resource_usage_statistics) {
            switch (native_os) {
                .linux,
                .macos,
                .ios,
                .tvos,
                .watchos,
                .freebsd,
                .netbsd,
                .openbsd,
                .dragonfly,
                => {
                    var ru: posix.rusage = undefined;
                    const res = posix.wait4(self.id, 0, &ru);
                    self.resource_usage_statistics.rusage = ru;
                    break :b res;
                },
                else => {},
            }
        }
        break :b posix.waitpid(self.id, 0);
    };

    return if (posix.W.IFEXITED(res.status))
        .{ .exit = posix.W.EXITSTATUS(res.status) }
    else if (posix.W.IFSIGNALED(res.status))
        .{ .signal = @intCast(posix.W.TERMSIG(res.status)) }
    else if (posix.W.IFSTOPPED(res.status))
        .{ .stop = @intCast(posix.W.STOPSIG(res.status)) }
    else
        .{ .unknown = res.status };
}

pub const BasicActionType = enum {
    inherit,
    ignore,
    close,
};

pub const ID = posix.pid_t;

pub const PipeDisposition = enum { source, sink };

pub const ResourceUsageStatistics = struct {
    rusage: @TypeOf(rusage_init) = rusage_init,

    /// Returns the peak resident set size of the child process, in bytes,
    /// if available.
    pub inline fn getMaxRss(rus: ResourceUsageStatistics) ?usize {
        switch (native_os) {
            .linux,
            .freebsd,
            .netbsd,
            .openbsd,
            .dragonfly,
            => {
                if (rus.rusage) |ru| {
                    return @as(usize, @intCast(ru.maxrss)) * 1024;
                } else {
                    return null;
                }
            },
            .macos, .ios, .tvos, .watchos => {
                if (rus.rusage) |ru| {
                    // Darwin oddly reports in bytes instead of kilobytes.
                    return @as(usize, @intCast(ru.maxrss));
                } else {
                    return null;
                }
            },
            .windows => {
                if (rus.rusage) |ru| {
                    return ru.PeakWorkingSetSize;
                } else {
                    return null;
                }
            },
            else => return null,
        }
    }

    const rusage_init = switch (native_os) {
        .linux,
        .macos,
        .ios,
        .tvos,
        .watchos,
        .freebsd,
        .netbsd,
        .openbsd,
        .dragonfly,
        => @as(?posix.rusage, null),
        .windows => @as(?windows.VM_COUNTERS, null),
        else => {},
    };
};

pub const RunError = posix.GetCwdError || posix.ReadError || SpawnError || posix.PollError || error{
    StdoutStreamTooLong,
    StderrStreamTooLong,
};

pub const RunResult = struct {
    term: Term,
    stdout: []u8,
    stderr: []u8,
};

pub const SpawnError = error{
    OutOfMemory,

    /// An error tripped during child fork-context which performs final setup
    /// and calls system exec.
    /// `exec_err` may be inspected to further distinguish the error.
    ExecError,

    /// POSIX-only. `StdIo.Ignore` was selected and opening `/dev/null` returned ENODEV.
    NoDevice,

    /// Windows-only. `cwd` or `argv` was provided and it was invalid WTF-8.
    /// https://simonsapin.github.io/wtf-8/
    InvalidWtf8,

    /// Windows-only. `cwd` was provided, but the path did not exist when spawning the child process.
    CurrentWorkingDirectoryUnlinked,
} ||
    posix.ExecveError ||
    posix.SetIdError ||
    posix.ChangeCurDirError ||
    windows.CreateProcessError ||
    windows.GetProcessMemoryInfoError ||
    windows.WaitForSingleObjectError;

pub const Term = union(enum) {
    unknown: u32,
    exit: u8,
    signal: u8,
    stop: u8,
};

fn addAction(self: *Child, key: Endpoint.Handle, action: Action) !void {
    const new = try self.allocator.create(Action);
    new.* = action;

    const entry = try self.action_set.getOrPut(key);
    debug.assert(!entry.found_existing);
    entry.value_ptr.* = new;

    try self.actions.append(new);
}

fn addCollect(self: *Child, pipe_end: std.fs.File, buffer: *std.ArrayList(u8), max_bytes: ?usize) !void {
    const new = try self.allocator.create(Collector);
    new.* = .{
        .pipe_end = pipe_end,
        .buffer = buffer,
        .max_bytes = max_bytes,
    };
    try self.collectors.append(new);
}

// We are the child.
fn exec(self: *Child, envp: [*:null]const ?[*:0]const u8, argv: [:null]?[*:0]const u8) !void {
    if (self.cwd) |path| try posix.chdir(path);
    if (self.cwd_dir) |dir| try posix.fchdir(dir.fd);
    if (self.gid) |gid| try posix.setregid(gid, gid);
    if (self.uid) |uid| try posix.setreuid(uid, uid);

    for (self.actions.items) |action| {
        switch (action.*) {
            .inherit => {},
            .close => |ep| posix.close(ep.getHandle()),
            .redirect => |r| try posix.dup2(r.to.getHandle(), r.endpoint.getHandle()),
        }
    }

    if (self.close_range) |range| {
        var i: Endpoint.Handle = range.begin;
        while (i < range.end) : (i += 1) if (!self.action_set.contains(i)) posix.close(i);
    }

    return switch (self.expand_arg0) {
        .expand => posix.execvpeZ_expandArg0(.expand, argv.ptr[0].?, argv.ptr, envp),
        .no_expand => posix.execvpeZ_expandArg0(.no_expand, argv.ptr[0].?, argv.ptr, envp),
    };
}

// Actions performed in child fork-context before calling system exec.
const Action = union(enum) {
    /// Child endpoint is inherited from parent.
    inherit: Endpoint,

    /// Child endpoint is closed.
    close: Endpoint,

    /// Child endpoint is redirected to another child endpoint.
    redirect: struct {
        endpoint: Endpoint,
        to: Endpoint,
    },
};

const Collector = struct {
    pipe_end: std.fs.File,
    buffer: *std.ArrayList(u8),
    max_bytes: ?usize,
};

const Endpoint = union(enum) {
    /// Symbolic endpoint representing STDIN.
    stdin: void,

    /// Symbolic endpoint representing STDOUT.
    stdout: void,

    /// Symbolic endpoint representing STDERR.
    stderr: void,

    /// Symbolic endpoint representing '/dev/null'.
    dev_null: void,

    /// Native endpoint.
    handle: Handle,

    /// Stdlib endpoint.
    file: std.fs.File,

    /// Endpoint to a newly created file.
    create: struct {
        path: []const u8,
        flags: std.fs.File.CreateFlags,
    },

    /// Endpoint to an existing file.
    open: struct {
        path: []const u8,
        flags: std.fs.File.OpenFlags,
    },

    fn fromAny(endpoint: anytype, comptime to: bool) !Endpoint {
        const T = @TypeOf(endpoint);
        if (T == @TypeOf(.EnumLiteral)) {
            if (endpoint == .dev_null and !to) @compileError("unexpected EnumLiteral '." ++ @tagName(endpoint) ++ "'");
            return endpoint;
        } else if (T == Endpoint) {
            return endpoint;
        } else if (T == Handle) {
            return .{ .handle = endpoint };
        } else if (T == std.fs.File) {
            return .{ .file = endpoint };
        } else if (to) {
            // tuple[0]: .create | .open
            // tuple[1]: string
            // tuple[2]: optional, nested create/open flags tuple
            switch (endpoint[0]) {
                .create => return .{
                    .create = .{
                        .path = endpoint[1],
                        .flags = if (endpoint.len == 2) .{} else endpoint[2],
                    },
                },
                .open => return .{
                    .open = .{
                        .path = endpoint[1],
                        .flags = if (endpoint.len == 2) .{} else endpoint[2],
                    },
                },
                else => @compileError("expecting first tuple item to be one of { .create, .open }"),
            }
        }

        @compileError("unexpected type '" ++ @typeName(T) ++ "' with value '" ++ @tagName(endpoint) ++ "'");
    }

    fn getHandle(self: Endpoint) Handle {
        return switch (self) {
            .stdin => posix.STDIN_FILENO,
            .stdout => posix.STDOUT_FILENO,
            .stderr => posix.STDERR_FILENO,
            .dev_null => unreachable,
            .handle => |h| h,
            .file => |f| f.handle,
            .create => unreachable,
            .open => unreachable,
        };
    }

    fn getFile(self: Endpoint) std.fs.File {
        return .{ .handle = self.getHandle() };
    }

    const Handle = std.fs.File.Handle;
};

// TODO: mike: move to std.process and rename -> createNullDelimitedEnvironFromEnvMap()
pub fn createNullDelimitedEnvMap(arena: mem.Allocator, env: *const std.process.EnvMap) ![:null]?[*:0]u8 {
    const envp_count = env.count();
    const envp_buf = try arena.allocSentinel(?[*:0]u8, envp_count, null);
    {
        var it = env.iterator();
        var i: usize = 0;
        while (it.next()) |pair| : (i += 1) {
            const env_buf = try arena.allocSentinel(u8, pair.key_ptr.len + pair.value_ptr.len + 1, 0);
            @memcpy(env_buf[0..pair.key_ptr.len], pair.key_ptr.*);
            env_buf[pair.key_ptr.len] = '=';
            @memcpy(env_buf[pair.key_ptr.len + 1 ..][0..pair.value_ptr.len], pair.value_ptr.*);
            envp_buf[i] = env_buf.ptr;
        }
        debug.assert(i == envp_count);
    }
    return envp_buf;
}

// TODO: mike: move to std.process
/// Read '/proc/self/environ' and return null-delimited environ.
/// Caller owns returned memory.
fn createNullDelimitedEnvironFromProcfs(allocator: mem.Allocator) !NullDelimitedEnviron {
    const f = std.fs.cwd().openFile("/proc/self/environ", .{}) catch return error.SystemResources;
    defer f.close();
    const bytes = try f.reader().readAllAlloc(allocator, 1024 * 1024);
    var buf = std.ArrayList(?[*:0]u8).init(allocator);
    defer buf.deinit();

    if (bytes.len != 0) try buf.append(@ptrCast(&bytes[0]));
    var i: usize = 1;
    var grab: bool = false;
    while (i < bytes.len) : (i += 1) {
        if (grab) {
            grab = false;
            try buf.append(@ptrCast(&bytes[i]));
            continue;
        }
        if (bytes[i] == 0) grab = true;
    }
    try buf.append(null);
    return .{ .slice = try buf.toOwnedSlice(), .backing = bytes };
}

const NullDelimitedEnviron = struct {
    slice: []?[*:0]u8,
    backing: []u8,

    fn deinit(self: @This(), allocator: mem.Allocator) void {
        allocator.free(self.slice);
        allocator.free(self.backing);
    }
};

test {
    _ = @import("Child_test.zig");
}

// TODO: mike: nuke when finished no-libc testing
export fn foo() void {
    bar() catch |err| {
        std.log.err("ERR: {}", .{err});
    };
}

// TODO: mike: nuke when finished no-libc testing
fn bar() !void {
    var _arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const arena = _arena.allocator();

    var env = std.process.EnvMap.init(arena);
    const result = try createNullDelimitedEnvironFromProcfs(arena);
    defer result.deinit(arena);
    for (result.slice) |ptr| {
        const line = ptr orelse continue;
        const span = mem.span(line);
        if (mem.indexOfScalar(u8, span, '=')) |pos| {
            try env.put(span[0..pos], span[pos + 1 ..]);
        }
    }
    try env.put("MIKE", "WAS HERE");

    var child = Child.init(arena, &.{"env"});
    defer child.deinit();
    child.env = &env;
    try child.spawn();
    const wr = try child.wait();
    _ = wr;
}
