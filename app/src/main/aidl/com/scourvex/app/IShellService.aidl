package com.scourvex.app;

// Runs inside Shizuku's process as the shell uid (2000).
interface IShellService {
    // Shizuku calls this transaction id to stop the service.
    void destroy() = 16777114;

    // Runs a shell command; returns "exitCode\n" followed by stdout+stderr (truncated to 256 KB).
    String exec(String command) = 1;

    // Writes "size\tmtimeMillis\tflags\tpath" lines (flags: d = directory) for everything under root,
    // skipping any path that starts with one of skipPrefixes. Closes sink when done.
    void walk(String root, in String[] skipPrefixes, in ParcelFileDescriptor sink) = 2;

    // Opens a file for reading as shell uid.
    ParcelFileDescriptor open(String path) = 3;

    // Deletes a file or directory tree. Returns bytes freed, or -1 on failure.
    long delete(String path) = 4;
}
