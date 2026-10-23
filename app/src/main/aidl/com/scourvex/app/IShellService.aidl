package com.scourvex.app;

// Runs inside Shizuku's process as the shell uid (2000).
interface IShellService {
    // Shizuku calls this transaction id to stop the service.
    void destroy() = 16777114;

    // Runs a shell command; returns "exitCode\n" followed by stdout+stderr (truncated to 256 KB).
    String exec(String command) = 1;

    // Writes "size\tmtimeMillis\tflags\tpath" lines for everything under root,
    // never stat'ing, entering or reporting anything on the skip list (only the parent's name list is read). Flags: d dir, f file,
    // u directory that could not be listed. Closes sink when done.
    void walk(String root, in String[] skip, in ParcelFileDescriptor sink) = 2;

    // Opens a file for reading as shell uid. Throws SecurityException for a skipped path.
    ParcelFileDescriptor open(String path, in String[] skip) = 3;

    // Deletes a file or directory tree except skip-list entries. Returns bytes freed, or -1 on failure/refusal.
    long delete(String path, in String[] skip) = 4;
}
