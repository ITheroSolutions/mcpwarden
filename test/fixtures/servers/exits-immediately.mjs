#!/usr/bin/env node
/**
 * A server that dies the moment it is spawned.
 *
 * This is the shape of a real and common failure: a server whose package needs
 * an argument it was not given, or whose runtime is missing, exits before it
 * ever reads a byte of stdin. A capture against it must fail with a typed,
 * explainable error rather than waiting on a process that no longer exists.
 */

process.stderr.write('fatal: missing required argument --dsn\n');
process.exit(1);
