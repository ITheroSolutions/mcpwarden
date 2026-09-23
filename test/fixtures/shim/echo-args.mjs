// Prints the arguments it received as JSON, so a test can compare them byte for
// byte against what was intended.
process.stdout.write(JSON.stringify(process.argv.slice(2)));
