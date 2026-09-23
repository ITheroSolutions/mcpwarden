@ECHO OFF
:: Shaped like npm's own npx.cmd: it forwards its arguments with %*,
:: which makes cmd.exe parse them a second time. That second parse is where
:: single escaping stops being enough.
SETLOCAL
"node" "%~dp0echo-args.mjs" %*
