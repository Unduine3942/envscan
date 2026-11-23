// main.go: envscan, the static Linux scanner (port of envscan.sh). See engine_scan.go.
package main

import "os"

func main() { os.Exit(runMain(os.Args[1:], os.Stdout, os.Stderr, os.Environ())) }
