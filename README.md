# brute38
## Resumable BIP38 Brute Force Password Cracker (written in Go)

#### (C) 2018 Calin Culianu <calin.culianu@gmail.com> BCH/BTC: 1Ca1inQuedcKdyELCTmN8AtKTTehebY4mC

Based on Charlie Hothersall-Thomas' implementation, but added features, bugs fixed, 
and expanded with more command-line options and better support for variable-length passwords. 

See Charlie Hothersall-Thomas' original implementation at: https://github.com/chigley/bip38

## Distinguishing Features:

- Support for Bitcoin, Bitcoin Cash plus over 170+ other different address styles. Run it with the --coin=list option to see the full list of supported coins/addresses.
- Design philosophy is for a *resumable* brute force cracker. This way you can start and stop it and let cracking sessions run for weeks at a time, and persist across reboots. Given the same input parameters (password length, thread count, pattern, key, etc), you can hit CTRL-C at any time, get a magic number, and then re-run the app with the --resume=N parameter, and it will continue brute forcing from where it left off.

## Requires:

- Go Language 

## Installation/Compilation:

> go get github.com/cculianu/brute38

> go build github.com/cculianu/brute38

> go install github.com/cculianu/brute38

## Running:

(Unix/Linux/OSX) 

> $GOPATH/bin/brute38 -h 

(Windows)

> %GOPATH%/bin/brute38.exe -h

All of the above assumes you have Go set up properly.

## Feature Wishlist:

- I really want to add GPU-based cracking. I need to read up on getting a scrypt password hasher to work in OpenCL. Any volunteers to help with this would be really greatly appreciated! 

## Caveats

Resumability has some tradeoffs: 

1. It always searches the keyspace linearly, so no lotto-style luck is ever involved. 
2. Regular expression pattern specs don't naturally fit in with the design so I have been holding off on implementing them. The preferred workflow if you want regular expressions is to generate a flat file with a whole bunch of passphrases to try, then pass that to the program with the -i parameter.
3. To correctly resume a previously-interrupted search, you must use the same specification for the search. This includes: number of threads (-t), BIP38 key, pattern (or pattern length or -i input file), and --charset all need to be the same! The program will not warn you if you are resuming a search incorrectly.

## Questions? Comments?

For feature requests, troubleshooting tips, love letters, hatemail, etc, don't be shy and feel free to contact me!
