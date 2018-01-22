brute38
=======

(C) 2018 Calin Culianu <calin.culianu@gmail.com> BCH/BTC: 1Ca1inQuedcKdyELCTmN8AtKTTehebY4mC

BIP38 brute force password cracker, written in Go

Based on Charlie Hothersall-Thomas' implementation, but added features, bugs fixed, 
and expanded with more command-line options and better support for variable-length passwords. 

See Charlie Hothersall-Thomas' original implementation at: https://github.com/chigley/bip38

Distinguishing Features:

- Support for Bitcoin, Bitcoin Cash plus over 170+ other different address styles. Run it with the --coin=list option to see the full list of supported coins/addresses.
- Design philosophy is for a *resumable* brute force cracker. This way you can start and stop it and let cracking sessions run for weeks at a time. Given the same input parameters (password length, thread count, pattern, key, etc), you can hit CTRL-C at any time, get a magic number, and then re-run the app with the --resume=N parameter.


Requires:

- Go Language 

Installation/Compilation:

> go get github.com/cculianu/brute38

> go build github.com/cculianu/brute38

> go install github.com/cculianu/brute38

Running:

> $GOPATH/bin/brute38 -h 

(Windows)

> %GOPATH%/bin/brute38.exe -h

All of the above assumes you have Go set up properly.
