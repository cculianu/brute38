brute38
=======

(C) 2018 Calin Culianu <calin.culianu@gmail.com> BCH/BTC: 1Ca1inQuedcKdyELCTmN8AtKTTehebY4mC

BIP38 brute force password cracker, written in Go

Based on Charlie Hothersall-Thomas' implementation, but added features, bugs fixed, 
and expanded with more command-line options and better support for variable-length passwords. 

See Charlie Hothersall-Thomas' original implementation at: https://github.com/chigley/bip38

Includes support for Bitcoin addresses, plus MANY other coins (run it with the --coin=list option to see the full list of supported coin addresses).

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
