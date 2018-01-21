brute38
=======

(C) 2018 Calin Culianu <calin.culianu@gmail.com> BCH/BTC: 1Ca1inQuedcKdyELCTmN8AtKTTehebY4mC

BIP38 brute force password cracker, written in Go

Based on Charlie Hothersall-Thomas' implementation, but added features, bugs fixed, 
and expanded with more command-line options and better support for variable-length passwords. 

See Charlie Hothersall-Thomas' original implementation at: https://github.com/chigley/bip38

Includes support for Bitcoin addresses, plus MANY other coins (run it with --coin=list option to see the list).

Requires:

- Go Language 

Installation/Compilation:

> go get

> go build

Running:

> ./brute38 -h 

This program takes a variety of command-line options.  See the help (-h).

All of the above assumes you have Go set up properly and you copied the code into your GOPATH/src somewhere.
