package main

import (
	"fmt"
	"github.com/cculianu/brute38/bip38"
	"github.com/docopt/docopt.go"
	"log"
	"runtime"
	"strconv"
	"strings"
)

var APP_NAME string = "BIP38 Bruteforce Cracker"
var APP_USAGE string = `BIP38 Bruteforce Cracker v 1.2
Copyright (c) 2017, Calin Culianu <calin.culianu@gmail.com>
BTC & BCH Donation Address: 1Ca1inQuedcKdyELCTmN8AtKTTehebY4mC 

Usage:
  brute38 [--chunk=N/T] [--charset=S] [-t N] [--resume=NUM]
  brute38 [--chunk=N/T] [--charset=S] [-t N] [--resume=NUM] <pwlen> <privatekey>
   
Default key:
  If no privkey is specified, 6PfQoEzqbz3i2LpHibYnwAspwBwa3Nei1rU7UH9yzfutXT7tyUzV8aYAvG is used, with pwlen 4

Specifying a key to crack:
  <privatekey>   Bruteforce crack the given BIP38 key.
  <pwlen>        Length, in characters, of the original passphrase.

Options:
  --chunk=N/T    For running on multiple machines to search the same space, break space up into T pieces and process piece N
  --charset=S    The set of characters to use. Defaults to !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_abcdefghijklmnopqrstuvwxyz{|}~. 
  -t N           Set maximum threads to N
  --resume=NUM   For continuing from a previously-aborted run. Specify the resume offset to continue from, as printed onscreen after a ^C
  -h             Usage Help
`

var arguments map[string]interface{}

func init() {
	var err error

	arguments, err = docopt.Parse(APP_USAGE, nil, true, APP_NAME, false)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	chunks := 1
	chunk := 0
	charset := "" // use default
	if arguments["--chunk"] != nil {
		var n int
		var err error
		n, err = fmt.Sscanf(arguments["--chunk"].(string), "%d/%d", &chunk, &chunks)
		if err != nil {
			log.Fatal(err)
		}
		if n != 2 {
			log.Fatal("Parse error for --chunk argument")
		}
		if chunk >= chunks || chunk < 0 || chunks <= 0 {
			log.Fatal("chunk parameter invalid")
		}
	}
	if arguments["--charset"] != nil {
		charset = arguments["--charset"].(string)
	}
	var priv string = "6PfQoEzqbz3i2LpHibYnwAspwBwa3Nei1rU7UH9yzfutXT7tyUzV8aYAvG" // original reddit key see post: http://www.reddit.com/r/Bitcoin/comments/1zkcya/lets_see_how_long_it_takes_to_crack_a_4_digit/
	var pwlen int = 4
	if arguments["<privatekey>"] != nil {
		priv = arguments["<privatekey>"].(string)
	}
	if arguments["<pwlen>"] != nil {
		pwlen, _ = strconv.Atoi(arguments["<pwlen>"].(string))
	}
	ncpu := runtime.NumCPU()
	if arguments["-t"] != nil {
		ncpu, _ = strconv.Atoi(arguments["-t"].(string))
	}
	var resume uint64 = 0
	if arguments["--resume"] != nil {
		resume, _ = strconv.ParseUint(arguments["--resume"].(string), 10, 64)
	}
	fmt.Printf("Running brute force for BIP0038-encrypted string on %d CPUs\n", ncpu)
	runtime.GOMAXPROCS(ncpu)
	result := bip38.BruteChunk(ncpu, priv, charset, pwlen, chunk, chunks, resume)
	if result == "" {
		fmt.Printf("\nNot found.\n")
		return
	} else if strings.HasPrefix(result, "to resume") {
		fmt.Printf("Exiting... %s                                               \n", result)
	} else {
		fmt.Printf("\n!!! FOUND !!!!\n%s\n", result)
	}
}
