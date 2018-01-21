package main

import (
	"fmt"
	"github.com/cculianu/brute38/bip38"
	"github.com/docopt/docopt.go"
	"log"
	"runtime"
	"strconv"
	"strings"
	"os"
    "bufio"
)

var APP_NAME string = "BIP38 Bruteforce Cracker"
var APP_USAGE string = `BIP38 Bruteforce Cracker v 1.4.2
Copyright (c) 2018, Calin Culianu <calin.culianu@gmail.com>
BTC & BCH Donation Address: 1Ca1inQuedcKdyELCTmN8AtKTTehebY4mC 

Usage:
  brute38 [--chunk=N/T] [--charset=S] [--coin=C] [-t N] [--resume=NUM]
  brute38 [--chunk=N/T] [--charset=S] [--coin=C] [-t N] [--resume=NUM] <pwlen_or_pat> <privatekey>
  brute38 [--chunk=N/T] [--coin=C] [-t N] [--resume=NUM] [-s] -i <input_file> <privatekey>
   
Default key:
  If no privkey is specified,
         6PfQoEzqbz3i2LpHibYnwAspwBwa3Nei1rU7UH9yzfutXT7tyUzV8aYAvG
  is used, with pwlen 4 (equivalent to pattern: '????').

Specifying a key and a set of passwords to try:

  <privatekey>   Bruteforce crack the given BIP38 key.

  <pwlen_or_pat> Length, in characters, of the original passphrase. Cracking
                 will try all possible combinations of characters from charset
                 of length pwlen.
                                        *OR*
                 A pattern, where ? represents unknown characters, eg:
                    foo??bar?     -- try things like foo12bar3, fooABbarZ,
                                     fooefbarg, etc
                    ??foo???bar?? -- try things like ABfooCDEbarFG,
                                     12foo345bar67, etc
                 
                 CAVEAT: Note that in this scheme there is no way to represent
                 a '?' character in the static pattern -- ? will always match
                 an unknown character!
                 
                 NOTE: Specifying eg ???? as the pattern is equivalent to
                 specifying pwlen of 4 (for users of versions 1.1 of this program
                 which *only* had a pwlen parameter, and lacked a pattern matcher).

  <input_file>   Instead of specifying a pattern and a character set, simply
                 read a list of passwords to try from input_file. The
                 passwords should be one per line. Leading/trailing whitespace
                 will be trimmed from the lines read, unless -s is specified.

Options:
  --coin=C       Specify which network the original address was for. Currently
                 only 'btc' and 'onion' are supported for this parameter.
                 Defaults to: btc
  --chunk=N/T    For running on multiple machines to search the same space,
                 break space up into T pieces and process piece N
  --charset=S    The set of characters to use. Defaults to
                   !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_abcdefghijklmnopqrstuvwxyz{|}~
                 Be sure to set this as restrictive as possible as it greatly
                 affects runtime and search space complexity! (Not used in
                 <input_file> mode.)
  -t N           Set maximum threads to N, defaults to number of CPUs detected
  --resume=NUM   For continuing from a previously-aborted run. Specify the
                 resume offset to continue from, as printed onscreen after a ^C
  -i             Use input file reading mode. Next argument should be a
                 filename to read.  See <input_file> above.
  -s             When using <input_file> reading mode, specifies that leading
                 and trailing whitespace should NOT be trimmed from each
                 password that will be tried (default is to trim).
  -h             Usage Help
  
Examples:
    brute38 --resume=3 m?p 6PRM2NBu9Zg9Z5Loxma1RUQiktGDQrqLBg3X7171UDJt9bPTGDqSHWibTh
        Resumes at 3, searches a password of length 3 with the middle
        character being unknown, from the entire ASCII set.
        
    brute38 --charset='mopab' 3 6PRM2NBu9Zg9Z5Loxma1RUQiktGDQrqLBg3X7171UDJt9bPTGDqSHWibTh
        Searches a password of length 3 with all characters being unknown,
        from a very limited set.

    brute38 --charset='12345' 'foo??bar???' 6PRSWiQDUmjYFtZ4PyVDNa9cRABDwoegJK8N96vBL4ZQSDj55ukRhYiXu9
        Searches a password of length 11, with 2 middle characters unknown and
        3 at the end unknonw, from a very small numeric set.
        Hint: the actual password above was 'foo35bar111'. 
 
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
    infile := ""
    notrim := false
    networkVersion := [2]byte{0x0,0x80} // BTC
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
    if arguments["--coin"] != nil {
        switch (strings.ToLower(arguments["--coin"].(string))) {
            case "btc":
                networkVersion[0] = 0x0
                networkVersion[1] = 0x80
            case "onion":
                networkVersion[0] = 0x1f
                networkVersion[1] = 0x9f
            default: log.Fatal("Unknown coin: " + arguments["--coin"].(string) + ".  Supported coins are: btc, onion")
        }
    } else {
        
    }
    if arguments["-i"] != nil && arguments["-i"].(bool) {
        infile = arguments["<input_file>"].(string)
    }
    if arguments["-s"] != nil && arguments["-s"].(bool) {
        if infile == "" {
            log.Fatal("Option -s can only be used if using -i mode!")
        }
        notrim = true
    }
	if arguments["--charset"] != nil {
        if infile != "" {
            log.Fatal("--charset argument cannot be combined with -i!")
        }
		charset = arguments["--charset"].(string)
	}
	var priv string = "6PfQoEzqbz3i2LpHibYnwAspwBwa3Nei1rU7UH9yzfutXT7tyUzV8aYAvG" // original reddit key see post: http://www.reddit.com/r/Bitcoin/comments/1zkcya/lets_see_how_long_it_takes_to_crack_a_4_digit/
	var pwlen int = 4
	var pat string = ""
	if arguments["<privatekey>"] != nil {
		priv = arguments["<privatekey>"].(string)
	}
	if arguments["<pwlen_or_pat>"] != nil {
        if infile != "" {
            log.Fatal("<pwlen_or_pat> cannot be combined with -i!")
        }
		var err error
		pwlen, err = strconv.Atoi(arguments["<pwlen_or_pat>"].(string))
		if err == nil {
			// used old 'pwlen' syntax, so make pattern be a string full of '?'
			if pwlen < 1 {
				log.Fatal("pwlen must be greater than or requal to 1!")
			}
		} else {
			// uses new 'pattern' syntax
			pat = arguments["<pwlen_or_pat>"].(string)
			pwlen = 0
			runes := []rune(pat)
			for i := 0; i < len(runes); i++ {
				if runes[i] == '?' { pwlen++ }
			}
			if pwlen < 1 || len(runes) < 1 {
				log.Fatal("Error parsing pattern.  Make sure it contains at least one '?' character!")
			}
		}
	}
    
    var lines []string = nil
    if infile != "" {
        fmt.Printf("Reading password file into memory: %s...\n", infile)
        var mem uint64
        lines, mem = readAllLines(infile, !notrim)
        fmt.Printf("%s memory used for password file data\n",prettyFormatMem(mem))
    }
	
	ncpu := runtime.NumCPU()
	if arguments["-t"] != nil {
		ncpu, _ = strconv.Atoi(arguments["-t"].(string))
	}
	var resume uint64 = 0
	if arguments["--resume"] != nil {
		resume, _ = strconv.ParseUint(arguments["--resume"].(string), 10, 64)
	}
	fmt.Printf("Running brute force for BIP38-encrypted key on %d CPUs\n", ncpu)
	runtime.GOMAXPROCS(ncpu)
	result := bip38.BruteChunk(ncpu, priv, charset, pwlen, pat, lines, chunk, chunks, resume, networkVersion)
	if result == "" {
		fmt.Printf("\nNot found.\n")
		os.Exit(2)
	} else if strings.HasPrefix(result, "to resume") {
		fmt.Printf("Exiting... %s                                               \n", result)
		os.Exit(3)
	} else {
		fmt.Printf("\n!!! FOUND !!!!\n%s\n", result)
		os.Exit(0)	
	}
	os.Exit(4) // not reached but added here defensively
}

func readAllLines(fileName string, trim bool) (lines []string, memUsed uint64) {
    file, err := os.Open(fileName)
    if (err != nil) {
        log.Fatal(fmt.Sprintf("Cannot open input file, error was '%s'",err.Error()))
    }
    scanner := bufio.NewScanner(file)
    var mem runtime.MemStats
    runtime.GC()
    runtime.ReadMemStats(&mem)
    memUsed = mem.Alloc
//    var tot uint64 = 0
	for scanner.Scan() {
		line := scanner.Text()
        if trim {
            line = strings.TrimSpace(line)
        }
        if len(line) > 0 {
            lines = append(lines,line)
//            tot += uint64(len(line))
        }
	}
	if err = scanner.Err(); err != nil {
		log.Fatal("error reading input file:" + err.Error())
	}
    runtime.GC()
    runtime.ReadMemStats(&mem)
    memUsed = mem.Alloc - memUsed
//    memUsed = tot
    return
}

func prettyFormatMem(size uint64) string {
    rem := uint64(0)
    suffixes := []string{ "bytes", "KB", "MB", "GB", "TB"}
    var i int
    for i = 0; i < len(suffixes)-1 && size > 1024; i++ {
        rem = size % 1024
        size /= 1024
    }
    if rem > 0 {
        rem = (rem*100)/1024
        return fmt.Sprintf("%v.%v %s",size,rem,suffixes[i])        
    }
    return fmt.Sprintf("%v %s",size,suffixes[i])
}
