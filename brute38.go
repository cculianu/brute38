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
    "sort"
)

var APP_NAME string = "BIP38 Bruteforce Cracker"
var APP_USAGE string = `BIP38 Bruteforce Cracker v 1.4.5
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
  --coin=C       Specify which network the original address was for. Specify
                 'list' to see a list of supported coins.
                 Defaults to: btc
                 Note: bch and btc are identical for addresses
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
    coin := supportedCoins[defaultCoin] // default is BTC
    
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
        carg := strings.ToLower(arguments["--coin"].(string))
        var ok bool
        coin, ok = supportedCoins[carg]
        if !ok && carg != "list" {
            fmt.Fprintln(os.Stderr, "Unknown coin '" + carg +"'.  Specify --coin=list to see a list of valid coin arguments.")
            os.Exit(1)
        } 
        if !ok || carg == "list" {
            fmt.Fprintln(os.Stdout, "Supported coins are:" )
            sorted := make([]string,0)
            for k := range supportedCoins {
                sorted = append(sorted, k)
            }
            sort.Strings(sorted)
            for i := range sorted {
                k := sorted[i]
                c := supportedCoins[k]
                fmt.Fprintf(os.Stdout,"    %18s\t(for %s)\n",k,c.name)
            }
            os.Exit(0)
        }
        // ok to proceed,  --coin=arg is ok
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
    result := bip38.BruteChunk(ncpu, priv, charset, pwlen, pat, lines, chunk, chunks, resume, [2]byte{coin.networkVersion, coin.privateKeyPrefix}, coin.name)
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

type Coin struct {
    name, ticker string
    networkVersion, privateKeyPrefix byte
}

var defaultCoin = "btc"

var supportedCoins = map[string]Coin{
    "btc"   : {name: "Bitcoin",           ticker: "btc",         networkVersion: 0x00, privateKeyPrefix: 0x80},
    "bch"   : {name: "Bitcoin Cash",      ticker: "bch",         networkVersion: 0x00, privateKeyPrefix: 0x80},
    "btcd"  : {name: "Bitcoin Dark",      ticker: "btcd",        networkVersion: 0x3c, privateKeyPrefix: 0xbc},
    "btg"   : {name: "Bitcoin Gold",      ticker: "btg",         networkVersion: 0x26, privateKeyPrefix: 0x80},
    "onion" : {name: "Deep Onion",        ticker: "onion",       networkVersion: 0x1f, privateKeyPrefix: 0x9f},
    "doge"  : {name: "Doge Coin",         ticker: "doge",        networkVersion: 0x1e, privateKeyPrefix: 0x9e},
    "dogd"  : {name: "Doge Coin Dark",    ticker: "doged",       networkVersion: 0x1e, privateKeyPrefix: 0x9e},
    "ltc"   : {name: "Litecoin",          ticker: "ltc",         networkVersion: 0x30, privateKeyPrefix: 0xb0},
    "vtc"   : {name: "VertCoin",          ticker: "vtc",         networkVersion: 0x47, privateKeyPrefix: 0x80},
    "cdy"   : {name: "Bitcoin Candy",     ticker: "cdy",         networkVersion: 0x1c, privateKeyPrefix: 0x80},
    
    // below are a bunch of coins taken from the javascript at walletgenerator.net.  not tested.. but should work
    "2give" : {name: "2GIVE", ticker: "2give", networkVersion: 0x27, privateKeyPrefix:  0xa7},
    "42coin" : {name: "42coin", ticker: "42coin", networkVersion: 0x08, privateKeyPrefix:  0x88},
    "acoin" : {name: "Acoin", ticker: "acoin", networkVersion: 0x17, privateKeyPrefix:  0xe6},
    "alphacoin" : {name: "Alphacoin", ticker: "alphacoin", networkVersion: 0x52, privateKeyPrefix:  0xd2},
    "alqo" : {name: "Alqo", ticker: "alqo", networkVersion: 0x17, privateKeyPrefix:  0xc1},
    "animecoin" : {name: "Animecoin", ticker: "animecoin", networkVersion: 0x17, privateKeyPrefix:  0x97},
    "anoncoin" : {name: "Anoncoin", ticker: "anoncoin", networkVersion: 0x17, privateKeyPrefix:  0x97},
    "apexcoin" : {name: "Apexcoin", ticker: "apexcoin", networkVersion: 0x17, privateKeyPrefix:  0x97},
    "auroracoin" : {name: "Auroracoin", ticker: "auroracoin", networkVersion: 0x17, privateKeyPrefix:  0x97},
    "aquariuscoin" : {name: "Aquariuscoin", ticker: "aquariuscoin", networkVersion: 0x17, privateKeyPrefix:  0x97},
    "bbqcoin" : {name: "BBQcoin", ticker: "bbqcoin", networkVersion: 0x55, privateKeyPrefix:  0xd5},
    "biblepay" : {name: "Biblepay", ticker: "biblepay", networkVersion: 0x19, privateKeyPrefix:  0xb6},
//    "bitcoin" : {name: "Bitcoin", ticker: "bitcoin", networkVersion: 0x00, privateKeyPrefix:  0x80},
//    "bitcoincash" : {name: "BitcoinCash", ticker: "bitcoincash", networkVersion: 0x00, privateKeyPrefix:  0x80},
//    "bitcoindark" : {name: "BitcoinDark", ticker: "bitcoindark", networkVersion: 0x3c, privateKeyPrefix:  0xbc},
//    "bitcoingold" : {name: "BitcoinGold", ticker: "bitcoingold", networkVersion: 0x26, privateKeyPrefix:  0x80},
    "bitconnect" : {name: "Bitconnect", ticker: "bitconnect", networkVersion: 0x12, privateKeyPrefix:  0x92},
    "birdcoin" : {name: "Birdcoin", ticker: "birdcoin", networkVersion: 0x2f, privateKeyPrefix:  0xaf},
    "bitsynq" : {name: "BitSynq", ticker: "bitsynq", networkVersion: 0x3f, privateKeyPrefix:  0xbf},
    "bitzeny" : {name: "BitZeny", ticker: "bitzeny", networkVersion: 0x51, privateKeyPrefix:  0x80},
    "blackcoin" : {name: "Blackcoin", ticker: "blackcoin", networkVersion: 0x19, privateKeyPrefix:  0x99},
    "blackjack" : {name: "BlackJack", ticker: "blackjack", networkVersion: 0x15, privateKeyPrefix:  0x95},
    "blocknet" : {name: "BlockNet", ticker: "blocknet", networkVersion: 0x1a, privateKeyPrefix:  0x9a},
    "bolivarcoin" : {name: "BolivarCoin", ticker: "bolivarcoin", networkVersion: 0x55, privateKeyPrefix:  0xd5},
    "boxycoin" : {name: "BoxyCoin", ticker: "boxycoin", networkVersion: 0x4b, privateKeyPrefix:  0xcb},
    "bunnycoin" : {name: "BunnyCoin", ticker: "bunnycoin", networkVersion: 0x1a, privateKeyPrefix:  0x9a},
    "cagecoin" : {name: "Cagecoin", ticker: "cagecoin", networkVersion: 0x1f, privateKeyPrefix:  0x9f},
    "canadaecoin" : {name: "CanadaeCoin", ticker: "canadaecoin", networkVersion: 0x1c, privateKeyPrefix:  0x9c},
    "cannabiscoin" : {name: "CannabisCoin", ticker: "cannabiscoin", networkVersion: 0x1c, privateKeyPrefix:  0x9c},
    "capricoin" : {name: "Capricoin", ticker: "capricoin", networkVersion: 0x1c, privateKeyPrefix:  0x9c},
    "cassubiandetk" : {name: "CassubianDetk", ticker: "cassubiandetk", networkVersion: 0x1e, privateKeyPrefix:  0x9e},
    "cashcoin" : {name: "CashCoin", ticker: "cashcoin", networkVersion: 0x22, privateKeyPrefix:  0xa2},
    "catcoin" : {name: "Catcoin", ticker: "catcoin", networkVersion: 0x15, privateKeyPrefix:  0x95},
    "chaincoin" : {name: "ChainCoin", ticker: "chaincoin", networkVersion: 0x1c, privateKeyPrefix:  0x9c},
    "colossuscoinxt" : {name: "ColossusCoinXT", ticker: "colossuscoinxt", networkVersion: 0x1e, privateKeyPrefix:  0xd4},
    "condensate" : {name: "Condensate", ticker: "condensate", networkVersion: 0x3c, privateKeyPrefix:  0xbc},
    "copico" : {name: "Copico", ticker: "copico", networkVersion: 0x1c, privateKeyPrefix:  0x90},
    "corgicoin" : {name: "Corgicoin", ticker: "corgicoin", networkVersion: 0x1c, privateKeyPrefix:  0x9c},
    "cryptobullion" : {name: "CryptoBullion", ticker: "cryptobullion", networkVersion: 0xb, privateKeyPrefix:  0x8b},
    "cryptoclub" : {name: "CryptoClub", ticker: "cryptoclub", networkVersion: 0x23, privateKeyPrefix:  0xa3},
    "cryptoescudo" : {name: "Cryptoescudo", ticker: "cryptoescudo", networkVersion: 0x1c, privateKeyPrefix:  0x9c},
    "cryptonite" : {name: "Cryptonite", ticker: "cryptonite", networkVersion: 0x1c, privateKeyPrefix:  0x80},
    "cryptowisdomcoin" : {name: "CryptoWisdomCoin", ticker: "cryptowisdomcoin", networkVersion: 0x49, privateKeyPrefix:  0x87},
    "c2coin" : {name: "C2coin", ticker: "c2coin", networkVersion: 0x1c, privateKeyPrefix:  0x9c},
    "dash" : {name: "Dash", ticker: "dash", networkVersion: 0x4c, privateKeyPrefix:  0xcc},
    "deafdollars" : {name: "DeafDollars", ticker: "deafdollars", networkVersion: 0x30, privateKeyPrefix:  0xb0},
//    "deeponion" : {name: "DeepOnion", ticker: "deeponion", networkVersion: 0x1f, privateKeyPrefix:  0x9f},
    "devcoin" : {name: "Devcoin", ticker: "devcoin", networkVersion: 0x00, privateKeyPrefix:  0x80},
    "digibyte" : {name: "DigiByte", ticker: "digibyte", networkVersion: 0x1e, privateKeyPrefix:  0x9e},
    "digitalcoin" : {name: "Digitalcoin", ticker: "digitalcoin", networkVersion: 0x1e, privateKeyPrefix:  0x9e},
    "dnotes" : {name: "DNotes", ticker: "dnotes", networkVersion: 0x1f, privateKeyPrefix:  0x9f},
//    "dogecoin" : {name: "Dogecoin", ticker: "dogecoin", networkVersion: 0x1e, privateKeyPrefix:  0x9e},
//    "dogecoindark" : {name: "DogecoinDark", ticker: "dogecoindark", networkVersion: 0x1e, privateKeyPrefix:  0x9e},
    "egulden" : {name: "eGulden", ticker: "egulden", networkVersion: 0x30, privateKeyPrefix:  0xb0},
    "ekrona" : {name: "eKrona", ticker: "ekrona", networkVersion: 0x2d, privateKeyPrefix:  0xad},
    "electra" : {name: "ELECTRA", ticker: "electra", networkVersion: 0x21, privateKeyPrefix:  0xa1},
    "emerald" : {name: "Emerald", ticker: "emerald", networkVersion: 0x22, privateKeyPrefix:  0xa2},
    "emercoin" : {name: "Emercoin", ticker: "emercoin", networkVersion: 0x21, privateKeyPrefix:  0x80},
    "energycoin" : {name: "EnergyCoin", ticker: "energycoin", networkVersion: 0x5c, privateKeyPrefix:  0xdc},
    "espers" : {name: "Espers", ticker: "espers", networkVersion: 0x21, privateKeyPrefix:  0xa1},
    "fastcoin" : {name: "Fastcoin", ticker: "fastcoin", networkVersion: 0x60, privateKeyPrefix:  0xe0},
    "feathercoin" : {name: "Feathercoin", ticker: "feathercoin", networkVersion: 0x0e, privateKeyPrefix:  0x8e},
    "fedoracoin" : {name: "Fedoracoin", ticker: "fedoracoin", networkVersion: 0x21, privateKeyPrefix:  0x80},
    "fibre" : {name: "Fibre", ticker: "fibre", networkVersion: 0x23, privateKeyPrefix:  0xa3},
    "florincoin" : {name: "Florincoin", ticker: "florincoin", networkVersion: 0x23, privateKeyPrefix:  0xb0},
    "flurbo" : {name: "Flurbo", ticker: "flurbo", networkVersion: 0x23, privateKeyPrefix:  0x30},
    "fluttercoin" : {name: "Fluttercoin", ticker: "fluttercoin", networkVersion: 0x23, privateKeyPrefix:  0xa3},
    "frazcoin" : {name: "FrazCoin", ticker: "frazcoin", networkVersion: 0x23, privateKeyPrefix:  0xA3},
    "freicoin" : {name: "Freicoin", ticker: "freicoin", networkVersion: 0x00, privateKeyPrefix:  0x80},
    "fudcoin" : {name: "FUDcoin", ticker: "fudcoin", networkVersion: 0x23, privateKeyPrefix:  0xa3},
    "fuelcoin" : {name: "Fuelcoin", ticker: "fuelcoin", networkVersion: 0x24, privateKeyPrefix:  0x80},
    "fujicoin" : {name: "Fujicoin", ticker: "fujicoin", networkVersion: 0x24, privateKeyPrefix:  0xa4},
    "gabencoin" : {name: "GabenCoin", ticker: "gabencoin", networkVersion: 0x10, privateKeyPrefix:  0x90},
    "globalboost" : {name: "GlobalBoost", ticker: "globalboost", networkVersion: 0x26, privateKeyPrefix:  0xa6},
    "goodcoin" : {name: "Goodcoin", ticker: "goodcoin", networkVersion: 0x26, privateKeyPrefix:  0xa6},
    "gridcoinresearch" : {name: "GridcoinResearch", ticker: "gridcoinresearch", networkVersion: 0x3e, privateKeyPrefix:  0xbe},
    "gulden" : {name: "Gulden", ticker: "gulden", networkVersion: 0x26, privateKeyPrefix:  0xa6},
    "guncoin" : {name: "Guncoin", ticker: "guncoin", networkVersion: 0x27, privateKeyPrefix:  0xa7},
    "hamradiocoin" : {name: "HamRadioCoin", ticker: "hamradiocoin", networkVersion: 0x00, privateKeyPrefix:  0x80},
    "hodlcoin" : {name: "HOdlcoin", ticker: "hodlcoin", networkVersion: 0x28, privateKeyPrefix:  0xa8},
    "htmlcoin" : {name: "HTMLCoin", ticker: "htmlcoin", networkVersion: 0x29, privateKeyPrefix:  0xa9},
    "hyperstake" : {name: "HyperStake", ticker: "hyperstake", networkVersion: 0x75, privateKeyPrefix:  0xf5},
    "imperiumcoin" : {name: "ImperiumCoin", ticker: "imperiumcoin", networkVersion: 0x30, privateKeyPrefix:  0xb0},
    "incakoin" : {name: "IncaKoin", ticker: "incakoin", networkVersion: 0x35, privateKeyPrefix:  0xb5},
    "incognitocoin" : {name: "IncognitoCoin", ticker: "incognitocoin", networkVersion: 0x00, privateKeyPrefix:  0x80},
    "influxcoin" : {name: "Influxcoin", ticker: "influxcoin", networkVersion: 0x66, privateKeyPrefix:  0xe6},
    "innox" : {name: "Innox", ticker: "innox", networkVersion: 0x4b, privateKeyPrefix:  0xcb},
    "iridiumcoin" : {name: "IridiumCoin", ticker: "iridiumcoin", networkVersion: 0x30, privateKeyPrefix:  0xb0},
    "icash" : {name: "iCash", ticker: "icash", networkVersion: 0x66, privateKeyPrefix:  0xcc},
    "ixcoin" : {name: "iXcoin", ticker: "ixcoin", networkVersion: 0x8a, privateKeyPrefix:  0x80},
    "judgecoin" : {name: "Judgecoin", ticker: "judgecoin", networkVersion: 0x2b, privateKeyPrefix:  0xab},
    "jumbucks" : {name: "Jumbucks", ticker: "jumbucks", networkVersion: 0x2b, privateKeyPrefix:  0xab},
    "khcoin" : {name: "KHcoin", ticker: "khcoin", networkVersion: 0x30, privateKeyPrefix:  0xb0},
    "lanacoin" : {name: "Lanacoin", ticker: "lanacoin", networkVersion: 0x30, privateKeyPrefix:  0xb0},
    "latium" : {name: "Latium", ticker: "latium", networkVersion: 0x17, privateKeyPrefix:  0x80},
//    "litecoin" : {name: "Litecoin", ticker: "litecoin", networkVersion: 0x30, privateKeyPrefix:  0xb0},
    "litedoge" : {name: "LiteDoge", ticker: "litedoge", networkVersion: 0x5a, privateKeyPrefix:  0xab},
    "lomocoin" : {name: "LoMoCoin", ticker: "lomocoin", networkVersion: 0x30, privateKeyPrefix:  0xb0},
    "madbytecoin" : {name: "MadbyteCoin", ticker: "madbytecoin", networkVersion: 0x32, privateKeyPrefix:  0x6e},
    "magicinternetmoney" : {name: "MagicInternetMoney", ticker: "magicinternetmoney", networkVersion: 0x30, privateKeyPrefix:  0xb0},
    "magicoin" : {name: "Magicoin", ticker: "magicoin", networkVersion: 0x14, privateKeyPrefix:  0x94},
    "marscoin" : {name: "Marscoin", ticker: "marscoin", networkVersion: 0x32, privateKeyPrefix:  0xb2},
    "martexcoin" : {name: "MarteXcoin", ticker: "martexcoin", networkVersion: 0x32, privateKeyPrefix:  0xb2},
    "masterdoge" : {name: "MasterDoge", ticker: "masterdoge", networkVersion: 0x33, privateKeyPrefix:  0x8b},
    "mazacoin" : {name: "Mazacoin", ticker: "mazacoin", networkVersion: 0x32, privateKeyPrefix:  0xe0},
    "megacoin" : {name: "Megacoin", ticker: "megacoin", networkVersion: 0x32, privateKeyPrefix:  0xb2},
    "mintcoin" : {name: "MintCoin", ticker: "mintcoin", networkVersion: 0x33, privateKeyPrefix:  0xb3},
    "mobiuscoin" : {name: "MobiusCoin", ticker: "mobiuscoin", networkVersion: 0x00, privateKeyPrefix:  0x80},
    "monetaryunit" : {name: "MonetaryUnit", ticker: "monetaryunit", networkVersion: 0x10, privateKeyPrefix:  0x7e},
    "monocle" : {name: "Monocle", ticker: "monocle", networkVersion: 0x32, privateKeyPrefix:  0xb2},
    "mooncoin" : {name: "MoonCoin", ticker: "mooncoin", networkVersion: 0x03, privateKeyPrefix:  0x83},
    "myriadcoin" : {name: "Myriadcoin", ticker: "myriadcoin", networkVersion: 0x32, privateKeyPrefix:  0xb2},
    "namecoin" : {name: "NameCoin", ticker: "namecoin", networkVersion: 0x34, privateKeyPrefix:  0x80},
    "navcoin" : {name: "Navcoin", ticker: "navcoin", networkVersion: 0x35, privateKeyPrefix:  0x96},
    "needlecoin" : {name: "NeedleCoin", ticker: "needlecoin", networkVersion: 0x35, privateKeyPrefix:  0xb5},
    "neoscoin" : {name: "Neoscoin", ticker: "neoscoin", networkVersion: 0x35, privateKeyPrefix:  0xb1},
    "nevacoin" : {name: "Nevacoin", ticker: "nevacoin", networkVersion: 0x35, privateKeyPrefix:  0xb1},
    "novacoin" : {name: "Novacoin", ticker: "novacoin", networkVersion: 0x08, privateKeyPrefix:  0x88},
    "nubits" : {name: "Nubits", ticker: "nubits", networkVersion: 0x19, privateKeyPrefix:  0xbf},
    "nyancoin" : {name: "Nyancoin", ticker: "nyancoin", networkVersion: 0x2d, privateKeyPrefix:  0xad},
    "ocupy" : {name: "Ocupy", ticker: "ocupy", networkVersion: 0x73, privateKeyPrefix:  0xf3},
    "omnicoin" : {name: "Omnicoin", ticker: "omnicoin", networkVersion: 0x73, privateKeyPrefix:  0xf3},
    "onyxcoin" : {name: "Onyxcoin", ticker: "onyxcoin", networkVersion: 0x73, privateKeyPrefix:  0xf3},
    "particl" : {name: "Particl", ticker: "particl", networkVersion: 0x38, privateKeyPrefix:  0x6c},
    "paycoin" : {name: "Paycoin", ticker: "paycoin", networkVersion: 0x37, privateKeyPrefix:  0xb7},
    "pandacoin" : {name: "Pandacoin", ticker: "pandacoin", networkVersion: 0x37, privateKeyPrefix:  0xb7},
    "parkbyte" : {name: "ParkByte", ticker: "parkbyte", networkVersion: 0x37, privateKeyPrefix:  0xb7},
    "pesetacoin" : {name: "Pesetacoin", ticker: "pesetacoin", networkVersion: 0x2f, privateKeyPrefix:  0xaf},
    "phcoin" : {name: "PHCoin", ticker: "phcoin", networkVersion: 0x37, privateKeyPrefix:  0xb7},
    "phoenixcoin" : {name: "PhoenixCoin", ticker: "phoenixcoin", networkVersion: 0x38, privateKeyPrefix:  0xb8},
    "pinkcoin" : {name: "Pinkcoin", ticker: "pinkcoin", networkVersion: 0x3, privateKeyPrefix:  0x83},
    "pivx" : {name: "PIVX", ticker: "pivx", networkVersion: 0x1e, privateKeyPrefix:  0xd4},
    "peercoin" : {name: "Peercoin", ticker: "peercoin", networkVersion: 0x37, privateKeyPrefix:  0xb7},
    "potcoin" : {name: "Potcoin", ticker: "potcoin", networkVersion: 0x37, privateKeyPrefix:  0xb7},
    "primecoin" : {name: "Primecoin", ticker: "primecoin", networkVersion: 0x17, privateKeyPrefix:  0x97},
    "prospercoinclassic" : {name: "ProsperCoinClassic", ticker: "prospercoinclassic", networkVersion: 0x3a, privateKeyPrefix:  0xba},
    "quark" : {name: "Quark", ticker: "quark", networkVersion: 0x3a, privateKeyPrefix:  0xba},
    "qubitcoin" : {name: "Qubitcoin", ticker: "qubitcoin", networkVersion: 0x26, privateKeyPrefix:  0xe0},
    "reddcoin" : {name: "Reddcoin", ticker: "reddcoin", networkVersion: 0x3d, privateKeyPrefix:  0xbd},
    "riecoin" : {name: "Riecoin", ticker: "riecoin", networkVersion: 0x3c, privateKeyPrefix:  0x80},
    "rimbit" : {name: "Rimbit", ticker: "rimbit", networkVersion: 0x3c, privateKeyPrefix:  0xbc},
    "roicoin" : {name: "ROIcoin", ticker: "roicoin", networkVersion: 0x3c, privateKeyPrefix:  0x80},
    "rubycoin" : {name: "Rubycoin", ticker: "rubycoin", networkVersion: 0x3c, privateKeyPrefix:  0xbc},
    "rupaya" : {name: "Rupaya", ticker: "rupaya", networkVersion: 0x3c, privateKeyPrefix:  0xbc},
    "sambacoin" : {name: "Sambacoin", ticker: "sambacoin", networkVersion: 0x3e, privateKeyPrefix:  0xbe},
    "seckcoin" : {name: "SecKCoin", ticker: "seckcoin", networkVersion: 0x3f, privateKeyPrefix:  0xbf},
    "sibcoin" : {name: "SibCoin", ticker: "sibcoin", networkVersion: 0x3f, privateKeyPrefix:  0x80},
    "sixeleven" : {name: "SixEleven", ticker: "sixeleven", networkVersion: 0x34, privateKeyPrefix:  0x80},
    "smileycoin" : {name: "SmileyCoin", ticker: "smileycoin", networkVersion: 0x19, privateKeyPrefix:  0x99},
    "songcoin" : {name: "SongCoin", ticker: "songcoin", networkVersion: 0x3f, privateKeyPrefix:  0xbf},
    "spreadcoin" : {name: "SpreadCoin", ticker: "spreadcoin", networkVersion: 0x3f, privateKeyPrefix:  0xbf},
    "stealthcoin" : {name: "StealthCoin", ticker: "stealthcoin", networkVersion: 0x3e, privateKeyPrefix:  0xbe},
    "stratis" : {name: "Stratis", ticker: "stratis", networkVersion: 0x3f, privateKeyPrefix:  0xbf},
    "swagbucks" : {name: "SwagBucks", ticker: "swagbucks", networkVersion: 0x3f, privateKeyPrefix:  0x99},
    "syscoin" : {name: "Syscoin", ticker: "syscoin", networkVersion: 0x00, privateKeyPrefix:  0x80},
    "tajcoin" : {name: "Tajcoin", ticker: "tajcoin", networkVersion: 0x41, privateKeyPrefix:  0x6f},
    "terracoin" : {name: "Terracoin", ticker: "terracoin", networkVersion: 0x00, privateKeyPrefix:  0x80},
    "titcoin" : {name: "Titcoin", ticker: "titcoin", networkVersion: 0x00, privateKeyPrefix:  0x80},
    "tittiecoin" : {name: "TittieCoin", ticker: "tittiecoin", networkVersion: 0x41, privateKeyPrefix:  0xc1},
    "topcoin" : {name: "Topcoin", ticker: "topcoin", networkVersion: 0x42, privateKeyPrefix:  0xc2},
    "transfercoin" : {name: "TransferCoin", ticker: "transfercoin", networkVersion: 0x42, privateKeyPrefix:  0x99},
    "treasurehuntcoin" : {name: "TreasureHuntCoin", ticker: "treasurehuntcoin", networkVersion: 0x32, privateKeyPrefix:  0xb2},
    "trezarcoin" : {name: "TrezarCoin", ticker: "trezarcoin", networkVersion: 0x42, privateKeyPrefix:  0xC2},
    "unobtanium" : {name: "Unobtanium", ticker: "unobtanium", networkVersion: 0x82, privateKeyPrefix:  0xe0},
    "usde" : {name: "USDe", ticker: "usde", networkVersion: 0x26, privateKeyPrefix:  0xa6},
    "vcash" : {name: "Vcash", ticker: "vcash", networkVersion: 0x47, privateKeyPrefix:  0xc7},
    "versioncoin" : {name: "Versioncoin", ticker: "versioncoin", networkVersion: 0x46, privateKeyPrefix:  0xc6},
    "vergecoin" : {name: "VergeCoin", ticker: "vergecoin", networkVersion: 0x1e, privateKeyPrefix:  0x9e},
//    "vertcoin" : {name: "Vertcoin", ticker: "vertcoin", networkVersion: 0x47, privateKeyPrefix:  0x80},
    "viacoin" : {name: "Viacoin", ticker: "viacoin", networkVersion: 0x47, privateKeyPrefix:  0xc7},
    "vikingcoin" : {name: "VikingCoin", ticker: "vikingcoin", networkVersion: 0x46, privateKeyPrefix:  0x56},
    "w2coin" : {name: "W2Coin", ticker: "w2coin", networkVersion: 0x49, privateKeyPrefix:  0xc9},
    "wacoins" : {name: "WACoins", ticker: "wacoins", networkVersion: 0x49, privateKeyPrefix:  0xc9},
    "wankcoin" : {name: "WankCoin", ticker: "wankcoin", networkVersion: 0x00, privateKeyPrefix:  0x80},
    "wearesatoshicoin" : {name: "WeAreSatoshiCoin", ticker: "wearesatoshicoin", networkVersion: 0x87, privateKeyPrefix:  0x97},
    "worldcoin" : {name: "WorldCoin", ticker: "worldcoin", networkVersion: 0x49, privateKeyPrefix:  0xc9},
    "xp" : {name: "XP", ticker: "xp", networkVersion: 0x4b, privateKeyPrefix:  0xcb},
    "zetacoin" : {name: "Zetacoin", ticker: "zetacoin", networkVersion: 0x50, privateKeyPrefix:  0xE0},

}
