package bip38

import (
    "fmt"
    "log"
    "math"
    "os"
    "os/signal"
    "strconv"
    "sync/atomic"
)

var totalTried uint64 = 0
var stopSearch int32 = 0

func tryPasswords(start, finish uint64, key *Key, passwords []string, c chan string) {
    var i uint64
    if finish > uint64(len(passwords)) {
        log.Fatal("INTERNAL ERROR: tryPasswords -- finish > len(passwords)!")
    }
    for i = start; atomic.LoadInt32(&stopSearch) == 0 && i < finish; i++ {
        privKey, addr := DecryptWithPassphrase(key, passwords[i])
        if privKey != "" {
            c <- privKey + "    pass = '" + passwords[i] + "'   ( Address: " + addr + " )"
            return
        }

        atomic.AddUint64(&totalTried, 1)

        fmt.Printf("%6d passphrases tried (latest guess: %s )                       \r", atomic.LoadUint64(&totalTried), passwords[i])
    }
    if atomic.LoadInt32(&stopSearch) != 0 {
        c <- fmt.Sprintf("%d", i-start) // interrupt signal received, announce our position for the resume code
        return
    }
    c <- ""    
}

func searchRange(start, finish uint64, key *Key, charset string, pwlen int, pat []rune, c chan string) {
    cset := []rune(charset)
    var i uint64

    var guess []rune = make([]rune, len(pat))
    
    for i = start; atomic.LoadInt32(&stopSearch) == 0 && i < finish; i++ {
        acum := i
        for j := 0; j < len(pat); j++ {
            if pat[j] == '?' {
                guess[j] = cset[acum%uint64(len(cset))]
                acum /= uint64(len(cset))
            } else {
                guess[j] = pat[j]   
            }
        }
        guessString := string(guess)
        privKey, addr := DecryptWithPassphrase(key, guessString)
        if privKey != "" {
            c <- privKey + "    pass = '" + guessString + "'   ( Address: " + addr + " )"
            return
        }

        atomic.AddUint64(&totalTried, 1)

        fmt.Printf("%6d passphrases tried (latest guess: %s )                      \r", atomic.LoadUint64(&totalTried), guessString)
    }
    if atomic.LoadInt32(&stopSearch) != 0 {
        c <- fmt.Sprintf("%d", i-start) // interrupt signal received, announce our position for the resume code
        return
    }
    c <- ""
}

func BruteChunk(routines int, encryptedKey, charset string, pwlen int, pat string, passwords []string, chunk, chunks int, resume uint64, coinInfo [2]byte, coinName string) string {
    if chunk < 0 || chunks <= 0 || chunk >= chunks {
        log.Fatal("chunk/chunks specification invalid")
    }
    if encryptedKey == "" {
        log.Fatal("encryptedKey required")
    }
    
    key := NewKey(encryptedKey)

    key.networkVersion = coinInfo[0]
    key.privateKeyPrefix = coinInfo[1]
    
    if routines < 1 {
        log.Fatal("routines must be >= 1")
    }

    if pwlen < 1 && passwords == nil {
        log.Fatal("pw length must be >= 1")
    }

    // Extended ASCII
    //charset := " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~.€.‚ƒ„…†‡ˆ‰Š‹Œ.Ž..‘’“”•–—˜™š›œ.žŸ ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ"

    // Printable ASCII
    if charset == "" && passwords == nil {
        charset = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~."
    }
    
    if charset != "" {
        fmt.Printf("Using character set: %s\n",charset)
    }
    fmt.Printf("Encrypted key: %s\nKeyType: %s\nNetwork: %s\n", encryptedKey, key.TypeString(), coinName)
    
    spaceSize := uint64(math.Pow(float64(len(charset)), float64(pwlen)))
    
    if passwords == nil {
        if len([]rune(pat)) != 0 {
            fmt.Printf("Pattern: %s\n", pat)
            fmt.Printf("Unknown chars: %d\n", pwlen)        
            fmt.Printf("Password length: %d\n", len([]rune(pat)))
        } else {
            pat = ""
            for i := 0; i < pwlen; i++ {
                pat = pat + "?"
            }
            fmt.Printf("Password length: %d\n", pwlen)
        }
        fmt.Printf("Total passphrase space size: %d\n", spaceSize)
    } else {
        spaceSize = uint64(len(passwords))
        fmt.Printf("Number of passphrases to try: %d\n", len(passwords))
    }
    
    patAsRunes := []rune(pat)
    startFrom := uint64(0)
    chunkSize := spaceSize / uint64(chunks)
    blockSize := uint64(chunkSize / uint64(routines))
    if chunks > 1 {
        startFrom = chunkSize * uint64(chunk)
        csz := chunkSize
        if chunk == chunks-1 {
            csz = spaceSize - startFrom
        }
        fmt.Printf("Chunk passphrase space size: %d  Starting from point: %d\n", csz, startFrom)
    }

    totalTried = resume * uint64(routines)
    c := make(chan string)

    sigc := make(chan os.Signal, 1)
    signal.Notify(sigc, os.Interrupt)
    defer signal.Stop(sigc)

    for i := 0; i < routines; i++ {
        var finish uint64
        if i == routines-1 {
            // Last block needs to go right to the end of the search space
            finish = chunkSize + startFrom
            if chunk == chunks-1 {
                finish = spaceSize
            }
        } else {
            finish = uint64(i)*blockSize + blockSize + startFrom
        }
        start := uint64(i)*blockSize + startFrom + resume
        
        if passwords == nil {
            go searchRange(start, finish, key, charset, pwlen, patAsRunes, c)
        } else {
            go tryPasswords(start, finish, key, passwords, c)
        }
    }
    var minResumeKey uint64 = 0
    i := routines
    for {
        select {
        case s := <-c:
            if s == "" {
                // a search thread has ended!
                i--
                if i <= 0 {
                    return "" // last search thread ended!
                }
            } else if atomic.LoadInt32(&stopSearch) != 0 {
                u, err := strconv.ParseUint(s, 10, 64)
                if err == nil && (u+resume < minResumeKey || minResumeKey == 0) {
                    minResumeKey = u + resume
                } else if err != nil {
                    // happened to crack key on interrupt! return cracked key
                    return s
                }
                i--
                if i <= 0 {
                    return fmt.Sprintf("to resume, use offset %d", minResumeKey)
                }
            } else { // found/cracked key! return answer!
                return s
            }
        case sig := <-sigc:
            atomic.StoreInt32(&stopSearch, 1) // tell search functions they need to stop
            fmt.Printf("\n(%s)\n", sig.String())
        }
    }
    return "" // not reached
}
