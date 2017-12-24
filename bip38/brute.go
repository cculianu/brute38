package bip38

import (
	"fmt"
	"log"
	"math"
	"os"
	"os/signal"
	"strconv"
	"sync/atomic"
	"github.com/cculianu/gocoin/btc"
)

var totalTried uint64 = 0
var stopSearch int32 = 0

func searchRange(start uint64, finish uint64, encryptedKey string, charset string, pwlen int, c chan string) {
	cset := []rune(charset)
	var i uint64
	decKey := btc.Decodeb58(encryptedKey)[:39] // trim to length 39 (not sure why needed)
	if decKey == nil {
		log.Fatal("Cannot decode base58 string " + encryptedKey)
	}

	for i = start; atomic.LoadInt32(&stopSearch) == 0 && i < finish; i++ {
		acum := i
		var guess string = ""
		for j := 0; j < pwlen; j++ {
			guess = guess + string(cset[acum%uint64(len(cset))])
			acum /= uint64(len(cset))
		}
		privKey := DecryptWithPassphrase(decKey, guess)
		if privKey != "" {
			c <- privKey + "    pass = '" + guess + "'"
			return
		}

		atomic.AddUint64(&totalTried, 1)

		fmt.Printf("%6d passphrases tried (latest guess: %s )     \r", atomic.LoadUint64(&totalTried), guess)
	}
	if atomic.LoadInt32(&stopSearch) != 0 {
		c <- fmt.Sprintf("%d", i-start) // interrupt signal received, announce our position for the resume code
		return
	}
	c <- ""
}

func Brute(routines int, encryptedKey string, charset string, pwlen int, resume uint64) string {
	return BruteChunk(routines, encryptedKey, charset, pwlen, 0, 1, resume)
}

func BruteChunk(routines int, encryptedKey string, charset string, pwlen int, chunk int, chunks int, resume uint64) string {
	if chunk < 0 || chunks <= 0 || chunk >= chunks {
		log.Fatal("chunk/chunks specification invalid")
	}
	if encryptedKey == "" {
		log.Fatal("encryptedKey required")
	}

	if routines < 1 {
		log.Fatal("routines must be >= 1")
	}

	if pwlen < 1 {
		log.Fatal("pw length must be >= 1")
	}

	// Extended ASCII
	//charset := " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~.€.‚ƒ„…†‡ˆ‰Š‹Œ.Ž..‘’“”•–—˜™š›œ.žŸ ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ"

	// Printable ASCII
	if charset == "" {
		charset = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~."
	}
	fmt.Printf("Using character set: %s\nEncrypted key: %s\nPassword length: %d\n", charset, encryptedKey, pwlen)

	spaceSize := uint64(math.Pow(float64(len(charset)), float64(pwlen)))
	fmt.Printf("Total keyspace size: %d\n", spaceSize)
	startFrom := uint64(0)
	chunkSize := spaceSize / uint64(chunks)
	blockSize := uint64(chunkSize / uint64(routines))
	if chunks > 1 {
		startFrom = chunkSize * uint64(chunk)
		csz := chunkSize
		if chunk == chunks-1 {
			csz = spaceSize - startFrom
		}
		fmt.Printf("Chunk keyspace size: %d  Starting from point: %d\n", csz, startFrom)
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
		go searchRange(start, finish, encryptedKey, charset, pwlen, c)
	}
	var minResumeKey uint64 = 0
	i := routines - 1
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
