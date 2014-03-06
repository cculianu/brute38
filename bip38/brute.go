package bip38

import (
	"fmt"
	"log"
	"math"
	"sync/atomic"
)

var totalTried uint64 = 0

func searchRange(start uint64, finish uint64, encryptedKey string, charset string, pwlen int, c chan string) {
	cset := []rune(charset)
	for i := start; i < finish; i++ {
		acum := i
		var guess string = ""
		for j := 0; j < pwlen; j++ {
			guess = guess + string(cset[acum%uint64(len(cset))])
			acum /= uint64(len(cset))
		}
		privKey := DecryptWithPassphrase(encryptedKey, guess)
		if privKey != "" {
			c <- privKey + " (" + guess + ")"
			return
		}
		atomic.AddUint64(&totalTried, 1)

		//if totalTried == 1 || totalTried%uint64(10) == 0 {
		fmt.Printf("%6d passphrases tried (latest guess: %s )     \r", totalTried, guess)
		//}

	}

	c <- ""
}

func Brute(routines int, encryptedKey string, charset string, pwlen int) string {
	return BruteChunk(routines, encryptedKey, charset, pwlen, 0, 1)
}

func BruteChunk(routines int, encryptedKey string, charset string, pwlen int, chunk int, chunks int) string {
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

	c := make(chan string)

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
		start := uint64(i)*blockSize + startFrom
		go searchRange(start, finish, encryptedKey, charset, pwlen, c)
	}
	var s string
	i := routines - 1
	for s = <-c; s == "" && i > 0; s = <-c {
		i--
	}
	return s
}
