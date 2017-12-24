package bip38

import (
	"bytes"
	"golang.org/x/crypto/scrypt"
	"crypto/aes"
	"crypto/sha256"
	"github.com/cculianu/gocoin/btc"
	"log"
	"math/big"
)


func sha256Twice(b []byte) []byte {
	h := sha256.New()
	h.Write(b)
	hashedOnce := h.Sum(nil)
	h.Reset()
	h.Write(hashedOnce)
	return h.Sum(nil)
}

func Pk2Wif(pk []byte, compressed bool) string {
	pk = append([]byte{0x80},pk...) // prepend 0x80 for mainnet
	if compressed {
		pk = append(pk,0x01)
	}
	sha2 := sha256Twice(pk)
	pkChk := append(pk, sha2[0:4]...)
	return btc.Encodeb58(pkChk)
}

func DecryptWithPassphraseNoEC(dec []byte, passphrase string) string {
	flagByte := dec[2]
	compressed := (flagByte&0x20) == 0x20
	if !compressed && flagByte != 0xc0 {
		log.Fatal("Invalid BIP38 compression flag")
	}
	salt := dec[3:7]
	scryptBuf, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 8, 64)
	derivedHalf1 := scryptBuf[0:32]
	derivedHalf2 := scryptBuf[32:64]
	encryptedHalf1 := dec[7:23]
	encryptedHalf2 := dec[23:39]
	h, err := aes.NewCipher(derivedHalf2)
	if h == nil {
		log.Fatal(err)
	}
	k1 := make([] byte, 16)
	k2 := make([] byte, 16)
	h.Decrypt(k1, encryptedHalf1)
	h, err = aes.NewCipher(derivedHalf2)
	if h == nil {
		log.Fatal(err)
	}
	h.Decrypt(k2, encryptedHalf2)
	keyBytes := make([] byte, 32)
	for i := 0; i < 16; i++ {
		keyBytes[i] = k1[i] ^ derivedHalf1[i];
		keyBytes[i+16] = k2[i] ^ derivedHalf1[i+16];
	}
	d := new (big.Int).SetBytes(keyBytes)
	pubKey, err := btc.PublicFromPrivate(d.Bytes(), compressed)
	if pubKey == nil {
		log.Fatal(err)
	}
	addr := btc.NewAddrFromPubkey(pubKey, 0).String()
	
	addrHashed := sha256Twice([]byte(addr))[0:4]

	if addrHashed[0] != salt[0] || addrHashed[1] != salt[1] || addrHashed[2] != salt[2] || addrHashed[3] != salt[3] {
		return ""
	}

	return Pk2Wif(d.Bytes(),compressed)
}

func DecryptWithPassphrase(encryptedKey string, passphrase string) string {
	dec := btc.Decodeb58(encryptedKey)[:39] // trim to length 39 (not sure why needed)
	if dec == nil {
		log.Fatal("Cannot decode base58 string " + encryptedKey)
	}

	if dec[0] == 0x01 && dec[1] == 0x42 {
		return DecryptWithPassphraseNoEC(dec, passphrase)
	} else if dec[0] == 0x01 && dec[1] == 0x43 {
		compress := dec[2]&0x20 == 0x20
		hasLotSequence := dec[2]&0x04 == 0x04

		var ownerSalt, ownerEntropy []byte
		if hasLotSequence {
			ownerSalt = dec[7:11]
			ownerEntropy = dec[7:15]
		} else {
			ownerSalt = dec[7:15]
			ownerEntropy = ownerSalt
		}

		prefactorA, err := scrypt.Key([]byte(passphrase), ownerSalt, 16384, 8, 8, 32)
		if prefactorA == nil {
			log.Fatal(err)
		}

		var passFactor []byte
		if hasLotSequence {
			prefactorB := bytes.Join([][]byte{prefactorA, ownerEntropy}, nil)
			passFactor = sha256Twice(prefactorB)
		} else {
			passFactor = prefactorA
		}

		passpoint, err := btc.PublicFromPrivate(passFactor, true)
		if passpoint == nil {
			log.Fatal(err)
		}

		encryptedpart1 := dec[15:23]
		encryptedpart2 := dec[23:39]

		derived, err := scrypt.Key(passpoint, bytes.Join([][]byte{dec[3:7], ownerEntropy}, nil), 1024, 1, 1, 64)
		if derived == nil {
			log.Fatal(err)
		}

		h, err := aes.NewCipher(derived[32:])
		if h == nil {
			log.Fatal(err)
		}

		unencryptedpart2 := make([]byte, 16)
		h.Decrypt(unencryptedpart2, encryptedpart2)
		for i := range unencryptedpart2 {
			unencryptedpart2[i] ^= derived[i+16]
		}

		encryptedpart1 = bytes.Join([][]byte{encryptedpart1, unencryptedpart2[:8]}, nil)

		unencryptedpart1 := make([]byte, 16)
		h.Decrypt(unencryptedpart1, encryptedpart1)
		for i := range unencryptedpart1 {
			unencryptedpart1[i] ^= derived[i]
		}

		seeddb := bytes.Join([][]byte{unencryptedpart1[:16], unencryptedpart2[8:]}, nil)
		factorb := sha256Twice(seeddb)

		bigN, success := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
		if !success {
			log.Fatal("Failed to create Int for N")
		}

		passFactorBig := new(big.Int).SetBytes(passFactor)
		factorbBig := new(big.Int).SetBytes(factorb)

		privKey := new(big.Int)
		privKey.Mul(passFactorBig, factorbBig)
		privKey.Mod(privKey, bigN)

		pubKey, err := btc.PublicFromPrivate(privKey.Bytes(), compress)
		if pubKey == nil {
			log.Fatal(err)
		}

		addr := btc.NewAddrFromPubkey(pubKey, 0).String()

		addrHashed := sha256Twice([]byte(addr))

		if addrHashed[0] != dec[3] || addrHashed[1] != dec[4] || addrHashed[2] != dec[5] || addrHashed[3] != dec[6] {
			return ""
		}

		return Pk2Wif(privKey.Bytes(),compress)
	}

	log.Fatal("Malformed byte slice")
	return ""
}
