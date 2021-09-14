package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/bits"
	"os"
	"strings"
	"unicode"
)

func chal1() {
	str := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	decoded, err := hex.DecodeString(str)
	if err != nil {
		fmt.Printf("Challenge 1 - Failed. Error decoding hex string: %v\n", err)
	}
	result := base64.StdEncoding.EncodeToString(decoded)
	if expected != result {
		fmt.Printf("Challenge 1 - Failed. Got: %v, Want:%v\n", result, expected)
	}
	fmt.Println("Challenge 1 - Passed")
}

func chal2() {
	const (
		str      = "1c0111001f010100061a024b53535009181c"
		xorStr   = "686974207468652062756c6c277320657965"
		expected = "746865206b696420646f6e277420706c6179"
	)

	decodedStr, err := hex.DecodeString(str)
	if err != nil {
		fmt.Printf("Challenge 2 - Failed. Error decoding hex string: %v\n", err)
	}

	decodedXorStr, err := hex.DecodeString(xorStr)
	if err != nil {
		fmt.Printf("Challenge 2 - Failed. Error decoding xor string: %v\n", err)
	}

	buf := make([]byte, len(decodedStr))

	for i, _ := range decodedStr {
		buf[i] = decodedStr[i] ^ decodedXorStr[i]
	}

	result := hex.EncodeToString(buf)
	if result != expected {
		fmt.Printf("Challenge 2 - Failed. Got: %v, Want: %v\n", result, expected)
	}

	fmt.Printf("Challenge 2 - Passed\n")

}

func chal3() {
	const (
		str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
		//str = "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f"
	)

	decodedStr, err := hex.DecodeString(str)
	if err != nil {
		fmt.Printf("Challenge 3 - Failed. Error decoding hex string: %v\n", err)
	}

	analyzeSingleXor(decodedStr)

}

func analyzeSingleXor(seq []byte) byte {
	var (
		highestFreq     float32
		highestFreqChar int
	)
	for x := 1; x <= 255; x++ {
		freq := checkAsciiFrequency(xorByteSequenceWithSingleVal(seq, x))
		if freq > highestFreq {
			highestFreqChar = x
			highestFreq = freq
		}
	}
	fmt.Printf("highest frequency (%f) when xor'd with %v\n", highestFreq, highestFreqChar)
	return byte(highestFreqChar)
}

func checkAsciiFrequency(seq []byte) float32 {
	var asciiCount int
	for _, block := range seq {
		if unicode.IsLetter(rune(block)) && block <= unicode.MaxASCII {
			asciiCount++
		}
	}
	return float32(asciiCount) / float32(len(seq))
}

func xorByteSequenceWithSingleVal(seq []byte, val int) []byte {
	var encodedBytes []byte
	for _, b := range seq {
		xordByte := byte(b ^ byte(val))
		encodedBytes = append(encodedBytes, xordByte)
	}
	return encodedBytes
}

func analyzeSingleXorSkew(seq []byte) {
	var skews []int
	for x := 1; x <= 255; x++ {
		skew := 1
		byteCount := make(map[byte]int)
		for _, b := range seq {
			xordByte := byte(b ^ byte(x))
			if xordByte <= unicode.MaxASCII {
				byteCount[xordByte]++
			}
		}
		for _, count := range byteCount {
			skew = skew * count
		}
		skews = append(skews, skew)
	}

	var skewSum int
	for _, indSkew := range skews {
		skewSum = skewSum + indSkew
	}
	fmt.Println(skewSum)
}

func chal4() {
	f, err := os.Open("4.txt")
	if err != nil {
		fmt.Printf("Challenge 4 - Failed. Error reading file: %v\n")
	}
	defer f.Close()

	var skews []int
	var unknownStrs []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		unknownStr := scanner.Text()
		skew, err := getAsciiSkew(scanner.Text()) // Println will add back the final '\n'
		if err != nil {
			fmt.Printf("Challenge 4 - Failed. Error getting char skew: %v\n")
			return
		}
		skews = append(skews, skew)
		unknownStrs = append(unknownStrs, unknownStr)
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading standard input:", err)
	}

	for idx, sk := range skews {
		fmt.Printf("%v - %v\n", sk, unknownStrs[idx])
	}

}

func getAsciiSkew(str string) (int, error) {
	var skews []int
	decodedStr, err := hex.DecodeString(str)
	if err != nil {
		return 0, err
	}

	for x := 1; x <= 255; x++ {
		skew := 1
		byteCount := make(map[byte]int)
		for _, b := range decodedStr {
			xordByte := byte(b ^ byte(x))
			if xordByte <= unicode.MaxASCII {
				byteCount[xordByte]++
			}
		}
		for _, count := range byteCount {
			skew = skew * count
		}
		skews = append(skews, skew)
	}

	var skewSum int
	for _, indSkew := range skews {
		skewSum = skewSum + indSkew
	}

	return skewSum, nil
}

// repeated key xors
func chal5() {

	const (
		key string = "ICE"
		msg string = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	)

	var encryptedBytes []byte
	reader := strings.NewReader(msg)
	keyIdx := 0
	for x := 0; x < len([]byte(msg)); x++ {
		nextByte, err := reader.ReadByte()
		if err != nil {
			panic(err)
		}
		encryptedBytes = append(encryptedBytes, nextByte^key[keyIdx])
		if keyIdx == 2 {
			keyIdx = 0
		} else {
			keyIdx++
		}
	}
	fmt.Println(hex.EncodeToString(encryptedBytes))

}

// break repeating key xor
func chal6() {

	dat, err := ioutil.ReadFile("6.txt")
	if err != nil {
		panic(err)
	}
	decodedMsg, err := base64.StdEncoding.DecodeString(string(dat))
	if err != nil {
		panic(err)
	}

	// iterate possible key sizes
	var (
		minMeanHammingDistance    float32
		minMeanHammingDistanceVal int
	)
	for x := 2; x <= 40; x++ {
		var byteSeq [][]byte
		buffer := bytes.NewBuffer(decodedMsg)
		for buffer.Len() >= x {
			byteSeq = append(byteSeq, buffer.Next(x))
		}
		meanHammingDistance := meanHammingDistanceSequence(byteSeq)
		if meanHammingDistance < minMeanHammingDistance || minMeanHammingDistance == float32(0) {
			minMeanHammingDistance = meanHammingDistance
			minMeanHammingDistanceVal = x
		}
	}

	buffer := bytes.NewBuffer(decodedMsg)
	var blocks, transposedBlocks [][]byte
	chosenKeySize := minMeanHammingDistanceVal
	readBytes := chosenKeySize
	for readBytes == chosenKeySize {
		dat := buffer.Next(chosenKeySize)
		readBytes = len(dat)
		if readBytes == chosenKeySize {
			blocks = append(blocks, dat)
		}
	}
	var allegedKey []byte
	for x := 0; x < chosenKeySize; x++ {
		var transposedBlock []byte
		for _, block := range blocks {
			transposedBlock = append(transposedBlock, block[x])
		}
		transposedBlocks = append(transposedBlocks, transposedBlock)
		allegedKey = append(allegedKey, analyzeSingleXor(transposedBlocks[x]))
	}
	decodeVignere(decodedMsg, allegedKey)
}

func hammingDistance(a, b []byte) float32 {
	var dist int
	for idx, achar := range a {
		xordByte := achar ^ b[idx]
		dist += bits.OnesCount(uint(xordByte))
	}
	return float32(dist) / float32(len(a))
}

func meanHammingDistanceSequence(seq [][]byte) float32 {
	var cumulativeHammingDistance float32
	for x := 0; x < len(seq)-1; x++ {
		cumulativeHammingDistance += hammingDistance(seq[x], seq[x+1])
	}
	return cumulativeHammingDistance / float32(len(seq))
}

func decodeVignere(seq, key []byte) {
	decodedSeq := make([]byte, len(seq))
	for idx, block := range seq {
		decodedBlock := block ^ key[idx%len(key)]
		decodedSeq[idx] = decodedBlock
	}
	fmt.Println(string(decodedSeq))
}

func chal7() {
	const keyStr = "YELLOW SUBMARINE"

	dat, err := ioutil.ReadFile("7.txt")
	if err != nil {
		panic(err)
	}
	decodedMsg, err := base64.StdEncoding.DecodeString(string(dat))
	if err != nil {
		panic(err)
	}

	decryptedBytes := make([]byte, len(decodedMsg))
	aesCipher, err := aes.NewCipher([]byte(keyStr))
	if err != nil {
		panic(err)
	}

	aesCipher.Decrypt(decryptedBytes, decodedMsg)
	fmt.Println(string(decryptedBytes))
}

func chal8() {
	f, err := os.Open("8.txt")
	if err != nil {
		fmt.Printf("Challenge 4 - Failed. Error reading file: %v\n")
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		token := scanner.Text()
		decodedStr, err := hex.DecodeString(token)
		if err != nil {
			panic(err)
		}
		fmt.Println(getBlockMapLen(decodedStr))
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading standard input:", err)
	}
}

func getBlockMapLen(seq []byte) int {
	blockMap := make(map[string]int)
	buffer := bytes.NewBuffer(seq)
	for buffer.Len() >= 16 {
		byteBlock := buffer.Next(16)
		num := blockMap[string(byteBlock)]
		if num == 0 {
			blockMap[string(byteBlock)] = 1
		} else {
			blockMap[string(byteBlock)] += num
		}
	}
	return len(blockMap)
}
