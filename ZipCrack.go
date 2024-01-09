package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/mem"
	"github.com/yeka/zip"
)

var startTime = time.Now()
var numGoroutines = runtime.NumCPU()

func getBuffer() int64 {
	totalMemory, err := mem.VirtualMemory()
	if err != nil {
		log.Printf("Warning: Failed to get memory information. Using default buffer size.")
		totalMemory.Available = 4 << 30
	}
	return int64(totalMemory.Available) / 12 / 4
}

func GenerateCombinationsString(data []string, length int) <-chan []string {
	c := make(chan []string)
	go func(c chan []string) {
		defer close(c)
		combosString(c, []string{}, data, length)
	}(c)
	return c
}

func combosString(c chan []string, combo []string, data []string, length int) {
	if length <= 0 {
		return
	}
	var newCombo []string
	for _, ch := range data {
		newCombo = append(combo, ch)
		if length == 1 {
			output := make([]string, len(newCombo))
			copy(output, newCombo)
			c <- output
		}
		combosString(c, newCombo, data, length-1)
	}
}

func unzip(filename string, password string) bool {
	r, err := zip.OpenReader(filename)
	if err != nil {
		return false
	}
	defer r.Close()

	buffer := new(bytes.Buffer)

	for _, f := range r.File {
		f.SetPassword(password)
		r, err := f.Open()
		if err != nil {
			return false
		}
		defer r.Close()
		n, err := io.Copy(buffer, r)
		if n == 0 || err != nil {
			return false
		}
		break
	}
	return true
}

func bruteforce(zipFile string, alphabet []string) {
	resultChannel := make(chan bool)
	quitChannel := make(chan bool)

	chunkSize := len(alphabet) / numGoroutines
	for i := 0; i < numGoroutines; i++ {
		startIdx := i * chunkSize
		endIdx := (i + 1) * chunkSize
		if i == numGoroutines-1 {
			endIdx = len(alphabet)
		}
		go bruteForceWorker(zipFile, alphabet[startIdx:endIdx], resultChannel, quitChannel)
	}

	select {
	case <-resultChannel:
		close(quitChannel)
	}
}

func bruteForceWorker(zipFile string, alphabet []string, resultChannel, quitChannel chan bool) {
	for i := 1; ; i++ {
		select {
		case <-quitChannel:
			return
		default:
			for combo := range GenerateCombinationsString(alphabet, i) {
				res := unzip(zipFile, strings.Join(combo, ""))
				if res == true {
					fmt.Printf("Password matched: %s\nCombinations tried: %d\n", strings.Join(combo, ""), i)
					fmt.Printf("Time taken: %f seconds\n", time.Since(startTime).Seconds())
					resultChannel <- true
					return
				}
			}
		}
	}
}

func dictionaryAttackWorker(zipFile string, dictionary []string, resultChannel, quitChannel chan bool, wg *sync.WaitGroup) {
	defer wg.Done()
	for _, password := range dictionary {
		select {
		case <-quitChannel:
			return
		default:
			res := unzip(zipFile, password)
			if res == true {
				fmt.Printf("Password matched: %s\n", password)
				resultChannel <- true
				return
			}
		}
	}
}

func processData(data []byte, zipFile string) bool {
	resultChannel := make(chan bool)
	quitChannel := make(chan bool)
	dictionaries := make([][]string, numGoroutines)
	blockScanner := bufio.NewScanner(bytes.NewReader(data))

	for i := 0; i < numGoroutines; i++ {
		dictionaries[i] = make([]string, 0)
	}

	i := 0
	for blockScanner.Scan() {
		password := blockScanner.Text()
		dictionaries[i%numGoroutines] = append(dictionaries[i%numGoroutines], password)
		i++
	}

	var wg sync.WaitGroup
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go dictionaryAttackWorker(zipFile, dictionaries[i], resultChannel, quitChannel, &wg)
	}

	go func() {
		wg.Wait()
		close(resultChannel)
		close(quitChannel)
	}()

	for foundPassword := range resultChannel {
		if foundPassword {
			return true
		}
	}
	return false
}

func crack(zipFile string, dictFile string) {
	file, err := os.Open(dictFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	buffer := make([]byte, getBuffer())
	for {
		bytesRead, err := file.Read(buffer)
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatal(err)
		}
		if processData(buffer[:bytesRead], zipFile) {
			fmt.Printf("Time taken: %f seconds\n", time.Since(startTime).Seconds())
			return
		}
	}
}

func main() {
	if len(os.Args) < 4 {
		fmt.Printf("\nUsage: %s [zip file] [dictionary file/letters] [type of attack]\n"+
			"\nExample:\n"+
			"\t- Dictionary: %s ExampleFile.zip passwords.txt dictionary\n"+
			"\t- Brute force: %s ExampleFile.zip abcdefghijklmnopqrstuvwxyz bruteforce\n\n",
			os.Args[0], os.Args[0], os.Args[0])
		os.Exit(1)
	}

	zipFile := os.Args[1]
	dictFile := os.Args[2]
	attack := os.Args[3]

	if attack == "bruteforce" {
		fmt.Println("Starting brute force attack..")
		alphabet := strings.Split(dictFile, "")
		bruteforce(zipFile, alphabet)
	} else if attack == "dictionary" {
		fmt.Println("Starting dictionary attack..")
		crack(zipFile, dictFile)
	} else {
		os.Exit(1)
	}

	os.Exit(0)
}
