package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

var (
	// Program metadata set by the compiler
	Version = "undefined"   // Program's version
	BuildTime = "undefined" // Build time of the program
	GitHash = "undefined"   // Git commit hash of the source tree
)

// Entry point of the program
func main() {
	if err := run(); err != nil {  
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
		var usageErr usageError
		if errors.As(err, &usageErr) {
			flag.Usage()
		}
		os.Exit(1)
	}
}

// usageError type for incorrect usage of command line arguments
type usageError string

// Implementing Error method for usageError to satisfy the error interface
func (u usageError) Error() string {
	return string(u)
}

// The run function orchestrates the entire workflow of the program
func run() error {
	cfg, err := parseArgs()  
	if err != nil {
		return err
	}

	card, err := parseProxMark3JSONFile(cfg.InputJSONFile)  
	if err != nil {
		return err
	}

	return writeNFCFile(cfg.OutputNFCFile, card)  
}

// Struct that holds names of input and output files
type config struct {
	InputJSONFile string
	OutputNFCFile string
}

// Function to parse command line arguments and return a config struct
func parseArgs() (*config, error) {
	var cfg config
	flag.StringVar(&cfg.InputJSONFile, "i", "", "input Proxmark3 dump file in JSON format")
	flag.StringVar(&cfg.OutputNFCFile, "o", "", "output Flipper file in NFC format")

	defaultUsage := flag.Usage
	flag.Usage = func() {
		defaultUsage()
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "Version: %s\tBuildTime: %v\tGitHash: %s\n", Version, BuildTime, GitHash)
	}
	flag.Parse()  

	if cfg.InputJSONFile == "" {
		return nil, usageError("please provide input Proxmark3 dump file in JSON format")
	}

	if cfg.OutputNFCFile == "" {
		return nil, usageError("please provide output Flipper file in NFC format")
	}

	return &cfg, nil
}

// Type for a slice of bytes, which is used to represent hexadecimal data
type hexData []byte

// String method for hexData type to print hexadecimal data
func (h hexData) String() string {
	var sb strings.Builder

	n := len(h)
	for i := 0; i < n-1; i++ {
		sb.WriteString(fmt.Sprintf("%02X ", h[i]))
	}
	if n >= 1 {
		sb.WriteString(fmt.Sprintf("%02X", h[n-1]))
	}

	return sb.String()
}

// Struct representing the data structure of a Mifare card
type mifareCard struct {
	UID    hexData
	ATQA   hexData
	SAK    hexData
	Blocks []hexData
}

// Function that reads a Proxmark3 JSON dump file and returns a mifareCard struct
func parseProxMark3JSONFile(fileName string) (*mifareCard, error) {
	jsonFile, err := os.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Proxmark3 dump file '%s': %w", fileName, err)
	}
	defer jsonFile.Close()

	return parseProxMark3JSON(jsonFile)
}

// Function that parses the Proxmark3 JSON data and returns a mifareCard struct
func parseProxMark3JSON(r io.Reader) (*mifareCard, error) {
	var proxmark3JSON struct {
		Created  string `json:"Created"`
		FileType string `json:"FileType"`
		Card     struct {
			UID  string `json:"UID"`
			ATQA string `json:"ATQA"`
			SAK  string `json:"SAK"`
		} `json:"Card"`
		Blocks map[string]string `json:"blocks"`
	}

	if err := json.NewDecoder(r).Decode(&proxmark3JSON); err != nil {
		return nil, fmt.Errorf("failed to decode Proxmark3 JSON file: %w", err)
	}

	if proxmark3JSON.Created != "proxmark3" {
		return nil, errors.New("JSON file must be produced by Proxmark3")
	}

	if proxmark3JSON.FileType != "mfcard" {
		return nil, errors.New("expecting Mifare card dump")
	}

	card := &proxmark3JSON.Card
	uid, err := decodeHexData(card.UID)
	if err != nil {
		return nil, fmt.Errorf("cannot parse card UID: %w", err)
	}
	atqa, err := decodeHexData(card.ATQA)
	if err != nil {
		return nil, fmt.Errorf("cannot parse card ATQA: %w", err)
	}
	sak, err := decodeHexData(card.SAK)
	if err != nil {
		return nil, fmt.Errorf("cannot parse card SAK: %w", err)
	}

	blocksMap := proxmark3JSON.Blocks
	blocksNum := len(blocksMap)
	blocks := make([]hexData, blocksNum)
	for i := 0; i < blocksNum; i++ {
		blockNumStr := strconv.Itoa(i)
		blockData, ok := blocksMap[blockNumStr]
		if !ok {
			return nil, fmt.Errorf("cannot find Mifare card data for block %d", i)
		}
		bs, err := decodeHexData(blockData)
		if err != nil {
			return nil, fmt.Errorf("cannot parse block %d data: %w", i, err)
		}
		blocks[i] = bs
	}

	return &mifareCard{
		UID:    uid,
		ATQA:   atqa,
		SAK:    sak,
		Blocks: blocks,
	}, nil
}

// Function that decodes hexadecimal data from a string and returns it as a hexData type
func decodeHexData(hexStr string) (bs hexData, err error) {
	bs, err = hex.DecodeString(hexStr)
	if err != nil {
		err = fmt.Errorf("failed to parse hex data '%s': %w", hexStr, err)
	}
	return
}

// Function that creates an NFC file and writes Mifare card data to it
func writeNFCFile(fileName string, c *mifareCard) error {
	nfcFile, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("failed to create NFC file '%s': %w", fileName, err)
	}
	defer nfcFile.Close()

	return writeNFC(nfcFile, c)
}

// Function that writes Mifare card data to a writer in NFC format
func writeNFC(w io.Writer, c *mifareCard) error {
	_, err := fmt.Fprintln(w, `Filetype: Flipper NFC device
Version: 2
# Nfc device type can be UID, Mifare Ultralight, Mifare Classic, Bank card
Device type: Mifare Classic
# UID, ATQA and SAK are common for all formats`)
	_, err = fmt.Fprintf(w, "UID: %s\n", c.UID)
	_, err = fmt.Fprintf(w, "ATQA: %s\n", c.ATQA)
	_, err = fmt.Fprintf(w, "SAK: %s\n", c.SAK)
	_, err = fmt.Fprintln(w, "# Mifare Classic specific data")
	mfSize := 0
	switch len(c.Blocks) {
	case 64:
		mfSize = 1
	case 128:
		mfSize = 2
	case 256:
		mfSize = 4
	}
	_, err = fmt.Fprintf(w, "Mifare Classic type: %dK\n", mfSize)
	_, err = fmt.Fprintln(w, `Data format version: 2
# Mifare Classic blocks, '??' means unknown data`)
	for i, block := range c.Blocks {
		_, err = fmt.Fprintf(w, "Block %d: %s\n", i, block)
	}

	return err
}

