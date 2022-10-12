package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/database"

	_ "github.com/btcsuite/btcd/database/ffldb"
)

var separator = []byte{0xFA, 0xBF, 0xB5, 0xDA}

var utxoSetBucketName = []byte("utxosetv2")

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {

	// Database filepath
	dbPath := filepath.Join(os.TempDir(), "btcd")

	// Create a database
	os.RemoveAll(dbPath)
	db, err := database.Create("ffldb", dbPath, chaincfg.RegressionNetParams.Net)
	check(err)

	// Create a blockchain
	chain, err := blockchain.New(&blockchain.Config{
		DB:          db,
		ChainParams: &chaincfg.RegressionNetParams,
		TimeSource:  blockchain.NewMedianTime(),
	})
	check(err)

	//blockchain.KeyToHash = map[string]string{}

	// Import blocks
	dat, err := os.ReadFile("./import/import.dat")
	check(err)
	var imported_blocks_raw = bytes.Split(dat, separator)

	// Remove first block if empty
	if len(imported_blocks_raw[0]) == 0 {
		imported_blocks_raw = imported_blocks_raw[1:]
	}

	// Parse all improted blocks
	var imported_txos []*chainhash.Hash
	for _, block_raw := range imported_blocks_raw[1:] {
		block, err := btcutil.NewBlockFromBytes(block_raw[4:])
		check(err)
		chain.ProcessBlock(block, blockchain.BFNone)
		for _, txo := range block.Transactions() {
			imported_txos = append(imported_txos, txo.Hash())
		}
	}

	// Read all test cases
	test_cases, err := os.ReadDir("./test_cases")
	check(err)

	//Process all test cases
	for _, test_case := range test_cases {
		// Print test case name
		fmt.Println(test_case.Name())

		// Import all test blocks
		dat, err := os.ReadFile(filepath.Join("./test_cases", test_case.Name()))
		check(err)
		test_blocks := bytes.Split(dat, separator)

		// Remove first block if empty
		if len(test_blocks[0]) == 0 {
			test_blocks = test_blocks[1:]
		}

		// Try adding each block to the chain
		result := map[string]interface{}{}
		var txos []*chainhash.Hash

		var blocks []*btcutil.Block

		for i, block_raw := range test_blocks {

			block, err := btcutil.NewBlockFromBytes(block_raw[9:])

			if err != nil {
				result["Block "+strconv.Itoa(i)] = map[string]interface{}{"accept": false, "reason": err.Error()}
				continue
			}

			accepted, _, err := chain.ProcessBlock(block, blockchain.BFNone)

			var reason string = "Valid"

			if err != nil {
				reason = err.Error()
			} else {
				for _, txo := range block.Transactions() {
					txos = append(txos, txo.Hash())
				}
				blocks = append(blocks, block)
			}

			result["Block "+strconv.Itoa(i)] = map[string]interface{}{"accept": accepted, "reason": reason}
		}

		result["HashTip"] = chain.BestSnapshot().Hash.String()

		var utxos []string
		var utxos_set = make(map[string]bool)

		// Check whether txos are utxos
		for _, txo := range imported_txos {
			db.View(func(tx database.Tx) error {
				_, err := blockchain.DBFetchUtxoEntryByHash(tx, txo)
				if err == nil && utxos_set[txo.String()] == false {
					utxos = append(utxos, txo.String())
					utxos_set[txo.String()] = true
				}
				return nil
			})
		}

		for _, txo := range txos {
			db.View(func(tx database.Tx) error {
				entry, err := blockchain.DBFetchUtxoEntryByHash(tx, txo)
				if err == nil && entry != nil && utxos_set[txo.String()] == false {
					utxos = append(utxos, txo.String())
					utxos_set[txo.String()] = true
				}
				return nil
			})
		}

		sort.Strings(utxos)

		result["UTXO"] = utxos

		// Parse to JSON and save
		jsonData, err := json.MarshalIndent(result, "", "    ")
		check(err)
		err = os.WriteFile(filepath.Join("./output/", test_case.Name()), jsonData, 0644)
		check(err)

		// Reset chain
		chain.PurgeOrphans()
		for chain.BestSnapshot().Height >= int32(len(imported_blocks_raw)) {
			chain.RemoveLastMainBlock()
		}
		chain.RemoveLostBlocks(blocks)
	}

	os.RemoveAll(dbPath)
}
