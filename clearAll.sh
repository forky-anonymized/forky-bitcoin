#!/bin/bash
docker-compose down 
sudo rm -rf ./fuzzing_corpus
sudo rm -rf ./test_cases
sudo rm -rf ./output
mkdir fuzzing_corpus
mkdir test_cases
sudo rm -rf ./result/*
sudo rm -rf ./*.time
sudo rm -rf ./*.out