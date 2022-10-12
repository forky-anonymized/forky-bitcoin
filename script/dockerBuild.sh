#!/bin/bash
echo "############################" 
echo 'Build Docker base image...'
echo "############################" 
echo
cd ./version/base
docker build -t ubuntu-bitcoin:base .

cd ../v22.0
echo
echo "############################" 
echo 'Build bitcoin v22.0 image'
echo "############################" 
echo
docker build -t ubuntu-bitcoin:v22.0 .

cd ../v0.21.0
echo
echo "############################" 
echo 'Build bitcoin v0.21.0 image'
echo "############################" 
echo
docker build -t ubuntu-bitcoin:v0.21.0 .

# cd ../v0.20.0
# echo
# echo "############################" 
# echo 'Build bitcoin v0.20.0 image'
# echo "############################" 
# echo
# docker build -t ubuntu-bitcoin:v0.20.0 .

# cd ../v0.19.0
# echo
# echo "############################" 
# echo 'Build bitcoin v0.19.0 image'
# echo "############################" 
# echo
# docker build -t ubuntu-bitcoin:v0.19.0 .

# cd ../v0.18.0
# echo
# echo "############################" 
# echo 'Build bitcoin v0.18.0 image'
# echo "############################" 
# echo
# docker build -t ubuntu-bitcoin:v0.18.0 .

# cd ../v0.17.0
# echo
# echo "############################" 
# echo 'Build bitcoin v0.17.0 image'
# echo "############################" 
# echo
# docker build -t ubuntu-bitcoin:v0.17.0 .

# cd ../v0.16.0
# echo
# echo "############################" 
# echo 'Build bitcoin v0.16.0 image'
# echo "############################" 
# echo
# docker build -t ubuntu-bitcoin:v0.16.0 .

echo
echo "############################" 
echo 'Try remove <none> images...'
echo "############################" 
echo
docker rmi $(docker images -f "dangling=true" -q)

echo
echo "############################" 
echo 'Build finished'
echo "############################" 