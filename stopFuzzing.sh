#!/bin/bash
sudo pwd
ps -ef | grep 'startFuzzing' | grep -v grep | awk '{print $2}' | xargs -r kill -9
docker stop -f $(docker ps -a -q)
ps -ef | grep 'startFuzzing' | grep -v grep | awk '{print $2}' | xargs -r kill -9
docker rm -f $(docker ps -a -q)      
ps -ef | grep 'startFuzzing' | grep -v grep | awk '{print $2}' | xargs -r kill -9
docker rm -f $(docker ps -a -q)      