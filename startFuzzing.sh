#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "$# is Illegal number of parameters."
    echo "Usage: ./startFuzzing.sh [start round] [max round]"
	exit 1
fi

# PACKAGE_VERSION=("23.0.0" "22.0.0" "0.21.0" "0.20.0" "0.19.0" "0.18.0" "0.17.0" "0.16.0" "0.15.0") 
PACKAGE_VERSION=("bitcoin/23.0.0" "bitcoin/22.0.0" "bitcoin/0.21.2" "bitcoin/0.21.1" "bitcoin/0.21.0" 
"bitcoin/0.20.1" "bitcoin/0.20.0" "bitcoin/0.19.1" "bitcoin/0.19.0.1" "bitcoin/0.19.0" "bitcoin/0.18.1" 
"bitcoin/0.18.0" "bitcoin/0.17.1" "bitcoin/0.17.0.1" "bitcoin/0.17.0" "bitcoin/0.16.3" "bitcoin/0.16.2" 
"bitcoin/0.16.1" "bitcoin/0.16.2" "bitcoin/0.15.2" "bitcoin/0.15.1" "bitcoin/0.15.0" 
"knots/23.0.0" "knots/22.0.0" 
"bcoin/2.2.0" "bcoin/2.1.0" "bcoin/2.0.0" 
"btcd/0.23.1" "btcd/0.23.0" "btcd/0.22.1")
WORKDIR=$PWD
echo "$WORKDIR"
ROUND=$1
END=$2
PARALLEL=4
pids=""

if [ $((ROUND)) -eq $((END)) ] ; then
    exit 1
fi
if [ $((ROUND)) -eq 0 ] ; then
    echo "############################" 
    echo "       TRY FIRST ROUND"
    echo "############################" 
    sleep 1
fi

if [ ! -d $WORKDIR/output ] ; then
    mkdir -p $WORKDIR/output
fi

if [ ! -d $WORKDIR/log ] ; then
    mkdir -p $WORKDIR/log
fi


# for ((i=0;i<1;i++)); do
sudo mkdir -p  $WORKDIR/output/r$ROUND
sudo mkdir -p $WORKDIR/output/r$ROUND/test_cases

for VERSION in ${PACKAGE_VERSION[@]}; do
    if [ ! -d $WORKDIR/output/r$ROUND/results/${VERSION} ] ; then
        sudo mkdir -p $WORKDIR/output/r$ROUND/results/${VERSION}
    fi
done

echo "Start Fuzzing..."
cp ./docker-compose/docker-compose.fuzz.yaml $WORKDIR/output/r$ROUND
find $WORKDIR/output/r$ROUND/docker-compose.fuzz.yaml -exec sed -i "s/\-fuzz/\-fuzz.r${ROUND}/g" {} +
time (docker-compose -f $WORKDIR/output/r$ROUND/docker-compose.fuzz.yaml up) 2>> fuzz-up.time
time (docker-compose -f $WORKDIR/output/r$ROUND/docker-compose.fuzz.yaml down) 2>> fuzz-down.time
sudo rm $WORKDIR/output/r$ROUND/docker-compose.fuzz.yaml

echo "docker down"
#echo "move test_cases to $WORKDIR/all_test_cases/r0/all_test_cases" 
#find $WORKDIR/test_cases -name "*" -exec sudo mv  {} $WORKDIR/all_test_cases/r0/ \;

# Not PARALLEL * n th round 
# spawn when fuzzing phase end...
# wait for background child end
if [ `expr $((ROUND)) % $PARALLEL` -ne 0 ]
then
    NEXT_ROUND=$((ROUND+1))
    echo "Go next round: $NEXT_ROUND"
    echo "$WORKDIR"
    $WORKDIR/startFuzzing.sh $NEXT_ROUND $END &
    pids="$!"
fi

echo "TESTING"
# copy docker-compose file and change container name in docker-compose.test.yaml
cp ./docker-compose/docker-compose.test.yaml $WORKDIR/output/r$ROUND
find $WORKDIR/output/r$ROUND/docker-compose.test.yaml -exec sed -i "s/\-test/\-test.r${ROUND}/g" {} +
#find $WORKDIR/output/r$ROUND/docker-compose.test.yaml -exec sed -i "s/\/results:/\/results\/r${ROUND}:/g" {} +

# echo "Start testing..."
time (docker-compose -f $WORKDIR/output/r$ROUND/docker-compose.test.yaml up) 2>> test-up.time
time (docker-compose -f $WORKDIR/output/r$ROUND/docker-compose.test.yaml down) 2>> test-down.time
sudo rm $WORKDIR/output/r$ROUND/docker-compose.test.yaml
# time (docker-compose -f $WORKDIR/output/r$ROUND/docker-compose.test.yaml up) 2>> test-up.time
# time (docker-compose -f $WORKDIR/output/r$ROUND/docker-compose.test.yaml down) 2>> test-down.time
# sudo rm $WORKDIR/output/r$ROUND/docker-compose.cov.yaml
# sudo rmdir $WORKDIR/output/r$ROUND/results/r$ROUND

echo "VALIDATING"
cp ./docker-compose/docker-compose.validate.yaml $WORKDIR/output/r$ROUND
find $WORKDIR/output/r$ROUND/docker-compose.validate.yaml -exec sed -i "s/\-validate/\-validate.r${ROUND}/g" {} +
time (docker-compose -f $WORKDIR/output/r$ROUND/docker-compose.validate.yaml up) 2>> log/validate-up.time
time (docker-compose -f $WORKDIR/output/r$ROUND/docker-compose.validate.yaml down) 2>> log/validate-down.time
sudo rm $WORKDIR/output/r$ROUND/docker-compose.validate.yaml

# echo "Before remove testcase"
# sudo rm -rf $WORKDIR/output/r$ROUND/test_cases

# PARALLEL * n th round 
# spawn when validation phase end...
if [ `expr $((ROUND)) % $PARALLEL` -eq 0 ]
then
    NEXT_ROUND=$((ROUND+1))
    echo "Go next round: $NEXT_ROUND"
    echo "$WORKDIR"
    $WORKDIR/startFuzzing.sh $NEXT_ROUND $END 
    pids="$!"
fi

if [ `expr $((ROUND)) % $PARALLEL` -ne 0 ]
then
    wait $pids
fi
# done

# #docker exec 
