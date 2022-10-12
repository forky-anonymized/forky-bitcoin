#!/bin/bash
# set -x
shopt -s expand_aliases

if [ "$#" -ne 2 ]; then
    echo "$# is Illegal number of parameters."
    echo "Usage: ./genBlockchain.sh [#nodes] [bitcoin_root]"
    echo "You need Bitcoin Core dir that contain \"bitcoind\" & \"bitcoin-cli\""
    echo "Recommend #node=5"
	exit 1
fi

echo "Start make new Blockchain for environment setup"

BITCOIN_ROOT="$2"
WORK_DIR=$( cd "$(dirname "$0")" ; pwd )
DATA_DIR="${WORK_DIR}/regtest_datadir"
port=10000
rpcport=30000
echo "==bitcoin-core is in $BITCOIN_ROOT=="

echo
echo "=clear previous Settings and make new datadir="
kill $(pidof bitcoind)
rm -rf $DATA_DIR
mkdir -p $DATA_DIR
cd $DATA_DIR

echo
echo "creating datadir..."
for((i=0; i < $1; i++))
do
    mkdir -p node$i
done
rm ~/setAlias.sh
touch ~/setAlias.sh
chmod +x ~/setAlias.sh
echo "#!/bin/bash" >> ~/setAlias.sh
echo "=start new nodes="
bitcoind="${BITCOIN_ROOT}bitcoind"
cli="${BITCOIN_ROOT}bitcoin-cli"
for((i=0; i<$1; i++))
do
    let rpcport_=$i+$rpcport
    let port_=$i+$port
    $bitcoind -regtest -port=$port_ -rpcport=$rpcport_ -datadir=$DATA_DIR/node$i --daemon
    echo 'alias node'$i'="'${BITCOIN_ROOT}'bitcoin-cli -regtest -datadir='$DATA_DIR'/node'$i' -rpcport='$rpcport_'"' >> ~/setAlias.sh
done

source ~/setAlias.sh

echo "creating wallets for nodes..."
for((i=0; i<$1; i++))
do
	let rpcport_=$i+$rpcport
	$cli -regtest -rpcport=$rpcport_ -datadir=$DATA_DIR/node$i createwallet testwallet$i
done

echo
echo "connecting node each other..."
for((i=0; i<$1; i++))
do
    let rpcport_=$i+$rpcport
    for((j=0; j<$1; j++))
    do
        if [ $i -ne $j ]
		then
            let port_=$j+$port
            echo "node$i connect node$j"
			$cli -regtest -rpcport=$rpcport_ -datadir=$DATA_DIR/node$i addnode "127.0.0.1:$port_" "add"
		fi
    done
done

echo "Wait sync..."
sleep 5
cd $WORK_DIR

for((i=0; i<30; i++))
do
    for((j=0; j<$1; j++))
    do
        let rpcport_=$j+$rpcport
        $cli -regtest -rpcport=$rpcport_ -datadir=$DATA_DIR/node$j -generate
    done
done

echo "Ready for make transaction..."
sleep 5
rm ./block.txt
touch ./block.txt
for((i=0; i<10; i++))
do
    for((j=0; j<$1; j++))
    do
        let rand=$RANDOM%200
        for((k=0; k<$rand; k++))
        do
            let rpcport_=$j+$rpcport
            echo "Try make tx$k on node$j"
            $cli -regtest -rpcport=$rpcport_ -datadir=$DATA_DIR/node$j sendtoaddress "$($cli -regtest -rpcport=30000 -datadir=${DATA_DIR}/node0 getnewaddress)" 0.00001 null null true true null "unset" null 1.1
        done
    done
    echo "Mining..."
    sleep 5
    let num=$i%5
    let rpcport_=$num+$rpcport
    $cli -regtest -rpcport=$rpcport_ -datadir=$DATA_DIR/node$num -generate >> ./block.txt
    cat ./block.txt
done

echo "make empty 10 block to confirm previous block"
sleep 1

for((i=0; i<2; i++))
do
    for((j=0; j<$1; j++))
    do
        let rpcport_=$j+$rpcport
        $cli -regtest -rpcport=$rpcport_ -datadir=$DATA_DIR/node$j -generate
    done
done

echo "Block height"
$cli -regtest -rpcport=30000 -datadir=$DATA_DIR/node0 getblockchaininfo | grep height

echo "Copy Blockchain..."
cp $DATA_DIR/node0/regtest/blocks/blk00000.dat $WORK_DIR/blockchain.dat
# mv $WORK_DIR/block.txt $WORK_DIR/import/blockinfo.txt
if [ -e $WORK_DIR/import/import.dat ]; then
    echo "Previous import.dat exists..."
    if [ -e $WORK_DIR/import/import.dat.old ]; then
        echo "Previous import.dat.old exists..."
        echo "REmove previous import.dat.old..."
        rm -rf $WORK_DIR/import/import.dat.old
    fi
    echo "Backup previous import.dat..."
    mv $WORK_DIR/import/import.dat $WORK_DIR/import/import.dat.old
fi

echo "Replace import.dat to new blockchain..."
mv $WORK_DIR/blockchain.dat $WORK_DIR/import/import.dat

echo "..."
echo "Finish"