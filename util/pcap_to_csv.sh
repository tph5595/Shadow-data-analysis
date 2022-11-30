#!/bin/bash
shopt -s nullglob
for f in $(find data -type f -name "*.pcap"); do
    base=${f##*/}
    tshark -r "$f" \
        -T fields -e frame.number -e frame.time \
        -e ip.src -e ip.dst -e ip.proto -e frame.len \
        -E header=y -E separator=, -E quote=d \
        -E occurrence=f> ./"${base%.pcap}.csv"
done
mkdir data/csv
mv *.csv data/csv

