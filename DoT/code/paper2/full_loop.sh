#!/bin/sh
set -euxo pipefail

RATIOS=(10 20 30 40 50 60 70 80 90 100)
SPLITS=30

CONFIG="config_multiscope/dot_vpn_multi_scale5k10k_base"

for r in ${RATIOS[@]}; do
    for i in $(seq 1 $SPLITS); do
        dst_file="${CONFIG}_${r}_${i}.yaml"
        # setup config file
        cp $CONFIG $dst_file
        sed -i "s/replace-me-r/${r}/g" $dst_file
        sed -i "s/replace-me-i/${i}/g" $dst_file
        
        # main proccess each
        poetry run python main.py $dst_file
    done
done
