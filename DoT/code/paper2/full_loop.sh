#!/bin/sh
set -euxo pipefail

RATIOS=(10 100)
SPLITS=3


for r in ${RATIOS[@]}; do
    for i in $(seq 1 $SPLITS); do
        dst_file="config_multiscope/dot_vpn_multi_scale5k10k_base_${r}_${i}.yaml"
        # setup config file
        cp config_multiscope/dot_vpn_multi_scale5k10k_base $dst_file
        sed -i "s/replace-me-r/${r}/g" $dst_file
        sed -i "s/replace-me-i/${i}/g" $dst_file
        
        # main proccess each
        poetry run python main.py $dst_file
    done
done
