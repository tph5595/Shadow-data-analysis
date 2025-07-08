#!/bin/sh
set -euxo pipefail

RATIOS=(10 100)
SPLITS=3

# poetry run jupyter nbconvert --to script analysis.ipynb
# poetry run jupyter nbconvert --to script best_new.ipynb

for r in ${RATIOS[@]}; do
    for i in $(seq 1 $SPLITS); do
        dst_file="config_multiscope/dot_vpn_multi_scale5k10k_base_${r}_${i}.yaml"

        # run NCC fast
        poetry run python analysis.py ../$dst_file
        # Get best
        poetry run python best_new.py ../$dst_file
        popd

        rm $dst_file

    done
done
