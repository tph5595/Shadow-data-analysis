#!/bin/sh
for i in *.csv; do 
      rpls -n $i -k 1 -c $i.rpls.csv
done
