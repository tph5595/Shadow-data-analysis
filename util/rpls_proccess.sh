#!/bin/sh
for i in $1*.csv; do 
      rpls -n $i -k 1 -c $i.pl
done
