#!/bin/bash

monitors=$(airmon-ng | grep mon | cut -f1)
for mon in $monitors
do
   echo "stopping $mon"
   airmon-ng stop $mon > /dev/null
done


