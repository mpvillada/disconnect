#!/bin/bash

wlan=$1

echo "starting monitors in $wlan"
ifconfig $wlan up
airmon-ng start $wlan > /dev/null
   

