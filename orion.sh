#!/bin/sh

sudo mn -c

sudo mn --custom orion_topo.py --topo orion --mac --controller=remote,ip=127.0.0.1,port=6653 --switch ovs,protocols=OpenFlow13 --nat

