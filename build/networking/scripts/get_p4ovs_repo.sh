#!/usr/bin/bash
#Copyright (C) 2021 Intel Corporation
#SPDX-License-Identifier: Apache-2.0

if [ -z "$1" ]
then
   echo "-Missing mandatory arguments;"
   echo " - Usage: ./get_p4ovs_repo.sh <WORKDIR> "
   return 1
fi

WORKDIR=$1

cd "$WORKDIR" || exit
echo "Removing P4-OVS directory if it already exits"
if [ -d "P4-OVS" ]; then rm -Rf P4-OVS; fi
echo "Cloning P4-OVS repo"
cd "$WORKDIR" || exit
git clone https://github.com/ipdk-io/ovs.git -b ovs-with-p4 P4-OVS
cd P4-OVS
git checkout a0a623af26347d9fc441c35cd1126a12e75d8d97
git submodule update --init --recursive
