#!/bin/bash
#
# Generate Mu2e metadata for art files.
#
# $1 = local filespec of art file
#

#source /cvmfs/mu2e.opensciencegrid.org/setupmu2e-art.sh
#muse setup /mu2e/app/users/rlc/dev
#muse status


ARTFILE=$1

if [ -z "$ARTFILE" ]; then
    echo "mdh artMetadata.sh - no art file argument"
    exit 1
fi

if [ -z "$MUSE_WORK_DIR" ]; then

    if [ ! -r /cvmfs/mu2e.opensciencegrid.org/setupmu2e-art.sh ]; then
        echo "mdh artMetadata.sh can't run without an Offline available"
        exit 1
    fi

    source /cvmfs/mu2e.opensciencegrid.org/setupmu2e-art.sh
    unsetup sqlite
    unsetup python
    muse setup /mu2e/app/users/rlc/dev

    if [ $? -ne 0 ]; then
        echo "mdh artMetadata.sh failed to setup Offline"
        exit 1
    fi
fi

mu2e -c Offline/Print/fcl/printMetadata.fcl -s $ARTFILE
if [ $? -ne 0 ]; then
    echo "mdh artMetadata.sh failed to run Offline"
    exit 1
fi

exit 0
