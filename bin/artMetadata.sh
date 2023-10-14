#!/bin/bash
#
# Generate Mu2e metadata for art files.
#
# $1 = local filespec of art file
# $2 = if "mc" use the sim version of metadata extractor
#

ARTFILE=$1
if [ "$2" == "mc" ]; then
    FCLFS=Offline/Print/fcl/printMetadataSim.fcl
else
    FCLFS=Offline/Print/fcl/printMetadata.fcl
fi

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
    muse setup Offline
    #muse setup /mu2e/app/users/rlc/dev
    if [ $? -ne 0 ]; then
        echo "mdh artMetadata.sh failed to setup Offline"
        exit 1
    fi
fi

mu2e -c $FCLFS -s $ARTFILE
if [ $? -ne 0 ]; then
    echo "mdh artMetadata.sh failed to run Offline"
    exit 1
fi

exit 0
