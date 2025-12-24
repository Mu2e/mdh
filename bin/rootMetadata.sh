#!/bin/bash
#
# Generate Mu2e metadata for art files.
#
# $1 = local filespec of art file
# $2 = if "mc" use the sim version of metadata extractor for GenEventCount
#

ENFILE=$1
if [ -z "$ENFILE" ]; then
    echo "mdh rootMetadata.sh - no file argument"
    exit 1
fi

if [ -z "$MU2E" ] ; then

    if [ ! -r /cvmfs/mu2e.opensciencegrid.org/setupmu2e-art.sh ]; then
        echo "mdh rootMetadata.sh can't run without an Offline available"
        exit 1
    fi

    source /cvmfs/mu2e.opensciencegrid.org/setupmu2e-art.sh
    if [ $? -ne 0 ]; then
        echo "mdh rootMetadata.sh failed to run mu2einit"
        exit 1
    fi
fi

if ! command -v mu2e > /dev/null ; then

    muse setup Offline
    if [ $? -ne 0 ]; then
        echo "mdh rootMetadata.sh failed to setup Offline"
        exit 1
    fi
fi

rseEventNtuple $ENFILE
RC=$?

exit $RC
