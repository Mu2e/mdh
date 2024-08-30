#! /bin/bash
#
# see the main section below for how to setup the test paths
#


basic() {

    echo "[$(date)] start basic"
    local RC=0
    cp $ART_SOURCE $EX_ART

    echo "********************* help"
    mdh -h
    RC=$((RC+$?))
    mdh compute-crc -h
    RC=$((RC+$?))

    echo "********************* crc"
    echo "test one arg"
    mdh compute-crc -d $EX_ART
    RC=$((RC+$?))
    echo "test pipe"
    ls $EX_ART $EX_ART | mdh compute-crc -d -v -

    echo "********************* print-url"
    mdh print-url -l tape -s http $EX_ART
    RC=$((RC+$?))
    mdh print-url -l scratch -s root mu2e:$EX_ART
    RC=$((RC+$?))

    echo "********************* create-metadata"
    TMP=/tmp/etc.rlc.d.c.s.txt
    date > $TMP
    mdh create-metadata $TMP
    RC=$((RC+$?))
    rm -f $TMP
    mdh create-metadata \
        -p ${OWNER}:etc.${OWNER}.d.c.s1.txt,${OWNER}:etc.${OWNER}.d.c.s2.txt \
        -s ${OWNER}_ana \
        -a appfam -n appname -e appversion \
        $EX_ART
    RC=$((RC+$?))
    echo "[$(date)] done basic $RC"
    return $RC
}

oneupload() {

    CONFIG=$(date +%s) # unique name for the file
    echo "[$(date)] start upload"
    LOCS=scratch

    local RC=0
    local EX_DS=mcs.${OWNER}.dh_test.${CONFIG}.art
    local EX_UPLOAD=mcs.${OWNER}.dh_test.${CONFIG}.001200_000001.art
    cp $ART_SOURCE $EX_UPLOAD

    echo "***** create-metadata"
    mdh create-metadata -v -f -d -o $EX_UPLOAD
    RC=$((RC+$?))

    echo "***** copy-file"
    mdh copy-file -d -v -o -l $LOCS $EX_UPLOAD
    RC=$((RC+$?))

    PP=$(mdh print-url -l $LOCS $EX_UPLOAD)
    ls -l $PP


    echo "***** locate-dataset"
    mdh locate-dataset -v -l $LOCS $EX_DS
    RC=$((RC+$?))

    echo "***** validate-dataset"
    mdh verify-dataset $EX_DS
    RC=$((RC+$?))

    # cleanup

    echo "***** delete replica"
    mdh delete-files -v -r -l $LOCS $EX_DS
    RC=$((RC+$?))
    echo "***** delete dcache and catalog"
    mdh delete-files -v -c -d -l $LOCS $EX_DS
    RC=$((RC+$?))

    echo "[$(date)] done upload $RC"
    return $RC
}



grid() {
    echo "[$(date)] start grid"
    local LOCS=scratch
    local RC=0
    local DT=$(date)
    local DSF="$1"
    [ -z "$DSF" ] && DSF=$( date +%s | cut -c 6- )
    echo "DSF=$DSF"

    mkdir -p jsb_tmp
    local CONTENT="$DSF $DT"
    echo "$CONTENT in log" > jsb_tmp/JOBSUB_LOG_FILE
    echo "$CONTENT in err" > jsb_tmp/JOBSUB_ERR_FILE

    echo "$DSF $DT"
    local F1="etc.${OWNER}.dh_test.${DSF}.000.txt"
    echo "$CONTENT in F1" > $F1
    local F2="etc.${OWNER}.dh_test.${DSF}.001.txt"
    echo "$CONTENT in F2" > $F2
    local LL="etc.${OWNER}.dh_test.${DSF}.001.log"
    echo "$CONTENT in LL" > $LL

    # logf iel will pick up a tag, so can only refer to DS, not file name
    local LLDS="etc.${OWNER}.dh_test.${DSF}.log"

    local FS1=$(mdh print-url -l $LOCS $F1)
    local FS2=$(mdh print-url -l $LOCS  $F2)

    #localfile , rse , parents , json , newname
    echo "# comment" > output.txt
    echo "$F1,scratch" >> output.txt
    echo "$F2,scratch" >> output.txt
    echo ", scratch ,  , , $LL" >> output.txt

    # default is to assume the grid job has set this
    export MOO_CONFIG=test-000-000-000
    echo "MOO_CONFIG=$MOO_CONFIG"

    echo "output.txt"
    cat output.txt

    echo "mdh upload-grid output.txt"
    mdh upload-grid -v output.txt
    RC=$((RC+$?))
    echo "dir uploaded files"
    ls -l $FS1
    ls -l $FS2

    echo "cat uploaded files"
    cat $FS1
    cat $FS2

    echo "delete files from grid upload"
    mdh delete-files -v -d -c -l $LOCS $FS1 $FS2 $LLDS
    echo "cleanup from grid upload"
    rm -f $F1 $F2
    rm -rf jsb_tmp
    rm -f output.txt

    echo "[$(date)] done grid $RC"
    return $RC
}

#
#  main
#

# typical setup to get the mdh to be tested in the path
source /cvmfs/mu2e.opensciencegrid.org/setupmu2e-art.sh
muse setup ops

# need to do checkout and paths
export PATH=$PWD/mdh/bin/:$PATH
export PYTHONPATH=$PWD/mdh/python/:$PYTHONPATH

echo "versions being tested:"
command -v metacat
command -v rucio
command -v mdh

DOBASIC=1
DOUPLOAD=1
DOGRID=1

RCT=0

# this file should be readily available
ART_SOURCE=/cvmfs/mu2e.opensciencegrid.org/DataFiles/Validation/dts.brownd.EleBeamFlashCat.MDC2020f.001202.art

OWNER=$USER
[ "$USER" == "mu2epro" ] && OWNER=mu2e
echo OWNER=$OWNER

EX_ART=mcs.${OWNER}.dh_test.000.001200_000001.art
EX_UPLOAD=mcs.${OWNER}.dh_test.100.001200_000001.art

if [ "$DOBASIC" ]; then
    echo "********************* basics"
    basic
    RCT=$(($RCT+$?))
fi

if [ "$DOUPLOAD" ]; then
    echo "********************* one upload"
    oneupload
    RCT=$(($RCT+$?))
fi

if [ "$DOGRID" ]; then
    echo "********************* upload grid"
    grid
    RCT=$(($RCT+$?))
fi

echo "[$(date)] done $RCT"

exit $RCT
