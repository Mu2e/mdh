#!/bin/bash
#
# Generate Mu2e metadata for art files.
#
# $1 = local filespec of art file
# $2 = if "mc" use the sim version of metadata extractor for GenEventCount
#

ARTFILE=$1
# in MC files only, cut off the subrun list at this length
MAXLENGTH=100
FILETYPE=$2

if [ -z "$ARTFILE" ]; then
    echo "mdh artMetadata.sh - no art file argument"
    exit 1
fi

if [ -z "$MU2E" ] ; then

    if [ ! -r /cvmfs/mu2e.opensciencegrid.org/setupmu2e-art.sh ]; then
        echo "mdh artMetadata.sh can't run without an Offline available"
        exit 1
    fi

    source /cvmfs/mu2e.opensciencegrid.org/setupmu2e-art.sh
    if [ $? -ne 0 ]; then
        echo "mdh artMetadata.sh failed to run mu2einit"
        exit 1
    fi
fi

if ! command -v mu2e > /dev/null ; then

    muse setup Offline
    if [ $? -ne 0 ]; then
        echo "mdh artMetadata.sh failed to setup Offline"
        exit 1
    fi
fi

TMP=$(mktemp)

file_info_dumper --event-list $ARTFILE >& $TMP
RC=$?
if [ $RC -ne 0 ]; then
    echo "file_info_dumper returns RC=$RC"
    cat $TMP
    rm -f $TMP
    exit $RC
fi

cat $TMP    | awk '
BEGIN{
  PROCINFO["sorted_in"] = "@ind_str_asc";
  started=0;
  eventCount=0;
  fer="";
  fsr="";
};
function array_length(a) {
  count=0; for(i in a) count++; return count;
}
{
  if(started) {
    if(NF==2) {
      # process subrun list
      if(!fsr) fsr=$0;
      lsr=$0;

      if((array_length(asr) < 1+'$MAXLENGTH') || ("'$FILETYPE'" != "mc")) {
          asr[$0]++;
      }
      else {
          # Empty the subrun list
          for(i in asr) delete asr[i];
      }

    }
    if(NF==3) {
      # process event list
      ++eventCount;
      if(!fer) fer=$0;
      ler=$0;
    }
  };
};
/Run *SubRun *Event/{started=1};
END {
print "start RunSubrunEvent"
# Info on the first (sorted) subrun in the file
  split(fsr, fsra);
  print "    rs.first_run     "fsra[1];
  print "    rs.first_subrun  "fsra[2];

# Info on the last (sorted) subrun in the file
  split(lsr, lsra);
  print "    rs.last_run      "lsra[1];
  print "    rs.last_subrun   "lsra[2];

# Info on the first (sorted) event in the file, not defined for files with no events.
  if(eventCount) {
    split(fer, fera);
    print "    rse.first_run    "fera[1];
    print "    rse.first_subrun "fera[2];
    print "    rse.first_event        "fera[3];
  }
# Info on the last (sorted) event in the file, not defined for files with no events.
  if(eventCount) {
    split(ler, lera);
    print "    rse.last_run      "lera[1];
    print "    rse.last_subrun   "lera[2];
    print "    rse.last_event          "lera[3];
  }
  print "    rse.nevent   "eventCount;

# List of subruns
  printf "    rs.runs ";
  for(i in asr) {
    split(i,tmp);
    rsr = tmp[1]*1000000 + tmp[2]
    printf " "rsr;
  }
printf "\nend RunSubrunEvent\n"
}
'

if [ "$FILETYPE" != "mc" ]; then
    exit 0
fi


TMPF=$(mktemp)
cat > $TMPF <<EOF
process_name: genCountPrint
source: { module_type: RootInput }
physics: {
   analyzers: {
      genCountPrint: { module_type: GenEventCountReader makeHistograms: false }
   }
   e1: [ genCountPrint ]
   end_paths: [ e1 ]
}
source.readParameterSets: false
# source.compactEventRanges: true # 2025-07-22: Mu2e DAQ broke this.
source.processingMode: RunsAndSubRuns
EOF

mu2e -c $TMPF -s $ARTFILE > $TMP
RC=$?
if [ $RC == 0 ]; then
    LINE="$(grep "GenEventCount total" $TMP)"
    if [ "$LINE" ]; then
        echo $LINE
    else
        echo "ERROR: could not find GenCount total"
        RC=1
    fi
else
    if grep -q 'no *GenEventCount *record' $TMP; then
        # allowed to fail by not finding the product
        RC=0
    fi
fi

[ $RC -ne 0 ] && cat $TMP

rm -f $TMP $TMPF

exit $RC
