#! /bin/bash
if [ -v BEARER_TOKEN_FILE ]; then
    :
elif [ -v XDG_RUNTIME_DIR ]; then
    BEARER_TOKEN_FILE=${XDG_RUNTIME_DIR}"/bt_u"$(id -u)
else
    echo "Could not find token path"
    exit 1
fi
RENEW=""
if ! command -v httokendecode 2>&1 > /dev/null ; then
    echo "Could not find httokendecode command"
    exit 1
fi
SCRIPT=/cvmfs/mu2e.opensciencegrid.org/bin/getToken
if ! command -v $SCRIPT 2>&1 > /dev/null ; then
    echo "Could not find $SCRIPT"
    exit 1
fi
OUTPUT=$( eval $SCRIPT --minsec=600 --nooidc )
if [ $? -ne 0 ]; then
    echo "failed to renew token"
    echo "$OUTPUT"
    exit 1
fi
echo $BEARER_TOKEN_FILE
exit 0
