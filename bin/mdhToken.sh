#! /bin/bash

# grid job, token is there or not

if [ -v GRID_USER ]; then
    if [ -v BEARER_TOKEN_FILE ]; then
        echo $BEARER_TOKEN_FILE
        exit 0
    else
        echo -e "\nCould not find token path in grid mode\n"
        exit 1
    fi
fi

# interactive, can renew

if [ -v BEARER_TOKEN_FILE ]; then
    :
elif [ -v XDG_RUNTIME_DIR ]; then
    BEARER_TOKEN_FILE=${XDG_RUNTIME_DIR}"/bt_u"$(id -u)
else
    echo -e "\nCould not find token path\n"
    exit 1
fi
RENEW=""
if ! command -v httokendecode 2>&1 > /dev/null ; then
    echo -e "\nCould not find httokendecode command\n"
    exit 1
fi
SCRIPT=/cvmfs/mu2e.opensciencegrid.org/bin/getToken
if ! command -v $SCRIPT 2>&1 > /dev/null ; then
    echo -e "\nCould not find $SCRIPT \n"
    exit 1
fi

# will need a kerberos ticket to get token
if ! klist -s ; then
    echo -e "\nfailed to find kerberos ticket\n"
    exit 1
fi

OUTPUT=$( eval $SCRIPT --minsec=1500 --nooidc )
if [ $? -ne 0 ]; then
    echo -e "\nfailed to renew token\n"
    echo "$OUTPUT"
    exit 1
fi
echo $BEARER_TOKEN_FILE
exit 0
