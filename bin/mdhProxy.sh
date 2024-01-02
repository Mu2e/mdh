#! /bin/bash
if ! command -v voms-proxy-info 2>&1 > /dev/null ; then
    echo -e "\nCould not find voms-proxy-info command\n"
    exit 1
fi
RENEW=""
if ! voms-proxy-info -exists ; then
    printenv | grep X509
    RENEW=TRUE
fi
if ! voms-proxy-info -exists -valid 00:10 ; then
    echo "X509 proxy has less than 10 min to expiration"
    RENEW=TRUE
fi
SCRIPT=/cvmfs/mu2e.opensciencegrid.org/bin/vomsCert
if [ "$RENEW" ]; then
    echo "Renewing proxy"
    if klist -s ; then
        if [ -x $SCRIPT ]; then
            OUTPUT=$( $SCRIPT 2>&1 )
            if [ $? -eq 0 ]; then
                echo "Sucess renewing proxy"
            else
                echo "$OUTPUT"
                exit 1
            fi
        else
            echo -e "\nfailed to find vomsCert script\n"
            exit 1
        fi
    else
        echo -e "\nfailed to find valid kerberos ticket\n"
        exit 1
    fi
fi
# print the path to the proxy
voms-proxy-info -path
exit 0
