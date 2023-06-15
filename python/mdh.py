'''
Mu2e data handling functionality supplimenting standard tools
'''

import os
import re
import zlib
import hashlib
import requests
import json
import base64
import time
from location_def import *



#
#
#

def checkFileName(fileName):
    '''
    Check file name for the right number of fields, and allowed
    chars, data_tiers, and file_types

    Parameters:
        fileName (str) : the base file name

    Returns:
        fields (list[str]) : the file name, split by dot fields
            or None if the file name did not pass tests
    '''

    # if there is any path, ignore it
    fileName = os.path.basename(fileName)

    fields = fileName.split(".")

    if len(fields) != 6:
        return None

    pat = re.compile("[a-zA-Z0-9_-]+")

    for field in fields:
        if len(field) == 0 :
            return None
        if not re.fullmatch(pat,field) :
            return None

    if fields[5] not in file_formats :
        return None

    return fields


#
#
#
def getToken():
    '''
    Lookup bearer token file and return the encoded token string.
    Search, in order
       1. $BEARER_TOKEN
       2. $BEARER_TOKEN_FILE
       3. $XDG_RUNTIME_DIR/bt_u$UID

    Returns:
        token (str) : the coded token

    Raises:
        FileNotFoundError : for token file not found
        RuntimeError : token was expired
    '''

    token = None
    tokenFile = None
    if 'BEARER_TOKEN' in os.environ :
        token = os.environ['BEARER_TOKEN']
    elif 'BEARER_TOKEN_FILE' in os.environ :
        tokenFile = os.environ['BEARER_TOKEN_FILE']
    elif 'XDG_RUNTIME_DIR' in os.environ :
        tokenFile = os.environ['XDG_RUNTIME_DIR'] + "/bt_u" + str(os.getuid())

    if token == None and tokenFile != None :
        with open(tokenFile, 'r') as file:
            token = file.read().replace('\n', '')

    if token == None :
        raise FileNotFoundError("token file not found")

    subtoken = token.split(".")[1]
    dectoken = base64.b64decode(subtoken,altchars="_-").decode("utf-8")
    ddtoken = json.loads(dectoken)

    deltat = int(ddtoken['exp']) - int(time.time())
    if deltat < 10 :
        raise RuntimeError("token was expired")

    return token


#
#
#

def fileCRC(filespec):
    '''
    Compute the enstore and dcache CRC values for a local file.
    This returns both enstore,dcache sums as ints
    enstore typically refers to the CRC as an int, while
    dcache usually refers to it as zero-padded 8 char hex

    Parameters:
        filespec (str) : the full file spec of the file to be processed

    Returns:
        enstore (int) : enstore CRC as an int
        dcache (int) :  dcache CRC as an int
    '''

    buffer_size=2**10*8
    hash0 = 0
    hash1 = 1

    with open(filespec, mode="rb") as f:
        chunk = f.read(buffer_size)
        while chunk:
            hash0 = zlib.adler32(chunk,hash0)
            hash1 = zlib.adler32(chunk,hash1)
            chunk = f.read(buffer_size)

    return hash0,hash1

#
#
#

def fileUrl(fileName=None, location="tape", schema="path"):
    '''
    Return the full dCache file path or url for a file name

    Parameters:
        fileName (str) : the file name (any directories are stripped)
        location (str) : location to return (tape,disk,scratch,nersc)
        schema (str) :  the protocol of the filespec (path,http,root,dcap,sam)
            path: '/pnfs/mu2e/.../file'
            http: 'http://.../file'
            root: 'root://.../file'
            dcap: 'dcap://.../file'
            sam: 'enstore:/pnfs/mu2e/...' (no file name)

    Returns:
        url (str) : the path or url

    Raises:
        ValueError : for invalid inputs

    '''


    if location not in locs :
        raise ValueError("Invalid file location in fileUrl: " + location)

    if schema not in schemas :
        raise ValueError("Invalid schema in fileUrl: " + schema)

    if location == "nersc" :
        if not (schema == "path" or schema == "sam" ) :
            raise ValueError("Invalid nersc schema in fileUrl: " + schema)

    # if there is any path, ignore it
    fileName = os.path.basename(fileName)

    fields = checkFileName(fileName)
    if fields == None :
        raise ValueError("Invalid file name in fileUrl: "+fileName)

    userType = "user"
    if fields[1] == "mu2e" :
        userType = "prod"

    ff = fileFamilies[fields[0]][userType]

    hs = hashlib.sha256(fileName.encode('utf-8')).hexdigest()

    path = ff + "/" + fields[0] + "/" + fields[1] + "/" + fields[2]
    path = path + "/" + fields[3] + "/" + fields[5]
    path = path + "/" + hs[0:2] + "/" + hs[2:4]

    path = locs[location]["prefix"] + "/" + path

    if schema == "path" :
        url = path + "/" + fileName
    elif schema == "sam" :
        url = locs[location]["sam"] + ":" + path
    else :
        path = "/pnfs/fnal.gov/usr" + path[5:] + "/" + fileName
        if schema == "http" :
            url = "https://fndcadoor.fnal.gov:2880" + path
        elif schema == "root" :
            url = "root://fndcadoor.fnal.gov" + path
        elif schema == "dcap" :
            url = "dcap://fndcadoor.fnal.gov:24125" + path

    return url

#
#
#

def dcacheInfo(fileName=None, location="tape"):
    '''
    Return a dictionary of the content of the dCache database for a file

    Parameters:
        fileName (str) : (required)
            the base file name or the full path for the file
        location (str) :
            location to lookup (tape,disk,scratch). If the full path
            is given with the filename, that path is used.

    Returns:
    info (dictionary) : the dCache database content as a dictionary

    Throws:
        ValueError : for bad file name, or unknown location
        HTTPError : for requests call

    '''


    if location not in locs :
        raise ValueError("Invalid file location in fileUrl: " + location)

    if fileName == None :
        raise ValueError("File name required but not provided")

    if fileName.find("/") == -1 :
        fileSpec = fileUrl(fileName,location)
    else :
        fileSpec = fileName

    # strip the "/pnfs" from the file path to make the url
    url = "https://fndcadoor.fnal.gov:3880/api/v1/namespace/" \
          + fileSpec[5:] + "?checksum=true&locality=true"

    token = getToken()

    header={ 'Authorization' : "Bearer " + token }

    response = requests.get(url,headers=header,
                            verify="/etc/grid-security/certificates")

    if response.status_code == 404 :
        raise RuntimeError("File not found in dCache")
    elif response.status_code != 200 :
        response.raise_for_status()

    return json.loads(response.text)
