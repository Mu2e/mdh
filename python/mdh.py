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
import subprocess
import pprint
from datetime import datetime

from metacat.webapi import MetaCatClient
from metacat.common.auth_client import AuthenticationError
from metacat.webapi.webapi import AlreadyExistsError
from metacat.webapi.webapi import NotFoundError
from metacat.webapi.webapi import BadRequestError

from data_dispatcher.api import DataDispatcherClient

from rucio.client import Client as RucioClient
from rucio.client.replicaclient import ReplicaClient
from rucio.client.didclient import DIDClient
from rucio.common.exception import DataIdentifierAlreadyExists
from rucio.common.exception import DuplicateRule
from rucio.common.exception import DataIdentifierNotFound
#
# a single global instance of the MParameters class
# created after the definition
#
_pars = None


#
#
#
class MParameters :
    def __init__(self) :
        self.file_families = {
            "raw":{"prod":"phy-raw","user":"phy-raw","type":"data"},
            "rec":{"prod":"phy-rec","user":"usr-dat","type":"data"},
            "ntd":{"prod":"phy-ntd","user":"usr-dat","type":"data"},
            "ext":{"prod":None,     "user":"usr-dat","type":"data"},
            "rex":{"prod":None,     "user":"usr-dat","type":"data"},
            "xnt":{"prod":None,     "user":"usr-dat","type":"data"},
            "cnf":{"prod":"phy-etc","user":"usr-etc","type":"other"},
            "sim":{"prod":"phy-sim","user":"usr-sim","type":"mc"},
            "dts":{"prod":"phy-sim","user":"usr-sim","type":"mc"},
            "mix":{"prod":"phy-sim","user":"usr-sim","type":"mc"},
            "dig":{"prod":"phy-sim","user":"usr-sim","type":"mc"},
            "mcs":{"prod":"phy-sim","user":"usr-sim","type":"mc"},
            "nts":{"prod":"phy-nts","user":"usr-nts","type":"mc"},
            "log":{"prod":"phy-etc","user":"usr-etc","type":"other"},
            "bck":{"prod":"phy-etc","user":"usr-etc","type":"other"},
            "etc":{"prod":"phy-etc","user":"usr-etc","type":"other"}}

        self.file_formats = [ "art", "root", "txt", "tar", "tgz", "log", "fcl",
                         "mid", "tbz", "stn", "enc", "dat", "tka", "pdf" ]

        self.schemas = {"path" : "",
                        "http" : "https://fndcadoor.fnal.gov:2880",
                        "root" : "root://fndcadoor.fnal.gov:1094",
                        "dcap" : "dcap://fndcadoor.fnal.gov:24125",
                        "sam" : ""}

        self.locs = {
            "tape" :    { "prefix":"/pnfs/mu2e/tape",
                          "sam":"enstore",
                          "rucio":"FNAL_DCACHE_TAPE"},
            "disk" :    { "prefix":"/pnfs/mu2e/persistent/datasets",
                          "sam":"dcache",
                          "rucio":"FNAL_DCACHE_PERSISTENT"},
            "scratch" : { "prefix":"/pnfs/mu2e/scratch/datasets",
                          "sam":"dcache",
                          "rucio":"FNAL_SCRATCH"},
            "nersc" :   { "prefix":"/global/cfs/cdirs/m3249/datasets",
                          "sam":"nersc",
                          "rucio":""}
        }

        return


    def location(self, location, key) :
        if location not in self.locs :
            raise RuntimeError('bad location : '+location)
        ff = self.locs[location]
        if key not in ff :
            raise RuntimeError('bad locations key : '+key)
        return ff[key]

    def loc_from_rse(self, rse) :
        for k,v in self.locs.items() :
            if v['rucio'] == rse :
                return k
        return None

    def file_family(self, tier, key):
        if tier not in self.file_families :
            raise RuntimeError('bad file tier : '+tier)
        ff = self.file_families[tier]
        if key not in ff :
            raise RuntimeError('bad file family key : '+key)
        return ff[key]

    def check_location(self, location):
        if location not in self.locs :
            raise RuntimeError('bad location : '+location)

    def check_schema(self, schema):
        if schema not in self.schemas :
            raise RuntimeError('bad schema : '+schema)

    def url_prefix(self, schema):
        self.check_schema(schema)
        return self.schemas[schema]

    def check_format(self, format):
        if format not in self.file_formats :
            raise RuntimeError('bad file format : '+format)

    def check_name(self, name, qfile=True):
        did = os.path.basename(name)
        if ':' not in did:
            did = name.split('.')[1] + ':' + name
        self.check_did(did,qfile)

    def check_did(self, did, qfile=True, qAddhocDs=True):
        '''
        Check file name for the right number of fields, and allowed
        chars, data_tiers, and file_types

        Parameters:
            did (str) : the namespace and file name
            qfile (bool) : check for legal file name (t) or dataset (f)
            qAddhocDs (bool) : allow dataset names with no dots
        Raises:
            RuntimeError : file name is illegal
        '''

        dida = did.split(':')
        if len(dida) != 2 :
            raise RuntimeError('did did not contain a colon : '+did)

        ns = dida[0]
        name = dida[1]

        if len(ns) == 0 :
            raise RuntimeError('"did" namespace was zero length : '+did)

        fields = name.split('.')

        if qfile :
            nFields = 6
        else :
            nFields = 5;

        # dataset with ad-hoc format, no dots, is allowed
        qah = qAddhocDs and (not qfile) and len(fields) == 1

        if len(fields) != nFields and (not qah):
            raise RuntimeError(f'"did" did not have {nFields} fields: {did}')

        pat = re.compile('[a-zA-Z0-9_-]+')

        for field in fields:
            if len(field) == 0 :
                raise RuntimeError('file name has empty field: '+did)
            if not re.fullmatch(pat,field) :
                raise RuntimeError('file name contains bad characters: '+did)

        if qah : # if one ad-hoc field, then done checking
            return

        if not re.fullmatch(pat,field) :
            raise RuntimeError('file name contains bad characters: '+did)

        if fields[0] not in self.file_families :
            raise RuntimeError('file name contains unknown tier: '+did)

        if fields[nFields-1] not in self.file_formats :
            raise RuntimeError('file name contains unknown format: '+did)

        return

    def get_username(self):
        if 'GRID_USER' in os.environ :
            user = os.environ['GRID_USER']
        elif 'USER' in os.environ :
            user = os.environ['USER']
        else :
            raise RuntimeError('Could not find username')
        return user


#
# create the single global instance of MParameters
#
_pars = MParameters()

#
#
#
class MDataset :
    def __init__(self, name = None, namespace = None, catmetadata = None) :
        self.ds = None
        self.ns = None

        if name :
            if ':' in name :
                self.ds = name.split(':')[1]
                self.ns = name.split(':')[0]
            else :
                self.ds = name

        if namespace :
            self.ns = namespace

        if (not self.ns) and self.ds :
            # default namespace is the owner field of the dataset name
            fields = self.ds.split('.')
            if len(fields) == 5 :
                self.ns = fields[1]

        self.catmd = catmetadata

        # use the global MParameters to check name structure
        _pars.check_did(self.did(),False)

        self.file_list = []

        return

    def __str__(self) :
        return self.did()

    def add_catmetadata(self, catmetadata) :
        self.catmd = catmetadata

    def add_file(self, fn, checkName=False) :
        if checkName :
            _pars.check_did(fn)
        self.file_list.append(fn)

    def add_files(self, fn_list, checkName=False) :
        if checkName :
            for fn in fn_list :
                _pars.check_did(fn)
        self.file_list = self.file_list + fn_list

    def add_mfile(self, mfile, checkName=False) :
        if checkName :
            _pars.check_did(mfile.did())
        self.file_list.append(mfile)

    def add_mfiles(self, mfile_list, checkName=False) :
        if checkName :
            for mfile in mfile_list :
                _pars.check_did(mfile.did())
        self.file_list = self.file_list + mfiles_list

    def name(self) :
        return self.ds
    def namespace(self) :
        return self.ns
    def scope(self) :
        return self.ns
    def did(self) :
        return self.ns+':'+self.ds

    def tier(self) :
        fields = self.ds.split('.')
        if len(fields) == 5 :
            return fields[0]
        else :
            return None
    def owner(self) :
        fields = self.ds.split('.')
        if len(fields) == 5 :
            return fields[1]
        else :
            return None
    def description(self) :
        fields = self.ds.split('.')
        if len(fields) == 5 :
            return fields[2]
        else :
            return None
    def configuration(self) :
        fields = self.ds.split('.')
        if len(fields) == 5 :
            return fields[3]
        else :
            return None
    def format(self) :
        fields = self.ds.split('.')
        if len(fields) == 5 :
            return fields[4]
        else :
            return None

    def files(self) :
        return self.file_list

    def catmetadata(self) :
        return self.catmd


#
#
#
class MFile :
    def __init__(self, name = None, namespace = None,
                 filespec = None, catmetadata = None) :
        if name :
            if ':' in name :
                self.fn = name.split(':')[1]
            else :
                self.fn = name
        elif filespec :
            self.fn = os.path.basename(filespec)
        elif catmetadata :
            self.fn = catmetadata['name']
        else :
            self.fn = None

        if namespace :
            self.ns = namespace
        elif name and ':' in name :
            self.ns = name.split(':')[0]
        elif catmetadata :
            self.ns = catmetadata['namespace']
        elif self.fn :
            # default namespace is the owner field of the file name
            aa = self.fn.split('.')
            if len(aa) == 6 :  # if standard file name
                self.ns = aa[1]
            else :
                self.ns = _pars.get_username()

        if filespec :
            self.fs = os.path.abspath(filespec)

        self.catmd = catmetadata

        _pars.check_did(self.did())

        return

    def add_catmetadata(self, catmetadata) :
        self.catmd = catmetadata

    def name(self) :
        return self.fn
    def namespace(self) :
        return self.ns
    def did(self) :
        return self.ns+':'+self.fn
    def set_name(self,newname) :
        self.fn = newname

    def tier(self) :
        return self.fn.split('.')[0]
    def owner(self) :
        return self.fn.split('.')[1]
    def description(self) :
        return self.fn.split('.')[2]
    def configuration(self) :
        return self.fn.split('.')[3]
    def sequencer(self) :
        return self.fn.split('.')[4]
    def format(self) :
        return self.fn.split('.')[5]
    def extension(self) :
        return self.fn.split('.')[-1]

    def user_type(self) :
        if self.owner() == "mu2e" :
            return "prod"
        else :
            return "user"

    def filespec(self) :
        return self.fs
    def catmetadata(self) :
        return self.catmd
    def metadata(self) :
        if not self.catmd :
            return None
        return self.catmd.get('metadata')
    def adler32(self) :
        if not self.catmetadata() :
            return None
        if not 'checksums' in self.catmetadata() :
            return None
        return self.catmetadata()['checksums'].get('adler32')

    def default_dataset(self) :
        fa = self.name().split('.')
        del fa[4]
        return '.'.join(fa)

    def default_dataset_did(self) :
        return self.namespace()+':'+self.default_dataset()


    def url(self, location="tape", schema="path") :

        _pars.check_schema(schema)

        if location == "nersc" :
            if not (schema == "path" or schema == "sam" ) :
                raise ValueError("Invalid nersc schema in url: " + schema)

        ff = _pars.file_family(self.tier(),self.user_type())

        hs = hashlib.sha256(self.name().encode('utf-8')).hexdigest()

        fields = self.name().split('.')
        path = ff + "/" + fields[0] + "/" + fields[1] + "/" + fields[2]
        path = path + "/" + fields[3] + "/" + fields[5]
        path = path + "/" + hs[0:2] + "/" + hs[2:4]

        path = _pars.location(location,"prefix") + "/" + path

        if schema == "path" :
            url = path + "/" + self.name()
        elif schema == "sam" :
            url = _pars.locations(location,"sam") + ":" + path
        else :
            #strip "/pnfs"
            path = path[5:] + "/" + self.name()
            url = _pars.url_prefix(schema) + path

        return url

#
#
#
#
#

class MdhClient() :
    '''
    Mu2e custom data-handling commands based on metacat and Rucio.
    These command simplify the user commands and implement and
    enforce mu2e conventions
    '''

    def __init__(self) :
        # don't renew token or proxy too often
        self.renew_time = 1500
        self.last_token_time = 0
        self.last_proxy_time = 0
        self.token = ""
        self.proxy = ""
        # require less than this time left in authorization before
        # attempting a re-authorized operation
        self.auth_renew_time = 1500
        self.auth_expire_time = 0
        self.metacat = MetaCatClient(timeout = 3600)
        self.ddisp = DataDispatcherClient()
        # RucioClient reads X509 proxies when it is created, so
        # delay creation until there is a request for a Rucio action
        self.rucio = None
        self.verbose = 0
        self.dryrun = False


    def set_verbose(self, verbose = 0 ) :
        self.verbose = verbose

    def set_dryrun(self, dryrun = True ) :
        self.dryrun = dryrun

    def is_file(self,item) :
        if item.split(':')[-1].count('.') == 5 :
            return True
        else :
            return False

    def chunker(self, seq, size):
        return (seq[pos:pos + size] for pos in range(0, len(seq), size))

    #
    #
    #
    def get_token(self):
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

        ctime = int( time.time() )
        if ctime - self.last_token_time < self.renew_time :
            return self.token

        result = subprocess.run("mdhToken.sh",shell=True,
                                timeout=600,capture_output=True)
        if result.returncode != 0 :
            print(result.stdout.decode("utf-8"))
            print(result.stderr.decode("utf-8"))
            raise RuntimeError("Error checking if token is valid")

        token_file = result.stdout.decode("utf-8").split('\n')[-2]
        if self.verbose > 1 :
            print("found token_file:",token_file)

        with open(token_file, 'r') as file:
            token = file.read().replace('\n', '')

        self.last_token_time = ctime
        self.token = token

        return token

    #
    #
    #
    def get_metacat_auth(self):
        '''

        Check if there is a valid metacat authorization,
        with more than required time left.  if needed, try to
        renew user OIDC JWT token and renew rmetacat auth.

        Returns:
            time_left (int) : seconds left in the metacat auth

        Raises:
            RuntimeError : could not find unix user name in evironment
                           (this is used as the metacat account name)
        '''

        ctime = int( time.time() )
        time_left = self.auth_expire_time - ctime
        if time_left > self.auth_renew_time :
            return time_left

        try :
            auser, etime = self.metacat.auth_info()
            self.auth_expire_time = etime
            time_left = etime - ctime
            if time_left > self.auth_renew_time :
                if self.verbose > 1 :
                    print("time left in metacat auth:",time_left)
                return time_left
        except AuthenticationError as e :
            # no metacat token yet, make one below
            pass

        token = self.get_token()

        user = _pars.get_username()

        if self.verbose > 1 :
            print("renewing metacat auth")
        # take JWT token and create new metacat auth token on auth server
        auser,etime = self.metacat.login_token(user,token)
        self.auth_expire_time = etime
        time_left = etime - ctime
        self.ddisp.login_token(user,token)
        # save metacat auth token in token library (~/.token_library)
        self.metacat.TokenLib.save_tokens()

        return time_left

    #
    #
    #
    def get_proxy(self):
        '''
        Lookup user x509 proxy and check that is it not expired
        Search, in order
        1. os.environ['X509_USER_PROXY']
        2. '/tmp/x509up_u'+str(os.getuid())
        A proxy will be made (from an existing kerberos ticket),
        if needed and possible.

        Returns:
           path (str) : the path to the cert

        Raises:
            RuntimeError : any problem finding or making the proxy
        '''

        ctime = int( time.time() )
        if ctime - self.last_proxy_time < self.renew_time :
            return

        result = subprocess.run("mdhProxy.sh",shell=True,
                                timeout=600,capture_output=True)
        if result.returncode != 0 :
            print(result.stdout.decode("utf-8"))
            print(result.stderr.decode("utf-8"))
            raise RuntimeError("Error checking if proxy is valid")

        filespec = result.stdout.decode("utf-8").split('\n')[-2]

        self.last_proxy_time = ctime
        self.proxy = filespec

        return filespec

    #
    #
    #

    def ready_metacat(self) :
        '''
        Prepare metacat client object with authentication
        '''
        self.get_metacat_auth()

    #
    #
    #

    def ready_rucio(self) :
        '''
        Prepare Rucio client object, and add authentication
        '''
        self.get_proxy()
        # delayed construction because creating the client causes
        # proxy to be made
        if not self.rucio :
            self.rucio = RucioClient()

    #
    #
    #

    def ready_gfal(self) :
        '''
        Prepare gfal client object with authentication
        '''
        token = self.get_token()

    #
    #
    #

    def names_to_files(self, names) :
        '''
        Converts datasets and files in a list of files
        Ambiguous names are interpreted a files if 5-dot format

        Parameters
            names (str,list,MDataset,MFile) : names of files or dataset
        Returns
            flist (list[str]) : file names
        '''
        if not isinstance(names,list) :
            items = [names]
        else :
            items = names

        flist = []

        for item in items :
            ds = None
            if isinstance(item,MFile) :
                flist.append(item.name())
            elif isinstance(item,MDataset) :
                ds = item
            elif self.is_file(item) :
                flist.append(os.path.basename(item))
            else :
                ds = MDataset(item)

            if ds :
                self.ready_metacat()
                for mcf in self.metacat.get_dataset_files(did = ds.did()) :
                    flist.append(mcf['name'])

        return flist

    #
    #
    #

    def get_metadata(self, mfile):
        '''

        Read the metacat database and fill mfile object with the metadata

        Parameters:
            mfile (MFile) : a file object containing at least the file name

        Returns:
            fills the catmetadata field of the MFile argument

        '''

        if mfile.catmetadata() :
            return

        self.ready_metacat()
        cmd = self.metacat.get_file(name=mfile.name(),
                                    namespace=mfile.namespace(),
                                    with_metadata = True,
                                    with_provenance=False,
                                    with_datasets=False)
        mfile.add_catmetadata(cmd)

        return

    #
    #
    #

    def retire_metacat_file(self, file, force=False):
        '''

        Retire a file in the metacat database

        Parameters:
            mfile (str|MFile) : a file name or object containing the file name
            force (bool) : (default=F) do not raise if file not
                  available or already retired

        '''

        if isinstance(file,MFile) :
            mf = file
        else :
            mf = MFile(file)

        self.ready_metacat()
        if self.verbose > 1 :
            print("retiring "+mf.did())

        # retire file does not throw if file is already retired
        self.metacat.retire_file(did=mf.did())

        return

    #
    #
    #

    def compute_crc(self, filespec):
        '''
        Compute the enstore and dcache CRC values for a local file.
        This returns both enstore,dcache sums as strings
        enstore typically refers to the CRC as an int, while
        dcache usually refers to it as zero-padded 8 char hex

        Parameters:
            filespec (str) : the full file spec of the file to be processed

        Returns:
            enstore (str) : enstore CRC
            dcache (str) :  dcache CRC in zero-padded 8 char hex
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

        enstore = str(hash0)
        dcache = "{:08x}".format(hash1)
        return enstore,dcache


    #
    #
    #

    def query_dcache(self, file_name=None, location="tape"):
        '''
        Return a dictionary of the content of the dCache database for a file

        Parameters:
            file_name (str) : (required)
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


        _pars.check_location(location)


        if file_name == None :
            raise ValueError("File name required but not provided")

        if file_name.find("/") == -1 :
            mf = MFile(file_name)
        else :
            mf = MFile(filespec=file_name)
        file_spec = mf.url(location)

        # strip the "/pnfs" from the file path to make the url
        url = "https://fndcadoor.fnal.gov:3880/api/v1/namespace/" \
              + file_spec[5:] \
              + "?checksum=true&locality=true&xattr=true&optional=true"

        token = self.get_token()

        header={ 'Authorization' : "Bearer " + token }

        #print("file_name=",file_name)
        #print("token=",token[0:20])
        response = requests.get(url,headers=header,
                                verify="/etc/grid-security/certificates")

        if response.status_code == 404 :
            raise RuntimeError("File not found in dCache: "+file_spec)
        elif response.status_code != 200 :
            print("Uknown error in query_dcache for file : "+file_spec)
            response.raise_for_status()

        return json.loads(response.text)


    #
    #
    #

    def declare_file(self, file, force=False, delete=False, overwrite=False):
        '''

        Create a file record in metacat using the information in mfile.
        Associate the file with its default dataset. If the default
        dataset does not exist, it will also be created.

        Parameters:
            file (MFile|path) : file object with name, namespace, metacat file
                attibutes (crc and size) and mu2e metadata dictionary
                or path to local json file containing these
            force (bool) : (default=F) if file exists and is retired,
                          unretire and declare
            overwrite (bool) : (default=F) if file exists, overwrite it
            delete (bool) : (default=F) delete file after declaration

        Returns:
            catmetadata (dict) : the file catmetadata as a dictionary

        '''

        if isinstance(file,MFile) :
            mfile = file
            localFile = None
        else :
            with open(file,"r") as fp :
                text = fp.read()
            mfile = MFile(catmetadata=json.loads(text))
            localFile = file


        self.ready_metacat()

        dsdid = mfile.default_dataset_did()

        if self.verbose > 0 :
            print("declaring file : "+mfile.did())

        if self.dryrun :
            # the only thing left to do is the actual declare
            return

        done = False;
        while not done :
            try :
                self.metacat.declare_file(did = mfile.did(),
                            dataset_did = dsdid,
                            size = mfile.catmetadata()['size'],
                            checksums = mfile.catmetadata()['checksums'],
                            parents = mfile.catmetadata().get('parents'),
                            metadata = mfile.metadata())
                done = True
            except AlreadyExistsError as e :
                # file already exists, it may or may not be retired
                if self.verbose > 0 :
                    print("metacat file record already exists, force=",force,", overwrite=",overwrite)
                # if requested, unretire and update
                if force or overwrite :
                    # need to ask if retired
                    fd = self.metacat.get_file(did = mfile.did(),
                          with_metadata = False, with_provenance=False)
                    if self.verbose > 1 :
                        print("fd = ",fd)
                    if fd['retired'] :
                        # attempt unretire and update
                        if self.verbose > 0 :
                            print("unretire and update file")
                        self.metacat.retire_file(did = mfile.did(),
                                                 retire=False)
                    elif overwrite :
                        pass
                        # file exists and was not retired, overwrite
                    else :
                        # file exists and was not retired, no overwrite
                        if self.verbose > 0 :
                            print("file exist and was not retired")
                        raise


                    # file was retired and force,
                    # or file exists and overwrite
                    # update the record
                    if self.verbose > 0 :
                        print("updating metacat file record")
                    self.metacat.update_file(did = mfile.did(),
                            replace = True,
                            size = mfile.catmetadata()['size'],
                            checksums = mfile.catmetadata()['checksums'],
                            parents = mfile.catmetadata().get('parents'),
                            metadata = mfile.metadata())
                    done = True


                else : # file exists and do not force or overwrite
                    if self.verbose > 0 :
                        print("file exists, no force/overwrite requested")
                    raise

            except BadRequestError as e :
                # expect this if the default dataset does not exist
                if self.verbose > 0 :
                    print("while declaring file, default dataset does not exist, will declare it")
                # declare default dataset, force=False because we expect it DNE
                self.create_metacat_dataset(dsdid, False)
            except Exception as e :
                # expect this if the default dataset does not exist
                if self.verbose > 0 :
                    print("declare error final error"+str(e))
                    raise


        if delete :
            delp = pathlib.Path(localFile)
            delp.unlink()

        return mfile.catmetadata()


    #
    #
    #

    def create_dataset_metadata(self, did) :
        '''
        Create a dictionary of the metadata for a dataset

        Parameters:
            did (str) : the dataset did, with or without the namespace
        Returns:
            info (dictionary) : the dataset metadata as a dictionary

        '''

        dsn = did.split(':')[-1]
        da = dsn.split('.')
        md = {'ds.tier' : da[0],
              'ds.owner' : da [1],
              'ds.description' : da [2],
              'ds.configuration' : da [3],
              'ds.format' : da [4]  }
        return md

    #
    #
    #

    def create_metadata(self, mfile, parents=None, rename_seq = False,
                        appFamily=None,appName=None,appVersion=None,
                        declare=False, ignore=False,
                        force=False, overwrite=False):
        '''
        Create a dictionary of the catmetadata for a file

        Parameters:
            mfile (MFile) : the file to be processed, must include filespec
            parents (str or list(str)) : the parent files, a str of files separated
                by commas, or as a list of 'did' file names (default=None)
            rename_seq = rename sequencer to output from art metadata
            appFamily (str) : file processing record family (default=None)
            appName (str) : file processing record name (default=None)
            appVersion (str) : file processing record version (default=None)
            declare (bool) : if true, also declare the file in metacat
            ignore (bool) : if true, do not read genCount product
            force (bool) : passed to declare_file, if that's requested
            overwrite (bool) : passed to declare_file, if that's requested
        Returns:
            info (dictionary) : the file metadata as a dictionary

        Throws:
            FileNotFoundError : for source file not found
            ValueError : for bad file names
            RuntimeError : could not extract metadata

        '''

        # general metacat metadata, also called "attributes"
        catmetadata = {}
        artmetadata = {}
        if mfile.extension() == "art" :
            cmd = "artMetadata.sh " + mfile.filespec() + \
                  " " + _pars.file_family(mfile.tier(),"type")

            result = subprocess.run(cmd, shell=True, timeout=600,
                                    capture_output=True)
            if result.returncode != 0 :
                print(result.stdout.decode("utf-8"))
                print(result.stderr.decode("utf-8"))
                raise RuntimeError("Could not extract art metadata")

            mtext = result.stdout.decode("utf-8")
            inText = False
            for line in mtext.split("\n") :
                if line[0:21] == "GenEventCount total:" :
                    artmetadata["gen.count"] = int(line.split()[2])

                if line[0:18] == "end RunSubrunEvent" :
                    inText = False
                if inText :
                    ss = line.split()
                    if ss[0]=='rs.runs' :
                        srlist = [ int(sr) for sr in ss[1:] ]
                        artmetadata[ss[0]] = srlist
                    else :
                        artmetadata[ss[0]] = int(ss[1])
                if line[0:20] == "start RunSubrunEvent" :
                    inText = True

        if rename_seq :
            if not artmetadata :
                raise RunTimeError("Rename requested but no art metadata")
            aa = mfile.name().split(".")
            run = int(artmetadata["rs.first_run"])
            subrun = int(artmetadata["rs.first_subrun"])
            seq = ".{:06d}_{:06d}.".format(run,subrun)
            newname = aa[0]+"."+aa[1]+"."+aa[2]+"."+aa[3]+seq+aa[5]
            mfile.set_name(newname)

        catmetadata["name"] = mfile.name()
        catmetadata["namespace"] = mfile.namespace()

        # mu2e custom metadata
        metadata = {}
        metadata["dh.dataset"] = mfile.default_dataset()
        metadata["dh.type"] = _pars.file_family(mfile.tier(),"type")
        metadata["dh.status"] = "good"

        metadata["fn.tier"] = mfile.tier()
        metadata["fn.owner"] = mfile.owner()
        metadata["fn.description"] = mfile.description()
        metadata["fn.configuration"] = mfile.configuration()
        metadata["fn.sequencer"] = mfile.sequencer()
        metadata["fn.format"] = mfile.format()
        if appFamily :
            metadata["app.family"] = appFamily
        if appName :
            metadata["app.name"] = appName
        if appVersion :
            metadata["app.version"] = appVersion

        metadata.update(artmetadata)

        stats = os.stat(mfile.filespec())
        enstore,dcache = self.compute_crc(mfile.filespec())
        catmetadata["size"] = stats.st_size
        catmetadata['checksums'] = {"adler32" : dcache}

        if parents :
            parentList = []
            catmetadata['parents'] = []
            if isinstance(parents, list):
                for pp in parents :
                    parentList.append(pp)
            else :
                for pp in parents.split(",") :
                    parentList.append(pp)
            for pp in parentList :
                mf = MFile(pp)
                _pars.check_did(mf.did())
                catmetadata['parents'].append({'did':mf.did()})

        # the mu2e custom metadata part of the
        # file metadata is called "metadata"
        catmetadata['metadata'] = metadata

        mfile.add_catmetadata(catmetadata)

        if declare :
            self.declare_file(mfile,force=force,overwrite=overwrite)

        return catmetadata


    #
    #
    #

    def gfal_rm_file(self, url):
        '''
        Run gfal to delete a file via url or path
        Parameters:
            url (str) : a file, local path or http url
        Raises:
            RuntimeError : could not run gfal-rm
        Returns:
            rc (bool) : True is deleted False is file was missing
        '''

        self.ready_gfal()

        env = {"BEARER_TOKEN" : self.token}
        cmd = f"gfal-rm -t 300 {url}"
        result = subprocess.run(cmd, shell=True, timeout=320, encoding="utf-8",
                                capture_output=True, env=env)
        if result.returncode == 0 :
            return True
        elif result.returncode == 2 and "MISSING" in result.stdout :
            return False
        else :
            print(result.stdout)
            print(result.stderr)
            raise RuntimeError("Could not run gfal-rm")

        return False

    #
    #
    #

    def copy_file(self, file, location = 'tape', source = 'local',
                  effort = 1, secure = False, delete=False, overwrite=False):
        '''
        Copy to or among standard dCache locations.
        The dCache location is determined by the location
        and the file name.

        Parameters:
            file (str|MFile) : a file object containing at least
              the name, and local path if source='local'
            location (str) : location (tape (default),disk,scratch)
            effort (int 1-3) : (default=1) level of effort to make
            secure (bool) : (default=F) check the dcache result checksum
            delete (bool) : (default=F) delete the source file after copy
            overwrite (bool) : (default=F) overwrite the output file
        Raises:
            RuntimeError : dcache checksum does not match local checksum

        '''

        if isinstance(file,MFile) :
            mfile = file
        else :
            if source == 'local' :
                mfile = MFile(filespec=file)
            else :
                mfile = MFile(file)

        if source != 'local' :
            _pars.check_location(source)
        if location != 'local' :
            _pars.check_location(location)

        self.ready_gfal()

        self.ready_metacat()

        if source == 'local' :
            source_url = "file://" + mfile.filespec()
        else :
            source_url = mfile.url(location = source, schema = 'http')

        if location == 'local' :
            destination_url = "file://" + os.getcwd() + "/" + mfile.name()
        else :
            destination_url = mfile.url(location = location, schema = 'http')

        env = {"BEARER_TOKEN" : self.token}
        cmd = "gfal-copy --parent --timeout 1000"
        if overwrite :
            cmd = cmd + " --force "
        cmd = cmd + " " + source_url + " " + destination_url

        rc = 999
        for itry in range(effort) :
            time.sleep(5**itry - 1)

            if self.verbose > 0 :
                print(f"copy try {itry} {source_url} {destination_url}")
            result = subprocess.run(cmd, shell=True, timeout=1100,
                    encoding="utf-8", capture_output=True, env=env)
            if result.returncode == 0 :
                break
            else :
                print(f"Error running gfal-copy on try {itry}, output follows:")
                print(result.stdout)
                print(result.stderr)
            if itry >= effort - 1 :
                raise RuntimeError(f"Error exhausted retries while running gfal-copy {source_url} {destination_url}")


        if secure :

            adler32 = mfile.adler32()
            if not adler32 :
                if source == 'local' :
                    enstore, dcache = self.compute_crc(mfile.filespec())
                    adler32 = dcache
                else :
                    self.get_metadata(mfile)
                    adler32 = mfile.adler32()

            if not adler32 :
                raise runTimeError('Secure copy requested, but CRC not found '+mfile.name())
            dci = self.query_dcache(mfile.name(),location)

            remoteCRC = None
            # array of dicts
            for crcd in dci["checksums"]:
                if crcd['type'] == "ADLER32" :
                    remoteCRC = crcd['value']
                    break

            if remoteCRC != adler32 or adler32 == None :
                raise RuntimeError('dcache checksum does not match local checksum\n' + "    " + mfile.name()+" at "+location)


        if delete :
            self.gfal_rm_file(source_url)

        return


    #
    #
    #

    def check_dcache_file(self, mfile, location = 'tape'):
        '''
        Use gfal to check if a file exists in dCache

        Parameters:
            mfile (MFile) : a file object containing at least
              the name
            location (str) : location (tape (default),disk,scratch)

        '''

        self.ready_gfal()
        url = mfile.url(location = location, schema = "http")


        env = {"BEARER_TOKEN" : self.token}
        cmd = f"gfal-stat -t 300 {url}"
        result = subprocess.run(cmd, shell=True, timeout=320, encoding="utf-8",
                                capture_output=True, env=env)
        if result.returncode == 0 :
            return True
        elif result.returncode == 2 and "File not found" in result.stderr :
            return False
        else :
            print(result.stdout)
            print(result.stderr)
            raise RuntimeError("Could not run gfal-lstat")

        return True

    #
    #
    #

    def delete_dcache_file(self, file, location, force=False ):
        '''
        Use gfal to delete a file in dCache

        Parameters:
            file (str|MFile) : a file object or file name
            location (str) : location (tape, disk, scratch)
            force (bool) = (default=False) Do Not Raise on 404 error

        Returns:
            rc (int) : 0 or 404 (if force)

        '''

        if isinstance(file,MFile) :
            mfile = file
        else :
            mfile = MFile(name=file)

        _pars.check_location(location)

        self.ready_gfal()

        url = mfile.url(location = location, schema = "http")

        try:
            if self.dryrun :
                print("would delete ",url)
            else :
                self.gfal_rm_file(url)
        except Exception as e:
            message = str(e)
            if force :
                if message.find("File not found") >= 0 :
                    return 404
            raise

        return 0

    #
    #
    #

    def create_metacat_dataset(self, did, force=False) :
        '''
        create a new metacat dataset

        Parameters:
            did (str|MDataset) : a dataset object or dataset name
            force (bool) = (default=False) Do Not Raise on already exists

        Returns:
            rc (int) : 0 or 1 (if force and ds exists)

        '''


        if isinstance(did,MDataset) :
            ds = did
        else :
            ds = MDataset(did)

        if self.verbose > 0 :
            print("check/create metacat dataset",ds.did())

        self.ready_metacat()
        md = self.create_dataset_metadata(ds.did())
        if self.verbose > 1 :
            print("Creating metacat dataset with metadata: ")
            print(md)

        if self.dryrun :
            return 0

        try :
            self.metacat.create_dataset(ds.did(), metadata=md)
        except AlreadyExistsError as e :
            if self.verbose >0 :
                print("metacat dataset already exists :"+ds.did())
            if force :
                return 1
            raise
            #metacat.create_dataset(dsdid)

        return 0

    #
    #
    #


    def create_rucio_dataset(self, dataset, force=False ):
        '''
        Create a Rucio dataset

        Parameters:
            dataset (str|MDataset) : a dataset object or dataset name
            force (bool) = (default=False) Do Not Raise on already exists

        Returns:
            rc (int) : 0 or 2 for already exists (if force)

        '''

        if isinstance(dataset,MDataset) :
            ds = dataset
        else :
            ds = MDataset(dataset)

        if self.verbose > 0 :
            print(f"creating Rucio dataset {ds.did()}")

        if self.dryrun > 0 :
            print(f"would create Rucio dataset {ds.did()}")
            return 0

        rc = 0
        try :
            self.rucio.add_dataset(scope=ds.namespace(),name=ds.name())
        except DataIdentifierAlreadyExists as e:
            if self.verbose > 0 :
                print(f"found Rucio dataset already exists {ds.did()}")
            if force :
                rc = 2
            else :
                raise


        return rc

    #
    #
    #

    def delete_rucio_dataset(self, dataset, force=False ):
        '''
        INCOMPLETE - no dataset delete in Rucio

        Delete a Rucio dataset record

        Parameters:
            dataset (str|MDataset) : a dataset object or dataset name
            force (bool) = (default=False) do not raise if does not exist

        Returns:
            rc (int) : 0 or 2 for already exists (if force)

        '''

        print("delete Rucio dataset not implementd")

#        if isinstance(dataset,MDataset) :
#            ds = dataset
#        else :
#            ds = MDataset(dataset)
#
#
#        rc = 0
#        try :
#            self.rucio.add_dataset(scope=ds.namespace(),name=ds.name())
#        except DataIdentifierAlreadyExists as e:
#            if self.verbose > 0 :
#                print(f"found Rucio dataset already exists {ds.did()}")
#            if force :
#                rc = 2
#            else :
#                raise
#
#
        return 0


    #
    #
    #

    def locate_dataset(self, dataset, location='tape'):
        '''

        Add a dCache location (tape-backed, persistent) record in
        in the rucio database for a given dataset.  If the Rucio
        file records need to be created they will be, if the dataset
        record needs to be created, it will be, and any new files
        will be attached to the dataset.

        Parameters:
            dataset (str|MDataset) : dataset name or did
            location (str) : location (tape (default),disk,scratch,nersc)
        Raises :
             RunTimeError : Rucio has more files than metacat
        '''


        if isinstance(dataset, MDataset):
            ds = dataset
        else :
            ds = MDataset(dataset)

        if self.verbose > 0 :
            print(f"Starting locate dataset {ds.did()}")

        self.ready_metacat()
        self.ready_rucio()

        nfiles = self.metacat.get_dataset(ds.did())['file_count']
        if self.verbose > 0 :
            print(f"Found {nfiles} metacat files for dataset {ds.did()}")

        if nfiles == 0 :
            if self.verbose > 0 :
                print("No files to process")
            return


        rse = _pars.location(location,'rucio')
        dids = [{"scope":ds.namespace(), "name":ds.name()}]

        # make sure Rucio dataset exists, or create it
        self.create_rucio_dataset(ds,True)

        # collect all existing files attached to this dataset
        rfiles = []
        rfiles2 = [] # collect them rucio format
        for rfile in self.rucio.list_files(scope=ds.namespace(),
                                           name=ds.name()) :
            rfiles.append(rfile['name'])
            rfiles2.append({'scope' : ds.namespace() ,'name' : rfile['name']})

        nrfiles = len(rfiles)
        if self.verbose > 0 :
            print(f"Found {nrfiles} rucio records in this dataset")

        # files listed in this dataset, already with the request RSE
        # we want to simply call list_replicas with a dataset name,
        # but that has a bug so we need to call it with each file name
        rrfiles = []
        for split in self.chunker(rfiles2,1000):
            tempa = []
            qmore = True
            itry = 0
            # protection againt unstable Rucio server
            while qmore and itry < 5 :
                itry = itry + 1
                tempa.clear()
                try :
                    for rrfile in self.rucio.list_replicas(split,rse_expression=rse) :
                        if rrfile['rses'] != {} : # matched rse
                            tempa.append(rrfile['name'])
                    qmore = False
                except Exception as e :
                    print(f"caught list_replicas exception, itry={itry}",flush=True)
            if qmore :
                raise RuntimeError("rucio list_replicas failed after 5 tries"+ds.did())
            rrfiles.extend(tempa)

        nrrfiles = len(rrfiles)

        if self.verbose > 0 :
            print(f"Found {nrrfiles} rucio records in this dataset with location {location}")
        if nrrfiles == nfiles :
            if self.verbose > 0 :
                print(f"Locations are complete")
            return

        if nrfiles > nfiles :
            raise RuntimeError(f'Rucio file count {nrfiles} is larger than metacat count {nfiles}, repairs are required')

        if self.verbose > 0 :
            print("Setting locations on Rucio files")

        nrcre = 0
        dids = []   # list for creating files records
        attdids = [] # list for creating attachments of files to the dataset
        rdids = [] # list for creating RSE entries for files
        ncrec = 0
        ncrep = 0
        #print("DEBUG starting Rcuio list loop ",ds.did())
        for mcf in self.metacat.get_dataset_files(did = ds.did()) :

            filed = {'scope' : mcf['namespace'],
                     'name' : mcf['name'] }

            #print("DEBUG",mcf['name'],len(rrfiles))
            if mcf['name'] not in rrfiles :
                # file does not have replica for this RSE

                if 'checksums' in mcf :
                    adler32 = mcf['checksums'].get('adler32')
                if not adler32 :
                    raise RuntimeError('File missing adler32 checksum required by Rucio : '+mcf['name'])
                filei = {'scope' : mcf['namespace'],
                         'name' : mcf['name'],
                         'bytes' : mcf.get('size'),
                         'adler32' : adler32 }

                if mcf['name'] not in rfiles :
                    #print("DEBUG adding0 ")
                    # file does not have record
                    dids.append(filei) # files to create
                    attdids.append(filed) # and to append to dataset
                else :
                    #print("DEBUG adding1 ")
                    # files which exist but need RSE added
                    rdids.append(filei)


        ncrec = len(dids)
        ncrep = len(rdids)
        if self.verbose > 0 :
            print(f"Need to create {ncrec} new files with locations")
            print(f"Need to create {ncrep} locations for existing files")

        if ncrec > 0 :
            if self.verbose > 0 :
                print(f"Creating {ncrec} new files with locations")
            # do the bulk creation of file records
            if self.dryrun :
                print(f"would add {ncrec} new files with locations, and attach them to the dataset")
            else :
                for split in self.chunker(dids,500):

                    qmore = True
                    itry = 0
                    # protection againt unstable Rucio server
                    while qmore and itry < 5 :
                        itry = itry + 1
                        try:
                            self.rucio.add_replicas(rse = rse, files = split)
                            qmore = False
                        except Exception as e :
                            print(f"caught add_replicas exception, itry={itry}",flush=True)
                    if qmore :
                        raise RuntimeError('rucio add_replicas1 failed after 5 tries : '+ds.did())


                # attach the file records to a dataset
                for split in self.chunker(attdids,500):
                    self.rucio.attach_dids( scope = ds.scope(),
                                            name = ds.name(),
                                            dids = split)
        if ncrep > 0 :
            if self.verbose > 0 :
                print(f"Adding replica {rse} to {ncrep} files")
            if self.dryrun :
                print(f"would add {ncrep} replica {rse} records to files")
            else :
                for split in self.chunker(rdids,500):

                    qmore = True
                    itry = 0
                    # protection againt unstable Rucio server
                    while qmore and itry < 5 :
                        itry = itry + 1
                        try:
                            self.rucio.add_replicas(rse = rse, files = split)
                            qmore = False
                        except Exception as e :
                            print(f"caught add_replicas exception, itry={itry}",flush=True)

                    if qmore :
                        raise RuntimeError('rucio add_replicas2 failed after 5 tries : '+ds.did())

        if self.verbose > 0 :
            print(f"Finished locations for "+ds.did())

        return


    #
    #
    #

    def delete_rucio_replica(self, dataset, files, location, force=False ):
        '''
        Delete a Rucio file replica

        Parameters:
            dataset (str|MDataset) : a dataset object or dataset name
            files (str|list) = file names to delete replica
            location (str) : standard location (tape, disk, scratch)
            force (bool) = (default=False) Do Not Raise on file does not exist

        Returns:
            rc (int) : 0 or 2 for already exists (if force)

        '''

        if isinstance(dataset,MDataset) :
            ds = dataset
        else :
            ds = MDataset(dataset)

        self.ready_rucio()

        rse = _pars.location(location,'rucio')
        dids = [{"scope":ds.namespace(), "name":ds.name()}]

        rrfiles = []
        for rrfile in self.rucio.list_replicas(dids,rse_expression=rse) :
            rrfiles.append(rrfile['name'])

        gfiles = []
        for file in files :
            if isinstance(file,MFile) :
                mf = file
            else :
                mf = MFile(file)
            if mf.name() in rrfiles :
                filed = {'scope' : mf.namespace(),
                         'name' : mf.name() }
                gfiles.append(filed)

        if self.verbose >0 or self.dryrun :
            print(f'delete replica: {len(files)} input files,\n   {len(rrfiles)} file in locations dataset, {len(gfiles)} overlap')

        if self.dryrun :
            print("would remove {len(gfiles)} files from {location} location")
        else :
            if self.verbose >1 :
                print("deleting replicas ",rse,gfiles)
            for split in self.chunker(gfiles,500):
                self.rucio.delete_replicas(rse = rse, files = split)

        return

    #
    #
    #

    def create_rucio_rule(self, dataset, location=None, force=False ):
        '''
        Create a Rucio dataset+location rule

        Parameters:
            dataset (str|MDataset) : a dataset object or dataset name
            location (str) : location (tape,disk,scratch).
            force (bool) = (default=False) Do Not Raise on already exists

        Returns:
            rc (int) : 0 or 2 for already exists (if force)

        '''

        if isinstance(dataset,MDataset) :
            ds = dataset
        else :
            ds = MDataset(dataset)

        dids = [{"scope":ds.namespace(), "name":ds.name()}]
        rse = _pars.location(location,'rucio')

        if self.dryrun :
            print("Would create rule for "+ds.did()+" and "+rse)
            return 0

        rc = 0
        try :
            if self.verbose > 0 :
                print("adding replica rule",ds.did(),rse)
                self.rucio.add_replication_rule(dids, 1, rse)
        except DuplicateRule as e :
            if self.verbose > 0 :
                print("found rule already exists ")
            if force :
                return 2
            else :
                raise


    #
    #
    #

    def delete_rucio_rule(self, dataset, location=None, force=False ):
        '''
        Delete a Rucio dataset+location rule

        Parameters:
            dataset (str|MDataset) : a dataset object or dataset name
            location (str) : location (tape,disk,scratch).
            force (bool) = (default=False) Do Not Raise on does not exists

        Returns:
            rc (int) : 0 or 2 for does not exist (if force)

        '''

        if isinstance(dataset,MDataset) :
            ds = dataset
        else :
            ds = MDataset(dataset)

        dids = [{"scope":ds.namespace(), "name":ds.name()}]
        rse = _pars.location(location,'rucio')


        filters={'scope':ds.scope(), 'name': ds.name(),
                 'rse_expression' : rse}

        rules = list( self.rucio.list_replication_rules(filters) )
        if len(rules) > 1 :
            print(rules)
            raise RuntimeError(f'Found {len(rules)} rules, only one expected')
        elif len(rules) == 0 :
            if self.verbose > 0 :
                print("Did not find rule for {ds.did()} at {location}")
            if force :
                return 2
            else :
                raise RuntimeError(f'Did not find rule to delete for {ds.did()} at {location}')

        rule_id = rules[0]['id']

        if self.verbose > 0 :
            print(f"Unlocking replica rule for {ds.did()} at {location}")
        options = {'locked': False}
        if self.dryrun :
            print(f"Would unlock rule for {ds.did()} and {rse}")
        else :
            self.rucio.update_replication_rule(rule_id, options)

        if self.verbose > 0 :
            print(f"Removing replica rule for {ds.did()} at {location}")

        if self.dryrun :
            print(f"Would delete rule for {ds.did()} and {rse}")
        else :
            self.rucio.delete_replication_rule(rule_id)


    #
    #
    #

    def delete_files(self, files, location=None, catalog=False, dcache=False,
                     replica=False, force=False):
        '''

        Delete files and records.

        Parameters:
            files (list[str]) : list of file names
            location (str) : location (tape,disk,scratch,nersc)
            catalog (bool) : remove file catalog record
            dcache (bool) : remove physical file in dcache
            replica (bool) : remove location record
        Raises :
             RunTimeError : inconsistent flags
        '''


        if self.verbose > 0 or self.dryrun :
            print("location:",location)
            print("delete physical files in dcache:",dcache)
            print("delete location records:",replica)
            print("delete file catalog records:",catalog)
            print(f"processing {len(files)} files")

        if (dcache or replica) and not location :
            raise RunTimeError("explicit location required for dcache or replica")

        for file in files :
            if self.verbose > 1 or self.dryrun :
                print("processing "+file)
            if dcache :
                if self.dryrun :
                    print("    delete file in {location} location")
                else :
                    self.delete_dcache_file(file,location,force)
            if replica :
                if self.dryrun :
                    print(f"    delete {location} replica record")
                else :
                    mfile = MFile(file)
                    self.delete_rucio_replica(mfile.default_dataset(),[file],location,force)
            if catalog :
                if self.dryrun :
                    print("    delete file catalog record")
                else :
                    self.retire_metacat_file(file,force)

    #
    #
    #

    def prestage_files(self, flist, monitor=False):
        '''

        Use data dispatcher to prestage a dataset by requesting all files

        Parameters:
            flist (list(str)) : the list of files to prestage
            monitor (bool) : T = skip pin commands, just check on disk

        '''


        nfile = len(flist)
        if self.verbose > 0 :
            print(f"working on {nfile} files")

        if self.dryrun > 0 :
            print(f"would work on {nfile} files")
            return

        filedl = []
        fstatus = []
        for fn in flist :
            mfile = MFile(name=fn)
            path = mfile.url() # tape path
            path = path[5:] # strip /pnfs
            filedl.append(path)
            fstatus.append({'name':mfile.name(),'staged':False})


        if monitor :
            if self.verbose > 0 :
                print(f"skip prestage calls")
        else :
            if self.verbose > 0 :
                print(f"start prestage calls")
            split = 1000 # anticpating threads
            stage_url = "https://fndcadoor.fnal.gov:3880/api/v1/namespace"
            datad={"action" : "pin", "lifetime" : "14", "lifetime-unit" : "DAYS"}
            files = []
            for ifile,filed in enumerate(filedl) :
                files.append(filed)
                if (ifile > 0 and ifile%split == 0) or ifile == nfile-1 :
                    # process chunk
                    # refresh token here since full list can take more than 1h
                    token = self.get_token()
                    header={ 'Authorization' : "Bearer " + token }
                    for file in files:
                        url = stage_url+file
                        response = requests.post(url, headers=header,
                                     json=datad, verify=False)

                        if (self.verbose >1 and ifile < 5) or self.verbose >2:
                            print("call dcache prestage url")
                            print("stage_url",url)
                            print("header",header)
                            print("datad",datad)
                            print("response",str(response))
                            print("response text",response.text)
                    if self.verbose > 0 :
                        nows = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        print(f"{nows} prestaging calls: {ifile+1}",flush=True)
                    files = []



        nstaged = 0
        while nstaged < nfile :
            self.ready_metacat()
            nstaged = 0
            nunstaged = 0
            ifile = 0
            while ifile < nfile and nunstaged < 20 :
                fst = fstatus[ifile]
                if fst['staged'] :
                    nstaged = nstaged + 1
                else :
                    dd = self.query_dcache(file_name=fst['name'])
                    if "ONLINE" in dd["fileLocality"] :
                        nstaged = nstaged + 1
                        fst['staged'] = True
                    else :
                        nunstaged = nunstaged + 1
                ifile = ifile + 1

            if self.verbose :
                nows = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                percent = int(100*nstaged/(nstaged+nunstaged))
                print(f"{nows} {percent:3d}% staged",flush=True)
            if nunstaged > 0 :
                time.sleep(100)


        return


    #
    #
    #

    def verify_dataset(self, dataset, options=[] ):
        '''

        Check the metacat and Rucio records for a dataset.
        Also check a single file in dCache.

        output is like
           s    1   -    143    0  rlc:etc.rlc.dh_test.2024.log
           status word : tds (tape, disk, scratch) for real file locations
                         TDS for Rucio replica entries
           number of metacat files
           number of Rucio files
           total bytes
           total events
           dataset name

        Parameters:
            dataset (str|MDataset) : dataset name or did

        Returns:
            report (dict) : containing the report numbers.
                       report['summary'] is a summary str

        Raises:
            runTimeError : dataset not found in metacat

        '''


        self.ready_metacat()
        self.ready_rucio()

        if isinstance(dataset,MDataset) :
            ds = dataset
        else :
            ds = MDataset(dataset)

        dd = self.metacat.get_dataset(did = ds.did())
        if not dd :
            raise RuntimeError('dataset not found in metacat : '+ds.did())

        report = {}
        report['dataset'] = ds.did()

        # this is running the file list generator once
        mfile = None
        nfiles = 0
        totalb = 0
        totalev = 0
        for fi in self.metacat.get_dataset_files(did = ds.did(),
                                                 with_metadata=True) :
            nfiles = nfiles + 1
            # example file
            if not mfile :
                mfile = MFile(namespace=fi['namespace'],name=fi['name'])
            if 'size' in fi :
                totalb = totalb + fi['size']
            md = fi.get('metadata')
            if md :
                if 'rse.nevent' in md :
                    totalev = totalev + md['rse.nevent']

        report['metacat_nfiles'] = nfiles

        report['total_bytes'] = totalb
        report['total_events'] = totalev
        if mfile :
            report['example_file'] = mfile.did()
        else :
            report['example_file'] = None

        if self.verbose > 0 :
            print("Example file:",report['example_file'])


        nrfiles = 0
        rexists = True
        try :
            for rfile in self.rucio.list_files(scope=ds.namespace(),
                                               name=ds.name()) :
                nrfiles = nrfiles + 1
        except DataIdentifierNotFound as e :
            rexists = False

        report['rucio_nfiles'] = nrfiles

        if self.verbose > 0 :
            print("Checking locations in Rucio")

        rlocs = []
        if rexists and mfile:
            dids = [{"scope":mfile.namespace(), "name":mfile.name()}]
            for rr in self.rucio.list_replicas(dids=dids) :
                for rse in rr['rses'].keys() :
                    rlocs.append(_pars.loc_from_rse(rse))

        report['rucio_locations'] = rlocs

        if self.verbose > 0 :
            print("Check for physical files in dCache")

        status = ""

        report['dcache_locations'] = []
        for loc in ["tape","disk","scratch"] :
            if loc in rlocs :
                status = status + loc[0].upper()
            exists = False
            if mfile :
                exists = self.check_dcache_file(mfile,loc)
            if exists :
                if self.verbose > 0 :
                    print("exists in "+loc)
                status = status + loc[0]
                report['dcache_locations'].append(loc)

        if not status :
            status ="-"
        status = status.rjust(10)
        if rexists :
            rstatus=f'{nrfiles:7d}'
        else :
            rstatus = "-"
        rstatus = rstatus.rjust(7)

        summary=f'{status} {nfiles:7d} {rstatus} {totalb:22,d} {totalev:15,d}  {ds.did()}'
        report['summary'] = summary

        return report

    #
    #
    #

    def upload_grid_log(self, fn):
        '''

        Create a log file from $JSB_TMP/JOBSUB_LOG_FILE and JOBSUB_LOG_FILE
        This will work on all know grid jobs, but
        obviously has to be setup to work locally
        It will create the file in the default directory

        Parameters:
            fn (str) : the name of the output log file

        Raises:
            runTimeError : fails to find input logs or write output

        '''

        if not fn :
            raise runTimeError("no output log file name")

        # this is usually set in grid jobs
        jdir = os.environ.get("JSB_TMP")
        if not jdir :
            # default here since this is usually where they are
            # this might also be true in local recoveries
            jdir = "jsb_tmp"

        fout = jdir+"/JOBSUB_LOG_FILE"
        ferr = jdir+"/JOBSUB_ERR_FILE"

        if not os.path.exists(fout) :
            raise runTimeError("could not find log file " + fout)
        if not os.path.exists(ferr) :
            raise runTimeError("could not find log file " + ferr)

        with open(fn,"w") as f:
            with open(fout) as jf:
                line = jf.readline()
                while line :
                    f.write(line)
                    line = jf.readline()
            jf.close()
            f.write("\n")
            f.write("************************* JOBSUB_ERR *********************\n")
            f.write("\n")
            with open(ferr) as jf:
                line = jf.readline()
                while line :
                    f.write(line)
                    line = jf.readline()
        return


    #
    #
    #

    def upload_grid_tagclean(self, mfile):
        '''
        Look for files from a previous upload attempt and retire them
        The files will have the given name, but with an earlier
        time stamp appended to the sequencer

        '''
        #self.metacat.retire_metacat_file(self, file, force=False):

        did = mfile.default_dataset_did()
        # the file here will be the new tagged name t.o.d.c.s-tag.e
        # so extract the sequencer before the tag
        seq = '-'.join(mfile.sequencer().split('-')[0:-1])
        query = 'files from '+did+  \
          ' where fn.sequencer ~ "'+seq+'-"'
        if self.verbose > 0 :
            print("querying old tag files ",query)
        flist = self.metacat.query(query)
        for ff in flist:
            odid = ff['namespace']+':'+ff['name']
            if self.verbose > 0 :
                print("Retiring old tag file ",odid)
            self.metacat.retire_file(did=odid)

#         cmd = self.metacat.get_file(name=mfile.name(),
#                                    namespace=mfile.namespace(),
#                                    with_metadata = True,
#                                    with_provenance=False,
#                                    with_datasets=False)

        return

    #
    #
    #

    def upload_grid(self, manifest, app=None, mode="overwrite"):
        '''

        NOT IMPLEMENTED

        rows in the manifest or file to upload:

        localfile , rse , parents , json , newname

        lines that start with "#" are comments and ignored
        if localfile is empty and rename is *.log, then create
        log file out of condor logs (recommended)
        log files should be last in the list to capture as much
        as possible.

        Parameters:
            manifest (str) : text file containing the list of
                 files to transfer (sse above for format

        Raises:
            runTimeError : fail to find or interpret manifest
            runTimeError : MOO_CONFIG requested but not found
            runTimeError : fail to find file names in manifest

        '''

        if self.verbose > 0 :
            print('['+time.ctime()+'] Starting upload grid')

        appFamily = None
        appName = None
        appVersion = None
        if app=='moo_config':
            if not 'MOO_CONFIG' in os.environ :
                raise runTimeError("app switch requests MOO_CONFIG but not in evironment")
            appFamily = "Production"
            config = os.environ['MOO_CONFIG']
            appName = config.split("-")[0]
            appVersion = "-".join(config.split("-")[1:])

        timestr = str(int(time.time()))

        if self.verbose > 0 :
            print("  manifest = ", manifest)
            print("  appFamily = ", appFamily)
            print("  appName = ", appName)
            print("  appVersion = ", appVersion)
            print("  time_tag = ", timestr)

        self.ready_metacat()

        # read the manifest file and process each file in turn
        with open(manifest) as fman:
            line = fman.readline()
            while line :
                if line[0] == '#':
                    line = fman.readline()
                    continue

                if self.verbose > 0 :
                    print('['+time.ctime()+'] Starting "'+line+'"')

                aa = line.split(',')
                localfile = aa[0].strip()
                dest = aa[1].strip()

                # check for valid location str
                _pars.location(dest,'prefix')
                if len(aa) > 2 :
                    parentsFile = aa[2].strip()
                else :
                    parentsFile = None
                if len(aa) > 3 :
                    jsonfile = aa[3].strip()
                else :
                    jsonfile = None
                newname = aa[0].strip()
                if len(aa) > 4 :
                    newname = aa[4].strip()

                # log file trigger
                isLogFile = False
                if not localfile :
                    newext = newname.split('.')[-1]
                    if newext == 'log' :
                        # create the local log file out of the
                        # the condor logs on the grid node
                        if self.verbose > 0 :
                            print('['+time.ctime()+'] Creating log file')
                        self.upload_grid_log(newname)
                        localfile = newname
                        isLogFile = True
                    else :
                        raise runTimeError('local file not found in line "'+line+'"')
                else :
                    if not os.path.exists(localfile) :
                        raise runTimeError('local file not found in line "'+line+'"')

                if mode == "tag" or mode == "tagclean" or isLogFile :
                    # files gain a time stamp at end of sequencer
                    # log files always do
                    aa = newname.split(".")
                    aa[4] = aa[4]+"-"+timestr
                    newname = ".".join(aa)

                # mv the file if it needs to be renamed
                if newname :
                    if jsonfile :
                        raise RunTimeError("Request for file rename but json file provided (inconsistent)")
                    fs = os.path.abspath(localfile)
                    fd = os.path.dirname(fs)
                    newlocalfile = fd+"/"+newname
                    os.rename(localfile,newlocalfile)
                    localfile = newlocalfile

                if not os.path.exists(localfile) :
                    raise runTimeError('local file not found in line "'+line+'"')
                mfile = MFile(filespec=localfile)

                # at this point, localfile exists and renamed, get metadata
                if jsonfile :
                    # if json is provided, read metadata
                    if not os.path.exists(jsonfile) :
                        raise runTimeError('json file not found in line "'+line+'"')
                    with open(jsonfile) as fjson:
                        text = fjson.read()
                    catmd = json.loads(text)
                else :
                    # need to be make metadata content
                    catmd = self.create_metadata(mfile, parents = parentsFile,
                                            appFamily = appFamily,
                                            appName = appName,
                                            appVersion = appVersion)

                mfile.add_catmetadata(catmd)

                if mode == "tagclean" and not isLogFile :
                    # remove earlier files with different time tags
                    # we keep all previous log files
                    self.upload_grid_tagclean(mfile)

                # copy file, with forced overwrites
                if self.verbose > 0 :
                    print('['+time.ctime()+'] Starting copy '+mfile.did())

                # whether output file can be overwritten
                ow = False
                if mode=="overwrite" :
                    ow = True

                self.copy_file(mfile, location=dest, source='local',
                    effort=3, secure=True, delete=False, overwrite=ow)

                if self.verbose > 0 :
                    print('['+time.ctime()+'] Starting declare '+mfile.did())

                # declare file, with overwrites set by mode
                self.declare_file(mfile,force=ow, delete=False,
                                  overwrite=ow)

                # repeat with the next line in the file
                line = fman.readline()
