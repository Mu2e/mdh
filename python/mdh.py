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

import gfal2

from metacat.webapi import MetaCatClient
from metacat.common.auth_client import AuthenticationError

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
                          "rucio":"FNAL_ENSTORE"},
            "disk" :    { "prefix":"/pnfs/mu2e/persistent/datasets",
                          "sam":"dcache",
                          "rucio":"FNAL_DCACHE_PERSISTENT"},
            "scratch" : { "prefix":"/pnfs/mu2e/scratch/datasets",
                          "sam":"dcache",
                          "rucio":"FNAL_DCACHE_SCRATCH"},
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

    def check_did(self, did, qfile=True):
        '''
        Check file name for the right number of fields, and allowed
        chars, data_tiers, and file_types

        Parameters:
            fileName (str) : the base file name
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

        if len(fields) != nFields:
            raise RuntimeError(f'"did" did not have {nFields} fields: {did}')

        pat = re.compile('[a-zA-Z0-9_-]+')

        for field in fields:
            if len(field) == 0 :
                raise RuntimeError('file name has empty field: '+did)
            if not re.fullmatch(pat,field) :
                raise RuntimeError('file name contains bad characters: '+did)

        if not re.fullmatch(pat,field) :
            raise RuntimeError('file name contains bad characters: '+did)

        if fields[0] not in self.file_families :
            raise RuntimeError('file name contains unknown tier: '+did)

        if fields[nFields-1] not in self.file_formats :
            raise RuntimeError('file name contains unknown format: '+did)

        return

#
# create the single global instance of MParameters
#
_pars = MParameters()

#
#
#
class MDataset :
    def __init__(self, name = None, namespace = None,
                 catmetadata = None, standard = True) :
        if name :
            if ':' in name :
                self.ds = name.split(':')[1]
            else :
                self.ds = name
        else :
            self.ds = None

        if namespace :
            self.ns = namespace
        elif self.ds :
            # default namespace is the owner field of the dataset name
            self.ns = self.ds.split('.')[1]

        self.catmd = catmetadata

        # use the gloabl MParameters to check name structure
        if standard :
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
        return self.ds.split('.')[0]
    def owner(self) :
        return self.ds.split('.')[1]
    def description(self) :
        return self.ds.split('.')[2]
    def configuration(self) :
        return self.ds.split('.')[3]
    def format(self) :
        return self.ds.split('.')[5]

    def files(self) :
        return self.file_list

    def catmetadata(self) :
        return self.catmd


#
#
#
class MFile :
    def __init__(self, name = None, namespace = None,
                 localpath = None, filespec = None, catmetadata = None) :
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
            self.ns = self.fn.split('.')[1]

        if localpath :
            self.lp = localpath
        elif filespec :
            self.lp = os.path.dirname(filespec)
        else :
            self.lp = os.getcwd()

        self.catmd = catmetadata

        #self.check_file_name(self.fn)
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

    def user_type(self) :
        if self.owner() == "mu2e" :
            return "prod"
        else :
            return "user"

    def localpath(self) :
        return self.lp
    def filespec(self) :
        return self.localpath() + '/' + self.name()
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
    Mu2e custom data-handling commands based on metacat and Rcuio.
    These command simplify the user commands and implement and
    enforce mu2e conventions
    '''

    def __init__(self) :
        # don't renew token or proxy too often
        self.renew_time = 600
        self.last_token_time = 0
        self.last_proxy_time = 0
        self.token = ""
        self.proxy = ""
        # require less than this time left in authorization before
        # attempting a re-authorized operation
        self.auth_time_left = 600
        self.metacat = MetaCatClient()
        # RucioClient reads X509 proxies when it is created, so
        # delay creation until there is a request for a Rucio action
        self.rucio = None
        # gfal command parameters
        self.ctx = gfal2.creat_context()
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
        if self.verbose > 0 :
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

        try :
            auser, etime = self.metacat.auth_info()
            time_left = etime - ctime
            if time_left > self.auth_time_left :
                if self.verbose > 0 :
                    print("time left in metacat auth:",time_left)
                return time_left
        except AuthenticationError as e :
            # no token yet, make one below
            pass

        token = self.get_token()

        if 'GRID_USER' in os.environ :
            user = os.environ['GRID_USER']
        elif 'USER' in os.environ :
            user = os.environ['USER']
        else :
            raise RuntimeError('Could not find username for metacat')

        if self.verbose > 0 :
            print("renewing metacat auth")
        auser,etime = self.metacat.login_token(user,token)
        time_left = etime - ctime

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
    #                self.__ctx.set_opt_string('X509', 'CERT', proxy)
    #                self.__ctx.set_opt_string('X509', 'KEY', proxy)

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
        self.ctx.set_opt_string('BEARER', 'TOKEN', token)

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
                flist.append(item)
            else :
                ds = MDataset(item,standard=False)

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

    def retire_metacat_file(self, file, dnr=False):
        '''

        Retire a file in the metacat database

        Parameters:
            mfile (str|MFile) : a file name or object containing the file name
            dnr (bool) : (default=F) do not raise if file not
                  available or already retired

        '''

        if isinstance(file,MFile) :
            mf = file
        else :
            mf = MFile(file)

        self.ready_metacat()
        if self.verbose > 1 :
            print("retiring"+mf.did())

        # retire file does not throw if file is already retired
        self.metacat.retire_file(did=mf.did())

        return

    #
    #
    #

    def compute_crc(self, filespec):
        '''
        Compute the enstore and dcache CRC values for a local file.
        This returns both enstore,dcache sums as ints
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

    def dcache_info(self, file_name=None, location="tape"):
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
            mf = MFile(localpath=file_name)
        file_spec = mf.url(location)

        # strip the "/pnfs" from the file path to make the url
        url = "https://fndcadoor.fnal.gov:3880/api/v1/namespace/" \
              + file_spec[5:] \
              + "?checksum=true&locality=true&xattr=true&optional=true"

        token = self.get_token()

        header={ 'Authorization' : "Bearer " + token }

        response = requests.get(url,headers=header,
                                verify="/etc/grid-security/certificates")

        if response.status_code == 404 :
            raise RuntimeError("File not found in dCache")
        elif response.status_code != 200 :
            response.raise_for_status()

        return json.loads(response.text)


    #
    #
    #

    def declare_file(self, file):
        '''

        Create a file record in metacat using the information in mfile.
        Associate the file with its default dataset. If the default
        dataset does not exist, it will also be created.

        Parameters:
            mfile (MFile) : file object with name, namespace, metacat file
                attibutes (crc and size) and mu2e metadata dictionary

        Returns:
            catmetadata (dict) : the file catmetadata as a dictionary

        '''

        if isinstance(file,MFile) :
            mfile = file
        else :
            mfile = MFile(file)

        self.ready_metacat()

        dsdid = mfile.default_dataset_did()

        print("checking metacat ds ",dsdid)
        if not self.metacat.get_dataset(did=dsdid) :
            print("ds not found, create it")
            md = self.create_dataset_metadata(dsdid)
            print(md)
            self.metacat.create_dataset(dsdid, metadata=md)
            #metacat.create_dataset(dsdid)
        else :
            print("ds found, declare file")
            self.metacat.declare_file(did = mfile.did(),
                                 dataset_did = dsdid,
                                 size = mfile.catmetadata()['size'],
                                 checksums = mfile.catmetadata()['checksums'],
                                 parents = mfile.catmetadata().get('parents'),
                                 metadata = mfile.metadata())

        return


    #
    #
    #

    def create_dataset_metadata(self, did) :
        '''
        '''
        dsn = did.split(':')[1]
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

    def create_metadata(self, mfile, parents=None,
                        appFamily=None,appName=None,appVersion=None,
                        declare=False, ignore=False):
        '''
        Create a dictionary of the catmetadata for a file

        Parameters:
            mfile (MFile) : the file to be processed, must include filespec
            parents (str or list(str)) : the parent files, a str of files separated
                by commas, or as a list of 'did' file names (default=None)
            appFamily (str) : file processing record family (default=None)
            appName (str) : file processing record name (default=None)
            appVersion (str) : file processing record version (default=None)
            declare (bool) : if true, also declare the file in metacat
            ignore (bool) : if true, do not read genCount product

        Returns:
            info (dictionary) : the file metadata as a dictionary

        Throws:
            FileNotFoundError : for source file not found
            ValueError : for bad file names
            RuntimeError : could not extract metadata

        '''

        # general metacat metadata, also called "attributes"
        catmetadata = {}

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
        metadata["fn.confguration"] = mfile.configuration()
        metadata["fn.sequencer"] = mfile.sequencer()
        metadata["fn.format"] = mfile.format()
        if appFamily :
            metadata["app.family"] = appFamily
        if appName :
            metadata["app.name"] = appName
        if appVersion :
            metadata["app.version"] = appVersion

        if mfile.format() == "art" :
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
                    metadata["gen.count"] = int(line.split()[2])

                if line[0:18] == "end RunSubrunEvent" :
                    inText = False
                if inText :
                    ss = line.split()
                    if ss[0]=='rse.runs' :
                        srlist = [ int(sr) for sr in ss[1:] ]
                        metadata[ss[0]] = srlist
                    else :
                        metadata[ss[0]] = int(ss[1])
                if line[0:20] == "start RunSubrunEvent" :
                    inText = True

        stats = os.stat(mfile.filespec())
        catmetadata["size"] = stats.st_size

        enstore,dcache = self.compute_crc(mfile.filespec())
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
            self.declare_file(mfile)
        return catmetadata

    #
    #
    #

    def copy_file(self, file, location = 'tape', source = 'local',
                  effort = 1, secure = False):
        '''
        Copy a local file to a standard dCache location.
        The dCache location is determined by the file name.

        Parameters:
            file (str|MFile) : a file object containing at least
              the name, and local path if source='local'
            location (str) : location (tape (default),disk,scratch)
            effort (int) : (default=1) level of effort to make
            secure (bool) : (default=F) check the dcache result checksum
        Raises:
            RuntimeError : dcache checksum does not match local checksum

        '''

        if not isinstance(file,MFile) :
            if source == 'local' :
                mfile = MFile(filespec=file)
            else :
                mfile = MFile(file)

        if source != 'local' :
            _pars.check_location(source)
        if location != 'local' :
            _pars.check_location(location)

        self.ready_gfal()

        params = self.ctx.transfer_parameters()
        params.overwrite = False
        params.create_parent = True
        params.set_checksum = False
        params.timeout = 300

        self.ready_metacat()

        if source == 'local' :
            source_url = "file://" + mfile.filespec()
        else :
            source_url = mfile.url(location = source, schema = 'http')

        if location == 'local' :
            print("DEB ",mfile.filespec(),mfile.name())
            destination_url = "file://" + mfile.filespec()
        else :
            destination_url = mfile.url(location = location, schema = 'http')

        #print("local_url ",local_url)
        #print("dcache_url ",dcache_url)

        rc = 999
        for itry in range(effort) :
            time.sleep(5**itry - 1)

            try:
                rc = self.ctx.filecopy(params, source_url, destination_url)
                # if this didn't raise, then break out of retries
                break
            except Exception as e:
                rc = 1
                # gfal only raises generic errors, so have to parse the text
                message = str(e)
                # if the output file already exists, then quit with error
                if "file exists" in message :
                    raise
                if itry == effort - 1 :
                    raise

        # if we get here, there was no error raised

        if not secure :
            return

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
        dci = self.dcache_info(mfile.name(),location)

        remoteCRC = None
        # array of dicts
        for crcd in dci["checksums"]:
            if crcd['type'] == "ADLER32" :
                remoteCRC = crcd['value']
                break

        if remoteCRC != adler32 or adler32 == None :
            raise RuntimeError('dcache checksum does not match local checksum\n' + "    " + mfile.name()+" at "+location)

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
        Raises:
            RuntimeError : dcache checksum does not match local checksum

        '''

        self.ready_gfal()
        url = mfile.url(location = location, schema = "http")

        params = self.ctx.transfer_parameters()
        params.timeout = 300

        try :
            #self.ctx.listdir(params, url)
            self.ctx.lstat(url)
        except Exception as e :
            #print(str(e))
            return False

        return True

    #
    #
    #

    def check_dcache_file_whatisthis(self, mfile, location = 'tape'):
        '''
        Use gfal to check if a file exists in dCache

        Parameters:
            mfile (MFile) : a file object containing at least
              the name
            location (str) : location (tape (default),disk,scratch)
        Raises:
            RuntimeError : dcache checksum does not match local checksum

        '''
    #
    #
    #

    def delete_dcache_file(self, file, location, dnr=False ):
        '''
        Use gfal to delete a file in dCache

        Parameters:
            file (str|MFile) : a file object or file name
            location (str) : location (tape, disk, scratch)
            dnr (bool) = (default=False) Do Not Raise on 404 error

        Returns:
            rc (int) : 0 or 404 (if dnr)

        '''

        if isinstance(file,MFile) :
            mfile = file
        else :
            mfile = MFile(filespec=file)

        _pars.check_location(location)

        self.ready_gfal()

        url = mfile.url(location = location, schema = "http")

        try:
            if self.dryrun :
                print("would delete",url)
            else :
                self.ctx.unlink(url)
        except Exception as e:
            message = str(e)
            if dnr :
                if message.find("File not found") >= 0 :
                    return 404
            raise

        return 0

    #
    #
    #

    def create_rucio_dataset(self, dataset, dnr=False ):
        '''
        Create a Rucio dataset

        Parameters:
            dataset (str|MDataset) : a dataset object or dataset name
            dnr (bool) = (default=False) Do Not Raise on already exists

        Returns:
            rc (int) : 0 or 2 for already exists (if dnr)

        '''

        if isinstance(dataset,mDataset) :
            ds = dataset
        else :
            ds = MDataet(dataset)


        rc = 0
        try :
            self.rucio.add_dataset(scope=ds.namespace(),name=ds.name())
        except DataIdentifierAlreadyExists as e:
            if self.verbose > 0 :
                print(f"found Rucio dataset already exists {ds.did()}")
            if dnr :
                rc = 2
            else :
                raise


        return rc

    #
    #
    #

    def delete_rucio_dataset(self, dataset, dnr=False ):
        '''
        Delete a Rucio dataset record

        Parameters:
            dataset (str|MDataset) : a dataset object or dataset name
            dnr (bool) = (default=False) Do Not Raise on already exists

        Returns:
            rc (int) : 0 or 2 for already exists (if dnr)

        '''

        print("not implemetd")

        if isinstance(dataset,mDataset) :
            ds = dataset
        else :
            ds = MDataet(dataset)


        rc = 0
        try :
            self.rucio.add_dataset(scope=ds.namespace(),name=ds.name())
        except DataIdentifierAlreadyExists as e:
            if self.verbose > 0 :
                print(f"found Rucio dataset already exists {ds.did()}")
            if dnr :
                rc = 2
            else :
                raise


        return rc

    #
    #
    #

    def delete_rucio_replica(self, dataset, files, location, dnr=False ):
        '''
        Delete a Rucio dataset record

        Parameters:
            dataset (str|MDataset) : a dataset object or dataset name
            files (str|list) = file names to delete replica
            location (str) : standard location (tape, disk, scratch)
            dnr (bool) = (default=False) Do Not Raise on file does not exist

        Returns:
            rc (int) : 0 or 2 for already exists (if dnr)

        '''

        if isinstance(dataset,mDataset) :
            ds = dataset
        else :
            ds = MDataet(dataset)

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
                gfile.append(filed)

        if self.verbose >0 or self.dryrun :
            print(f'delete replica: {len(files)} input files,\n   {len(rrfiles)} file in locations dataset, {len(gfiles)} overlap')

        if self.dryrun :
            print("would remove {len(gfiles)} files from {location} location")
        else :
            self.rucio.delete_replicas(rse = rse, files = gfiles)

        return

    #
    #
    #

    def create_rucio_rule(self, dataset, location=None, dnr=False ):
        '''
        Create a Rucio dataset+location rule

        Parameters:
            dataset (str|MDataset) : a dataset object or dataset name
            location (str) : location (tape,disk,scratch).
            dnr (bool) = (default=False) Do Not Raise on already exists

        Returns:
            rc (int) : 0 or 2 for already exists (if dnr)

        '''

        if isinstance(dataset,mDataset) :
            ds = dataset
        else :
            ds = MDataet(dataset)

        dids = [{"scope":ds.namespace(), "name":ds.name()}]
        rse = _pars.location(location,'rucio')

        rc = 0
        try :
            if self.verbose > 0 :
                print("adding replica rule",ds.did(),rse)
            self.rucio.add_replication_rule(dids, 1, rse)
        except DuplicateRule as e :
            if self.verbose > 0 :
                print("found rule already exists ")
            if drn :
                return 2
            else :
                raise


    #
    #
    #

    def delete_rucio_rule(self, dataset, location=None, dnr=False ):
        '''
        Delete a Rucio dataset+location rule

        Parameters:
            dataset (str|MDataset) : a dataset object or dataset name
            location (str) : location (tape,disk,scratch).
            dnr (bool) = (default=False) Do Not Raise on does not exists

        Returns:
            rc (int) : 0 or 2 for does not exist (if dnr)

        '''

        if isinstance(dataset,mDataset) :
            ds = dataset
        else :
            ds = MDataet(dataset)

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
            if dnr :
                return 2
            else :
                raise RuntimeError(f'Did not find rule to delete for {ds.did()} at {location}')

        rule_id = rules[0]['id']

        if self.verbose > 0 :
            print(f"Unlocking replica rule for {ds.did()} at {location}")
        options = {'locked': False}
        self.rucio.update_replication_rule(rule_id, options)

        if self.verbose > 0 :
            print(f"Removing replica rule for {ds.did()} at {location}")
        self.rucio.delete_replication_rule(rule_id)

    #
    #
    #

    def locate_dataset(self, dataset, location='tape', remove=False):
        '''

        Add a dCache location (tape-backed, persistent) record in
        in the rucio database for a given file.  The file will
        be attached to the default dataset derived from the file name.
        If the dataset does not exist, it will be made.

        Parameters:
            dataset (str|MDataset) : dataset name or did
            location (str) : location (tape (default),disk,scratch,nersc)
            remove (bool) : remove instead of add (default False)
        Raises :
             RunTimeError : more than one related rule
             RunTimeError : Rucio has more files than metacat
        '''


        if isinstance(dataset, MDataset):
            ds = dataset
        else :
            ds = MDataset(dataset)

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

        if remove :

            # remove the rule tying this dataset to this RSE

            filters={'scope':ds.scope(), 'name': ds.name(),
                     'rse_expression' : rse}

            rules = list( self.rucio.list_replication_rules(filters) )
            if len(rules) > 1 :
                print(rules)
                raise RuntimeError(f'Found {len(rules)} rules, only one expected')
            rule_id = rules[0]['id']

            if self.verbose > 0 :
                print("Unlocking replica rule")
            options = {'locked': False}
            self.rucio.update_replication_rule(rule_id, options)

            if self.verbose > 0 :
                print("Removing replica rule")
            self.rucio.delete_replication_rule(rule_id)

        else :

            # make sure Rucio dataset exists, or create it
            # and add the right rule

            try :
                self.rucio.add_dataset(scope=ds.namespace(),name=ds.name())
            except DataIdentifierAlreadyExists as e:
                if self.verbose > 0 :
                    print("found dataset already exists")

            try :
                if self.verbose > 0 :
                    print("adding replica rule",ds.did(),rse)
                self.rucio.add_replication_rule(dids, 1, rse)
            except DuplicateRule as e :
                if self.verbose > 0 :
                    print("found rule already exists ")


        rfiles = []
        for rfile in self.rucio.list_files(scope=ds.namespace(),
                                           name=ds.name()) :
            #print(rfile)
            rfiles.append(rfile['name'])

        nrfiles = len(rfiles)
        if self.verbose > 0 :
            print(f"Found {nrfiles} rucio records in this dataset")

        rrfiles = []
        for rrfile in self.rucio.list_replicas(dids,rse_expression=rse) :
            #print(rrfile)
            rrfiles.append(rrfile['name'])
        nrrfiles = len(rrfiles)

        if self.verbose > 0 :
            print(f"Found {nrrfiles} rucio records in this dataset with this location")
        if nrrfiles == nfiles and not remove :
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
        ddids = [] # list for removing RSE
        ncrec = 0
        ncrep = 0
        for mcf in self.metacat.get_dataset_files(did = ds.did()) :

            filed = {'scope' : mcf['namespace'],
                     'name' : mcf['name'] }

            if mcf['name'] not in rrfiles :
                # file does not have record and RSE

                if mcf['name'] not in rfiles :
                    # file does not have record
                    if 'checksums' in mcf :
                        adler32 = mcf['checksums'].get('adler32')
                    else :
                        adler32 = None
                    filei = {'scope' : mcf['namespace'],
                             'name' : mcf['name'],
                             #'type' : 'file',
                             'bytes' : mcf.get('size'),
                             'adler32' : adler32 }
                    dids.append(filei)
                    attdids.append(filed)
                else :
                    # files which exist but need RSE added
                    rdids.append(filed)
            else :
                # in Rucio and in this RSE
                ddids.append(filed)


        ncrec = len(dids)
        ncrep = len(rdids)
        ndrep = len(ddids)

        if remove :
            if self.verbose > 0 :
                print("Removing {ndrep} files from location")
            self.rucio.delete_replicas(rse = rse, files = ddids)
            return

        if ncrec > 0 :
            if self.verbose > 0 :
                print(f"Creating {ncrec} new files with locations")
            # do the bulk creation of file records
            #self.rucio.add_dids(dids)
            self.rucio.add_replicas(rse = rse, files = dids)
            # attach the file records to a dataset
            self.rucio.attach_dids( scope = ds.scope(), name = ds.name(),
                                    dids = attdids)
        if ncrep > 0 :
            if self.verbose > 0 :
                print(f"Adding replica {rse} to {ncrep} files")
            # add the replica rse to the files
            print(rse)
            print(rdids)
            self.rucio.add_replicas(rse = rse, files = rdids)


        return


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
             RunTimeError : inconsitent flags
        '''


        if self.verbose > 0 or self.dryrun :
            print("location:",location)
            print("delete physical files in dcache:",dcache)
            print("delete location records:",replica)
            print("delete file catalog records:",catalog)
            print(f"processing {len(files)} files")

        if (dcache or replica) and not location :
            raise runTimeError("location required for dcache or replica")


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
                    pass
                    #self.delete_dcache_file(file,location,force)
            if catalog :
                if self.dryrun :
                    print("    delete file catalog record")
                else :
                    self.retire_metacat_file(file,force)

#        if replica :
#            
#        if isinstance(dataset, MDataset):
#            ds = dataset
#        else :
#            ds = MDataset(dataset)
#
#        self.ready_metacat()
#        self.ready_rucio()
#
#        nfiles = self.metacat.get_dataset(ds.did())['file_count']
#        if self.verbose > 0 :
#            print(f"Found {nfiles} metacat files for dataset {ds.did()}")
#
#        if nfiles == 0 :
#            if self.verbose > 0 :
#                print("No files to process")
#            return
#
#
#        rse = _pars.location(location,'rucio')
#        dids = [{"scope":ds.namespace(), "name":ds.name()}]
#
#        if remove :
#
#            # remove the rule tying this dataset to this RSE
#
#            filters={'scope':ds.scope(), 'name': ds.name(),
#                     'rse_expression' : rse}
#
#            rules = list( self.rucio.list_replication_rules(filters) )
#            if len(rules) > 1 :
#                print(rules)
#                raise RuntimeError(f'Found {len(rules)} rules, only one expected')
#            rule_id = rules[0]['id']
#
#            if self.verbose > 0 :
#                print("Unlocking replica rule")
#            options = {'locked': False}
#            self.rucio.update_replication_rule(rule_id, options)
#
#            if self.verbose > 0 :
#                print("Removing replica rule")
#            self.rucio.delete_replication_rule(rule_id)
#
#        else :
#
#            # make sure Rucio dataset exists, or create it
#            # and add the right rule
#
#            try :
#                self.rucio.add_dataset(scope=ds.namespace(),name=ds.name())
#            except DataIdentifierAlreadyExists as e:
#                if self.verbose > 0 :
#                    print("found dataset already exists")
#
#            try :
#                if self.verbose > 0 :
#                    print("adding replica rule",ds.did(),rse)
#                self.rucio.add_replication_rule(dids, 1, rse)
#            except DuplicateRule as e :
#                if self.verbose > 0 :
#                    print("found rule already exists ")
#
#
#        rfiles = []
#        for rfile in self.rucio.list_files(scope=ds.namespace(),
#                                           name=ds.name()) :
#            #print(rfile)
#            rfiles.append(rfile['name'])
#
#        nrfiles = len(rfiles)
#        if self.verbose > 0 :
#            print(f"Found {nrfiles} rucio records in this dataset")
#
#        rrfiles = []
#        for rrfile in self.rucio.list_replicas(dids,rse_expression=rse) :
#            #print(rrfile)
#            rrfiles.append(rrfile['name'])
#        nrrfiles = len(rrfiles)
#
#        if self.verbose > 0 :
#            print(f"Found {nrrfiles} rucio records in this dataset with this location")
#        if nrrfiles == nfiles and not remove :
#            if self.verbose > 0 :
#                print(f"Locations are complete")
#            return
#
#        if nrfiles > nfiles :
#            raise RuntimeError(f'Rucio file count {nrfiles} is larger than metacat count {nfiles}, repairs are required')
#
#        if self.verbose > 0 :
#            print("Setting locations on Rucio files")
#
#        nrcre = 0
#        dids = []   # list for creating files records
#        attdids = [] # list for creating attachments of files to the dataset
#        rdids = [] # list for creating RSE entries for files
#        ddids = [] # list for removing RSE
#        ncrec = 0
#        ncrep = 0
#        for mcf in self.metacat.get_dataset_files(did = ds.did()) :
#
#            filed = {'scope' : mcf['namespace'],
#                     'name' : mcf['name'] }
#
#            if mcf['name'] not in rrfiles :
#                # file does not have record and RSE
#
#                if mcf['name'] not in rfiles :
#                    # file does not have record
#                    if 'checksums' in mcf :
#                        adler32 = mcf['checksums'].get('adler32')
#                    else :
#                        adler32 = None
#                    filei = {'scope' : mcf['namespace'],
#                             'name' : mcf['name'],
#                             #'type' : 'file',
#                             'bytes' : mcf.get('size'),
#                             'adler32' : adler32 }
#                    dids.append(filei)
#                    attdids.append(filed)
#                else :
#                    # files which exist but need RSE added
#                    rdids.append(filed)
#            else :
#                # in Rucio and in this RSE
#                ddids.append(filed)
#
#
#        ncrec = len(dids)
#        ncrep = len(rdids)
#        ndrep = len(ddids)
#
#        if remove :
#            if self.verbose > 0 :
#                print("Removing {ndrep} files from location")
#            self.rucio.delete_replicas(rse = rse, files = ddids)
#            return
#
#        if ncrec > 0 :
#            if self.verbose > 0 :
#                print(f"Creating {ncrec} new files with locations")
#            # do the bulk creation of file records
#            #self.rucio.add_dids(dids)
#            self.rucio.add_replicas(rse = rse, files = dids)
#            # attach the file records to a dataset
#            self.rucio.attach_dids( scope = ds.scope(), name = ds.name(),
#                                    dids = attdids)
#        if ncrep > 0 :
#            if self.verbose > 0 :
#                print(f"Adding replica {rse} to {ncrep} files")
#            # add the replica rse to the files
#            print(rse)
#            print(rdids)
#            self.rucio.add_replicas(rse = rse, files = rdids)
#
#
#        return


    #
    #
    #

    def prestage_dataset(self, dataset=None):
        '''

        NOT IMPLEMENTED

        Return the full dCache file path or url for a file name

        Parameters:
            file_name (str) : the file name (any directories are stripped)
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

    #    print("in fileTouch "+fileName)
    #
    #    with open(fileName, 'rb') as fh:
    #        fh.read(128)

        return



    #
    #
    #

    def verify_dataset(self, dataset, options=[] ):
        '''

        NOT IMPLEMENTED

        Return the full dCache file path or url for a file name

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

        nfiles = dd["file_count"]
        report['metacat_nfiles'] = nfiles

        # this is running the file list generator once
        mfile = None
        totalb = 0
        totalev = 0
        for fi in self.metacat.get_dataset_files(did = ds.did(),
                                                 with_metadata=True) :
            # example file
            if not mfile :
                mfile = MFile(namespace=fi['namespace'],name=fi['name'])
            if 'size' in fi :
                totalb = totalb + fi['size']
            md = fi.get('metadata')
            if md :
                if 'rse.nevent' in md :
                    totalev = totalev + md['rse.nevent']

        report['total_bytes'] = totalb
        report['total_events'] = totalev

        if self.verbose > 0 :
            print("Example file:",mfile.did())

        report['example_file'] = mfile.did()

        nrfiles = 0
        rexists = True
        try :
            for rfile in self.rucio.list_files(scope=ds.namespace(),
                                               name=ds.name()) :
                nrfiles = nrfiles + 1
        except DataIdentifierNotFound as e :
            rexists = False

        report['rucio_nfiles'] = nrfiles

        dids = [{"scope":mfile.namespace(), "name":mfile.name()}]

        if self.verbose > 0 :
            print("Checking locations in Rucio")

        rlocs = []
        if rexists :
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

        summary=f'{status} {nfiles:7d} {rstatus} {totalb:20,d} {totalev:12,d}  {ds.did()}'
        report['summary'] = summary

        return report
