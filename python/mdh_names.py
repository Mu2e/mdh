'''
Mu2e file and dataset names, and the standard paths they imply.

This module holds the Mu2e naming conventions and the classes that
interpret them: MParameters (the convention tables), MDataset and MFile.
It deliberately imports nothing outside the python standard library, so
MFile.url() and the name-parsing methods are available without installing
metacat, rucio or data_dispatcher.  Keep it that way - the heavier
data-handling client lives in mdh.py, which imports from here.
'''

import os
import re
import hashlib

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
            "dqm":{"prod":"phy-ntd","user":"usr-dat","type":"data"},
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
        self.replicas = {}

        _pars.check_did(self.did())

        return

    def add_catmetadata(self, catmetadata) :
        self.catmd = catmetadata
    def add_replica(self,location,status="unknown") :
        self.replicas[location] = status;

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

    def get_replicas(self) :
        return self.replicas

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
            url = _pars.location(location,"sam") + ":" + path
        else :
            #strip "/pnfs"
            path = path[5:] + "/" + self.name()
            url = _pars.url_prefix(schema) + path

        return url
