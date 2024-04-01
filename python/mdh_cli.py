# mu2e data handling functionality supplimenting standard tools
import sys
import argparse
import json
import mdh

#
#
#

class MdhCli() :
    '''
    Provide a command line interface to MdhClient

    '''
    def __init__(self) :
        self.mdh = mdh.MdhClient()

    def help_cmd(self) :
        print("""
        Commands for Mu2e data handling

          mdh <command> [OPTIONS] [ARGS]

          commands:
            compute-crc      print crc for a file
            print-url        print full standard path or url for a file name
            query-dcache     print dCache database info for a file
            create-metadata  print DH metadata for a local file
            declare-files    create metacat file record from json metadata file
            copy-files       copy files to/from/within dCache
            locate-dataset   record dcache location for files in a dataset
            delete-files     delete files and records
            prestage-dataset move a dataset from tape to disk
            verify-dataset   check aspects of a dataset
            upload-grid      upload a set of grid job output files

        help for each command:
          mdh <command> -h

    """)

    def add_verbose(self, parser) :
        parser.add_argument("-v", "--verbose", action="count",
                            default=0, help="increase verbosity")
        return

    def add_dryrun(self, parser) :
        parser.add_argument("-y", "--dryrun", "--dry-run", "--dry_run",
                            action="store_true", help="enable dry run mode")
        return

    def collect_names(self, pargs) :
        names = []
        if pargs.names[0] == "-" :
            for line in sys.stdin:
                name = line.strip()
                if name == "Exit" :
                    break
                names.append(name)
        else :
            for name in pargs.names :
                names.append(name)
        return names
    #
    #
    #

    def compute_crc_cmd(self, args):

        parser = argparse.ArgumentParser(
            prog="mdh compute-crc",
            description='Compute dCache CRC for a file',
            epilog="one of -d or -e should be specified")

        parser.add_argument("names", nargs="+",
                            type=str, help="filespecs for files\n   \"-\" means read filespecs from stdin")
        parser.add_argument("-d","--dcache", action="store_true",
                            dest="dcache", default=False,
                            help="if present, print dCache CRC")
        parser.add_argument("-e","--enstore", action="store_true",
                            dest="enstore", default=False,
                            help="if present, print enstore CRC")
        self.add_verbose(parser)
        pargs = parser.parse_args(args)

        fslist = self.collect_names(pargs)

        for fs in fslist :
            enstore,dcache = self.mdh.compute_crc(fs)
            output = ""
            if pargs.enstore :
                output = output + enstore + " "
            if pargs.dcache :
                output = output + dcache + " "
            if pargs.verbose :
                output = output + fs
            print(output)

    #
    #
    #

    def print_url_cmd(self, args):

        parser = argparse.ArgumentParser(
            prog="mdh print-url",
            description="Print the standard path for a file or files in a dataset",
            formatter_class=argparse.RawTextHelpFormatter
        )

        parser.add_argument("names", nargs="+", 
                            type=str, help="names of files or datasets (one or more)\n\"-\" take files from stdin")
        parser.add_argument("-l","--location", action="store",
                            dest="location", default="tape",
                            help="standard location to use:\n  tape (default), disk, scratch, nersc")
        parser.add_argument("-s","--schema", action="store",
                            dest="schema", default="path",
                            help="Schema to use in writing the url:\n  path (default),http,root,dcap,sam")

        pargs = parser.parse_args(args)

        names = self.collect_names(pargs)

        flist = self.mdh.names_to_files(names)

        for file in flist :
            mf = mdh.MFile(name=file)
            url = mf.url(pargs.location,pargs.schema)
            print(url)

    #
    #
    #

    def query_dcache_cmd(self, args):

        parser = argparse.ArgumentParser(
            prog="mdh query-dcache",
            description="Print file information from the dcache database",
            formatter_class=argparse.RawTextHelpFormatter
        )

        parser.add_argument("names", nargs="+", 
                            type=str, help="names of files or datasets (one or more)\n\"-\" take files from stdin")
        parser.add_argument("-o","--online", action="store_true",
                            dest="online", default=False,
                            help="print locality NEARLINE (tape only), ONLINE_AND_NEARLINE")
        parser.add_argument("-c","--crc", action="store_true",
                            dest="crc", default=False,
                            help="print dCache CRC")
        parser.add_argument("-a","--all", action="store_true",
                            dest="pall", default=False,
                            help="print all dCache info")
        parser.add_argument("-l","--location", action="store",
                            dest="location", default="tape",
                            help="standard location to use: tape (default), disk, scratch")
        self.add_verbose(parser)
        pargs = parser.parse_args(args)

        names = self.collect_names(pargs)

        flist = self.mdh.names_to_files(names)

        for file in flist :
            info = self.mdh.query_dcache(file,pargs.location)

            if pargs.pall :
                print(json.dumps(info, indent=4))
            else :
                line = ""
                if pargs.online :
                    line = line + info["fileLocality"] + " "
                if pargs.crc :
                    crcs = info["checksums"]
                    for crc in crcs :
                        if crc['type'] == "ADLER32" :
                            line = line + crc["value"] + " "
                if pargs.verbose :
                    line = line + file
                print(line)

    #
    #
    #

    def create_metadata_cmd(self, args):

        parser = argparse.ArgumentParser(
            prog="mdh create-metadata",
            description="Compute and print metadata for a local file",
            formatter_class=argparse.RawTextHelpFormatter
        )

        parser.add_argument("filespec",
                            type=str, help="full filespec of file")
        parser.add_argument("-p","--parents", action="store",
                            dest="parents", default=None,
                            help="parents as a comma-separated list or the filepsec\nof a txt file which contains the parents names\n(default=None)")
        parser.add_argument("-s","--namespace", action="store",
                            dest="namespace", default=None,
                            help="metacat namespace, default=file owner field")
        parser.add_argument("-r","--rename_seq", action="store_true",
                            dest="rename_seq", default=False,
                            help="if present, find new sequencer (art only)")
        parser.add_argument("-a","--appFamily", action="store",
                            dest="appFamily", default=None,
                            help="appFamily string")
        parser.add_argument("-n","--appName", action="store",
                            dest="appName", default=None,
                            help="appName string")
        parser.add_argument("-e","--appVersion", action="store",
                            dest="appVersion", default=None,
                            help="appVersion string")
        parser.add_argument("-d","--declare", action="store_true",
                            dest="declare", default=False,
                            help="if present, also declare file to metacat")
        parser.add_argument("-f","--force", action="store_true",
                            dest="force", default=False,
                            help="if present, unretire files if needed")
        parser.add_argument("-o","--overwrite", action="store_true",
                            dest="overwrite", default=False,
                            help="if present, overwrite existing records, if needed")
        parser.add_argument("-i","--ignore", action="store_true",
                            dest="ignore", default=False,
                            help="if present, ignore GenCount product\n   (only for rare legacy files)")

        self.add_verbose(parser)
        pargs = parser.parse_args(args)
        self.mdh.set_verbose(pargs.verbose)
        mfile = mdh.MFile(filespec = pargs.filespec,
                          namespace = pargs.namespace)
        info = self.mdh.create_metadata(mfile,
                                        parents=pargs.parents,
                                        rename_seq=pargs.rename_seq,
                                        appFamily=pargs.appFamily,
                                        appName=pargs.appName,
                                        appVersion=pargs.appVersion,
                                        declare=pargs.declare,
                                        ignore=pargs.ignore,
                                        force=pargs.force,
                                        overwrite=pargs.overwrite)

        if not pargs.declare :
            print(json.dumps(info, indent=4))


    #
    #
    #

    def declare_files_cmd(self, args):

        parser = argparse.ArgumentParser(
            prog="mdh declare-files",
            description="Create a metacat database file record from a catmetadata json file",
            formatter_class=argparse.RawTextHelpFormatter
        )


        parser.add_argument("-d","--delete", action="store_true",
                            dest="delete", default=False,
                            help="if present, delete json file after declaration")
        parser.add_argument("-f","--force", action="store_true",
                            dest="force", default=False,
                            help="if present, unretire file if needed")
        parser.add_argument("-o","--overwrite", action="store_true",
                            dest="overwrite", default=False,
                            help="if present, overwrite existing record, if needed")
        parser.add_argument("filespec", nargs="+",
                            type=str, help="filespec for json catmetadata files\n   \"-\" means read filespecs from stdin")

        pargs = parser.parse_args(args)

        fslist = []
        if pargs.filespec[0] == "-" :
            for line in sys.stdin:
                fs = line.strip()
                if fs == "Exit" :
                    break
                fslist.append(fs)
        else :
            for fs in pargs.filespec :
                fslist.append(fs)

        for fs in fslist :
            self.mdh.declare_file(file=fs, force=pargs.force,
                                  overwrite=pargs.overwrite,
                                  delete=pargs.delete)


    #
    #
    #

    def copy_files_cmd(self, args):

        parser = argparse.ArgumentParser(
            prog="mdh copy-files",
            description="Copy local files to dcache,\nor file/dataset between dcache locations",
            formatter_class=argparse.RawTextHelpFormatter
        )

        parser.add_argument("names", nargs="+",
                            type=str, help="names of files or datasets (one or more)\n\"-\" to take files from stdin")
        parser.add_argument("-l","--location", action="store",
                            dest="location", default=None,
                            help="destination dCache location (required)\n  (tape, disk, scratch) or \"local\" ")
        parser.add_argument("-s","--source", action="store",
                            dest="source", default="local",
                            help="source \"local\" (default) with filespecs for input\nor  dCache location (tape, disk, scratch)")
        parser.add_argument("-c","--check", action="store_true",
                            dest="check", default=False,
                            help="if present, check destination checksum")
        parser.add_argument("-e","--effort", action="store",
                            dest="effort", type=int, default=1,
                            help="higher allows more retires")
        parser.add_argument("-o","--overwrite", action="store_true",
                            dest="overwrite", default=False,
                            help="if present, overwrite destination file, if needed")
        parser.add_argument("-d","--delete", action="store_true",
                            dest="delete", default=False,
                            help="if present, delete source file after copy")

        self.add_verbose(parser)
        pargs = parser.parse_args(args)
        self.mdh.set_verbose(pargs.verbose)

        names = self.collect_names(pargs)

        flist = self.mdh.names_to_files(names)

        for file in flist :
            self.mdh.copy_file(file = file, location=pargs.location,
                               source=pargs.source, secure=pargs.check,
                               effort=pargs.effort, delete=pargs.delete,
                               overwrite=pargs.overwrite)


    #
    #
    #

    def locate_dataset_cmd(self, args):

        parser = argparse.ArgumentParser(
            prog="mdh locate-dataset",
            description="Add a standard dCache location to files in a metacat dataset",
            formatter_class=argparse.RawTextHelpFormatter
        )

        parser.add_argument("dataset",
                            type=str, help="dataset name")
        parser.add_argument("-l","--location", action="store",
                            dest="location", default="tape",
                            help="standard location to use:\n  tape (default), disk, scratch")

        self.add_verbose(parser)
        pargs = parser.parse_args(args)
        self.mdh.set_verbose(pargs.verbose)

        self.mdh.locate_dataset(dataset = pargs.dataset,
                                location = pargs.location)

    #
    #
    #

    #
    #
    #

    def delete_files_cmd(self, args):

        parser = argparse.ArgumentParser(
            prog="mdh delete-files",
            description="Delete files, catalog and location records",
            formatter_class=argparse.RawTextHelpFormatter
        )

        parser.add_argument("names", nargs="+",
                            type=str, help="names of files or datasets (one or more)\n\"-\" to take files from stdin")
        parser.add_argument("-l","--location", action="store",
                            dest="location", default=None,
                            help="delete file in dCache location\n  (tape, disk, scratch)\n  and remove location record")
        parser.add_argument("-c","--catalog", action="store_true",
                            dest="catalog", default=False,
                            help="if present, delete file catalog records")
        parser.add_argument("-d","--dcache", action="store_true",
                            dest="dcache", default=False,
                            help="if present, delete file in dcache")
        parser.add_argument("-r","--replica", action="store_true",
                            dest="replica", default=False,
                            help="if present, delete location records")
        parser.add_argument("-f","--force", action="store_true",
                            dest="force", default=False,
                            help="if present, ignore file not found errors")

        self.add_verbose(parser)
        self.add_dryrun(parser)
        pargs = parser.parse_args(args)
        self.mdh.set_verbose(pargs.verbose)
        self.mdh.set_dryrun(pargs.dryrun)

        names = self.collect_names(pargs)

        flist = self.mdh.names_to_files(names)
        self.mdh.delete_files(flist,
                              location = pargs.location,
                              catalog = pargs.catalog,
                              dcache = pargs.dcache,
                              replica = pargs.replica,
                              force=pargs.force)


#        for file in flist :
#            self.mdh.copy_file(file = file, location = pargs.location,
#                               source = pargs.source)


    def prestage_dataset_cmd(self,args):

        parser = argparse.ArgumentParser(
            prog="mdh prestage-dataset",
            description='Move a dataset from tape to tape-backed dCache',
            formatter_class=argparse.RawTextHelpFormatter )

        parser.add_argument("dataset",
                            type=str, help="dataset of files to operate on")

        self.add_verbose(parser)
        pargs = parser.parse_args(args)
        self.mdh.set_verbose(pargs.verbose)

        self.mdh.prestage_dataset(pargs.dataset)


    #
    #
    #

    def verify_dataset_cmd(self,args):

        parser = argparse.ArgumentParser(
            prog="mdh verify-dataset",
            description='check aspects of a dataset',
            formatter_class=argparse.RawTextHelpFormatter )

        parser.add_argument("dataset", nargs="+",
                            type=str, help="dataset of files to operate on")

        self.add_verbose(parser)
        pargs = parser.parse_args(args)
        self.mdh.set_verbose(pargs.verbose)

        ds_list = []

        if pargs.dataset[0] == "-" :
            for line in sys.stdin:
                ds = line.strip()
                if ds == "Exit" :
                    break
                ds_list.append(ds)
        else :
            for ds in pargs.dataset :
                ds_list.append(ds)

        for ds in ds_list :
            report = self.mdh.verify_dataset(ds)
            print(report['summary'])

    #
    #
    #

    def upload_grid_cmd(self,args):

        parser = argparse.ArgumentParser(
            prog="mdh upload-grid",
            description='copy and declare a set of grid job output files',
            formatter_class=argparse.RawTextHelpFormatter )

        parser.add_argument("manifest",
                            type=str, help="text file with list of files to move")
        parser.add_argument("-m","--mode", action="store",
                            dest="mode", default="overwrite",
                            help="output method: overwrite (default), tag, tagclean")
        parser.add_argument("-a","--app", action="store",
                            dest="app", default="moo_config",
                            help="string defining AppFamily, Name and Version.\nif \"moo_config\" (default) take from $MOO_CONFIG\nexplicit value should be AppFamily-AppName-AppVersion")

        self.add_verbose(parser)
        pargs = parser.parse_args(args)
        self.mdh.set_verbose(pargs.verbose)

        self.mdh.upload_grid(manifest=pargs.manifest,
                             mode=pargs.mode,
                             app=pargs.app)

    #
    #
    #

    def run(self, args=None):
        if args == None :
            args = sys.argv[1:]

        command = args [0]
        if command == "help" or command == "--help" or command == "-h" :
            self.help_cmd()
            return

        args = args[1:]

        if command == "compute-crc" :
            self.compute_crc_cmd(args)
        elif command == "print-url" :
            self.print_url_cmd(args)
        elif command == "query-dcache" :
            self.query_dcache_cmd(args)
        elif command == "create-metadata" :
            self.create_metadata_cmd(args)
        elif command == "declare-files" or command == "declare-file" :
            self.declare_files_cmd(args)
        elif command == "copy-files" or command == "copy-file" :
            self.copy_files_cmd(args)
        elif command == "locate-dataset" :
            self.locate_dataset_cmd(args)
        elif command == "delete-files" :
            self.delete_files_cmd(args)
        elif command == "prestage-dataset" :
            self.prestage_dataset_cmd(args)
        elif command == "verify-dataset" :
            self.verify_dataset_cmd(args)
        elif command == "upload-grid" :
            self.upload_grid_cmd(args)
        else :
            print("Unknown command: ",command)
