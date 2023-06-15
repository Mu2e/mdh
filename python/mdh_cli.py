# mu2e data handling functionality supplimenting standard tools
import sys
import argparse
import json
from mdh import *

#
#
#

def helpCmd():
    print("""
    Commands for Mu2e data handling

      mdh <command> [OPTIONS] [ARGS]

      commands:
        file-crc     print crc for a file
        file-url     print full standard path or url for a file name
        dcache-info  print dCache database info for a file

    help for each command:
      mdh <command> -h

""")

#
#
#

def fileCrcCmd(args):

    parser = argparse.ArgumentParser(
        prog="mdh file-crc",
        description='Compute dCache CRC for a file',
        epilog="one of -d or -e should be specified")

    parser.add_argument("filespec", 
                        type=str, help="full filespec of file")
    parser.add_argument("-d","--dcache", action="store_true",
                        dest="dcache", default=False,
                        help="if present, print dCache CRC")
    parser.add_argument("-e","--enstore", action="store_true",
                        dest="enstore", default=False,
                        help="if present, print enstore CRC")

    pargs = parser.parse_args(args)

    enstore,dcache = fileCRC(pargs.filespec)

    if pargs.dcache :
        print("{:08x}".format(dcache))
    if pargs.enstore :
        print(enstore)

#
#
#

def fileUrlCmd(args):

    parser = argparse.ArgumentParser(
        prog="mdh file-url",
        description="Print the standard path for a file with standard six-field format",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("filename", nargs="+", 
                        type=str, help="base file name of files (one or more)\n\"-\" take files from stdin")
    parser.add_argument("-l","--location", action="store",
                        dest="location", default="tape",
                        help="standard location to use:\n  tape (default), disk, scratch, nersc")
    parser.add_argument("-s","--schema", action="store",
                        dest="schema", default="path",
                        help="Schema to use in writing the path:\n  path (default),http,root,dcap,sam")

    pargs = parser.parse_args(args)

    if pargs.filename[0] == "-" :
        for line in sys.stdin:
            fn = line.strip()
            if fn == "Exit" :
                break
            url = fileUrl(fn,pargs.location,pargs.schema)
            print(url)
        return
    else :
        for fn in pargs.filename :
            url = fileUrl(fn,pargs.location,pargs.schema)
            print(url)

#
#
#

def dcacheInfoCmd(args):

    parser = argparse.ArgumentParser(
        prog="mdh dcache-info",
        description="Print file information from the dcache database",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("filename",
                        type=str, help="base file name of file")
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
                        help="standard location to use: tape, disk, scratch")

    pargs = parser.parse_args(args)

    info = dcacheInfo(pargs.filename,pargs.location)

    if pargs.pall :
        print(json.dumps(info, indent=4))
    else :
        if pargs.online :
            print(info["fileLocality"])
        if pargs.crc :
            crcs = info["checksums"]
            for crc in crcs :
                if crc['type'] == "ADLER32" :
                    print(crc["value"])



#
#
#

def run(args=None):
    if args == None :
        args = sys.argv[1:]

    command = args [0]
    if command == "help" or command == "--help" or command == "-h" :
        helpCmd()
        return

    args = args[1:]

    if command == "file-crc" :
        fileCrcCmd(args)
    elif command == "file-url" :
        fileUrlCmd(args)
    elif command == "dcache-info" :
        dcacheInfoCmd(args)
    else :
        print("Unknown command: ",command)
