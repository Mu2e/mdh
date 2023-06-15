#
# facts about Mu2e file location conventions
#

fileFamilies = {
    "raw":{"prod":"phy-raw","user":"phy-raw"},
    "rec":{"prod":"phy-rec","user":"usr-dat"},
    "ntd":{"prod":"phy-ntd","user":"usr-dat"},
    "ext":{"prod":None,     "user":"usr-dat"},
    "rex":{"prod":None,     "user":"usr-dat"},
    "xnt":{"prod":None,     "user":"usr-dat"},
    "cnf":{"prod":"phy-etc","user":"usr-etc"},
    "sim":{"prod":"phy-sim","user":"usr-sim"},
    "dts":{"prod":"phy-sim","user":"usr-sim"},
    "mix":{"prod":"phy-sim","user":"usr-sim"},
    "dig":{"prod":"phy-sim","user":"usr-sim"},
    "mcs":{"prod":"phy-sim","user":"usr-sim"},
    "nts":{"prod":"phy-nts","user":"usr-nts"},
    "log":{"prod":"phy-etc","user":"usr-etc"},
    "bck":{"prod":"phy-etc","user":"usr-etc"},
    "etc":{"prod":"phy-etc","user":"usr-etc"}}

file_formats = [ "art", "root", "txt", "tar", "tgz", "log", "fcl",
                 "mid", "tbz", "stn", "enc", "dat", "tka", "pdf" ]

schemas = ["path", "http", "root", "dcap", "sam"]

locs = {
    "tape" :    { "prefix":"/pnfs/mu2e/tape",
                  "sam":"enstore"},
    "disk" :    { "prefix":"/pnfs/mu2e/persistent/datasets",
                  "sam":"dcache"},
    "scratch" : { "prefix":"/pnfs/mu2e/scratch/datasets",
                   "sam":"dcache"},
    "nersc" :   { "prefix":"/global/cfs/cdirs/m3249/datasets",
                   "sam":"nersc"}
    }

# ucondb is not standard
#             "ucondb":"/mu2e_ucondb_prod/app/data",
#             "ucondb","dbdata0vm.fnal.gov",
