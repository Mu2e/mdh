#
# facts about Mu2e file location conventions
#

fileFamilies = {
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

file_formats = [ "art", "root", "txt", "tar", "tgz", "log", "fcl",
                 "mid", "tbz", "stn", "enc", "dat", "tka", "pdf" ]

schemas = ["path", "http", "root", "dcap", "sam"]

locs = {
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


# ucondb is not standard
#             "ucondb":"/mu2e_ucondb_prod/app/data",
#             "ucondb","dbdata0vm.fnal.gov",
