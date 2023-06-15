#
# script to make this repo into a UPS tarball.
# asusmes the current code is correct
# will not force the new version to be the "current" version
# currently this ups file will setup a specific version of python
#
# One argument required:
# $1  version, like v1_0_0 (needs to appear in ups dirs)
#

if [ $# -ne 1 ]; then
    echo "ERROR expected one argument: version string"
    exit 1
fi

VERSION=$1
PYTHON_VERSION=v3_9_13
FLAVOR=Linux64bit+3.10-2.17

OWD=$PWD
SDIR=$(dirname $(readlink -f $BASH_SOURCE)  | sed 's|/ups||' )

TDIR=$(mktemp -d)

cd $TDIR
mkdir -p mdh
cd mdh
mkdir -p $VERSION/$FLAVOR
cd $VERSION/$FLAVOR

rsync --exclude "*~" -r $SDIR/bin $SDIR/python  .

cd $TDIR/mdh/$VERSION
mkdir -p ups
cd ups

cat > mdh.table <<EOL
File    = table
Product = mdh

Group:

  Flavor = $FLAVOR
  Qualifiers =

  Common:
    Action = setup
      prodDir()
      setupEnv()
      setupRequired( python $PYTHON_VERSION )
      setupRequired( datadispatcher )
      setupRequired( rucio )
      envSet(\${UPS_PROD_NAME_UC}_VERSION, $VERSION)
      envSet( \${UPS_PROD_NAME_UC}_FQ_DIR, \${\${UPS_PROD_NAME_UC}_DIR}/\${UPS_PROD_FLAVOR} )
      envPrepend(PYTHONPATH, \${\${UPS_PROD_NAME_UC}_FQ_DIR}/python)
      pathPrepend(PATH, \${\${UPS_PROD_NAME_UC}_FQ_DIR}/bin)

End:
EOL


cd $TDIR/mdh

mkdir -p ${VERSION}.version
cd ${VERSION}.version

cat > $FLAVOR <<EOL
FILE    = version
PRODUCT = mdh
VERSION = $VERSION

FLAVOR = $FLAVOR
QUALIFIERS =
  PROD_DIR = mdh/$VERSION
  UPS_DIR = ups
  TABLE_FILE = mdh.table
EOL

cd $TDIR

tar -cjf $OWD/mdh-${VERSION}.bz2 mdh

cd $OWD
exit 0
