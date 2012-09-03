#!/usr/bin/env python

import sys, os
import shlex

# Env
# 0. default_ip_prefix
DEFAULT_IP_PREFIX = os.getenv("DEFAULT_IP_PREFIX", "127.0.0.")

# 1. mds ip prefix
MDS_IP_PREFIX = os.getenv("MDS_IP_PREFIX", DEFAULT_IP_PREFIX)
# 2. mds ip suffix set
MDS_IP_SUFFIX = os.getenv("MDS_IP_SUFFIX", "1")
MDS_PORT = os.getenv("MDS_PORT", "8210")

# 3. mdsl ip prefix
MDSL_IP_PREFIX = os.getenv("MDSL_IP_PREFIX", DEFAULT_IP_PREFIX)
# 4. mdsl ip suffix set
MDSL_IP_SUFFIX = os.getenv("MDSL_IP_SUFFIX", "1")
MDSL_PORT = os.getenv("MDSL_PORT", "8810")

# 5. r2 ip prefix
R2_IP_PREFIX = os.getenv("R2_IP_PREFIX", DEFAULT_IP_PREFIX)
# 6. r2 ip suffix set
R2_IP_SUFFIX = os.getenv("R2_IP_SUFFIX", "1")
R2_PORT = os.getenv("R2_PORT", "8710")

# 7. client ip prefix
CLIENT_IP_PREFIX = os.getenv("CLIENT_IP_PREFIX", DEFAULT_IP_PREFIX)
# 8. client ip suffix set
CLIENT_IP_SUFFIX = os.getenv("CLIENT_IP_SUFFIX", "1")
CLIENT_PORT = os.getenv("CLIENT_PORT", "8412")

# 9. amc ip prefix
AMC_IP_PREFIX = os.getenv("AMC_IP_PREFIX", DEFAULT_IP_PREFIX)
# A. amc ip suffix set
AMC_IP_SUFFIX = os.getenv("AMC_IP_SUFFIX", None)
AMC_PORT = os.getenv("AMC_PORT", "9001")

# B. bp ip prefix
BP_IP_PREFIX = os.getenv("BP_IP_PREFIX", DEFAULT_IP_PREFIX)
# C. bp ip suffix set
BP_IP_SUFFIX = os.getenv("BP_IP_SUFFIX", None)
BP_PORT = os.getenv("BP_PORT", "7900")

# D. osd ip prefix
OSD_IP_PREFIX = os.getenv("OSD_IP_PREFIX", DEFAULT_IP_PREFIX)
# E. osd ip suffix set
OSD_IP_SUFFIX = os.getenv("OSD_IP_SUFFIX", None)
OSD_PORT = os.getenv("OSD_PORT", "7900")

def main(argv):
    # argv[1] is target file
    if len(argv) < 2:
        print "Usage: %s config_file" % argv[0]
        return

    try:
        f = open(argv[1], 'w')
    except IOError, ie:
        print "IOError: %s" % ie

    # write conf file header
    f.write("# HVFS Config file \n\n")

    # write mds region
    sset = shlex.split(MDS_IP_SUFFIX)
    id = 0
    for x in sset:
        line = "mds:" + MDS_IP_PREFIX + x + ":" + MDS_PORT + ":" + str(id)
        id += 1
        f.write(line + "\n")
        print line

    # write mdsl region
    sset = shlex.split(MDSL_IP_SUFFIX)
    id = 0
    for x in sset:
        line = "mdsl:" + MDSL_IP_PREFIX + x + ":" + MDSL_PORT + ":" + str(id)
        id += 1
        f.write(line + "\n")
        print line

    # write r2 region
    sset = shlex.split(R2_IP_SUFFIX)
    id = 0
    for x in sset:
        line = "r2:" + R2_IP_PREFIX + x + ":" + R2_PORT + ":" + str(id)
        id += 1
        f.write(line + "\n")
        print line

    # write client region
    sset = shlex.split(CLIENT_IP_SUFFIX)
    id = 0
    for x in sset:
        line = "client:" + CLIENT_IP_PREFIX + x + ":" + CLIENT_PORT + ":" + str(id)
        id += 1
        f.write(line + "\n")
        print line

    # write amc region
    if AMC_IP_SUFFIX != None:
        sset = shlex.split(AMC_IP_SUFFIX)
        id = 0
        for x in sset:
            line = "amc:" + AMC_IP_PREFIX + x + ":" + AMC_PORT + ":" + str(id)
            id += 1
            f.write(line + "\n")
            print line
            
    # write bp region
    if BP_IP_SUFFIX != None:
        sset = shlex.split(BP_IP_SUFFIX)
        id = 0
        for x in sset:
            line = "bp:" + BP_IP_PREFIX + x + ":" + BP_PORT + ":" + str(id)
            id += 1
            f.write(line + "\n")
            print line

    # write osd region
    if OSD_IP_SUFFIX != None:
        sset = shlex.split(OSD_IP_SUFFIX)
        id = 0
        for x in sset:
            line = "osd:" + OSD_IP_PREFIX + x + ":" + OSD_PORT + ":" + str(id)
            id += 1
            f.write(line + "\n")
            print line

if __name__ == '__main__':
    main(sys.argv[0:])
