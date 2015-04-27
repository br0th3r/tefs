#!/usr/bin/python
#########################################################################
#                                                                       #
# Name:      teFS                                                       #
#                                                                       #
# Project:   Transparent Encrypted Filesystem                           #
# Module:    Main                                                       #
# Started:   20110904                                                   #
#                                                                       #
# Important: WHEN EDITING THIS FILE, USE SPACES TO INDENT - NOT TABS!   #
#                                                                       #
#########################################################################
#                                                                       #
# Juan Miguel Taboada Godoy <juanmi@centrologic.com>                    #
#                                                                       #
#########################################################################
'''
teFS command processor, please check tefs.py for more documentation
'''

__version__ = "201109111103"

__all__ = []

# Try to start psyco
try:
    import psyco
    psyco.full()
except:
    # Warn we couldn't start psyco
    redcolor="\033[1;31m"
    endcolor="\033[1;00m"
    print "%sPsyco profiler is not available in this system. I will not use it%s" % (redcolor,endcolor)

# Import the rest of libraries
import os
import sys
import fuse
from tefs import teFS

def getargv(name):
    if name in sys.argv:
        sys.argv.pop(sys.argv.index(name))
        return True
    else:
        return False
    
def main(key):
    usage  = ""
    usage += "Usage: %s PATH MOUNTPOINT [options] {encrypt|decrypt}\n" % (sys.argv[0])
    usage += "Options:\n"
    
    # ALLOWALL: allow to read /dev /proc /sys and the directory where teFS is mounted on
    # Allows recursive encryption but it can not be used with a recursive command or will
    # stack in a infinite loop
    usage += "    --allowall    Allow everything, doesn't take any control over allowed folders\n"
    
    # LOG: Make sure to remove every debugger named 'screen' so everythin is sent to files
    # and nothing to the screen
    usage += "    --log         Everything is sent to files nothing to the screen\n"
    
    if len(sys.argv) >= 4:
        
        # Get basic configuration from the command line
        try:
            datapath = sys.argv.pop(1)
            mountpoint = os.path.abspath(sys.argv[1])
            action = sys.argv.pop(-1)
        except:
            print "Warning: missing arguments"
            print
            print usage
            sys.exit()
        
        # Check action
        if action != 'encrypt' and action != 'decrypt':
            print "Warning: action can be only encrypt or decrypt, you used '%s'" % (action)
            print
            print usage
            sys.exit()
        
        # Process options
        allowall = getargv('--allowall')
        log = getargv('--log')
        
        
        # Configure debugger
        debugger = {}
        debugger['screen'] = (sys.stdout, ['*'] )
        if action=='encrypt':
            debugger['log'] = (open("log/tefs_encrypt.log","a"), ['*'] )
        else:
            debugger['log'] = (open("log/tefs_decrypt.log","a"), ['*'] )
        
        if log:
            if action == 'encrypt':
                fich = open ("log/tefs_encrypt.out", "a")
            else:
                fich = open ("log/tefs_decrypt.out", "a")
            
            sys.stdout = fich
            sys.stderr = fich
            debugger.pop('screen')
        
        # Build teFS and make it to work
        server = teFS(key, datapath, action, mountpoint, allowall, debugger = debugger, version="%prog " + fuse.__version__, usage = usage, dash_s_do = 'setsingle')
        server.parse(values = server, errex = 1)
        server.main()
    else:
        print usage

if __name__ == '__main__':
    key = 'AESECB$CIt16CXA9j73Yx1jCCMH6CXvS8DwHQuR'
    #key = 'BlowfishECB$ASFFQWER'
    #key = None
    main(key)
