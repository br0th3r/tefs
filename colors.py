#!/usr/bin/python
#########################################################################
#                                                                       #
# Name:      Colors                                                     #
#                                                                       #
# Project:   Transparent Encrypted Filesystem                           #
# Module:    Debugger                                                   #
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
Colors definition
'''

__version__ = "201109111106"

__all__ = ['colors']


colors={}

colors['simplegrey']   = (0, 30)
colors['simplered']    = (0, 31)
colors['simplegreen']  = (0, 32)
colors['simpleyellow'] = (0, 33)
colors['simpleblue']   = (0, 34)
colors['simplepurple'] = (0, 35)
colors['simplecyan']   = (0, 36)
colors['simplewhite']  = (0, 37)

colors['grey']   = (1, 30)
colors['red']    = (1, 31)
colors['green']  = (1, 32)
colors['yellow'] = (1, 33)
colors['blue']   = (1, 34)
colors['purple'] = (1, 35)
colors['cyan']   = (1, 36)
colors['white']  = (1, 37)

colors['close']  = (1, 0)


if __name__ == "__main__":
    # Show up all colors
    for color in ['simplegrey', 'simplered', 'simplegreen', 'simpleyellow', 'simpleblue', 'simplepurple', 'simplecyan', 'simplewhite', 'grey', 'red', 'green', 'yellow', 'blue', 'purple', 'cyan', 'white', 'close']:
        # Get the color information
        (simplebit, subcolor) = colors[color]
        # Show it
        print "%1d:%02d - \033[%1d;%02dm%-14s\033[1;00m%s" % (simplebit, subcolor, simplebit, subcolor, color, color)

