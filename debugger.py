#########################################################################
#                                                                       #
# Name:      Debugger                                                   #
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
Debugger helps to debug the system
'''

__version__ = "201109142036"

__all__ = ['Debugger','lineno']

import time
import datetime
import inspect

from colors import colors

def lineno():
    '''
    Returns the current line number in our program.
    '''
    return inspect.currentframe().f_back.f_lineno

class Debugger:
    
    __indebug={}
    
    def set_debug(self,debug):
        if type(debug) is dict:
            self.__indebug=debug
        else:
            raise IOError("Argument is not a dictionary")
    
    def get_debug(self):
        return self.__indebug
    
    def color(self,color):
        # Colors$
        if color in colors:
            (darkbit,subcolor)=colors[color]
            return "\033[%1d;%02dm" % (darkbit,subcolor)
        else:
            if color:
                self.debug("\033[1;31mColor '%s' unknown\033[1;00m\n" % (color))
            return ''
    
    def debug(self,msg,header=True,color=None):
        
        # Retrieve the name of the class
        clname=self.__class__.__name__
        
        # For each element inside indebug
        for name in self.__indebug:
            
            # Get color
            if name!='screen': color=None
            color_ini=self.color(color)
            color_end=self.color('close')
            
            # Get file output handler and indebug list
            (handler,indebug)=self.__indebug[name]
            
            # Look up if the name of the class is inside indebug
            if (clname in indebug) or (('*' in indebug) and ('-%s' % (clname) not in indebug)):
                
                # Build the message
                message=color_ini
                if header:
                    now=datetime.datetime.fromtimestamp(time.time())
                    message+="%02d/%02d/%d %02d:%02d:%02d %-10s - " % (now.day, now.month, now.year, now.hour, now.minute, now.second, clname)
                message+=str(msg)
                message+=color_end
                
                # Print it on the file handler
                handler.write(message)
                handler.flush()
    
    def warning(self,msg,header=True):
        self.warningerror(msg,header,'WARNING','yellow')
    
    def error(self,msg,header=True):
        self.warningerror(msg,header,'ERROR','red')
    
    def warningerror(self,msg,header,prefix,color):
        
        # Retrieve the name of the class
        clname=self.__class__.__name__
        
        # For each element inside indebug
        for name in self.__indebug:
            
            # Get file output handler and indebug list
            (handler,indebug)=self.__indebug[name]
            
            # Get color
            if name!='screen': color=None
            color_ini=self.color(color)
            color_end=self.color('close')
            
            # Build the message
            message=color_ini
            if header:
                now=datetime.datetime.fromtimestamp(time.time())
                message+="\n%s - %02d/%02d/%d %02d:%02d:%02d %-10s - " % (prefix,now.day, now.month, now.year, now.hour, now.minute, now.second, clname)
            message+=str(msg)
            message+=color_end
            
            # Print it on the file handler
            handler.write(message)
            handler.flush()

