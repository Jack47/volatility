#!/usr/bin/python
#  -*- mode: python; -*-

#pylint: disable-msg=C0111

import pdb
import sys

if sys.version_info < (2, 6, 0):
    sys.stderr.write("Volatility requires python version 2.6, please upgrade your python installation.")
    sys.exit(1)

try:
    import psyco #pylint: disable-msg=W0611,F0401
except ImportError:
    pass

if False:
    # Include a fake import for things like pyinstaller to hit
    # since this is a dependency of the malware plugins
    import yara

import textwrap
import volatility.conf as conf
#config = conf.ConfObject()
import volatility.constants as constants
import volatility.registry as registry
import volatility.exceptions as exceptions
import volatility.obj as obj
import volatility.debug as debug

import volatility.addrspace as addrspace
import volatility.commands as commands
import volatility.scan as scan

#config.add_option("INFO", default = None, action = "store_true",
                  #cache_invalidator = False,
                  #help = "Print information about all registered objects")
class Volatility(object):

	
	config = conf.ConfObject()
	cmds = {}
	profile = "--profile=Linuxcentos5_5x86"

	def Is_SystemCallHooked(self, vmname):

	   data = self.Check_SystemCall( vmname)
	   for ( table_name, i, call_addr, hooked) in data:
		if hooked != 0:
			return True
	   return False

	def Check_SystemCall(self, vmname):
	  #for (table_name, i, call_addr, hooked) in data:
            #if hooked == 0:
	   return self.ExecuteCommand(vmname, "linux_check_syscall")
	   
	def Check_ProcessName(self, vmname):
	   data = self.ExecuteCommand(vmname, "linux_pslist")
	   list = []
	   for task in data:
		list.append(str(task.comm))
	   return list
		
	def Check_Process(self, vmname):
	   return self.ExecuteCommand(vmname, "linux_pslist")

	def ExecuteCommand(self, vmname, command):
	    location = "-l vmi://"+vmname;
	    argv = self.profile+" "+location+" "+command
	    self.config.parse_options_from_string(argv, False)
	    module  = self.GetModule(self.config)
	    return self.ExecuteModule(module, argv)

	def GetModule(self, config):
		for m in config.args:
			if m in self.cmds.keys():
			    module = m
			    return module 

		if not module:
		#config.parse_options()
			debug.error("You must specify something to do (try -h)")
		
		
	def ExecuteModule(self, module, argv):
		    if not module:			
			debug.error("You must specify something to do (try -h)")
		    try:
			if module in self.cmds.keys():
			    command = self.cmds[module](self.config)
			    #print dir(config)

			    #print config.args
			    ## Register the help cb from the command itself
			    #self.config.set_help_hook(obj.Curry(command_help, command))
			    #config.parse_options()
			    self.config.parse_options_from_string(argv)
			    #pdb.set_trace()

			    if not self.config.LOCATION:
				debug.error("Please specify a location (-l) or filename (-f)")

			    data = command.execute_call()
			    return data
			    #for task in data:
			#	print str(task.comm)+"\t"+str(task.pid)
		    except exceptions.AddrSpaceError, e:
		   	print e
#		    except (exceptions.VolatilityException,exceptions.AddrSpaceError) as e:
			#print e

	def __init__(self):	

	    # Get the version information on every output from the beginning
	    # Exceptionally useful for debugging/telling people what's going on
	    #sys.stderr.write("Volatile Systems Volatility Framework {0}\n".format(constants.VERSION))
	    #sys.stderr.flush()

	    self.config.add_option("INFO", default = None, action = "store_true",
			  cache_invalidator = False,
			  help = "Print information about all registered objects")

	    # Setup the debugging format
	    debug.setup()
	    # Load up modules in case they set config options
	    registry.PluginImporter()

	    ## Register all register_options for the various classes
	    registry.register_global_options(self.config, addrspace.BaseAddressSpace)
	    registry.register_global_options(self.config, commands.Command)

		# Reset the logging level now we know whether debug is set or not
	    debug.setup(self.config.DEBUG)
	    
	    #pdb.set_trace()
	    
	    ## Try to find the first thing that looks like a module name
	    self.cmds = registry.get_plugin_classes(commands.Command, lower = True)
	    
class MonitorCmd(object):
	pname = {}
	isRestoreSnapShot = False	
	isRestartVM = False
	vmname = ""
	def __init__(self, vmname):
		self.vmname = vmname	

	def AddRestartProcess(self, pname):
		if pname not in self.pname:
			self.pname.add(pname)	
	def SetRestoreSnapShot(self):
		self.isRestoreSnapShot = True
	def SetRestartVM(self):
		self.isRestartVM = True
	def Execute(self):
		pdb.set_trace()
		print "Action"+self.vmname
		if self.isRestoreSnapShot:
			print "\tRestoreing from snapshot"
		elif self.isRestartVM:
			print "\tRestarting vm"
		elif self.pname:	
			pnames = ""
 			for p in self.pname :
				pnames.append(p+",")
			print "\tRestarting process\t"+ pnames

class VmCheckConfig(object):
	processList = {'sshd':"restartP", 'gnome':"restartV", 'kvm':"restore"}
 	vmname = ""
	def __init__(self, vmname):
		self.vmname = vmname
	def GetProcessMap(self):
		return self.processList;
	def GetVmName(self):
		return self.vmname
		
def CheckVMS():
	vm01config = VmCheckConfig("vm01")
	vm02config = VmCheckConfig("vm02")
	vmxpconfig = VmCheckConfig("vm_xp")
	vmcfgs = [ vm02config, vmxpconfig]
#	vmcfgs = [vm01config, vm02config ]
	
	for vmcfg in vmcfgs:
		print "Checking VMs:"+" "+vmcfg.GetVmName()
		vmCmd = MonitorCmd( vmcfg.GetVmName())	
		CheckVMProcess(vmcfg, vmCmd)
		CheckVMSystemCall(vmcfg, vmCmd)
		vmCmd.Execute()

def ProcessActionStr(pname, action, vmCmd):
	if action == "restartP":
		vmCmd.AddRestartProcess(pname)
	elif action == "restore":
		vmCmd.SetRestoreSnapShot()
	elif action == "restartV":
		vmCmd.SetRestartVM()
		
def CheckVMProcess(vmcfg, vmCmd):
		
	vmProcessList = volatility.Check_ProcessName(vmcfg.GetVmName())
	processMap = vmcfg.GetProcessMap()	
	#pdb.set_trace()

	for k,v in sorted(processMap.items()):
		print k+" "+v
		if k not in vmProcessList:
			ProcessActionStr(k, v, vmCmd) 
def CheckVMSystemCall(vmcfg, vmCmd):
	if volatility.Is_SystemCallHooked(vmcfg.GetVmName())	:
		vmCmd.SetRestartVM()
	   
if __name__ == "__main__":
    #config.add_help_hook(list_plugins)
    vmlist = { 'vm02':'', '':''}
    
    try:
	
        volatility = Volatility() 
	data = volatility.Check_Process("vm02")
	#pdb.set_trace()	
	CheckVMS()
    except Exception, ex:
        #if config.DEBUG:
            debug.post_mortem()
        #else:
        #    raise
    except KeyboardInterrupt:
        print "Interrupted"
