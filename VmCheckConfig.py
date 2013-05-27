import xml.dom.minidom
import pdb
 
class VmCheckConfig(object):
	processMap = {}
 	vmname = ""
	profile = ""
	def __init__(self, vmname, processMap, profile):
		self.vmname = vmname
		self.processMap = processMap
		self.profile = profile

	def GetProcessMap(self):
		return self.processMap;
	def GetVmName(self):
		return self.vmname

def GetVmCheckConfigs(fileName):
	dom = xml.dom.minidom.parse(fileName)
	vmCheckCfgList = []
	vms = dom.getElementsByTagName("vm")	
	for vm in vms:
		profile = vm.getElementsByTagName("profile")[0].childNodes[0].data
		processes = vm.getElementsByTagName("process")[0]
		pitems = processes.getElementsByTagName("item")

	#	pdb.set_trace()

		pmap = {}
		for p in pitems:
			pname = p.attributes['name'].value
			paction = p.childNodes[0].data
			pmap[pname] = paction;
			#print " "+pname+" "+pmap[pname]
		vname = vm.attributes['name'].value
		print " "+vname+" "+profile	
		cfg = VmCheckConfig(vname, pmap, profile)
		vmCheckCfgList.append(cfg)	

	return vmCheckCfgList
	
if __name__ == "__main__":
	vmCfgs = GetVmCheckConfigs("./vms.cfg")
	
document = """\	
<vmlist>
	<vm name="vm01">
		<profile>Linuxcentos5_5x86</profile>
		<process>
			<item name="sshd">restartP</item>
			<item name="gnome">restartP</item>
			<item name="init">restartV</item>
		</process>
	</vm>
	<vm name="vm02">
		<profile>Linuxcentos5_5x86</profile>
		<process>
			<item name="sshd">restartP</item>
			<item name="gnome">restartP</item>
			<item name="init">restartV</item>
		</process>
	</vm>
	<vm name="vm_xp">
		<profile>WindowsXPSP2</profile>
		<process>
			<item name="sshd">restartP</item>
			<item name="gnome">restartP</item>
			<item name="init">restartV</item>
		</process>
	</vm>
</vmlist>
"""
