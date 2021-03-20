# BMC-SDN
BMC-SDN is Blockchain-based Multi-controller Architecture for Secure Software-defined Networks
This code shows how to deploy a secure multi-controller SDN architecture using MultiChain. First we need to install MININET and then install and configure the controller ONOS and MultiChain.
In this code, we deploy three controllers using three IP addresses 192.168.1.39, 192.168.1.40, 192.168.1.41.

In mininet's VM, we run the command:
$ sudo mn –custom /mininet/custom/newtopo.py –topo mytopo –controller = remote, ip = 192.168.1.40

We create a custom topology in the newtopo.py file using the IP addresses of the three controllers. We run the below command on mininet's VM:
$ sudo ovs-vsctl set-controller s1 tcp: 192.168.1.39: 6653 tcp: 192.168.1.40: 6653 tcp: 192.168.1.41: 6653

For each Vswitch, we give the addresses of the master and redundant controllers.
ONOS> device-role of: 000000000000000c 192.168.1.39 master

Installation of Multichain:
The installation is done on the three controllers using the below steps:
• su (enter the root password)
• cd / tmp
• wget https: //www.multichain.com/download/multichain-2.0.2.tar.gz
• tar -xvzf multichain-2.0.2.tar.
• multichain-2.0.2 cd
• mv multichaind multichain-cli multichain-util / usr / local / bin
• exit (go back to your usual user)
To create a chain, we execute the following command:
multichain-util create chain_sdn1
Initialize the blockchain, including the exploitation of the genesis block:
multichaind chain_sdn1 -daemon
We now have the IP address and the port, so we can connect to this BlockChain:
multichaind chain_sdn1@192.168.1.41: 6747
Now, run the following command on each controller to connect to the blockchain:
multichaind chain_sdn1 -daemon
*************************************************************************************************
Below is the used python script
*************************************************************************************************
import requests
from requests.auth import HTTPBasicAuth
import json
import sys
import pprint
import time, threading
import binascii
import timeit
from termcolor import colored, cprint
from Savoir import Savoir
import logging
from logging.handlers import RotatingFileHandler

def is_json(myjson):
	try:
		json_object = json.loads(myjson)
		return True
	except ValueError as e:
		return False


def safe_json(data):
    if data is None:
        return True
    elif isinstance(data, (bool, int, float)):
        return True
    elif isinstance(data, (tuple, list)):
        return all(safe_json(x) for x in data)
    elif isinstance(data, dict):
        return all(isinstance(k, str) and safe_json(v) for k, v in data.items())
    return False
  

def compare_flows(flow1,flow2):
	if len(flow1["flows"]) == len(flow2["flows"]) :
		flow11=flow1
		flow22=flow2 	
		for flow in flow11["flows"]:
			flow.pop('life',None)
			flow.pop('packets',None)
			flow.pop('bytes',None)
			flow.pop('lastSeen',None)
		for flow in flow22["flows"]:
			flow.pop('life',None)
			flow.pop('packets',None)
			flow.pop('bytes',None)
			flow.pop('lastSeen',None)
		if (flow11 != flow22): 
			return "false"
		else : 
			return "true"
	else : 	
		return "false"

		
def compare_topology(topo1,topo2):
	topo11=topo1
	topo22=topo2 	
	topo11.pop('time',None)
	topo22.pop('time',None)
	if(topo11 != topo22): 	
		return "false"
		
	else : 
		return "true"
	
		
		

def pending(flow1):
	for flow in flow1["flows"]:
		if flow["state"] != "ADDED" :
			print(flow["state"]+' ===> flow still panding')				
			return "true"
	return "false"
	
	
def stillmac(flow1):	
	for flow in flow1["flows"]:
		for element in flow["selector"]["criteria"] :
			if element["type"] == "ETH_DST" :
				print(element["type"]+' ===> flow stillmac')
				return "true"
	return "false"


def insert_flows(flow1):
	flow11=flow1	
	for flow in flow11["flows"]:
		flow.pop('life',None)
		flow.pop('packets',None)
		flow.pop('bytes',None)
		flow.pop('lastSeen',None)
		flow.pop('id',None)
		flow.pop('tableId',None)
		flow.pop('groupId',None)
	headers = {'Content-Type':'application/json' , 'Accept':'application/json'}
	response = requests.post('http://localhost:8181/onos/v1/flows?appId=org.onosproject.core', data=flow11, auth=('onos', 'rocks'), headers=headers)
	print (response.status_code)


def insert_hosts(host1):
	host11=host1
	headers = {'Content-Type':'application/json' , 'Accept':'application/json'}
	for host in host11["hosts"] :
		#host1 = json.dumps(host)
		response = requests.post('http://localhost:8181/onos/v1/hosts', data=host, auth=('onos', 'rocks'), headers=headers)
		print (response.status_code)


def insert_topology(topology1):		
	topology11=topology1
	topology11.pop('time',None)
	headers = {'Content-Type':'application/json' , 'Accept':'application/json'}
	response = requests.post('http://localhost:8181/onos/v1/topology', data=topology11, auth=('onos', 'rocks'), headers=headers)
	print (response.status_code)

	
def compare_blocks(block1, block2):
	if(block1[0]['txid'] != block2[0]['txid']):
		#print (block1[0]['txid'])
		#print (block2[0]['txid'])
		return 'false'
	else: 
		return 'true'	
	

def post_flows(current_flow):
	while True:
		get_flows = requests.get(url,auth=('onos', 'rocks'))
		#print(get_flows.status_code)
		get_flows_json = get_flows.json()
		if compare_flows(current_flow,get_flows_json) == "false" :
			current_flow = get_flows_json
			step_f3 = timeit.default_timer()
			with open('data.json', 'w') as json___file:
				json.dump(get_flows_json,json___file)
				json___file.close()	
		else :
			#print('the same flows')
			pass
		time.sleep(0.1)	


def post_flows1(current_flow1):
	while True:
		#get_flows = requests.get(url,auth=('onos', 'rocks'))
		#print(get_flows.status_code)
		with open('data.json') as json_file:  
			get_flows_json = json.load(json_file)
		if compare_flows(current_flow1,get_flows_json) == "false" :
			global step_f1
			step_f1 = timeit.default_timer()
			cprint('change in the flows detected at : '+str(step_f1),'white','on_grey')			
			#print(len(current_flow1["flows"]))
			current_flow1 = get_flows_json
			#cprint('changes in the flows','white','on_grey')
			while(pending(current_flow1)=="true") : 
				get_flows = requests.get(url,auth=('onos', 'rocks'))
				#print(get_flows.status_code)
				get_flows_json = get_flows.json()
				current_flow1 = get_flows_json
				time.sleep(1)
			
			step_f2 = timeit.default_timer()
			cprint('begining flow consensus at : '+str(step_f2-step_f1),'white','on_grey')
			urlbackup= 'http://192.168.1.40:8181/onos/v1/flows'
			get_backup_flows = requests.get(urlbackup,auth=('onos','rocks'))
			get_backup_flows_json = get_backup_flows.json()
			if compare_flows(current_flow1,get_backup_flows_json) == "false" :
				step_ff2=timeit.default_timer()
				cprint('flows consensus not reatched : '+str(step_ff2-step_f1),'white','on_red' )
				logger.warning('flows consensus not reatched, consensus level = 0 % , senderIp: 192.168.1.39 ')
			else :
				step_f3 = timeit.default_timer()
				cprint('flows consensus reached at : '+str(step_f3-step_f2),'white','on_grey')
				api.publish("sdn_flows","key1", {'json':current_flow1})
				global step_f4
				step_f4 = timeit.default_timer()
				cprint('flows posted to block chain at : '+str(step_f4-step_f3),'white','on_grey')
				#with open('data.json', 'w') as outfile:
					#json.dump(current_flow1, outfile) 
		else :
			#print('the same flows')
			pass
		time.sleep(1)
		



def post_hosts(current_hosts):
	while True:
		get_hosts = requests.get(url2,auth=('onos','rocks'))
		get_hosts_json = get_hosts.json()
		if current_hosts != get_hosts_json :
			#pprint.pprint(current_hosts)
			#print ('--------------')
			#pprint.pprint(get_hosts_json)
			current_hosts = get_hosts_json
			cprint('changes in the hosts','grey','on_green')
			global step_h1
			step_h1 = timeit.default_timer()
			urlbackup= 'http://192.168.1.40:8181/onos/v1/hosts'
			get_backup_hosts = requests.get(urlbackup,auth=('onos','rocks'))
			get_backup_hosts_json = get_backup_hosts.json()
			if current_hosts != get_backup_hosts_json :
				cprint('hosts consensus not reatched','grey','on_green')
			else :
				cprint('hosts consensus reached','grey','on_green')
				step_h2 = timeit.default_timer()
				cprint('host consensus reached at : '+str(step_h2-step_h1),'grey','on_green')
				api.publish("sdn_hosts","key1", {'json':current_hosts})
				global step_h3
				step_h3 = timeit.default_timer()
				cprint('hosts posted to block chain at : '+str(step_h3-step_h2),'grey','on_green')
		else :
			#print('the same hosts')
			pass
		time.sleep(1)
		

def post_topology(current_topology):
	while True:
		get_topology=requests.get(url3,auth=('onos','rocks'))
		get_topology_json=get_topology.json()
		if compare_topology(current_topology, get_topology_json) == "false" :
			current_topology = get_topology_json
			cprint('changes in the topology','white','on_cyan')
			global step_t1
			step_t1 = timeit.default_timer()
			urlbackup= 'http://192.168.1.40:8181/onos/v1/topology'
			get_backup_topology = requests.get(urlbackup,auth=('onos','rocks'))
			get_backup_topology_json = get_backup_topology.json()
			if compare_topology(current_topology, get_backup_topology_json) == "false" :
				cprint('topology consensus not reatched','white','on_cyan')
			else :
				cprint('topology consensus reached','white','on_cyan')
				step_t2 = timeit.default_timer()
				cprint('topology consensus reached at : '+str(step_t2-step_t1),'white','on_cyan')
				api.publish("sdn_topology","key1", {'json':current_topology})
				global step_t3
				step_t3 = timeit.default_timer()
				cprint('topology posted to block chain at : '+str(step_t3-step_t2),'white','on_cyan')
		else :
			#print('the same topology')
			pass
		time.sleep(1)
		


def update_flows(current_bc_flows):
	while True:
		get_bc_flows=api.liststreamkeyitems("sdn_flows","key1",bool("foo"),1)
		get_bc_flows_json=json.loads(json.dumps(get_bc_flows))
		if compare_blocks(current_bc_flows, get_bc_flows_json) == "false" :
			current_bc_flows = get_bc_flows_json
			if(get_bc_flows_json[0]['publishers'][0] != myaddress):
				cprint('updating the flows','white','on_grey')
				insert_flows(current_bc_flows[0]['data']['json'])
				cprint('flows updated from blockchain at : '+time.ctime(),'white','on_grey')	
			else:
				cprint('new flows from me','white','on_grey')
				
				pass
			step_f5 = timeit.default_timer()
			cprint('flows updated from BC at : '+str(step_f5-step_f4),'white','on_grey')
			cprint('The total time for execution : '+str(step_f5-step_f2),'white','on_grey')	
		else :
			#print('no flows updates')
			pass
		time.sleep(0.01)
		


def update_hosts(current_bc_hosts):
	while True:
		get_bc_hosts=api.liststreamkeyitems("sdn_hosts","key1",bool("foo"),1)
		get_bc_hosts_json=json.loads(json.dumps(get_bc_hosts))
		if compare_blocks(current_bc_hosts, get_bc_hosts_json) == "false" :
			current_bc_hosts = get_bc_hosts_json
			if(get_bc_hosts_json[0]['publishers'][0] != myaddress):
				cprint('updating the hosts','grey','on_green')
				insert_hosts(current_bc_flows[0]['data']['json'])
			else:
				cprint('new hosts from me','grey','on_green')
				step_h4 = timeit.default_timer()
				cprint('hosts updated from BC at : '+str(step_h4-step_h3),'grey','on_green')
				cprint('The total host-time for execution : '+str(step_h4-step_h1),'grey','on_green')
				pass
					
		else :
			#print('no hosts updates')
			pass
		time.sleep(0.001)
		


def update_topology(current_bc_topology):
	while True:
		get_bc_topology=api.liststreamkeyitems("sdn_topology","key1",bool("foo"),1)
		get_bc_topology_json=json.loads(json.dumps(get_bc_topology))
		if compare_blocks(current_bc_topology, get_bc_topology_json) == "false" :
			current_bc_topology = get_bc_topology_json
			if(get_bc_topology_json[0]['publishers'][0] != myaddress):
				cprint('updating the topology','white','on_cyan')
				#insert_hosts(current_bc_flows[0]['data']['json'])
			else:
				cprint('new topology from me','white','on_cyan')
				step_t4 = timeit.default_timer()
				cprint('topology updated from BC at : '+str(step_t4-step_t3),'white','on_cyan')
				cprint('The total topology-time for execution : '+str(step_t4-step_t1),'white','on_cyan')
				pass	
		else :
			#print('no topology updates')
			pass
		time.sleep(0.01)


			
def log():
# creation of the logger object which will be used to write to the logs
    global logger 
    logger = logging.getLogger()
# on met le niveau du logger à DEBUG, comme ça il écrit tout
    logger.setLevel(logging.WARNING)
 
# creation of a formatter who will add the time at the level of each message when we write a message in the log
    formatter = logging.Formatter('%(asctime)s :: %(levelname)s :: %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
# creation of a handler which will redirect a log entry to a file in 'append' mode, 
# with 1 backup and a maximum size of 1MB
    file_handler = RotatingFileHandler('activity.log', 'a', 1000000, 1)
# we put the level on DEBUG, we tell him that he must use the formatter
# created previously and we add this handler to the logger
    file_handler.setLevel(logging.WARNING)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler) 
# creation of a second handler which will redirect each log write to the console
    #stream_handler = logging.StreamHandler()
    #stream_handler.setLevel(logging.DEBUG)
    #hyvlogger.addHandler(stream_handler)

log()


rpcuser = 'multichainrpc'
rpcpasswd = '2RPJYthqTCH1S1rz62iLFJb62DEVRiomPy9VKLmeVJVb'
rpchost = '127.0.0.1'
rpcport = '6746'
chainname = 'chain_sdn1'

api = Savoir(rpcuser, rpcpasswd, rpchost, rpcport, chainname)
#print(api.getinfo())

myaddress='1DNTCuJ62djSorwZ5cNE7yku64MZmQJdpsSaTM'

url = 'http://192.168.1.39:8181/onos/v1/flows'
url2= 'http://192.168.1.39:8181/onos/v1/hosts'
url3= 'http://192.168.1.39:8181/onos/v1/topology'

get_flows = requests.get(url,auth=('onos', 'rocks'))
get_flows_json = get_flows.json()

get_hosts = requests.get(url2,auth=('onos','rocks'))
get_hosts_json = get_hosts.json()

get_topology=requests.get(url3,auth=('onos','rocks'))
get_topology_json=get_topology.json()

get_bc_flows=api.liststreamkeyitems("sdn_flows","key1",bool("foo"),1)
get_bc_flows_json=json.loads(json.dumps(get_bc_flows))

get_bc_hosts=api.liststreamkeyitems("sdn_hosts","key1",bool("foo"),1)
get_bc_hosts_json=json.loads(json.dumps(get_bc_hosts))

get_bc_topology=api.liststreamkeyitems("sdn_topology","key1",bool("foo"),1)
get_bc_topology_json=json.loads(json.dumps(get_bc_topology))

current_flow = get_flows_json
current_flow1= get_flows_json  
with open('data.json', 'w') as json___file:
	json.dump(get_flows_json,json___file)
	json___file.close()

threading.Timer(1, post_flows,[current_flow]).start()
threading.Timer(1, post_flows1,[current_flow1]).start()

current_hosts = get_hosts_json

threading.Timer(1, post_hosts,[current_hosts]).start()

current_topology = get_topology_json

threading.Timer(1, post_topology,[current_topology]).start()

current_bc_flows = get_bc_flows_json

threading.Timer(1, update_flows,[current_bc_flows]).start()

current_bc_hosts=get_bc_hosts_json

threading.Timer(1, update_hosts,[current_bc_hosts]).start()

current_bc_topology=get_bc_topology_json

threading.Timer(1, update_topology,[current_bc_topology]).start()

#threading.Timer(1, send_attack_changes,[10]).start()

step_f1 = step_f2 = step_f3 = step_f4 = step_f5 = 0

step_h1 = step_h2 = step_h3 = step_h4 = 0

step_t1 = step_t2 = step_t3 = step_t4 = 0

print('all processus started at : '+time.ctime())

#text_color=['green','red','blue','yellow','white','grey','magenta','cyan']
#background_color=['on_green','on_red','on_blue','on_yellow','on_white','on_grey','on_magenta','on_cyan']

#for bc in background_color:
#	for tc in text_color:
#		cprint('Hello, World!',tc,bc)


#c_f=get_flows.text
#x=c_f
#x=binascii.hexlify(str.encode(x))
#y=str(x,'ascii')
#api.publish("d","key1", {'json':current_flow})
#yes=api.liststreamkeyitems("stream1","key1",bool("foo"),1)
#yes=json.loads(json.dumps(yes))
#x=binascii.unhexlify(x)
#y=str(x,'ascii')
#print(yes[0]['data'])


#print(type(get_flows))
#print(get_flows.status_code)
#api.create('stream', 'd', True)
#api.publish("d","key1", {'json':get_flows_json})
#elem=api.liststreamitems('d');
#pprint.pprint(elem)
#print(type(get_flows_json))
#pprint.pprint(get_flows_json)
