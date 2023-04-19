import subprocess
import sys
import os
import csv

bt_dht_bencoded_string = 5
ip_dst = 1
port_dst = 3
info_col = 4

def init_flag(bs_dict):
    with open("./csv/bt_dht.csv", newline='') as btdht_csv:
        reader = csv.reader(btdht_csv, delimiter=";")
        for key in bs_dict.keys():
            req = False
            res = False
            btdht_csv.seek(0)
            for rows in reader:
                if req == False and rows[ip_dst] == key and "bs" in rows[bt_dht_bencoded_string]:
                    tID_index = rows[bt_dht_bencoded_string].find("t,")
                    if tID_index == -1:
                        sys.exit("Invalid BT-DHT packet.")
                    tID = rows[bt_dht_bencoded_string][tID_index+2:tID_index+6]
                    bs_dict[key] += "\n1 initial request sent to port {port}, transaction ID {id}\n".format(port=rows[port_dst], id=tID)
                    req = True
                    continue
                if req == True and tID in rows[bt_dht_bencoded_string]:
                    bs_dict[key] += "1 response received: {info}\n".format(info=rows[info_col])
                    res = True
                    break
            if req == False:
                bs_dict[key] += "\nno initial request sent\n"
            if req == True and res == False:
                bs_dict[key] += "no response received\n"
    for key in bs_dict.keys():
        print("{key} : {val}".format(key=key, val=bs_dict[key]))

# get bootstrap nodes
dns_bs_filters = '"udp.srcport == 53 && (dns.qry.name contains dht || dns.qry.name contains router) && dns.resp.type == 1"'
dns_bs_call = "tshark -r ./pcap/tcp_only.pcap -T fields -E separator=';' -Y " + dns_bs_filters + " -e dns.qry.name -e dns.a"
dns_bs_file = open("./csv/dns_bootstrap.csv", "w")
tshark_run = subprocess.call(dns_bs_call, shell=True, stdout=dns_bs_file, stderr=subprocess.STDOUT)
if tshark_run != 0:
    sys.exit('Error: tshark call was unsuccessful. See csv/dns_bootstrap.csv for further information.')
with open("./csv/dns_bootstrap.csv", newline='') as dns_bs_csv:
    reader = csv.reader(dns_bs_csv, delimiter=";")
    bootstrap_list = {}
    for rows in reader:
        ips = rows[1].split(",")
        for ip in ips:
            bootstrap_list[ip] = rows[0]

# get BT-DHT initial requests to bootstrap nodes
## find out port used for BT-DHT from initial requests
nodes_bs_filters = "" 
for key in bootstrap_list.keys():
    nodes_bs_filters += "ip.dst == " + key + " || "
nodes_bs_filters = nodes_bs_filters[:len(nodes_bs_filters)-4]
nodes_bs_call = "tshark -r ./pcap/tcp_only.pcap -T fields -E separator=';' -Y \"" + nodes_bs_filters + "\" -e udp.srcport"
nodes_bs_file = open("./csv/nodes_bootstrap.csv", "w")
tshark_run = subprocess.call(nodes_bs_call, shell=True, stdout=nodes_bs_file, stderr=subprocess.STDOUT)
if tshark_run != 0:
    sys.exit('Error: tshark call was unsuccessful. See csv/nodes_bootstrap.csv for further information.')
with open("./csv/nodes_bootstrap.csv", newline='') as node_bs_csv:
    reader = csv.reader(node_bs_csv, delimiter=";")
    row1 = next(reader)
    dht_port = row1[0]
## get all BT-DHT communication as a csv file
btdht_call = "tshark -r ./pcap/tcp_only.pcap -d udp.port=={port},bt-dht -T fields -E separator=\";\" -E header=y -e ip.src -e ip.dst -e udp.srcport -e udp.dstport -e _ws.col.Info -e bt-dht.bencoded.string -e bt-dht.ip -e bt-dht.port -e bt-dht.id \"bt-dht\"".format(port=dht_port)
btdht_file = open("./csv/bt_dht.csv", "w")
tshark_run = subprocess.call(btdht_call, shell=True, stdout=btdht_file, stderr=subprocess.STDOUT)
if tshark_run != 0:
    sys.exit('Error: tshark call was unsuccessful. See csv/bt_dht.csv for further information.')

init_flag(bootstrap_list)