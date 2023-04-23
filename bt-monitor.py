import subprocess
import sys
import os
import argparse
import csv

ip_src = 1
ip_dst = 2
port_src = 3
port_dst = 4
info_col = 5
bt_dht_bencoded_string = 6
bt_id = 7
bt_ip = 8
bt_port = 9

def call_tshark(filename, call):
    filename_csv = "./csv/{name}.csv".format(name=filename)
    file_out = open(filename_csv, "w")
    tshark_run = subprocess.call(call, shell=True, stdout=file_out, stderr=subprocess.STDOUT)
    if tshark_run != 0:
        error_msg = "Error: tshark call was unsuccessful. See csv/{name}.csv for further information.".format(name=filename)
        sys.exit(error_msg)

def init_flag():
    # get DNS queries for bootstrap nodes
    dns_bs_filters = "udp.srcport == 53 && (dns.qry.name contains dht || dns.qry.name contains router) && dns.resp.type == 1"
    dns_bs_call = "tshark -r {pcap} -T fields -E separator=';' -Y \"{filter}\" -e frame.time_relative -e dns.qry.name -e dns.a".format(pcap=args.pcap, filter=dns_bs_filters)
    call_tshark("dns_bs_file", dns_bs_call)
    with open("./csv/dns_bootstrap.csv", newline='') as dns_bs_csv:
        ##TODO if empty, signatury nebo 8999
        reader = csv.reader(dns_bs_csv, delimiter=";")
        bootstrap_list = {}
        for rows in reader:
            ips = rows[2].split(",")
            for ip in ips:
                bootstrap_list[ip] = rows[1]

    # get BT-DHT initial requests to bootstrap nodes
    ## find out port used for BT-DHT from initial requests
    nodes_bs_filters = "" 
    for key in bootstrap_list.keys():
        nodes_bs_filters += "ip.dst == " + key + " || "
    nodes_bs_filters = nodes_bs_filters[:len(nodes_bs_filters)-4]
    nodes_bs_call = "tshark -r {pcap} -T fields -E separator=';' -Y \"{filter}\" -e frame.time_relative -e udp.srcport".format(pcap=args.pcap, filter=nodes_bs_filters)
    call_tshark("nodes_bs_file", nodes_bs_call)
    with open("./csv/nodes_bootstrap.csv", newline='') as node_bs_csv:
        reader = csv.reader(node_bs_csv, delimiter=";")
        row1 = next(reader)
        dht_port = row1[1]
    ## get all BT-DHT communication as a csv file
    btdht_call = "tshark -r {pcap} -d udp.port=={port},bt-dht -T fields -E separator=';' -E header=y -e frame.time_relative -e ip.src -e ip.dst -e udp.srcport -e udp.dstport -e _ws.col.Info -e bt-dht.bencoded.string -e bt-dht.id -e bt-dht.ip -e bt-dht.port \"bt-dht\"".format(pcap=args.pcap, port=dht_port)
    call_tshark("bt_dht", btdht_call)

    # collect information about initial bootstrapping
    with open("./csv/bt_dht.csv", newline='') as btdht_csv:
        reader = csv.reader(btdht_csv, delimiter=";")
        for key in bootstrap_list.keys():
            req = False
            res = False
            btdht_csv.seek(0)
            for rows in reader:
                if req == False and rows[ip_dst] == key and "bs" in rows[bt_dht_bencoded_string]:
                    tID_index = rows[bt_dht_bencoded_string].find("t,")
                    if tID_index == -1:
                        sys.exit("Invalid BT-DHT packet.")
                    tID = rows[bt_dht_bencoded_string][tID_index+2:tID_index+6]
                    bootstrap_list[key] += "\n1 initial request sent to port {port}, transaction ID {id}\n".format(port=rows[port_dst], id=tID)
                    req = True
                    continue
                if req == True and tID in rows[bt_dht_bencoded_string]:
                    bootstrap_list[key] += "1 response received: {info}\n".format(info=rows[info_col])
                    res = True
                    break
            if req == False:
                bootstrap_list[key] += "\nno initial request sent\n"
            if req == True and res == False:
                bootstrap_list[key] += "no response received\n"
    for key in bootstrap_list.keys():
        print("{key} : {val}".format(key=key, val=bootstrap_list[key]))

def peer_flag():
    # get BT-DHT port number
    btdht_port_call = "tshark -r {pcap} -a packets:1 -T fields -Y \'udp contains \"get_peers\" || udp contains \"find_node\"\' -E separator=';' -e udp.srcport".format(pcap=args.pcap)
    try:
        dht_port_s = subprocess.check_output(btdht_port_call, shell=True)
    except subprocess.CalledProcessError as e:
        sys.exit("Error: tshark call was unsuccessful.")
    if not dht_port_s:
        sys.exit("Error: BT-DHT port not found. Possibly no BT-DHT requests in the input capture or TShark version is not 4.0.0 or higher.")
    dht_port = int(dht_port_s)
    # get all BT-DHT communication as a csv file
    btdht_call = "tshark -r {pcap} -d udp.port=={port},bt-dht -T fields -E separator=';' -E header=y -e frame.time_relative -e ip.src -e ip.dst -e udp.srcport -e udp.dstport -e _ws.col.Info -e bt-dht.bencoded.string -e bt-dht.id -e bt-dht.ip -e bt-dht.port \"bt-dht\"".format(pcap=args.pcap, port=dht_port)
    call_tshark("bt_dht", btdht_call)
    # get information about neighbours (filter responses only)
    nodes_list = {}
    with open("./csv/bt_dht.csv", newline='') as btdht_csv, open("./csv/bt_dht_nodes_peers.csv", "w", newline='') as btdht_csv_np:
        reader = csv.reader(btdht_csv, delimiter=";")
        responses_f = filter(lambda p: 'y,r' in p[bt_dht_bencoded_string], reader)
        csv.writer(btdht_csv_np, delimiter=";").writerows(responses_f)
    with open("./csv/bt_dht_nodes_peers.csv", newline='') as btdht_csv_np:
        reader = csv.reader(btdht_csv_np, delimiter=";")
        for rows in reader:
            node_id_i = rows[bt_dht_bencoded_string].find("id,")
            node_id = rows[bt_dht_bencoded_string][node_id_i+3:node_id_i+43]
            if (node_id in nodes_list):
                nodes_list[node_id][2] += 1
            else:
                nodes_list[node_id] = list((rows[ip_src], rows[port_src], 1))
        for key in nodes_list.keys():
            print("Node ID {id}: {ip}:{port}, {conn} connection(s)".format(id=key, ip=nodes_list[key][0], port=nodes_list[key][1], conn=nodes_list[key][2]))

# parse arguments
parser = argparse.ArgumentParser()
parser.add_argument('-pcap', type=str, required=True)
parser.add_argument('-init', action='store_true')
parser.add_argument('-peers', action='store_true')
parser.add_argument('-download', action='store_true')
args = parser.parse_args()



if args.init:
    init_flag()
if args.peers:
    peer_flag()
