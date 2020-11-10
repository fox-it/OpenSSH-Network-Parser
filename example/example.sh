mkdir /tmp/ssh

#parse pcap output only in/output data
network-parser -p dump_ssh.pcap --popt keyfile=keys.json --proto ssh -o /tmp/ssh/

#parse pcap, output verbose information
network-parser -p dump_ssh.pcap --popt keyfile=keys.json --proto ssh -o /tmp/ssh/ -vvvv