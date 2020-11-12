# OpenSSH Network Parser
Project to decrypt and parse OpenSSH traffic. More information can be found in [this blogpost](https://blog.fox-it.com/2020/11/11/decrypting-openssh-sessions-for-fun-and-profit/).


# Usage
```
network-parser -p my_pcap.pcap -o my/output/dir --proto=[protocol] [--popt key=value] [-s] [-vvvv] 
```

Possible values for --proto are base and ssh. Base will parse some basic packet information.
--popt is used to pass additional information to the network parser. The SSH parser supports one required parameter called 'keyfile'. An example:

```
network-parser -p my_pcap.pcap --proto=ssh --popt keyfile=keys.json -o /tmp/ssh/ -s 
```
