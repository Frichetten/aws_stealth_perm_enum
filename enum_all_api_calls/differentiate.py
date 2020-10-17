#!/usr/bin/env python3

# This script will read in both files and check for differences
# in the status code or the hash

no_perms = {}
with open('1.0-no-permissions-all', 'r') as r:
    for line in r:
        no_perms[line.split(":")[2]] = line[:-1]

# Iterate though all of the items and check if the status codes are different
# If they are, alert on them (checking by service name + action)
with open('1.0-yes-permissions-all', 'r') as r:
    for line in r:
        service_name = line.split(":")[2]
        no_perm_status_code = no_perms[service_name].split(":")[0]
        yes_perm_status_code = line.split(":")[0]
        
        no_perm_hash = no_perms[service_name].split(":")[3]
        yes_perm_hash = line.split(":")[3]

        if no_perm_status_code != yes_perm_status_code:
            # status code different
            print(line[:-1])

        else:
            # The status codes are the same, let's check the hashes
            # If they are different that is also a tell
            if no_perm_hash != yes_perm_hash:
                print(line[:-1])

        
