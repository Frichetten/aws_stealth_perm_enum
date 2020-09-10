#!/usr/bin/env python3
import json, pprint

output = {}
with open('final-vuln-api-list.txt','r') as r:
    for line in r:
        split = line.split(" ")
        # I'm aware how bad this code is, mistakes were made. It just needs to run once
        if split[1][:-1]+":"+split[0][:split[0].find(":")] not in output.keys():
            output[split[1][:-1]+":"+split[0][:split[0].find(":")]] = []

        output[split[1][:-1]+":"+split[0][:split[0].find(":")]].append(split[0][split[0].find(":")+1:])
            
pp = pprint.PrettyPrinter(indent=3)
pp.pprint(output)
