#!/usr/bin/env python3
import json, pprint

# This tool is responsible for converting differentiate.py output into a json format
# Which can be interpretted by the proof_of_concept.py

output = {}
with open('differentiate_output.txt','r') as r:
    for line in r:
        line_parts = line[:-1].split(":")
        key = line_parts[4] + ":" + line_parts[1] + ":" + line_parts[0]
        if key not in output.keys():
            output[key] = [line_parts[2]]
        else:
            output[key].append(line_parts[2])
            
pp = pprint.PrettyPrinter(indent=3)
pp.pprint(output)
