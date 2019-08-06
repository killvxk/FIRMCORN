import subprocess
from time import sleep
import sys
radamsa_bin = '/usr/bin/radamsa'
def mutate(payload):
    try:
        radamsa = [radamsa_bin, '-n', '1', '-']
        p = subprocess.check_output(radamsa, shell = False)
        mutated_data = p.communicate(payload)[0]
    except:
        print "Could not execute 'radamsa'."
        sys.exit(1)

    return mutated_data

payload = "sss"
payload = mutate(payload)