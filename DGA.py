

import Locky
import re
import numpy
import string
import random
from datetime import date
from datetime import datetime
from hashlib import sha3_256
from hashlib import sha3_512

def example_dga1(int_seed, date_str = None):
    if date_str == None:
        date_str = '{0.year}-{0.month}-{0.day}'.format(date.today())

    domain_suffixes = [".com", ".net", ".gov", ".uk.co",".edu", ".ca.co"]
    hash = sha3_256('{0}{1}'.format(date_str, int_seed).encode()).hexdigest()[0:(25+(int_seed % 7))]
    replace_char = chr(0XFF & ((int_seed % 23)+ 107))

    return "{0}{1}{2}".format(replace_char, hash, domain_suffixes[int_seed % len(domain_suffixes)])

##This is a DGA called Locky. It was reverse engineered by Forcepoint (Associated with Raytheon).
## https://github.com/sourcekris/pyLockyDGA
## pos should be an int between 0 and 7
def example_dga2(pos):
    return Locky.LockyDGA(pos)

## A poor man DGA.
def example_dga3(int_seed, dateYMD = date.today()):

    domain_suffixes = [".com", ".net", ".com", ".uk.co",".com", ".ca.co"]

    fullSeed = (int_seed + (3 * dateYMD.day) + (5 * dateYMD.month) + (7* dateYMD.year)) % 0x1ef7 #1001st prime. 7927.
    random.seed(fullSeed)
    domain = "".join([random.choice(string.ascii_lowercase) for n in range((int_seed % 11) + 7)])

    return(domain + domain_suffixes[int_seed % len(domain_suffixes)])


# sha256, sha512 with hexdigest() return a string of hexadecimal digits (0-9,a-f).
# We also do a replace character insertion. This replace character is not guaranteed to be a valid domain character.
#     We clean any invalid characters away
def clean_domain(s):

    domain_regex = "[^\w._]" #\w is all alphanumeric characters.
    #Remove everything except a-zA-Z0-9 and . and _

    return(re.sub(domain_regex, '', s))

def print_domains(*domains):
    for d in domains:
        print(d, '\n')




our_domains1_raw = [example_dga1(seed) for seed in range(20)]

our_domains1_clean = [clean_domain(d) for d in our_domains1_raw]

#print(*our_domains1_clean, sep= '\n')

our_domains2 = [example_dga2(seed) for seed in range(8)]


with open("C:/Users/REESRD/PycharmProjects/DGA_Maker/Locky Domains/list.txt", "a") as f: #Append today's domains into a text file.
        f.writelines("%s\n" %d for d in our_domains2)


#print(*our_domains2, sep= '\n')

our_domains3 = [example_dga3(seed) for seed in range(100)]

print(*our_domains3, sep= '\n')


