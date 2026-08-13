import json
from config import *

with open(RULES_FILE, 'r') as f:
    rules = json.load(f)

ip_blacklist = rules[IP_LST_N]
port_blacklist = rules[PORt_LST_N]