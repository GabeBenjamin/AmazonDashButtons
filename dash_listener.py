#!/usr/bin/python
import time
import requests
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

from secrets import IFTTT_KEY

# Set these up at https://ifttt.com/maker
ifttt_toggle_lights = 'https://maker.ifttt.com/trigger/toggle_lights/with/key/' + IFTTT_KEY
ifttt_email = 'https://maker.ifttt.com/trigger/email/with/key/' + IFTTT_KEY

# Trigger a IFTTT URL. Body includes JSON with timestamp values.
def trigger_ifttt_with_name(name):
  print "Found Button '{}'".format(name)
  data = {
        'value1': time.strftime("%Y-%m-%d"),
        'value2': time.strftime("%H:%M"),
        'value3': "SOURCE: {}".format(name)
  }
  print "IFTTT RESPONSE: {}".format(requests.post(ifttt_toggle_lights, data=data))

def udp_filter(pkt):
  options = pkt[DHCP].options
  for option in options:
    if isinstance(option, tuple):
      if 'requested_addr' in option:
        # we've found the IP address, which means its the second and final UDP request, so we can trigger our action
        mac_to_action[pkt.src](mac_to_name[pkt.src])
        break


mac_to_action = {'b4:7c:9c:95:ae:e1': trigger_ifttt_with_name}
mac_to_name = {'b4:7c:9c:95:ae:e1': 'hershey'}
mac_id_list = list(mac_to_action.keys())

print "Waiting for a button press..."
email_data = {'value1': 'Dash button listener started!'}
print "IFTTT RESPONSE: {}".format(requests.post(ifttt_email, data=email_data))

sniff(prn=udp_filter, store=0, filter="udp", lfilter=lambda d: d.src in mac_id_list)

if __name__ == "__main__":
  main()
