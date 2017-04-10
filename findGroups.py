#!/usr/bin/env python
from __future__ import with_statement

# eg: python findGroups.py --apikey=$myKey --radius=10 --zip=02143 --text="python"
# get your key at https://secure.meetup.com/meetup_api/key/

import meetup_api_client as mac
from meetup_api_client import *
from optparse import OptionParser

if __name__ == '__main__':
    option = OptionParser('%prog --apikey --zip --radius --text')
    option.add_option('--apikey', dest='apikey', 
        help='API key')
    option.add_option('--zip', dest='zip',
        help='Zip code used for radial search')
    option.add_option('--radius', dest='radius',
        help='Radius to search in miles')
    option.add_option('--text', dest='text', 
        help='Text to search for in group name / description')
    (options, args) = option.parse_args()

    client = mac.Meetup(options.apikey)
    groups = client.find_groups(zip=options.zip, radius=options.radius, text=options.text, order="members")

    for group in groups:
    	print str(group['id']) + ': ' + group['name'] + ' (' + str(group['members']) + ' members)'

