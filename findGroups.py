#!/usr/bin/env python

"""Outputs a list of meetup groups based on user search criteria to either an Excel file or prints the output to the console.

Search parameters can be passed in via the command line- else default parameters are used.
command line example: python findGroups.py --radius=10 --zip=02143 --text="python"

An api key can be obtained at https://secure.meetup.com/meetup_api/key/
"""

import argparse
import base64
import sys
import meetup_api_client as mac

TO_EXCEL = True
DEFAULT_ZIP_CODE = '92024'
DEFAULT_RADIUS = '25'
DEFAULT_SEARCH_PARAM = 'Python'

if __name__ == '__main__':
    #get user API key from config file
    try:
        import config
    except:
        print("\nFailed to import config file- please run setup.py")
    KEY = base64.b64decode(config.credentials['api_key']).decode()
    client = mac.Meetup(KEY)

    #if user entered command line arguments
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser()
        parser.add_argument('--zip', dest='zip', help='Zip code used for radial search')
        parser.add_argument('--radius', dest='radius', help='Radius to search in miles')
        parser.add_argument('--text', dest='text', help='Text to search for in group name / description')

        args = parser.parse_args()
        print('\nArguments Inputted: '+str(args))
        groups = client.find_groups(zip=args.zip, radius=args.radius, text=args.text, order="members")
        
    #else no cmd line arguments- use default arguments
    else:
        extra_fields = 'last_event, past_event_count'
        sort_on = 'members'

        kwargs = {'zip':DEFAULT_ZIP_CODE, 'radius':DEFAULT_RADIUS, 'text':DEFAULT_SEARCH_PARAM, 'fields':extra_fields, 'order':sort_on}
        print('\nNo command line arguments supplied, default arguments are {}'.format(kwargs))
        groups = client.find_groups(**kwargs)
    

    if TO_EXCEL:
        from MeetupDF import MeetupDF
        df = MeetupDF(groups)
        try:
            df = df.edit_df(extra_fields)
        except:    
            df = df.edit_df()
        df.save_wb(title = search_param + ' Meetup Groups')

    else:    
        print('\n')
        for group in groups:
            print((str(group['id']) + ': ' + group['name'] + ' (' + str(group['members']) + ' members)'))
