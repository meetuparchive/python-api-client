import pandas as pd
import re
import os
from datetime import datetime

pd.options.mode.chained_assignment = 'raise'

class MeetupDF(pd.DataFrame):
        
    @property
    def _constructor(self):
        return MeetupDF

    @staticmethod
    def clean_description(desc):
        #remove html tags
        desc = re.sub('<[^>]+>', '', desc)
        desc_spl = desc.split('.')

        for i, sentence in enumerate(desc_spl):
            sentence = sentence + '.'
            if i == 0:
                new_desc = sentence
            elif len(new_desc) < 285:
                new_desc = new_desc + sentence
            else:
                break

        new_desc = new_desc.replace('\n', '')
        new_desc = new_desc.replace('&nbsp', '')
        return new_desc

    @staticmethod
    def parse_extra_col_names(extra_fields):
        s = extra_fields.replace(' ','')
        return s.split(',')

    def edit_df(self, extra_fields=None):
        col_to_keep = ['name','members', 'city', 'description', 'next_event', 'join_mode','link','score']
        if extra_fields is not None:
            extra_cols = self.parse_extra_col_names(extra_fields)
            col_to_keep = col_to_keep + extra_cols

        self = self[col_to_keep]
        self = self.rename(columns={'score':'relevancy_score'})
        self['description'] = self['description'].apply(self.clean_description)

        if 'last_event' in col_to_keep:
            self['prev_event_name'] = self['last_event'].apply(lambda x: x['name'] if pd.notnull(x) else -1)
            self['prev_event_rsvp_count'] = self['last_event'].apply(lambda x: x['yes_rsvp_count'] if pd.notnull(x) else -1)
            self.drop(['last_event'], axis=1, inplace=True)

        self['next_event_name'] = self['next_event'].apply(lambda x: x['name'] if pd.notnull(x) else -1)
        self['next_event_time'] = self['next_event'].apply(lambda x: datetime.fromtimestamp(x['time']/1000) if pd.notnull(x) else -1)
        self['next_event_rsvp_count'] = self['next_event'].apply(lambda x: x['yes_rsvp_count'] if pd.notnull(x) else -1)
        self.drop(['next_event'], axis=1, inplace=True)

        self = self.sort_values(['members'],ascending=False)
        return self

    def save_wb(self, path = os.path.expanduser('~/Documents/'), title = 'Meetup Groups'):
        print('\nsaving excel file to {}'.format(path))
        writer = pd.ExcelWriter(path+ datetime.now().strftime("%Y-%m-%d ") + title + '.xlsx',engine='xlsxwriter', date_format = "m/d/yyy",datetime_format = "m/d/yyy")
        self.to_excel(writer,sheet_name=title, merge_cells=False,index=False)
        writer.save()

    
