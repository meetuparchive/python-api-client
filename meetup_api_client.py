#!/usr/bin/env python

import datetime
import oauth
import time
from urllib import urlencode
from urllib2 import HTTPError, urlopen, Request

# This is an example of a client wrapper that you can use to
# make calls to the Meetup.com API. It requires that you have 
# a JSON parsing module available.

API_JSON_ENCODING = 'ISO-8859-1'

try:
    try:
        import cjson
        parse_json = lambda s: cjson.decode(s.decode(API_JSON_ENCODING), True)
    except ImportError:
        try:
            import simplejson
            parse_json = lambda s: simplejson.loads(s.decode(API_JSON_ENCODING))
        except ImportError:
            import json
            parse_json = lambda s: _unicodify(json.read(s))
except:
    print "Error - your system is missing support for a JSON parsing library."

GROUPS_URI = 'groups'
EVENTS_URI = 'events'
CITIES_URI = 'cities'
TOPICS_URI = 'topics'
PHOTOS_URI = 'photos'
MEMBERS_URI = 'members'
RSVPS_URI = 'rsvps'
API_BASE_URL = 'http://api.meetup.com/'
OAUTH_BASE_URL = 'http://www.meetup.com/'


signature_method_plaintext = oauth.OAuthSignatureMethod_PLAINTEXT()
signature_method_hmac = oauth.OAuthSignatureMethod_HMAC_SHA1()

# TODO : restrict which URL parameters can be used in each of the API calls 
# TODO : screen bad queries before they go to the server 
# TODO : take care of bug with the JSON quoting (done)
# TODO : add the tests
# TODO : load the meta data from JSON (done)
# TODO : parse the 'updated' into a real python date object with strptime()
# TODO : add __str__ funcs for the objects that get created

class Meetup(object):
    def __init__(self, api_key):
        """Initializes a new session with an api key that will be added
        to subsequent api calls"""
        self.api_key = api_key

    def get_groups(self, **args):
        return API_Response(self._fetch(GROUPS_URI, **args), GROUPS_URI)
 
    def get_events(self, **args):
        return API_Response(self._fetch(EVENTS_URI, **args), EVENTS_URI) 

    def get_photos(self, **args):
        return API_Response(self._fetch(PHOTOS_URI, **args), PHOTOS_URI)
    
    def get_topics(self, **args):
        return API_Response(self._fetch(TOPICS_URI, **args), TOPICS_URI)

    def get_rsvps(self, **args):
        return API_Response(self._fetch(RSVPS_URI, **args), RSVPS_URI)

    def get_cities(self, **args):
        return API_Response(self._fetch(CITIES_URI, **args), CITIES_URI) 

    def get_members(self, **args):
        return API_Response(self._fetch(MEMBERS_URI, **args), MEMBERS_URI) 

    def _fetch(self, uri, **url_args):
        url_args['format'] = 'json'
        if self.api_key:
            url_args['key'] = self.api_key
        args = urlencode(url_args)
        url = API_BASE_URL + uri + '/' + "?" + args
        print "requesting %s" % (url)
        try:
           return parse_json(urlopen(url).read())
        except HTTPError, e:
           error_json = parse_json(e.read())
           if e.code == 401:
               raise UnauthorizedError(error_json)
           elif e.code in ( 400, 500 ):
               raise BadRequestError(error_json)
           else:
               raise ClientException(error_json)

class NoToken(Exception):
    def __init__(self, description):
        self.description = description

    def __str__(self):
        return "NoRequestToken: %s" % (self.description)


class MeetupOAuthSession:
    def __init__(self, consumer, request_token, access_token):
        self.consumer = consumer
        self.request_token = request_token
        self.access_token = access_token

    def fetch_request_token(self, signature_method=signature_method_hmac):
        oauth_req = oauth.OAuthRequest.from_consumer_and_token(self.consumer, http_url=(OAUTH_BASE_URL + 'oauth/request/'))
        oauth_req.sign_request(signature_method, self.consumer, None)
        token_string = urlopen(Request(oauth_req.http_url, headers=oauth_req.to_header())).read()
        self.request_token = oauth.OAuthToken.from_string(token_string)

    def get_authorize_url(self, oauth_callback=None):
        if oauth_callback:
            callbackUrl = "&" + urlencode({"oauth_callback":oauth_callback})
        else:
            callbackUrl = ""
        return OAUTH_BASE_URL + "authorize/?oauth_token=%s%s" % (self.request_token.key, callbackUrl)

    def fetch_access_token(self, signature_method=signature_method_hmac, request_token=None):
        temp_request_token = request_token or self.request_token
        if not temp_request_token:
            raise NoToken("You must provide a request token to exchange for an access token")
        oauth_req = oauth.OAuthRequest.from_consumer_and_token(self.consumer, token=temp_request_token, http_url=OAUTH_BASE_URL + 'oauth/access/')
        oauth_req.sign_request(signature_method, self.consumer, temp_request_token)
        token_string = urlopen(Request(oauth_req.http_url, headers=oauth_req.to_header())).read()
        self.access_token = oauth.OAuthToken.from_string(token_string)

class MeetupOAuth(Meetup):

    def __init__(self, oauth_consumer_key, oauth_consumer_secret, access_key=None, access_secret=None):
        self.oauth_consumer_key = oauth_consumer_key
        self.oauth_consumer_secret = oauth_consumer_secret
        self.consumer = oauth.OAuthConsumer(self.oauth_consumer_key, self.oauth_consumer_secret)
        if access_key and access_secret:
            self.oauth_session = self.new_session(access_key=access_key, access_secret=access_secret)

    def new_session(self, request_key=None, request_secret=None, access_key=None, access_secret=None):
        if request_secret and request_key:
            request_token = oauth.OAuthToken(request_key, request_secret)
        else: 
            request_token = None
        if access_secret and access_key:
            access_token = oauth.OAuthToken(access_key, access_secret)
        else: 
            access_token = None
        return MeetupOAuthSession(self.consumer, request_token, access_token)

    def _fetch(self, uri, sess=None, oauthreq=None, signature_method=signature_method_plaintext, **url_args):
        # the oauthreq parameter name is deprecated, please use sess or bind the session in __init__
        session = self.oauth_session or sess or oauthreq
        if not session:
            raise BadRequestError("MeetupOAuth client requires either a bound MeetupOAuthSession or one in the `sess` argument.")
        if not session.access_token:
            raise BadRequestError("Current MeetupOAuthSession does not have an access_token.")
        
        url_args['format'] = 'json'
        oauth_access = oauth.OAuthRequest.from_consumer_and_token(self.consumer, 
                                                                  token = session.access_token,
                                                                  http_url=API_BASE_URL + uri + "/",
                                                                  parameters=url_args)
        oauth_access.sign_request(signature_method, self.consumer, session.access_token)
        url = oauth_access.to_url()

        print "requesting %s" % (url)
        try:
           return parse_json(urlopen(url).read())
        except HTTPError, e:
           error_json = parse_json(e.read())
           if e.code == 401:
               raise UnauthorizedError(error_json)
           elif e.code == 500:
               raise BadRequestError(error_json)
           else:
               raise ClientException(error_json)


class API_Response(object):
    def __init__(self, json, uritype):
         """Creates an object to act as container for API return val. Copies metadata from JSON"""
         self.meta = json['meta']
         uriclasses = {GROUPS_URI:Group,
                       EVENTS_URI:Event,
                       TOPICS_URI:Topic,
                       CITIES_URI:City, 
                       MEMBERS_URI:Member,
                       PHOTOS_URI:Photo,
                       RSVPS_URI:Rsvp}
         self.results = [uriclasses[uritype](item) for item in json['results']]

    def __str__(self):
        return 'meta: ' + str(self.meta) + '\n' + str(self.results)

class API_Item(object):
    """Base class for an item in a result set returned by the API."""

    datafields = [] #override
    def __init__(self, properties):
         """load properties that are relevant to all items (id, etc.)"""
         for field in self.datafields:
             self.__setattr__(field, properties[field])

    def __repr__(self):
         return self.__str__();

class Member(API_Item):
    datafields = ['bio', 'name', 'link','id','photo_url', 'zip','lat','lon','city','state','country','joined','visited']
    
    def get_groups(self, apiclient, **extraparams):
        extraparams.update({'member_id':self.id})
        return apiclient.get_groups(extraparams);

    def __str__(self):
        return "Member %s (url: %s)" % (self.name, self.link)

class Photo(API_Item):
    datafields = ['albumtitle', 'link', 'member_url', 'descr', 'created']

    def __str__(self):
        return "Photo located at %s posted by member at %s: (%s)" % (self.link, self.member_url, self.descr)


class Event(API_Item):
    datafields = ['id', 'name', 'updated', 'time', 'photo_url', 'event_url']

    def __str__(self):
        return 'Event %s named %s at %s (url: %s)' % (self.id, self.name, self.time, self.event_url)

    def get_rsvps(self, apiclient, **extraparams):
        extraparams['event_id'] = self.id
        return apiclient.get_rsvps(**extraparams)

class Rsvp(API_Item):
    datafields = ['name', 'link', 'comment','zip','coord','lon','city','state','country','response','guests','answers','updated','created']

    def __str__(self):
        return 'Rsvp by %s (%s) with comment: %s' % (self.name, self.link, self.comment)

class Group(API_Item):
    datafields = [ 'id','name','link','updated',\
                   'members','created','photo_url',\
                   'description','zip','lat','lon',\
                   'city','state','country','organizerProfileURL', \
                   'topics']
    
    def __str__(self):
         return "%s (%s)" % (self.name, self.link)

    def get_events(self, apiclient, **extraparams):
        extraparams['group_id'] = self.id
        return apiclient.get_events(**extraparams)

    def get_photos(self, apiclient, **extraparams):
        extraparams['group_id'] = self.id
        return apiclient.get_photos(**extraparams)

    def get_members(self, apiclient, **extraparams):
        extraparams['group_id'] = self.id
        return apiclient.get_members(**extraparams)

class City(API_Item):
    datafields = ['city','country','state','zip','members','lat','lon']

    def __str__(self):
         return "%s %s, %s, %s, with %s members" % (self.city, self.zip, self.country, self.state, self.members)

    def get_groups(self,apiclient,  **extraparams):
        extraparams.update({'city':self.city, 'country':self.country})
        if self.country=='us': extraparams['state'] = self.state
        return apiclient.get_groups(**extraparams)

    def get_events(self,apiclient,  **extraparams):
        extraparams.update({'city':self.city, 'country':self.country})
        if self.country=='us': extraparams['state'] = self.state
        return apiclient.get_events(**extraparams) 

class Topic(API_Item):
    datafields = ['id','name','description','link','updated',\
                  'members','urlkey']
    
    def __str__(self):
         return "%s with %s members (%s)" % (self.name, self.members,
                                             self.urlkey)

    def get_groups(self, apiclient, **extraparams):
         extraparams['topic'] = self.urlkey
         return apiclient.get_groups(**extraparams)
    
    def get_photos(self, apiclient, **extraparams):
         extraparams['topic_id'] = self.id
         return apiclient.get_photos(**extraparams)

def _unicodify(json):
    """Makes all strings in the given JSON-like structure unicode."""
    try:
        if isinstance(json, str):
            return json.decode(API_JSON_ENCODING).encode('utf-8')
        elif isinstance(json, dict):
            for name in json:
                json[name] = _unicodify(json[name])
        elif isinstance(json, list):
            for part in json:
                _unicodify(part)
    except:
        print 'decoding error: ' +  json
    return json     

########################################

class ClientException(Exception):
    """
         Base class for generic errors returned by the server
    """
    def __init__(self, error_json):
         self.description = error_json['details']
         self.problem = error_json['problem']

    def __str__(self):
         return "%s: %s" % (self.problem, self.description)

class UnauthorizedError(ClientException):
    pass;

class BadRequestError(ClientException):
    pass;

