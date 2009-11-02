import datetime
import oauth
import time
import urllib
import httplib
import urllib2 
from urllib2 import HTTPError

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

DEV = ''
API_BASE_URL = 'http://api' + DEV + '.meetup.com/'
GROUPS_URI = 'groups'
EVENTS_URI = 'events'
CITIES_URI = 'cities'
TOPICS_URI = 'topics'
PHOTOS_URI = 'photos'
MEMBERS_URI = 'members'
RSVPS_URI = 'rsvps'
REQUESTTOKEN_URL = 'http://www' + DEV + '.meetup.com/oauth/request/'
ACCESSTOKEN_URL = 'http://www' + DEV + '.meetup.com/oauth/access/'
AUTH_URL = 'http://www' + DEV + '.meetup.com/oauth/az/'

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
        args = urllib.urlencode(url_args)
        url = API_BASE_URL + uri + '/' + "?" + args
        print "requesting %s" % (url)
        try:
           request = urllib2.Request(url)
           stream = urllib2.urlopen(request)
           data = stream.read()
           stream.close()
           return parse_json(data)  
        except HTTPError, e:
           error_json = parse_json(e.read())
           if e.code == 401:
               raise UnauthorizedError(error_json)
           elif e.code in ( 400, 500 ):
               raise BadRequestError(error_json)
           else:
               raise ClientException(error_json)

class SimpleOAuthClient(oauth.OAuthClient):

    def __init__(self, server, port=httplib.HTTP_PORT, request_token_url='', access_token_url='', authorization_url=''):
        self.server = server
        self.port = port
        self.request_token_url = request_token_url
        self.access_token_url = access_token_url
        self.authorization_url = authorization_url
        self.connection = httplib.HTTPConnection("%s:%d" % (self.server, self.port))

    def fetch_request_token(self, oauth_request):
        self.connection.request(oauth_request.http_method, self.request_token_url, headers=oauth_request.to_header()) 
        response = self.connection.getresponse()
        result = response.read()
        print result
        return oauth.OAuthToken.from_string(result)

    def fetch_access_token(self, oauth_request):
        self.connection.request(oauth_request.http_method, self.access_token_url, headers=oauth_request.to_header()) 
        response = self.connection.getresponse()
        result = response.read()
        return oauth.OAuthToken.from_string(result)

    def authorize_token(self, oauth_request):
        self.connection.request(oauth_request.http_method, oauth_request.to_url()) 
        response = self.connection.getresponse()
        return response.read()

    def access_resource(self, oauth_request):
        headers = {'Content-Type' :'application/x-www-form-urlencoded'}
        self.connection.request('POST', RESOURCE_URL, body=oauth_request.to_postdata(), headers=headers)

oauth_client = SimpleOAuthClient('www' + DEV + '.meetup.com', 80, REQUESTTOKEN_URL, ACCESSTOKEN_URL, AUTH_URL)

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

    def fetch_request_token(self, signature_method=signature_method_plaintext):
        oauth_req = oauth.OAuthRequest.from_consumer_and_token(self.consumer, http_url=REQUESTTOKEN_URL)
        oauth_req.sign_request(signature_method, self.consumer, None)
        self.request_token = oauth_client.fetch_request_token(oauth_req)

    def get_authorize_url(self, oauth_callback=None):
        if oauth_callback:
            callbackUrl = "&" + urllib.urlencode({"oauth_callback":oauth_callback})
        else:
            callbackUrl = ""
        return "http://www" + DEV + ".meetup.com/authorize/?oauth_token=%s%s" % (self.request_token.key, callbackUrl)

    def fetch_access_token(self, signature_method=signature_method_plaintext, request_token=None):
        temp_request_token = request_token or self.request_token
        if not temp_request_token:
            raise NoToken("You must provide a request token to exchange for an access token")
        oauth_req = oauth.OAuthRequest.from_consumer_and_token(self.consumer, token=temp_request_token, http_url=ACCESSTOKEN_URL)
        oauth_req.sign_request(signature_method_hmac, self.consumer, temp_request_token)
        print oauth_req.to_header()
        token = oauth_client.fetch_access_token(oauth_req)
        if token:
            self.access_token = token

class MeetupOAuth(Meetup):

    def __init__(self, oauth_consumer_key, oauth_consumer_secret):
        self.oauth_consumer_key = oauth_consumer_key
        self.oauth_consumer_secret = oauth_consumer_secret
        self.consumer = oauth.OAuthConsumer(self.oauth_consumer_key, self.oauth_consumer_secret)

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

    def _fetch(self, uri, oauthreq=None, signature_method=signature_method_plaintext, use_access_token=None, use_access_token_secret=None, **url_args):
        temp_access_token = oauthreq.access_token
        if temp_access_token:
            url_args['format'] = 'json'
            oauth_access = oauth.OAuthRequest.from_consumer_and_token(self.consumer, 
                                                                      token = temp_access_token,
                                                                      http_url="http://api" + DEV + ".meetup.com/",
                                                                      parameters=url_args)
            oauth_access.sign_request(signature_method, self.consumer, temp_access_token)
            url_args.update(oauth_access.get_oauth_parameters());
        args = urllib.urlencode(url_args)
        url = API_BASE_URL + uri + '/' + "?" + args
        print "requesting %s" % (url)
        try:
           request = urllib2.Request(url)
           stream = urllib2.urlopen(request)
           data = stream.read()
           stream.close()
           return parse_json(data)  
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
                   'city','state','country','organizerProfileURL']
    
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

