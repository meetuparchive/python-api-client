#!/usr/bin/env python
from __future__ import with_statement

import datetime
import time
import cgi
import types
import logging
from urllib import urlencode
from urllib2 import HTTPError, HTTPErrorProcessor, urlopen, Request, build_opener

import oauth
import MultipartPostHandler as mph

# This is an example of a client wrapper that you can use to
# make calls to the Meetup.com API. It requires that you have 
# a JSON parsing module available.

API_JSON_ENCODING = 'utf-8'

try:
    try:
        import cjson
        parse_json = lambda s: cjson.decode(s.decode(API_JSON_ENCODING), True)
    except ImportError:
        try:
            import json
            parse_json = lambda s: json.loads(s.decode(API_JSON_ENCODING))
        except ImportError:
            import simplejson
            parse_json = lambda s: simplejson.loads(s.decode(API_JSON_ENCODING))
except:
    print "Error - your system is missing support for a JSON parsing library."

GROUPS_URI = '2/groups'
EVENTS_URI = '2/events'
TOPICS_URI = 'topics'
CITIES_URI = '2/cities'
MEMBERS_URI = '2/members'
RSVPS_URI = '2/rsvps'
PHOTOS_URI = '2/photos'
RSVP_URI = '2/rsvp'
COMMENTS_URI = 'comments'
PHOTO_URI = '2/photo'
MEMBER_PHOTO_URI = '2/member_photo'

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

class MeetupHTTPErrorProcessor(HTTPErrorProcessor):
    def http_response(self, request, response):
        try:
            return HTTPErrorProcessor.http_response(self, request, response)
        except HTTPError, e:
            error_json = parse_json(e.read())
            if e.code == 401:
                raise UnauthorizedError(error_json)
            elif e.code in ( 400, 500 ):
                raise BadRequestError(error_json)
            else:
                raise ClientException(error_json)

class Meetup(object):
    opener = build_opener(MeetupHTTPErrorProcessor)
    def __init__(self, api_key):
        """Initializes a new session with an api key that will be added
        to subsequent api calls"""
        self.api_key = api_key
        self.opener.addheaders = [('Accept-Charset', 'utf-8')]

    def post_rsvp(self, **args):
        return self._post(RSVP_URI, **args)

    def post_photo(self, **args):
        return self._post_multipart(PHOTO_URI, **args)

    def post_member_photo(self, **args):
        return self._post_multipart(MEMBER_PHOTO_URI, **args)

    def args_str(self, url_args):
        if self.api_key:
            url_args['key'] = self.api_key
        return urlencode(url_args)

    def _fetch(self, uri, **url_args):
        args = self.args_str(url_args)
        url = API_BASE_URL + uri + '/' + "?" + args
        logging.debug("requesting %s" % (url))
        return parse_json(self.opener.open(url).read())

    def _post(self, uri, **params):
        args = self.args_str(params)
        url = API_BASE_URL + uri + '/'
        logging.debug("posting %s to %s" % (args, url))
        return self.opener.open(url, data=args).read()

    def _post_multipart(self, uri, **params):
        params['key'] = self.api_key

        opener = build_opener(mph.MultipartPostHandler)
        url = API_BASE_URL + uri + '/'
        logging.debug("posting multipart %s to %s" % (params, url))
        return opener.open(url, params).read()

"""Add read methods to Meetup class dynamically (avoiding boilerplate)"""
READ_METHODS = { 
        'groups': '2/groups', 
        'events': '2/events', 
        'topics': 'topics', 
        'cities': '2/cities', 
        'members': '2/members', 
        'rsvps': '2/rsvps',
        'photos': '2/photos', 
        'comments': 'comments', 
        'activity': 'activity',
        }
def _generate_read_method(name):
    def read_method(self, **args):
        return API_Response(self._fetch(name, **args), name)
    return read_method
for method, uri in READ_METHODS.items():
    read_method = types.MethodType(_generate_read_method(uri), None, Meetup)
    setattr(Meetup, 'get_' + method, read_method)

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

    def fetch_request_token(self, callback="oob", signature_method=signature_method_hmac):
        oauth_req = oauth.OAuthRequest.from_consumer_and_token(
            self.consumer, http_url=(OAUTH_BASE_URL + 'oauth/request/'), callback=callback)
        oauth_req.sign_request(signature_method, self.consumer, None)
        token_string = urlopen(Request(oauth_req.http_url, headers=oauth_req.to_header())).read()
        self.request_token = oauth.OAuthToken.from_string(token_string)

    def get_authorize_url(self, oauth_callback=None):
        if oauth_callback:
            callbackUrl = "&" + urlencode({"oauth_callback":oauth_callback})
        else:
            callbackUrl = ""
        return OAUTH_BASE_URL + "authorize/?oauth_token=%s%s" % (self.request_token.key, callbackUrl)

    def get_authenticate_url(self, oauth_callback=None):
        if oauth_callback:
            callbackUrl = "&" + urlencode({"oauth_callback":oauth_callback})
        else:
            callbackUrl = ""
        return OAUTH_BASE_URL + "authenticate/?oauth_token=%s%s" % (self.request_token.key, callbackUrl)

    def fetch_access_token(self, oauth_verifier, signature_method=signature_method_hmac, request_token=None):
        temp_request_token = request_token or self.request_token
        if not temp_request_token:
            raise NoToken("You must provide a request token to exchange for an access token")
        oauth_req = oauth.OAuthRequest.from_consumer_and_token(self.consumer, token=temp_request_token, 
            http_url=OAUTH_BASE_URL + 'oauth/access/', verifier=oauth_verifier)
        oauth_req.sign_request(signature_method, self.consumer, temp_request_token)
        token_string = urlopen(Request(oauth_req.http_url, headers=oauth_req.to_header())).read()
        self.access_token = oauth.OAuthToken.from_string(token_string)
        return cgi.parse_qs(token_string)['member_id'][0]

class MeetupOAuth(Meetup):

    def __init__(self, oauth_consumer_key, oauth_consumer_secret, access_key=None, access_secret=None):
        self.oauth_consumer_key = oauth_consumer_key
        self.oauth_consumer_secret = oauth_consumer_secret
        self.consumer = oauth.OAuthConsumer(self.oauth_consumer_key, self.oauth_consumer_secret)
        self.oauth_session = None
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

    def _sign(self, uri, sess, oauthreq, signature_method, http_method='GET', **params):
        # the oauthreq parameter name is deprecated, please use sess or bind the session in __init__
        session = self.oauth_session or sess or oauthreq
        if not session:
            raise BadRequestError("MeetupOAuth client requires either a bound MeetupOAuthSession or one in the `sess` argument.")
        if not session.access_token:
            raise BadRequestError("Current MeetupOAuthSession does not have an access_token.")
        
        oauth_access = oauth.OAuthRequest.from_consumer_and_token(self.consumer, 
                                                                  http_method=http_method,
                                                                  token = session.access_token,
                                                                  http_url=API_BASE_URL + uri + "/",
                                                                  parameters=params)
        oauth_access.sign_request(signature_method, self.consumer, session.access_token)
        return oauth_access

    def _fetch(self, uri, sess=None, oauthreq=None, signature_method=signature_method_hmac, **url_args):
        oauth_access = self._sign(uri, sess, oauthreq, signature_method, **url_args)
        url = oauth_access.to_url()

        logging.debug("requesting %s" % (url))
        return parse_json(self.opener.open(url).read())

    def _post(self, uri, sess=None, oauthreq=None, signature_method=signature_method_hmac, **params):
        oauth_access = self._sign(uri, sess, oauthreq, signature_method, http_method='POST', **params)
        url, data = oauth_access.get_normalized_http_url(), oauth_access.to_postdata()

        logging.debug("posting %s to %s" % (data, url))
        return self.opener.open(url, data=data).read()

    def _post_multipart(self, uri, sess=None, oauthreq=None, signature_method=signature_method_hmac, **params):
        oauth_access = self._sign(uri, sess, oauthreq, signature_method, http_method='POST')
        url, headers = oauth_access.get_normalized_http_url(), oauth_access.to_header()

        opener = build_opener(mph.MultipartPostHandler)
        logging.debug("posting multipart %s to %s" % (params, url))
        return opener.open(Request(url, params, headers=headers)).read()


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
                       RSVPS_URI:Rsvp,
                       COMMENTS_URI:Comment}
         self.results = [uriclasses[uritype](item) for item in json['results']]

    def __str__(self):
        return 'meta: ' + str(self.meta) + '\n' + str(self.results)

class API_Item(object):
    """Base class for an item in a result set returned by the API."""

    datafields = [] #override
    def __init__(self, properties):
         """load properties that are relevant to all items (id, etc.)"""
         for field in self.datafields:
             # Not all fields are required to be returned
             if properties.has_key(field):
                self.__setattr__(field, properties[field])
         self.json = properties

    def __repr__(self):
         return self.__str__();

class Member(API_Item):

    datafields = ['bio', 'birthday', 'country, city, state', 'email', 
            'gender', 'hometown', 'id', 'joined', 'lang', 'lat, lon', 'link',
            'membership_count', 'messagable', 'messaging_pref', 'name',
            'other_services', 'photo', 'photo_url', 'photos', 'privacy',
            'reachable', 'self', 'topics', 'visited']
    
    def get_groups(self, apiclient, **extraparams):
        extraparams.update({'member_id':self.id})
        return apiclient.get_groups(extraparams);

    def __str__(self):
        return "Member %s (url: %s)" % (self.name, self.link)

class Photo(API_Item):

    datafields = ['caption', 'created', 'highres_link', 'member', 
            'member_photo', 'photo_album', 'photo_id', 'photo_link', 
            'self', 'site_link', 'thumb_link', 'updated']

    def __str__(self):
        return "Photo located at %s posted by member at %s: (%s)" % (self.link, self.member_url, self.descr)


class Event(API_Item):
    datafields = ['announced', 'comment_count', 'created', 'description', 
            'distance', 'duration', 'email_reminders', 'event_hosts', 
            'event_url', 'featured', 'fee', 'group', 'headcount', 
            'how_to_find_us', 'id', 'is_simplehtml', 'maybe_rsvp_count', 
            'name', 'photo_album_id', 'photo_count', 'photo_url', 
            'publish_status', 'rating', 'rsvp_alerts', 'rsvp_limit', 
            'rsvp_rules', 'rsvpable', 'self', 'short_link', 
            'simple_html_description', 'status', 'survey_questions', 
            'time', 'timezone', 'trending_rank', 'updated', 'utc_offset', 
            'venue', 'venue_visibility', 'visibility', 'why', 'yes_rsvp_count']

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

    datafields = ['category', 'city', 'country', 'created', 'description',
            'ga_code', 'group_photo', 'id', 'is_simplehtml', 'join_info',
            'join_mode', 'lat', 'link', 'list_addr', 'list_mode', 'lon',
            'members', 'membership_dues', 'name', 'next_event', 'organizer',
            'other_services', 'pending_members', 'photos', 'primary_topic',
            'rating', 'self', 'short_link', 'similar_groups',
            'simple_html_description', 'sponsors', 'state', 'timezone',
            'topics', 'urlname', 'visibility', 'welcome_message', 'who']    

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

    datafields = ['city', 'country', 'distance', 'id', 'lat', 'lon', 
            'member_count', 'name_string', 'ranking', 'state', 'zip']

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

class Comment(API_Item):
    datafields = ['name','link','comment','photo_url',\
                  'created','lat','lon','country','city','state']
    
    def __str__(self):
         return "Comment from %s (%s)" % (self.name, self.link)

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

