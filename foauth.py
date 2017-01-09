# Test for common bugs and vulnerabilities in an OAuth2 implementation
#
# todo:
#
# get access code for unregistered redirect uri
# get access code for invalid scope
# get access code for invalid client
# get access code for mismatching client and redirect uri
# get acess code with various permutations of redirect uri to test for open redirection
#
# post access code with submitting any kind of CSRF check
# post access code for unregistered redirect uri
# post access code for invalid scope
# post access code for invalid client
# post access code for mismatching client and redirect uri
# post acess code with various permutations of redirect uri to test for open redirection
#
# post token with invalid client credentials
# post token with access code issued for different client
# post token with access code issued for different redirect uri
# post token with with previously used access code
# confused deputy on implicit flow
#
# get resource with expired token
#
from __future__ import print_function # Python 2/3 compatibility
import sys
import requests
import argparse
import urlparse
import uuid

def basic_auth():

    print('Basic Auth:'),

    basic_auth_response = requests.post(args.basic_auth_uri, auth=requests.auth.HTTPBasicAuth(args.resource_owner_id, args.resource_owner_secret), allow_redirects=False)

    if basic_auth_response.status_code != 200:
        print('  ERROR: could not authenticate resource owner')
        exit()

    print('  OK')

    return basic_auth_response.cookies

def test_authorization_code_flow(cookies):

    print('Authorization Code Flow:')

    state = str(uuid.uuid4())

    get_authorize_response = requests.get('%s?response_type=code&client_id=%s&scope=%s&state=%s&redirect_uri=%s' % (args.authorize_uri, args.client_id, args.scope, state, args.redirect_uri), cookies=cookies, allow_redirects=False)

    if get_authorize_response.status_code != 200:
        print('  FAIL - GET authorize returned invalid status code %s' % get_authorize_response.status_code)
        return

    post_authorize_response = requests.post('%s?response_type=code&client_id=%s&scope=%s&state=%s&redirect_uri=%s' % (args.authorize_uri, args.client_id, args.scope, state, args.redirect_uri), data={'submit': 'Allow access'}, cookies=cookies, allow_redirects=False)

    if post_authorize_response.status_code != 302:
        print('  FAIL - POST authorize returned invalid status code %s' % post_authorize_response.status_code)
        return

    if not post_authorize_response.headers['Location'].startswith(args.redirect_uri):
        print('  FAIL - POST authorize returned invalid Location header %s' % post_authorize_response.headers['Location'])
        return

    post_authorize_response_query = urlparse.parse_qs(urlparse.urlparse(post_authorize_response.headers['Location']).query)

    if 'code' not in post_authorize_response_query:
        print('  FAIL - POST authorize Location header does not contain code query parameter %s' % post_authorize_response.headers['Location'])
        return

    if 'state' not in post_authorize_response_query:
        print('  WARN - POST authorize Location header does not contain state query parameter %s' % post_authorize_response.headers['Location'])

    if 'state' in post_authorize_response_query and post_authorize_response_query['state'][0] != state:
        print('  WARN - POST authorize Location header state query parameter %s does not match submitted value %s' % (post_authorize_response_query['state'][0], state))

    code = urlparse.parse_qs(urlparse.urlparse(post_authorize_response.headers['Location']).query)['code'][0]

    #, auth=requests.auth.HTTPBasicAuth(args.client_id, args.client_secret),
    post_token_response = requests.post(args.token_uri, data={'grant_type': 'authorization_code', 'redirect_uri': args.redirect_uri, 'code': code, 'client_id': args.client_id, 'client_secret': args.client_secret}, allow_redirects=False)

    if post_token_response.status_code != 200:
        print('  FAIL - POST token returned invalid status code %s' % post_token_response.status_code)
        return

    if 'access_token' not in post_token_response.json():
        print('  FAIL - POST token response does not contain value for access_token %s' % post_token_response.content)
        return

    if 'token_type' not in post_token_response.json():
        print('  WARN - POST token response does not contain value for token_type %s' % post_token_response.content)

    if 'expires_in' not in post_token_response.json():
        print('  WARN - POST token response does not contain value for expires_in %s' % post_token_response.content)

    if post_token_response.json()['expires_in'] > 3600:
        print('  WARN - POST token response has long lived access token (%s seconds)' % post_token_response.json()['expires_in'])

    print('  OK')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--authorize-uri')
    parser.add_argument('--resource-uri')
    parser.add_argument('--client-id')
    parser.add_argument('--client-secret')
    parser.add_argument('--scope')
    parser.add_argument('--redirect-uri')
    parser.add_argument('--token-uri')
    parser.add_argument('--basic-auth-uri')
    parser.add_argument('--resource-owner-id')
    parser.add_argument('--resource-owner-secret')
    args = parser.parse_args()
    cookies = basic_auth()
    test_authorization_code_flow(cookies)
