from __future__ import print_function # Python 2/3 compatibility
import sys
import requests
import argparse
import urlparse
import uuid

def basic_auth():
    print('basic_auth: ', end=''),
    basic_auth_response = requests.post(args.basic_auth_uri, auth=requests.auth.HTTPBasicAuth(args.resource_owner_id, args.resource_owner_secret), allow_redirects=False)
    if basic_auth_response.status_code != 200:
        print('ERROR: could not authenticate resource owner')
        exit()
    print('OK')
    return basic_auth_response.cookies

def test_happy_path(cookies):
    print('test_happy_path: ', end='')
    state = str(uuid.uuid4())
    get_authorize_uri = '%s?response_type=code&client_id=%s&scope=%s&state=%s&redirect_uri=%s' % (args.authorize_uri, args.client_id, args.scope, state, args.redirect_uri)
    get_authorize_response = requests.get(get_authorize_uri, cookies=cookies, allow_redirects=False)
    if get_authorize_response.status_code != 200:
        print('FAIL - GET authorize returned invalid status code %s' % get_authorize_response.status_code)
        return
    post_authorize_response = requests.post(get_authorize_uri, data={'submit': 'Allow access'}, cookies=cookies, allow_redirects=False)
    if post_authorize_response.status_code != 302:
        print('FAIL - POST authorize returned invalid status code %s' % post_authorize_response.status_code)
        return
    if not post_authorize_response.headers['Location'].startswith(args.redirect_uri):
        print('FAIL - POST authorize returned invalid Location header %s' % post_authorize_response.headers['Location'])
        return
    post_authorize_response_query = urlparse.parse_qs(urlparse.urlparse(post_authorize_response.headers['Location']).query)
    if 'code' not in post_authorize_response_query:
        print('FAIL - POST authorize Location header does not contain code query parameter %s' % post_authorize_response.headers['Location'])
        return
    if 'state' not in post_authorize_response_query:
        print('FAIL - POST authorize Location header does not contain state query parameter %s' % post_authorize_response.headers['Location'])
        return
    if post_authorize_response_query['state'][0] != state:
        print('FAIL - POST authorize Location header state query parameter %s does not match submitted value %s' % (post_authorize_response_query['state'][0], state))
        return
    code = urlparse.parse_qs(urlparse.urlparse(post_authorize_response.headers['Location']).query)['code'][0]
    post_token_response = requests.post(args.token_uri, data={'grant_type': 'authorization_code', 'redirect_uri': args.redirect_uri, 'code': code}, auth=requests.auth.HTTPBasicAuth(args.client_id, args.client_secret), allow_redirects=False)
    if post_token_response.status_code != 200:
        print('FAIL - POST token returned invalid status code %s' % post_token_response.status_code)
        return
    if 'access_token' not in post_token_response.json():
        print('FAIL - POST token response does not contain value for access_token %s' % post_token_response.content)
        return
    if 'token_type' not in post_token_response.json():
        print('FAIL - POST token response does not contain value for token_type %s' % post_token_response.content)
        return
    if 'expires_in' not in post_token_response.json():
        print('FAIL - POST token response does not contain value for expires_in %s' % post_token_response.content)
        return
    if post_token_response.json()['expires_in'] > 3600:
        print('FAIL - POST token response has long lived access token (%s seconds)' % post_token_response.json()['expires_in'])
        return
    print('OK')

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
    test_happy_path(cookies)
