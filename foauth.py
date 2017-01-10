from __future__ import print_function # Python 2/3 compatibility
import sys
import requests
import argparse
import urlparse
import uuid
import difflib
import bs4
import math

#  NOTE: resource owner authentication will differ between implementations
def authenticate_resource_owner(basic_auth_uri, resource_owner_id, resource_owner_secret):

    basic_auth_response = requests.post(basic_auth_uri, auth=requests.auth.HTTPBasicAuth(resource_owner_id, resource_owner_secret), allow_redirects=False)

    if basic_auth_response.status_code != 200:
        print('  ERROR: could not authenticate resource owner')
        exit()

    return basic_auth_response.cookies

# run through entire authorization code flow and print any errors or warnings
def test_authorization_code_flow(cookies, authorize_uri, token_uri, client_id, client_secret, scope, redirect_uri, state):

    print('client_id: %s, client_secret: %s, scope: %s, redirect_uri: %s, state: %s' % (client_id, client_secret, scope, redirect_uri, state))

    get_authorize_uri = '%s?response_type=code&client_id=%s&scope=%s&state=%s&redirect_uri=%s' % (authorize_uri, client_id, scope, state, redirect_uri)

    get_authorize_response = requests.get(get_authorize_uri, cookies=cookies, allow_redirects=False)

    # oauth spec recommends to redirect on error (though this is pretty terrible)
    if get_authorize_response.status_code == 302:

        if 'Location' not in get_authorize_response.headers:
            print('  FAIL - GET authorize does not have a Location header')
            return

        if not get_authorize_response.headers['Location'].startswith(redirect_uri):
            print('  WARN - GET authorize returned invalid Location header %s' % post_authorize_response.headers['Location'])

        print('  *** REDIRECT ON ERROR: %s ***' % get_authorize_response.headers['Location'])

        return

    if get_authorize_response.status_code != 200:
        print('  FAIL - GET authorize returned invalid status code %s' % get_authorize_response.status_code)
        return

    # NOTE: authorize will differ between implementations
    allow_access_form_inputs = {'submit': 'Allow access'}

    # populate form data with hidden variables (try to catch CSRF token, etc.)
    hidden_form_inputs = {}
    for i in bs4.BeautifulSoup(get_authorize_response.content, 'html.parser').find_all('input'):
        if i['type'] == 'hidden':
            hidden_form_inputs[i['name']] = i['value']

    #if len(data) == 0:
    #    print('  WARN - GET authorize response does not contain any hidden inputs, it may not contain an anti-XSRF token')

    post_authorize_response = requests.post(get_authorize_uri, data=dict(allow_access_form_inputs, **hidden_form_inputs), cookies=cookies, allow_redirects=False)

    if post_authorize_response.status_code != 302:
        print('  FAIL - POST authorize returned invalid status code %s' % post_authorize_response.status_code)
        return

    if 'Location' not in post_authorize_response.headers:
        print('  FAIL - POST authorize does not have a Location header')
        return

    if not post_authorize_response.headers['Location'].startswith(redirect_uri):
        print('  WARN - POST authorize returned invalid Location header %s' % post_authorize_response.headers['Location'])

    post_authorize_response_query = urlparse.parse_qs(urlparse.urlparse(post_authorize_response.headers['Location']).query)

    if 'code' not in post_authorize_response_query:
        print('  FAIL - POST authorize Location header does not contain code query parameter %s' % post_authorize_response.headers['Location'])
        return

    if 'state' not in post_authorize_response_query:
        print('  WARN - POST authorize Location header does not contain state query parameter %s' % post_authorize_response.headers['Location'])

    if 'state' in post_authorize_response_query and post_authorize_response_query['state'][0] != state:
        print('  WARN - POST authorize Location header state query parameter %s does not match submitted value %s' % (post_authorize_response_query['state'][0], state))

    code = urlparse.parse_qs(urlparse.urlparse(post_authorize_response.headers['Location']).query)['code'][0]

    post_authorize_xsrf_response = requests.post(get_authorize_uri, data=allow_access_form_inputs, cookies=cookies, allow_redirects=False)

    if post_authorize_xsrf_response.status_code == 302 and post_authorize_xsrf_response.headers['Location'].startswith(redirect_uri):
        print('  WARN - POST authorize is vulnerable to XSRF')

    post_token_response = requests.post(token_uri, data={'grant_type': 'authorization_code', 'redirect_uri': redirect_uri, 'code': code, 'client_id': client_id, 'client_secret': client_secret}, allow_redirects=False)

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

    post_token_reuse_response = requests.post(token_uri, data={'grant_type': 'authorization_code', 'redirect_uri': redirect_uri, 'code': code, 'client_id': client_id, 'client_secret': client_secret}, allow_redirects=False)

    if post_token_reuse_response.status_code == 200 and 'access_token' in post_token_reuse_response.json():
        print('  WARN - POST token is vulnerable to authorization code re-use')

    # also supports basic auth
    #post_token_response = requests.post(token_uri, data={'grant_type': 'authorization_code', 'redirect_uri': redirect_uri, 'code': code}, auth=requests.auth.HTTPBasicAuth(client_id, client_secret), allow_redirects=False)

    # commented out getting resource as it is quite slow and doesn't prove much
    #get_resource_response = requests.get(args.resource_uri, headers={'Authorization': 'Bearer ' + post_token_response.json()['access_token']})
    #if get_resource_response.status_code != 200:
    #    print('  FAIL - GET resource with access_token returned invalid status code %s' % get_resource_response.status_code)
    #    return

    print('  *** TOKEN ACQUIRED ***')

# generate permutations of redirect_uri and run through test harness
def test_redirect_uri_permutations(cookies, authorize_uri, token_uri, client_id, client_secret, scope, redirect_uri):

    redirect_uri_permutations = [
        str.replace(redirect_uri, 'https://', 'http://'), # downgrade to HTTP
        str.replace(redirect_uri, 'https://', '//'), # downgrade to HTTP via protocol resolution bypass
        str.replace(redirect_uri, 'https://', 'https://sub.'), # navigate subdomain
        #redirect_uri + '&i=293'
    ]

    site_permutations = [
        'https://66.102.7.147', # ip
        '//google.com', # protocol resolution bypass
        'https://1113982867', # dword encoded
        'https://0102.0146.0007.00000223', # octal encoded
        'https://0x42.0x0000066.0x7.0x93', # hex encoded
        'https://%77%77%77%2E%67%6F%6F%67%6C%65%2E%63%6F%6D', # url encoded
        'h\ntt	ps://6	6.000146.0x7.147/', # mix encoded
        'htt	ps://6	6.000146.0x7.147/', # mix encoded
        'https://6	6.000146.0x7.147/', # mix encoded
        'http://6	6.000146.0x7.147/', # mix encoded
        'javascript:', # javascript
    ]

    for permutation in site_permutations:
        redirect_uri_permutations.append(permutation)

    for permutation in site_permutations:
        redirect_uri_permutations.append(permutation + '/' + redirect_uri)

    path_permutations = [
        'val',
        'javascript',
        ':',
        'javascript:',
        '../', # path traversal
        '%20', # uri enc
        '%2F', # uri enc
        '%2F%2F', # uri enc
        '0102', # octal enc
        '0x42', # hex enc
        #'&#47;', # ascii enc
        #'&#47;&#74;&#65;&#73;&#74;', # ascii enc
        '@google', # feeling lucky
        '?i=293', # query parameter
        #'&i=547', # append query parameter
        '#47', # ascii enc
    ]

    for permutation in path_permutations:
        redirect_uri_permutations.append(str.replace(redirect_uri, 'https://', 'https://' + permutation))

    for permutation in path_permutations:
        redirect_uri_permutations.append(str.replace(redirect_uri, 'https://', 'https://' + permutation + '/'))

    for permutation in path_permutations:
        redirect_uri_permutations.append(str.replace(redirect_uri, 'https://', 'https://' + permutation + '.'))

    for permutation in path_permutations:
        redirect_uri_permutations.append(redirect_uri + permutation)

    for permutation in path_permutations:
        redirect_uri_permutations.append(redirect_uri + '/' + permutation)

    for permutation in redirect_uri_permutations:
        test_authorization_code_flow(cookies, authorize_uri, token_uri, client_id, client_secret, scope, permutation, str(uuid.uuid4()))

# generate permutations of scope and run through test harness
def test_scope_permutations(cookies, authorize_uri, token_uri, client_id, client_secret, scope, redirect_uri):

    scope_permutations = [
        scope + 'test',
        scope + '/',
        scope + ',test',
        scope + ':test',
        scope + ';test',
        scope + '-test',
        'test',
        '',
        '%20',
        '%2F'
    ]

    for permutation in scope_permutations:
        test_authorization_code_flow(cookies, authorize_uri, token_uri, client_id, client_secret, permutation, redirect_uri, str(uuid.uuid4()))

# generate permutations of client_id and client_secret and run through test harness
def test_client_permutations(cookies, authorize_uri, token_uri, client_id, client_secret, scope, redirect_uri):

    client_permutations = [
        client_id + 'test',
        client_id + '/',
        'test' + client_id,
        'test',
        '',
        '%20',
        '%2F',
        '%00',
        '%00'
    ]

    for permutation in client_permutations:
        test_authorization_code_flow(cookies, authorize_uri, token_uri, permutation, client_secret, scope, redirect_uri, str(uuid.uuid4()))

    for permutation in client_permutations:
        test_authorization_code_flow(cookies, authorize_uri, token_uri, client_id, permutation, scope, redirect_uri, str(uuid.uuid4()))

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
    parser.add_argument('--redirect-uri-different-client')
    parser.add_argument('--client-id-different-client')
    args = parser.parse_args()

    print('AUTHENTICATE RESOURCE OWNER:')
    cookies = authenticate_resource_owner(args.basic_auth_uri, args.resource_owner_id, args.resource_owner_secret)
    print('  OK')

    print('\nSTANDARD USE:')
    test_authorization_code_flow(cookies, args.authorize_uri, args.token_uri, args.client_id, args.client_secret, args.scope, args.redirect_uri, str(uuid.uuid4()))

    print('\nSCOPE PERMUTATIONS:')
    test_scope_permutations(cookies, args.authorize_uri, args.token_uri, args.client_id, args.client_secret, args.scope, args.redirect_uri)

    print('\nCLIENT PERMUTATIONS:')
    test_client_permutations(cookies, args.authorize_uri, args.token_uri, args.client_id, args.client_secret, args.scope, args.redirect_uri)

    print('\nREDIRECT URI OF DIFFERENT CLIENT:')
    test_authorization_code_flow(cookies, args.authorize_uri, args.token_uri, args.client_id, args.client_secret, args.scope, args.redirect_uri_different_client, str(uuid.uuid4()))

    print('\nCLIENT ID OF DIFFERENT CLIENT:')
    test_authorization_code_flow(cookies, args.authorize_uri, args.token_uri, args.client_id_different_client, args.client_secret, args.scope, args.redirect_uri, str(uuid.uuid4()))

    print('\nREDIRECT URI PERMUTATIONS:')
    test_redirect_uri_permutations(cookies, args.authorize_uri, args.token_uri, args.client_id, args.client_secret, args.scope, args.redirect_uri)

    print('\nREDIRECT URI PERMUTATIONS (ERROR REDIRECT WITH INVALID CLIENT_ID):')
    test_redirect_uri_permutations(cookies, args.authorize_uri, args.token_uri, 'demclients', args.client_secret, args.scope, args.redirect_uri)

    print('\nREDIRECT URI PERMUTATIONS (ERROR REDIRECT WITH INVALID CLIENT_SECRET):')
    test_redirect_uri_permutations(cookies, args.authorize_uri, args.token_uri, args.client_id, 'demsecretz', args.scope, args.redirect_uri)

    print('\nREDIRECT URI PERMUTATIONS (ERROR REDIRECT WITH INVALID SCOPE):')
    test_redirect_uri_permutations(cookies, args.authorize_uri, args.token_uri, args.client_id, args.client_secret, 'wrongscopebro', args.redirect_uri)
