# import the Flask class from the flask module
import json
import os
import re
import urllib
import urlparse
import requests
import flask

from flask import Flask, render_template, redirect, url_for, request
from flask_login import LoginManager
from flask_login import current_user
from flask_login import login_required
from flask_login import login_user
from flask_login import logout_user
from flask_login import AnonymousUserMixin
from jose import jws
from jose import jwt
from okta import SessionsClient

# create the application object
application = Flask(__name__)

okta = { "base_url" : "https://dev-788346.oktapreview.com", "api_token" : "00FG7qLvuvldXlDNK9mXrUlQvcpcy7YRuwuQZKjbXy", "client_id" : "RYP9v4p5PpF9sADb5nsQ"}

not_alpha_numeric = re.compile('[^a-zA-Z0-9]+')

headers = {
    # "Authorization" is only needed for social transaction calls
    'Content-Type': 'application/json',
    'Authorization': 'SSWS {}'.format(okta["api_token"]),
}

sessionsClient = SessionsClient(okta["base_url"], okta["api_token"])

application.secret_key = okta["api_token"]
public_keys = {}
allowed_domains = ['okta.com', 'oktapreview.com']

login_manager = LoginManager()
login_manager.setup_app(application)

class Anonymous(AnonymousUserMixin):
  def __init__(self):
    self.user_id = 'Guest'

login_manager.anonymous_user = Anonymous

class UserSession:
    def __init__(self, user_id):
        self.authenticated = True
        self.user_id = user_id

    def is_active(self):
        return self.authenticated

    def is_authenticated(self):
        return self.authenticated

    def is_anonymous(self):
        return not self.authenticated

    def get_id(self):
        return self.user_id


@login_manager.user_loader
def load_user(user_id):
	print "Loading user: " + user_id
	return UserSession(user_id)

@application.route('/', methods=['GET', 'POST'])
def home():
	if (request.method == 'GET' and current_user.user_id != "Guest"):
		url = url_for('logged_in', _external=True)
		return redirect(url)
		
	elif request.method == 'GET':
		return render_template('login.html')

	opts = {}

	session = None
	try:
		session = sessionsClient.create_session(
			request.form['username'],
			request.form['password'])
	except Exception, e:
		print e
		opts['invalid_username_or_password'] = True
		return render_template('logged_in.html', opts=opts)

	user = UserSession(session.userId)
	login_user(user)
	url = url_for('logged_in', _external=True)
	return redirect(url)


@application.route('/logged_in')
@login_required
def logged_in():
	print current_user.is_authenticated
	opts = {'user': current_user}
	user_id_login = current_user.user_id
	authn_url = "{}/api/v1/users/{}".format(okta["base_url"], user_id_login)
	r = requests.get(authn_url, headers=headers)
	result = r.json()
	return render_template('logged_in.html', opts = opts, result = result)

@application.route("/logout")
def logout():
	logout_user()
	return redirect(url_for('home'))

@application.route('/registration', methods=['GET', 'POST'])
def registration():
	if (request.method  == 'POST'):
		payload = {'profile':{'firstName': request.form['firstName'],'lastName': request.form['lastName'], 'email': request.form['email'], 'login': request.form['login']}, 'credentials': { 'password': { 'value': request.form['password']}}}
		authn_url = "{}/api/v1/users?activate=false".format(okta["base_url"])
		r = requests.post(authn_url, headers=headers, data=json.dumps(payload))
		result = r.json()
		username = request.form['firstName']
		return render_template('create_user.html', user=username)
	return render_template('registration.html')

@application.route('/admin_list_users', methods=['GET'])
@login_required
def listusers():
	opts = {'user': current_user}
	authn_url = "{}/api/v1/users?limit=25".format(okta["base_url"])
	r = requests.get(authn_url, headers=headers)
	result = r.json()
	return render_template('admin_list_users.html', opts = opts, results=result)

@application.route('/delete_user', methods=['GET','POST'])
@login_required
def deleteuser():
	if (request.method  == 'POST'):
		login = request.form['login']
		authn_url = "{}/api/v1/users?q={}".format(okta["base_url"], login)
		r = requests.get(authn_url, headers=headers)
		result = r.json()
		user_id = result[0]['id']
		authn_url2 = "{}/api/v1/users/{}/lifecycle/deactivate".format(okta["base_url"], user_id)
		r = requests.post(authn_url2, headers=headers)
		return redirect('/admin_list_users')
	opts = {'user': current_user}
	authn_url = "{}/api/v1/users?limit=25".format(okta["base_url"])
	r = requests.get(authn_url, headers=headers)
	result = r.json()
	return render_template('delete_user.html', results=result, opts = opts)

@application.route('/change_user', methods=['GET', 'POST'])
@login_required
def changeuser():
	if (request.method  == 'POST'):
		login = request.form['login']
		authn_url = "{}/api/v1/users?q={}".format(okta["base_url"], login)
		r = requests.get(authn_url, headers=headers)
		result = r.json()
		user_id = result[0]['id']
		authn_url2 = "{}/api/v1/users/{}/lifecycle/reset_password?sendEmail=false".format(okta["base_url"], user_id)
		r = requests.post(authn_url2, headers=headers)
		return redirect('/admin_list_users')
	opts = {'user': current_user}
	authn_url = "{}/api/v1/users?limit=25".format(okta["base_url"])
	r = requests.get(authn_url, headers=headers)
	result = r.json()
	return render_template('modify_user.html', results=result, opts = opts)

def domain_name_for(url):
    second_to_last_element = -2
    domain_parts = url.netloc.split('.')
    (sld, tld) = domain_parts[second_to_last_element:]
    return sld + '.' + tld


# FIXME: Rename since this is not about public keys anymore
def fetch_jwt_public_key_for(id_token=None):
    if id_token is None:
        raise NameError('id_token is required')

    dirty_header = jws.get_unverified_header(id_token)
    cleaned_key_id = None
    if 'kid' in dirty_header:
        dirty_key_id = dirty_header['kid']
        cleaned_key_id = re.sub(not_alpha_numeric, '', dirty_key_id)
        print "cleaned key id"
        print cleaned_key_id
    else:
        raise ValueError('The id_token header must contain a "kid"')
    if cleaned_key_id in public_keys:
        return public_keys[cleaned_key_id]

    unverified_claims = jwt.get_unverified_claims(id_token)
    dirty_url = urlparse.urlparse(unverified_claims['iss'])
    if domain_name_for(dirty_url) not in allowed_domains:
        raise ValueError('The domain in the issuer claim is not allowed')
    cleaned_issuer = dirty_url.geturl()
    print "cleaned issuer"
    print cleaned_issuer
    oidc_discovery_url = "{}/.well-known/openid-configuration".format(
        cleaned_issuer)
    print "OIDC discovery url"
    print oidc_discovery_url
    r = requests.get(oidc_discovery_url)
    print "r"
    print r
    openid_configuration = r.json()
    jwks_uri = openid_configuration['jwks_uri']
    print "jwks_uri"
    print jwks_uri
    r = requests.get(jwks_uri)
    jwks = r.json()
    print "jwks - xxxxxx"
    print jwks
    for key in jwks['keys']:
        print "key in jwks"
        print key
        jwk_id = key['kid']
        print "jwk_id"
        print jwk_id
        jwk_id2 = "sPUbzcPTXF6wvvR7dVsh299KdaXPc0sAqsTYaVmM"
        public_keys[jwk_id2] = key

    if cleaned_key_id in public_keys:
        return public_keys[cleaned_key_id]
    else:
        raise RuntimeError("Unable to fetch public key from jwks_uri")

def parse_jwt(id_token):
    public_key = fetch_jwt_public_key_for(id_token)
    rv = jwt.decode(
        id_token,
        public_key,
        algorithms='RS256',
        issuer=okta['base_url'],
        audience=okta['client_id'])
    print "rv"
    print rv
    return rv

@application.route("/sso/oidc", methods=['GET', 'POST'])
def sso_oidc():
    if 'error' in request.form:
        flash(request.form['error_description'])
        return redirect(url_for('home', _external=True, _scheme='https'))
    id_token = request.form['id_token']
    decoded = parse_jwt(id_token)
    user_id = decoded['sub']
    user = UserSession(user_id)
    login_user(user)
    return redirect(url_for('logged_in', _external=True, _scheme='https'))

@application.route("/spa")
def spa():
    return render_template(
        'spa.html',
        okta=okta)

@application.route("/users/me")
def users_me():
    print ("hi")
    authorization = request.headers.get('Authorization')
    token = authorization.replace('Bearer ', '')
    decoded = parse_jwt(token)
    rv = {'user_id': decoded['sub']}
    return flask.jsonify(**rv)

# start the server with the 'run()' method
if __name__ == '__main__':
    application.run(host='0.0.0.0', port=5000, debug=True)