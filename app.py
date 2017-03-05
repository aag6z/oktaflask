# import the Flask class from the flask module
from flask import Flask, render_template, redirect, url_for, request
from flask_login import LoginManager
from flask_login import current_user
from flask_login import login_required
from flask_login import login_user
from flask_login import logout_user
import requests
import json

# create the application object
app = Flask(__name__)

base_url =  'https://dev-788346.oktapreview.com'
api_token = '00AQM7JlAklG5P-ipn2zwuXtQNDZlkAfkFkA0o6ayy'
okta = {}

headers = {
    # "Authorization" is only needed for social transaction calls
    'Content-Type': 'application/json',
    'Authorization': 'SSWS {}'.format(api_token),
}

public_keys = {}
allowed_domains = ['okta.com', 'oktapreview.com']
app.secret_key = api_token

login_manager = LoginManager()
login_manager.setup_app(app)


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

@app.route('/')
def home():
    return render_template('login.html') 

@app.route('/loggedin')
#@login_required
def logged_in():
#	print current_user
#	opts = {'user': current_user}
	return render_template('loggedin.html') #,
#		opts=opts,
#		okta=okta)

@app.route('/registration', methods=['GET', 'POST'])
def registration():
	if (request.method  == 'POST'):
		payload = {'profile':{'firstName': request.form['firstName'],'lastName': request.form['lastName'], 'email': request.form['email'], 'login': request.form['login']}, 'credentials': { 'password': { 'value': request.form['password']}}}
		authn_url = "{}/api/v1/users?activate=false".format(base_url)
		r = requests.post(authn_url, headers=headers, data=json.dumps(payload))
		result = r.json()
		username = request.form['firstName']
		return render_template('createuser.html', user=username)
	return render_template('registration.html')

@app.route('/adminlistusers', methods=['GET'])
def listusers():
	authn_url = "{}/api/v1/users?limit=25".format(base_url)
	r = requests.get(authn_url, headers=headers)
	result = r.json()
	return render_template('adminlistusers.html', results=result)

@app.route('/deleteuser', methods=['GET','POST'])
def deleteuser():
	if (request.method  == 'POST'):
		login = request.form['login']
		authn_url = "{}/api/v1/users?q={}".format(base_url, login)
		r = requests.get(authn_url, headers=headers)
		result = r.json()
		user_id = result[0]['id']
		authn_url2 = "{}/api/v1/users/{}/lifecycle/deactivate".format(base_url, user_id)
		r = requests.post(authn_url2, headers=headers)
		return redirect('/adminlistusers')
	authn_url = "{}/api/v1/users?limit=25".format(base_url)
	r = requests.get(authn_url, headers=headers)
	result = r.json()
	return render_template('deleteuser.html', results=result)

@app.route('/changeuser', methods=['GET', 'POST'])
def changeuser():
	if (request.method  == 'POST'):
		login = request.form['login']
		authn_url = "{}/api/v1/users?q={}".format(base_url, login)
		r = requests.get(authn_url, headers=headers)
		result = r.json()
		user_id = result[0]['id']
		authn_url2 = "{}/api/v1/users/{}/lifecycle/reset_password?sendEmail=false".format(base_url, user_id)
		r = requests.post(authn_url2, headers=headers)
		return redirect('/adminlistusers')
	authn_url = "{}/api/v1/users?limit=25".format(base_url)
	r = requests.get(authn_url, headers=headers)
	result = r.json()
	return render_template('modifyuser.html', results=result)


# start the server with the 'run()' method
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)