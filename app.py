# import the Flask class from the flask module
from flask import Flask, render_template, redirect, url_for, request
from flask_login import LoginManager
from flask_login import current_user
from flask_login import login_required
from flask_login import login_user
from flask_login import logout_user
from flask_login import AnonymousUserMixin
from okta import SessionsClient
import requests
import json

# create the application object
app = Flask(__name__)

base_url =  'https://dev-788346.oktapreview.com'
api_token = '00AQM7JlAklG5P-ipn2zwuXtQNDZlkAfkFkA0o6ayy'

headers = {
    # "Authorization" is only needed for social transaction calls
    'Content-Type': 'application/json',
    'Authorization': 'SSWS {}'.format(api_token),
}

sessionsClient = SessionsClient(base_url, api_token)

app.secret_key = api_token

login_manager = LoginManager()
login_manager.setup_app(app)

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

@app.route('/', methods=['GET', 'POST'])
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


@app.route('/logged_in')
@login_required
def logged_in():
	print current_user.is_authenticated
	opts = {'user': current_user}
	user_id_login = current_user.user_id
	authn_url = "{}/api/v1/users/{}".format(base_url, user_id_login)
	r = requests.get(authn_url, headers=headers)
	result = r.json()
	return render_template('logged_in.html', opts = opts, result = result)

@app.route("/logout")
def logout():
	logout_user()
	return redirect(url_for('home'))

@app.route('/registration', methods=['GET', 'POST'])
def registration():
	if (request.method  == 'POST'):
		payload = {'profile':{'firstName': request.form['firstName'],'lastName': request.form['lastName'], 'email': request.form['email'], 'login': request.form['login']}, 'credentials': { 'password': { 'value': request.form['password']}}}
		authn_url = "{}/api/v1/users?activate=false".format(base_url)
		r = requests.post(authn_url, headers=headers, data=json.dumps(payload))
		result = r.json()
		username = request.form['firstName']
		return render_template('create_user.html', user=username)
	return render_template('registration.html')

@app.route('/admin_list_users', methods=['GET'])
@login_required
def listusers():
	opts = {'user': current_user}
	authn_url = "{}/api/v1/users?limit=25".format(base_url)
	r = requests.get(authn_url, headers=headers)
	result = r.json()
	return render_template('admin_list_users.html', opts = opts, results=result)

@app.route('/delete_user', methods=['GET','POST'])
@login_required
def deleteuser():
	if (request.method  == 'POST'):
		login = request.form['login']
		authn_url = "{}/api/v1/users?q={}".format(base_url, login)
		r = requests.get(authn_url, headers=headers)
		result = r.json()
		user_id = result[0]['id']
		authn_url2 = "{}/api/v1/users/{}/lifecycle/deactivate".format(base_url, user_id)
		r = requests.post(authn_url2, headers=headers)
		return redirect('/admin_list_users')
	opts = {'user': current_user}
	authn_url = "{}/api/v1/users?limit=25".format(base_url)
	r = requests.get(authn_url, headers=headers)
	result = r.json()
	return render_template('delete_user.html', results=result, opts = opts)

@app.route('/change_user', methods=['GET', 'POST'])
@login_required
def changeuser():
	if (request.method  == 'POST'):
		login = request.form['login']
		authn_url = "{}/api/v1/users?q={}".format(base_url, login)
		r = requests.get(authn_url, headers=headers)
		result = r.json()
		user_id = result[0]['id']
		authn_url2 = "{}/api/v1/users/{}/lifecycle/reset_password?sendEmail=false".format(base_url, user_id)
		r = requests.post(authn_url2, headers=headers)
		return redirect('/admin_list_users')
	opts = {'user': current_user}
	authn_url = "{}/api/v1/users?limit=25".format(base_url)
	r = requests.get(authn_url, headers=headers)
	result = r.json()
	return render_template('modify_user.html', results=result, opts = opts)


# start the server with the 'run()' method
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)