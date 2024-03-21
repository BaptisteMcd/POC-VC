# flask_ngrok_example.py
from flask import Flask, render_template, redirect, url_for, request, session
import requests
from Requests import requetes_keycloak

app = Flask(__name__,static_url_path='/static')
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'


@app.route('/')
def default():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        rq_code , rq_json = requetes_keycloak.requete_jeton_user(request.form['username'],request.form['password'])
        #print(rq_json)
        if(rq_code != 200):
            error = 'Invalid Credentials. Please try again.'
        else:
            print('login successfull')
            session['access_token'] = rq_json['access_token']
            session['refresh_token'] = rq_json['refresh_token']
            session['user'] = request.form['username']
            return redirect(url_for('home',req = rq_json,user = request.form['username']))
    return render_template('login.html', error=error)


@app.route('/home', methods=['GET'])
def home():
    return render_template('home.html',username= request.args.get('user'),serv_response = request.args.get('req'))

"""
@app.route('/register', methods=['GET','POST'])
def register():
    error = None
    if request.method == 'POST':
        rq_code , rq_json = requetes_keycloak.requete_s_enregister(request.form['username'],request.form['password'],request.form['prenom'],request.form['nom'],request.form['email'])
        #print(rq_json)
        print(rq_code)
        print(rq_json)
        
        if(rq_code != 200):
            error = 'Invalid Credentials. Please try again.'
            error = rq_json['error']
        else:
            print('register successfull')
            session['access_token'] = rq_json['access_token']
            session['refresh_token'] = rq_json['refresh_token']
            session['user'] = request.form['username']
            print("ici")
            return redirect(url_for('home',req = rq_json,user = request.form['username']))

    return render_template('register.html', error=error)
"""

@app.route('/logout', methods=['POST'])
def logout():
    if 'access_token' in session:
        statut = requetes_keycloak.requete_deconnecter(session['access_token'],session['refresh_token'])
        if statut == 200 or statut == 204 : 
            session.pop('access_token', None)
            session.pop('refresh_token', None)
            return redirect(url_for('login'))


@app.route('/infos', methods=['GET','POST'])
def infos():
    if 'access_token' in session:
        if request.method == 'POST':
            statut ,rq = requetes_keycloak.requete_infos(session['access_token'])
            print("statut de la requete : " + str(statut))
            if statut == 200 or statut == 204 :
                rq_code , rq_json = requetes_keycloak.requete_infos(session['access_token'])
                return redirect(url_for('infos',req = rq_json,user = session['user']))
        else:
            return render_template('infos.html',username= request.args.get('user'),serv_response = request.args.get('req'))