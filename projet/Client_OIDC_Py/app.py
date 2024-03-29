# flask_ngrok_example.py
from flask import Flask, render_template, redirect, url_for, request, session
import requests
from Requests import requetes_keycloak # Requêtes préparées 
import config # Config
from base64 import b64decode

import jwt
from cryptography.hazmat.primitives import serialization
from jwt import PyJWKClient
    
app = Flask(__name__,static_url_path='/static')
app.secret_key = config.app_secret_key


@app.route('/')
def default():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        rq_code , rq_json = requetes_keycloak.requete_jeton_user(request.form['username'],request.form['password'])
        if(rq_code != 200):
            error = 'Invalid Credentials. Please try again.'
        else:
            session['access_token'] = rq_json['access_token']
            session['refresh_token'] = rq_json['refresh_token']
            session['user'] = request.form['username']

            pubkey = requetes_keycloak.requete_get_pubkey()
            payload = jwt.decode(rq_json['access_token'], pubkey, algorithms=["RS256"],options={"verify_aud": False, "verify_signature": True}) #CHECKER AUDIENCE
            var_to_send = str(rq_json) +"\r\n"+ str(payload)
            return redirect(url_for('home',req = var_to_send,user = request.form['username']))
    return render_template('login.html', error=error)


@app.route('/home', methods=['GET'])
def home():
    return render_template('home.html',username= request.args.get('user'),serv_response = request.args.get('req'))


@app.route('/register', methods=['GET','POST'])
def register():
    error = None
    if request.method == 'POST':
        r,r_json = requetes_keycloak.requete_jeton_client()
        rq_code , rq_json = requetes_keycloak.requete_s_enregister(request.form['username'],request.form['password'],request.form['prenom'],request.form['nom'],request.form['email'],r_json['access_token'])
        if(rq_code != 201):
            error = 'Invalid Credentials. Please try again.'
            error = rq_json.json().get('errorMessage')
        else:
            session['user'] = request.form['username']
            rq_code , rq_json = requetes_keycloak.requete_jeton_user(request.form['username'],request.form['password'])
            session['access_token'] = rq_json['access_token']
            session['refresh_token'] = rq_json['refresh_token']      
            return redirect(url_for('home',req = rq_json,user = request.form['username']))
    return render_template('register.html', error=error)


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
            if statut == 200 or statut == 204 :
                rq_code , rq_json = requetes_keycloak.requete_infos(session['access_token'])
                return redirect(url_for('infos',req = rq_json,user = session['user']))
        else:
            return render_template('infos.html',username= request.args.get('user'),serv_response = request.args.get('req'))

# mettre en dernier pour 
if __name__ == '__main__':
    app.run(host='0.0.0.0',port='5000',debug=True)