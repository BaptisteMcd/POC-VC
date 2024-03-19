# flask_ngrok_example.py
from flask import Flask
from flask import render_template
import requests


app = Flask(__name__)




@app.route('/')
def default(name=None):
    return render_template('index.html', name=name)


@app.route('/hello/')
@app.route('/hello/<name>')
def hello(name=None):
    return render_template('hello.html', name=name)