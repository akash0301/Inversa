from flask import Flask,render_template, request, redirect,url_for
from wtforms import Form,StringField
import os
import time

class params(Form):
    site = StringField('site')
    vulnerability = StringField('vulnerability')

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

def long_load():
    time.sleep(10) #just simulating the waiting period
    return "Your Tracking is in progress "

@app.route('/upload', methods=['POST'])
def upload():
    form = params(request.form)
    site=form.site.data
    vulnerability=form.vulnerability.data
    print(site,vulnerability)
    
    os.system('python3 temp.py '+site+' -v '+ vulnerability)
    # os.system('python3 temp.py -v Injection')
    return redirect('/')
    

if __name__ == '__main__':
    app.run()

    

