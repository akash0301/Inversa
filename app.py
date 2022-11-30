from flask import Flask,render_template, request, redirect,url_for
from wtforms import Form,StringField
import os
import time
import subprocess


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

@app.route('/report/<response>')
def report(response):
    f = open("rs.vul."+response, "r")
    response=f.read()
    return render_template('report.html',response=response)

@app.route('/upload', methods=['POST'])
def upload():
    form = params(request.form)
    site=form.site.data
    vulnerability=form.vulnerability.data
    print(site,vulnerability)
    
    os.system('python3 inversa.py '+site+' -v '+ vulnerability)
    dict_s=site.split('.')
    site=""
    for i in range(1,len(dict_s)):
        if i == 1:
            site=site+dict_s[i]
        else:
            site=site+'.'+dict_s[i]
    path="rs.vul."+site+'.txt'
    subprocess.call(('xdg-open', path))

    return redirect('/')

    

if __name__ == '__main__':
    app.run()

"""
proc = subprocess.Popen(['python3','inversa.py',site,'-v',vulnerability],stdout=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    print("program output:", stdout)
    
    dict_s=site.split('.')
    site=""
    for i in range(1,len(dict_s)):
        if i == 1:
            site=site+dict_s[i]
        else:
            site=site+'.'+dict_s[i]
"""

    

