from flask import Flask, request
from jinja2 import Template
from markupsafe import escape

name = "main"
app = Flask(name)

@app.route("/page")
def page():
    name = escape(request.values.get('name'))
    age = escape(request.values.get('age', 'unknown'))
    output = Template('Hello ' + name + '! Your age is ' + age + '.').render()
    return output

if name == "main":
    app.run(debug=True)