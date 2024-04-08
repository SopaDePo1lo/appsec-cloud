from flask import Flask, request
from jinja2 import Template

name = "main"
app = Flask(name)

@app.route("/page")
def page():
    name = request.values.get('name')
    age = request.values.get('age', 'unknown')
    output = Template('Hello ' + str(name) + '! Your age is ' + age + '.').render()
    return output

if name == "main":
    app.run(debug=True)