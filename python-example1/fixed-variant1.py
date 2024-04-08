from flask import Flask, request
from jinja2 import Template

def parse_input_value(value : str) -> str:
    forbidden_chrs = set([*"<>/&%"])
    return ''.join([c for c in value if c not in forbidden_chrs])


name = "main"
app = Flask(name)

@app.route("/page")
def page():
    name = parse_input_value(str(request.values.get('name')))
    age = parse_input_value(request.values.get('age', 'unknown'))
    output = Template('Hello ' + name + '! Your age is ' + age + '.').render()
    return output

if name == "main":
    app.run(debug=True)