from flask import Flask
import json

test_dict = {"a": 1, "b": 2, "c": 3}
app = Flask(__name__)

json_test = json.dumps(test_dict)
xml_larger_than_2 = "<number_size>larger than 2</number_size>"
xml_smaller_than_2 = "<number_size>smaller than 2</number_size>"
xml_equal_to_2 = "<number_size>equal to 2</number_size>"

@app.route("/")
def front_page():
    return "<p>Hello, World!</p>"

@app.get("/test_get")
def test_get_api():
    return json_test

@app.post("/test_post/<int:post_id>")
def test_post_api(post_id):
    if post_id > 2:
        return xml_larger_than_2
    elif post_id < 2:
        return xml_smaller_than_2
    else:
        return xml_equal_to_2