import ast
import json
import pyshark
import time
from flask import Flask
from flask_cors import CORS, cross_origin

app = Flask(__name__)
CORS(app, support_credentials=True)


@app.route('/results', methods=['GET'])
@cross_origin(supports_credentials=True)
# Return prediction for inference model with the requested data as input
def results():
    file = open("captured.txt")
    result = ast.literal_eval(file.read())
    file.close()

    return json.dumps(result)


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
