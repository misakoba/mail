"""A Flask app implementing the mailing backend for misakoba.github.io."""

import os

import flask
import flask_cors
import requests

app = flask.Flask(__name__)  # Default GAE Entry point
flask_cors.CORS(app)


@app.route('/send', methods=['POST'])
def send():
    """Serves the '/send' endpoint for sending messages."""
    requests.post(
        'https://www.google.com/recaptcha/api/siteverify',
        params={
            'secret': os.environ['RECAPTCHA_SECRET'],
            'response': flask.request.args['recaptcha_response'],
        })

    return 'Successfully validated message request.'


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
