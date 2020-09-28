"""A Flask app implementing the mailing backend for misakoba.github.io."""

import http
import os

import flask
import flask_cors  # type: ignore
import requests

app = flask.Flask(__name__)  # Default GAE Entry point
flask_cors.CORS(app)

@app.route('/send', methods=['POST'])
def send():
    """Serves the '/send' endpoint for sending messages."""
    response = requests.post(
        'https://www.google.com/recaptcha/api/siteverify',
        params={
            'secret': os.environ['RECAPTCHA_SECRET'],
            'response': flask.request.args['recaptcha_response'],
        })

    try:
        response.raise_for_status()
    except requests.HTTPError:
        flask.abort(http.HTTPStatus.INTERNAL_SERVER_ERROR,
                    b'Error in communicating with reCAPTCHA server.')

    return 'Successfully validated message request.'


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
