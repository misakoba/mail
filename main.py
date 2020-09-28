"""A Flask app implementing the mailing backend for misakoba.github.io."""

import http
import sys
import os

import flask
import flask_cors  # type: ignore
import requests


class MisakobaMailError(Exception):
    """Base class for application-specific errors."""


class UndefinedReCAPTCHASecretError(MisakobaMailError):
    """Error for undefined reCAPTCHA secret."""


def create_app():
    """Creates the Flask app."""
    app = flask.Flask(__name__)  # pylint: disable=redefined-outer-name
    flask_cors.CORS(app)

    app.config['RECAPTCHA_SECRET'] = os.environ.get('RECAPTCHA_SECRET')
    if not app.config['RECAPTCHA_SECRET']:
        raise UndefinedReCAPTCHASecretError(
            'Cannot create web application without RECAPTCHA_SECRET '
            'configuration value.')

    @app.route('/send', methods=['POST'])
    def send():  # pylint: disable=unused-variable
        """Serves the '/send' endpoint for sending messages."""
        response = requests.post(
            'https://www.google.com/recaptcha/api/siteverify',
            params={
                'secret': app.config['RECAPTCHA_SECRET'],
                'response': flask.request.args['recaptcha_response'],
            })

        try:
            response.raise_for_status()
        except requests.HTTPError:
            flask.abort(http.HTTPStatus.INTERNAL_SERVER_ERROR,
                        b'Error in communicating with reCAPTCHA server.')

        return 'Successfully validated message request.'

    return app


def create_app_or_die():
    """Create the webapp, or report the error and terminate."""
    try:
        return create_app()
    except MisakobaMailError as error:
        sys.exit(str(error))


app = create_app_or_die()  # Default GAE Entry point


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
