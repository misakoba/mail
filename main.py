"""A Flask app implementing the mailing backend for misakoba.github.io."""

import http
import json
import sys
import os

import flask
import werkzeug.exceptions
import flask_cors  # type: ignore
import requests

RECAPTCHA_DEFAULT_EXPECTED_ACTION = 'submit'


class MisakobaMailError(Exception):
    """Base class for application-specific errors."""


class UndefinedReCAPTCHASecretError(MisakobaMailError):
    """Error for undefined reCAPTCHA secret."""


def create_app():
    """Creates the Flask app."""
    app = flask.Flask(__name__)
    flask_cors.CORS(app)

    app.config['RECAPTCHA_SECRET'] = os.environ.get('RECAPTCHA_SECRET')
    if not app.config['RECAPTCHA_SECRET']:
        raise UndefinedReCAPTCHASecretError(
            'Cannot create web application without RECAPTCHA_SECRET '
            'configuration value.')

    @app.route('/send', methods=['POST'])
    def send():  # pylint: disable=unused-variable
        """Serves the '/send' endpoint for sending messages."""
        _validate_send_parameters()
        response = _post_to_recaptcha_site_verify()
        _check_recaptcha_site_verify_http_status(response)
        _check_recaptcha_site_verify_response_contents(response)

        return 'Successfully validated message request.'

    def _validate_send_parameters():
        if 'recaptcha_response' not in flask.request.args:
            flask.abort(http.HTTPStatus.BAD_REQUEST,
                        'Request sent without recaptcha_response parameter.')

    def _post_to_recaptcha_site_verify():
        response = requests.post(
            'https://www.google.com/recaptcha/api/siteverify',
            params={
                'secret': app.config['RECAPTCHA_SECRET'],
                'response': flask.request.args['recaptcha_response'],
                'remoteip': flask.request.remote_addr,
            })
        return response

    def _check_recaptcha_site_verify_http_status(response):
        try:
            response.raise_for_status()
        except requests.HTTPError as error:
            app.logger.exception(  # pylint: disable=no-member
                f'Error in communicating with reCAPTCHA server: {error}')
            flask.abort(http.HTTPStatus.INTERNAL_SERVER_ERROR,
                        'Error in communicating with reCAPTCHA server.')

    def _check_recaptcha_site_verify_response_contents(response):
        site_verify_response = response.json()
        if site_verify_response['success']:
            _check_recaptcha_action(site_verify_response['action'])

    def _check_recaptcha_action(action):
        if action != RECAPTCHA_DEFAULT_EXPECTED_ACTION:
            flask.abort(
                http.HTTPStatus.BAD_REQUEST,
                f'The received reCAPTCHA action "{action}" is not '
                'expected on this server.')

    @app.errorhandler(werkzeug.exceptions.HTTPException)
    def handle_exception(error):  # pylint: disable=unused-variable
        """Return JSON instead of HTML for HTTP errors."""
        response = error.get_response()
        response.data = json.dumps({
            'code': error.code,
            'name': error.name,
            'description': error.description,
        })
        response.content_type = 'application/json'
        return response

    return app


def create_app_or_die():
    """Create the webapp, or report the error and terminate."""
    try:
        return create_app()
    except MisakobaMailError as error:
        sys.exit(str(error))


if __name__ == '__main__':
    create_app_or_die().run(host='127.0.0.1', port=8080, debug=True)
