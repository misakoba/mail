"""A Flask app implementing the mailing backend for misakoba.github.io."""

import email.headerregistry
import email.policy
import http
import json
import sys
import os

import flask
import werkzeug.exceptions
import flask_cors  # type: ignore
import requests

RECAPTCHA_DEFAULT_EXPECTED_ACTION = 'submit'
RECAPTCHA_DEFAULT_SCORE_THRESHOLD = 0.5
SEND_FORM_REQUIRED_FIELDS = {'g-recaptcha-response', 'name', 'email',
                             'message'}
REQUIRED_CONFIG_VALUES = {'RECAPTCHA_SECRET', 'MAILGUN_API_KEY',
                          'MAILGUN_DOMAIN', 'MESSAGE_TO_HEADER'}


class MisakobaMailError(Exception):
    """Base class for application-specific errors."""


class MissingRequiredConfigValueError(MisakobaMailError):
    """Error for MissingConfigValue."""


class InvalidMessageToHeader(MisakobaMailError):
    """Error if the Message's To Header is invalid"""


def create_app():  # pylint: disable=too-many-statements
    """Creates the Flask app."""
    # pylint: disable=too-many-locals

    app = flask.Flask(__name__)
    flask_cors.CORS(app)

    config = app.config
    _populate_config_from_environment(config)
    _check_for_required_config_values(config)
    _standardized_message_to_header(config['MESSAGE_TO_HEADER'])

    @app.route('/messages', methods=['POST'])
    def send_message():  # pylint: disable=unused-variable
        """Serves the '/messages' endpoint for sending messages."""
        _validate_form()
        _validate_recaptcha_response()
        _send_message_via_mailgun_api()

        return 'Successfully sent message.'

    def _validate_form():
        for field in SEND_FORM_REQUIRED_FIELDS:
            _check_missing_send_form_field(field)
            _check_empty_form_field(field)

        # NOTE: The exceptions returned by email.registry.Address are currently
        # (as of 2020-10-05) not documented well, so we're using a catch-all
        # exception below.
        addr_spec = flask.request.form['email']
        try:
            email.headerregistry.Address(addr_spec=addr_spec)
        except Exception:  # pylint: disable=broad-except
            flask.abort(http.HTTPStatus.BAD_REQUEST,
                        f'Email address "{addr_spec}" is invalid.')

    def _check_missing_send_form_field(field):
        if field not in flask.request.form:
            flask.abort(
                http.HTTPStatus.BAD_REQUEST,
                f'The posted form was missing the "{field}" field.')

    def _check_empty_form_field(field):
        if flask.request.form[field] == '':
            flask.abort(http.HTTPStatus.BAD_REQUEST,
                        f'The posted form had an empty "{field}" field.')

    def _validate_recaptcha_response():
        response = _post_to_recaptcha_site_verify()
        _check_recaptcha_site_verify_http_status(response)
        _check_recaptcha_site_verify_response_contents(response)

    def _post_to_recaptcha_site_verify():
        return requests.post(
            'https://www.google.com/recaptcha/api/siteverify',
            params=_recaptcha_site_verify_params())

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
            _check_recaptcha_score(site_verify_response['score'])
        else:
            _check_site_verify_response_client_only_errors(
                site_verify_response)
            _handle_non_client_site_verify_error(site_verify_response)

    def _check_recaptcha_action(action):
        if action != RECAPTCHA_DEFAULT_EXPECTED_ACTION:
            flask.abort(
                http.HTTPStatus.BAD_REQUEST,
                f'The received reCAPTCHA action "{action}" is not '
                'expected on this server.')

    def _check_recaptcha_score(score):
        if score < RECAPTCHA_DEFAULT_SCORE_THRESHOLD:
            flask.abort(http.HTTPStatus.BAD_REQUEST,
                        f'The received reCAPTCHA score {score} was too low to '
                        f'send a message.')

    def _check_site_verify_response_client_only_errors(site_verify_response):
        _check_site_verify_response_invalid_input_response(
            site_verify_response)
        _check_site_verify_response_timeout_or_duplicate(
            site_verify_response)

    def _check_site_verify_response_invalid_input_response(
            site_verify_response):
        if site_verify_response['error-codes'] == ['invalid-input-response']:
            flask.abort(
                http.HTTPStatus.BAD_REQUEST,
                'The recaptcha_response parameter value '
                f'"{flask.request.form["g-recaptcha-response"]}" was not '
                'valid.')

    def _check_site_verify_response_timeout_or_duplicate(site_verify_response):
        if site_verify_response['error-codes'] == ['timeout-or-duplicate']:
            flask.abort(
                http.HTTPStatus.BAD_REQUEST,
                'The recaptcha_response parameter value '
                f'"{flask.request.form["g-recaptcha-response"]}" was too '
                'old or previously used.')

    def _handle_non_client_site_verify_error(site_verify_response):
        app.logger.error(  # pylint: disable=no-member
            'Non-client errors detected in with reCAPTCHA siteverify '
            'API.\n'
            f'request parameters: {_recaptcha_site_verify_params()}\n'
            f'siteverify response data: {site_verify_response}')
        flask.abort(http.HTTPStatus.INTERNAL_SERVER_ERROR,
                    'An error was encountered when validating the '
                    'reCAPTCHA response token. Please try again later.')

    def _recaptcha_site_verify_params():
        return {
            'secret': config['RECAPTCHA_SECRET'],
            'response': flask.request.form['g-recaptcha-response'],
            'remoteip': flask.request.remote_addr,
        }

    def _send_message_via_mailgun_api():
        requests.post(
            f"https://api.mailgun.net/v3/{app.config['MAILGUN_DOMAIN']}/"
            'messages',
            auth=('api', app.config['MAILGUN_API_KEY']),
            data={'from': str(email.headerregistry.Address(
                display_name=flask.request.form['name'],
                addr_spec=flask.request.form['email'])),
                'to': app.config['MESSAGE_TO_HEADER'],
                'text': flask.request.form['message']})

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


def _populate_config_from_environment(config):
    for config_value_name in REQUIRED_CONFIG_VALUES:
        config[config_value_name] = os.environ.get(config_value_name)


def _check_for_required_config_values(config):
    for config_value_name in REQUIRED_CONFIG_VALUES:
        if not config[config_value_name]:
            raise MissingRequiredConfigValueError(
                f'Cannot create web application without {config_value_name} '
                'configuration value.')


def _standardized_message_to_header(raw_message_to_header):
    try:
        standardized_to_header = email.policy.strict.header_factory(
            'to', raw_message_to_header)
    except IndexError as error:
        raise InvalidMessageToHeader(
            "Could not parse MESSAGE_TO_HEADER config value "
            f"{raw_message_to_header!r}.") from error

    if defects := standardized_to_header.defects:
        defects_listing = '\n'.join(f'- {defect}' for defect in defects)
        raise InvalidMessageToHeader(
            f'MESSAGE_TO_HEADER config value {raw_message_to_header!r} has '
            f'the following defects:\n{defects_listing}')

    return standardized_to_header


def create_app_or_die():
    """Create the webapp, or report the error and terminate."""
    try:
        return create_app()
    except MisakobaMailError as error:
        sys.exit(str(error))


if __name__ == '__main__':
    create_app_or_die().run(host='127.0.0.1', port=8080, debug=True)
