"""A Flask app implementing the mailing backend for misakoba.github.io."""

import email.headerregistry
import email.policy
import http
import json
import logging
import sys
import os

import flask
import google.cloud.logging  # type: ignore
import flask_cors  # type: ignore
import requests
import werkzeug.exceptions
import werkzeug.middleware.proxy_fix

RECAPTCHA_DEFAULT_EXPECTED_ACTION = 'submit'
RECAPTCHA_DEFAULT_SCORE_THRESHOLD = 0.5
SEND_FORM_REQUIRED_FIELDS = {'g-recaptcha-response', 'name', 'email',
                             'message'}
CONFIG_VALUES = {
    'RECAPTCHA_SECRET',
    'MAILGUN_API_KEY',
    'MAILGUN_DOMAIN',
    'MESSAGE_TO',
    'MESSAGE_SUBJECT',
    'LOGGING_LEVEL',
    'USE_GOOGLE_CLOUD_LOGGING',
    'USE_PROXY_FIX',
}

STR_CONFIG_VALUES = {'RECAPTCHA_SECRET', 'MAILGUN_API_KEY', 'MAILGUN_DOMAIN',
                     'MESSAGE_TO', 'MESSAGE_SUBJECT'}

assert STR_CONFIG_VALUES <= CONFIG_VALUES

REQUIRED_CONFIG_VALUES = {'RECAPTCHA_SECRET', 'MAILGUN_API_KEY',
                          'MAILGUN_DOMAIN', 'MESSAGE_TO'}

assert REQUIRED_CONFIG_VALUES <= CONFIG_VALUES


class MisakobaMailError(Exception):
    """Base class for application-specific errors."""


class MissingRequiredConfigValueError(MisakobaMailError):
    """Error for MissingConfigValue."""


class InvalidMessageToError(MisakobaMailError):
    """Error when the Message's 'to' Header is invalid."""


class InvalidEnvironmentConfigValueError(MisakobaMailError):
    """Error for invalid config values derived from the environment."""
    def __init__(self, config_value_name, value):
        super().__init__()
        self.config_value_name = config_value_name
        self.value = value

    def __str__(self):
        return (f'Invalid {self.config_value_name} value {self.value!r} '
                f'specified.')


class InvalidLoggingLevelError(InvalidEnvironmentConfigValueError):
    """Error if the 'LOGGING_LEVEL' config value is invalid."""

    def __init__(self, value):
        super().__init__('LOGGING_LEVEL', value)


class InvalidProxyFixXForError(InvalidEnvironmentConfigValueError):
    """Error if the 'PROXY_FIX_X_FOR' config value is invalid."""

    def __init__(self, value):
        super().__init__('PROXY_FIX_X_FOR', value)


def create_app():
    """Creates the Flask app."""

    app = flask.Flask(__name__)
    flask_cors.CORS(app)
    _configure(app)

    _add_handlers(app)
    return app


def _configure(app):
    config = app.config
    _populate_config_from_environment(config)
    _check_for_required_config_values(config)
    _check_message_to(config['MESSAGE_TO'])

    if config.get('USE_GOOGLE_CLOUD_LOGGING'):
        logging_client = google.cloud.logging.Client()
        logging_client.setup_logging()

    if (logging_level := app.config.get('LOGGING_LEVEL')) is not None:
        app.logger.setLevel(logging_level)

    if config['USE_PROXY_FIX']:
        app.wsgi_app = werkzeug.middleware.proxy_fix.ProxyFix(
            app.wsgi_app, x_for=config['PROXY_FIX_X_FOR'])


def _populate_config_from_environment(config):
    for config_value_name in STR_CONFIG_VALUES:
        config[config_value_name] = os.environ.get(config_value_name)

    config['USE_GOOGLE_CLOUD_LOGGING'] = bool(
        os.environ.get('USE_GOOGLE_CLOUD_LOGGING'))

    if use_proxy_fix := bool(os.environ.get('USE_PROXY_FIX')):
        proxy_fix_x_for = os.environ.get('PROXY_FIX_X_FOR', 1)
        try:
            config['PROXY_FIX_X_FOR'] = int(proxy_fix_x_for)
        except ValueError as error:
            raise InvalidProxyFixXForError(proxy_fix_x_for) from error

    config['USE_PROXY_FIX'] = use_proxy_fix

    _configure_logging_level_from_env(config)


def _configure_logging_level_from_env(config):
    logging_levels_by_name = {
        'CRITICAL': logging.CRITICAL,
        'ERROR': logging.ERROR,
        'WARNING': logging.WARNING,
        'INFO': logging.INFO,
        'DEBUG': logging.DEBUG,
        'NOTSET': logging.NOTSET,
    }
    if logging_level_name := os.environ.get('LOGGING_LEVEL'):
        logging_level = logging_levels_by_name.get(logging_level_name)
        if logging_level is None:
            raise InvalidLoggingLevelError(logging_level_name)
        config['LOGGING_LEVEL'] = logging_level


def _check_for_required_config_values(config):
    for config_value_name in REQUIRED_CONFIG_VALUES:
        if not config[config_value_name]:
            raise MissingRequiredConfigValueError(
                f'Cannot create web application without {config_value_name} '
                'configuration value.')


def _check_message_to(raw_message_to):
    try:
        standardized_to_header = email.policy.strict.header_factory(
            'to', raw_message_to)
    except IndexError as error:
        raise InvalidMessageToError(
            "Could not parse MESSAGE_TO config value "
            f"{raw_message_to!r}.") from error

    if defects := standardized_to_header.defects:
        defects_listing = '\n'.join(f'- {defect}' for defect in defects)
        raise InvalidMessageToError(
            f'MESSAGE_TO config value {raw_message_to!r} has '
            f'the following defects:\n{defects_listing}')


def _add_handlers(app):  # pylint: disable=too-many-locals, too-many-statements
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
        post_kwargs = {
            'url': 'https://www.google.com/recaptcha/api/siteverify',
            'params': _recaptcha_site_verify_params(),
        }
        app.logger.info('POST to RECAPTCHA site verify: %s', post_kwargs)
        return requests.post(**post_kwargs)

    def _check_recaptcha_site_verify_http_status(response):
        app.logger.info('reCAPTCHA site verify response status: %s', response)
        try:
            response.raise_for_status()
        except requests.HTTPError as error:
            app.logger.exception(  # pylint: disable=no-member
                f'Error in communicating with reCAPTCHA server: {error}')
            flask.abort(http.HTTPStatus.INTERNAL_SERVER_ERROR,
                        'Error in communicating with reCAPTCHA server.')

    def _check_recaptcha_site_verify_response_contents(response):
        site_verify_response = response.json()
        app.logger.info('reCAPTCHA site verify response data: %s',
                        site_verify_response)
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
            'secret': app.config['RECAPTCHA_SECRET'],
            'response': flask.request.form['g-recaptcha-response'],
            'remoteip': flask.request.remote_addr,
        }

    def _send_message_via_mailgun_api():
        post_kwargs = _mailgun_message_post_kwargs()
        response = requests.post(**post_kwargs)
        _check_mailgun_send_response_status(post_kwargs, response)

    def _mailgun_message_post_kwargs():
        post_kwargs = {
            'url': 'https://api.mailgun.net/v3/'
                   f"{app.config['MAILGUN_DOMAIN']}/messages",
            'auth': ('api', app.config['MAILGUN_API_KEY']),
            'data': {'from': _create_from_header(),
                     'to': app.config['MESSAGE_TO'],
                     'text': flask.request.form['message']},

        }

        if subject := app.config.get('MESSAGE_SUBJECT'):
            post_kwargs['data']['subject'] = subject

        return post_kwargs

    def _create_from_header():
        from_address = str(email.headerregistry.Address(
            display_name=flask.request.form['name'],
            addr_spec=flask.request.form['email']))
        return from_address

    def _check_mailgun_send_response_status(post_kwargs, response):
        try:
            response.raise_for_status()
        except requests.HTTPError as error:
            app.logger.error(  # pylint: disable=no-member
                f'Mailgun send message request encountered error: {error!r}\n'
                f'POST sent with parameters: {_pii_redacted(post_kwargs)}'
            )
            flask.abort(http.HTTPStatus.INTERNAL_SERVER_ERROR,
                        'An error was encountered when sending the message. '
                        'Please try again later.')

    def _pii_redacted(post_kwargs):
        redacted_kwargs = {k: v for k, v in post_kwargs.items() if k != 'data'}
        redacted_kwargs['data'] = {
            key: '<REDACTED>' if key in {'from', 'text'} else value
            for key, value in post_kwargs['data'].items()}
        return redacted_kwargs

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


def create_app_or_die():
    """Create the webapp, or report the error and terminate."""
    try:
        return create_app()
    except MisakobaMailError as error:
        sys.exit(str(error))


if __name__ == '__main__':
    create_app_or_die().run(host='127.0.0.1', port=8080, debug=True)
