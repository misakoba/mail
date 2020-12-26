"""A Flask app implementing the mailing backend for misakoba.github.io."""

import email.errors
import email.headerregistry
import email.policy
import json
import logging
import sys
import os

import flask
import google.cloud.logging  # type: ignore
import flask_cors  # type: ignore
import werkzeug.exceptions
import werkzeug.middleware.proxy_fix

import misakoba_mail.exceptions
import misakoba_mail.messages

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
            raise misakoba_mail.exceptions.InvalidProxyFixXForError(
                proxy_fix_x_for) from error

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
            raise misakoba_mail.exceptions.InvalidLoggingLevelError(
                logging_level_name)
        config['LOGGING_LEVEL'] = logging_level


def _check_for_required_config_values(config):
    for config_value_name in REQUIRED_CONFIG_VALUES:
        if not config[config_value_name]:
            raise misakoba_mail.exceptions.MissingRequiredConfigValueError(
                f'Cannot create web application without {config_value_name} '
                'configuration value.')


def _check_message_to(raw_message_to):
    try:
        standardized_to_header = email.policy.strict.header_factory(
            'to', raw_message_to)
    except IndexError as error:
        raise misakoba_mail.exceptions.InvalidMessageToError(
            "Could not parse MESSAGE_TO config value "
            f"{raw_message_to!r}.") from error

    if defects := standardized_to_header.defects:
        defects_listing = '\n'.join(f'- {defect}' for defect in defects)
        raise misakoba_mail.exceptions.InvalidMessageToError(
            f'MESSAGE_TO config value {raw_message_to!r} has '
            f'the following defects:\n{defects_listing}')


def _add_handlers(app):
    app.register_blueprint(misakoba_mail.messages.messages)

    @app.errorhandler(werkzeug.exceptions.HTTPException)
    def handle_exception(error):  # pylint: disable=unused-variable
        """Returns JSON instead of HTML for HTTP errors."""
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
    except misakoba_mail.exceptions.MisakobaMailError as error:
        sys.exit(str(error))
