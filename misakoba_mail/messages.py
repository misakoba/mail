"""Defines the blueprint for handling the '/messages' endpoint."""
import email.errors
import email.headerregistry
import http

import flask
import requests

RECAPTCHA_DEFAULT_EXPECTED_ACTION = 'submit'
RECAPTCHA_DEFAULT_SCORE_THRESHOLD = 0.5
EXTERNAL_SERVICE_DEFAULT_TIMEOUT_SECONDS = 15.0
SEND_FORM_REQUIRED_FIELDS = {'g-recaptcha-response', 'name', 'email',
                             'message'}

messages = flask.Blueprint('messages', __name__, url_prefix='/messages')


@messages.route('', methods=['POST'])
def send_message():
    """Serves the '/messages' endpoint for sending messages."""
    _validate_form()
    _validate_recaptcha_response()
    _send_message_via_mailgun_api()

    return 'Successfully sent message.'


def _validate_form():
    for field in SEND_FORM_REQUIRED_FIELDS:
        _check_missing_send_form_field(field)
        _check_empty_form_field(field)

    addr_spec = flask.request.form['email']
    try:
        email.headerregistry.Address(addr_spec=addr_spec)
    except (IndexError,
            ValueError,
            email.errors.HeaderParseError):
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
        'timeout': EXTERNAL_SERVICE_DEFAULT_TIMEOUT_SECONDS,
    }
    flask.current_app.logger.info('POST to reCAPTCHA site verify: %s',
                                  post_kwargs)
    try:
        return requests.post(**post_kwargs)
    except requests.exceptions.ConnectionError as error:
        _abort_on_recaptcha_communication_error(error)


def _check_recaptcha_site_verify_http_status(response):
    flask.current_app.logger.info('reCAPTCHA site verify response status: %s',
                                  response)
    try:
        response.raise_for_status()
    except requests.HTTPError as error:
        _abort_on_recaptcha_communication_error(error)


def _abort_on_recaptcha_communication_error(error):
    flask.current_app.logger.error(
        f'Error in communicating with reCAPTCHA server: {error}')
    flask.abort(http.HTTPStatus.INTERNAL_SERVER_ERROR,
                'Error in communicating with reCAPTCHA server.')


def _check_recaptcha_site_verify_response_contents(response):
    site_verify_response = response.json()
    flask.current_app.logger.info('reCAPTCHA site verify response data: %s',
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
    flask.current_app.logger.error(
        'Non-client errors detected in with reCAPTCHA siteverify '
        'API.\n'
        f'request parameters: {_recaptcha_site_verify_params()}\n'
        f'siteverify response data: {site_verify_response}')
    flask.abort(http.HTTPStatus.INTERNAL_SERVER_ERROR,
                'An error was encountered when validating the '
                'reCAPTCHA response token. Please try again later.')


def _recaptcha_site_verify_params():
    return {
        'secret': flask.current_app.config['RECAPTCHA_SECRET'],
        'response': flask.request.form['g-recaptcha-response'],
        'remoteip': flask.request.remote_addr,
    }


def _send_message_via_mailgun_api():
    post_kwargs = _mailgun_message_post_kwargs()
    app = flask.current_app
    app.logger.info('POST to Mailgun messages API: %s',
                    _pii_redacted(post_kwargs))
    try:
        response = requests.post(**post_kwargs)
    except requests.ConnectionError as error:
        _abort_on_mailgun_communication_error(error, post_kwargs)
    _check_mailgun_send_response_status(post_kwargs, response)
    app.logger.info('Mailgun messages API response data: %s',
                    response.json())


def _mailgun_message_post_kwargs():
    app = flask.current_app
    post_kwargs = {
        'url': 'https://api.mailgun.net/v3/'
               f"{app.config['MAILGUN_DOMAIN']}/messages",
        'auth': ('api', app.config['MAILGUN_API_KEY']),
        'data': {'from': _create_from_header(),
                 'to': app.config['MESSAGE_TO'],
                 'text': flask.request.form['message']},
        'timeout': EXTERNAL_SERVICE_DEFAULT_TIMEOUT_SECONDS,
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
    flask.current_app.logger.info(
        'Mailgun messages API response status: %s', response)
    try:
        response.raise_for_status()
    except requests.HTTPError as error:
        _abort_on_mailgun_communication_error(error, post_kwargs)


def _abort_on_mailgun_communication_error(error, post_kwargs):
    flask.current_app.logger.error(
        f'Mailgun send message request encountered error: {error!r}\n'
        f'POST sent with parameters: {_pii_redacted(post_kwargs)}')
    flask.abort(http.HTTPStatus.INTERNAL_SERVER_ERROR,
                'An error was encountered when sending the message. '
                'Please try again later.')


def _pii_redacted(post_kwargs):
    redacted_kwargs = {k: v for k, v in post_kwargs.items() if k != 'data'}
    redacted_kwargs['data'] = {
        key: '<REDACTED>' if key in {'from', 'text'} else value
        for key, value in post_kwargs['data'].items()}
    return redacted_kwargs
