"""Unit tests for misakoba-mail's main module."""

import collections
import http
import json
from unittest import mock

import pytest
import requests

import main


@pytest.fixture(name='client')
def _a_test_client():
    return _a_test_client_with()


def _a_test_client_with(*, environment=None):
    """Creates and returns the default Flask test client fixture."""
    app = _an_app_with(environment=environment)
    app.testing = True
    return app.test_client()


def _an_app_with(*, environment=None):
    if environment is None:
        environment = _an_environment()
    with mock.patch.dict('os.environ', environment):
        app = main.create_app()
    return app


def test_successful_send_message(client, subtests):
    """Tests messages successfully sent."""
    message_forms = [
        _a_message_form_with(g_recaptcha_response='my_request_token',
                             name='Mr. X',
                             email='mr.x@somedomain.com',
                             message="Hey, what's up?"),
        _a_message_form_with(g_recaptcha_response='another_request_token',
                             name='Princess Peach',
                             email='peach@royal.gov.mk',
                             message="Please come to the castle. I've baked a "
                                     "cake for you."),
    ]
    mailgun_api_keys = ['some_mailgun_api_key', 'another_mailgun_api_key']
    mailgun_domains = ['some_mailgun_domain', 'another_mailgun_domain']
    message_tos = ['a@b.c', 'foo@bar.baz']
    expected_froms = [
       '"Mr. X" <mr.x@somedomain.com>',
       'Princess Peach <peach@royal.gov.mk>',
    ]
    for (message_form,
         mailgun_api_key,
         mailgun_domain,
         message_to,
         expected_from) in zip(message_forms,
                               mailgun_api_keys,
                               mailgun_domains,
                               message_tos,
                               expected_froms):
        with subtests.test(message_form=message_form,
                           mailgun_api_key=mailgun_api_key,
                           mailgun_domain=mailgun_domain,
                           message_to=message_to,
                           expected_from=expected_from):
            client = _a_test_client_with(
                environment=_an_environment_with(
                    mailgun_api_key=mailgun_api_key,
                    mailgun_domain=mailgun_domain,
                    message_to=message_to))
            with mock.patch('requests.post', autospec=True) as mock_post:
                mock_json = mock_post.return_value.json
                mock_json.return_value = _a_site_verify_response_with(
                    success=True)

                response = client.post('/messages', data=message_form)

            mock_post.assert_has_calls([
                # reCAPTCHA Validation
                mock.call(
                    'https://www.google.com/recaptcha/api/siteverify',
                    params={'secret': mock.ANY,
                            'response': message_form['g-recaptcha-response'],
                            'remoteip': mock.ANY,
                            }),
                mock.call().raise_for_status(),
                mock.call().json(),

                # Message sending
                mock.call(
                    f'https://api.mailgun.net/v3/{mailgun_domain}/messages',
                    auth=('api', mailgun_api_key),
                    data={
                        'from': expected_from,
                        'to': message_to,
                        'text': message_form['message'],
                    }),
            ])
            assert response.status_code == http.HTTPStatus.OK
            assert response.data == b'Successfully sent message.'


def test_message_subject_sent_if_defined():
    """Tests messages successfully sent."""
    client = _a_test_client_with(
         environment=_an_environment_with(message_subject='A message for you'))
    with mock.patch('requests.post', autospec=True) as mock_post:
        mock_json = mock_post.return_value.json
        mock_json.return_value = _a_site_verify_response_with(
            success=True)

        client.post('/messages', data=_a_message_form())

    mock_post.assert_called_with(
        mock.ANY,
        auth=mock.ANY,
        data={
            'from': mock.ANY,
            'to': mock.ANY,
            'subject': 'A message for you',
            'text': mock.ANY,
        })


def test_send_message_propagates_remote_ip(client, subtests):
    """Tests remote IP address sent to reCAPTCHA server."""
    for remote_addr in ['123.45.67.89', '98.76.54.123']:
        with subtests.test(remote_addr=remote_addr):
            with mock.patch('requests.post', autospec=True) as mock_post:
                client.post('/messages', data=_a_message_form(),
                            environ_base={'REMOTE_ADDR': remote_addr})

            mock_post.assert_called_once_with(
                'https://www.google.com/recaptcha/api/siteverify',
                params={'secret': mock.ANY,
                        'response': mock.ANY,
                        'remoteip': remote_addr,
                        })


def test_send_message_wrong_method(client):
    """Tests a 405 error returned when accessing send with a bad method."""
    response = client.get('/messages')

    assert response.status_code == http.HTTPStatus.METHOD_NOT_ALLOWED
    assert response.content_type == 'application/json'


def test_send_message_400_error_if_no_g_recaptcha_response_specified(client):
    """Tests 400 error returned if form has no reCAPTCHA response."""
    with mock.patch('requests.post', autospec=True) as mock_post:
        mock_json = mock_post.return_value.json
        mock_json.return_value = _a_site_verify_response_with(success=True)

        response = client.post(
            '/messages',
            data=_a_message_form_without('g-recaptcha-response'))

    assert response.status_code == http.HTTPStatus.BAD_REQUEST
    assert json.loads(response.data) == {
        'code': http.HTTPStatus.BAD_REQUEST,
        'name': 'Bad Request',
        'description': 'The posted form was missing the '
                       '"g-recaptcha-response" field.',
    }


def test_send_messgae_400_error_if_g_recaptcha_response_is_empty(client):
    """Tests 400 error returned if form has an empty g-recaptcha-response."""
    with mock.patch('requests.post', autospec=True) as mock_post:
        mock_json = mock_post.return_value.json
        mock_json.return_value = _a_site_verify_response_with(success=True)

        response = client.post(
            '/messages',
            data=_a_message_form_with(g_recaptcha_response=''))

    assert response.status_code == http.HTTPStatus.BAD_REQUEST
    assert json.loads(response.data) == {
        'code': http.HTTPStatus.BAD_REQUEST,
        'name': 'Bad Request',
        'description': 'The posted form had an empty "g-recaptcha-response" '
                       'field.'
    }


def test_send_message_400_error_if_no_name_specified(client):
    """Tests 400 error returned if form has no sender name."""
    with mock.patch('requests.post', autospec=True) as mock_post:
        mock_json = mock_post.return_value.json
        mock_json.return_value = _a_site_verify_response_with(success=True)

        response = client.post('/messages',
                               data=_a_message_form_without('name'))

    assert response.status_code == http.HTTPStatus.BAD_REQUEST
    assert json.loads(response.data) == {
        'code': http.HTTPStatus.BAD_REQUEST,
        'name': 'Bad Request',
        'description': 'The posted form was missing the "name" field.'
    }


def test_send_message_400_error_if_name_is_empty(client):
    """Tests 400 error returned if form has an empty sender name."""
    with mock.patch('requests.post', autospec=True) as mock_post:
        mock_json = mock_post.return_value.json
        mock_json.return_value = _a_site_verify_response_with(success=True)

        response = client.post('/messages',
                               data=_a_message_form_with(name=''))

    assert response.status_code == http.HTTPStatus.BAD_REQUEST
    assert json.loads(response.data) == {
        'code': http.HTTPStatus.BAD_REQUEST,
        'name': 'Bad Request',
        'description': 'The posted form had an empty "name" field.'
    }


def test_send_message_400_error_if_no_email_specified(client):
    """Tests 400 error returned if form has no sender email address."""
    with mock.patch('requests.post', autospec=True) as mock_post:
        mock_json = mock_post.return_value.json
        mock_json.return_value = _a_site_verify_response_with(success=True)

        response = client.post('/messages',
                               data=_a_message_form_without('email'))

    assert response.status_code == http.HTTPStatus.BAD_REQUEST
    assert json.loads(response.data) == {
        'code': http.HTTPStatus.BAD_REQUEST,
        'name': 'Bad Request',
        'description': 'The posted form was missing the "email" field.'
    }


def test_send_message_400_error_if_empty_email_specified(client):
    """Tests 400 error returned if form has an empty sender email address."""
    with mock.patch('requests.post', autospec=True) as mock_post:
        mock_json = mock_post.return_value.json
        mock_json.return_value = _a_site_verify_response_with(success=True)

        response = client.post('/messages',
                               data=_a_message_form_with(email=''))

    assert response.status_code == http.HTTPStatus.BAD_REQUEST
    assert json.loads(response.data) == {
        'code': http.HTTPStatus.BAD_REQUEST,
        'name': 'Bad Request',
        'description': 'The posted form had an empty "email" field.'
    }


def test_send_message_400_error_if_empty_email_is_invalid(client, subtests):
    """Tests 400 error returned if the sender email address has no domain."""
    invalid_addresses = [
        'foo',  # No domain
        'foo@',  # Empty domain
        'foo@.bar',  # Bad domain delimiter
        'foo@.bar.',  # Bad domain delimiters
        'foo@bar.',  # Bad domain delimiters
        'foo@bar,baz',  # Unexpected comma
    ]
    for email in invalid_addresses:
        with subtests.test(email=email):
            with mock.patch('requests.post', autospec=True) as mock_post:
                mock_json = mock_post.return_value.json
                mock_json.return_value = _a_site_verify_response_with(
                    success=True)

                response = client.post('/messages',
                                       data=_a_message_form_with(email=email))

            assert response.status_code == http.HTTPStatus.BAD_REQUEST
            assert json.loads(response.data) == {
                'code': http.HTTPStatus.BAD_REQUEST,
                'name': 'Bad Request',
                'description': f'Email address "{email}" is invalid.'
            }


def test_send_message_400_error_if_no_message_specified(client):
    """Tests 400 error returned if form has no sender email address."""
    with mock.patch('requests.post', autospec=True) as mock_post:
        mock_json = mock_post.return_value.json
        mock_json.return_value = _a_site_verify_response_with(success=True)

        response = client.post('/messages',
                               data=_a_message_form_without('message'))

    assert response.status_code == http.HTTPStatus.BAD_REQUEST
    assert json.loads(response.data) == {
        'code': http.HTTPStatus.BAD_REQUEST,
        'name': 'Bad Request',
        'description': 'The posted form was missing the "message" field.'
    }


def test_send_message_400_error_if_empty_message_specified(client):
    """Tests 400 error returned if form has an empty message."""
    with mock.patch('requests.post', autospec=True) as mock_post:
        mock_json = mock_post.return_value.json
        mock_json.return_value = _a_site_verify_response_with(success=True)

        response = client.post('/messages',
                               data=_a_message_form_with(message=''))

    assert response.status_code == http.HTTPStatus.BAD_REQUEST
    assert json.loads(response.data) == {
        'code': http.HTTPStatus.BAD_REQUEST,
        'name': 'Bad Request',
        'description': 'The posted form had an empty "message" field.'
    }


def test_send_message_recaptcha_request_failed(client):
    """Tests a 500 error returned when accessing send with a bad method."""
    mock_recaptcha_response = mock.create_autospec(requests.Response,
                                                   instance=True)
    mock_recaptcha_response.raise_for_status.side_effect = requests.HTTPError(
        'Bad request.')

    with mock.patch('requests.post', autospec=True) as mock_post:
        mock_raise_for_status = mock_post.return_value.raise_for_status
        mock_raise_for_status.side_effect = requests.HTTPError(
            'Bad request.')
        response = client.post('/messages',
                               data=_a_message_form())
        mock_post.assert_called_once_with(
            'https://www.google.com/recaptcha/api/siteverify',
            params={'secret': mock.ANY,
                    'response': mock.ANY,
                    'remoteip': mock.ANY})

        assert (response.status_code ==
                http.HTTPStatus.INTERNAL_SERVER_ERROR)
        assert response.content_type == 'application/json'
        assert json.loads(response.data) == {
            'code': http.HTTPStatus.INTERNAL_SERVER_ERROR,
            'name': 'Internal Server Error',
            'description': 'Error in communicating with reCAPTCHA server.',
        }


def test_send_message_recaptcha_request_failure_logged(client, caplog):
    """Tests that the HTTPRequestError is logged on reCAPTCHA HTTP failure."""
    mock_recaptcha_response = mock.create_autospec(requests.Response,
                                                   instance=True)
    mock_recaptcha_response.raise_for_status.side_effect = requests.HTTPError(
        'Bad request.')

    with mock.patch('requests.post', autospec=True) as mock_post:
        mock_raise_for_status = mock_post.return_value.raise_for_status
        mock_raise_for_status.side_effect = requests.HTTPError(
            'Bad request.')
        client.post('/messages',
                    data=_a_message_form())

    error_logs = [record for record in caplog.records
                  if record.levelname == 'ERROR']
    assert len(error_logs) == 1
    record = error_logs[0]
    assert record.getMessage() == (
        'Error in communicating with reCAPTCHA server: Bad request.')


def test_send_message_env_variable_recaptcha_secret(subtests):
    """Test reCAPTCHA secret configured via environment variable."""
    for recaptcha_secret in ['secret_from_env', 'another_secret_from_env']:
        with subtests.test(recaptcha_secret=recaptcha_secret):
            client = _a_test_client_with(
                environment=_an_environment_with(
                    recaptcha_secret=recaptcha_secret))
            with mock.patch('requests.post', autospec=True) as mock_post:
                client.post('/messages', data=_a_message_form())

            mock_post.assert_called_once_with(
                'https://www.google.com/recaptcha/api/siteverify',
                params={'secret': recaptcha_secret,
                        'response': mock.ANY,
                        'remoteip': mock.ANY})


def test_send_message_with_unexpected_action_returns_400_error(client,
                                                               subtests):
    """Test 400 error returned when reCAPTCHA action is not 'submit'."""
    for action in ['bad_action', 'unexpected_action']:
        with subtests.test(action=action):
            with mock.patch('requests.post', autospec=True) as mock_post:
                mock_json = mock_post.return_value.json
                mock_json.return_value = _a_site_verify_response_with(
                    success=True, action=action)

                response = client.post('/messages',
                                       data=_a_message_form())

            assert response.status_code == http.HTTPStatus.BAD_REQUEST
            assert response.content_type == 'application/json'
            assert json.loads(response.data) == {
                'code': http.HTTPStatus.BAD_REQUEST,
                'name': 'Bad Request',
                'description': f'The received reCAPTCHA action "{action}" '
                               'is not expected on this server.'
            }


def test_send_message_with_recaptcha_score_below_threshold_400_error(client,
                                                                     subtests):
    """Test 400 error returned when reCAPTCHA score is below threshold."""
    for score in [main.RECAPTCHA_DEFAULT_SCORE_THRESHOLD - 0.1,
                  main.RECAPTCHA_DEFAULT_SCORE_THRESHOLD - 0.2]:
        with subtests.test(score=score):
            with mock.patch('requests.post', autospec=True) as mock_post:
                mock_json = mock_post.return_value.json
                mock_json.return_value = _a_site_verify_response_with(
                    success=True, score=score)
                response = client.post('/messages',
                                       data=_a_message_form())

            assert response.status_code == http.HTTPStatus.BAD_REQUEST
            assert response.content_type == 'application/json'
            assert json.loads(response.data) == {
                'code': http.HTTPStatus.BAD_REQUEST,
                'name': 'Bad Request',
                'description': f'The received reCAPTCHA score {score} was too '
                               'low to send a message.',
            }


def test_send_message_with_an_invalid_recaptcha_response_400_error(client,
                                                                   subtests):
    """Test 400 error returned when reCAPTCHA response is invalid."""
    for recaptcha_response in ['some_invalid_token', 'another_invalid_token']:
        with subtests.test(recaptcha_response=recaptcha_response):
            with mock.patch('requests.post', autospec=True) as mock_post:
                mock_json = mock_post.return_value.json
                mock_json.return_value = _a_site_verify_response_with(
                    success=False, error_codes=['invalid-input-response'])

                response = client.post(
                    '/messages',
                    data=_a_message_form_with(
                        g_recaptcha_response=recaptcha_response))

            assert response.status_code == http.HTTPStatus.BAD_REQUEST
            assert response.content_type == 'application/json'
            assert json.loads(response.data) == {
                'code': http.HTTPStatus.BAD_REQUEST,
                'name': 'Bad Request',
                'description': 'The recaptcha_response parameter value '
                               f'"{recaptcha_response}" was not valid.',
            }


def test_send_message_with_stale_or_duplicate_recaptcha_response_400_error(
        client, subtests):
    """Test 400 error returned when reCAPTCHA response is stale or duped."""
    for recaptcha_response in ['some_stale_secrete', 'an already_used_secret']:
        with subtests.test(recaptcha_response=recaptcha_response):
            with mock.patch('requests.post', autospec=True) as mock_post:
                mock_json = mock_post.return_value.json
                mock_json.return_value = _a_site_verify_response_with(
                    success=False, error_codes=['timeout-or-duplicate'])

                response = client.post(
                    '/messages',
                    data=_a_message_form_with(
                        g_recaptcha_response=recaptcha_response))

            assert response.status_code == http.HTTPStatus.BAD_REQUEST
            assert response.content_type == 'application/json'
            assert json.loads(response.data) == {
                'code': http.HTTPStatus.BAD_REQUEST,
                'name': 'Bad Request',
                'description': 'The recaptcha_response parameter value '
                               f'"{recaptcha_response}" was too old or '
                               'previously used.'
            }


def test_send_message_site_verify_non_client_errors_returns_500_error(client):
    """Test 500 error returned when site verify has non-client errors."""
    with mock.patch('requests.post', autospec=True) as mock_post:
        mock_json = mock_post.return_value.json
        mock_json.return_value = _a_site_verify_response_with(
            success=False, error_codes=['some-other-error', 'another-error'])

        response = client.post('/messages',
                               data=_a_message_form())

    assert response.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR
    assert response.content_type == 'application/json'
    assert json.loads(response.data) == {
        'code': http.HTTPStatus.INTERNAL_SERVER_ERROR,
        'name': 'Internal Server Error',
        'description': 'An error was encountered when validating the '
                       'reCAPTCHA response token. Please try again later.',
    }


def test_send_message_site_verify_non_client_errors_logged_error(subtests,
                                                                 caplog):
    """Test useful data logged when site verify has non-client errors."""
    TestInput = collections.namedtuple(
        'TestInput',
        'recaptcha_secret recaptcha_response remote_addr error_codes')
    for test_input in [
        TestInput('some_recaptcha_secret', 'some_response_token',
                  '123.45.67.89', ['some-other-error', 'another-error']),
        TestInput('another_recaptcha_secret', 'another_response_token',
                  '98.76.54.32', ['invalid-input-secret',
                                  'invalid-input-response']),
    ]:
        with subtests.test(**test_input._asdict()):
            (recaptcha_secret, recaptcha_response, remote_addr,
             error_codes) = test_input
            caplog.clear()
            with mock.patch('requests.post', autospec=True) as mock_post:
                mock_json = mock_post.return_value.json
                mock_json.return_value = _a_site_verify_response_with(
                    success=False, error_codes=error_codes)

                client = _a_test_client_with(
                    environment=_an_environment_with(
                        recaptcha_secret=recaptcha_secret))
                client.post('/messages',
                            data=_a_message_form_with(
                                g_recaptcha_response=recaptcha_response),
                            environ_base={'REMOTE_ADDR': remote_addr})

        error_logs = [record for record in caplog.records
                      if record.levelname == 'ERROR']
        assert len(error_logs) == 1
        record = error_logs[0]
        assert record.getMessage() == (
            'Non-client errors detected in with reCAPTCHA siteverify API.\n'
            'request parameters: {'
            f"'secret': '{recaptcha_secret}', "
            f"'response': '{recaptcha_response}', "
            f"'remoteip': '{remote_addr}'}}\n"
            "siteverify response data: {'success': False, "
            f"'error-codes': {error_codes}}}")


def test_mailgun_message_send_http_error_returns_500_error(client):
    """Tests messages successfully sent."""
    with mock.patch('requests.post', autospec=True) as mock_post:
        mock_json = mock_post.return_value.json
        mock_json.return_value = _a_site_verify_response_with(success=True)
        mock_post.return_value.raise_for_status.side_effect = [
            None, requests.HTTPError('Bad request.')]

        response = client.post('/messages', data=_a_message_form())

    assert response.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR
    assert response.content_type == 'application/json'
    assert json.loads(response.data) == {
        'code': http.HTTPStatus.INTERNAL_SERVER_ERROR,
        'name': 'Internal Server Error',
        'description': 'An error was encountered when sending the '
                       'message. Please try again later.',
    }


def test_mailgun_message_send_http_error_logs_error(caplog):
    """Tests messages successfully sent."""
    with mock.patch('requests.post', autospec=True) as mock_post:
        mock_json = mock_post.return_value.json
        mock_json.return_value = _a_site_verify_response_with(success=True)
        mock_post.return_value.raise_for_status.side_effect = [
            None, requests.HTTPError('Bad request.')]
        client = _a_test_client_with(environment=_an_environment_with(
            mailgun_domain='my_mailgun_domain',
            mailgun_api_key='my_mailgun_api_key',
            message_to='a@b.c'
        ))
        message_form = _a_message_form_with(
            name='Mr. X',
            email='mr.x@somedomain.com',
            message="Hey, what's up?")

        client.post('/messages', data=message_form)

    error_logs = [record for record in caplog.records
                  if record.levelname == 'ERROR']
    assert len(error_logs) == 1
    record = error_logs[0]
    message = record.getMessage()
    assert message.startswith(
        "Mailgun send message request encountered error: "
        "HTTPError('Bad request.')")
    assert 'https://api.mailgun.net/v3/my_mailgun_domain/messages' in message
    assert 'my_mailgun_api_key' in message
    assert 'a@b.c' in message
    assert '"Mr. X" <mr.x@somedomain.com>' in message
    assert "Hey, what's up?" in message


def test_app_creation_failed_no_recaptcha_secret(subtests):
    """Test exception raised when reCAPTCHA secret is undefined."""
    for subcase, environ in [
        ('unset', _an_environment_without('RECAPTCHA_SECRET')),
        ('empty', _an_environment_with(recaptcha_secret=''))
    ]:
        with subtests.test(subcase=subcase):
            with mock.patch.dict('os.environ', environ, clear=True):
                with pytest.raises(
                        main.MissingRequiredConfigValueError,
                        match=(
                        'Cannot create web application without '
                        'RECAPTCHA_SECRET configuration value.')):
                    main.create_app()


def test_app_creation_failed_no_mailgun_api_key(subtests):
    """Test exception raised when Mailgun API Key is undefined."""
    for subcase, environ in [
        ('unset', _an_environment_without('MAILGUN_API_KEY')),
        ('empty', _an_environment_with(mailgun_api_key=''))
    ]:
        with subtests.test(subcase=subcase):
            with mock.patch.dict('os.environ', environ, clear=True):
                with pytest.raises(
                        main.MissingRequiredConfigValueError,
                        match=('Cannot create web application without '
                               'MAILGUN_API_KEY configuration value.')):
                    main.create_app()


def test_app_creation_failed_no_mailgun_domain(subtests):
    """Test exception raised when Mailgun Domain is undefined."""
    for subcase, environ in [
        ('unset', _an_environment_without('MAILGUN_DOMAIN')),
        ('empty', _an_environment_with(mailgun_domain='')),
    ]:
        with subtests.test(subcase=subcase):
            with mock.patch.dict('os.environ', environ, clear=True):
                with pytest.raises(
                        main.MissingRequiredConfigValueError,
                        match=('Cannot create web application without '
                               'MAILGUN_DOMAIN configuration value.')):
                    main.create_app()


def test_app_creation_failed_no_message_to(subtests):
    """Test exception raised when config val MESSAGE_TO is undefined."""
    for subcase, environ in [
        ('unset', _an_environment_without('MESSAGE_TO')),
        ('empty', _an_environment_with(message_to='')),
    ]:
        with subtests.test(subcase=subcase):
            with mock.patch.dict('os.environ', environ, clear=True):
                with pytest.raises(
                        main.MissingRequiredConfigValueError,
                        match=('Cannot create web application without '
                               'MESSAGE_TO configuration value.')):
                    main.create_app()


def test_app_creation_failed_message_to_parse_failure(subtests):
    """Test exception raised when MESSAGE_TO is unparsable."""
    to_headers = ['a@', 'foo@']
    for to_header in to_headers:
        with subtests.test(to_header=to_header):
            with mock.patch.dict('os.environ',
                                 _an_environment_with(
                                     message_to=to_header),
                                 clear=True):
                with pytest.raises(
                        main.InvalidMessageToHeader,
                        match="Could not parse MESSAGE_TO config value "
                              f"'{to_header}'."):
                    main.create_app()


def test_app_creation_failed_no_message_to_has_defects(subtests):
    """Test exception raised when Mailgun Domain is undefined."""
    for to_header, defects_listing in [
        ('a', '- addr-spec local part with no domain'),
        ('a, <b@c', ('- addr-spec local part with no domain\n'
                     "- missing trailing '>' on angle-addr"))
    ]:
        with subtests.test(to_header=to_header,
                           defects_listing=defects_listing):
            with mock.patch.dict('os.environ',
                                 _an_environment_with(
                                     message_to=to_header),
                                 clear=True):
                with pytest.raises(
                        main.InvalidMessageToHeader,
                        match=f"MESSAGE_TO config value '{to_header}' "
                              'has the following defects:\n'
                              f'{defects_listing}'):
                    main.create_app()


def test_create_app_or_die_graceful_death_on_creation_failure():
    """Test that a SystemExit is raised on failure create to main app."""
    with mock.patch.dict('os.environ',
                         _an_environment_without('RECAPTCHA_SECRET'),
                         clear=True):
        with pytest.raises(
                SystemExit,
                match=(
                'Cannot create web application without RECAPTCHA_SECRET '
                'configuration value.')):
            main.create_app_or_die()


def _a_site_verify_response_with(
        *,
        success=True,
        score=None,
        action=None,
        challenge_ts=None,
        hostname=None,
        error_codes=None):
    response = {'success': success}

    for var, attribute, present_on_success, default in [
        (score, 'score', True, 0.9),
        (action, 'action', True, main.RECAPTCHA_DEFAULT_EXPECTED_ACTION),
        (challenge_ts, 'challenge_ts', True, '2020-10-01T03:17:06Z'),
        (hostname, 'hostname', True, 'some_verify_host'),
        (error_codes, 'error-codes', False, ['invalid-input-secret']),
    ]:
        if var is None:
            if success == present_on_success:
                response[attribute] = default
        else:
            response[attribute] = var

    return response


def _a_message_form_without(*excluded_fields):
    return {field: value for field, value in _a_message_form().items()
            if field not in excluded_fields}


def _a_message_form():
    return _a_message_form_with()


def _a_message_form_with(
        *,
        g_recaptcha_response='some_response_token',
        name='Foo McBar',
        email='foo.mcbar@baz.qux',
        message='Hey there, I think we should talk.\nAre you aware of the '
                'many uses essential oils can bring to your everyday'
                'well-being? Well, let me tell you...'):
    return {
        'g-recaptcha-response': g_recaptcha_response,
        'name': name,
        'email': email,
        'message': message,
    }


def _an_environment_without(*excluded_variables):
    excluded_variables = set(var.upper() for var in excluded_variables)
    return {variable: value for variable, value in _an_environment().items()
            if variable not in excluded_variables}


def _an_environment():
    return _an_environment_with()


def _an_environment_with(*,
                         recaptcha_secret='some_secret',
                         mailgun_api_key='some_mailgun_api_key',
                         mailgun_domain='some_mailgun_domain',
                         message_to='someone@somewhere',
                         message_subject=None):
    env = [
        ('RECAPTCHA_SECRET', recaptcha_secret),
        ('MAILGUN_API_KEY', mailgun_api_key),
        ('MAILGUN_DOMAIN', mailgun_domain),
        ('MESSAGE_TO', message_to),
        ('MESSAGE_SUBJECT', message_subject),
    ]
    return {var: val for var, val in env if val is not None}


if __name__ == '__main__':
    pytest.main()
