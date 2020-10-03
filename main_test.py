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


def _a_test_client_with(*, recaptcha_secret='some_secret'):
    """Creates and returns the default Flask test client fixture."""
    with mock.patch.dict('os.environ',
                         {'RECAPTCHA_SECRET': recaptcha_secret}):
        app = main.create_app()
    app.testing = True
    return app.test_client()


def test_successful_send(client, subtests):
    """Tests messages successfully sent."""
    recaptcha_responses = [
        'my_request_token',
        'another_request_token',
    ]
    for recaptcha_response in recaptcha_responses:
        with subtests.test(recaptcha_response=recaptcha_response):
            with mock.patch('requests.post', autospec=True) as mock_post:
                mock_json = mock_post.return_value.json
                mock_json.return_value = _a_site_verify_response_with(
                    success=True)

                response = client.post(
                    f'/send?recaptcha_response={recaptcha_response}')

            mock_post.assert_called_once_with(
                'https://www.google.com/recaptcha/api/siteverify',
                params={'secret': mock.ANY,
                        'response': recaptcha_response,
                        'remoteip': mock.ANY
                        })
            assert response.status_code == http.HTTPStatus.OK
            assert response.data == b'Successfully validated message request.'


def test_send_propagates_remote_ip(client, subtests):
    """Tests remote IP address sent to reCAPTCHA server."""
    for remote_addr in ['123.45.67.89', '98.76.54.123']:
        with subtests.test(remote_addr=remote_addr):
            with mock.patch('requests.post', autospec=True) as mock_post:
                client.post(
                    '/send?recaptcha_response=some_token',
                    environ_base={'REMOTE_ADDR': remote_addr}
                )

            mock_post.assert_called_once_with(
                'https://www.google.com/recaptcha/api/siteverify',
                params={'secret': mock.ANY,
                        'response': 'some_token',
                        'remoteip': remote_addr,
                        })


def test_send_wrong_method(client):
    """Tests a 405 error returned when accessing send with a bad method."""
    response = client.get('/send')

    assert response.status_code == http.HTTPStatus.METHOD_NOT_ALLOWED
    assert response.content_type == 'application/json'


def test_send_recaptcha_request_failed(client):
    """Tests a 500 error returned when accessing send with a bad method."""
    mock_recaptcha_response = mock.create_autospec(requests.Response,
                                                   instance=True)
    mock_recaptcha_response.raise_for_status.side_effect = requests.HTTPError(
        'Bad request.')

    with mock.patch('requests.post', autospec=True) as mock_post:
        mock_raise_for_status = mock_post.return_value.raise_for_status
        mock_raise_for_status.side_effect = requests.HTTPError(
            'Bad request.')
        response = client.post('/send?recaptcha_response=my_token')
        mock_post.assert_called_once_with(
            'https://www.google.com/recaptcha/api/siteverify',
            params={'secret': mock.ANY,
                    'response': 'my_token',
                    'remoteip': mock.ANY})

        assert (response.status_code ==
                http.HTTPStatus.INTERNAL_SERVER_ERROR)
        assert response.content_type == 'application/json'
        assert json.loads(response.data) == {
            'code': http.HTTPStatus.INTERNAL_SERVER_ERROR,
            'name': 'Internal Server Error',
            'description': 'Error in communicating with reCAPTCHA server.',
        }


def test_send_recaptcha_request_failure_logged(client, caplog):
    """Tests that the HTTPRequestError is logged on reCAPTCHA HTTP failure."""
    mock_recaptcha_response = mock.create_autospec(requests.Response,
                                                   instance=True)
    mock_recaptcha_response.raise_for_status.side_effect = requests.HTTPError(
        'Bad request.')

    with mock.patch('requests.post', autospec=True) as mock_post:
        mock_raise_for_status = mock_post.return_value.raise_for_status
        mock_raise_for_status.side_effect = requests.HTTPError(
            'Bad request.')
        client.post('/send?recaptcha_response=my_token')

    error_logs = [record for record in caplog.records
                  if record.levelname == 'ERROR']
    assert len(error_logs) == 1
    record = error_logs[0]
    assert record.getMessage() == (
        'Error in communicating with reCAPTCHA server: Bad request.')
    assert record.exc_info


def test_send_env_variable_recaptcha_secret(subtests):
    """Test recaptcha secret configured via environment variable."""
    for recaptcha_secret in ['secret_from_env', 'another_secret_from_env']:
        with subtests.test(recaptcha_secret=recaptcha_secret):
            with mock.patch('requests.post', autospec=True) as mock_post:
                client = _a_test_client_with(
                    recaptcha_secret=recaptcha_secret)
                client.post('/send?recaptcha_response=some_token')

            mock_post.assert_called_once_with(
                'https://www.google.com/recaptcha/api/siteverify',
                params={'secret': recaptcha_secret,
                        'response': 'some_token',
                        'remoteip': mock.ANY})


def test_send_without_recaptcha_response_returns_400_error(client):
    """Test 400 error returned when reCAPTCHA token is missing."""
    with mock.patch('requests.post', autospec=True) as mock_post:
        response = client.post('/send')

    mock_post.assert_not_called()
    assert response.status_code == http.HTTPStatus.BAD_REQUEST
    assert response.content_type == 'application/json'
    assert json.loads(response.data) == {
        'code': http.HTTPStatus.BAD_REQUEST,
        'name': 'Bad Request',
        'description': 'Request sent without recaptcha_response parameter.'
    }


def test_send_with_unexpected_action_returns_400_error(client, subtests):
    """Test 400 error returned when reCAPTCHA action is not 'submit'."""
    for action in ['bad_action', 'unexpected_action']:
        with subtests.test(action=action):
            with mock.patch('requests.post', autospec=True) as mock_post:
                mock_json = mock_post.return_value.json
                mock_json.return_value = _a_site_verify_response_with(
                    success=True, action=action)

                response = client.post('/send?recaptcha_response=some_token')

            assert response.status_code == http.HTTPStatus.BAD_REQUEST
            assert response.content_type == 'application/json'
            assert json.loads(response.data) == {
                'code': http.HTTPStatus.BAD_REQUEST,
                'name': 'Bad Request',
                'description': f'The received reCAPTCHA action "{action}" '
                               'is not expected on this server.'
            }


def test_send_with_recaptcha_score_below_threshold_400_error(client, subtests):
    """Test 400 error returned when reCAPTCHA score is below threshold."""
    for score in [main.RECAPTCHA_DEFAULT_SCORE_THRESHOLD - 0.1,
                  main.RECAPTCHA_DEFAULT_SCORE_THRESHOLD - 0.2]:
        with subtests.test(score=score):
            with mock.patch('requests.post', autospec=True) as mock_post:
                mock_json = mock_post.return_value.json
                mock_json.return_value = _a_site_verify_response_with(
                    success=True, score=score)
                response = client.post('/send?recaptcha_response=some_token')

            assert response.status_code == http.HTTPStatus.BAD_REQUEST
            assert response.content_type == 'application/json'
            assert json.loads(response.data) == {
                'code': http.HTTPStatus.BAD_REQUEST,
                'name': 'Bad Request',
                'description': f'The received reCAPTCHA score {score} was too '
                               'low to send a message.',
            }


def test_send_with_an_invalid_recaptcha_response_400_error(client, subtests):
    """Test 400 error returned when reCAPTCHA response is invalid."""
    for recaptcha_response in ['some_invalid_token', 'another_invalid_token']:
        with subtests.test(recaptcha_response=recaptcha_response):
            with mock.patch('requests.post', autospec=True) as mock_post:
                mock_json = mock_post.return_value.json
                mock_json.return_value = _a_site_verify_response_with(
                    success=False, error_codes=['invalid-input-response'])

                response = client.post(
                    f'/send?recaptcha_response={recaptcha_response}')

            assert response.status_code == http.HTTPStatus.BAD_REQUEST
            assert response.content_type == 'application/json'
            assert json.loads(response.data) == {
                'code': http.HTTPStatus.BAD_REQUEST,
                'name': 'Bad Request',
                'description': 'The recaptcha_response parameter value '
                               f'"{recaptcha_response}" was not valid.',
            }


def test_send_with_stale_or_duplicate_recaptcha_response_400_error(
        client, subtests):
    """Test 400 error returned when reCAPTCHA response is stale or duped."""
    for recaptcha_response in ['some_stale_secrete', 'an already_used_secret']:
        with subtests.test(recaptcha_response=recaptcha_response):
            with mock.patch('requests.post', autospec=True) as mock_post:
                mock_json = mock_post.return_value.json
                mock_json.return_value = _a_site_verify_response_with(
                    success=False, error_codes=['timeout-or-duplicate'])

                response = client.post(
                    f'/send?recaptcha_response={recaptcha_response}')

            assert response.status_code == http.HTTPStatus.BAD_REQUEST
            assert response.content_type == 'application/json'
            assert json.loads(response.data) == {
                'code': http.HTTPStatus.BAD_REQUEST,
                'name': 'Bad Request',
                'description': 'The recaptcha_response parameter value '
                               f'"{recaptcha_response}" was too old or '
                               'previously used.'
            }


def test_send_site_verify_non_client_errors_returns_500_error(client):
    """Test 500 error returned when site verify has non-client errors."""
    with mock.patch('requests.post', autospec=True) as mock_post:
        mock_json = mock_post.return_value.json
        mock_json.return_value = _a_site_verify_response_with(
            success=False, error_codes=['some-other-error', 'another-error'])

        response = client.post('/send?recaptcha_response=some_response_token')

    assert response.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR
    assert response.content_type == 'application/json'
    assert json.loads(response.data) == {
        'code': http.HTTPStatus.INTERNAL_SERVER_ERROR,
        'name': 'Internal Server Error',
        'description': 'An error was encountered when validating the '
                       'reCAPTCHA response token. Please try again later.',
    }


def test_send_site_verify_non_client_errors_logged_error(subtests, caplog):
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

                client = _a_test_client_with(recaptcha_secret=recaptcha_secret)
                client.post(f'/send?recaptcha_response={recaptcha_response}',
                            environ_base={'REMOTE_ADDR': remote_addr})

        error_logs = [record for record in caplog.records
                      if record.levelname == 'ERROR']
        assert len(error_logs) == 1
        record = error_logs[0]
        assert record.getMessage() == (
                        'Non-client errors detected in with reCAPTCHA '
                        'siteverify API.\n'
                        'request parameters: {'
                        f"'secret': '{recaptcha_secret}', "
                        f"'response': '{recaptcha_response}', "
                        f"'remoteip': '{remote_addr}'}}\n"
                        "siteverify response data: {'success': False, "
                        "'error-codes': "
                        f'{error_codes}}}')


def test_app_creation_failed_no_recaptcha_secret():
    """Test exception raised when reCAPTCHA secret is undefined."""
    with mock.patch.dict('os.environ', clear=True):
        with pytest.raises(
                main.UndefinedReCAPTCHASecretError,
                match=(
                'Cannot create web application without RECAPTCHA_SECRET '
                'configuration value.')):
            main.create_app()


def test_create_app_or_die_graceful_death_on_creation_failure():
    """Test that a SystemExit is raised on failure create to main app."""
    with mock.patch.dict('os.environ', clear=True):
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


if __name__ == '__main__':
    pytest.main()
