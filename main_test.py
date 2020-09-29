"""Unit tests for misakoba-mail's main module."""

import http
from unittest import mock

import pytest
# pylint: disable=unused-import
import pytest_subtests  # type: ignore # noqa: F401
# pylint: enable=unused-import
import requests

import main


@pytest.fixture(name='client')
def test_client():
    """Creates and returns the default Flask test client fixture."""
    with mock.patch.dict('os.environ',
                         {'RECAPTCHA_SECRET': 'some_secret'}):
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
                response = client.post(
                    f'/send?recaptcha_response={recaptcha_response}')

            mock_post.assert_called_once_with(
                'https://www.google.com/recaptcha/api/siteverify',
                params={'secret': mock.ANY,
                        'response': recaptcha_response})
            assert response.status_code == http.HTTPStatus.OK
            assert response.data == b'Successfully validated message request.'


def test_send_wrong_method(client):
    """Tests a 403 error returned when accessing send with a bad method."""
    assert (client.get('/send').status_code ==
            http.HTTPStatus.METHOD_NOT_ALLOWED)


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
                    'response': 'my_token'})
        assert (response.status_code ==
                http.HTTPStatus.INTERNAL_SERVER_ERROR)
        assert (b'Error in communicating with reCAPTCHA server.' in
                response.data)


def test_send_env_variable_recaptcha_secret(subtests):
    """Test recaptcha secret configured via environment variable."""
    for recaptcha_secret in ['secret_from_env', 'another_secret_from_env']:
        with subtests.test(recaptcha_secret=recaptcha_secret):
            with mock.patch.dict('os.environ',
                                 {'RECAPTCHA_SECRET': recaptcha_secret}):
                app = main.create_app()
            app.testing = True
            client = app.test_client()

            with mock.patch('requests.post', autospec=True) as mock_post:
                response = client.post(
                    '/send?recaptcha_response=some_token')

            mock_post.assert_called_once_with(
                'https://www.google.com/recaptcha/api/siteverify',
                params={'secret': recaptcha_secret,
                        'response': 'some_token'})
            assert response.status_code == http.HTTPStatus.OK
            assert response.data == b'Successfully validated message request.'


def test_send_without_recaptcha_response_returns_403_error(client):
    """Test 403 error when recaptcha ticket is missing."""
    with mock.patch('requests.post', autospec=True) as mock_post:
        response = client.post('/send')

    mock_post.assert_not_called()
    assert response.status_code == http.HTTPStatus.FORBIDDEN
    assert (b'Request sent without recaptcha_response parameter.' in
            response.data)


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


if __name__ == '__main__':
    pytest.main()
