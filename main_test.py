"""Unit tests for misakoba-mail's main module."""

import http
from unittest import mock

import pytest
# pylint: disable=unused-import
import pytest_subtests  # type: ignore # noqa: F401
# pylint: enable=unused-import
import requests

import main


@pytest.fixture
def client():
    """Creates and returns the default Flask test client fixture."""
    main.app.testing = True
    return main.app.test_client()


def test_successful_send(client,  # pylint: disable=redefined-outer-name
                         subtests):
    """Tests messages successfully sent."""
    subtest_inputs = [
        ('my_recaptcha_secret', 'my_request_token'),
        ('another_recaptcha_secret', 'another_request_token'),
    ]
    for recaptcha_secret, recaptcha_response in subtest_inputs:
        with subtests.test(recacptca_secret=recaptcha_secret,
                           recaptcha_response=recaptcha_response):
            with mock.patch.dict('os.environ',
                                 {'RECAPTCHA_SECRET': recaptcha_secret}):
                with mock.patch('requests.post', autospec=True) as mock_post:
                    response = client.post(
                        f'/send?recaptcha_response={recaptcha_response}')

            mock_post.assert_called_once_with(
                'https://www.google.com/recaptcha/api/siteverify',
                params={'secret': recaptcha_secret,
                        'response': recaptcha_response})
            assert response.status_code == http.HTTPStatus.OK
            assert response.data == b'Successfully validated message request.'


def test_send_wrong_method(client):  # pylint: disable=redefined-outer-name
    """Tests a 403 error returned when accessing send with a bad method."""
    assert (client.get('/send').status_code ==
            http.HTTPStatus.METHOD_NOT_ALLOWED)


def test_send_recaptcha_request_failed(
        client):  # pylint: disable=redefined-outer-name
    """Tests a 500 error returned when accessing send with a bad method."""
    mock_recaptcha_response = mock.create_autospec(requests.Response,
                                                   instance=True)
    mock_recaptcha_response.raise_for_status.side_effect = requests.HTTPError(
        'Bad request.')

    with mock.patch.dict('os.environ',
                         {'RECAPTCHA_SECRET': 'my_secret'}):
        with mock.patch('requests.post', autospec=True) as mock_post:
            mock_raise_for_status = mock_post.return_value.raise_for_status
            mock_raise_for_status.side_effect = requests.HTTPError(
                'Bad request.')
            response = client.post('/send?recaptcha_response=my_token')
            mock_post.assert_called_once_with(
                'https://www.google.com/recaptcha/api/siteverify',
                params={'secret': 'my_secret',
                        'response': 'my_token'})
            assert (response.status_code ==
                    http.HTTPStatus.INTERNAL_SERVER_ERROR)
            assert (b'Error in communicating with reCAPTCHA server.' in
                    response.data)

if __name__ == '__main__':
    pytest.main()
