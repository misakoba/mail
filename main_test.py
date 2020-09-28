"""Unit tests for misakoba-mail's main module."""

import http
from unittest import mock

import pytest
import pytest_subtests  # pylint: disable=unused-import # noqa: F401

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


if __name__ == '__main__':
    pytest.main()
