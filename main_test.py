import pytest

import main


def test_index():
    main.app.testing = True
    client = main.app.test_client()

    r = client.get('/')

    assert r.status_code == 200
    assert r.data == b'Hello from misakoba-mail'


if __name__ == '__main__':
    pytest.main()
