# requirements_to_freeze
This directory defines the direct dependencies of the app. It is used to define
the corresponding `requirements*.txt` files at the root directory with the
 `pip freeze` command.
 
## Refreeze recipe

Create a fresh venv, install the requirements to freeze, then freeze them at the
project root.

```
# From project root, create and activate the venv
$ python3 -m venv venv
$ source venv/bin/activate

# Refreeze the product dependencies
$ pip install -r requirements_to_freeze/requirements.txt 
$ pip freeze > requirements.txt

# Refreeze the test dependencies, added to the product dependencies
$ pip install -r requirements_to_freeze/requirements-test.txt 
$ pip freeze > requirements-test.txt
```