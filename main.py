from flask import Flask

app = Flask(__name__)  # Default GAE Entry point


@app.route('/')
def hello():
    return 'Hello from misakoba-mail'


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
