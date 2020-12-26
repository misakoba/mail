"""The main module, which runs a debug test server."""

import misakoba_mail.app

app = misakoba_mail.app.create_app_or_die()
app.run(host='127.0.0.1', port=8080, debug=True)
