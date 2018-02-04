from flask import Flask, render_template
from core.data import *
app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def results():
    data = Data()
    if request.method == 'POST':
        data.get_testers()
        data.get_addressess()
        data.init_status()
        data.run()
        return render_template("result.html", database=data.show_data(), name=" - Result")
    return render_template("index.html", data=data)


if __name__ == '__main__':
    app.run(debug=False,
            threaded=True,
            port=80
            )
