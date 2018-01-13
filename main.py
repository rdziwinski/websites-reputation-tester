from flask import Flask, render_template
from multiprocessing.dummy import Pool as ThreadPool
from core.data import *
from core.tester import *
app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def results():
    if request.method == 'POST':
        data = Data()
        data.run()
        print(data.show_data())
        database = data.show_data()
        return render_template("result.html", database=database)
    return render_template("index.html")


if __name__ == '__main__':
    app.run(debug=True,
            threaded=True,
            port=80
            )
