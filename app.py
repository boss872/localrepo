from flask import Flask, render_template, request
from analyzer import analyze_url

app = Flask(__name__, template_folder='.')


@app.route("/", methods=["GET", "POST"])
def index():
    report = None

    if request.method == "POST":
        target = request.form.get("url")
        report = analyze_url(target)

    return render_template("index.html", report=report)

if __name__ == "__main__":
    app.run(debug=True)
