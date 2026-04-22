from flask import Flask, render_template, jsonify
from packet_engine import analyze_pcap

app = Flask(__name__)

stats, packets = analyze_pcap("test_safe.pcap")

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/api/data")
def data():
    return jsonify({
        "stats": stats,
        "packets": packets[:100]
    })

if __name__ == "__main__":
    app.run(debug=True)