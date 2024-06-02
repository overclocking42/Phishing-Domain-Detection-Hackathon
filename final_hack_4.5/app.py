from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import run  # Import the necessary functions from new.py
app = Flask(__name__)
CORS(app)  # Enable CORS to allow requests from the Chrome extension

@app.route("/")
def home():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/dev')
def dev():
    return render_template('dev.html')


@app.route('/check_phishing', methods=['POST'])
def check_phishing():
    domain = request.form.get('url', request.form.get('URL', ''))  # Get the input URL from the form or AJAX request
    if not domain:
        return jsonify({"result": "invalid"}), 400

    result = run.process_url_input(domain)  # Call the function from new.py directly
    
    # Check if the request is from the website or the extension
    if 'url' in request.form:
        return render_template('result.html', result=result['result_text'], additional_info=result['additional_info'])
    else:
        return jsonify(result)


if __name__ == '__main__':
    app.run(debug=True, port=2002)
