from flask import Flask

# Initialize the Flask application
app = Flask(__name__)


# Route 1: Base/Root path
@app.route("/")
def home():
  return "Welcome! Try visiting /hello, /night, or /bye."


# Route 2: /hello
@app.route("/hello")
def say_hello():
  return "hello"


# Route 3: /night
@app.route("/night")
def say_night():
  return "good night"


# Route 4: /bye
@app.route("/bye")
def say_bye():
  return "bye"


# Start the local development server
if __name__ == "__main__":
  app.run(host="127.0.0.1", port=5000, debug=True)