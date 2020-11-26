import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    row = db.execute("SELECT * FROM users WHERE id=:id", id=session["user_id"])
    total = float(row[0]["cash"])
    tabs = db.execute("SELECT * FROM combo WHERE id=:id", id=session["user_id"])
    for tab in tabs:
        if tab["Symbol"] is not None:
            quoted = lookup(tab["Symbol"])
            tab["Price"] = usd(quoted["price"])
            tab["TOTAL"] = quoted["price"] * tab["Shares"]
            total += tab["TOTAL"]
            tab["TOTAL"] = usd(tab["TOTAL"])
    return render_template("index.html", tabs=tabs, cash=usd(row[0]["cash"]), total=usd(total))

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        Symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        if not shares:
            return apology("Please enter number of Shares!")
        shares=int(shares)
        row = db.execute("SELECT * FROM users WHERE id=:id", id=session["user_id"])
        quoted = lookup(Symbol)
        if not quoted:
            return apology("Please enter a valid symbol")
        if shares is None or shares <= 0:
            return apology("Please enter a positive number")
        cost = quoted["price"] * shares
        if cost > row[0]["cash"]:
            return apology("Not enough balance!")
        else:
            oldcash = row[0]["cash"]
            left = oldcash - cost
            db.execute("INSERT INTO data (Symbol, Name, Shares, Price, TOTAL, id, Transacted) VALUES (:Symbol, :Name, :Shares, :Price, :TOTAL, :id, datetime('now'))",##### RARE FUNCTION TO GET TIME
                           Symbol=Symbol, Name=quoted["name"], Shares=shares, Price=quoted["price"], TOTAL=quoted["price"] * shares, id=session["user_id"])
            db.execute("UPDATE users SET cash=:left WHERE id=:id", left=left, id=session["user_id"])
            s = db.execute("SELECT * FROM combo WHERE id=:id AND Symbol=:Sy", id=session["user_id"], Sy=Symbol)
            if not s:
                db.execute("INSERT INTO combo (id, Symbol, Name, Shares, Price) VALUES (:id, :Symbol, :Name, :Shares, :Price)",
                           id=session["user_id"], Symbol=Symbol, Name=quoted["name"], Shares=shares, Price=0)
            else:
                k = s[0]["Shares"]
                k += shares
                db.execute("UPDATE combo SET Shares=:k WHERE id=:id AND Symbol=:Sy", k=k, id=session["user_id"], Sy=Symbol)
        return redirect("/")
    else:
        return render_template("buy.html")

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    tabs=db.execute("SELECT * FROM data WHERE id=:id ORDER BY Transacted DESC", id=session["user_id"])
    for tab in tabs:
        if tab["Price"] is not None:
            tab["Price"]=usd(tab["Price"])
    return render_template("history.html", tabs=tabs)
    # return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    if request.method == "POST":
        Symbol = request.form.get("Symbol")
        quoted = lookup(Symbol)
        if not quoted:
            return apology("Please enter a valid symbol")
        else:
            return render_template("quoted.html", quoted=quoted, cost=usd(quoted["price"]))
    else:
        return render_template("quote.html")

    return apology("TODO")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not username:
            return apology("must provide username", 403)

        # Ensure username doesn't exist already
        elif db.execute("SELECT * FROM users WHERE username = :username", username=username):
            return apology("username already exists", 403)

        # Ensure password was submitted
        elif not password:
            return apology("must provide password", 403)

        # Ensure confirmation was submitted
        elif not confirmation:
            return apology("must provide confirmation", 403)

        elif confirmation != password:
            return apology("passwords do not match", 403)

        # insert
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)",
                   username=username, hash=generate_password_hash(password, method='pbkdf2:sha256', salt_length=8))

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        symbol=request.form.get("symbol")
        shares = request.form.get("shares")
        if not shares:
            return apology("Please enter number of shares!")
        shares = int(shares)
        quoted=lookup(symbol)
        if not quoted:
            return apology("You don't own these shares!")
        tabs=db.execute("SELECT * FROM combo WHERE id=:id AND symbol=:symbol",
                        id=session["user_id"], symbol=symbol)
        if shares > int(tabs[0]["Shares"]):
            return apology("You do not own that many shares of the stock!")
        else:
            db.execute("INSERT INTO data (Symbol, Name, Shares, Price, TOTAL, id, Transacted) VALUES (:Symbol, :Name, :Shares, :Price, :TOTAL, :id, datetime('now'))",##### RARE FUNCTION TO GET TIME
                           Symbol=symbol, Name=quoted["name"], Shares=-shares, Price=quoted["price"], TOTAL=-(quoted["price"] * shares), id=session["user_id"])
            row=db.execute("SELECT * FROM users WHERE id=:id", id=session["user_id"])
            db.execute("UPDATE users SET cash=:left WHERE id=:id", left=row[0]["cash"] + (quoted["price"] * shares), id=session["user_id"])
            s = db.execute("SELECT * FROM combo WHERE id=:id AND Symbol=:Sy", id=session["user_id"], Sy=symbol)
            k = s[0]["Shares"]
            k -= shares
            if k == 0:
                db.execute("DELETE FROM combo WHERE id=:id AND Symbol=:Sy", id=session["user_id"], Sy=symbol)
            else:
                db.execute("UPDATE combo SET Shares=:k WHERE id=:id AND Symbol=:Sy", k=k, id=session["user_id"], Sy=symbol)
        return redirect("/")
    else:
        tabs = db.execute("SELECT * FROM combo WHERE id=:id", id=session["user_id"])
        return render_template("sell.html", tabs=tabs)

@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    """Change Password"""

    if request.method == "POST":
        old = request.form.get("old")
        new = request.form.get("new")
        confirmation = request.form.get("confirmation")
        if not old:
            return apology("must provide old password", 403)

        rows = db.execute("SELECT * FROM users WHERE id = :id",
                          id=session["user_id"])
        # check if old pwd is correct
        if not check_password_hash(rows[0]["hash"], old):
            return apology("Old password didn't match!", 403)

        # Ensure password was submitted
        if not new:
            return apology("must provide New password", 403)

        # Ensure confirmation was submitted
        if not confirmation:
            return apology("must provide confirmation", 403)

        if confirmation != new:
            return apology("New password do not match Confirmation", 403)

        # UPDATE password
        db.execute("UPDATE users SET hash=:h WHERE id=:id",
                    h=generate_password_hash(new, method='pbkdf2:sha256', salt_length=8), id=session["user_id"])

        return redirect("/")
    else:
        return render_template("change.html")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
