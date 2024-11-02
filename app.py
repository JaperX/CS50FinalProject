from flask import Flask, render_template, request, redirect, session, g, url_for #g is like a global thats unique to each reqesut and resets and stuff
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from datetime import datetime, timedelta

from app_functions import get_db, query_db, get_exercise_data, start_date, login_required

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app) 

@app.route('/', methods=['POST', 'GET'])
@login_required
def index():
    if request.method == 'POST':
        selected_date = start_date(request.form.get('date'))
        if 'previous' in request.form:
            print('previous day')
            selected_date -= timedelta(days=1)
        elif 'next' in request.form:
            print('next day')
            selected_date += timedelta(days=1)
        return redirect(url_for('index', date=selected_date.strftime("%Y-%m-%d")))
   
    if request.method == 'GET':
        selected_date = start_date(request.args.get('date'))
        date_str = selected_date.strftime("%Y-%m-%d")

        if date_str == datetime.now().replace(hour=0, minute=0, second=0).strftime("%Y-%m-%d"):
            print("ITS TODAY")
        
        # Get all exercises with data for the selected date
        exercises_with_data = query_db("""
            SELECT exercises.name, user_exercises.set_number, user_exercises.weight, user_exercises.reps
            FROM user_exercises
            INNER JOIN exercises ON exercises.id = user_exercises.exercise_id
            WHERE user_exercises.user_id = ? AND DATE(user_exercises.date) = ?
        """, [session['user_id'], date_str])

        # Create a dictionary to store exercises and their data
        exercise_data = {}
        for exercise in exercises_with_data:
            exercise_name = exercise['name']
            if exercise_name not in exercise_data:
                exercise_data[exercise_name] = []  # Initialize list for sets

            
            linear_set_number = len(exercise_data[exercise_name]) + 1
            exercise_data[exercise_name].append({
                'set_number': linear_set_number, #create a linear amount for sets (if user deletes the sets arent updated so this is just a easy fix visually when displayed)
                'weight': exercise['weight'],
                'reps': exercise['reps']
            })

        print(exercise_data)


        # Get a list of all exercise names (for selection)
        selectable_exercises = [exercise['name'] for exercise in query_db("""
            SELECT name FROM exercises
        """)]
        
        last_added_exercise = session.pop('last_added_exercise', None)

        return render_template(
            'index.html',
            exercises=exercise_data,
            selected_date=date_str,
            selectable_exercises=selectable_exercises,
            last_added_exercise=last_added_exercise
        )
    
    
#to stop confusing post methods when adding exercise overlay inside index.html
@app.route('/remove_set', methods=['POST'])
@login_required
def remove_set():
    #get values for specific exercise button 
    exercise_name = request.form.get('exercise_name')
    exercise_id = query_db("SELECT id FROM exercises WHERE name = ?", [exercise_name], one=True)[0]
    set_number = request.form.get('set_number')
    weight = request.form.get('weight')
    reps = request.form.get('reps')
    selected_date = request.form.get('date')
    print(exercise_name, set_number, weight, reps, selected_date)
    
    #remove from database
    db = get_db()
    db.execute("""
        DELETE FROM user_exercises WHERE
        user_id = ? AND exercise_id = ? AND set_number = ? 
        AND weight = ? AND reps = ? AND date = ?
    """, [session['user_id'], exercise_id, set_number, weight, reps, selected_date])
    db.commit()
    
    return redirect(url_for('index'))


#to stop confusing post methods when adding exercise overlay inside index.html
@app.route('/add_set', methods=['POST'])
@login_required
def add_set():
    #get form data
    add_set_data = request.form
    print(add_set_data)
    exercise_name = add_set_data["exercise_name"]
    weight = add_set_data["weight"]
    reps = add_set_data["reps"]
    user_id = add_set_data["user_id"]
    date = add_set_data["date"]

    exercise_id = query_db("SELECT id FROM exercises WHERE name = ?", [exercise_name], one=True)[0]
    print(exercise_id)

    total_exercise_sets = query_db("SELECT set_number FROM user_exercises WHERE date = ? AND exercise_id = ? AND user_id = ?", [date, exercise_id, user_id])
    if total_exercise_sets:
        set_number = max(set[0] for set in total_exercise_sets) + 1
    else: 
        set_number = 1

    #add to database
    db = get_db()
    db.execute("INSERT INTO user_exercises (user_id, exercise_id, set_number, weight, reps, date) VALUES (?, ?, ?, ?, ?, ?)", 
    (user_id, exercise_id, set_number, weight, reps, date))
    db.commit()

    session['last_added_exercise'] = exercise_name
    
    return redirect(url_for('index'))


@app.route('/add_exercise', methods=['POST'])
@login_required
def add_exercise():
    exercise_name = request.form.get('exercise_name').title()
    #database logic here
    print("selected exercise name: " + exercise_name)
    existing_exercises = query_db("SELECT id FROM exercises WHERE name = ?", [exercise_name], one=True)

    if existing_exercises:
        print("exercise already exists")
        return redirect(url_for('index'))
    else:
        db = get_db()
        # Insert the exercise
        db.execute("INSERT INTO exercises (name) VALUES (?)", [exercise_name])
        # Get the id of the newly inserted exercise
        exercise_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        # Commit the transaction
        db.commit()
        print("added new exercsies to db")

    return redirect(url_for('index'))


@app.route('/chart', methods=['POST', 'GET'])
@login_required
def charts():
    if request.method == 'POST':
        from_month = request.form.get('from_month')
        to_month = request.form.get('to_month')
        year = request.form.get('year_date')

        #format date string
        if int(from_month) < 10:
            from_month = f"0{from_month}"
        if int(to_month) < 10:
            to_month = f"0{to_month}"
        from_date = f"{year}-{from_month}-01"
        to_date = f"{year}-{to_month}-28"
        print(f"selected dates: {from_date}, {to_date}")

        return redirect(url_for('charts', 
            from_month=from_month,
            to_month=to_month,
            year=year)
            )

    if request.method == 'GET':
        #get the years the user has been inputting data
        dates = query_db("SELECT date FROM user_exercises WHERE user_id = ?",[session['user_id']])
        user_years = set(date[0].split("-")[0] for date in dates)
        
        from_month = request.args.get('from_month')
        to_month = request.args.get('to_month')
        year = request.args.get('year')

        print(from_month, to_month, year)
        if not from_month:
            from_month = "01"
        if not to_month:
            to_month = "12"
        if not year:
            year = "2024"

        from_date = f"{year}-{from_month}-01"
        to_date = f"{year}-{to_month}-28"
        print(f"selected dates: {from_date}, {to_date}")

        selectable_exercises = [exercise['name'] for exercise in query_db("""SELECT name FROM exercises""")]
        # Dictionary to store results for each exercise
        exercise_data = get_exercise_data(selectable_exercises, from_date, to_date)
        
        return render_template('charts.html', 
            exercise_data = exercise_data,
            selectable_exercises=selectable_exercises, 
            user_years=user_years,
            from_date=from_date,
            to_date=to_date,
            selected_from_month=from_month,
            selected_to_month = to_month,
            selected_year=year
            )
    
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        login_error = None
        # Ensure username was submitted
        if not request.form.get("username"):
            login_error = "must provide username"
            return render_template('login.html', login_error = login_error)

        # Ensure password was submitted
        elif not request.form.get("password"):
            login_error = "must provide password"
            return render_template('login.html', login_error = login_error)

        # Improved database query
        user = query_db('SELECT * FROM users WHERE username = ?', [request.form.get("username")], one=True)
        if user is None or not check_password_hash(user['password_hash'], request.form.get("password")):
            login_error = "invalid username and/or password"
            return render_template('login.html', login_error = login_error)

        # Remember which user has logged in
        session["user_id"] = user['id']

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")
    

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/logout")
def logout():
    """Log user out"""
    # Forget any user_id
    session.clear()
    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # display register form
    if request.method == "GET":
        return render_template("register.html")

    # check possible errors and insert the new user into users db
    if request.method == "POST":
        register_error = None
        name = request.form.get("username")
        password = request.form.get("password")
        confirm_password = request.form.get("confirmation_password")
        email = request.form.get("email")

        if not password or not confirm_password or not name:
            register_error = "no empty fields"
            return render_template("register.html", register_error = register_error)
        
        # Check for existing user
        existing_user = query_db("SELECT username FROM users WHERE username = ?", [name], one=True)
        if existing_user:
            register_error = "username already exists"
            return render_template("register.html", register_error = register_error)

        if password != confirm_password:
            register_error = "passwords dont match"
            return render_template("register.html", register_error = register_error)

        # Insert new user with hashed password
        db = get_db()
        db.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", [name, generate_password_hash(password), email])
        db.commit()

        # Get the new user's ID and log them in
        user = query_db("SELECT id FROM users WHERE username = ?", [name], one=True)
        session["user_id"] = user['id']
        return redirect("/")
    

if __name__ == '__main__':
    app.run(debug=True)