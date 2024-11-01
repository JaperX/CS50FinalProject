import sqlite3
import time
from datetime import datetime, timedelta
from flask import g
from flask_session import Session
from flask import session
from flask import redirect, session
from functools import wraps

#database helper functions to open and close sqlite3 db
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect("ProgressiveOverload.db")
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(error):
    #close db connection at end of request
    db = g.pop('db', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    #Execute query and fetch results
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def start_date(date_request_argument):
    selected_date = date_request_argument
    if selected_date:
        # If date provided in URL, parse it
        try:
            start_date = datetime.strptime(selected_date, "%Y-%m-%d").replace(hour=0, minute=0, second=0)
        except ValueError:
        # Handle invalid date format by defaulting to today
            start_date = datetime.now().replace(hour=0, minute=0, second=0)
    else:
        # No date provided, use today
        start_date = datetime.now().replace(hour=0, minute=0, second=0)
    return start_date

def get_exercise_data(selectable_exercises, date_str, date_end_str):
        exercise_data = {}
        # For each exercise, get the best sets per day
        for exercise in selectable_exercises:
            # Get the exercise ID
            exercise_id_result = query_db("""
                SELECT id FROM exercises WHERE name = ?""", [exercise], one=True)
            
            if exercise_id_result:
                exercise_id = exercise_id_result['id']
                # Get best weight and reps per day for this exercise
                daily_bests = query_db("""
                    WITH DailyMaxes AS (
                        SELECT 
                            date,
                            MAX(weight) as max_weight,
                            MAX(reps) as max_reps
                        FROM user_exercises
                        WHERE exercise_id = ? 
                        AND user_id = ?
                        AND date BETWEEN ? AND ?
                        GROUP BY date
                    )
                    SELECT 
                        ue.date,
                        ue.weight,
                        ue.reps
                    FROM user_exercises ue
                    INNER JOIN DailyMaxes dm 
                        ON ue.date = dm.date 
                        AND (ue.weight = dm.max_weight OR ue.reps = dm.max_reps)
                    WHERE ue.exercise_id = ?
                    AND ue.user_id = ?
                    AND ue.date BETWEEN ? AND ?
                    ORDER BY ue.date
                """, [exercise_id, session['user_id'], date_str, date_end_str,
                      exercise_id, session['user_id'], date_str, date_end_str])

                # Format the data for the chart
                exercise_data[exercise] = {
                    'dates': [],
                    'weights': [],
                    'reps': []
                }

                for record in daily_bests:
                    date = record['date']
                    if date not in exercise_data[exercise]['dates']:
                        exercise_data[exercise]['dates'].append(date)
                        exercise_data[exercise]['weights'].append(record['weight'])
                        exercise_data[exercise]['reps'].append(record['reps'])
        #print("Chart data:", exercise_data)  # Debug print

        return exercise_data

def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/latest/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function

