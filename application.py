'''
PROG:   application.py
AUTH:   Jose De La Rosa Rodriguez
DATE:   Started - 20200709 Completed - XX/XX/2020
DESC:   Create back end program in Python using the Flask framework to host final project website
'''


# import libraries needed
import os
import sqlite3
from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash

from helpers import error, login_required


# Configure application
app = Flask(__name__)

# Enable templates to auto-reload when changed
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Set a random secret key the sessions object
app.secret_key = os.urandom(16)

# Create a connection object that represents the database
conn = sqlite3.connect('personal.db')

# Create a cursor object to query the database using the execute() method
db = conn.cursor()



@app.route('/edit', methods=['GET', 'POST'])
@login_required

# Edit database trasaction data
def edit():

    if request.method == 'POST':

        return redirect('/edit')

    else:
        return render_template('/edit.html')

@app.route('/')
@login_required
def index():
    return render_template('index.html')



@app.route('/input', methods=['GET', 'POST'])
@login_required
def input():

    if request.method == 'POST':


        # Get input data from form
        form_data = request.form

        data_typ = request.form['data_typ'].lower()

        acct_typ = request.form['acct_typ'].lower()

        acct_desc = request.form['acct_desc']
        start_dt = request.form['start_dt']
        end_dt = request.form['end_dt']
        due_dt = request.form['due_dt']

        # Convert acct type to integer
        if acct_typ == 'checking':
            acct_typ = 1

        elif acct_typ == 'savings':
            acct_typ = 2

        elif acct_typ == 'credit card':
            acct_typ = 3


        acct_stat = 1 # Status 1 = 'Open'


        date = request.form['date']
        acct_desc1 = request.form['acct_desc1']
        tran_typ = request.form['tran_typ'].lower()
        desc = request.form['desc']
        amt = request.form['amt']
        note = request.form['note']

        # Convert transaction type to integer
        if tran_typ == 'deposit':
            tran_typ = 1

        elif tran_typ == 'purchase':
            tran_typ = 2

        elif tran_typ == 'withdraw':
            tran_typ = 3

        else:
            tran_typ= 0 # No type 'None' selected



        print(form_data)

        if data_typ == 'accounts':

            # Insert data into the database accounts table
            db.execute('INSERT INTO accounts (acct_typ, acct_desc, acct_dt_start, acct_dt_end, acct_stat, acct_dt_due, acct_usrs_id)\
                        VALUES(?,?,?,?,?,?,?)', (acct_typ, acct_desc, start_dt, end_dt, acct_stat, due_dt, session['user_id']))

            # Save changes to sqlite database
            conn.commit()


        ### TODO ### IMPLEMENT ACCOUNT HISTORY INPUT
        # Check of transaction data type
        # if data_typ == 'account history':


        # Check if transaction data type
        if data_typ == 'transactions':

            # Get account id
            acct_id = db.execute('SELECT acct_id FROM accounts WHERE acct_desc = ?', (acct_desc1,)).fetchall()

            print('to be inserted: ', date, tran_typ, desc, amt, note, acct_id)
            # Insert data into the database trasaction table
            db.execute('INSERT INTO transactions (tran_dt, tran_typ, tran_desc, tran_amt, tran_note, tran_acct_id)\
                        VALUES(?,?,?,?,?,?)', (date, tran_typ, desc, amt, note, acct_id[0][0]))

            # Save changes to sqlite database
            conn.commit()

            print('saved')

        return redirect('/input')

    else:

        # Fetch user existing accounts to preload input form
        acct_desc = db.execute('SELECT acct_desc FROM accounts WHERE acct_usrs_id = ?', (session['user_id'],)).fetchall()

        return render_template('input.html', acct_desc=acct_desc)


### DONE ###
@app.route('/login', methods=['GET', 'POST'])
def login():

    # For any user id
    session.clear()

    # Determine if page request via 'POST' method
    if request.method == 'POST':

        # Store the login form information in a variable (data is ImmutableMultiDict type)
        login_info = request.form

        # Check if user entered a username
        if not login_info['user_nm']:
            return error('No username entered', 403)

        # Check if user entered a username
        if not login_info['pw']:
            return error('No password entered', 403)

        # Get user information from the database
        user_nm_match = db.execute('SELECT * FROM users WHERE usrs_user_nm = ?', (login_info['user_nm'],)).fetchall()

        # Check if user name exists
        if len(user_nm_match) == 0:
            return error("Username does not exists", 403)

        # Check if multiple username matches exist in the database
        if len(user_nm_match) > 1:
            return error("Multiple username matches found", 403)

        # Get password information from the database
        user_pw_info = db.execute('SELECT users.usrs_id, password_hist.pw_hist_pw_hash FROM users \
                                    INNER JOIN password_hist ON users.usrs_id = password_hist.pw_hist_usrs_id \
                                    WHERE users.usrs_user_nm = ? ORDER BY password_hist.pw_hist_id DESC LIMIT 1', (login_info['user_nm'],)).fetchall()

        # Check if password exists
        if not user_pw_info:
            return error("Password not found", 403)

        # Check if password match password in database
        if not check_password_hash(user_pw_info[0][1], login_info['pw']):
            return error('Incorrect password entered', 403)

        # Remember user logged in
        session['user_id'] = user_pw_info[0][0]

        # Redirect to homepage
        return redirect('/')

    else:
        return render_template('login.html')


### DONE ###
@app.route('/logout')
def logout():

    '''Log out the user'''

    # Forget any user_id
    session.clear()

    # Redirect user to login page
    return redirect('/')



@app.route('/lookup', methods=['GET', 'POST'])
@login_required

# Lookup data in the database
def lookup():

    # Determine if page request via 'POST' method
    if request.method == 'POST':

        # TODO-Update perform validation and update databaae

        # TODO-Render updated information from thendatabase

        # Get form data to lookup
        lookup_data = request.form

        data_typ = request.form['data_typ'].lower()

        if data_typ == 'accounts':

            data = db.execute('SELECT * FROM accounts WHERE acct_usrs_id = ?', (session['user_id'],)).fetchall()

            if len(data) == 0:
                return error('No accounts found', 400)

        if data_typ == 'account history':

            data = db.execute('SELECT * FROM account_hist').fetchall()

        if data_typ == 'transactions':

            data = db.execute('SELECT * FROM transactions').fetchall()


        return render_template('view.html', data_typ=data_typ, data=data)

    else:

        # Fetch user existing accounts to preload input form
        acct_desc = db.execute('SELECT acct_desc FROM accounts WHERE acct_usrs_id = ?', (session['user_id'],)).fetchall()

        return render_template('lookup.html', acct_desc=acct_desc)



@app.route('/profile', methods=['GET', 'POST'])
@login_required
# Show user profile and allow to user to make changes
def profile():

    # Determine if page request via 'POST' method
    if request.method == 'POST':

        profile_updt_info = request.form
        print('Test: ', profile_updt_info)

        if not profile_updt_info['pw']:
            return error('No password provided', 403)

        if not profile_updt_info['pw_conf']:
            return error('No password confirmation provided', 403)

        if profile_updt_info['pw'] != profile_updt_info['pw_conf']:
            return error('Passwords do not match', 403)

        pw_hash_new = generate_password_hash(profile_updt_info['pw'])

        db.execute('INSERT INTO password_hist (pw_hist_pw_hash, pw_hist_usrs_id) \
                    VALUES (?, ?)', (pw_hash_new, session['user_id']))

        print('passed insert')

        # Save changes to sqlite database
        conn.commit()

        # Close connection to sqlite database
        #conn.close()

        return redirect('/profile')

    else:
        # Query the database for user profile information
        user_profile_info = db.execute('SELECT * FROM users WHERE usrs_id = ?', (session['user_id'],)).fetchall()

        # Check if user informtion exists
        if len(user_profile_info) == 0:
            return error('No users profile information found', 403)

        # Check if multiple users exits with the same information
        if len(user_profile_info) > 1:
            return error('Multiple user profiles found', 403)

        return render_template('profile.html',
            user_nm = user_profile_info[0][1],
            pw = '*' * 10,
            first_nm = user_profile_info[0][3],
            middle_nm = user_profile_info[0][4],
            last_nm = user_profile_info[0][5],
            address = user_profile_info[0][6],
            phone = user_profile_info[0][7],
            email = user_profile_info[0][8])
            #pw_last_updt = user_profile_info[0][9])



@app.route('/recover', methods=['GET', 'POST'])
def recover():

    ''' Recover a user's password '''
    if request.method == 'POST':

        #TODO-Validate phone/email exist and send username or password
        return redirect('/login')
    else:
        return render_template('recover.html')


@app.route('/register', methods=['GET', 'POST'])

# Register users to access web application
def register():

    # Determine if page request via 'POST' method
    if request.method == 'POST':

        # Store the form information in a variable (data is ImmutableMultiDict type)
        regi_info = request.form

        # Query database for existing username (using placeholder and tupple holding the argument)
        users_info_fetch = db.execute('SELECT * FROM users WHERE usrs_user_nm = ?', (regi_info['user_nm'],)).fetchall()

        print('user name:', users_info_fetch)
        # Check if username already exists
        if not len(users_info_fetch) == 0:
            return error('User name exists', 403)

        # Check if passwords match
        if regi_info['pw'] != regi_info['pw_conf']:
            return error('Password do not match', 403) ### NEED TO IMPLEMENT APLOGY PAGE ###

        ### TEST CODE - DELETE WHEN DONE ###
        for item in regi_info:
            print(item, ': ', regi_info[item])

        # Get a hash value of the password to store in the database
        pw_hash = generate_password_hash(regi_info['pw'])

        # Insert registration information into the 'users' table
        db.execute('INSERT INTO users (usrs_user_nm, usrs_pw_hash, usrs_first_nm, usrs_middle_nm, usrs_last_nm, usrs_address, usrs_phone, usrs_email) \
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)', \
                    (regi_info['user_nm'], pw_hash, regi_info['first_nm'], regi_info['middle_nm'], regi_info['last_nm'], regi_info['address'], regi_info['phone'], regi_info['email']))

        # Get user_id for new user
        user_id_new = db.execute('SELECT usrs_id FROM users WHERE usrs_user_nm = ?', (regi_info['user_nm'],)).fetchall()

        # Update password to password history
        db.execute('INSERT INTO password_hist (pw_hist_pw_hash, pw_hist_usrs_id) \
                    VALUES (?, ?)', (pw_hash, user_id_new[0][0]))

        # Save changes to sqlite database
        conn.commit()

        # Close connection to sqlite database
        #conn.close()

        return redirect('/')

    else:

        # Forget current user id
        session.clear()

        return render_template('register.html')