from flask import Flask, render_template, flash, request, redirect, url_for, jsonify, render_template
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError, TextAreaField
from wtforms.validators import DataRequired, EqualTo, Length
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
import pymysql
from passlib.hash import sha256_crypt
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
import requests
import pandas as pd
import xmltodict
import plotly.graph_objects as go
import os
import matplotlib.pyplot as plt
import numpy as np


# Create a Flask Instance
app = Flask(__name__)
# Old SQLite Database
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
# New MySQL Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Password123@localhost/our_users'
#Secret Key
app.config['SECRET_KEY'] =  "my super secret key that no one is supposed to know"
#Initialize The Database
db = SQLAlchemy(app)
migrate = Migrate(app, db)



# Flask_Login Stuff
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
	return Users.query.get(int(user_id))

# Create Login Form
class LoginForm(FlaskForm):
	user_name = StringField("Username", validators=[DataRequired()])
	password = PasswordField("Password", validators=[DataRequired()])
	submit = SubmitField("Submit")


# Create Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		user = Users.query.filter_by(user_name=form.user_name.data).first()
		if user:
			# Check the hash
			if sha256_crypt.verify(form.password.data,user.password_hash):
				login_user(user)
				flash("Login Succesfull!!")
				return redirect(url_for('chart'))
			else:
				flash("Wrong Password - Try Again!")
		else:
			flash("That User Doesn't Exist! Try Again...")


	return render_template('login.html', form=form)

# Create Logout Page
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
	logout_user()
	flash("You Have Been Logged Out!  Thanks For Stopping By...")
	return redirect(url_for('login'))


# Update Database Record
@app.route('/update/<int:id>', methods=['GET', 'POST'])
def update(id):
	form = UserForm()
	name_to_update = Users.query.get_or_404(id)
	if request.method == "POST":
		name_to_update.name = request.form['name']
		name_to_update.email = request.form['email']
		try:
			db.session.commit()
			flash("User Updated Successfully!")
			return render_template("update.html", 
				form=form,
				name_to_update = name_to_update, id=id)
		except:
			flash("Error!  Looks like there was a problem...try again!")
			return render_template("update.html", 
				form=form,
				name_to_update = name_to_update,
				id=id)
	else:
		return render_template("update.html", 
				form=form,
				name_to_update = name_to_update,
				id = id)


# Create Model

class Users(db.Model, UserMixin):
	id = db.Column(db.Integer, primary_key=True)
	user_name = db.Column(db.String(20), nullable=False, unique=True)
	name = db.Column(db.String(200), nullable=False)
	email = db.Column(db.String(120), nullable=False, unique=True)
	date_added = db.Column(db.DateTime, default=datetime.utcnow)

	# Do some password stuff!
	password_hash = db.Column(db.String(128))
	
	@property
	def password(self):
		raise AttributeError('password is not a readable attribute!')

	#this function set the password hash
	@password.setter
	def password(self, password):
		self.password_hash = generate_password_hash(password)

	#this function verifing hashed value vs password
	def verify_password(self, password):
		return check_password_hash(self.password_hash, password)

	# Create A String
	def __repr__(self):
		return '<Name %r>' % self.name

# Create a UserForm Class
class UserForm(FlaskForm):
	name = StringField("Name", validators=[DataRequired()])
	username = StringField("Username", validators=[DataRequired()])
	email = StringField("Email", validators=[DataRequired()])
	password_hash = PasswordField("Password", validators=[DataRequired(), EqualTo('password_hash2', message='Passwords Must Match!')])
	password_hash2 = PasswordField("Confirm Password", validators=[DataRequired()])
	submit = SubmitField("Submit")

@app.route('/user/add', methods=['GET', 'POST'])

#This function is called when user submits the form
def add_user():
	name = None
	form = UserForm()


	#that's the check for unique email in the database. If not unique then email incorrect
	if form.validate_on_submit():
		user = Users.query.filter_by(email=form.email.data).first()
		if user is None:
			# Hash the password!!!
			hashed_pw = sha256_crypt.hash(form.password_hash.data)
			user = Users(user_name=form.username.data, name=form.name.data, email=form.email.data, password_hash=hashed_pw)
			db.session.add(user)
			db.session.commit()
		name = form.name.data
		#this part is clearing the form
		form.name.data = ''
		form.username.data = ''
		form.email.data = ''
		form.password_hash.data = ''

		flash("User Added Successfully!")
	our_users = Users.query.order_by(Users.date_added)
	return render_template("add_user.html", 
		form=form,
		name=name,
		#this return our users from db
		our_users = our_users
		)


@app.route('/delete/<int:id>')
def delete(id):
	# Check logged in id vs. id to delete
		user_to_delete = Users.query.get_or_404(id)
		name = None
		form = UserForm()

		try:
			db.session.delete(user_to_delete)
			db.session.commit()
			flash("User Deleted Successfully!!")

			our_users = Users.query.order_by(Users.date_added)
			return render_template("add_user.html", 
			form=form,
			name=name,
			our_users=our_users)

		except:
			flash("Whoops! There was a problem deleting user, try again...")
			return render_template("add_user.html", 
			form=form, name=name,our_users=our_users)
	



# Create a Form Class
class NameForm(FlaskForm):
	name = StringField("What's Your Name", validators=[DataRequired()])
	submit = SubmitField("Submit")

# Create a route decorator
@app.route('/')

def index():
	return render_template('index.html')

# localhost:5000/user/Natalia
@app.route('/user/<name>')

def user(name):
    return render_template('user.html', user_name=name)

# Create Custom Error Pages

# Invalid URL
@app.errorhandler(404)
def page_not_found(e):
	return render_template("404.html"), 404

# Internal Server Error
@app.errorhandler(500)
def page_not_found(e):
	return render_template("500.html"), 500



# Create Password Test Page
@app.route('/test_pw', methods=['GET', 'POST'])
def test_pw():
	email = None
	password = None
	pw_to_check = None
	passed = None
	form = PasswordForm()


	# Validate Form
	if form.validate_on_submit():
		email = form.email.data
		password = form.password_hash.data
		# Clear the form
		form.email.data = ''
		form.password_hash.data = ''

		# Lookup User By Email Address
		pw_to_check = Users.query.filter_by(email=email).first()
		
		# Check Hashed Password
		passed = sha256_crypt.verify(password, pw_to_check.password_hash)

	return render_template("test_pw.html", 
		email = email,
		password = password,
		pw_to_check = pw_to_check,
		passed = passed,
		form = form)

#Create a Form Class
class PasswordForm(FlaskForm):
	email = StringField("What's Your Email", validators=[DataRequired()])
	password_hash = PasswordField("What's Your Password", validators=[DataRequired()])
	submit = SubmitField("Submit")

# Create Name Page
@app.route('/name', methods=['GET', 'POST'])
def name():
	name = None
	form = NameForm()
	# Validate Form
	if form.validate_on_submit():
		name = form.name.data
		form.name.data = ''
		flash("Form Submitted Successfully!")
		
	return render_template("name.html", 
		name = name,
		form = form)



#API call - for Table
@app.route('/get_data_from_gus')
def get_data_from_gus():


    def get_data_from_GUS(variable_list, parent_id_list):
        all_data = []
        for variable_id in variable_list:
            for parent_id in parent_id_list:
                url = f"https://bdl.stat.gov.pl/api/v1/data/by-variable/{variable_id}?unit-parent-id={parent_id}"
                headers = {
                    "X-ClientId": "ace37d5f-bfc3-4b0b-7365-08dc134fef30"
                }
                params = {
                    "format": "xml",
                    "page-size": "100",
                }
                while url:
                    response = requests.get(url, headers=headers, params=params)
                    if response.status_code == 200:
                        data_dict = xmltodict.parse(response.text)
                        for unit_data in data_dict.get("singleVariableData", {}).get("results", {}).get("unitData", []):
                            unit_id = unit_data.get("id")
                            name = unit_data.get("name")
                            values = []
                            for year_val in unit_data.get("values", {}).get("yearVal", []):
                                year = int(year_val.get("year"))
                                val = int(year_val.get("val"))
                                attr_id = int(year_val.get("attrId"))
                                values.append({"year": year, "value": val, "attrId": attr_id})
                            all_data.append({"id": unit_id, "variable_id": variable_id, "name": name, "values": values})
                        next_link = data_dict.get("singleVariableData", {}).get("links", {}).get("next")
                        url = next_link if next_link else None
                    else:
                        print(f"Błąd {response.status_code}: {response.text}")

        df_list = []
        for entry in all_data:
            for value in entry["values"]:
                df_list.append({
                    "id": entry["id"],
                    "variable_id": entry["variable_id"],
                    "name": entry["name"],
                    "year": value["year"],
                    "value": value["value"],
                    "attrId": value["attrId"]
                })

        df = pd.DataFrame(df_list)[["id", "variable_id", "name", "year", "value"]]
        df['id'] = df['id'].astype(str)
        pd.set_option("display.max_rows", None)
        return df

    parent_id_list = ['010000000000','020000000000','030000000000','040000000000','050000000000','060000000000','070000000000']
    variable_list = ['1611283','1611284','1611285','1611286','1611287','1611288','1611289','1611290','1611291']
    df = get_data_from_GUS(variable_list, parent_id_list)
    voivodeship=['011200000000','012400000000','020800000000','023000000000','023200000000', \
                 '030200000000','031600000000','040400000000','042200000000','042800000000', \
                 '051000000000','052600000000','060600000000','061800000000','062000000000','071400000000']
    df_gus = (df[df['id'].isin(voivodeship)].reset_index(drop=True))
    df_gus['variable_id'] = df_gus['variable_id'].astype('int64')

    data = {
        "studenci ogółem studia stacjonarne": {"variable_id": 1611284, "category": "studenci", "gender": "ogółem", "study_type": "studia stacjonarne"},
        "studenci ogółem studia niestacjonarne": {"variable_id": 1611285, "category": "studenci", "gender": "ogółem", "study_type": "studia niestacjonarne"},
        "studenci kobiety studia stacjonarne": {"variable_id": 1611287, "category": "studenci", "gender": "kobiety", "study_type": "studia stacjonarne"},
        "studenci kobiety studia niestacjonarne": {"variable_id": 1611288, "category": "studenci", "gender": "kobiety", "study_type": "studia niestacjonarne"},
        "studenci mężczyźni studia stacjonarne": {"variable_id": 1611290, "category": "studenci", "gender": "mężczyźni", "study_type": "studia stacjonarne"},
        "studenci mężczyźni studia niestacjonarne": {"variable_id": 1611291, "category": "studenci", "gender": "mężczyźni", "study_type": "studia niestacjonarne"},
        "absolwenci ogółem studia stacjonarne": {"variable_id": 1611293, "category": "absolwenci", "gender": "ogółem", "study_type": "studia stacjonarne"},
        "absolwenci ogółem studia niestacjonarne": {"variable_id": 1611294, "category": "absolwenci", "gender": "ogółem", "study_type": "studia niestacjonarne"},
        "absolwenci kobiety studia stacjonarne": {"variable_id": 1611296, "category": "absolwenci", "gender": "kobiety", "study_type": "studia stacjonarne"},
        "absolwenci kobiety studia niestacjonarne": {"variable_id": 1611297, "category": "absolwenci", "gender": "kobiety", "study_type": "studia niestacjonarne"},
        "absolwenci mężczyźni studia stacjonarne": {"variable_id": 1611299, "category": "absolwenci", "gender": "mężczyźni", "study_type": "studia stacjonarne"},
        "absolwenci mężczyźni studia niestacjonarne": {"variable_id": 1611300, "category": "absolwenci", "gender": "mężczyźni", "study_type": "studia niestacjonarne"},
    }

    df_with_mapping = pd.DataFrame.from_dict(data, orient='index').reset_index(drop=True)
    df_with_mapping['variable_id'] = df_with_mapping['variable_id'].astype('int64')

    merged_df = pd.merge(df_gus, df_with_mapping, on="variable_id")
    merged_df = merged_df.drop(columns=['id']).drop(columns=['variable_id'])

    return render_template('table.html', data=merged_df.to_dict(orient='records'))




#API call
@app.route('/get_data_from_gus')
def get_data_from_gus2():

    def get_data_from_GUS(variable_list, parent_id_list):
        all_data = []
        for variable_id in variable_list:
            for parent_id in parent_id_list:
                url = f"https://bdl.stat.gov.pl/api/v1/data/by-variable/{variable_id}?unit-parent-id={parent_id}"
                headers = {
                    "X-ClientId": "ace37d5f-bfc3-4b0b-7365-08dc134fef30"
                }
                params = {
                    "format": "xml",
                    "page-size": "100",
                }
                while url:
                    response = requests.get(url, headers=headers, params=params)
                    if response.status_code == 200:
                        data_dict = xmltodict.parse(response.text)
                        for unit_data in data_dict.get("singleVariableData", {}).get("results", {}).get("unitData", []):
                            unit_id = unit_data.get("id")
                            name = unit_data.get("name")
                            values = []
                            for year_val in unit_data.get("values", {}).get("yearVal", []):
                                year = int(year_val.get("year"))
                                val = int(year_val.get("val"))
                                attr_id = int(year_val.get("attrId"))
                                values.append({"year": year, "value": val, "attrId": attr_id})
                            all_data.append({"id": unit_id, "variable_id": variable_id, "name": name, "values": values})
                        next_link = data_dict.get("singleVariableData", {}).get("links", {}).get("next")
                        url = next_link if next_link else None
                    else:
                        print(f"Błąd {response.status_code}: {response.text}")

        df_list = []
        for entry in all_data:
            for value in entry["values"]:
                df_list.append({
                    "id": entry["id"],
                    "variable_id": entry["variable_id"],
                    "name": entry["name"],
                    "year": value["year"],
                    "value": value["value"],
                    "attrId": value["attrId"]
                })

        df = pd.DataFrame(df_list)[["id", "variable_id", "name", "year", "value"]]
        df['id'] = df['id'].astype(str)
        pd.set_option("display.max_rows", None)
        return df

    parent_id_list = ['010000000000','020000000000','030000000000','040000000000','050000000000','060000000000','070000000000']
    variable_list = ['1611284','1611285']
    df = get_data_from_GUS(variable_list, parent_id_list)
    voivodeship=['011200000000','012400000000','020800000000','023000000000','023200000000', \
                 '030200000000','031600000000','040400000000','042200000000','042800000000', \
                 '051000000000','052600000000','060600000000','061800000000','062000000000','071400000000']
    df_gus = (df[df['id'].isin(voivodeship)].reset_index(drop=True))
    df_gus['variable_id'] = df_gus['variable_id'].astype('int64')

    data = {
    "studenci ogółem studia stacjonarne": {"variable_id": 1611284, "category": "studenci", "gender": "ogółem", "study_type": "studia stacjonarne"},
    "studenci ogółem studia niestacjonarne": {"variable_id": 1611285, "category": "studenci", "gender": "ogółem", "study_type": "studia niestacjonarne"}
	}

    df_with_mapping = pd.DataFrame.from_dict(data, orient='index').reset_index(drop=True)
    df_with_mapping['variable_id'] = df_with_mapping['variable_id'].astype('int64')

    merged_df = pd.merge(df_gus, df_with_mapping, on="variable_id")
    merged_df = merged_df.drop(columns=['id']).drop(columns=['variable_id'])

    return merged_df

#function to create charts(studia stacjonarne i niestacjonarne)
@app.route('/chart', methods=['GET', 'POST'])
@login_required
def chart():
    try:
        # Retrieve data from the function
        merged_df = get_data_from_gus2()

        # Define years to display
        years_to_display = [2022, 2021, 2020, 2019]

        # Create a larger figure to accommodate multiple charts
        plt.figure(figsize=(15, 12))  # Increased height of the figure

        chart_files = []

        for study_type in ['studia stacjonarne', 'studia niestacjonarne']:
            # Create separate figure for each study type
            plt.figure(figsize=(15, 12))

            for i, year in enumerate(years_to_display, start=1):
                # Filter data for the current year and study type
                merged_df_filtered = merged_df[merged_df['study_type'] == study_type]
                merged_df_year = merged_df_filtered[merged_df_filtered['year'] == year]
                chart_data_year = merged_df_year.groupby('name')['value'].sum()
                chart_data_year = chart_data_year.sort_values(ascending=False)

                # Calculate total students for the current year
                total_students = chart_data_year.sum()

                # Calculate mean and median
                mean_students = np.mean(chart_data_year)
                median_students = np.median(chart_data_year)

                # Plot the current year's chart
                plt.subplot(2, 2, i)
                plt.bar(chart_data_year.index, chart_data_year.values)
                plt.plot([*chart_data_year.index], [mean_students] * len(chart_data_year.index), color='green', linestyle='-',
                         label=f'Średnia: {mean_students:.2f}')
                plt.plot([*chart_data_year.index], [median_students] * len(chart_data_year.index), color='red', linestyle='--',
                         label=f'Mediana: {median_students:.2f}')
                plt.title(f'{year} - Liczba Studentów w Podziale na Województwo\nSuma wszystkich studentów: {total_students}')
                plt.xlabel('Województwo')
                plt.ylabel('Liczba studentów')
                plt.legend()

                # Add values above the bars
                for j, val in enumerate(chart_data_year.values):
                    plt.annotate(str(val), xy=(j, val), ha='center', va='bottom', fontsize=8)

                # Adjust x-axis font size
                plt.xticks(rotation=45, ha='right', fontsize=9)  # Decreased font size for x-axis labels

            # Adjust spacing between subplots
            plt.subplots_adjust(wspace=0.3, hspace=0.7, bottom=0.25)  # Increased bottom margin

            # Save the chart to a file
            chart_file = f'static/images/chart_{study_type.replace(" ", "_")}.png'  # Path to save the chart image
            plt.savefig(chart_file)
            chart_files.append(chart_file)

        # Pass the chart file paths to the template
        return render_template('chart.html', chart_file_stacjonarne=chart_files[0], chart_file_niestacjonarne=chart_files[1])
    except Exception as e:
        return f"Error: {e}"


if __name__ == '__main__':
    app.run(debug=True)
