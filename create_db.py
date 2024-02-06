import mysql.connector

mydb = mysql.connector.connect(
	host="localhost",
	user="root",
	passwd = "Password123",
	)
	

my_cursor = mydb.cursor()

#uncomment if you want to cerate db
#my_cursor.execute("CREATE DATABASE IF NOT EXISTS our_users")

my_cursor.execute("SHOW DATABASES")
for db in my_cursor:
	print(db)