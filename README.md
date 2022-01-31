# jwt_authorization_flask

follow following step for project set up:

# 1) creation of virtual env
python3 -m venv env
source env/bin/activate

pip install -r requirements.txt

Next you need to type the following in your python or python3 in your terminal then run below 2 commands:
from app import db
db.create_all()

So, what this does is first it imports the database object and then calls the create_all() function to create all the tables from the ORM.

# for starting application
python app1.py
