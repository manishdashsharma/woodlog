import firebase
from .config import *

# config = {

# }
app = firebase.initialize_app(config)

auth = app.auth()
database = app.database()
print(database)