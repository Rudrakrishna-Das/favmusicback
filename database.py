import os
from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()

class Db:
    def __init__(self):
        client = MongoClient(os.getenv('MONGO_CLIENT'))
        db = client['fav-music']
        self.user = db.user


