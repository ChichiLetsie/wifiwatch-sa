import os
#to work with files and folders easily.
from pathlib import Path 

#finds the main folder of your project (the "root" folder) as saves the location in BASE_DIR
BASE_DIR = Path(__file__).resolve().parent.parent 

#To figure out where to save or find the database.
SQLITE_DB_PATH = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR}/wifiwatch.db")