import os
from time import gmtime, strftime

def current_path():
  return os.environ['PATH_INFO']

def history_datetime( datetime ):
  return datetime.strftime('%c')
