from google.appengine.ext import db

def wikis_key(group = 'default'):
    return db.Key.from_path('wikis', group)

class Wiki(db.Model):
  subject = db.StringProperty(required = True)
  content = db.StringProperty(required = True)
  created = db.DateTimeProperty( auto_now_add = True )

  @classmethod
  def create(cls, subject, content):
      return Wiki( parent = wikis_key(), subject  = subject, content = content )

  @classmethod
  def by_subject(cls, subject):
      w = Wiki.all().filter('subject =', subject).get()
      return w

  @classmethod
  def last(cls, subject):
      w = Wiki.all().order('-created').filter('subject =', subject).get()
      return w and w