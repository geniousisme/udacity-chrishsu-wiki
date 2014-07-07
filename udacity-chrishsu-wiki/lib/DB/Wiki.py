from google.appengine.ext import db

def wikis_key(group = 'default'):
    return db.Key.from_path('wikis', group)

class Wiki(db.Model):
  subject = db.StringProperty(required = True)
  content = db.TextProperty(required = True)
  created = db.DateTimeProperty( auto_now_add = True )

  def render( self ):
      self._render_text = self.content.replace('\n', '<br>')
      return render_str("wiki.html", p = self)

  @classmethod
  def create(cls, subject, content):
      return Wiki( parent = wikis_key(), subject  = subject, content = content )

  @classmethod
  def by_subject_all(cls, subject):
      w = Wiki.all().filter('subject =', subject).order('-created')
      return w

  @classmethod
  def by_subject_last(cls, subject):
      w = Wiki.by_subject_all( subject ).get()
      return w and w