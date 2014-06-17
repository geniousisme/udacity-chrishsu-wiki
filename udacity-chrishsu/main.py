 #!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import jinja2
import os
import hashlib
import hmac
import string

SECRET = "lalalala"

# def hash_str(s):
#   return hashlib.md5(s).hexdigest()
def hash_str(s):
  return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
  return s + '|' + hash_str(s)

def check_secure_val(h):
  h_s = h.split('|')[0]
  return h_s if make_secure_val( h_s ) == h else None

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))
# Implement the function valid_pw() that returns True if a user's password 
# matches its hash. You will need to modify make_pw_hash.

def make_pw_hash(name, pw):
    salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    ###Your code here
    name_pw_salt, salt = h.split(',')
    return name_pw_salt == hashlib.sha256(name + pw + salt).hexdigest() 

from google.appengine.ext import db

template_dir = os.path.join( os.path.dirname(__file__), "template" )
jinja_env = jinja2.Environment( loader = jinja2.FileSystemLoader( template_dir ), autoescape = True )

class Handler(webapp2.RequestHandler):
  def write(self, *a, **kw):
    self.response.out.write(*a, **kw)

  def render_str(self, template, **params):
    t = jinja_env.get_template( template )
    return t.render( params )

  def render( self, template, **kw ):
    self.write( self.render_str( template, **kw ) )

class Art(db.Model):
  title   = db.StringProperty( required = True )  
  art     = db.TextProperty( required = True )
  created = db.DateTimeProperty( auto_now_add = True )

def blog_key(name = 'default'):
  return db.Key.from_path('blogs', name)

class Blog( db.Model ):
  subject = db.StringProperty( required = True )
  content = db.TextProperty( required = True )
  created = db.DateTimeProperty( auto_now_add = True )
  last_modified = db.DateTimeProperty( auto_now = True )

  def render( self ):
    self._render_text = self.content.replace('\n', '<br>')
    return render_str("post.html", p = self)


class MainHandler( Handler ):
  def render_ascii(self, title = "", art = "", error = ""):
    arts = db.GqlQuery("select * from Art order by created desc")
    self.render( "ascii.html", title = title, art = art, error = error, arts = arts )

  def get(self):
    self.response.headers['Content-Type'] = 'text/plain'
    # visits = self.request.cookies.get('visits', 0) # get is the dictionary method, if we get the argument 'visit', then tae the value, else we take 0
    visits = 0
    visit_cookie_str = self.request.cookies.get('visits')
    if visit_cookie_str:
      cookie_val = check_secure_val( visit_cookie_str )
      if cookie_val:
        visits = int( cookie_val )
    visits += 1
    new_cookie_val = make_secure_val( str( visits ) )
    self.response.headers.add_header( 'Set-Cookie', 'visits=%s' % new_cookie_val )
    if visits >= 10000:
      self.write("You are the best forever !!!!")
    else:
      self.write("You have been here for %s times!" % visits)
    # self.render_ascii()
   
  def post(self):
    title = self.request.get("title")
    art   = self.request.get("art")
    if title and art:
      new_art = Art( title = title, art = art )
      new_art.put()
      self.redirect("/")
    else:
      error = "We need both a title and some artwork!!!"
      self.render_ascii( title, art , error )

class BlogHandler( Handler ):
  def render_blog(self, blog_id = "" ):
    if blog_id == "":
      blogs = db.GqlQuery( "select * from Blog order by created desc" ) 
      self.render( "blog.html", blogs = blogs )
    else:
      blog = Blog.get_by_id( long( blog_id ) )
      self.render( "post.html", blog = blog )

  def get(self, blog_id = ""):
    self.render_blog( blog_id = blog_id )

class NewPostHandler( Handler ):
  def render_newpost(self, subject = "", content = "", error = "" ):
    self.render( "newpost.html", subject = subject, content = content, error = error )
  
  def get( self ):
    self.render_newpost()

  def post( self ):
    subject = self.request.get("subject")
    content = self.request.get("content").replace('\n', '<br>')

    if subject and content:
      newpost = Blog( subject = subject, content = content )
      newpost.put()
      self.redirect( "/blog/" + str( newpost.key().id() ) )
    else:
      error = "We need both subject and content for blog !!"
      self.render_newpost( subject, content, error )

class FizzBuzzHandler( Handler ):
  def get( self ):
    n = self.request.get("n", 0)
    n = n and int( n )
    self.render( "fizzbuzz.html", n = n )

app = webapp2.WSGIApplication([
    ( '/', MainHandler ), 
    ( '/fizzbuzz', FizzBuzzHandler ),
    ( '/blog', BlogHandler ),
    ( '/blog/(\d+)', BlogHandler ),
    ( '/blog/newpost', NewPostHandler )
], debug=True)
