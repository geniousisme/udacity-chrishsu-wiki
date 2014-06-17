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

import random
import string
import hashlib
import hmac



####################### validate the pw for the 

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

def make_pw_hash(name, pw):
    salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    name_pw_salt, salt = h.split(',')
    return name_pw_salt == hashlib.sha256(name + pw + salt).hexdigest()

####################### validate the user input for signing up

import re

def valid_username(username):
  username_re = re.compile(r"^[a-zA-Z0-9_-]{3,20}$").match(username)
  return username_re.group() if username_re is not None else None

def valid_password(password):
  password_re = re.compile(r"^.{3,20}$").match(password)
  return password_re.group() if password_re is not None else None

def valid_email(email):
  if email == "":
    return ""
  email_re = re.compile(r"^[\S]+@[\S]+\.[\S]+$").match(email)
  return email_re.group() if email_re is not None else None


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

class SignUpHandler( Handler ):
  def render_signup( self, **kw ):
    self.render( "signup.html", **kw )

  def get( self ):
    name = self.request.cookies.get('name')
    if name:
      self.redirect("/welcome")
    else:
      self.render_signup()

  def post( self, username = "", password = "", verify = "", email = "", invalid_username = "", invalid_password = "", invalid_verify = "", invalid_email = "" ):
    self.response.headers['Content-Type'] = 'text/plain'
    cookie_name = self.request.cookies.get('name')
    user_username = self.request.get("username")
    user_email    = self.request.get("email")

    vUsername = valid_username( user_username )
    vPassword = valid_password( self.request.get("password") )
    vVerify   = valid_password( self.request.get("verify") )
    vEmail    = valid_email( user_email )
    invalid_username_error = invalid_password_error = invalid_verify_error = invalid_email_error = ""
    if not ( vUsername and vPassword and vVerify and vPassword == vVerify and vEmail is not None and cookie_name ):
      if not vUsername:
        invalid_username_error = "That's not a valid username."
      if not cookie_name:
        invalid_username_error = "The username already existed."
      if not vPassword:
        invalid_password_error = "That wasn't a valid password."
      if vVerify != vPassword:
        invalid_verify_error   = "Your password didn't match."
      if vEmail is None:
        invalid_email_error    = "That's not a valid email."
      
      self.render_signup( username=user_username, password="", verify="", email=user_email, 
                          invalid_username=invalid_username_error, invalid_password=invalid_password_error, 
                          invalid_verify=invalid_verify_error, invalid_email=invalid_email_error )
    else:
      self.response.headers.add_header( 'Set-Cookie', 'name=%s' % str( vUsername ) )
      self.redirect( "/welcome" )

class WelcomeHandler( Handler ):
  def get( self ):
    name = self.request.cookies.get('name')
    if name:
      self.render( "welcome.html", username=name )

class FizzBuzzHandler( Handler ):
  def get( self ):
    n = self.request.get("n", 0)
    n = n and int( n )
    self.render( "fizzbuzz.html", n = n )

app = webapp2.WSGIApplication([
    ( '/', MainHandler ), 
    ( '/fizzbuzz', FizzBuzzHandler ),
    ( '/signup', SignUpHandler ),
    ( '/welcome', WelcomeHandler ),
    # ( '/login', LoginHandler ),
    # ( '/logout', LogoutHandler ),
    ( '/blog', BlogHandler ),
    ( '/blog/(\d+)', BlogHandler ),
    ( '/blog/newpost', NewPostHandler )
], debug=True)
