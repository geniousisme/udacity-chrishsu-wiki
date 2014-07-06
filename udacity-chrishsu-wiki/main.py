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
import sys
import os
import re
import logging
import time

from time import gmtime, strftime

# from google.appengine.ext import db
from google.appengine.api import memcache

sys.path.extend( [ 
                   os.path.join(os.path.dirname(__file__), 'lib'),
                   os.path.join(os.path.dirname(__file__), 'lib/DB'),
                   os.path.join(os.path.dirname(__file__), 'util') 
                  ] )
###### some modules ######
import secure_helpers
import valid_helpers
import auth_helpers

####### datastore ########
from User import User
from Wiki import Wiki

template_dir = os.path.join( os.path.dirname(__file__), "template" )
jinja_env = jinja2.Environment( loader = jinja2.FileSystemLoader( template_dir ), autoescape = True )


class Handler(webapp2.RequestHandler):
  def write(self, *a, **kw):
      self.response.out.write(*a, **kw)

  def render_str(self, template, **params):
      params['user'] = self.user
      t = jinja_env.get_template(template)
      return t.render(params)

  def render(self, template, **kw):
      self.write(self.render_str(template, **kw))

  def set_secure_cookie(self, name, val):
      cookie_val = secure_helpers.make_secure_val(val)
      self.response.headers.add_header(
          'Set-Cookie',
          '%s=%s; Path=/' % (name, cookie_val))

  def read_secure_cookie(self, name):
      cookie_val = self.request.cookies.get(name)
      return cookie_val and secure_helpers.check_secure_val(cookie_val)

  def login(self, user):
      self.set_secure_cookie('user_id', str(user.key().id()))

  def logout(self):
      self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

  def initialize(self, *a, **kw):
      webapp2.RequestHandler.initialize( self, *a, **kw )
      uid = self.read_secure_cookie('user_id')
      self.user = uid and User.by_id(int(uid))

class MainHandler(Handler):
  def get(self):
      self.render("wiki.html")

class Signup(Handler):
  def get(self):
      self.render("signup.html")

  def post(self):
      have_error = False
      self.username = self.request.get('username')
      self.password = self.request.get('password')
      self.verify = self.request.get('verify')
      self.email = self.request.get('email')

      params = dict(username = self.username,
                    email = self.email)

      if not valid_helpers.valid_username(self.username):
          params['error_username'] = "That's not a valid username."
          have_error = True

      if not valid_helpers.valid_password(self.password):
          params['error_password'] = "That wasn't a valid password."
          have_error = True
      elif self.password != self.verify:
          params['error_verify'] = "Your passwords didn't match."
          have_error = True

      if not valid_helpers.valid_email(self.email):
          params['error_email'] = "That's not a valid email."
          have_error = True

      if have_error:
          self.render('signup.html', **params)
      else:
          self.done()

  def done(self):
      raise NotImplementedError("Subclass must implement abstract method")

class Register(Signup):
  def done(self):
      u = User.by_name(self.username)
      if u:
        msg = 'That user already exists.'
        self.render('signup.html', error_username = msg)
      else:
        u = User.register(self.username, self.password, self.email)
        u.put()

        self.login(u)
        self.redirect('/')

class Login(Handler):
  def get(self):
      self.render('login.html')

  def post(self):
      username = self.request.get('username')
      password = self.request.get('password')

      u = User.login(username, password)
      if u:
        self.login(u)
        self.redirect('/')
      else:
        msg = 'Invalid login'
        self.render('login.html', error = msg)

class Logout(Handler):
  def get(self):
      self.logout()
      self.redirect('/')

class WikiPage(Handler):
  def get(self, wiki_subject=""):
      logging.error( "########################" + wiki_subject)
      logging.error( "!!!!!!!!!!!!!!!!!!!" + str(Wiki.all().order('-created').get().content ) )
      self.response.out.write(wiki_subject)
      wiki = Wiki.last(wiki_subject)
      if wiki:
        self.render("wiki.html", content=wiki.content)
      else:
        logging.error( "######################## not existed" )
        self.redirect("/_edit" + wiki_subject) 

class EditPage(Handler):
  def wiki_subject(self, url):
      subject = url.replace('/_edit/','')
      return subject if subject != '' else ' '

  def get(self, wiki_subject=""):
      self.response.out.write( os.environ['PATH_INFO'] )
      wiki = Wiki.last( wiki_subject )
      if wiki:
        self.render( "wiki_edit.html", subject=self.wiki_subject( os.environ['PATH_INFO'] ), content=wiki.content )
      else:
        self.render( "wiki_edit.html", subject="", content="" )

  def post(self, wiki_subject=""):
      logging.error( "########################" + wiki_subject )
      subject = wiki_subject
      # subject = self.request.get('subject')
      content = self.request.get('content')

      new_wiki = Wiki.create( subject, content )
      new_wiki.put()
      logging.error( "########################" + subject )
      self.redirect( subject )
##### url mapping #####
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([
    ('/login', Login),
    ('/logout', Logout),
    ('/signup', Register),
    ('/_edit' + PAGE_RE, EditPage),
    (PAGE_RE, WikiPage),  
], debug=True)
