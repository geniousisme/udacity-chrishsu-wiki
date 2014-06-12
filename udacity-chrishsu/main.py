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

class Blog( db.Model ):
  subject = db.StringProperty( required = True )
  content = db.TextProperty( required = True )
  created = db.DateTimeProperty( auto_now_add = True )

class MainHandler( Handler ):
  def render_ascii(self, title = "", art = "", error = ""):
    arts = db.GqlQuery("select * from Art order by created desc")
    self.render( "ascii.html", title = title, art = art, error = error, arts = arts, ids = ids )

  def get(self):
    self.render_ascii()
   
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
    content = self.request.get("content")

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
