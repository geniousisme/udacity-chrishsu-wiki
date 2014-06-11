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

# form_html = """
#               <form>
#                 <h2>Add a Food</h2>
#                 <input type="text" name="food">
#                 %s
#                 <button>Add</button>
#               </form>
#             """
# hidden_html = """
#                 <input type="hidden" name="food" value="%s">
#               """
# shopping_html = """
#                 <br>
#                 <br>
#                 <h2>Shopping List</h2>
#                 <ul>
#                 %s
#                 </ul>
#                 """
# item_html = "<li>%s</li>"

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

class MainHandler( Handler ):
    def render_ascii(self, title = "", art = "", error = ""):
      arts = db.GqlQuery("select * from Art order by created desc")
      self.render( "ascii.html", title = title, art = art, error = error, arts = arts)

    def get(self):
      self.render_ascii()
      # self.render("shopping_list.html")
      # test = self.request.get("test")
      #   if test:
      #   test = int( test )
      # self.render("shopping_list.html", name = self.request.get("name"))
      # self.render("shopping_list.html", test = test )
      # output = form_html
      # output_hidden = ""
      
      # items = self.request.get_all("food")
      # self.render("shopping_list.html", items = items)
      # if items:
      #   output_items = ""
      #   for item in items:
      #     output_hidden += hidden_html % item
      #     output_items += item_html % item
          
      #   output_shopping = shopping_html % output_items
      #   output += output_shopping

      # output = output % output_hidden

      # self.write( output )
    def post(self):
      title = self.request.get("title")
      art   = self.request.get("art")

      if title and art:
        # self.write("thx for your art !!")
        # self.render_ascii( title = title, art = art )
        new_art = Art( title = title, art = art )
        new_art.put()

        self.redirect("/")
      else:
        error = "We need both a title and some artwork!!!"
        self.render_ascii( title, art , error )
        # self.render("ascii.html", error = error)

class FizzBuzzHandler( Handler ):
  def get( self ):
    n = self.request.get("n", 0)
    n = n and int( n )
    self.render( "fizzbuzz.html", n = n )

app = webapp2.WSGIApplication([
    ('/', MainHandler), ( '/fizzbuzz', FizzBuzzHandler )
], debug=True)
