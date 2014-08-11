import os
import re
from string import letters

import webapp2
import jinja2
import time
from google.appengine.ext import db
import hashlib
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def hash_str(s):
    return hashlib.md5(s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s,hash_str(s))

def check_secure_val(h):
    val = h.split("|")[0]
    if h == make_secure_val(val) :
        return val

class BaseHandler(webapp2.RequestHandler):
    def render(self, template, **kw):
        self.response.out.write(render_str(template, **kw))

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

class FirstPage(BaseHandler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        visits = 0 
        visit_cookie_str = self.request.cookies.get('visits')
        if visit_cookie_str:
            cookie_val = check_secure_val(visit_cookie_str)
            if cookie_val:
                visits = int(cookie_val)            
        visits += 1

        new_cookie_val = make_secure_val(str(visits))        
        self.response.headers.add_header('Set-Cookie','visits=%s' % new_cookie_val )

        self.write("You've been here %s times!" % visits)

class Rot13(BaseHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text = rot13)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BaseHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = username,
                      email = email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.redirect('/unit2/welcome?username=' + username)

class Welcome(BaseHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/unit2/signup')

class Art(db.Model):
    title   = db.StringProperty(required = True)
    art     = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class MainPage(BaseHandler):
    def render_front(self,title='',art='',error=''):
        arts = db.GqlQuery("SELECT * FROM Art ORDER BY created DESC")
        self.render("art.html",title=title,art = art ,error = error,arts = arts)

    def get(self):
        self.render_front()
    
    def post(self):
        title = self.request.get("title")
        art   = self.request.get("art")

        if title and art:
            a = Art(title = title , art = art )
            a.put()
            time.sleep(1)
            self.redirect('/unit3/art')
        else:
            error = "We need both title and art "
            self.render_front("art.html",error = error,title= title,art = art)

class Article(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    
class Blog(BaseHandler):
    def get(self):
        articles = db.GqlQuery("SELECT * FROM Article ORDER BY created DESC")
        self.render("blog.html",articles = articles)

class Newpost(BaseHandler):
    def render_front(self,subject='',content='',error=''):
        
        self.render("newpost.html",subject=subject,content = content ,error = error)

    def get(self):
        self.render_front()

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content : 
            a = Article(subject = subject , content = content)
            a.put()
            x = a.key().id()
            time.sleep(1)
            self.redirect('/blog/%d' % x)

        else:
            error = "We need both subject and article "
            self.render_front("newpost.html",error = error,subject= subject,content = content)

class Newarticle(BaseHandler):
    def get(self,post_id):
        p = Article.get_by_id( int(post_id) )

        if not p:
            self.error(404)
            return 

        self.render("newarticle.html",article = p )
    #def render_front(self,subject='',content=''):      
     #   self.render("newarticle.html",subject='subject',content = 'content' )
        

app = webapp2.WSGIApplication([ ('/',FirstPage),
                                ('/unit2/rot13', Rot13),
                                ('/unit2/signup', Signup),
                                ('/unit2/welcome', Welcome),
                                ('/unit3/art',MainPage),
                                ('/blog',Blog),
                                ('/blog/(\d+)',Newarticle),
                                ('/blog/newpost',Newpost)],
                              debug=True)
