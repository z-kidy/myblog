import os
import re
from string import letters
import random
import webapp2
import jinja2
import time
from google.appengine.ext import db
import hashlib
import hmac


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

SECRET = "zkidy" 

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def hash_str(s):
    return hmac.new(SECRET,s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s,hash_str(s))

def check_secure_val(h):
    val = h.split("|")[0]
    if h == make_secure_val(val) :
        return val

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

class BaseHandler(webapp2.RequestHandler):
    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))
        
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))
    
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)
        #return check_secure_val(cookie_val) and cookie_val 
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

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
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()
    def done(self, *a, **kw):
        raise NotImplementedError

class Unit2Signup(Signup):
    def done(self):
        self.redirect('/unit2/welcome?username=' + self.username )

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

class Login(BaseHandler):
    def get(self):
        self.render("login-form.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BaseHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')

class Welcome(BaseHandler):
    def get(self):
        username = self.request.cookies.get('user_id')
        username = username.split('|')[0]

        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/unit2/signup')

class Unit3Welcome(BaseHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email    = db.StringProperty()
    
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)
    
    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(name = name,
                    pw_hash = pw_hash,
                    email = email)
    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u 

class Art(db.Model):
    title   = db.StringProperty(required = True)
    art     = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class Article(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

class Unit3art(BaseHandler):
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

class PostPage(BaseHandler):
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
                                ('/unit2/Unit2Signup', Unit2Signup),
                                ('/unit2/welcome', Welcome),
                                ('/unit3/art',Unit3art),
                                ('/blog',Blog),
                                ('/blog/(\d+)',PostPage),
                                ('/blog/newpost',Newpost),
                                ('/signup',Register),
                                ('/login',Login),
                                ('/logout',Logout),
                                ('/unit3/welcome', Unit3Welcome),
                                ('/login',Login)
                                ],

                              debug=True)
