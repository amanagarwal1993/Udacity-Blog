import webapp2
import re
import random
import string
import hashlib
import os
import jinja2
import models
from google.appengine.ext import ndb

Blogpost = models.Blogpost
User = models.User
Comment = models.Comment

template_dir = os.path.dirname(os.path.abspath(__file__))
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


# Defining a handler for render functions
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render_stuff(self, template, **kw):
        self.write(self.render_str(template, **kw))


# Functions to help verify user input
user_re = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
pass_re = re.compile(r"^.{3,20}$")
email_re = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
title_re = re.compile(r"[\w\W\d\D]{1,100}")
text_re = re.compile(r".{1,10000}")


def valid_username(username):
    return (user_re.match(username) != None)


def valid_password(password):
    return (pass_re.match(password) != None)


def valid_email(email):
    if (email == ''):
        return True
    else:
        return (email_re.match(email) != None)


def valid_title(title):
    return (title_re.match(title) != None)


def valid_text(text):
    return (text_re.match(text) != None and len(text) <= 10000)


# Password and username hashing/verification functions
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    hashvalue = hashlib.sha256(name+pw+salt).hexdigest()
    return '%s|%s' % (hashvalue, salt)


def valid_pw(name, pw, h):
    salt = h.split('|')[1]
    return h == make_pw_hash(name, pw, salt)


def user_hash(username):
    hashstring = hashlib.sha256(username).hexdigest()
    return "%s|%s" % (username, hashstring)


def user_check(hashstring):
    hashlist = hashstring.split('|')
    return hashstring == user_hash(hashlist[0])


# Cookie operations
def get_cookie_val(self, name):
    val = self.request.cookies.get(name)
    return val


def still_logged_in(self):
    hashstring = get_cookie_val(self, 'user')
    if hashstring == None:
        return False
    if user_check(hashstring):
        username = (hashstring.split('|'))[0]
        q = ndb.gql('SELECT * FROM User WHERE username = :1', username)
        result = q.fetch(1)
        if result:
            return True
    return False


def current_user(self):
    hashstring = get_cookie_val(self, 'user')
    return (hashstring.split('|'))[0]


# HANDLERS

class Main(Handler):
    def get(self):
        if still_logged_in(self):
            self.redirect('/welcome')
        else:
            blogs = (Blogpost.query().order(-Blogpost.date_of_creation)).fetch(20)
            if blogs:
                self.render_stuff('main.html', blogs=blogs)
            else:
                self.redirect('/signup')


class Signup(Handler):
    def get(self):
        if not still_logged_in(self):
            self.render_stuff('signup.html')
        else:
            self.response.write('You are already logged in!')

    def post(self):
        self.response.headers['Content-Type'] = 'text/plain'
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        username_error = ''
        password_error = ''
        verify_password_error = ''
        email_error = ''

        if (valid_username(username) and valid_password(password) and
        valid_email(email) and (verify == password)):

            q = ndb.gql('SELECT * FROM User WHERE username = :1', username)
            results = q.fetch(1)
            if results:
                self.render_stuff('signup.html', username="",
                                  email="", ue="", pe="",
                                  ve="", ee="",
                                  error="Username already exists!")
            else:
                if not email == "":
                    new_user = User(username=username,
                                    pwd_hash=make_pw_hash(username, password),
                                    email=email)
                else:
                    new_user = User(username=username,
                                    pwd_hash=make_pw_hash(username, password))
                new_user.put()
                
                # Store user value securely
                cookie = str(user_hash(username))
                self.response.headers.add_header('Set-Cookie',
                                                 'user=%s; Path=/' % cookie)
                self.redirect("/welcome")

        else:
            if (valid_username(username) == False):
                username_error = ("Not a valid username! "
                                  '''It should be alphanumeric with at 
                                  least 3 characters.''')

            if (valid_password(password) == False):
                password_error = "Sorry, that's not a valid password."

            if (valid_email(email) == False):
                email_error = 'Not a valid email address!'

            if (verify != password):
                verify_password_error = "Your passwords don't match."

            self.render_stuff('index.html', username=username,
                              email=email,
                              ue=username_error,
                              pe=password_error,
                              ve=verify_password_error,
                              ee=email_error)


class Login(Handler):
    def get(self):
        if still_logged_in(self):
            self.response.write('You are already logged in! Go back. :)')
        else:
            self.render_stuff('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        if (valid_username(username) and valid_password(password)):

            q = ndb.gql('SELECT * FROM User WHERE username = :1', username)
            result = q.fetch(1)
            if result:
                if valid_pw(username, password, result[0].pwd_hash):
                    cookie = str(user_hash(username))
                    self.response.headers.add_header('Set-Cookie',
                        'user=%s; Path=/' % cookie)
                    self.redirect("/welcome")
                else:
                    self.render_stuff('login.html', error='Wrong password')
                    
            else:
                self.render_stuff('login.html', error='User not found')

class Welcome(Handler):
    def get(self):
        if still_logged_in(self):
            blogs = (Blogpost.query().order(-Blogpost.date_of_creation)).fetch(10)
            self.render_stuff('welcome.html',
                              username=current_user(self),
                              style='none', blogs=blogs)
        else:
            self.redirect('/login')

    def post(self):
        if still_logged_in(self):
            
            if self.request.get('publish') == 'Publish':
                title = self.request.get('title')
                text = self.request.get('content')

                # find user's name and key by fetching from database
                user = current_user(self)
                user_entity = (User.query(User.username == user).fetch())[0]
                user_key = user_entity.key

                if valid_title(title) and valid_text(text):
                    post = Blogpost(title=title, content=text, writer=user_key)
                    post_key = post.put()

                    user_entity.blog_posts.append(post_key)
                    user_key = user_entity.put()

                    self.redirect('/welcome')

                else:
                    if valid_title(title):
                        error = "Dude your text seems to be invalid..."
                    if valid_text(text):
                        error = "Dude, your title seems invalid"
                    self.render_stuff('welcome.html',
                                      username=user, title=title,
                                      content=text, pe=error,
                                      style='block')
            
            # Checking if the comment writer is same as logged user
            else: 
                if self.request.get('comment_writer') == current_user(self):
                    # Now we do comment editing operations
                    if self.request.get('cancel') == 'cancel':
                        self.redirect(url)

                    elif self.request.get('save') == 'save':
                        new_text = self.request.get('new_text')
                        comment_id = self.request.get('edited_comment_id')
                        comment = Comment.get_by_id(int(comment_id))
                        comment.text = new_text
                        comment.put()
                        self.redirect(url)

                    elif self.request.get('delete') == 'delete':
                        comment_id = self.request.get('edited_comment_id')
                        comment_key = Comment.get_by_id(int(comment_id)).key

                        blogpost.comments.remove(comment_key)
                        comment_key.delete()
                        blogpost.put()
                        self.redirect(url)
                else:
                    self.response.write('''You are not authorized 
                                        to edit this comment. 
                                        Click <a href=' + url + '>here</a> 
                                        to go back.''')
        else:
            self.redirect('/login')


class Logout(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user=; Path=/')
        self.redirect('/login')


class EditPost(Handler):
    def get(self, post_id):
        blogpost = Blogpost.get_by_id(int(post_id))
        if still_logged_in(self) and current_user(self) == blogpost.writer.get().username:
            self.render_stuff('blogpost_edit.html',
                              post_id=post_id, blogpost=blogpost, 
                              title=blogpost.title,
                              content=blogpost.content,
                              upvotes=blogpost.upvotes,
                              user=blogpost.writer.get().username)
        else:
            self.response.write('''You are either offline or you are not 
                                authorized to edit this post. 
                                Please go back and try again.''')

    def post(self, post_id):
        if still_logged_in(self) and current_user(self) == blogpost.writer.get().username:
            save = self.request.get('save')
            cancel = self.request.get('cancel')
            url = '/' + str(post_id)

            if cancel == 'cancel':
                self.redirect(url)

            elif save == 'save':
                new_title = self.request.get('title')
                new_text = self.request.get('content')

                blogpost = Blogpost.get_by_id(int(post_id))
                blogpost.title = new_title
                blogpost.content = new_text
                blogpost.put()
                self.redirect(url)


class DeletePost(Handler):
    def get(self, post_id):
        blogpost = Blogpost.get_by_id(int(post_id))
        if still_logged_in(self) and current_user(self) == blogpost.writer.get().username:
            blogpost = Blogpost.get_by_id(int(post_id))
            self.render_stuff('blogpost_delete.html',
                              post_id=post_id, blogpost=blogpost,
                              title=blogpost.title,
                              post_content=blogpost.content,
                              upvotes=blogpost.upvotes,
                              user=blogpost.writer.get().username)
        else:
            self.response.write('''You are either offline or you are not 
                                authorized to delete this post. 
                                Please go back and try again.''')

    def post(self, post_id):
        if still_logged_in(self) and current_user(self) == blogpost.writer.get().username:
            user = current_user(self)
            user_entity = (User.query(User.username == user).fetch())[0]
            user_key = user_entity.key
            post_key = Blogpost.get_by_id(int(post_id)).key

            user_entity.blog_posts.remove(post_key)
            post_key.delete()
            user_key = user_entity.put()
            self.redirect('/welcome')
        else:
            self.redirect('/login')


class AddComment(Handler):
    def get(self, post_id):
        if still_logged_in(self):
            user = current_user(self)
            if not valid_username(user) or user == 'None':
                self.redirect('/login')
            else:
                blogpost = Blogpost.get_by_id(int(post_id))

                user_entity = (User.query(User.username == user).fetch())[0]
                user_key = user_entity.key
                blogpost = Blogpost.get_by_id(int(post_id))

                # check if post is already liked
                if (blogpost.key in user_entity.liked_posts) and not (current_user(self) == blogpost.writer.get().username):
                    self.render_stuff('blogpost_addcomment.html',
                                      blogpost=blogpost,
                                      title=blogpost.title,
                                      post_content=blogpost.content,
                                      upvotes=blogpost.upvotes,
                                      user=blogpost.writer.get().username,
                                      vote_direction='Unlike',
                                      votedir='dislike')
                else:
                    self.render_stuff('blogpost_addcomment.html',
                                      blogpost=blogpost,
                                      title=blogpost.title,
                                      post_content=blogpost.content,
                                      upvotes=blogpost.upvotes,
                                      user=blogpost.writer.get().username,
                                      votedir='like',
                                      vote_direction='Like')
        else:
            self.redirect('/login')

    def post(self, post_id):
        if still_logged_in(self):

            user = current_user(self)
            user_entity = (User.query(User.username == user).fetch())[0]
            user_key = user_entity.key
            blogpost = Blogpost.get_by_id(int(post_id))
            url = '/' + str(post_id)

            # check for button pressed
            if self.request.get('like') == 'like':
                if not (current_user(self) == blogpost.writer.get().username):
                    blogpost.upvotes = blogpost.upvotes + 1
                    user_entity.liked_posts.append(blogpost.key)
                    user_key = user_entity.put()
                    blogpost.key = blogpost.put()
                    self.redirect(url)
                else:
                    self.response.write('You cannot like your own post.')

            elif self.request.get('dislike') == 'like':
                if not (current_user(self) == blogpost.writer.get().username):
                    blogpost.upvotes -= 1
                    user_entity.liked_posts.remove(blogpost.key)
                    user_key = user_entity.put()
                    blogpost.key = blogpost.put()
                    self.redirect(url)
                else:
                    self.response.write('You cannot dislike your own post.')

            elif self.request.get('newcomment') == 'newcomment':
                comment_text = self.request.get('comment')

                comment = Comment(blog_post=blogpost.key,
                                  commenter=user_key,
                                  text=comment_text)
                comment_key = comment.put()

                blogpost.comments.append(comment_key)
                blogpost.put()
                self.redirect(url)
            
            # Checking if the comment writer is same as logged user
            if self.request.get('comment_writer') == current_user(self):
                # Now we do comment editing operations
                if self.request.get('cancel') == 'cancel':
                    self.redirect(url)

                elif self.request.get('save') == 'save':
                    new_text = self.request.get('new_text')
                    comment_id = self.request.get('edited_comment_id')
                    comment = Comment.get_by_id(int(comment_id))
                    comment.text = new_text
                    comment.put()
                    self.redirect(url)

                elif self.request.get('delete') == 'delete':
                    comment_id = self.request.get('edited_comment_id')
                    comment_key = Comment.get_by_id(int(comment_id)).key

                    blogpost.comments.remove(comment_key)
                    comment_key.delete()
                    blogpost.put()
                    self.redirect(url)
            else:
                self.response.write('''You are not authorized for this. 
                                    Click <a href=' + url + '>here</a> 
                                    to go back.''')
        else:
            self.redirect('/login')


app = webapp2.WSGIApplication(
    [
        ('/', Main),
        ('/signup', Signup),
        ('/welcome', Welcome),
        ('/login', Login),
        ('/logout', Logout),
        (r'/(\d+)/edit', EditPost),
        (r'/(\d+)/delete', DeletePost),
        (r'/(\d+)', AddComment)
    ], debug=True
)
