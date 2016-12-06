from google.appengine.ext import ndb

# Creating a model for user database.
class User(ndb.Model):
    username = ndb.StringProperty(required=True)
    pwd_hash = ndb.StringProperty(required=True)
    email = ndb.StringProperty()
    # each user entity will also have a list of keys
    # of different posts published by them
    blog_posts = ndb.KeyProperty(repeated=True)
    liked_posts = ndb.KeyProperty(repeated=True)


# Each blogpost is stored in a different database
class Blogpost(ndb.Model):
    title = ndb.TextProperty(required=True)
    writer = ndb.KeyProperty(required=True)
    content = ndb.TextProperty(required=True)
    date_of_creation = ndb.DateTimeProperty(auto_now_add=True)
    upvotes = ndb.IntegerProperty(required=True, default=0)
    comments = ndb.KeyProperty(repeated=True)


# Each individual comment is also kept separately in a new database
class Comment(ndb.Model):
    blog_post = ndb.KeyProperty(required=True, kind=Blogpost)
    commenter = ndb.KeyProperty(required=True, kind=User)
    text = ndb.StringProperty(required=True)
    creation_time = ndb.DateTimeProperty(auto_now_add=True)
