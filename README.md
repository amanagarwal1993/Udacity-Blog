# Udacious Blog
A multi-user blog application which has the following features:
1. User signup/login
2. Passwords and cookies are encrypted
3. User can't screw around with each other's data (i.e security)
4. Users can create blog articles and post them on the website

## Usage

##### How the project is organized
The app uses **google app engine** in python for its backend, along with an html template called **jinja2**.
There are two kinds of files here: first is the `app.py` file that has all the backend python code. All the other files are html templates for different pages of the front-end.

##### Backend
The backend code is all in the `app.py` file. It uses the `webapp2` library for defining its request handlers. Backend database is the Google Cloud Datastore, using the `ndb` library.
There are individual request handlers are:
1. Main (for the main page)
2. Signup
3. Login
4. Welcome
5. Logout
6. EditPost
7. DeletePost
8. AddComment (also used for like and dislike features)

In the datastore I have 3 different models:
1. User database
2. Blogpost database
3. Comments database

However, all 3 are connected: each user has a list of blogpost (stored in form of keys) that it has authored as well as the blogposts that it has 'liked'. Each blogpost has an author (key), and a list of comment keys. Each comment has an author (user key) and the blogpost it was for.

**User Security**
I use the sha256 hashing algorithm to encrypt passwords etc. There are a bunch of global  functions in the code (declared before all the handlers), which take care of encryption, cookie operations and checking user inputs.

## License
[GNU General Public License](http://choosealicense.com/licenses/gpl-3.0/)