#!/usr/bin/env python

# todo: make each title a link to the post's permalink page (DONE)
# todo: convert DB requests from GQL to procedure calls for performance reasons

# did: removed a bunch of debugging code
# did: Permalink pages have smart caching. Now, no DB read is supposed to happen when a new post is submitted
# did: secret used in cookie hashing is no longer in the repo.
# todo: After a new post, main page reads from DB once to fill the memcache. This is avoidable with smarter caching. (FIXED)
# todo: multiple signups with the same user name has to be prevented (DONE)
# todo: cookie-checking the signed-in user when posting (DONE)
# todo: and changing top bar according to login status (DONE)
# todo: each post has to have a user that posted it (DONE)


import webapp2
import jinja2
import os
import re
import security_core
import json
import time
import logging
from google.appengine.api import memcache
from google.appengine.ext import db


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir), autoescape=True)

log_db = False  # print the DB actions as warnings. Ignores DB reads for the JSON API.


class BlogPost(db.Model):
    title = db.StringProperty(required=True)
    text = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    poster_name = db.StringProperty(required=False)

    def to_json(self):  # returns a json string that includes the content and subject of the post
        return json.dumps({"content": self.text, "subject": self.title})

    @staticmethod
    def from_list_to_json(self, post_list):  # given a list of BlogPost objects, returns json string of the list
        return json.dumps([{"content": post.text, "subject": post.title} for post in post_list])


class BlogUser(db.Model):
    user_name = db.StringProperty(required=True)
    password_hash = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class Handler(webapp2.RequestHandler):
    def write(self, *args, **kwargs):
        self.response.write(*args, **kwargs)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, logged_user=self.is_user_authentic(), **kw))

    def is_user_authentic(self):
        user_name_hash = self.request.cookies.get('username')
        return security_core.check_secure_val(user_name_hash) if user_name_hash else None

    def get_all_posts(self):
        key = 'post_list'
        client = memcache.Client()
        all_posts = client.get(key)

        if all_posts is None:
            all_posts = list(db.GqlQuery("SELECT * FROM BlogPost ORDER BY created DESC"))
            if log_db:
                logging.warning("DATABASE READ: All posts!")

            client.set(key, all_posts)

        return all_posts

    def update_all_posts_cache(self, update_with_post):  # update_with_post is a BlogPost to be appended to the posts cache.
        key = 'post_list'
        client = memcache.Client()

        for k in xrange(100):
            previous_posts = client.gets(key)
            if previous_posts is None:
                previous_posts = list(db.GqlQuery("SELECT * FROM BlogPost ORDER BY created DESC"))
                if log_db:
                    logging.warning("DATABASE READ: All posts!")

            # we don't append, because the posts must stay ordered as newest first
            all_posts = [update_with_post] + previous_posts

            if client.cas(key, all_posts):
                break

    def get_single_post(self, post_id):
        key = str(post_id)
        single_post = memcache.get(key)

        if single_post is None:
            single_post = BlogPost.get_by_id(post_id)
            if log_db:
                logging.warning("DATABASE READ: Single post!")

            memcache.set(key, single_post)
        return single_post

    def update_single_post_cache(self, new_post):
        try:
            key = str(new_post.key().id())
            memcache.set(key, new_post)
        except:
            logging.warning("Tried to update single post cache with id before saving to DB.")


class NewPostHandler(Handler):
    def render_new_post(self, post_title="", post_text="", error_text="", logged_in=False):
        self.render("newpost.html", post_title=post_title, post_text=post_text, error_text=error_text, logged_in=logged_in)

    def get(self):
        user_authentic = self.is_user_authentic()
        if user_authentic:
            self.render_new_post(logged_in=user_authentic)
        else:
            self.redirect('/login?redirect=True')

    def post(self):
        post_title = self.request.get("subject")
        post_text = self.request.get("content")

        user_authentic = self.is_user_authentic()

        if post_text and post_title and user_authentic:
            new_post = BlogPost(title=post_title, text=post_text.replace('\n', '<br>'), poster_name=user_authentic)

            new_post.put()
            if log_db:
                logging.warning("DATABASE WRITE")

            self.update_all_posts_cache(update_with_post=new_post)
            self.update_single_post_cache(new_post)

            self.redirect("/posts/%s" % str(new_post.key().id()))
        else:
            if not user_authentic:
                self.redirect('/login?redirect=True')

            error_text = "Both a title and text of the blog post are required."
            self.render_new_post(post_title=post_title, post_text=post_text, error_text=error_text)


class PermaLinkHandler(Handler):
    def render_permalink_page(self, post_data, logged_in=False, elapsed_time=0.001):
        self.render("permalink.html", post_data=post_data, logged_in=logged_in, elapsed_time=elapsed_time)

    def get(self, *args):
        if args[0][-5:] == ".json":
            post_id = int(args[0][:-5])
            post_data = BlogPost.get_by_id(post_id)

            self.response.headers.add("Content-Type", "application/json; charset=UTF-8")
            self.response.write(post_data.to_json())
        else:
            post_id = int(args[0])
            post_data = self.get_single_post(post_id=post_id)

            self.render_permalink_page(post_data, logged_in=self.is_user_authentic())  #, elapsed_time=elapsed)


class MainPageHandler(Handler):
    def get(self):
        all_posts = self.get_all_posts()
        #query_time = memcache.get('time_key')
        #elapsed = time.time() - query_time

        self.render("postlist.html", all_posts=all_posts, logged_in=self.is_user_authentic())  #, elapsed_time=elapsed)


class MainJSONHandler(Handler):
    def get(self, *args):
        all_posts = db.GqlQuery("SELECT * FROM BlogPost ORDER BY created DESC")
        all_posts = list(all_posts)

        all_json = BlogPost.from_list_to_json(BlogPost, all_posts)
        self.response.headers.add("Content-Type", "application/json; charset=UTF-8")
        self.response.write(json.dumps(all_json))


class SignupHandler(Handler):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    PASSWORD_RE = re.compile("^.{3,20}$")
    EMAIL_RE = re.compile("^[\S]+@[\S]+\.[\S]+$")

    def render_form(self, user_name="", user_name_error="",
                  password="", password_error="",
                  verify_password="", verify_error="",
                  email="", email_error=""):
        self.render("signup.html", user_name=user_name, user_name_error=user_name_error,
                    password=password, password_error=password_error,
                    verify_password=verify_password, verify_error=verify_error,
                    email=email, email_error=email_error)

    def get(self):
        self.render_form()

    def post(self):
        def validate_username(raw_uname):  # returns True if valid, False if not
            return self.USER_RE.match(raw_uname)

        def validate_password(raw_password):  # this is NOT re-type validation.
            return self.PASSWORD_RE.match(raw_password)

        def validate_email(raw_email):
            return not raw_email or self.EMAIL_RE.match(raw_email)

        def duplicate_username(raw_uname):
            matching_people = list(db.GqlQuery("SELECT * FROM BlogUser WHERE user_name = :user_name", user_name=raw_uname))
            if log_db:
                logging.warning("DATABASE READ: Users!")

            return len(matching_people) > 0

        e_username = self.request.get("username")
        e_password = self.request.get("password")
        e_verify = self.request.get("verify")
        e_email = self.request.get("email")

        inputs_valid = (validate_username(e_username) and
                        validate_password(e_password) and
                        validate_email(e_email) and
                        (not duplicate_username(e_username)) and
                        e_verify == e_password)

        if inputs_valid:
            e_username = e_username.encode('ascii', 'replace')

            this_user = BlogUser(user_name=e_username, password_hash=security_core.make_pw_hash(e_username, e_password))
            this_user.put()
            if log_db:
                logging.warning("DATABASE Write: Single user!")

            uname_hashed = security_core.make_secure_val(e_username)
            self.response.headers.add_header('Set-Cookie', 'username=%s; Path=/' % uname_hashed)
            self.redirect("/")  # HW CHANGE
            #self.redirect("/welcome")  # HW CHANGE
        else:
            username_error = ''
            password_error = ''
            verify_error = ''
            email_error = ''

            if not validate_username(e_username):
                username_error = "That's not a valid user name."

            if duplicate_username(e_username):
                username_error = "That user name already exists."

            if not validate_password(e_password):
                password_error = "That wasn't a valid password."

            if not validate_email(e_email):
                email_error = "That's not a valid e-mail."

            if not e_verify == e_password:
                verify_error = "Your passwords didn't match."

            self.render_form(user_name=e_username, email=e_email, user_name_error=username_error,
                             password_error=password_error, verify_error=verify_error, email_error=email_error)


class WelcomeHandler(Handler):
    def get(self):
        authorized = self.is_user_authentic()
        if authorized:
            self.response.write('Welcome, %s!' % authorized)
        else:
            self.response.write('Unauthorized user!')


class LoginHandler(Handler):
    def render_form(self, user_name="", password="", credentials_error=""):
        self.render("login.html", user_name=user_name, password=password, credentials_error=credentials_error)

    def get(self):
        will_redirect = self.request.get("redirect")
        if will_redirect == "True":
            self.response.headers.add_header('Set-Cookie', 'blogapp_redirect_to_new_post=True')
        self.render_form()

    def post(self):
        e_username = self.request.get("username")
        e_password = self.request.get("password")
        e_username = e_username.encode('ascii', 'replace')

        matching_people = list(db.GqlQuery("SELECT * FROM BlogUser WHERE user_name = :user_name", user_name=e_username))
        if log_db:
            logging.warning("DATABASE READ: Single user!")

        username_matches = False
        password_mathces = False
        if len(matching_people) > 0:
            username_matches = True
            person = matching_people[0]  # check the password
            if security_core.valid_pw(e_username, e_password, person.password_hash):
                password_mathces = True

        if username_matches and password_mathces:
            e_username = e_username.encode('ascii', 'replace')
            uname_hashed = security_core.make_secure_val(e_username)
            self.response.headers.add_header('Set-Cookie', 'username=%s; Path=/' % uname_hashed)

            newpost_redirect_cookie = self.request.cookies.get('blogapp_redirect_to_new_post')
            if newpost_redirect_cookie == "True":
                self.response.headers.add_header('Set-Cookie', 'blogapp_redirect_to_new_post=False')
                self.redirect("/newpost")
            else:
                self.redirect("/")  # HW CHANGE
                #self.redirect("/welcome")  # HW CHANGE
        else:
            self.render_form(user_name=e_username, credentials_error="User name or password is invalid.")


class LogoutHandler(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'username=%s; Path=/' % "")
        self.redirect('/')


class FlushHandler(Handler):
    def get(self):
        memcache.flush_all()
        self.redirect('/')


app = webapp2.WSGIApplication([
    ('/', MainPageHandler),
    ('/.json', MainJSONHandler),
    ('/newpost/?', NewPostHandler),
    (r'/posts/(\S+)', PermaLinkHandler),  # add /? support
    ('/signup/?', SignupHandler),
    ('/login/?', LoginHandler),
    ('/logout/?', LogoutHandler),
    ('/welcome/?', WelcomeHandler),
    ('/flush/?', FlushHandler)
], debug=True)