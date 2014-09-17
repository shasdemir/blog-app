__author__ = 'sukruhasdemir'


#
# WARNING: Note to self: DO NOT use this in anything important. The sole purpose of this module is for me to learn about
#  User Accounts and Security in Udacity's Web Dev course. For real projects with real users, use real security
# libraries written by experts.
#


import hashlib
import hmac
import random
import string
# from operator import _compare_digest as compare_digest # DOESNT WORK ON GAE

# cookie hashing -------------------
SECRET = 'allocation, fx, its, imode, smode = opt.fmin_slsqp(func=budget_objective, x0=initial_point,'  # random stuff


def hash_str(s):
    return hmac.new(SECRET, s, digestmod=hashlib.sha512).hexdigest()


def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val): # unsafe!
        return val


# password security -------------------
def make_salt():
    text = string.ascii_letters
    crypter = random.SystemRandom('udacity')
    return "".join([crypter.choice(text) for k in range(128)])


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha512(name + pw + salt).hexdigest()
    return '%s|%s' % (h, salt)


def valid_pw(name, pw, h):
    salt = h.split('|')[-1]
    return h == make_pw_hash(name, pw, salt)