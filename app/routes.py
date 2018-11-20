from app import app, db, bcrypt, api, admin
from flask import jsonify, request, make_response
from flask_admin.contrib.sqla import ModelView
from flask_restful import Resource
from app.models import User, Donor, Address, Beneficiary, Listings, Orders, Reviews
from functools import wraps
from flask import g
import jwt
import datetime

admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(Donor, db.session))
admin.add_view(ModelView(Address, db.session))
admin.add_view(ModelView(Beneficiary, db.session))
admin.add_view(ModelView(Listings, db.session))
admin.add_view(ModelView(Orders, db.session))
admin.add_view(ModelView(Reviews, db.session))


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if auth and auth.username == 'username' and auth.password == 'passwor':
            return f(*args, **kwargs)

        return make_response('Could not verify your login!', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

    return decorated


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return {'message': 'Token is missing!'}, 403

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = Beneficiary.query.filter_by(username=data['username']).first()
        except:
            return {'message': 'Token is invalid!'}, 403

        return f(*args, **kwargs)

    return decorated


@app.route('/', methods=['GET'])
def home():
    return jsonify({'message': 'Welcome to the api'})

#
# @app.route('/login', methods=['GET'])
# @login_required
# def login():
#     auth = request.authorization
#     token = jwt.encode({'user': auth.get('name'), 'exp': datetime.datetime.utcnow()+datetime.timedelta(minutes=20)}, app.config['SECRET_KEY'])
#     return jsonify({'message': 'you are logged in', 'token': token.decode('UTF-8')})


@app.route('/createuser', methods=['POST'])
def create():
    user = request.json
    print(user)
    u = User(name=user.get('name'), info=user.get('info'))
    db.session.add(u)
    db.session.commit()
    return jsonify({'message': 'user added to database'})


@app.route('/users', methods=['GET'])
# @token_required
def users():
    users = User.query.all()
    users_list = []
    for user in users:
        d = {'name': user.name, 'info': user.info, 'id': user.id}
        users_list.append(d)
    return jsonify({'users': users_list})


def username_in_database_donor(username):
    username = Donor.query.filter_by(username=username).first()
    return username


def username_in_database_beneficiary(username):
    username = Beneficiary.query.filter_by(username=username).first()
    return username


@app.route('/donor', methods=['POST'])
def createdonor():
    donor = request.json
    if not donor:
        return "not json"
    print(donor)
    password_hash = bcrypt.generate_password_hash(donor.get('password')).decode('utf-8')
    username = donor.get('email').split('@')[0]
    check_username = username_in_database_donor(username)
    if check_username:
        while check_username:
            username = username+'1'
            check_username = username_in_database_donor(username)
    print(username)
    u = Donor(name=donor.get('name'), email=donor.get('email'), phone_no=donor.get('phone_no'), username=username,
              password_hash=password_hash)
    if donor.get('address'):
        address = Address(donor=u, city=donor.get('city'), street=donor.get('street'), country=donor.get('country'))
        db.session.add(address)
    db.session.add(u)
    db.session.commit()
    return jsonify({'message': 'donor added to database'})


@app.route('/donors', methods=['GET'])
def donors():
    donors = Donor.query.all()
    donor_list = []
    for donor in donors:
        address = Address.query.filter_by(donor=donor).first()
        print(address)
        if address:
            d = {'name': donor.name, 'password_hash': donor.password_hash, 'id': donor.id, 'phone_no': donor.phone_no,
                 'email': donor.email, 'username': donor.username, 'city': address.city, 'country': address.country,
                 'street': address.street}
        else:
            d = {'name': donor.name, 'password_hash': donor.password_hash, 'id': donor.id, 'phone_no': donor.phone_no,
                 'email': donor.email, 'username': donor.username}
        donor_list.append(d)
    return jsonify({'donors': donor_list})


@app.route('/beneficiaries', methods=['GET'])
def beneficiaries():
    beneficiaries = Beneficiary.query.all()
    beneficiaries_list = []
    for beneficiary in beneficiaries:
        address = Address.query.filter_by(beneficiary=beneficiary).first()
        print(address)
        if address:
            d = {'name': beneficiary.name, 'password_hash': beneficiary.password_hash, 'id': beneficiary.id, 'phone_no': beneficiary.phone_no,
                 'email': beneficiary.email, 'username': beneficiary.username, 'city': address.city, 'country': address.country,
                 'street': address.street}
        else:
            d = {'name': beneficiary.name, 'password_hash': beneficiary.password_hash, 'id': beneficiary.id, 'phone_no': beneficiary.phone_no,
                 'email': beneficiary.email, 'username': beneficiary.username}
        beneficiaries_list.append(d)
    return jsonify({'beneficiaries': beneficiaries_list})


@app.route('/beneficiary', methods=['POST'])
def createbeneficiary():
    beneficiary = request.json
    if not beneficiary:
        return "not json"
    print(beneficiary)
    password_hash = bcrypt.generate_password_hash(beneficiary.get('password')).decode('utf-8')
    username = beneficiary.get('email').split('@')[0]
    check_username = username_in_database_beneficiary(username)
    if check_username:
        while check_username:
            username = username+'1'
            check_username = username_in_database_beneficiary(username)
    print(username)
    u = Beneficiary(name=beneficiary.get('name'), email=beneficiary.get('email'), phone_no=beneficiary.get('phone_no'), username=username,
              password_hash=password_hash, type=1)
    if beneficiary.get('address'):
        address = Address(beneficiary=u, city=beneficiary.get('city'), street=beneficiary.get('street'), country=beneficiary.get('country'))
        db.session.add(address)
    db.session.add(u)
    db.session.commit()
    return jsonify({'message': 'beneficiary added to database'})


class Login(Resource):
    def get(self):
        return {"hi": "testing"}

    def post(self):
        user_data = request.json
        if not user_data:
            return {"not": "json"}
        if user_data.get('type') == 'beneficiary':
            user = Beneficiary.query.filter_by(email=user_data.get('email')).first()
        else:
            user = Donor.query.filter_by(email=user_data.get('email')).first()
        if user and bcrypt.check_password_hash(user.password_hash, user_data.get('password')):
            token = jwt.encode(
                {'username': user.username, 'name': user.name, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=20)},
                app.config['SECRET_KEY'])
            return {'token': token.decode('UTF-8')}
        else:
            return None


class Listing(Resource):
    def get(self):
        listings = Listings.query.all()
        listing_list = []
        for listing in listings:
            l = {"listing_id": listing.id, "quantity": listing.quantity, "expiry": listing.expiry}
            listing_list.append(l)
        return {"listing": listing_list}
    #
    # quantity = db.Column(db.Integer)
    # expiry = db.Column(db.String(20))
    # description = db.Column(db.String(250))
    # type = db.Column(db.String(10))
    # image = db.Column(db.String(100))

    @token_required
    def post(self):
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        listing = request.json
        if not listing:
            return {"not": "json"}
        print(token_data.get('username'))
        donor = Donor.query.filter_by(username=token_data.get('username')).first()
        print(listing)
        # print(donor.username, "xxx")
        l = Listings(quantity=listing.get('quantity'), expiry=listing.get('expiry'),
                    description=listing.get('description'), type=listing.get('type'),
                    image=listing.get('image'), donor=donor)
        db.session.add(l)
        db.session.commit()
        return {"listing": "added"}


class Order(Resource):
    def get(self):
        orders = Orders.query.all()
        order_list = []
        for order in orders:
            l = {"donor": order.donor, "beneficiary": order.beneficiary}
            order_list.append(l)
        return {"orders": order_list}
    #
    # quantity = db.Column(db.Integer)
    # expiry = db.Column(db.String(20))
    # description = db.Column(db.String(250))
    # type = db.Column(db.String(10))
    # image = db.Column(db.String(100))

    @token_required
    def post(self):
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        order = request.json
        if not order:
            return {"not": "json"}
        donor = Donor.query.get(order.get('donor_id'))
        beneficiary = Beneficiary.query.filter_by(username=order.get('beneficiary_username')).first()
        listing = Listings.query.get(order.get('listing_id'))
        o = Orders(donor=donor, beneficiary=beneficiary, listing=listing)
        db.session.add(o)
        db.session.commit()
        return {"orders": "added"}


api.add_resource(Login, '/login')
api.add_resource(Listing, '/listing')
api.add_resource(Order, '/order')