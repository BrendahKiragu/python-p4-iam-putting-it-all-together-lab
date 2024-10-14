#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe



@app.before_request
def check_if_logged_in():
    open_access_list = [
        'signup',
        'login',
        'check_session'
    ]

    if (request.endpoint) not in open_access_list and (not session.get('user_id')):
        return {'error': '401 Unauthorized'}, 401


class Signup(Resource):

    def post(self):
        username = request.json.get('username')
        password = request.json.get('password')
        image_url = request.json.get('image_url')
        bio = request.json.get('bio')

        if not username or not password:  # Validate input
            return {'error': '422 Unprocessable Entity'}, 422

        user = User(
            username=username,
            image_url=image_url,
            bio=bio
        )

        user.password_hash = password

        try:
            db.session.add(user)
            db.session.commit()
            session['user_id'] = user.id
            return user.to_dict(), 201
        except IntegrityError:
            return {'error': '422 Unprocessable Entity'}, 422


class CheckSession(Resource):

    def get(self):

        user_id = session['user_id']
        if user_id:
            user = User.query.filter(User.id == user_id).first()
            return user.to_dict(), 200

        return {}, 401



class Login(Resource):

    def post(self):

        username = request.json.get('username')
        password = request.json.get('password')

        user = User.query.filter(User.username == username).first()

        if user:
            if user.authenticate(password):

                session['user_id'] = user.id
                return user.to_dict(), 200

        return {'error': '401 Unauthorized'}, 401



class Logout(Resource):

    def delete(self):
        if 'user_id' in session:
            del session['user_id']
            return '', 204
        else:
            return {'error': '401 Unauthorized'}, 401

class RecipeIndex(Resource):
   def get(self):
       user_id = session.get('user_id')
       if not user_id:
           return {'error': '401 Unauthorized'}, 401
       
       recipes = Recipe.query.filter_by(user_id=user_id).all()
       return [recipe.to_dict() for recipe in recipes], 200

   def post(self):
     request_json = request.get_json()
     if request_json is None:
         return {'error': '422 Unprocessable Entity'}, 422
 
     title = request_json.get('title')
     instructions = request_json.get('instructions')
     minutes_to_complete = request_json.get('minutes_to_complete')
 
     if not title or not instructions or not minutes_to_complete:
         return {'error': '422 Unprocessable Entity'}, 422
 
     user_id = session.get('user_id')
     if not user_id:
         return {'error': '401 Unauthorized'}, 401
 
     try:
         recipe = Recipe(
             title=title,
             instructions=instructions,
             minutes_to_complete=minutes_to_complete,
             user_id=user_id,
         )
 
         db.session.add(recipe)
         db.session.commit()
         return recipe.to_dict(), 201
 
     except IntegrityError as e:
         db.session.rollback()  # Rollback the session on error
         return {'error': '422 Unprocessable Entity', 'message': str(e)}, 422
     except Exception as e:
         db.session.rollback()  # Rollback the session on any other error
         return {'error': '500 Internal Server Error', 'message': str(e)}, 500


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)