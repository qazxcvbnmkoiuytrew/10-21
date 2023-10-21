from flask import Flask, jsonify, request, render_template, session, redirect, Response
import pymongo
import json
import re
from bson import json_util
from passlib.hash import pbkdf2_sha256
from bson.objectid import ObjectId

myclient = pymongo.MongoClient("mongodb+srv://team17:TqZI3KaT56q6xwYZ@team17.ufycbtt.mongodb.net/")
mydb = myclient.test


class User:

    def start_session(self, user):
        del user['password']
        user_json = json_util.dumps(user)
        session['logged_in'] = True
        session['user'] = user_json
        session['name'] = user['name']
        return user_json

    def signup(self):

        if request.form.get('password') != request.form.get('password_confirm'):
            return jsonify({"error": "Confirm Password must match"}), 401

        user = {
            "name": request.form.get('name'),
            "email": request.form.get('email'),
            "password": request.form.get('password'),
            "phone": request.form.get('phone'),
            "address": request.form.get('address'),
            "gender": request.form.get('gender'),
            "birthday": request.form.get('birthday')
        }
        user['password'] = pbkdf2_sha256.encrypt(user['password'])

        user_json = json_util.dumps(user)

        if not mydb.users.find_one({"email": user['email']}):
            mydb.users.insert_one(user)
            return self.start_session(user)

        elif mydb.users.find_one({"email": user['email']}):
            return jsonify({"error": "email address already exist"}), 400

        else:
            return jsonify({"error": "something's wrong..."}), 400


    def signout(self):
        session.clear()
        return redirect('/')

    def login(self):
        print("login方法已啟動")
        user = mydb.users.find_one({
            "email": request.form.get('email')
        })

        if not user:
            return jsonify({"error": "email not found"}), 401

        elif not pbkdf2_sha256.verify(request.form.get('password'), user['password']):
            return jsonify({"error": "password incorrect"}), 401

        elif user and pbkdf2_sha256.verify(request.form.get('password'), user['password']):
            return self.start_session(user)

        return jsonify({"error": "Something's wrong..."}), 401
        # return jsonify({ "error": "Invalid" }), 401

    def update_user(self):
        user_json = session.get('user')  # Get user JSON from session
        user_data = json.loads(user_json)  # Parse JSON to dictionary
        user_email = user_data['email']

        if not user_email:
            return jsonify({"error": "Email not found in session"}), 400

        update_data = {
            "name": request.form.get('name'),
            "password": pbkdf2_sha256.encrypt(request.form.get('password')),
            "phone": request.form.get('phone'),
            "address": request.form.get('address'),
            "gender": request.form.get('gender'),
            "birthday": request.form.get('birthday')
        }
        for field in ['name', 'phone', 'address', 'gender', 'birthday']:
            new_value = request.form.get(field)
            if new_value:
                update_data[field] = new_value

        # Handle password separately to hash it before updating
        new_password = request.form.get('password')
        if new_password:
            update_data['password'] = pbkdf2_sha256.encrypt(new_password)

        if not update_data:
            return jsonify({"error": "No fields to update"}), 400

        # Update the user information
        result = mydb.users.update_one(
            {"email": user_email},
            {"$set": update_data}
        )

        if result.modified_count > 0:
            # Fetch and return the updated user
            updated_user = mydb.users.find_one({"email": user_email})
            del updated_user['password']

            # Update the session with the new user data
            session['user'] = json_util.dumps(updated_user)

            return json_util.dumps(updated_user)

        return jsonify({"error": "Update failed"}), 400

    def get_all_member(self):
        try:
            members = mydb.users.find({}, {"name": 1, "email": 1})
            # print("passed models.py, reaching for db")
            return render_template('admin.html', members=members)
        except Exception as e:
            print("error in models.py")
            return json_util.dumps({'error': str(e)})

    def delete_member(self, email):
        try:
            # 使用你的数据库客户端对象来执行删除操作
            mydb.users.delete_one({"email": email})
            return redirect('/admin')
        except Exception as e:
            print("Error deleting member:", str(e))
            return {'error': str(e)}

    # 個別會員的資料
    def get_member(self, email):
        try:
            members = mydb.users.find({}, {"name": 1, "email": 1})

            try:
                member_info = mydb.users.find_one({"email": email}, {"_id": 0, "password": 0})
                # test_member_json = json_util.dumps(test_member)
                print(member_info)
                return render_template('admin.html', members=members, member_info=member_info)

            except Exception as e:
                print("Error (inside) get member info: ", str(e))
                return json_util.dumps({'error': str(e)})

        except Exception as e:
            print("Error (outside) get all member: ", str(e))
            return json_util.dumps({'error': str(e)})

    def search(self):
        if request.method == 'POST':
            keyword = request.form['keyword']
            # 使用正则表达式进行模糊搜索，查询多个字段
            regex = re.compile(f'.*{keyword}.*', re.IGNORECASE)

            # 使用 $or 运算符来构建查询条件，以同时搜索 "name" 和 "email" 字段
            query = {
                "$or": [
                    {"title": regex},  # 搜索 "name" 字段
                    {"description": regex}  # 搜索 "email" 字段
                ]
            }

            results = list(mydb.events.find(query))  # 将结果转换为列表
            return render_template('search.html', results=results)

    def event_details(self, event_id):
        # 使用 event_id 检索事件的详细信息，然后将详细信息传递给模板
        event = mydb.events.find_one({"_id": ObjectId(event_id)})  # 假设您的事件具有唯一的 _id
        return render_template('event.html', event=event)
