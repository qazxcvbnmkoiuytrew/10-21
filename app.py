from flask import Flask, render_template, url_for, request, session, redirect, Response
import json
import pymongo
from functools import wraps
from user.models import User
from flask_wtf.csrf import CSRFProtect
from camera import VideoCamera
import cv2
import os, sys
import numpy as np
import time
from webcam2 import FaceRecognition

app = Flask(__name__)
app.secret_key = b'kushfuii7w4y7ry47ihwiheihf8774sdf4'

video_stream = VideoCamera()
global_name = None
# 全局变量用于存储已拍摄的照片
captured_photo = None

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            return redirect('/')

    return wrap

def gen(camera):
    global captured_photo  # 声明全局变量
    while True:
        frame = camera.get_frame()
        if frame:
            if captured_photo:
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + captured_photo + b'\r\n\r\n')
            else:
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n\r\n')

# routes
from user import routes

@app.route('/')
def home():
    user_json = session.get('user')
    if user_json:
        user = json.loads(user_json)
        user_data = json.loads(user_json)
        user_name = user_data['name']
        return render_template('home.html', user_name=user_name)
    else:
        return render_template('home.html')


@app.route('/register')
def user_signup():
    return render_template('register.html')


@app.route('/user/login', methods=['GET','POST'])
def user_login():

    return render_template('login.html')


@app.route('/dashboard/')
@login_required
def dashboard():
    user_json = session.get('user')
    if user_json:
        user = json.loads(user_json)
        user_data = json.loads(user_json)
        user_name = user_data['name']
        return render_template('dashboard.html', user_name=user_name)
    else:
        print("user_json is NOT a thing")
        return redirect('/user/login')


@app.route('/user/update_user')
@login_required
def edit():
    user_json = session.get('user')
    if user_json:
        user = json.loads(user_json)
        return render_template('update_user.html', user=user)  # Pass the user variable to the template
    else:
        return redirect('/login')

@app.route('/admin')
def admin():
    #print("reaching for admin.html")
    return render_template('admin.html', members = members)


#拍照
@app.route('/cam')
def cam():
    return render_template('cam.html', taken_photo=captured_photo)

@app.route('/video_feed')
def video_feed():
    return Response(gen(video_stream), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/take_photo', methods=['POST'])
def take_photo():
    global captured_photo  # 声明全局变量
    frame = video_stream.get_frame()

    if frame:
            # 使用 OpenCV 解码 JPEG 图像为 NumPy 数组
        nparr = np.frombuffer(frame, np.uint8)
        image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

            # 使用当前时间戳作为文件名
        timestamp = int(time.time())

            # 将照片数据存储在 captured_photo 中
        captured_photo = cv2.imencode('.jpg', image)[1].tobytes()

    return render_template('cam.html', taken_photo=captured_photo)

@app.route('/save_photo', methods=['POST'])
def save_photo():
    global captured_photo  # 声明全局变量
    if captured_photo:
        username = session.get('name')
            # 使用当前时间戳作为文件名
        timestamp = int(time.time())

            # 指定保存到 "faces" 子文件夹的路径
        output_folder = 'faces'

            # 确保目标文件夹存在，如果不存在则创建它
        os.makedirs(output_folder, exist_ok=True)

            # 创建完整的文件路径，将照片保存到 "faces" 子文件夹中
        photo_filename = os.path.join(output_folder, f'{username}.jpg')

            # 写入照片数据到文件
        with open(photo_filename, 'wb') as photo_file:
            photo_file.write(captured_photo)


    return redirect(url_for('dashboard'))

@app.route('/retake_photo', methods=['POST'])
def retake_photo():
    global captured_photo  # 声明全局变量
    captured_photo = None  # 重置 captured_photo 为 None
    return render_template('cam.html', taken_photo=captured_photo)


#人臉辨識
@app.route('/set_name')
def set_name():
    # 將名字設定為 session 的值
    name = session.get('name')
    print("這裡是setname")

    # 同時也設定全域變數 global_name
    global global_name
    global_name = name

    return 'Name set successfully'

@app.route('/cam2')
def cam2():
    return render_template('cam2.html')

def generate_frames(session):
    fr = FaceRecognition()
    video_capture = cv2.VideoCapture(0)

    if not video_capture.isOpened():
        sys.exit('video source not found...')
    count = 0

    while count < 5:
        ret, frame = video_capture.read()
        if not ret:
            break

        frame, recognized_name = fr.run_recognition(frame)
        recognized_name, confidence = recognized_name.split('(', 1)

        # 從 session 中獲取名字
        session_name = global_name
        print(session_name)
        print(recognized_name)
        # 比對辨識出來的名字和 session 中的名字是否一致
        if recognized_name == session_name:
            print("辨識結果和 session 中的名字一致")
        else:
            print("辨識結果和 session 中的名字不一致")

        _, buffer = cv2.imencode('.jpg', frame)
        frame = buffer.tobytes()
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

        count+=1

    video_capture.release()

@app.route('/video_feed2')
def video_feed2():
    return Response(generate_frames(session), mimetype='multipart/x-mixed-replace; boundary=frame')


if __name__ == "__main__":
    app.run(host='127.0.0.1', debug=True, port=5000)