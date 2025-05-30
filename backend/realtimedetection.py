
'''
import cv2
import numpy as np
import os
import datetime
import threading
import time
from pymongo import MongoClient
from tensorflow.keras.models import model_from_json, Sequential
from tensorflow.keras.utils import get_custom_objects
import sys
import argparse

# ========== CONFIGURATION ==========
SESSION_USERNAME = None  # Set on run
ASSIGNMENT_ID = None     # Set on run
RUN_DURATION = 300       # seconds
MONGO_URI = "mongodb://localhost:27017"
DB_NAME = "emotion_db"

# Register Sequential class so model_from_json can find it
get_custom_objects().update({'Sequential': Sequential})

# Initialize MongoDB
client = MongoClient(MONGO_URI)
db = client[DB_NAME]
emotion_log_collection = db.emotion_logs

# Load model and weights
base_dir = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(base_dir, "facialemotionmodel.json"), "r") as json_file:
    model_json = json_file.read()

model = model_from_json(model_json, custom_objects={'Sequential': Sequential})
model.load_weights(os.path.join(base_dir, "facialemotionmodel.h5"))

# Load Haar cascade for face detection
face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')

# Emotion labels
labels = ['angry', 'disgust', 'fear', 'happy', 'neutral', 'sad', 'surprise']

# ===== Feature Extraction =====
def extract_features(image):
    feature = np.array(image)
    feature = feature.reshape(1, 48, 48, 1)
    return feature / 255.0

# ===== Detection Loop =====
def start_emotion_detection():
    if SESSION_USERNAME is None or ASSIGNMENT_ID is None:
        print("❌ SESSION_USERNAME or ASSIGNMENT_ID not set.")
        return

    webcam = cv2.VideoCapture(0)
    if not webcam.isOpened():
        print("❌ Webcam could not be opened.")
        return

    print(f"🎥 Starting emotion detection for {SESSION_USERNAME} (Assignment: {ASSIGNMENT_ID})")
    start_time = time.time()

    try:
        while True:
            ret, frame = webcam.read()
            if not ret:
                print("⚠️ Failed to capture frame.")
                break

            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            faces = face_cascade.detectMultiScale(gray, 1.3, 5)

            for (x, y, w, h) in faces:
                roi = gray[y:y + h, x:x + w]
                roi = cv2.resize(roi, (48, 48))
                img = extract_features(roi)
                pred = model.predict(img, verbose=0)
                label = labels[pred.argmax()]

                # Draw annotation
                cv2.rectangle(frame, (x, y), (x + w, y + h), (255, 0, 0), 2)
                cv2.putText(frame, label, (x, y - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.9, (36, 255, 12), 2)

                # Log emotion to MongoDB
                emotion_log_collection.insert_one({
                    "username": SESSION_USERNAME,
                    "assignment_id": ASSIGNMENT_ID,
                    "emotion": label,
                    "timestamp": datetime.datetime.utcnow()
                })

            # Show video frame
            cv2.imshow("Emotion Detection", frame)
            if cv2.waitKey(1) & 0xFF == ord('q'):
                print("❎ Quit signal received.")
                break

            if time.time() - start_time > RUN_DURATION:
                print(f"⏰ Run duration {RUN_DURATION} seconds reached, stopping.")
                break

    except KeyboardInterrupt:
        print("🛑 Interrupted by user.")
    finally:
        webcam.release()
        cv2.destroyAllWindows()
        print("✅ Emotion detection finished.")

# ===== Threaded Entry Point =====
def run_emotion_detection(username, assignment_id, duration=300):
    global SESSION_USERNAME, ASSIGNMENT_ID, RUN_DURATION
    SESSION_USERNAME = username
    ASSIGNMENT_ID = assignment_id
    RUN_DURATION = duration

    thread = threading.Thread(target=start_emotion_detection)
    thread.start()
    return thread

# ===== Command-line Argument Parsing =====
def parse_args():
    parser = argparse.ArgumentParser(description="Run real-time emotion detection")
    parser.add_argument("--username", type=str, required=True, help="Username of the student")
    parser.add_argument("--assignment_id", type=str, required=True, help="Assignment ID")
    parser.add_argument("--duration", type=int, default=300, help="Run duration in seconds (default 300)")
    args = parser.parse_args()
    return args.username, args.assignment_id, args.duration

# ===== Main =====
if __name__ == "__main__":
    if len(sys.argv) > 1:
        username, assignment_id, duration = parse_args()
        run_emotion_detection(username, assignment_id, duration).join()
    else:
        print("⚠️ Warning: Running with default username and assignment_id. Use --username and --assignment_id for real data.")
        run_emotion_detection("test_user", "assignment_001", duration=60).join()

'''


import cv2
import numpy as np
import os
import datetime
import threading
import time
import argparse
from pymongo import MongoClient
from tensorflow.keras.models import model_from_json, Sequential
from tensorflow.keras.utils import get_custom_objects

# ========== CONFIGURATION ==========
SESSION_USERNAME = None
ASSIGNMENT_ID = None
RUN_DURATION = 300
MONGO_URI = "mongodb://localhost:27017"
DB_NAME = "emvi_portal"

get_custom_objects().update({'Sequential': Sequential})

client = MongoClient(MONGO_URI)
db = client[DB_NAME]
emotion_log_collection = db.emotion_logs

base_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(base_dir, "facialemotionmodel.json")
weights_path = os.path.join(base_dir, "facialemotionmodel.h5")

with open(model_path, "r") as json_file:
    model_json = json_file.read()

model = model_from_json(model_json, custom_objects={'Sequential': Sequential})
model.load_weights(weights_path)

face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')

labels = ['angry', 'disgust', 'fear', 'happy', 'neutral', 'sad', 'surprise']

def extract_features(image):
    feature = np.array(image).reshape(1, 48, 48, 1)
    return feature / 255.0

def start_emotion_detection():
    if not SESSION_USERNAME or not ASSIGNMENT_ID:
        print("❌ SESSION_USERNAME or ASSIGNMENT_ID not set.")
        return

    webcam = cv2.VideoCapture(0)
    if not webcam.isOpened():
        print("❌ Webcam could not be opened.")
        return

    print(f"\n🎥 Starting emotion detection for user: {SESSION_USERNAME}, assignment: {ASSIGNMENT_ID}")
    start_time = time.time()

    try:
        while True:
            ret, frame = webcam.read()
            if not ret:
                print("⚠️ Frame capture failed.")
                break

            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            faces = face_cascade.detectMultiScale(gray, 1.3, 5)

            for (x, y, w, h) in faces:
                roi = gray[y:y+h, x:x+w]
                roi = cv2.resize(roi, (48, 48))
                img = extract_features(roi)
                pred = model.predict(img, verbose=0)
                label = labels[np.argmax(pred)]

                cv2.rectangle(frame, (x, y), (x+w, y+h), (255, 0, 0), 2)
                cv2.putText(frame, label, (x, y-10), cv2.FONT_HERSHEY_SIMPLEX, 0.9, (36, 255, 12), 2)

                emotion_log_collection.insert_one({
                    "username": SESSION_USERNAME,
                    "assignment_id": ASSIGNMENT_ID,
                    "emotion": label,
                    "timestamp": datetime.datetime.utcnow()
                })

            cv2.imshow("Emotion Detection", frame)
            if cv2.waitKey(1) & 0xFF == ord('q'):
                print("❎ Quit key pressed.")
                break

            if time.time() - start_time > RUN_DURATION:
                print(f"⏰ Run time of {RUN_DURATION} seconds reached.")
                break

    except KeyboardInterrupt:
        print("🛑 Emotion detection interrupted manually.")
    finally:
        webcam.release()
        cv2.destroyAllWindows()
        print("✅ Emotion detection stopped.")

def run_emotion_detection(username, assignment_id, duration=300):
    global SESSION_USERNAME, ASSIGNMENT_ID, RUN_DURATION
    SESSION_USERNAME = username
    ASSIGNMENT_ID = assignment_id
    RUN_DURATION = duration

    thread = threading.Thread(target=start_emotion_detection)
    thread.start()
    return thread

def parse_args():
    parser = argparse.ArgumentParser(description="Run real-time emotion detection")
    # Changed to positional arguments
    parser.add_argument("username", type=str, help="Username of the student")
    parser.add_argument("assignment_id", type=str, help="Assignment ID")
    parser.add_argument("duration", type=int, nargs='?', default=300, help="Duration in seconds (default 300)")
    args = parser.parse_args()
    return args.username, args.assignment_id, args.duration

def main(username, assignment_id, duration=300):
    run_emotion_detection(username, assignment_id, duration).join()

if __name__ == "__main__":
    username, assignment_id, duration = parse_args()
    main(username, assignment_id, duration)
