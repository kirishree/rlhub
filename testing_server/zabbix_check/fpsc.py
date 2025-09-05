import cv2

cap = cv2.VideoCapture("my.webm")
if not cap.isOpened():
    print("Error: Cannot open video file")
else:
    fps = cap.get(cv2.CAP_PROP_FPS)
    total_frames = cap.get(cv2.CAP_PROP_FRAME_COUNT)
    duration = total_frames / fps if fps else 0

    print(f"FPS: {fps}")
    print(f"Total frames: {total_frames}")
    print(f"Duration (approx): {duration:.2f} seconds")

cap.release()
