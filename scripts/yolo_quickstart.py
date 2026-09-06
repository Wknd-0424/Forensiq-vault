"""
ForensIQ Vault — YOLOv8n Quick-Start (AI Triage Module)
=========================================================
This uses the OFFICIAL PRETRAINED yolov8n.pt weights (trained on the COCO
dataset by Ultralytics). Per the project spec, ForensIQ Vault does NOT
require custom training — person and vehicle classes are already covered
by COCO's pretrained classes. Custom training would only be justified if
you needed to detect something COCO doesn't cover (e.g., a specific
weapon type or a custom object class), which is explicitly out of scope
for this project.

Setup (run once, in your actual project's virtual environment):
    pip install ultralytics

Place yolov8n.pt in your project, e.g.:
    forensiq/ai_models/yolov8n.pt

Then use it like this from ai_service.py:
"""

from ultralytics import YOLO

# COCO class IDs relevant to this project (per your spec's scope):
# 0 = person, 2 = car, 3 = motorcycle, 5 = bus, 7 = truck
RELEVANT_CLASSES = [0, 2, 3, 5, 7]

CONFIDENCE_THRESHOLD = 0.45  # starting point; tune per your dataset


def run_triage(working_copy_frame_path: str, model_path: str = "yolov8n.pt"):
    """
    Runs YOLOv8n person/vehicle detection on a single frame extracted
    from a VERIFIED WORKING COPY ONLY. Never call this on original evidence.

    Returns a list of detections, each shaped to match your AIDetection
    model fields: model_name, model_version, class_name, confidence,
    bbox_json, threshold, frame_number/frame_timestamp (set by caller).
    """
    model = YOLO(model_path)

    results = model(
        working_copy_frame_path,
        classes=RELEVANT_CLASSES,
        conf=CONFIDENCE_THRESHOLD,
    )

    detections = []
    for result in results:
        for box in result.boxes:
            class_id = int(box.cls[0])
            detections.append({
                "model_name": "yolov8n",
                "model_version": "8.3.0",  # match the release you downloaded
                "class_name": model.names[class_id],
                "confidence": float(box.conf[0]),
                "threshold": CONFIDENCE_THRESHOLD,
                "bbox_json": box.xyxy[0].tolist(),  # [x1, y1, x2, y2]
                "reviewer_status": "PENDING",  # per spec: default is always PENDING
            })

    return detections


if __name__ == "__main__":
    # Quick manual test — replace with a real frame from a working copy
    import sys
    if len(sys.argv) < 2:
        print("Usage: python yolo_quickstart.py <path_to_test_frame.jpg>")
        sys.exit(1)

    dets = run_triage(sys.argv[1])
    for d in dets:
        print(f"{d['class_name']:12s} conf={d['confidence']:.2f}  bbox={d['bbox_json']}")
