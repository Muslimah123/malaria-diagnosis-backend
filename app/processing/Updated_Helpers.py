import os
from collections import defaultdict
import onnxruntime as ort
import numpy as np
import cv2

# Load the ONNX model
def load_model(onnx_model_path):
    session = ort.InferenceSession(onnx_model_path)
    return session

# Preprocess the image for YOLOv5 (resize, normalize, and convert to tensor format)
def preprocess_image(image_path, input_size=(640, 640)):
    img = cv2.imread(image_path)
    img_resized = cv2.resize(img, input_size)
    img_rgb = cv2.cvtColor(img_resized, cv2.COLOR_BGR2RGB)
    img_normalized = img_rgb / 255.0  # Normalize to [0, 1]
    img_transposed = np.transpose(img_normalized, (2, 0, 1))  # HWC to CHW format
    img_tensor = np.expand_dims(img_transposed, axis=0).astype(np.float32)  # Add batch dimension
    return img_tensor, img

# Function to calculate parasite density using WHO method
def calculate_parasite_density(parasite_count, wbc_count, wbc_standard=8000):
    if wbc_count == 0:
        return 0  # Avoid division by zero
    return (parasite_count / wbc_count) * wbc_standard
def postprocess_output(output, img_shape, parasite_threshold=0.75, wbc_threshold=0.6):
    detections = output[0][0]  # Shape is (25200, 10)
    
    img_h, img_w = img_shape[:2]
    
    boxes, confidences, class_ids = [], [], []

    # Loop through all detections
    for detection in detections:
        # Extract bounding box coordinates and objectness score
        x_center, y_center, width, height, objectness = detection[:5]
        class_scores = detection[5:]
        class_id = np.argmax(class_scores)
        class_confidence = class_scores[class_id]
        confidence = objectness * class_confidence

        # Apply different thresholds based on the detected class (parasite vs WBC)
        if (class_id in [0, 1, 2, 3] and confidence > parasite_threshold) or (class_id == 4 and confidence > wbc_threshold):
            # Convert from (center_x, center_y, width, height) to (x1, y1, x2, y2)
            x1 = int((x_center - width / 2) * img_w)
            y1 = int((y_center - height / 2) * img_h)
            x2 = int((x_center + width / 2) * img_w)
            y2 = int((y_center + height / 2) * img_h)
            
            boxes.append([x1, y1, x2, y2])
            confidences.append(confidence)
            class_ids.append(class_id)
    
    return boxes, confidences, class_ids

# Function to classify severity based on parasite density
def classify_severity(parasite_density):
    if parasite_density < 1000:
        return "Mild"
    elif 1000 <= parasite_density <= 10000:
        return "Moderate"
    else:
        return "Severe"

# Map class IDs to class names
class_names = {0: 'pf', 1: 'pm', 2: 'po', 3: 'pv', 4: 'wbc'}

def run_inference(onnx_model_path, image_path):
    # Load model
    session = load_model(onnx_model_path)

    # Preprocess the image
    input_tensor, original_img = preprocess_image(image_path)

    # Run the model inference
    input_name = session.get_inputs()[0].name
    outputs = session.run(None, {input_name: input_tensor})

    # Post-process the output to get bounding boxes, confidences, and class IDs
    boxes, confidences, class_ids = postprocess_output(outputs, original_img.shape)

    # Return results
    return len(class_ids), confidences, class_ids




# MODEL_PATH = 'models/new_best.onnx'
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'models', 'new_best.onnx')


def process_images(onnx_model_path, image_paths):
    # Initialize total counts
    total_parasites = 0
    total_wbcs = 0
    parasite_confidences = defaultdict(list)  # To store confidences of each parasite type
    image_results = []

    # Loop over all provided image paths
    for image_path in image_paths:
        image_file = os.path.basename(image_path)
        print (image_path)
        # print(f"Processing {image_file}...")

        # Run inference on the image
        num_parasites, confidences, class_ids = run_inference(onnx_model_path, image_path)

        # If parasites are detected, add to total count
        if num_parasites > 0:
            # Count WBCs separately (assuming class ID 4 is WBC)
            wbc_count = sum(1 for class_id in class_ids if class_id == 4)
            parasite_count = num_parasites - wbc_count  # Exclude WBCs from parasite count
            
            # Add to total counts
            total_parasites += parasite_count
            total_wbcs += wbc_count

            # Track the confidences for each parasite type
            for class_id, confidence in zip(class_ids, confidences):
                if class_id != 4:  # Skip WBCs
                    parasite_confidences[class_id].append(confidence)

            # Store result for this image
            image_results.append({
                "image": image_file,
                "parasite_count": parasite_count,
                "wbc_count": wbc_count
            })
    
    # Calculate the overall parasite density using WHO formula
    parasite_density = calculate_parasite_density(total_parasites, total_wbcs)
    severity = classify_severity(parasite_density)

    # Calculate the average confidence for each parasite type
    average_confidences = {class_id: sum(conf_list) / len(conf_list) 
                           for class_id, conf_list in parasite_confidences.items()}

    # Determine the dominant parasite type based on the highest average confidence
    if average_confidences:
        dominant_class_id = max(average_confidences, key=average_confidences.get)
        dominant_parasite = class_names[dominant_class_id]
        dominant_confidence = average_confidences[dominant_class_id]
    else:
        dominant_parasite, dominant_confidence = None, None

    # Return the results
    return {
        "total_parasites": total_parasites,
        "total_wbcs": total_wbcs,
        "parasite_density": parasite_density,
        "severity": severity,
        "dominant_parasite": dominant_parasite,
        "dominant_confidence": dominant_confidence,
        "image_results": image_results
    }


#  ----------------------------------The following process images in a directory--------

# def process_images(onnx_model_path, image_dir):
#     # Initialize total counts
#     total_parasites = 0
#     total_wbcs = 0
#     parasite_confidences = defaultdict(list)  # To store confidences of each parasite type
#     image_results = []

#     # Loop over all images in the directory
#     for image_file in os.listdir(image_dir):
#         image_path = os.path.join(image_dir, image_file)
#         print(f"Processing {image_file}...")

#         # Run inference on the image
#         num_parasites, confidences, class_ids = run_inference(onnx_model_path, image_path)

#         # If parasites are detected, add to total count
#         if num_parasites > 0:
#             # Count WBCs separately (assuming class ID 4 is WBC)
#             wbc_count = sum(1 for class_id in class_ids if class_id == 4)
#             parasite_count = num_parasites - wbc_count  # Exclude WBCs from parasite count
            
#             # Add to total counts
#             total_parasites += parasite_count
#             total_wbcs += wbc_count

#             # Track the confidences for each parasite type
#             for class_id, confidence in zip(class_ids, confidences):
#                 if class_id != 4:  # Skip WBCs
#                     parasite_confidences[class_id].append(confidence)

#             # Store result for this image
#             image_results.append({
#                 "image": image_file,
#                 "parasite_count": parasite_count,
#                 "wbc_count": wbc_count
#             })
    
#     # Calculate the overall parasite density using WHO formula
#     parasite_density = calculate_parasite_density(total_parasites, total_wbcs)
#     severity = classify_severity(parasite_density)

#     # Calculate the average confidence for each parasite type
#     average_confidences = {class_id: sum(conf_list) / len(conf_list) 
#                            for class_id, conf_list in parasite_confidences.items()}

#     # Determine the dominant parasite type based on the highest average confidence
#     if average_confidences:
#         dominant_class_id = max(average_confidences, key=average_confidences.get)
#         dominant_parasite = class_names[dominant_class_id]
#         dominant_confidence = average_confidences[dominant_class_id]
#     else:
#         dominant_parasite, dominant_confidence = None, None

#     # Return the results
#     return {
#         "total_parasites": total_parasites,
#         "total_wbcs": total_wbcs,
#         "parasite_density": parasite_density,
#         "severity": severity,
#         "dominant_parasite": dominant_parasite,
#         "dominant_confidence": dominant_confidence,
#         "image_results": image_results
#     }

# # Directory where images are stored
# # Test the function
# onnx_model_path = '/Users/alaindestinkarasira/Documents/MALARIA/Malaria_Pjct/MalariaDiagnosis/app/models/new_best.onnx'  # Update with your ONNX model path
# image_dir = '/Users/alaindestinkarasira/Documents/MALARIA/ImageData/External'  # Update with your image path

# # Process images and calculate parasite density
# results = process_images(onnx_model_path, image_dir)

# # Print results
# print(f"Total Parasites Detected: {results['total_parasites']}")
# print(f"Total WBCs Detected: {results['total_wbcs']}")
# print(f"Parasite Density (per µL): {results['parasite_density']:.2f}")
# print(f"Malaria Severity: {results['severity']}")

# # Print dominant parasite type and its average confidence
# if results['dominant_parasite']:
#     print(f"Dominant Parasite Type: {results['dominant_parasite']} with average confidence {results['dominant_confidence']:.2f}")
# else:
#     print("No dominant parasite detected")

# # If you want to display individual image results
# for image_result in results["image_results"]:
#     print(f"Image {image_result['image']}: Parasites: {image_result['parasite_count']}, WBCs: {image_result['wbc_count']}")
