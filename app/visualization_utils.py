import cv2
import numpy as np
import os
import json
import logging
from flask import current_app
from datetime import datetime

logger = logging.getLogger(__name__)

def draw_bounding_boxes(image_path, detection_data):
    """
    Draw bounding boxes on an image based on detection data from the ML API.
    
    Args:
        image_path (str): Path to the original image
        detection_data (dict): Detection data from the ML API
        
    Returns:
        str: Path to the annotated image
    """
    try:
        # Ensure image path is absolute
        if not os.path.isabs(image_path):
            image_path = os.path.abspath(image_path)
            
        # Log current working directory and image path for debugging
        logger.info(f"Current working directory: {os.getcwd()}")
        logger.info(f"Attempting to process image: {image_path}")
        
        # Validate that image exists
        if not os.path.exists(image_path):
            logger.error(f"Image not found: {image_path}")
            raise FileNotFoundError(f"Image not found: {image_path}")
        
        # Create output directory if it doesn't exist
        output_dir = os.path.join(os.path.dirname(image_path), 'annotated')
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate output filename
        base_filename = os.path.basename(image_path)
        filename, ext = os.path.splitext(base_filename)
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        output_path = os.path.join(output_dir, f"{filename}_annotated_{timestamp}{ext}")
        
        # Read the image
        logger.info(f"Reading image from: {image_path}")
        img = cv2.imread(image_path)
        if img is None:
            logger.error(f"Failed to read image: {image_path}")
            raise ValueError(f"Failed to read image: {image_path}")
        
        # Get image dimensions
        height, width, _ = img.shape
        logger.info(f"Image dimensions: {width}x{height}")
        
        # Define colors for different types
        colors = {
            'PF': (0, 0, 255),    # Red for P. falciparum (BGR format)
            'PV': (0, 255, 255),  # Yellow for P. vivax
            'PM': (255, 0, 0),    # Blue for P. malariae
            'PO': (0, 255, 0),    # Green for P. ovale
            'WBC': (255, 0, 255), # Purple for white blood cells
            'default': (255, 255, 255)  # White for unknown
        }
        
        # Log detection data structure
        logger.info(f"Detection data: {detection_data}")
        
        # Add info banner at the top
        info_height = 40
        canvas = np.zeros((height + info_height, width, 3), dtype=np.uint8)
        canvas[info_height:, :] = img  # Add the original image below the info banner
        canvas[:info_height, :] = (240, 240, 240)  # Light gray banner
        
        # Add detection summary to banner
        parasite_count = detection_data.get('parasite_count', 0)
        wbc_count = detection_data.get('white_blood_cells_detected', 0)
        
        # Check for different API response formats
        if 'parasites_detected' in detection_data:
            parasites = detection_data.get('parasites_detected', [])
        else:
            # Try alternate format
            parasites = []
            for key in detection_data:
                if isinstance(detection_data[key], dict) and 'bbox' in detection_data[key]:
                    parasites.append(detection_data[key])
        
        # Add text to banner
        cv2.putText(
            canvas, 
            f"Parasites: {parasite_count}   WBCs: {wbc_count}", 
            (10, 25), 
            cv2.FONT_HERSHEY_SIMPLEX, 
            0.7, 
            (0, 0, 0), 
            2
        )
        
        # Process parasites detected
        if parasites:
            logger.info(f"Processing {len(parasites)} parasites")
            for parasite in parasites:
                # Safely extract bbox
                bbox = None
                if isinstance(parasite, dict):
                    bbox = parasite.get('bbox')
                
                if not bbox or len(bbox) != 4:
                    logger.warning(f"Invalid bbox in parasite: {parasite}")
                    continue
                
                # Extract coordinates
                x1, y1, x2, y2 = map(int, bbox)
                
                # Adjust Y coordinates for the info banner
                y1 += info_height
                y2 += info_height
                
                # Determine type and get color
                p_type = parasite.get('type', 'default')
                confidence = parasite.get('confidence', 0.0)
                color = colors.get(p_type, colors['default'])
                
                # Draw bounding box
                cv2.rectangle(canvas, (x1, y1), (x2, y2), color, 2)
                
                # Create label with type and confidence
                label = f"{p_type}: {confidence:.2f}"
                
                # Draw background for text
                (text_width, text_height), _ = cv2.getTextSize(
                    label, cv2.FONT_HERSHEY_SIMPLEX, 0.5, 1
                )
                
                # Draw text background
                cv2.rectangle(
                    canvas,
                    (x1, y1 - text_height - 5),
                    (x1 + text_width + 5, y1),
                    color,
                    -1  # Filled rectangle
                )
                
                # Draw text label
                cv2.putText(
                    canvas,
                    label,
                    (x1, y1 - 5),
                    cv2.FONT_HERSHEY_SIMPLEX,
                    0.5,
                    (255, 255, 255),  # White text
                    1
                )
        
        # Process WBCs if they have bounding boxes
        # Some API responses might include WBC bounding boxes
        if 'wbc_bboxes' in detection_data:
            wbc_bboxes = detection_data.get('wbc_bboxes', [])
            logger.info(f"Processing {len(wbc_bboxes)} WBCs with bboxes")
            
            for bbox in wbc_bboxes:
                if not bbox or len(bbox) != 4:
                    continue
                
                # Extract coordinates
                x1, y1, x2, y2 = map(int, bbox)
                
                # Adjust Y coordinates for the info banner
                y1 += info_height
                y2 += info_height
                
                # Draw rectangle for WBC
                color = colors['WBC']
                cv2.rectangle(canvas, (x1, y1), (x2, y2), color, 2)
                
                # Add WBC label
                cv2.putText(
                    canvas,
                    "WBC",
                    (x1, y1 - 5),
                    cv2.FONT_HERSHEY_SIMPLEX,
                    0.5,
                    color,
                    1
                )
        
        # Save the annotated image
        logger.info(f"Saving annotated image to: {output_path}")
        cv2.imwrite(output_path, canvas)
        
        return output_path
        
    except Exception as e:
        logger.error(f"Error in draw_bounding_boxes: {str(e)}")
        # Re-raise the exception to be handled by the caller
        raise