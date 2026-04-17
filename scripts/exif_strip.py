#!/usr/bin/env python3 
""" 
exif_strip.py — Strip EXIF metadata (GPS, camera info, timestamps) from images. 
  
Removes all EXIF/metadata from JPEG and PNG images so they're safe to share 
without leaking your location, device info, or timestamps. 
  
Usage: 
    python exif_strip.py photo.jpg 
    python exif_strip.py photo.jpg -o cleaned_photo.jpg 
    python exif_strip.py ./photos/ --recursive 
    python exif_strip.py photo.jpg --preview   # show metadata without removing 
  
Supported formats: JPEG, PNG, TIFF, WebP 
""" 
  
import argparse 
import os 
import sys 
from pathlib import Path 
  
try: 
    from PIL import Image 
    from PIL.ExifTags import TAGS, GPSTAGS 
except ImportError: 
    print("ERROR: Pillow is required. Install it with: pip install Pillow") 
    sys.exit(1) 
  
# Image extensions we can process 
SUPPORTED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".tiff", ".tif", ".webp"} 
  
  
def get_exif_data(image_path): 
    """ 
    Extract and return human-readable EXIF data from an image. 
    Returns a dict of {tag_name: value} pairs. 
    """ 
    exif_data = {} 
    try: 
        img = Image.open(image_path) 
        raw_exif = img.getexif() 
        if not raw_exif: 
            return exif_data 
  
        for tag_id, value in raw_exif.items(): 
            tag_name = TAGS.get(tag_id, f"Unknown-{tag_id}") 
            # Convert bytes to string for display 
            if isinstance(value, bytes): 
                try: 
                    value = value.decode("utf-8", errors="replace") 
                except Exception: 
                    value = str(value) 
            exif_data[tag_name] = value 
  
        # Also extract GPS info if present 
        gps_info = raw_exif.get_ifd(0x8825)  # GPSInfo IFD 
        if gps_info: 
            gps_readable = {} 
            for tag_id, value in gps_info.items(): 
                tag_name = GPSTAGS.get(tag_id, f"GPS-Unknown-{tag_id}") 
                gps_readable[tag_name] = value 
            exif_data["GPSInfo_Decoded"] = gps_readable 
  
    except Exception as e: 
        exif_data["_error"] = str(e) 
  
    return exif_data 
  
  
def strip_exif(input_path, output_path=None, verbose=False): 
    """ 
    Remove ALL metadata from an image by re-saving pixel data only. 
  
    This works by reading the raw pixel data and saving it to a new file 
    without copying any metadata. This is the most reliable stripping method 
    because it doesn't try to selectively remove tags — it removes everything. 
  
    Args: 
        input_path: Path to the original image 
        output_path: Where to save the clean image (defaults to overwriting original) 
        verbose: If True, print details about what was removed 
  
    Returns: 
        True if successful, False otherwise 
    """ 
    input_path = Path(input_path) 
    if output_path is None: 
        output_path = input_path 
    else: 
        output_path = Path(output_path) 
  
    try: 
        # Read the original image 
        img = Image.open(input_path) 
        original_format = img.format or input_path.suffix.lstrip(".").upper() 
  
        # Map common format names 
        format_map = {"JPG": "JPEG", "TIF": "TIFF"} 
        save_format = format_map.get(original_format.upper(), original_format.upper()) 
  
        if verbose: 
            exif_before = get_exif_data(input_path) 
            if exif_before: 
                print(f"  Removing {len(exif_before)} metadata entries") 
            else: 
                print("  No metadata found (already clean)") 
  
        # Create a brand new image from pixel data only — no metadata carries over 
        pixel_data = img.copy() 
  
        # Clear any embedded info 
        if hasattr(pixel_data, "info"): 
            # Preserve only essential rendering info, strip everything else 
            safe_keys = {"transparency", "duration", "loop"} 
            pixel_data.info = { 
                k: v for k, v in pixel_data.info.items() if k in safe_keys 
            } 
  
        # Save without EXIF — the key is we never call img.save() with exif= param 
        save_kwargs = {} 
        if save_format == "JPEG": 
            save_kwargs["quality"] = 95  # High quality to minimize re-compression loss 
            save_kwargs["subsampling"] = 0  # Best quality chroma subsampling 
        elif save_format == "PNG": 
            save_kwargs["optimize"] = True 
        elif save_format == "WEBP": 
            save_kwargs["quality"] = 95 
  
        # Ensure output directory exists 
        output_path.parent.mkdir(parents=True, exist_ok=True) 
  
        pixel_data.save(str(output_path), format=save_format, **save_kwargs) 
        return True 
  
    except Exception as e: 
        print(f"  ERROR: {e}", file=sys.stderr) 
        return False 
  
  
def preview_metadata(image_path): 
    """Display all metadata found in an image without modifying it.""" 
    exif_data = get_exif_data(image_path) 
  
    if not exif_data: 
        print(f"  No metadata found in {image_path}") 
        return 
  
    print(f"\n  Metadata in: {image_path}") 
    print("  " + "-" * 50) 
  
    # Highlight the most privacy-sensitive fields 
    sensitive_tags = { 
        "GPSInfo", "GPSInfo_Decoded", "Make", "Model", "Software", 
        "DateTime", "DateTimeOriginal", "DateTimeDigitized", 
        "Artist", "Copyright", "CameraSerialNumber", 
        "LensMake", "LensModel", "BodySerialNumber", 
    } 
  
    for tag, value in sorted(exif_data.items()): 
        marker = " [!]" if tag in sensitive_tags else "" 
        # Truncate very long values for display 
        value_str = str(value) 
        if len(value_str) > 80: 
            value_str = value_str[:77] + "..." 
        print(f"  {tag}: {value_str}{marker}") 
  
    sensitive_found = sensitive_tags & set(exif_data.keys()) 
    if sensitive_found: 
        print(f"\n  [!] = Privacy-sensitive field ({len(sensitive_found)} found)") 
  
  
def find_images(path, recursive=False): 
    """Find all supported image files in a directory.""" 
    path = Path(path) 
  
    if path.is_file(): 
        if path.suffix.lower() in SUPPORTED_EXTENSIONS: 
            return [path] 
        else: 
            print(f"Unsupported file type: {path.suffix}", file=sys.stderr) 
            return [] 
  
    if path.is_dir(): 
        images = [] 
        pattern = "**/*" if recursive else "*" 
        for ext in SUPPORTED_EXTENSIONS: 
            images.extend(path.glob(f"{pattern}{ext}")) 
            images.extend(path.glob(f"{pattern}{ext.upper()}")) 
        return sorted(set(images)) 
  
    print(f"Path not found: {path}", file=sys.stderr) 
    return [] 
  
  
def main(): 
    parser = argparse.ArgumentParser( 
        description="Strip EXIF metadata from images to protect your privacy.", 
        epilog="Examples:\n" 
               "  python exif_strip.py photo.jpg\n" 
               "  python exif_strip.py ./photos/ --recursive\n" 
               "  python exif_strip.py photo.jpg --preview", 
        formatter_class=argparse.RawDescriptionHelpFormatter, 
    ) 
    parser.add_argument( 
        "input", 
        help="Image file or directory to process", 
    ) 
    parser.add_argument( 
        "-o", "--output", 
        help="Output file or directory (default: overwrite originals)", 
    ) 
    parser.add_argument( 
        "-r", "--recursive", 
        action="store_true", 
        help="Process subdirectories recursively", 
    ) 
    parser.add_argument( 
        "--preview", 
        action="store_true", 
        help="Show metadata without removing it", 
    ) 
    parser.add_argument( 
        "-v", "--verbose", 
        action="store_true", 
        help="Print detailed information during processing", 
    ) 
  
    args = parser.parse_args() 
  
    # Find all images to process 
    images = find_images(args.input, recursive=args.recursive) 
    if not images: 
        print("No supported images found.") 
        sys.exit(1) 
  
    print(f"Found {len(images)} image(s) to process.\n") 
  
    # Preview mode — just show metadata, don't modify anything 
    if args.preview: 
        for img_path in images: 
            preview_metadata(img_path) 
        return 
  
    # Process each image 
    success_count = 0 
    fail_count = 0 
  
    for img_path in images: 
        # Determine output path 
        if args.output: 
            out_path = Path(args.output) 
            if out_path.is_dir() or len(images) > 1: 
                out_path = out_path / img_path.name 
        else: 
            out_path = None  # Overwrite original 
  
        display_out = out_path or img_path 
        print(f"Processing: {img_path} -> {display_out}") 
  
        if strip_exif(img_path, out_path, verbose=args.verbose): 
            success_count += 1 
        else: 
            fail_count += 1 
  
    print(f"\nDone. {success_count} cleaned, {fail_count} failed.") 
  
  
if __name__ == "__main__": 
    main() 