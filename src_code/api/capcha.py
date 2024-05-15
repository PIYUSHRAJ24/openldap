from flask import Blueprint, request, jsonify
from lib.redislib import RedisLib
from PIL import Image, ImageDraw, ImageFont
import base64
from io import BytesIO
import random
from gtts import gTTS
import math


bp = Blueprint('captcha', __name__)
rs = RedisLib()

def generate_captcha_image(captcha_text):
    width, height = 160, 60
    
    captcha_image_pil = Image.new('RGB', (width, height), (255, 255, 255))
    
    draw = ImageDraw.Draw(captcha_image_pil)
    
    font = ImageFont.load_default().font_variant(size=34)
    
    for i in range(0, max(width, height), 10):
        tilt_angle = random.uniform(-math.pi/4, math.pi/4) 
        draw.line([(0, i), (width, i + int(width * math.tan(tilt_angle)))], fill='black', width=1)
        
        tilt_angle = random.uniform(-math.pi/4, math.pi/4)
        draw.line([(i, 0), (i + int(height * math.tan(tilt_angle)), height)], fill='black', width=1)
        
    text_bbox = draw.textbbox((0, 0), captcha_text, font=font)
    text_position = ((width - text_bbox[2]) / 2, (height - text_bbox[3]) / 2)
    
    draw.text(text_position, captcha_text, font=font, fill='#3D3D3D')
    
    buffered = BytesIO()
    captcha_image_pil.save(buffered, format="PNG")
    img_bytes = buffered.getvalue()

    return img_bytes

def generate_captcha_audio(text):
    language = 'en'
    tts = gTTS(text=text, lang=language, slow=False)
    audio_bytes = BytesIO()
    tts.write_to_fp(audio_bytes)
    return audio_bytes.getvalue()

def generate_random_key():
    random_number = ''.join(random.choices('0123456789', k=10))
    random_dash = '-'
    random_4_digit_number = ''.join(random.choices('0123456789', k=4))
    return f"{random_number}{random_dash}{random_4_digit_number}-"

def generate_captcha_text(length=6):
    captcha_characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    captcha_text = ''.join(random.choice(captcha_characters) for _ in range(length))
    return captcha_text

@bp.route('/api/generate_captcha', methods=['GET'])
def generate_captcha():
    captcha_text = request.args.get('text')
    captcha_rand = generate_captcha_text()
    image_bytes = generate_captcha_image(captcha_text or captcha_rand)
    audio_bytes = generate_captcha_audio(captcha_text or captcha_rand)
    captcha_key = generate_random_key()
    
    captcha_value = captcha_text or captcha_rand
    rs.set(key=captcha_key+'captcha', value=captcha_value, ex=604800)

    audio_base64 = base64.b64encode(audio_bytes).decode('utf-8')
    image_base64 = base64.b64encode(image_bytes).decode('utf-8')

    response_data = {
        "status": True,
        "s_key": captcha_key,
        "Content": image_base64,
        "captcha_audio": audio_base64
    }

    response = jsonify(response_data)
    response.headers['Content-Type'] = 'application/x-www-form-urlencoded'
    return response, 200

@bp.route('/api/verify_captcha', methods=['POST'])
def verify_captcha():
    input_text = request.form.get('s_text')
    s_key = request.form.get('s_key')
    
    if input_text is None or s_key is None:
        response_data = {
            'status': False,
            'verify': 'failed',
            'message': 'Input text or s_key is missing'
        }
        status_code = 400
    else:
        from_redis = rs.get(key=s_key+'captcha')
        
        if from_redis == input_text:
            rs.remove(key=s_key+'captcha')
            response_data = {'status': True, 'verify': 'success'}
            status_code = 200
        else:
            captcha_text = generate_captcha_text()
            image_bytes = generate_captcha_image(captcha_text)
            audio_bytes = generate_captcha_audio(captcha_text)
            captcha_key = generate_random_key()

            rs.set(key=captcha_key+'captcha', value=captcha_text, ex=604800)
            audio_base64 = base64.b64encode(audio_bytes).decode('utf-8')
            image_base64 = base64.b64encode(image_bytes).decode('utf-8')

            response_data = {
                'status': False,
                'verify': 'failed',
                'captcha_audio': audio_base64,
                'Content': image_base64,
                's_key': captcha_key
            }
            status_code = 400

    response = jsonify(response_data)
    
    response.headers['Content-Type'] = 'application/x-www-form-urlencoded'

    return response, status_code