import json
import boto3
import hashlib
import jwt
import os
from datetime import datetime, timedelta
import pymysql

# Environment variables
DB_HOST = os.environ['DB_HOST']
DB_USER = os.environ['DB_USER']
DB_PASSWORD = os.environ['DB_PASSWORD']
DB_NAME = os.environ['DB_NAME']
JWT_SECRET = os.environ['JWT_SECRET']

def lambda_handler(event, context):
    try:
        # Parse request body
        body = json.loads(event['body'])
        username = body.get('username')
        password = body.get('password')
        
        if not username or not password:
            return {
                'statusCode': 400,
                'headers': {
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
                    'Access-Control-Allow-Methods': 'POST,OPTIONS'
                },
                'body': json.dumps({
                    'success': False,
                    'message': 'Username and password are required'
                })
            }
        
        # Connect to RDS
        connection = pymysql.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            cursorclass=pymysql.cursors.DictCursor
        )
        
        try:
            with connection.cursor() as cursor:
                # Hash the password (use same method as when storing)
                hashed_password = hashlib.sha256(password.encode()).hexdigest()
                
                # Query user
                sql = "SELECT id, username, password_hash FROM users WHERE username = %s AND password_hash = %s"
                cursor.execute(sql, (username, hashed_password))
                user = cursor.fetchone()
                
                if user:
                    # Generate JWT token
                    payload = {
                        'user_id': user['id'],
                        'username': user['username'],
                        'exp': datetime.utcnow() + timedelta(hours=24)
                    }
                    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
                    
                    return {
                        'statusCode': 200,
                        'headers': {
                            'Access-Control-Allow-Origin': '*',
                            'Access-Control-Allow-Headers': 'Content-Type,Authorization',
                            'Access-Control-Allow-Methods': 'POST,OPTIONS'
                        },
                        'body': json.dumps({
                            'success': True,
                            'token': token,
                            'message': 'Login successful'
                        })
                    }
                else:
                    return {
                        'statusCode': 401,
                        'headers': {
                            'Access-Control-Allow-Origin': '*',
                            'Access-Control-Allow-Headers': 'Content-Type,Authorization',
                            'Access-Control-Allow-Methods': 'POST,OPTIONS'
                        },
                        'body': json.dumps({
                            'success': False,
                            'message': 'Invalid credentials'
                        })
                    }
        finally:
            connection.close()
            
    except Exception as e:
        print(f"Error: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type,Authorization',
                'Access-Control-Allow-Methods': 'POST,OPTIONS'
            },
            'body': json.dumps({
                'success': False,
                'message': 'Internal server error'
            })
        }
