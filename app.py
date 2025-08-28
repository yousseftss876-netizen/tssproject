import os
import imaplib
import email
import email.utils
from email.header import decode_header
from datetime import datetime, timezone
import logging
import json
import re
from flask import Flask, render_template, request, flash, jsonify, redirect, url_for, session, Response
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from connection_manager import gmail_manager

# Configure logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET")

# Validate required environment variables - allow fallback for development
if not app.secret_key:
    # Use a development fallback secret key if SESSION_SECRET is not set
    app.secret_key = "dev-secret-key-change-in-production"
    logging.warning("Using development fallback for SESSION_SECRET. Set SESSION_SECRET environment variable for production.")

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # type: ignore
login_manager.login_message = 'Please log in to access your emails.'
login_manager.login_message_category = 'info'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, username, entity):
        self.id = username
        self.username = username
        self.entity = entity

@login_manager.user_loader
def load_user(user_id):
    """Load user from session"""
    users = load_users_from_file()
    for entity, username, password in users:
        if username == user_id:
            return User(username, entity)
    return None

def load_users_from_file():
    """Load users from users.txt file"""
    users = []
    try:
        with open('users.txt', 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line and not line.startswith('#'):  # Skip empty lines and comments
                    try:
                        parts = line.split(',')
                        if len(parts) == 3:
                            entity = parts[0].strip()
                            username = parts[1].strip()
                            password = parts[2].strip()
                            users.append((entity, username, password))
                        else:
                            logging.warning(f"Invalid format in users.txt line {line_num}: {line}")
                    except Exception as e:
                        logging.error(f"Error parsing users.txt line {line_num}: {e}")
    except FileNotFoundError:
        logging.error("users.txt file not found")
    except Exception as e:
        logging.error(f"Error reading users.txt: {e}")
    
    return users

# Removed - now handled by EntityBasedGmailManager

def get_user_accounts(user_entity):
    """Get Gmail accounts accessible to a user based on their entity"""
    return gmail_manager.get_user_accounts(user_entity)

def authenticate_user(username, password):
    """Authenticate user against users.txt file"""
    users = load_users_from_file()
    for entity, stored_username, stored_password in users:
        if stored_username == username and stored_password == password:
            return entity
    return None

def connect_to_gmail(email_addr, password):
    """Connect to Gmail using IMAP with enhanced error handling and validation"""
    if not email_addr or not password:
        logging.error("Email address and password are required")
        return None
    
    # Basic email validation
    if '@' not in email_addr or '.' not in email_addr:
        logging.error(f"Invalid email address format: {email_addr}")
        return None
        
    try:
        mail = imaplib.IMAP4_SSL('imap.gmail.com', 993)
        mail.login(email_addr, password)
        logging.info(f"Successfully connected to Gmail account: {email_addr}")
        return mail
    except imaplib.IMAP4.error as e:
        logging.error(f"IMAP authentication failed for {email_addr}: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error connecting to Gmail {email_addr}: {e}")
        return None

def decode_mime_words(s):
    """Decode MIME encoded words"""
    if s is None:
        return ''
    
    decoded_parts = []
    for part, encoding in decode_header(s):
        if isinstance(part, bytes):
            if encoding:
                try:
                    decoded_parts.append(part.decode(encoding))
                except:
                    decoded_parts.append(part.decode('utf-8', errors='ignore'))
            else:
                decoded_parts.append(part.decode('utf-8', errors='ignore'))
        else:
            decoded_parts.append(str(part))
    
    return ''.join(decoded_parts)

def extract_and_analyze_emails(email_address, app_password, email_limit='all'):
    """Extract and analyze emails with SPF, DKIM, IP address, and categorization"""
    try:
        # Connect to Gmail
        mail = connect_to_gmail(email_address, app_password)
        if not mail:
            return None
        
        extracted_emails = []
        
        # Get folders to check
        folders_to_check = ['INBOX', '[Gmail]/Spam']
        
        for folder in folders_to_check:
            try:
                mail.select(folder, readonly=True)  # Keep emails unread
                
                # Search for emails
                result, message_ids = mail.uid('search', 'ALL')
                if result != 'OK':
                    continue
                
                uid_list = message_ids[0].split()
                # Apply email limit based on user selection
                if email_limit != 'all':
                    try:
                        limit = min(int(email_limit), 200)  # Max 200 emails
                        uid_list = uid_list[-limit:] if len(uid_list) > limit else uid_list
                    except (ValueError, TypeError):
                        # Default to 50 if invalid limit
                        uid_list = uid_list[-50:] if len(uid_list) > 50 else uid_list
                else:
                    # For 'all', limit to 200 max
                    uid_list = uid_list[-200:] if len(uid_list) > 200 else uid_list
                
                for uid in uid_list:
                    try:
                        # Fetch email headers and body
                        result, msg_data = mail.uid('fetch', uid, '(RFC822)')
                        if result != 'OK' or not msg_data or not msg_data[0]:
                            continue
                        
                        # Parse email
                        email_message = email.message_from_bytes(msg_data[0][1])
                        
                        # Extract basic info
                        subject = decode_mime_words(email_message.get('Subject', ''))
                        from_header = email_message.get('From', '')
                        date_header = email_message.get('Date', '')
                        
                        # Parse from header
                        from_name, from_email = email.utils.parseaddr(from_header)
                        from_email = from_email.lower()
                        from_domain_extracted = from_email.split('@')[-1] if '@' in from_email else ''
                        
                        # No filtering here - moved to dashboard client-side
                        
                        # Extract security info from headers
                        ip_address = extract_sender_ip(email_message)
                        spf_status = extract_spf_status(email_message)
                        dkim_status = extract_dkim_status(email_message)
                        
                        # Determine email type and category
                        email_type = 'Spam' if folder == '[Gmail]/Spam' else 'Inbox'
                        category = ''
                        
                        if email_type == 'Inbox':
                            # Get Gmail category
                            category = get_gmail_category(mail, uid)
                        
                        # Format date
                        try:
                            parsed_date = email.utils.parsedate_to_datetime(date_header)
                            formatted_date = parsed_date.strftime('%Y-%m-%d %H:%M')
                        except:
                            formatted_date = date_header[:50] if date_header else 'Unknown'
                        
                        extracted_emails.append({
                            'ip_address': ip_address,
                            'spf_status': spf_status,
                            'dkim_status': dkim_status,
                            'from_domain': from_domain_extracted,
                            'subject': subject[:100],  # Limit length
                            'email_type': email_type,
                            'category': category,
                            'date': formatted_date
                        })
                        
                    except Exception as e:
                        logging.error(f"Error processing email UID {uid}: {e}")
                        continue
                        
            except Exception as e:
                logging.error(f"Error accessing folder {folder}: {e}")
                continue
        
        mail.logout()
        return extracted_emails
        
    except Exception as e:
        logging.error(f"Error in extract_and_analyze_emails: {e}")
        return None

def extract_sender_ip(email_message):
    """Extract sender IP address from email headers"""
    try:
        # Check various IP-containing headers
        received_headers = email_message.get_all('Received', [])
        
        for received in received_headers:
            # Look for IP addresses in Received headers

            ip_pattern = r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]'
            matches = re.findall(ip_pattern, received)
            if matches:
                # Return the first external IP (not private)
                for ip in matches:
                    if not ip.startswith(('10.', '192.168.', '172.')):
                        return ip
                # If no external IP, return first IP
                return matches[0] if matches else None
        
        return None
    except:
        return None

def extract_spf_status(email_message):
    """Extract SPF status from Authentication-Results header"""
    try:
        auth_results = email_message.get('Authentication-Results', '')
        if 'spf=pass' in auth_results.lower():
            return 'PASS'
        elif 'spf=fail' in auth_results.lower():
            return 'FAIL'
        elif 'spf=softfail' in auth_results.lower():
            return 'SOFTFAIL'
        elif 'spf=neutral' in auth_results.lower():
            return 'NEUTRAL'
        elif 'spf=none' in auth_results.lower():
            return 'NONE'
        return 'UNKNOWN'
    except:
        return 'UNKNOWN'

def extract_dkim_status(email_message):
    """Extract DKIM status from Authentication-Results header"""
    try:
        auth_results = email_message.get('Authentication-Results', '')
        if 'dkim=pass' in auth_results.lower():
            return 'PASS'
        elif 'dkim=fail' in auth_results.lower():
            return 'FAIL'
        elif 'dkim=neutral' in auth_results.lower():
            return 'NEUTRAL'
        elif 'dkim=none' in auth_results.lower():
            return 'NONE'
        return 'UNKNOWN'
    except:
        return 'UNKNOWN'

def get_gmail_category(mail, uid):
    """Get Gmail category for an email"""
    try:
        result, msg_data = mail.uid('fetch', uid, '(X-GM-LABELS)')
        if result == 'OK' and msg_data and msg_data[0]:
            labels_info = msg_data[0][1].decode('utf-8', errors='ignore') if isinstance(msg_data[0][1], bytes) else str(msg_data[0][1])
            
            if '\\\\Category\\\\Promotions' in labels_info or 'Category/Promotions' in labels_info:
                return 'Promotions'
            elif '\\\\Category\\\\Social' in labels_info or 'Category/Social' in labels_info:
                return 'Social'
            elif '\\\\Category\\\\Updates' in labels_info or 'Category/Updates' in labels_info:
                return 'Updates'
            elif '\\\\Category\\\\Forums' in labels_info or 'Category/Forums' in labels_info:
                return 'Forums'
            else:
                return 'Primary'
        return 'Primary'
    except:
        return 'Primary'

def get_gmail_folder_type(mail, uid):
    """Determine Gmail folder type based only on authentic Gmail X-GM-LABELS"""
    try:
        # Only use Gmail's authentic X-GM-LABELS - no content analysis fallback
        result, msg_data = mail.uid('fetch', uid, '(X-GM-LABELS)')
        if result == 'OK' and msg_data and msg_data[0]:
            try:
                labels_info = msg_data[0][1].decode('utf-8', errors='ignore') if isinstance(msg_data[0][1], bytes) else str(msg_data[0][1])
                logging.debug(f"Gmail labels for UID {uid}: {labels_info}")
                
                # Check for Gmail category labels - use exact Gmail format
                if '\\\\Category\\\\Promotions' in labels_info or 'Category/Promotions' in labels_info:
                    return 'Inbox/Promotions'
                elif '\\\\Category\\\\Social' in labels_info or 'Category/Social' in labels_info:
                    return 'Inbox/Social'
                elif '\\\\Category\\\\Updates' in labels_info or 'Category/Updates' in labels_info:
                    return 'Inbox/Updates'
                elif '\\\\Category\\\\Forums' in labels_info or 'Category/Forums' in labels_info:
                    return 'Inbox/Forums'
                    
            except Exception as e:
                logging.debug(f"Error parsing labels for UID {uid}: {e}")
            
    except Exception as e:
        logging.debug(f"Error fetching labels for UID {uid}: {e}")
    
    # Default to Primary if no Gmail category labels found
    return 'Inbox/Primary'





def format_time_ago(dt):
    """Convert datetime to 'X sec/min/hour/day' (without 'ago')"""
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    
    diff = now - dt
    seconds = int(diff.total_seconds())
    
    if seconds < 60:
        return f"{seconds} sec"
    elif seconds < 3600:
        minutes = seconds // 60
        return f"{minutes} min"
    elif seconds < 86400:
        hours = seconds // 3600
        return f"{hours} h"
    else:
        days = seconds // 86400
        return f"{days} day{'s' if days > 1 else ''}"









def get_emails_from_folder(mail, folder, folder_name, limit=20):
    """Get emails with accurate Gmail category detection — only for Inbox"""
    emails = []
    
    try:
        # Select the folder
        result = mail.select(folder)
        if result[0] != 'OK':
            return emails
        
        # Search for all UIDs
        result, data = mail.uid('SEARCH', None, 'ALL')
        if result != 'OK' or not data[0]:
            return emails
        
        email_uids = data[0].split()
        if not email_uids:
            return emails
        
        # Take only the most recent ones
        recent_uids = email_uids[-limit:]
        recent_uids.reverse()

        # === ONLY DETECT CATEGORIES IF THIS IS THE INBOX FOLDER ===
        use_category_detection = folder_name.lower() == 'inbox'

        # Cache for category UIDs (only if needed)
        cat_uid_sets = {}
        if use_category_detection:
            categories = {
                'social': 'Inbox/Social',
                'promotions': 'Inbox/Promotions',
                'updates': 'Inbox/Updates',
                'forums': 'Inbox/Forums',
                'purchases': 'Inbox/Purchases',
                'reservations': 'Inbox/Reservations'
            }

            for cat_key in categories:
                status, data = mail.uid('SEARCH', 'X-GM-RAW', f'"category:{cat_key}"')
                cat_uid_sets[cat_key] = set(data[0].split()) if status == 'OK' and data[0] else set()
        else:
            # For non-Inbox folders, we don't need categories
            pass

        # === FETCH EMAILS ===
        for uid in recent_uids:
            try:
                # Fetch only headers
                result, msg_data = mail.uid('fetch', uid, '(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])')
                if result != 'OK' or not msg_data[0]:
                    continue

                msg = email.message_from_bytes(msg_data[0][1])

                from_header = msg.get('From', '')
                from_name, from_email = email.utils.parseaddr(from_header)
                from_name = decode_mime_words(from_name) if from_name else from_email

                subject = decode_mime_words(msg.get('Subject', 'No Subject'))

                date_header = msg.get('Date', '')
                try:
                    date_obj = email.utils.parsedate_to_datetime(date_header)
                    date_timestamp = date_obj.timestamp()
                    date_formatted = format_time_ago(date_obj)
                except:
                    date_timestamp = datetime.now().timestamp()
                    date_formatted = 'Unknown'

                # === DETERMINE FOLDER TYPE ===
                if use_category_detection:
                    # Only Inbox uses category tabs
                    detected_folder = 'Inbox/Primary'
                    for cat_key, folder_type_name in {
                        'social': 'Inbox/Social',
                        'promotions': 'Inbox/Promotions',
                        'updates': 'Inbox/Updates',
                        'forums': 'Inbox/Forums',
                        'purchases': 'Inbox/Purchases',
                        'reservations': 'Inbox/Reservations'
                    }.items():
                        if uid in cat_uid_sets[cat_key]:
                            detected_folder = folder_type_name
                            break
                else:
                    # Any other folder (Spam, Sent, etc.) → use folder name directly
                    detected_folder = folder_name  # e.g., "Spam", "Sent", etc.

                emails.append({
                    'folder': detected_folder,
                    'from_name': from_name,
                    'from_email': from_email,
                    'subject': subject,
                    'title': subject,
                    'date': date_timestamp,
                    'date_formatted': date_formatted
                })

            except Exception as e:
                logging.error(f"Error processing email UID {uid}: {e}")
                continue

    except Exception as e:
        logging.error(f"Error accessing folder {folder}: {e}")
    
    return emails

# Authentication Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template('login.html')
        
        # Authenticate user
        user_entity = authenticate_user(username, password)
        if user_entity:
            user = User(username, user_entity)
            login_user(user, remember=True)  # Remember user login
            
            # Notify connection manager about user login
            gmail_manager.user_login(username, user_entity)
            
            flash(f'Welcome {username}! You are logged in as {user_entity}.', 'success')
            
            # Redirect to next page if requested, otherwise dashboard
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('services'))
        else:
            flash('Invalid username or password. Please try again.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    username = current_user.username
    user_entity = current_user.entity
    
    # Notify connection manager about user logout
    gmail_manager.user_logout(username, user_entity)
    
    logout_user()
    flash(f'You have been logged out successfully, {username}.', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return redirect(url_for('services'))

@app.route('/services')
@login_required
def services():
    """Main services selection page"""
    return render_template('services.html', current_user=current_user)

@app.route('/extract_emails', methods=['GET', 'POST'])
@login_required
def extract_emails():
    """TSS Extract Emails service"""
    if request.method == 'GET':
        return render_template('extract_emails.html', current_user=current_user)
    
    # Handle POST request for email extraction
    try:
        email_address = request.form.get('email_address', '').strip()
        app_password = request.form.get('app_password', '').strip()
        
        # Validate required fields
        if not email_address or not app_password:
            return jsonify({'success': False, 'error': 'Email address and app password are required'})
        
        # Get email limit from form
        email_limit = request.form.get('email_limit', 'all').strip()
        if email_limit == 'limited':
            custom_limit = request.form.get('custom_limit', '50').strip()
            email_limit = custom_limit
        
        # Extract and analyze emails
        extracted_data = extract_and_analyze_emails(email_address, app_password, email_limit)
        
        if extracted_data is None:
            return jsonify({'success': False, 'error': 'Failed to connect to Gmail account. Please check your credentials.'})
        
        return jsonify({'success': True, 'data': extracted_data})
        
    except Exception as e:
        logging.error(f"Error in extract_emails: {e}")
        return jsonify({'success': False, 'error': f'Server error: {str(e)}'})

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    selected_account = ''
    emails = []
    error = ''
    email_limit = 50
    search_sender = ''
    search_subject = ''
    
    # Get accounts available to current user
    user_accounts = get_user_accounts(current_user.entity)
    
    if request.method == 'POST':
        # Input validation and sanitization
        selected_account = request.form.get('account', '').strip()
        try:
            email_limit = int(request.form.get('email_limit', 50))
            # Limit email_limit to reasonable bounds
            email_limit = max(1, min(email_limit, 50))
        except (ValueError, TypeError):
            email_limit = 50
            
        search_sender = request.form.get('search_sender', '').strip()[:100]  # Limit length
        search_subject = request.form.get('search_subject', '').strip()[:200]  # Limit length
        
        if selected_account and selected_account in user_accounts:
            account_data = user_accounts[selected_account]
            
            # Handle TSSW account selection
            if current_user.entity == 'TSSW':
                gmail_manager.connect_tssw_account(current_user.username, selected_account)
            
            # Get emails from connection manager
            emails = gmail_manager.get_emails(selected_account)
            
            if not emails:
                error = f'Loading emails for {account_data["email"]}... This may take a moment.'
    
    return render_template('dashboard.html', 
                         accounts=user_accounts,
                         selected_account=selected_account,
                         emails=emails,
                         error=error,
                         email_limit=email_limit,
                         search_sender=search_sender,
                         search_subject=search_subject,
                         current_user=current_user)

@app.route('/fetch_emails', methods=['POST'])
@login_required
def fetch_emails():
    """API endpoint to fetch emails using connection manager"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided', 'emails': []})
            
        # Get accounts available to current user
        user_accounts = get_user_accounts(current_user.entity)
            
        # Input validation and sanitization
        selected_account = str(data.get('account', '')).strip()
        try:
            email_limit = int(data.get('email_limit', 50))
            # Enforce reasonable bounds
            email_limit = max(1, min(email_limit, 50))
        except (ValueError, TypeError):
            email_limit = 50
            
        search_sender = str(data.get('search_sender', ''))[:100]  # Limit length
        search_subject = str(data.get('search_subject', ''))[:200]  # Limit length
        
        if not selected_account or selected_account not in user_accounts:
            return jsonify({'error': 'Invalid account selected', 'emails': []})
        
        account_data = user_accounts[selected_account]
        
        # Handle TSSW account selection
        if current_user.entity == 'TSSW':
            gmail_manager.connect_tssw_account(current_user.username, selected_account)
        
        # Get emails from connection manager
        emails = gmail_manager.get_emails(selected_account)
        
        return jsonify({
            'error': '',
            'emails': emails,
            'email_count': len(emails),
            'email_limit': email_limit,
            'search_sender': search_sender,
            'search_subject': search_subject
        })
            
    except Exception as e:
        logging.error(f"Error in fetch_emails endpoint: {e}")
        return jsonify({'error': f'Server error: {str(e)}', 'emails': []})

@app.route('/events/<account_key>')
@login_required
def events(account_key):
    """Server-Sent Events endpoint for real-time email updates"""
    # Verify user has access to this account
    user_accounts = get_user_accounts(current_user.entity)
    if account_key not in user_accounts:
        return Response("Unauthorized", status=403)
    
    # Handle TSSW account selection for events
    if current_user.entity == 'TSSW':
        gmail_manager.connect_tssw_account(current_user.username, account_key)
    
    def event_stream():
        try:
            # Queue to receive updates
            import queue
            update_queue = queue.Queue()
            
            def callback(acc_key, emails):
                if acc_key == account_key:
                    update_queue.put(emails)
            
            # Add callback to connection manager
            gmail_manager.add_update_callback(account_key, callback)
            
            # Send initial data
            emails = gmail_manager.get_emails(account_key)
            yield f"data: {json.dumps({'emails': emails})}\n\n"
            
            # Listen for updates
            while True:
                try:
                    emails = update_queue.get(timeout=30)  # 30 second timeout
                    yield f"data: {json.dumps({'emails': emails})}\n\n"
                except queue.Empty:
                    # Send heartbeat
                    yield f"data: {json.dumps({'heartbeat': True})}\n\n"
                    
        except Exception as e:
            logging.error(f"Error in event stream: {e}")
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
    
    return Response(event_stream(), mimetype='text/event-stream')

# Removed - entity-based connections don't need individual unsubscribe

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

application = app