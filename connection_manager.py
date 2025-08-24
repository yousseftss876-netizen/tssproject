import threading
import time
import imaplib
import email
import email.utils
from email.header import decode_header
from datetime import datetime, timezone
import logging
from collections import defaultdict

class EntityBasedGmailManager:
    """Enhanced Gmail connection manager with entity-based connection pooling"""
    
    def __init__(self):
        self.entity_connections = {}  # entity -> {account_key: connection_info}
        self.active_entities = set()  # entities with at least one logged-in user
        self.logged_users = defaultdict(set)  # entity -> set of user_ids
        self.tssw_selected_accounts = {}  # user_id -> account_key (for TSSW users)
        self.email_cache = {}  # account_key -> list of emails
        self.update_callbacks = defaultdict(list)  # account_key -> list of callback functions
        self.lock = threading.RLock()
        self.all_accounts = {}  # account_key -> account_info (loaded from file)
        logging.info("EntityBasedGmailManager initialized")
    
    def load_gmail_accounts(self):
        """Load Gmail accounts from gmailaccounts.txt file"""
        accounts = {}
        try:
            with open('gmailaccounts.txt', 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        try:
                            parts = line.split(',')
                            if len(parts) == 3:
                                entity = parts[0].strip().upper()
                                email_addr = parts[1].strip()
                                app_password = parts[2].strip()
                                
                                account_key = f"{entity}_{email_addr}"
                                accounts[account_key] = {
                                    "entity": entity,
                                    "email": email_addr,
                                    "app_password": app_password,
                                    "display_name": f"{entity} - {email_addr}"
                                }
                            else:
                                logging.warning(f"Invalid format in gmailaccounts.txt line {line_num}: {line}")
                        except Exception as e:
                            logging.error(f"Error parsing gmailaccounts.txt line {line_num}: {e}")
        except FileNotFoundError:
            logging.error("gmailaccounts.txt file not found")
        except Exception as e:
            logging.error(f"Error reading gmailaccounts.txt: {e}")
        
        with self.lock:
            self.all_accounts = accounts
        return accounts
    
    def user_login(self, user_id, user_entity):
        """Handle user login - connect accounts based on entity type"""
        user_entity = user_entity.upper()
        
        with self.lock:
            # Add user to logged users
            self.logged_users[user_entity].add(user_id)
            
            # Handle TSSW special case - they don't auto-connect, wait for account selection
            if user_entity == 'TSSW':
                logging.info(f"TSSW user {user_id} logged in - awaiting account selection")
            else:
                self._activate_entity(user_entity)
                logging.info(f"User {user_id} from entity {user_entity} logged in")
    
    def user_logout(self, user_id, user_entity):
        """Handle user logout - disconnect connections appropriately"""
        user_entity = user_entity.upper()
        
        with self.lock:
            # Handle TSSW logout - disconnect their selected account if needed
            if user_entity == 'TSSW' and user_id in self.tssw_selected_accounts:
                selected_account = self.tssw_selected_accounts[user_id]
                selected_entity = selected_account.split('_')[0]
                
                # If this was the only connection to this account and no users from that entity are logged in
                if (selected_entity != 'TSSW' and 
                    not self.logged_users.get(selected_entity) and
                    selected_account in self.email_cache):
                    self._close_connection(selected_account)
                
                # Remove from TSSW selections
                del self.tssw_selected_accounts[user_id]
            
            # Remove user from logged users
            if user_entity in self.logged_users:
                self.logged_users[user_entity].discard(user_id)
                
                # If no users left in this entity, deactivate it
                if not self.logged_users[user_entity]:
                    self._deactivate_entity(user_entity)
                    logging.info(f"Last user from entity {user_entity} logged out - disconnecting accounts")
    
    def get_user_accounts(self, user_entity):
        """Get Gmail accounts accessible to a user based on their entity"""
        user_entity = user_entity.upper()
        
        # Ensure accounts are loaded
        if not self.all_accounts:
            self.load_gmail_accounts()
        
        if user_entity == 'TSSW':
            # TSSW users can see all accounts
            return self.all_accounts
        else:
            # Other users can only see accounts from their entity
            user_accounts = {}
            for key, account in self.all_accounts.items():
                if account['entity'] == user_entity:
                    user_accounts[key] = account
            return user_accounts
    
    def get_emails(self, account_key):
        """Get cached emails for an account"""
        with self.lock:
            return self.email_cache.get(account_key, [])
    
    def connect_tssw_account(self, user_id, account_key):
        """Connect TSSW user to a specific account"""
        with self.lock:
            # Disconnect previous TSSW account selection if any
            if user_id in self.tssw_selected_accounts:
                old_account = self.tssw_selected_accounts[user_id]
                self._disconnect_tssw_account(user_id, old_account)
            
            # Store new selection
            self.tssw_selected_accounts[user_id] = account_key
            
            # Check if account is already connected
            if account_key in self.email_cache:
                logging.info(f"TSSW user {user_id} using existing connection for {account_key}")
                return
            
            # Get account info
            if not self.all_accounts:
                self.load_gmail_accounts()
            
            if account_key not in self.all_accounts:
                logging.error(f"Account {account_key} not found")
                return
            
            account_info = self.all_accounts[account_key]
            selected_entity = account_info['entity']
            
            # Check if entity has logged-in users (use existing connection)
            if (selected_entity != 'TSSW' and 
                self.logged_users.get(selected_entity) and 
                selected_entity in self.active_entities):
                logging.info(f"TSSW user {user_id} using existing {selected_entity} entity connection for {account_key}")
                return
            
            # Create new connection for this specific account
            self._start_single_connection(account_key, account_info)
            logging.info(f"TSSW user {user_id} created new connection for {account_key}")
    
    def _disconnect_tssw_account(self, user_id, account_key):
        """Disconnect TSSW user from specific account if it's not being used by others"""
        if account_key not in self.email_cache:
            return
        
        account_info = self.all_accounts.get(account_key)
        if not account_info:
            return
            
        selected_entity = account_info['entity']
        
        # Don't disconnect if:
        # 1. The entity has its own users logged in
        # 2. Other TSSW users are using this account
        # 3. It's a TSSW account and other TSSW users are logged in
        if (selected_entity != 'TSSW' and self.logged_users.get(selected_entity)):
            return
        
        if (selected_entity == 'TSSW' and 
            len([uid for uid, acc in self.tssw_selected_accounts.items() 
                 if acc == account_key and uid != user_id]) > 0):
            return
        
        if len(self.logged_users.get('TSSW', set())) > 1:
            # Check if other TSSW users are using this account
            other_tssw_using = any(acc == account_key for uid, acc in self.tssw_selected_accounts.items() if uid != user_id)
            if other_tssw_using:
                return
        
        # Safe to disconnect
        self._close_connection(account_key)
        logging.info(f"Disconnected TSSW account {account_key} for user {user_id}")
    
    def _start_single_connection(self, account_key, account_info):
        """Start connection for a single account (used by TSSW)"""
        try:
            # Create IMAP connection
            mail = imaplib.IMAP4_SSL('imap.gmail.com', 993)
            mail.login(account_info['email'], account_info['app_password'])
            mail.select('INBOX')
            
            connection_info = {
                'mail': mail,
                'account_info': account_info,
                'thread': None,
                'stop_event': threading.Event(),
                'last_update': time.time(),
                'single_account': True  # Mark as single account connection
            }
            
            # Store in entity connections
            entity = account_info['entity']
            if entity not in self.entity_connections:
                self.entity_connections[entity] = {}
            self.entity_connections[entity][account_key] = connection_info
            
            # Fetch initial emails
            self._fetch_emails(account_key)
            
            # Start monitoring thread
            monitor_thread = threading.Thread(
                target=self._monitor_connection,
                args=(account_key,),
                daemon=True
            )
            monitor_thread.start()
            connection_info['thread'] = monitor_thread
            
            logging.info(f"Started single connection for {account_key}")
            
        except Exception as e:
            logging.error(f"Failed to start single connection for {account_key}: {e}")
    
    def add_update_callback(self, account_key, callback):
        """Add a callback function to be called when emails are updated"""
        with self.lock:
            self.update_callbacks[account_key].append(callback)
    
    def _activate_entity(self, entity):
        """Activate all Gmail connections for an entity"""
        if entity in self.active_entities:
            return  # Already active
        
        self.active_entities.add(entity)
        
        # Ensure accounts are loaded
        if not self.all_accounts:
            self.load_gmail_accounts()
        
        # Connect all accounts for this entity
        entity_accounts = {k: v for k, v in self.all_accounts.items() if v['entity'] == entity}
        
        if entity not in self.entity_connections:
            self.entity_connections[entity] = {}
        
        for account_key, account_info in entity_accounts.items():
            self._start_connection(account_key, account_info)
        
        logging.info(f"Activated entity {entity} with {len(entity_accounts)} accounts")
    
    def _deactivate_entity(self, entity):
        """Deactivate all Gmail connections for an entity"""
        if entity not in self.active_entities:
            return  # Already inactive
        
        self.active_entities.discard(entity)
        
        # Close all connections for this entity
        if entity in self.entity_connections:
            for account_key in list(self.entity_connections[entity].keys()):
                self._close_connection(account_key)
            del self.entity_connections[entity]
        
        logging.info(f"Deactivated entity {entity}")
    
    def _check_tssw_deactivation(self):
        """Check if we should deactivate entities after TSSW logout"""
        # Keep entities active if they have their own users logged in
        entities_to_keep = set(entity for entity, users in self.logged_users.items() if users and entity != 'TSSW')
        
        # Deactivate entities that don't have their own users
        entities_to_deactivate = self.active_entities - entities_to_keep - {'TSSW'}
        for entity in entities_to_deactivate:
            self._deactivate_entity(entity)
    
    def _start_connection(self, account_key, account_info):
        """Start a new IMAP connection with polling monitoring"""
        try:
            # Create IMAP connection
            mail = imaplib.IMAP4_SSL('imap.gmail.com', 993)
            mail.login(account_info['email'], account_info['app_password'])
            mail.select('INBOX')
            
            connection_info = {
                'mail': mail,
                'account_info': account_info,
                'thread': None,
                'stop_event': threading.Event(),
                'last_update': time.time()
            }
            
            # Store in entity connections
            entity = account_info['entity']
            if entity not in self.entity_connections:
                self.entity_connections[entity] = {}
            self.entity_connections[entity][account_key] = connection_info
            
            # Fetch initial emails
            self._fetch_emails(account_key)
            
            # Start polling monitoring thread
            monitor_thread = threading.Thread(
                target=self._monitor_connection,
                args=(account_key,),
                daemon=True
            )
            monitor_thread.start()
            connection_info['thread'] = monitor_thread
            
            logging.info(f"Started connection for {account_key}")
            
        except Exception as e:
            logging.error(f"Failed to start connection for {account_key}: {e}")
    
    def _close_connection(self, account_key):
        """Close an IMAP connection"""
        entity = account_key.split('_')[0]
        
        if entity in self.entity_connections and account_key in self.entity_connections[entity]:
            connection_info = self.entity_connections[entity][account_key]
            
            # Signal thread to stop
            connection_info['stop_event'].set()
            
            # Close IMAP connection
            try:
                connection_info['mail'].close()
                connection_info['mail'].logout()
            except:
                pass
            
            # Clean up
            del self.entity_connections[entity][account_key]
            if account_key in self.email_cache:
                del self.email_cache[account_key]
            if account_key in self.update_callbacks:
                del self.update_callbacks[account_key]
            
            logging.info(f"Closed connection for {account_key}")
    
    def _monitor_connection(self, account_key):
        """Monitor IMAP connection using polling"""
        entity = account_key.split('_')[0]
        
        while (entity in self.entity_connections and 
               account_key in self.entity_connections[entity]):
            
            connection_info = self.entity_connections[entity][account_key]
            
            if connection_info['stop_event'].is_set():
                break
            
            try:
                # Poll every 10 seconds for new emails
                time.sleep(10)
                
                if connection_info['stop_event'].is_set():
                    break
                
                # Fetch emails periodically
                self._fetch_emails(account_key)
                
            except Exception as e:
                logging.error(f"Monitor error for {account_key}: {e}")
                # Try to reconnect
                self._reconnect(account_key)
                time.sleep(30)
    
    def _reconnect(self, account_key):
        """Reconnect to Gmail account"""
        entity = account_key.split('_')[0]
        
        if (entity not in self.entity_connections or 
            account_key not in self.entity_connections[entity]):
            return
        
        connection_info = self.entity_connections[entity][account_key]
        account_info = connection_info['account_info']
        
        try:
            # Close old connection
            try:
                connection_info['mail'].close()
                connection_info['mail'].logout()
            except:
                pass
            
            # Create new connection
            mail = imaplib.IMAP4_SSL('imap.gmail.com', 993)
            mail.login(account_info['email'], account_info['app_password'])
            mail.select('INBOX')
            
            connection_info['mail'] = mail
            logging.info(f"Reconnected to {account_key}")
            
            # Fetch latest emails
            self._fetch_emails(account_key)
            
        except Exception as e:
            logging.error(f"Failed to reconnect to {account_key}: {e}")
    
    def _fetch_emails(self, account_key):
        """Fetch the last 50 emails from all folders"""
        entity = account_key.split('_')[0]
        
        if (entity not in self.entity_connections or 
            account_key not in self.entity_connections[entity]):
            return
        
        connection_info = self.entity_connections[entity][account_key]
        mail = connection_info['mail']
        
        try:
            all_emails = []
            
            # Get emails from key folders
            folders_to_check = [
                ('INBOX', 'Inbox'),
                ('[Gmail]/Spam', 'Spam')
            ]
            
            # Pre-cache Gmail categories for inbox emails
            category_uid_cache = {}
            
            for folder_path, folder_name in folders_to_check:
                try:
                    result = mail.select(folder_path)
                    if result[0] != 'OK':
                        continue
                    
                    # Cache Gmail categories only for Inbox folder
                    if folder_name == 'Inbox':
                        categories = ['social', 'promotions', 'updates', 'forums']
                        for cat_key in categories:
                            try:
                                result, data = mail.uid('SEARCH', 'X-GM-RAW', f'"category:{cat_key}"')
                                category_uid_cache[cat_key] = set(data[0].split()) if result == 'OK' and data[0] else set()
                            except Exception as e:
                                logging.debug(f"Error caching category {cat_key}: {e}")
                                category_uid_cache[cat_key] = set()
                    
                    # Search for all emails
                    result, data = mail.uid('SEARCH', None, 'ALL')
                    if result != 'OK' or not data[0]:
                        continue
                    
                    email_uids = data[0].split()
                    if not email_uids:
                        continue
                    
                    # Get the most recent emails from this folder
                    recent_uids = email_uids[-30:]  # Get 30 from each folder
                    
                    for uid in reversed(recent_uids):
                        try:
                            # Fetch email headers
                            result, msg_data = mail.uid('fetch', uid, '(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)] FLAGS)')
                            if result != 'OK' or not msg_data[0]:
                                continue
                            
                            msg = email.message_from_bytes(msg_data[0][1])
                            
                            # Parse email data
                            from_header = msg.get('From', '')
                            from_name, from_email = email.utils.parseaddr(from_header)
                            from_name = self._decode_mime_words(from_name) if from_name else from_email
                            
                            subject = self._decode_mime_words(msg.get('Subject', 'No Subject'))
                            
                            date_header = msg.get('Date', '')
                            try:
                                date_obj = email.utils.parsedate_to_datetime(date_header)
                                date_timestamp = date_obj.timestamp()
                                date_formatted = self._format_time_ago(date_obj)
                            except:
                                date_timestamp = datetime.now().timestamp()
                                date_formatted = 'Unknown'
                            
                            # Determine folder type for inbox categorization
                            detected_folder = self._get_gmail_folder_type_cached(uid, folder_name, category_uid_cache)
                            
                            email_data = {
                                'uid': uid.decode() if isinstance(uid, bytes) else uid,
                                'folder': detected_folder,
                                'from_name': from_name,
                                'from_email': from_email,
                                'subject': subject,
                                'date': date_formatted,
                                'date_timestamp': date_timestamp,
                                'folder_name': folder_name
                            }
                            
                            all_emails.append(email_data)
                            
                        except Exception as e:
                            logging.debug(f"Error processing email UID {uid}: {e}")
                            continue
                
                except Exception as e:
                    logging.debug(f"Error processing folder {folder_path}: {e}")
                    continue
            
            # Sort by date and keep only the 50 most recent
            all_emails.sort(key=lambda x: x['date_timestamp'], reverse=True)
            recent_emails = all_emails[:50]
            
            # Update cache
            with self.lock:
                self.email_cache[account_key] = recent_emails
                connection_info['last_update'] = time.time()
            
            # Call update callbacks
            for callback in self.update_callbacks[account_key]:
                try:
                    callback(account_key, recent_emails)
                except Exception as e:
                    logging.error(f"Error in update callback: {e}")
            
            logging.debug(f"Fetched {len(recent_emails)} emails for {account_key}")
            
        except Exception as e:
            logging.error(f"Error fetching emails for {account_key}: {e}")
    
    def _decode_mime_words(self, s):
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
    
    def _format_time_ago(self, dt):
        """Convert datetime to 'X sec/min/hour/day' format"""
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
    
    def _get_gmail_folder_type_cached(self, uid, folder_name, category_uid_cache):
        """Determine Gmail folder type using cached category UIDs"""
        if folder_name.lower() != 'inbox':
            return folder_name
        
        # Check cached categories
        categories = [
            ('social', 'Inbox/Social'),
            ('promotions', 'Inbox/Promotions'), 
            ('updates', 'Inbox/Updates'),
            ('forums', 'Inbox/Forums')
        ]
        
        for cat_key, folder_type in categories:
            if uid in category_uid_cache.get(cat_key, set()):
                return folder_type
        
        # Default to Primary if no category found
        return 'Inbox/Primary'

# Global connection manager instance
gmail_manager = EntityBasedGmailManager()