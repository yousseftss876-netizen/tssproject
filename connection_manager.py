import threading
import time
import imaplib
import email
import email.utils
from email.header import decode_header
from datetime import datetime, timezone
import logging
import json
import os
from collections import defaultdict, Counter

class EntityBasedGmailManager:
    """Enhanced Gmail connection manager with smart monitoring and health management"""
    
    def __init__(self):
        self.entity_connections = {}  # entity -> {account_key: connection_info}
        self.active_entities = set()  # entities with at least one logged-in user
        self.logged_users = defaultdict(set)  # entity -> set of user_ids
        self.tssw_selected_accounts = {}  # user_id -> account_key (for TSSW users)
        self.email_cache = {}  # account_key -> list of emails
        self.update_callbacks = defaultdict(list)  # account_key -> list of callback functions
        self.lock = threading.RLock()
        self.all_accounts = {}  # account_key -> account_info (loaded from file)
        
        # Enhanced monitoring system
        self.connection_stats = {}  # account_key -> stats (health, last_heartbeat, errors, etc.)
        self.health_monitor_thread = None
        self.health_monitor_stop = threading.Event()
        self.rebuilding_connections = set()  # accounts currently being rebuilt
        self.heartbeat_interval = 120  # Send heartbeat every 2 minutes
        self.health_check_interval = 300  # Check health every 5 minutes
        self.max_connection_age = 900  # Rebuild connections older than 15 minutes
        
        # Hybrid intelligent system
        self.usage_analytics = {}  # Track usage patterns
        self.warm_pool = set()  # Always-connected accounts (top 5 most used)
        self.pre_connected_entities = set()  # Entities pre-connected based on patterns
        self.usage_history_file = 'connection_usage_history.json'
        self.max_warm_pool_size = 5
        self.backup_connections = {}  # Backup connections for critical accounts
        self.connection_retry_counts = defaultdict(int)  # Track retry attempts
        self.max_retries = 3
        
        # Load usage history and initialize intelligent pre-connections
        self._load_usage_history()
        self._initialize_intelligent_preconnections()
        
        # Start global health monitoring
        self._start_health_monitoring()
        logging.info("Hybrid intelligent system initialized with smart monitoring and pre-connections")
    
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
        """Handle user login with intelligent pre-connection and analytics"""
        user_entity = user_entity.upper()
        
        with self.lock:
            # Add user to logged users
            self.logged_users[user_entity].add(user_id)
            
            # Record login for analytics
            self._record_login_analytics(user_entity)
            
            # Handle TSSW special case - they don't auto-connect, wait for account selection
            if user_entity == 'TSSW':
                logging.info(f"TSSW user {user_id} logged in - awaiting account selection")
                # Pre-warm TSSW connections based on their usage patterns
                self._prewarm_tssw_connections(user_id)
            else:
                # Fast activation - entity likely already pre-connected
                self._activate_entity_fast(user_entity)
                logging.info(f"User {user_id} from entity {user_entity} logged in (fast activation)")
    
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
            
            # Initialize connection stats
            self._init_connection_stats(account_key)
            
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
    
    def _activate_entity_fast(self, entity):
        """Fast activate entity - likely already pre-connected"""
        if entity in self.active_entities:
            return  # Already active
        
        self.active_entities.add(entity)
        
        # Check if already pre-connected
        if entity in self.pre_connected_entities:
            logging.info(f"Entity {entity} was pre-connected, activation instant!")
            return
        
        # If not pre-connected, activate with error handling
        self._activate_entity_with_fallback(entity)
    
    def _activate_entity_with_fallback(self, entity):
        """Activate entity with comprehensive error handling and fallback"""
        try:
            # Ensure accounts are loaded
            if not self.all_accounts:
                self.load_gmail_accounts()
            
            # Connect all accounts for this entity
            entity_accounts = {k: v for k, v in self.all_accounts.items() if v['entity'] == entity}
            
            if entity not in self.entity_connections:
                self.entity_connections[entity] = {}
            
            # Connect with parallel processing for speed
            connection_threads = []
            for account_key, account_info in entity_accounts.items():
                thread = threading.Thread(
                    target=self._start_connection_safe,
                    args=(account_key, account_info),
                    daemon=True
                )
                thread.start()
                connection_threads.append(thread)
            
            # Wait for all connections to complete (max 5 seconds)
            for thread in connection_threads:
                thread.join(timeout=5)
            
            logging.info(f"Activated entity {entity} with {len(entity_accounts)} accounts")
            
        except Exception as e:
            logging.error(f"Error activating entity {entity}: {e}")
            # Fallback: try to activate accounts one by one
            self._activate_entity_fallback_mode(entity)
    
    def _activate_entity_fallback_mode(self, entity):
        """Fallback activation mode - connect accounts one by one with retries"""
        logging.info(f"Using fallback mode for entity {entity}")
        
        try:
            entity_accounts = {k: v for k, v in self.all_accounts.items() if v['entity'] == entity}
            
            for account_key, account_info in entity_accounts.items():
                try:
                    self._start_connection_with_retry(account_key, account_info)
                except Exception as e:
                    logging.error(f"Failed to connect {account_key} even in fallback mode: {e}")
                    # Continue with other accounts
                    continue
        except Exception as e:
            logging.error(f"Critical error in fallback mode for {entity}: {e}")
    
    def _activate_entity(self, entity):
        """Legacy activate method - now redirects to fast activation"""
        self._activate_entity_fast(entity)
    
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
    
    def _start_connection_safe(self, account_key, account_info):
        """Thread-safe connection starter with comprehensive error handling"""
        try:
            self._start_connection_with_retry(account_key, account_info)
        except Exception as e:
            logging.error(f"Critical error in safe connection for {account_key}: {e}")
            # Even if this account fails, don't crash the whole system
    
    def _start_connection_with_retry(self, account_key, account_info):
        """Start connection with retry logic and fallback mechanisms"""
        max_attempts = self.max_retries
        
        for attempt in range(max_attempts):
            try:
                # Check if we've exceeded retry limit for this account
                if self.connection_retry_counts[account_key] >= max_attempts:
                    logging.warning(f"Account {account_key} exceeded retry limit, adding to problem accounts")
                    return
                
                # Attempt connection
                self._start_connection_core(account_key, account_info)
                
                # Reset retry count on success
                self.connection_retry_counts[account_key] = 0
                return
                
            except Exception as e:
                self.connection_retry_counts[account_key] += 1
                logging.warning(f"Connection attempt {attempt + 1} failed for {account_key}: {e}")
                
                if attempt < max_attempts - 1:
                    # Wait before retry (exponential backoff)
                    wait_time = (2 ** attempt) * 1
                    time.sleep(wait_time)
                else:
                    logging.error(f"All connection attempts failed for {account_key}")
                    # Try backup connection method
                    self._try_backup_connection(account_key, account_info)
    
    def _start_connection_core(self, account_key, account_info):
        """Core connection logic with enhanced error handling"""
        try:
            # Create IMAP connection with timeout
            mail = imaplib.IMAP4_SSL('imap.gmail.com', 993)
            mail.sock.settimeout(30)  # 30 second timeout
            
            # Login with error handling
            try:
                mail.login(account_info['email'], account_info['app_password'])
            except imaplib.IMAP4.error as e:
                if 'authentication failed' in str(e).lower():
                    logging.error(f"Authentication failed for {account_key}: Check app password")
                    raise Exception(f"Authentication failed: {e}")
                else:
                    raise
            
            # Select inbox with fallback
            try:
                mail.select('INBOX')
            except Exception as e:
                logging.warning(f"Could not select INBOX for {account_key}, trying alternative")
                mail.select()  # Select default folder
            
            connection_info = {
                'mail': mail,
                'account_info': account_info,
                'thread': None,
                'stop_event': threading.Event(),
                'last_update': time.time(),
                'connection_type': 'primary',
                'created_at': time.time()
            }
            
            # Store in entity connections
            entity = account_info['entity']
            with self.lock:
                if entity not in self.entity_connections:
                    self.entity_connections[entity] = {}
                self.entity_connections[entity][account_key] = connection_info
            
            # Initialize connection stats
            self._init_connection_stats(account_key)
            
            # Fetch initial emails with error handling
            try:
                self._fetch_emails(account_key)
            except Exception as e:
                logging.warning(f"Initial email fetch failed for {account_key}: {e}")
                # Continue anyway, emails will be fetched later
            
            # Start monitoring thread
            monitor_thread = threading.Thread(
                target=self._monitor_connection_safe,
                args=(account_key,),
                daemon=True
            )
            monitor_thread.start()
            connection_info['thread'] = monitor_thread
            
            logging.info(f"Successfully started connection for {account_key}")
            
        except Exception as e:
            logging.error(f"Core connection failed for {account_key}: {e}")
            raise
    
    def _try_backup_connection(self, account_key, account_info):
        """Try alternative connection method as backup"""
        try:
            logging.info(f"Trying backup connection method for {account_key}")
            
            # Store backup connection info (simplified)
            backup_info = {
                'account_info': account_info,
                'status': 'backup_needed',
                'last_attempt': time.time(),
                'retry_after': time.time() + 300  # Retry after 5 minutes
            }
            
            self.backup_connections[account_key] = backup_info
            logging.info(f"Scheduled backup retry for {account_key}")
            
        except Exception as e:
            logging.error(f"Backup connection setup failed for {account_key}: {e}")
    
    def _monitor_connection_safe(self, account_key):
        """Enhanced monitoring with comprehensive error handling"""
        entity = account_key.split('_')[0]
        consecutive_errors = 0
        max_consecutive_errors = 5
        
        while (entity in self.entity_connections and 
               account_key in self.entity_connections[entity]):
            
            connection_info = self.entity_connections[entity][account_key]
            
            if connection_info['stop_event'].is_set():
                break
            
            try:
                # Poll every 5 seconds for new emails
                time.sleep(5)
                
                if connection_info['stop_event'].is_set():
                    break
                
                # Fetch emails with error handling
                try:
                    self._fetch_emails(account_key)
                    consecutive_errors = 0  # Reset on success
                except Exception as e:
                    consecutive_errors += 1
                    logging.warning(f"Email fetch error for {account_key}: {e}")
                    
                    if consecutive_errors >= max_consecutive_errors:
                        logging.error(f"Too many consecutive errors for {account_key}, triggering rebuild")
                        self._smart_rebuild_connection(account_key)
                        consecutive_errors = 0
                
            except Exception as e:
                consecutive_errors += 1
                logging.error(f"Monitor error for {account_key}: {e}")
                
                if consecutive_errors >= max_consecutive_errors:
                    logging.error(f"Monitor failure for {account_key}, attempting recovery")
                    try:
                        self._emergency_connection_recovery(account_key)
                    except Exception as recovery_error:
                        logging.error(f"Emergency recovery failed for {account_key}: {recovery_error}")
                    consecutive_errors = 0
                
                time.sleep(30)  # Wait longer after errors
    
    def _emergency_connection_recovery(self, account_key):
        """Last resort connection recovery"""
        logging.info(f"Starting emergency recovery for {account_key}")
        
        entity = account_key.split('_')[0]
        
        # Force close existing connection
        with self.lock:
            if (entity in self.entity_connections and 
                account_key in self.entity_connections[entity]):
                
                connection_info = self.entity_connections[entity][account_key]
                connection_info['stop_event'].set()
                
                try:
                    connection_info['mail'].close()
                    connection_info['mail'].logout()
                except:
                    pass
        
        # Wait a moment
        time.sleep(5)
        
        # Attempt to recreate connection
        if account_key in self.all_accounts:
            account_info = self.all_accounts[account_key]
            self._start_connection_with_retry(account_key, account_info)
    
    def _start_connection(self, account_key, account_info):
        """Legacy method - now redirects to safe connection"""
        self._start_connection_safe(account_key, account_info)
    
    def _load_usage_history(self):
        """Load usage history from persistent storage"""
        try:
            if os.path.exists(self.usage_history_file):
                with open(self.usage_history_file, 'r') as f:
                    data = json.load(f)
                    self.usage_analytics = data.get('usage_analytics', {})
                    self.warm_pool = set(data.get('warm_pool', []))
                    logging.info(f"Loaded usage history: {len(self.usage_analytics)} entities tracked")
            else:
                logging.info("No usage history found, starting fresh")
        except Exception as e:
            logging.error(f"Error loading usage history: {e}")
            # Continue with empty analytics
    
    def _save_usage_history(self):
        """Save usage history to persistent storage"""
        try:
            data = {
                'usage_analytics': self.usage_analytics,
                'warm_pool': list(self.warm_pool),
                'last_updated': time.time()
            }
            with open(self.usage_history_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logging.error(f"Error saving usage history: {e}")
    
    def _initialize_intelligent_preconnections(self):
        """Initialize intelligent pre-connections based on usage patterns"""
        try:
            current_time = time.time()
            current_hour = datetime.now().hour
            
            # Pre-connect entities that were active in last 24 hours
            entities_to_preconnect = set()
            
            for entity, analytics in self.usage_analytics.items():
                # Check recent activity (last 24 hours)
                recent_logins = [
                    login_time for login_time in analytics.get('login_times', [])
                    if current_time - login_time < 86400  # 24 hours
                ]
                
                if recent_logins:
                    entities_to_preconnect.add(entity)
                
                # Check if this hour is typically active for this entity
                typical_hours = analytics.get('typical_hours', [])
                if current_hour in typical_hours:
                    entities_to_preconnect.add(entity)
            
            # Pre-connect identified entities in background
            if entities_to_preconnect:
                preconnect_thread = threading.Thread(
                    target=self._preconnect_entities_background,
                    args=(entities_to_preconnect,),
                    daemon=True
                )
                preconnect_thread.start()
            
            # Maintain warm pool (top 5 most used accounts)
            self._maintain_warm_pool()
            
            logging.info(f"Intelligent pre-connections initialized: {len(entities_to_preconnect)} entities scheduled")
            
        except Exception as e:
            logging.error(f"Error in intelligent pre-connections: {e}")
            # Continue without pre-connections
    
    def _preconnect_entities_background(self, entities_to_preconnect):
        """Pre-connect entities in background thread"""
        for entity in entities_to_preconnect:
            try:
                self._preconnect_entity_safe(entity)
                time.sleep(2)  # Small delay between connections
            except Exception as e:
                logging.error(f"Background pre-connection failed for {entity}: {e}")
    
    def _preconnect_entity_safe(self, entity):
        """Safely pre-connect an entity with error handling"""
        try:
            if entity not in self.pre_connected_entities:
                logging.info(f"Pre-connecting entity {entity}")
                
                # Load accounts if not loaded
                if not self.all_accounts:
                    self.load_gmail_accounts()
                
                # Pre-connect accounts for this entity
                entity_accounts = {k: v for k, v in self.all_accounts.items() if v['entity'] == entity}
                
                if entity not in self.entity_connections:
                    self.entity_connections[entity] = {}
                
                # Connect accounts with error handling
                for account_key, account_info in entity_accounts.items():
                    try:
                        self._start_connection_safe(account_key, account_info)
                    except Exception as e:
                        logging.warning(f"Pre-connection failed for {account_key}: {e}")
                        # Continue with other accounts
                
                self.pre_connected_entities.add(entity)
                logging.info(f"Successfully pre-connected entity {entity}")
                
        except Exception as e:
            logging.error(f"Error pre-connecting entity {entity}: {e}")
    
    def _maintain_warm_pool(self):
        """Maintain warm pool of most-used accounts"""
        try:
            # Calculate account usage scores
            account_scores = {}
            
            for entity, analytics in self.usage_analytics.items():
                login_count = analytics.get('login_count', 0)
                recent_activity = len([
                    t for t in analytics.get('login_times', [])
                    if time.time() - t < 604800  # Last week
                ])
                
                # Score based on total logins and recent activity
                score = login_count + (recent_activity * 2)
                
                # Add all accounts for this entity to scoring
                if self.all_accounts:
                    entity_accounts = {k: v for k, v in self.all_accounts.items() if v['entity'] == entity}
                    for account_key in entity_accounts:
                        account_scores[account_key] = score
            
            # Select top accounts for warm pool
            if account_scores:
                top_accounts = sorted(account_scores.items(), key=lambda x: x[1], reverse=True)
                new_warm_pool = set([account for account, score in top_accounts[:self.max_warm_pool_size]])
                
                # Update warm pool connections
                self._update_warm_pool(new_warm_pool)
            
        except Exception as e:
            logging.error(f"Error maintaining warm pool: {e}")
    
    def _update_warm_pool(self, new_warm_pool):
        """Update warm pool connections"""
        try:
            old_warm_pool = self.warm_pool.copy()
            self.warm_pool = new_warm_pool
            
            # Connect new accounts in background
            for account_key in new_warm_pool - old_warm_pool:
                if self.all_accounts and account_key in self.all_accounts:
                    try:
                        account_info = self.all_accounts[account_key]
                        self._start_connection_safe(account_key, account_info)
                        logging.info(f"Added {account_key} to warm pool")
                    except Exception as e:
                        logging.warning(f"Failed to add {account_key} to warm pool: {e}")
            
        except Exception as e:
            logging.error(f"Error updating warm pool: {e}")
    
    def _record_login_analytics(self, user_entity):
        """Record login analytics for intelligence"""
        try:
            if user_entity not in self.usage_analytics:
                self.usage_analytics[user_entity] = {
                    'login_count': 0,
                    'login_times': [],
                    'typical_hours': [],
                    'first_seen': time.time()
                }
            
            analytics = self.usage_analytics[user_entity]
            current_time = time.time()
            current_hour = datetime.now().hour
            
            # Update login count
            analytics['login_count'] += 1
            
            # Add login time (keep last 100 logins)
            analytics['login_times'].append(current_time)
            if len(analytics['login_times']) > 100:
                analytics['login_times'] = analytics['login_times'][-100:]
            
            # Update typical hours
            hour_counter = Counter(analytics.get('typical_hours', []))
            hour_counter[current_hour] += 1
            
            # Keep top 6 most common hours
            analytics['typical_hours'] = [hour for hour, count in hour_counter.most_common(6)]
            
            # Save analytics periodically
            if analytics['login_count'] % 10 == 0:  # Save every 10 logins
                self._save_usage_history()
            
        except Exception as e:
            logging.error(f"Error recording login analytics: {e}")
    
    def _prewarm_tssw_connections(self, user_id):
        """Pre-warm connections for TSSW users based on their usage patterns"""
        try:
            # Get TSSW user's most common account selections from analytics
            # For now, pre-warm the warm pool accounts
            for account_key in list(self.warm_pool)[:3]:  # Top 3 accounts
                if self.all_accounts and account_key in self.all_accounts:
                    try:
                        account_info = self.all_accounts[account_key]
                        self._start_connection_safe(account_key, account_info)
                    except Exception as e:
                        logging.warning(f"TSSW pre-warm failed for {account_key}: {e}")
            
        except Exception as e:
            logging.error(f"Error pre-warming TSSW connections: {e}")
    
    def _update_usage_analytics(self, account_key):
        """Update usage analytics when account is accessed"""
        try:
            entity = account_key.split('_')[0]
            if entity in self.usage_analytics:
                analytics = self.usage_analytics[entity]
                analytics['last_accessed'] = time.time()
                
                # Track account-specific usage
                if 'account_usage' not in analytics:
                    analytics['account_usage'] = {}
                
                if account_key not in analytics['account_usage']:
                    analytics['account_usage'][account_key] = 0
                
                analytics['account_usage'][account_key] += 1
                
        except Exception as e:
            logging.error(f"Error updating usage analytics: {e}")
    
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
            if account_key in self.connection_stats:
                del self.connection_stats[account_key]
            
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
                # Poll every 5 seconds for new emails (enhanced speed)
                time.sleep(5)
                
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
    
    def _start_health_monitoring(self):
        """Start global health monitoring thread"""
        if self.health_monitor_thread is None or not self.health_monitor_thread.is_alive():
            self.health_monitor_thread = threading.Thread(
                target=self._health_monitor_loop,
                daemon=True
            )
            self.health_monitor_thread.start()
            logging.info("Started global health monitoring thread")
    
    def _health_monitor_loop(self):
        """Global health monitoring loop - checks all connections every 5 minutes"""
        while not self.health_monitor_stop.is_set():
            try:
                # Wait for health check interval (5 minutes)
                if self.health_monitor_stop.wait(self.health_check_interval):
                    break
                
                # Check health of all active connections
                self._check_all_connections_health()
                
            except Exception as e:
                logging.error(f"Error in health monitor loop: {e}")
                time.sleep(30)  # Wait before retrying
    
    def _check_all_connections_health(self):
        """Check health of all active connections and rebuild if needed"""
        with self.lock:
            all_accounts_to_check = []
            
            # Collect all active account keys
            for entity_connections in self.entity_connections.values():
                for account_key in entity_connections.keys():
                    if account_key not in self.rebuilding_connections:
                        all_accounts_to_check.append(account_key)
        
        # Check each connection (outside of lock to avoid blocking)
        for account_key in all_accounts_to_check:
            try:
                if self._needs_rebuild(account_key):
                    logging.info(f"Smart rebuilding connection for {account_key}")
                    self._smart_rebuild_connection(account_key)
                else:
                    # Send heartbeat to keep connection alive
                    self._send_heartbeat(account_key)
            except Exception as e:
                logging.error(f"Error checking health for {account_key}: {e}")
    
    def _needs_rebuild(self, account_key):
        """Check if connection needs rebuilding (unhealthy or too old)"""
        stats = self.connection_stats.get(account_key)
        if not stats:
            return True  # No stats means we should rebuild
        
        current_time = time.time()
        
        # Check if connection is too old (>15 minutes)
        if current_time - stats['created_time'] > self.max_connection_age:
            logging.debug(f"Connection {account_key} is too old, needs rebuild")
            return True
        
        # Check if connection is unhealthy (too many recent errors)
        if stats['error_count'] > 3:
            logging.debug(f"Connection {account_key} has too many errors, needs rebuild")
            return True
        
        # Check if last heartbeat failed
        if stats.get('last_heartbeat_failed', False):
            logging.debug(f"Connection {account_key} heartbeat failed, needs rebuild")
            return True
        
        return False
    
    def _send_heartbeat(self, account_key):
        """Send IMAP NOOP command to keep connection alive"""
        entity = account_key.split('_')[0]
        
        with self.lock:
            if (entity not in self.entity_connections or 
                account_key not in self.entity_connections[entity]):
                return
            
            connection_info = self.entity_connections[entity][account_key]
            mail = connection_info['mail']
        
        try:
            # Send NOOP command to keep connection alive
            status, response = mail.noop()
            if status == 'OK':
                self._update_connection_stats(account_key, 'heartbeat_success')
                logging.debug(f"Heartbeat successful for {account_key}")
            else:
                self._update_connection_stats(account_key, 'heartbeat_failed')
                logging.warning(f"Heartbeat failed for {account_key}: {response}")
        except Exception as e:
            self._update_connection_stats(account_key, 'heartbeat_error')
            logging.warning(f"Heartbeat error for {account_key}: {e}")
    
    def _smart_rebuild_connection(self, account_key):
        """Intelligently rebuild a connection with rolling reconnection"""
        entity = account_key.split('_')[0]
        
        # Mark as rebuilding to prevent concurrent rebuilds
        with self.lock:
            if account_key in self.rebuilding_connections:
                return  # Already being rebuilt
            self.rebuilding_connections.add(account_key)
        
        try:
            # Get account info
            with self.lock:
                if (entity not in self.entity_connections or 
                    account_key not in self.entity_connections[entity]):
                    return
                
                connection_info = self.entity_connections[entity][account_key]
                account_info = connection_info['account_info']
            
            logging.info(f"Smart rebuilding connection for {account_key}")
            
            # Create new connection
            new_mail = imaplib.IMAP4_SSL('imap.gmail.com', 993)
            new_mail.login(account_info['email'], account_info['app_password'])
            new_mail.select('INBOX')
            
            # Replace old connection atomically
            with self.lock:
                if (entity in self.entity_connections and 
                    account_key in self.entity_connections[entity]):
                    
                    old_connection_info = self.entity_connections[entity][account_key]
                    
                    # Close old connection
                    try:
                        old_connection_info['mail'].close()
                        old_connection_info['mail'].logout()
                    except:
                        pass
                    
                    # Update with new connection
                    old_connection_info['mail'] = new_mail
                    
                    # Reset connection stats
                    self._init_connection_stats(account_key)
                    
                    logging.info(f"Successfully rebuilt connection for {account_key}")
            
            # Fetch latest emails with new connection
            self._fetch_emails(account_key)
            
        except Exception as e:
            logging.error(f"Failed to smart rebuild connection for {account_key}: {e}")
            # If rebuild fails, try standard reconnection
            self._reconnect(account_key)
        
        finally:
            # Remove from rebuilding set
            with self.lock:
                self.rebuilding_connections.discard(account_key)
    
    def _init_connection_stats(self, account_key):
        """Initialize connection statistics"""
        self.connection_stats[account_key] = {
            'created_time': time.time(),
            'last_heartbeat': time.time(),
            'last_heartbeat_failed': False,
            'error_count': 0,
            'email_fetch_count': 0,
            'last_email_fetch': None,
            'health_status': 'healthy'
        }
    
    def _update_connection_stats(self, account_key, event_type, error=None):
        """Update connection statistics"""
        if account_key not in self.connection_stats:
            self._init_connection_stats(account_key)
        
        stats = self.connection_stats[account_key]
        current_time = time.time()
        
        if event_type == 'heartbeat_success':
            stats['last_heartbeat'] = current_time
            stats['last_heartbeat_failed'] = False
            stats['health_status'] = 'healthy'
        elif event_type == 'heartbeat_failed':
            stats['last_heartbeat_failed'] = True
            stats['error_count'] += 1
            stats['health_status'] = 'unhealthy'
        elif event_type == 'heartbeat_error':
            stats['last_heartbeat_failed'] = True
            stats['error_count'] += 1
            stats['health_status'] = 'error'
        elif event_type == 'email_fetch_success':
            stats['email_fetch_count'] += 1
            stats['last_email_fetch'] = current_time
            # Reset error count on successful operation
            stats['error_count'] = max(0, stats['error_count'] - 1)
        elif event_type == 'email_fetch_error':
            stats['error_count'] += 1
        elif event_type == 'connection_reset':
            # Reset stats after successful rebuild
            stats['created_time'] = current_time
            stats['error_count'] = 0
            stats['last_heartbeat'] = current_time
            stats['last_heartbeat_failed'] = False
            stats['health_status'] = 'healthy'

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
            
            # Update connection stats for successful fetch
            self._update_connection_stats(account_key, 'email_fetch_success')
            
            # Update usage analytics
            self._update_usage_analytics(account_key)
            
            # Call update callbacks
            for callback in self.update_callbacks[account_key]:
                try:
                    callback(account_key, recent_emails)
                except Exception as e:
                    logging.error(f"Error in update callback: {e}")
            
            logging.debug(f"Fetched {len(recent_emails)} emails for {account_key}")
            
        except Exception as e:
            logging.error(f"Error fetching emails for {account_key}: {e}")
            # Update stats for failed fetch
            self._update_connection_stats(account_key, 'email_fetch_error', error=str(e))
    
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